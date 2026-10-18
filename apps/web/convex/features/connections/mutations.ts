/**
 * Dashboard connection writes — one row per (user, connector).
 *
 * `tokenCipher` arrives ALREADY SEALED — by the dashboard's connect flow
 * (`apps/web/lib/credentials.ts`) or by the gateway. `CREDENTIAL_ENCRYPTION_KEY`
 * is never given to Convex, so this function can neither seal nor open one and
 * must never try. What it can do is refuse to store something that is obviously
 * not a sealed envelope: an unsealed token stored here would come back as an
 * opaque INTERNAL error at call time, hours later, far from the mistake.
 */
import { v } from "convex/values"
import { mutation } from "../../_generated/server"
import { requireUser } from "../../_shared/auth"
import { fail } from "../../_shared/errors"
import { assertIdentifier } from "../../_shared/input"
import { assertSealedEnvelope } from "../../_shared/sealed_envelope"
import { MAX_CONNECTIONS_PER_CONNECTOR } from "../../_shared/limits"
import { assertConnectionUrl } from "../../_shared/connection_url"
import { authTypeValidator } from "../../_shared/validators"
import type { Doc } from "../../_generated/dataModel"
import type { MutationCtx } from "../../_generated/server"

export const upsert = mutation({
  args: {
    connectorId: v.string(),
    baseUrl: v.string(),
    tokenCipher: v.string(),
    tokenExpiresAt: v.optional(v.number()),
    renewalCipher: v.optional(v.string()),
    authType: authTypeValidator,
  },
  returns: v.object({ connectionId: v.string() }),
  handler: async (ctx, args): Promise<{ connectionId: string }> => {
    const userId = await requireUser(ctx)
    const connectorId = assertIdentifier(args.connectorId, "connectorId")
    // Validated before any read, so a rejected URL never touches the database.
    const baseUrl = assertConnectionUrl(connectorId, args.baseUrl)
    const tokenCipher = assertSealedEnvelope(args.tokenCipher)
    const tokenExpiresAt = assertOptionalTimestamp(args.tokenExpiresAt)
    const renewalCipher =
      args.renewalCipher === undefined ? undefined : assertSealedEnvelope(args.renewalCipher)
    if (renewalCipher !== undefined && tokenExpiresAt === undefined) {
      fail("INVALID_INPUT", "A renewable credential must include its access-token expiry.")
    }

    const existing = await ownedConnections(ctx, userId, connectorId)
    // Historical builds could leave duplicates. A reconnect is the safest time
    // to repair them because the human is explicitly replacing this connector's
    // credential. Keep the newest row and delete every older copy before return.
    const current = [...existing].sort((a, b) => b._creationTime - a._creationTime)[0]
    if (current !== undefined) {
      // Re-connecting is an update, not a second row: the gateway resolves one
      // credential per (owner, connector) and a duplicate would be a coin flip.
      await ctx.db.patch(current._id, {
        authType: args.authType,
        baseUrl,
        tokenCipher,
        tokenExpiresAt,
        renewalCipher,
        credentialVersion: (current.credentialVersion ?? 1) + 1,
        refreshLeaseId: undefined,
        refreshLeaseUntil: undefined,
        status: "active",
      })
      for (const duplicate of existing) {
        if (duplicate._id !== current._id) await ctx.db.delete(duplicate._id)
      }
      return { connectionId: current._id }
    }

    const connectionId = await ctx.db.insert("connections", {
      connectorId,
      ownerType: "user",
      ownerId: userId,
      authType: args.authType,
      status: "active",
      baseUrl,
      tokenCipher,
      credentialVersion: 1,
      ...(tokenExpiresAt === undefined ? {} : { tokenExpiresAt }),
      ...(renewalCipher === undefined ? {} : { renewalCipher }),
    })
    return { connectionId }
  },
})

/**
 * Idempotent: removing a connector that is not connected succeeds silently.
 * Reporting "not found" would turn this into an existence oracle, and the
 * caller's intent — "this connector must not be connected" — is satisfied
 * either way. Ownership comes from the session, so another user's row is not
 * reachable through this function at all.
 */
export const remove = mutation({
  args: { connectorId: v.string() },
  returns: v.null(),
  handler: async (ctx, args): Promise<null> => {
    const userId = await requireUser(ctx)
    const connectorId = assertIdentifier(args.connectorId, "connectorId")
    for (const connection of await ownedConnections(ctx, userId, connectorId)) {
      await ctx.db.delete(connection._id)
    }
    return null
  },
})

/** Bounded index read — the owner is the session user, never an argument. */
async function ownedConnections(
  ctx: MutationCtx,
  userId: string,
  connectorId: string,
): Promise<Doc<"connections">[]> {
  return await ctx.db
    .query("connections")
    .withIndex("by_owner_connector", (q) =>
      q.eq("ownerType", "user").eq("ownerId", userId).eq("connectorId", connectorId),
    )
    .take(MAX_CONNECTIONS_PER_CONNECTOR)
}

function assertOptionalTimestamp(value: number | undefined): number | undefined {
  if (value === undefined) return undefined
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail("INVALID_INPUT", "Credential expiry is invalid.")
  }
  return value
}
