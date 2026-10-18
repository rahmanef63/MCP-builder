/**
 * The parts of the connect flow that are not themselves Server Actions.
 *
 * Split out because a `"use server"` module may export nothing but async
 * functions — a shared type or a synchronous helper living there is a build
 * error, not a style choice.
 */
import { encodeOAuthRenewal, type AuthType, type OAuthRenewal } from "@cg/core"
import { fetchMutation, fetchQuery } from "convex/nextjs"
import { convexAuthNextjsToken } from "@convex-dev/auth/nextjs/server"

import { api } from "@convex/_generated/api"
import { manifestFor } from "@/lib/catalog"
export { collectCredential } from "@/lib/credential-fields"
import { sealCredential } from "@/lib/credentials"
import type { ConnectErrorCode } from "@/components/connections/labels"

export type ConnectFormState = {
  readonly error: ConnectErrorCode | null
  /** Connector id, set when this submission finished the job with no redirect. */
  readonly connected?: string
}

export const fail = (error: ConnectErrorCode): ConnectFormState => ({ error })

export type Viewer = {
  readonly token: string
  readonly userId: string
}

/** The caller's identity, proven by Convex rather than assumed from a cookie. */
export async function requireViewer(): Promise<Viewer | null> {
  try {
    const token = await convexAuthNextjsToken()
    if (typeof token !== "string" || token.length === 0) return null
    const userId = await fetchQuery(api.features.auth.identity.currentUserId, {}, { token })
    if (typeof userId !== "string" || userId.length === 0) return null
    return { token, userId }
  } catch {
    return null
  }
}

export async function requireViewerToken(): Promise<string | null> {
  return (await requireViewer())?.token ?? null
}

export function field(formData: FormData, name: string): string {
  const value = formData.get(name)
  return typeof value === "string" ? value.trim() : ""
}

export type Connectable = {
  readonly id: string
  /**
   * `null` when the manifest cannot know the address.
   *
   * Most connectors point at one public server, so the manifest names it and
   * the user is never asked. Some cannot: Composio issues a server per
   * configuration (`/v3/mcp/<SERVER_ID>?user_id=<USER_ID>`), and a self-hosted
   * upstream is only nameable by whoever runs it. For those the address is part
   * of the connection, not part of the connector — so the form asks, and
   * `assertUpstreamUrl` in the Convex mutation is what makes a user-supplied
   * URL safe to store and later call.
   */
  readonly endpoint: string | null
  readonly authType: AuthType
}

/** A cloud connector this build ships. `endpoint` is null when the user supplies it. */
export function connectable(connectorId: string): Connectable | null {
  const manifest = manifestFor(connectorId)
  if (manifest === null || manifest.executor !== "cloud") return null
  const endpoint =
    typeof manifest.endpoint === "string" && manifest.endpoint.length > 0
      ? manifest.endpoint
      : null
  return { id: manifest.id, endpoint, authType: manifest.auth.type }
}

/** True when the connect form has to ask for an address. */
export function needsEndpoint(connectorId: string): boolean {
  return connectable(connectorId)?.endpoint === null
}

/**
 * Seal, then write. The plaintext exists only in this function's frame: it is
 * never returned to the browser, never logged, and Convex receives ciphertext
 * it has no key for.
 */
export type ConnectionTokenOptions = {
  /** Overrides `target.endpoint`; required when the manifest has none. */
  readonly endpoint?: string
  /** Absolute epoch milliseconds supplied by the upstream token response. */
  readonly tokenExpiresAt?: number
  /** Sealed as one document; Convex never sees its secrets. */
  readonly renewal?: OAuthRenewal
}

export async function storeConnection(
  target: Connectable,
  plaintext: string,
  token: string,
  options: ConnectionTokenOptions = {},
): Promise<void> {
  const baseUrl = options.endpoint ?? target.endpoint
  if (baseUrl === null) {
    throw new Error("storeConnection called without an address")
  }
  const renewalCipher =
    options.renewal === undefined
      ? undefined
      : await sealCredential(encodeOAuthRenewal(options.renewal))
  await fetchMutation(
    api.features.connections.mutations.upsert,
    {
      connectorId: target.id,
      baseUrl,
      tokenCipher: await sealCredential(plaintext),
      authType: target.authType,
      ...(options.tokenExpiresAt === undefined ? {} : { tokenExpiresAt: options.tokenExpiresAt }),
      ...(renewalCipher === undefined ? {} : { renewalCipher }),
    },
    { token },
  )
}



/** Never surfaces a third party's error text — only a code this app owns. */
export function classify(error: unknown): ConnectErrorCode {
  const name = error instanceof Error ? error.name : ""
  if (name === "DiscoveryError") return "discovery_failed"
  if (name === "OAuthExchangeError") return "registration_failed"
  if (name === "SealUnavailableError") return "sealing_unavailable"
  return "start_failed"
}
