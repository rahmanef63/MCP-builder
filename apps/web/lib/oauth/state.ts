/**
 * The flow state that has to survive a round trip through someone else's
 * consent screen: the PKCE verifier, the client credentials in use, and where
 * to redeem the code.
 *
 * It lives in ONE sealed httpOnly cookie rather than a database table. The
 * table would need a schema, an index, a TTL and a sweeper for rows abandoned
 * by every user who opened a consent screen and closed the tab; the cookie
 * expires by itself and the browser holds ciphertext this process alone can
 * open. `state` travels inside the sealed blob AND in the URL, and the callback
 * refuses unless they match, which is what makes a code delivered to a callback
 * nobody started useless.
 *
 * ponytail: one flow at a time per browser — starting a second connect
 * overwrites the first. Give the cookie a per-flow name if parallel connects
 * ever matter.
 */
import { cookies } from "next/headers"

import { sealCredential, unsealCredential } from "@/lib/credentials"

export const OAUTH_STATE_COOKIE = "cg_oauth"
/** Long enough to read a consent screen, short enough to be worthless if stolen. */
const TTL_SECONDS = 600

export type OAuthFlowState = {
  readonly v: 1
  /** Convex user who initiated this flow; sessions may refresh during consent. */
  readonly userId: string
  readonly connectorId: string
  readonly state: string
  readonly verifier: string
  readonly clientId: string
  readonly clientSecret: string | null
  readonly tokenEndpoint: string
  readonly redirectUri: string
  readonly resource: string
  /** Scope originally requested; reused only by a future refresh grant. */
  readonly scope: string | null
  /** Epoch seconds. Checked on the way back in — a cookie is not a clock. */
  readonly exp: number
}

export async function writeFlowState(state: Omit<OAuthFlowState, "v" | "exp">): Promise<void> {
  const payload: OAuthFlowState = {
    v: 1,
    ...state,
    exp: Math.floor(Date.now() / 1000) + TTL_SECONDS,
  }
  const store = await cookies()
  store.set(OAUTH_STATE_COOKIE, await sealCredential(JSON.stringify(payload)), {
    httpOnly: true,
    // Lax, not Strict: the browser arrives here on a top-level navigation from
    // the authorization server, and Strict would withhold the cookie exactly
    // then. Lax still withholds it from cross-site POSTs and subresources.
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/oauth",
    maxAge: TTL_SECONDS,
  })
}

export async function clearFlowState(): Promise<void> {
  const store = await cookies()
  store.delete({ name: OAUTH_STATE_COOKIE, path: "/oauth" })
}

/** The parsed flow, or null for anything absent, tampered with, or expired. */
export async function readFlowState(): Promise<OAuthFlowState | null> {
  const store = await cookies()
  const sealed = store.get(OAUTH_STATE_COOKIE)?.value
  if (sealed === undefined || sealed.length === 0) return null
  try {
    return parseFlowState(await unsealCredential(sealed), Date.now())
  } catch {
    // A failed tag check and a missing key look the same on purpose.
    return null
  }
}

/** Split out from the cookie read so it can be tested without a request. */
export function parseFlowState(json: string, nowMs: number): OAuthFlowState | null {
  let value: unknown
  try {
    value = JSON.parse(json)
  } catch {
    return null
  }
  if (typeof value !== "object" || value === null) return null
  const record = value as Record<string, unknown>
  if (record["v"] !== 1) return null
  if (typeof record["exp"] !== "number" || record["exp"] * 1000 < nowMs) return null

  for (const key of ["userId", "connectorId", "state", "verifier", "clientId", "tokenEndpoint", "redirectUri", "resource"]) {
    if (typeof record[key] !== "string" || (record[key] as string).length === 0) return null
  }
  const secret = record["clientSecret"]
  if (secret !== null && typeof secret !== "string") return null
  const scope = record["scope"]
  // Compatibility for a flow cookie minted by the previous deployment during
  // its ten-minute lifetime: missing scope means the server advertised none.
  if (scope !== undefined && scope !== null && typeof scope !== "string") return null

  return { ...(record as unknown as OAuthFlowState), scope: typeof scope === "string" ? scope : null }
}
