/**
 * OAuth token renewal against an upstream authorization server.
 *
 * The caller supplies decrypted renewal metadata and receives plaintext only in
 * this function's return value; the connection store seals it immediately. No
 * provider body, token, client secret, or refresh token is ever logged or placed
 * in an error message.
 */
import { safeFetch } from "@cg/transport"
import {
  OAUTH_REFRESH_SKEW_MS,
  normalizeUpstreamEndpointUrl,
  upstreamUrlPolicyFromEnvironment,
  type OAuthRenewal,
} from "@cg/core"

const TIMEOUT_MS = 10_000
const MAX_RESPONSE_BYTES = 64 * 1024

export type RefreshedOAuthToken = {
  readonly accessToken: string
  readonly tokenExpiresAt?: number
  readonly renewal: OAuthRenewal
}

export class OAuthRefreshError extends Error {
  constructor(
    readonly code: string,
    readonly permanent: boolean,
  ) {
    super("The upstream OAuth credential could not be renewed.")
    this.name = "OAuthRefreshError"
  }
}

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>

export type RefreshHttpOptions = {
  readonly fetcher?: FetchLike
  readonly now?: () => number
}

export async function refreshOAuthToken(
  renewal: OAuthRenewal,
  options: RefreshHttpOptions = {},
): Promise<RefreshedOAuthToken> {
  const endpoint = safeTokenEndpoint(renewal.tokenEndpoint)
  const body = new URLSearchParams({
    grant_type: renewal.grantType,
    client_id: renewal.clientId,
    resource: renewal.resource,
  })
  if (renewal.scope !== null) body.set("scope", renewal.scope)

  if (renewal.grantType === "refresh_token") {
    body.set("refresh_token", renewal.refreshToken)
    if (renewal.clientSecret !== null) body.set("client_secret", renewal.clientSecret)
  } else {
    body.set("client_secret", renewal.clientSecret)
  }

  let response: Response
  try {
    response = await (options.fetcher ?? safeFetch)(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: body.toString(),
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  } catch {
    throw new OAuthRefreshError("network_error", false)
  }

  if (response.status >= 300 && response.status < 400) {
    throw new OAuthRefreshError("redirect_refused", true)
  }

  const document = await readDocument(response)
  if (!response.ok) {
    const code = typeof document.error === "string" ? document.error : `http_${response.status}`
    throw new OAuthRefreshError(code, permanentFailure(response.status, code))
  }

  const accessToken = document.access_token
  if (typeof accessToken !== "string" || accessToken.length === 0) {
    throw new OAuthRefreshError("invalid_response", false)
  }
  // RFC 6749 §6: if a refresh response includes `scope`, it describes the
  // access token that was actually issued. A provider silently dropping one of
  // the scopes we require must never turn into a seemingly healthy connection.
  assertNoScopeDowngrade(renewal.scope, document.scope)
  const expiresIn =
    typeof document.expires_in === "number" &&
    Number.isFinite(document.expires_in) &&
    document.expires_in > 0
      ? document.expires_in
      : null
  const now = (options.now ?? Date.now)()
  const tokenExpiresAt =
    expiresIn === null || !Number.isFinite(now + expiresIn * 1_000)
      ? undefined
      : now + expiresIn * 1_000

  let nextRenewal = renewal
  if (
    renewal.grantType === "refresh_token" &&
    typeof document.refresh_token === "string" &&
    document.refresh_token.length > 0
  ) {
    nextRenewal = { ...renewal, refreshToken: document.refresh_token }
  }

  return {
    accessToken,
    ...(tokenExpiresAt === undefined ? {} : { tokenExpiresAt }),
    renewal: nextRenewal,
  }
}

function assertNoScopeDowngrade(requested: string | null, returned: unknown): void {
  if (requested === null || returned === undefined) return
  if (typeof returned !== "string") throw new OAuthRefreshError("invalid_scope", true)
  const required = scopeSet(requested)
  const granted = scopeSet(returned)
  for (const scope of required) {
    if (!granted.has(scope)) throw new OAuthRefreshError("invalid_scope", true)
  }
}

function scopeSet(value: string): ReadonlySet<string> {
  const scopes = value.trim().split(/\s+/).filter(Boolean)
  if (scopes.some((scope) => /[\u0000-\u0020\u007f]/.test(scope))) {
    throw new OAuthRefreshError("invalid_scope", true)
  }
  return new Set(scopes)
}

/** Shared predicate used before acquiring a control-plane lease. */
export function credentialNeedsRefresh(tokenExpiresAt: number | undefined, now = Date.now()): boolean {
  return tokenExpiresAt !== undefined && tokenExpiresAt <= now + OAUTH_REFRESH_SKEW_MS
}

function permanentFailure(status: number, code: string): boolean {
  if (["temporarily_unavailable", "server_error"].includes(code)) return false
  if (status >= 500 || status === 408 || status === 429) return false
  return [
    "invalid_grant",
    "invalid_client",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
  ].includes(code) || (status >= 400 && status < 500)
}

async function readDocument(response: Response): Promise<Record<string, unknown>> {
  const declared = Number(response.headers.get("content-length"))
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new OAuthRefreshError("invalid_response", false)
  }
  if (response.body === null) throw new OAuthRefreshError("invalid_response", false)

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (value === undefined) continue
      total += value.byteLength
      if (total > MAX_RESPONSE_BYTES) {
        void reader.cancel().catch(() => {})
        throw new OAuthRefreshError("invalid_response", false)
      }
      chunks.push(value)
    }
  } catch (error) {
    if (error instanceof OAuthRefreshError) throw error
    throw new OAuthRefreshError("network_error", false)
  }

  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new OAuthRefreshError("invalid_response", false)
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new OAuthRefreshError("invalid_response", false)
  }
  return parsed as Record<string, unknown>
}

function safeTokenEndpoint(raw: string): string {
  try {
    return normalizeUpstreamEndpointUrl(raw, upstreamUrlPolicyFromEnvironment(process.env))
  } catch {
    throw new OAuthRefreshError("invalid_endpoint", true)
  }
}
