/**
 * The two POSTs of an authorization-code flow: registering a client when the
 * server offers it (RFC 7591), and redeeming the code for a token.
 *
 * Token responses preserve expiry and refresh-token material for the sealed
 * connection record. The browser never sees either token; the gateway later
 * renews an expiring credential under a control-plane lease.
 */
import { safeFetch, type FetchLike } from "@cg/transport"
import { toBase64Url } from "@cg/auth"
import { assertUpstreamEndpointUrl } from "@convex/_shared/upstream_url"

export type OAuthHttpOptions = { readonly fetcher?: FetchLike }

const TIMEOUT_MS = 10_000
const MAX_BYTES = 32 * 1024

export class OAuthExchangeError extends Error {
  constructor(readonly code: string, description?: string) {
    super(description === undefined ? code : `${code}: ${description}`)
    this.name = "OAuthExchangeError"
  }
}

async function postJson(
  url: string,
  body: string,
  contentType: string,
  options: OAuthHttpOptions,
): Promise<Record<string, unknown>> {
  let endpoint: string
  try {
    endpoint = assertUpstreamEndpointUrl(url)
  } catch {
    throw new OAuthExchangeError("invalid_endpoint")
  }
  let response: Response
  try {
    response = await (options.fetcher ?? safeFetch)(endpoint, {
      method: "POST",
      headers: { "content-type": contentType, accept: "application/json" },
      body,
      // A token POST must not carry a client secret or authorization code to a
      // destination selected by an upstream redirect.
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      cache: "no-store",
    })
  } catch {
    throw new OAuthExchangeError("network_error")
  }
  if (response.status >= 300 && response.status < 400) {
    throw new OAuthExchangeError("redirect_refused")
  }

  const text = await readBoundedText(response)
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new OAuthExchangeError("invalid_response")
  }
  const document = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {}
  if (!response.ok) {
    const error = typeof document["error"] === "string" ? document["error"] : `http_${response.status}`
    const description =
      typeof document["error_description"] === "string" ? document["error_description"] : undefined
    throw new OAuthExchangeError(error, description)
  }
  return document
}

async function readBoundedText(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length"))
  if (Number.isFinite(declared) && declared > MAX_BYTES) {
    throw new OAuthExchangeError("invalid_response")
  }
  if (response.body === null) return ""

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (value === undefined) continue
      total += value.byteLength
      if (total > MAX_BYTES) {
        void reader.cancel().catch(() => {})
        throw new OAuthExchangeError("invalid_response")
      }
      chunks.push(value)
    }
  } catch (error) {
    if (error instanceof OAuthExchangeError) throw error
    throw new OAuthExchangeError("network_error")
  }

  const joined = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    joined.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(joined)
}

export type RegisteredClient = { readonly clientId: string; readonly clientSecret: string | null }

/**
 * RFC 7591 open registration. This is what makes "click Connect" possible with
 * nothing typed: a server that offers it hands out a client id to anyone, and a
 * registration on its own grants no access — the user still has to consent.
 *
 * A server MAY return a secret. We keep it if so, because the token endpoint
 * will then demand it.
 */
export async function registerClient(
  registrationEndpoint: string,
  redirectUri: string,
  clientName: string,
  options: OAuthHttpOptions = {},
): Promise<RegisteredClient> {
  const document = await postJson(
    registrationEndpoint,
    JSON.stringify({
      client_name: clientName,
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
    "application/json",
    options,
  )
  const clientId = document["client_id"]
  if (typeof clientId !== "string" || clientId.length === 0) {
    throw new OAuthExchangeError("registration_failed", "no client_id in response")
  }
  const secret = document["client_secret"]
  return { clientId, clientSecret: typeof secret === "string" && secret.length > 0 ? secret : null }
}

/**
 * PKCE (RFC 7636). S256 only. `plain` is still legal in RFC 7636 and is
 * forbidden by OAuth 2.1; an authorization server that advertises only `plain`
 * is one we refuse rather than downgrade to.
 */
export type Pkce = { readonly verifier: string; readonly challenge: string }

/** 32 bytes -> 43 base64url characters, the length RFC 7636 §4.1 recommends. */
const VERIFIER_BYTES = 32

export async function createPkce(): Promise<Pkce> {
  const raw = new Uint8Array(VERIFIER_BYTES)
  crypto.getRandomValues(raw)
  const verifier = toBase64Url(raw)
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))
  return { verifier, challenge: toBase64Url(new Uint8Array(digest)) }
}

/**
 * The `state` parameter. Its only job is to prove the callback belongs to the
 * flow this browser started — it is compared against the copy inside the sealed
 * state cookie, so a code delivered to a callback nobody initiated is dropped.
 */
export function createState(): string {
  return crypto.randomUUID()
}

export type AuthorizeParams = {
  readonly authorizationEndpoint: string
  readonly clientId: string
  readonly redirectUri: string
  readonly challenge: string
  readonly state: string
  readonly scope: string | null
  readonly resource: string
}

/** The URL the browser is sent to. Nothing secret is in it — by design. */
export function authorizeUrl(params: AuthorizeParams): string {
  const url = new URL(params.authorizationEndpoint)
  url.searchParams.set("response_type", "code")
  url.searchParams.set("client_id", params.clientId)
  url.searchParams.set("redirect_uri", params.redirectUri)
  url.searchParams.set("code_challenge", params.challenge)
  url.searchParams.set("code_challenge_method", "S256")
  url.searchParams.set("state", params.state)
  // RFC 8707: bind the token to the one resource it may be spent against, so a
  // token minted for this connector cannot be replayed at another.
  url.searchParams.set("resource", params.resource)
  if (params.scope !== null) url.searchParams.set("scope", params.scope)
  return url.toString()
}

export type ClientCredentialsParams = {
  readonly tokenEndpoint: string
  readonly clientId: string
  readonly clientSecret: string
  readonly scope: string | null
  readonly resource: string
}

/**
 * RFC 6749 §4.4, kept in OAuth 2.1 for exactly this case: a credential that
 * belongs to a machine, not to a browser session. No redirect, no consent
 * screen, no PKCE — the secret IS the proof — so a connector whose server
 * offers this grant is connected by pasting two values and pressing a button.
 *
 * Only ever used when the server ADVERTISES the grant. Sending it speculatively
 * to a server that does not support it produces an `unsupported_grant_type`
 * that would read to the user as "your credentials are wrong".
 */
export async function clientCredentialsGrant(
  params: ClientCredentialsParams,
  options: OAuthHttpOptions = {},
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: params.clientId,
    client_secret: params.clientSecret,
    resource: params.resource,
  })
  if (params.scope !== null) body.set("scope", params.scope)

  const document = await postJson(
    params.tokenEndpoint,
    body.toString(),
    "application/x-www-form-urlencoded",
    options,
  )
  return readToken(document)
}

export type ExchangeParams = {
  readonly tokenEndpoint: string
  readonly code: string
  readonly redirectUri: string
  readonly clientId: string
  readonly clientSecret: string | null
  readonly verifier: string
  readonly resource: string
}

/** Secrets and lifetime returned by a token endpoint. Never sent to the browser. */
export type TokenResponse = {
  readonly accessToken: string
  readonly expiresIn: number | null
  readonly refreshToken: string | null
}

/** Convert a valid relative lifetime to an absolute millisecond timestamp. */
export function tokenExpiresAt(response: TokenResponse, now = Date.now()): number | null {
  if (response.expiresIn === null) return null
  const value = now + response.expiresIn * 1_000
  return Number.isFinite(value) && value > now ? value : null
}

export async function exchangeCode(params: ExchangeParams, options: OAuthHttpOptions = {}): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    // Identical to the value sent to /authorize — the server compares them, and
    // a mismatch is how a code stolen from one callback is stopped at another.
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.verifier,
    resource: params.resource,
  })
  if (params.clientSecret !== null) body.set("client_secret", params.clientSecret)

  const document = await postJson(
    params.tokenEndpoint,
    body.toString(),
    "application/x-www-form-urlencoded",
    options,
  )
  return readToken(document)
}

/** A 200 with no `access_token` is a failure, not an empty credential. */
function readToken(document: Record<string, unknown>): TokenResponse {
  const token = document["access_token"]
  if (typeof token !== "string" || token.length === 0) {
    throw new OAuthExchangeError("invalid_response", "no access_token")
  }
  const expires = document["expires_in"]
  const expiresIn =
    typeof expires === "number" && Number.isFinite(expires) && expires > 0 ? expires : null
  const refresh = document["refresh_token"]
  const refreshToken = typeof refresh === "string" && refresh.length > 0 ? refresh : null
  return { accessToken: token, expiresIn, refreshToken }
}
