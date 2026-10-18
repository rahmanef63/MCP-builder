/**
 * Authorization-server discovery: RFC 9728 (protected resource metadata) then
 * RFC 8414 (authorization server metadata).
 *
 * This is the reason a connector needs no per-vendor code. 22 of 27 SaaS MCP
 * servers probed for docs/16 answer an unauthenticated call with
 * `WWW-Authenticate: Bearer resource_metadata="…"`, and everything the connect
 * flow needs — where to send the user, where to redeem the code, whether the
 * server will register a client for us — is in the two documents this walks.
 *
 * Every URL fetched here is server-side and derived from a document a third
 * party controls, so each one goes through the SAME SSRF gate the control plane
 * applies to a stored base URL. Without that, "token_endpoint":
 * "http://169.254.169.254/latest/meta-data/" is a cloud-credential read.
 */
import { assertUpstreamUrl } from "@convex/_shared/upstream_url"

export type AuthServer = {
  readonly issuer: string
  readonly authorizationEndpoint: string
  readonly tokenEndpoint: string
  /** RFC 7591. Present means we can obtain a client id without a human. */
  readonly registrationEndpoint: string | null
  /**
   * `grant_types_supported`. The one that matters here is
   * `client_credentials`: a server offering it can issue a token from an id and
   * a secret alone, with no browser round trip and no consent screen — which is
   * the whole connect flow reduced to two fields and one button.
   */
  readonly grantTypes: readonly string[]
  readonly scope: string | null
  /** RFC 8707 — the resource the token must be audience-bound to. */
  readonly resource: string
}

export class DiscoveryError extends Error {
  constructor(readonly reason: string) {
    super(`OAuth discovery failed: ${reason}`)
    this.name = "DiscoveryError"
  }
}

const TIMEOUT_MS = 8000
/** Metadata documents are a few hundred bytes; anything huge is not one. */
const MAX_BYTES = 64 * 1024

async function getJson(url: string): Promise<Record<string, unknown> | null> {
  try {
    const response = await fetch(url, {
      headers: { accept: "application/json" },
      // A redirect target has not passed the upstream URL gate.
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      cache: "no-store",
    })
    const declared = Number(response.headers.get("content-length"))
    if (!response.ok || (Number.isFinite(declared) && declared > MAX_BYTES)) {
      void response.body?.cancel().catch(() => {})
      return null
    }
    if (response.body === null) return null

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
          return null
        }
        chunks.push(value)
      }
    } finally {
      reader.releaseLock()
    }

    const bytes = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      bytes.set(chunk, offset)
      offset += chunk.byteLength
    }
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null
  } catch {
    // A failed body read, including a timeout, can try the next well-known URL.
    return null
  }
}

/**
 * RFC 9728 §3.1 and RFC 8414 §3.1 both insert the well-known segment BEFORE the
 * resource path (`/.well-known/x/mcp`, not `/mcp/.well-known/x`). Plenty of
 * servers only publish the path-less form, so both are tried, in spec order.
 */
function wellKnownUrls(base: string, suffix: string): string[] {
  const url = new URL(base)
  const path = url.pathname.replace(/\/+$/, "")
  const rooted = `${url.origin}/.well-known/${suffix}`
  return path.length > 0 && path !== "/" ? [`${rooted}${path}`, rooted] : [rooted]
}

async function firstDocument(urls: string[]): Promise<Record<string, unknown> | null> {
  for (const url of urls) {
    const document = await getJson(assertUpstreamUrl(url))
    if (document !== null) return document
  }
  return null
}

function readString(document: Record<string, unknown>, key: string): string | null {
  const value = document[key]
  return typeof value === "string" && value.length > 0 ? value : null
}

/** A metadata endpoint we are about to call, or a typed refusal. */
function endpointOrThrow(raw: string | null, label: string): string {
  if (raw === null) throw new DiscoveryError(`${label} missing`)
  try {
    return assertUpstreamUrl(raw)
  } catch {
    throw new DiscoveryError(`${label} is not a reachable https URL`)
  }
}

/**
 * `resourceUrl` is the connector's MCP endpoint — the thing a token will be
 * spent against, and the value RFC 8707 wants echoed as `resource`.
 */
export async function discoverAuthServer(resourceUrl: string): Promise<AuthServer> {
  const resource = assertUpstreamUrl(resourceUrl)

  const prm = await firstDocument(wellKnownUrls(resource, "oauth-protected-resource"))
  if (prm === null) throw new DiscoveryError("no protected-resource metadata")

  const servers = prm["authorization_servers"]
  const issuerRaw = Array.isArray(servers) && typeof servers[0] === "string" ? servers[0] : null
  const issuer = endpointOrThrow(issuerRaw, "authorization_servers")

  const asDocument = await firstDocument([
    ...wellKnownUrls(issuer, "oauth-authorization-server"),
    ...wellKnownUrls(issuer, "openid-configuration"),
  ])
  if (asDocument === null) throw new DiscoveryError("no authorization-server metadata")

  // RFC 8414 §3.3: the issuer inside the document must be the one we asked
  // about. A mismatch means the document describes a different server, which is
  // how a mix-up attack starts.
  if (readString(asDocument, "issuer") !== issuer) {
    throw new DiscoveryError("issuer mismatch")
  }

  const methods = asDocument["code_challenge_methods_supported"]
  if (!Array.isArray(methods) || !methods.includes("S256")) {
    // OAuth 2.1 requires PKCE; we will not fall back to `plain`.
    throw new DiscoveryError("server does not support PKCE S256")
  }

  const scopes = prm["scopes_supported"] ?? asDocument["scopes_supported"]
  const registration = readString(asDocument, "registration_endpoint")
  const grants = asDocument["grant_types_supported"]

  return {
    issuer,
    authorizationEndpoint: endpointOrThrow(
      readString(asDocument, "authorization_endpoint"),
      "authorization_endpoint",
    ),
    tokenEndpoint: endpointOrThrow(readString(asDocument, "token_endpoint"), "token_endpoint"),
    registrationEndpoint: registration === null ? null : endpointOrThrow(registration, "registration_endpoint"),
    // RFC 8414 §2: absent means `["authorization_code", "implicit"]`. Implicit
    // is gone in OAuth 2.1 and unused here, so the default is the code grant.
    grantTypes: Array.isArray(grants)
      ? grants.filter((grant): grant is string => typeof grant === "string")
      : ["authorization_code"],
    scope: Array.isArray(scopes) ? scopes.filter((s) => typeof s === "string").join(" ") : null,
    resource,
  }
}
