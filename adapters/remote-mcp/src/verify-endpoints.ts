/**
 * Credential-free production endpoint verification for shipped remote MCP connectors.
 *
 * A URL can be syntactically valid, answer OAuth discovery correctly, and still be the
 * wrong deployment. This verifier pins the complete chain we reviewed:
 *
 *   MCP endpoint -> WWW-Authenticate resource_metadata -> protected resource metadata
 *   -> authorization server metadata -> browser and token endpoints
 *
 * It sends only an unauthenticated MCP initialize probe. Redirects are never followed,
 * response bodies are bounded, and no connection credential is read or transmitted.
 */
import { safeFetch, type FetchLike } from "@cg/transport"
import type {
  ConnectorEndpointVerification,
  ConnectorManifest,
} from "@cg/core"
import { REMOTE_MCP_MANIFESTS } from "./connectors"

const METADATA_LIMIT_BYTES = 65_536
const REQUEST_TIMEOUT_MS = 10_000
const PROTOCOL_VERSION = "2025-06-18"

type JsonRecord = Record<string, unknown>

export type EndpointVerificationResult = {
  connectorId: string
  endpoint: string
  authorizationServer: string
  authorizationEndpoint: string
  tokenEndpoint: string
}

export async function verifyRemoteEndpoints(
  manifests: readonly ConnectorManifest[] = REMOTE_MCP_MANIFESTS,
  fetcher: FetchLike = safeFetch,
): Promise<EndpointVerificationResult[]> {
  const results: EndpointVerificationResult[] = []
  for (const manifest of manifests) {
    if (manifest.endpoint === undefined) continue
    if (manifest.verification === undefined) {
      throw failure(manifest.id, "a fixed endpoint has no reviewed production verification block")
    }
    results.push(await verifyRemoteEndpoint(manifest, fetcher))
  }
  return results
}

export async function verifyRemoteEndpoint(
  manifest: ConnectorManifest,
  fetcher: FetchLike = safeFetch,
): Promise<EndpointVerificationResult> {
  const expected = requireExpected(manifest)
  const endpoint = productionUrl(manifest.id, manifest.endpoint, "endpoint")
  const resourceMetadata = productionUrl(
    manifest.id,
    expected.resourceMetadata,
    "resource metadata URL",
  )
  const authorizationServer = productionOrigin(
    manifest.id,
    expected.authorizationServer,
    "authorization server",
  )
  const authorizationEndpoint = productionUrl(
    manifest.id,
    expected.authorizationEndpoint,
    "authorization endpoint",
  )
  const tokenEndpoint = productionUrl(
    manifest.id,
    expected.tokenEndpoint,
    "token endpoint",
  )
  const registrationEndpoint =
    expected.registrationEndpoint === undefined
      ? undefined
      : productionUrl(
          manifest.id,
          expected.registrationEndpoint,
          "registration endpoint",
        )

  const challenge = await request(
    manifest.id,
    fetcher,
    endpoint,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": PROTOCOL_VERSION,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: "connector-gateway-endpoint-verifier", version: "0.4.0" },
        },
      }),
    },
    "MCP endpoint",
  )
  if (challenge.status !== 401) {
    throw failure(manifest.id, `MCP endpoint returned HTTP ${challenge.status}, expected 401`)
  }

  const discoveredMetadata = resourceMetadataFromChallenge(
    manifest.id,
    challenge.headers.get("www-authenticate"),
  )
  if (productionUrl(manifest.id, discoveredMetadata, "discovered resource metadata URL") !== resourceMetadata) {
    throw failure(manifest.id, "MCP challenge points at unexpected resource metadata")
  }

  const resourceResponse = await request(
    manifest.id,
    fetcher,
    resourceMetadata,
    { method: "GET", headers: { accept: "application/json" } },
    "protected resource metadata",
  )
  const resourceDocument = await metadataDocument(
    manifest.id,
    resourceResponse,
    "protected resource metadata",
  )
  const discoveredResource = stringField(
    manifest.id,
    resourceDocument,
    "resource",
    "protected resource metadata",
  )
  if (productionUrl(manifest.id, discoveredResource, "discovered MCP resource") !== endpoint) {
    throw failure(manifest.id, "protected resource metadata names an unexpected MCP endpoint")
  }

  const servers = stringArrayField(
    manifest.id,
    resourceDocument,
    "authorization_servers",
    "protected resource metadata",
  ).map((value) => productionOrigin(manifest.id, value, "discovered authorization server"))
  if (servers.length !== 1 || servers[0] !== authorizationServer) {
    throw failure(manifest.id, "protected resource metadata names an unexpected authorization server")
  }

  const authorizationMetadataUrl = `${authorizationServer}/.well-known/oauth-authorization-server`
  const authorizationResponse = await request(
    manifest.id,
    fetcher,
    authorizationMetadataUrl,
    { method: "GET", headers: { accept: "application/json" } },
    "authorization server metadata",
  )
  const authorizationDocument = await metadataDocument(
    manifest.id,
    authorizationResponse,
    "authorization server metadata",
  )

  const issuer = productionOrigin(
    manifest.id,
    stringField(manifest.id, authorizationDocument, "issuer", "authorization server metadata"),
    "discovered issuer",
  )
  if (issuer !== authorizationServer) {
    throw failure(manifest.id, "authorization metadata issuer does not match the reviewed server")
  }

  assertEndpointField(
    manifest.id,
    authorizationDocument,
    "authorization_endpoint",
    authorizationEndpoint,
  )
  assertEndpointField(manifest.id, authorizationDocument, "token_endpoint", tokenEndpoint)
  if (registrationEndpoint !== undefined) {
    assertEndpointField(
      manifest.id,
      authorizationDocument,
      "registration_endpoint",
      registrationEndpoint,
    )
  }

  return {
    connectorId: manifest.id,
    endpoint,
    authorizationServer,
    authorizationEndpoint,
    tokenEndpoint,
  }
}

function requireExpected(manifest: ConnectorManifest): ConnectorEndpointVerification {
  if (manifest.endpoint === undefined || manifest.verification === undefined) {
    throw failure(manifest.id, "endpoint verification is not configured")
  }
  if (manifest.verification.environment !== "production") {
    throw failure(manifest.id, "endpoint verification is not marked production")
  }
  return manifest.verification
}

async function request(
  connectorId: string,
  fetcher: FetchLike,
  url: string,
  init: RequestInit,
  label: string,
): Promise<Response> {
  let response: Response
  try {
    response = await fetcher(url, {
      ...init,
      redirect: "manual",
      signal: init.signal ?? AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
  } catch {
    throw failure(connectorId, `${label} is unreachable`)
  }
  if ((response.status >= 300 && response.status < 400) || response.type === "opaqueredirect") {
    throw failure(connectorId, `${label} redirected; the destination was not followed`)
  }
  return response
}

async function metadataDocument(
  connectorId: string,
  response: Response,
  label: string,
): Promise<JsonRecord> {
  if (response.status !== 200) {
    throw failure(connectorId, `${label} returned HTTP ${response.status}, expected 200`)
  }
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? ""
  if (!contentType.includes("application/json")) {
    throw failure(connectorId, `${label} did not return JSON`)
  }
  const raw = await readBounded(connectorId, response, label)
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    throw failure(connectorId, `${label} returned malformed JSON`)
  }
  if (!isRecord(value)) {
    throw failure(connectorId, `${label} returned a non-object document`)
  }
  return value
}

async function readBounded(
  connectorId: string,
  response: Response,
  label: string,
): Promise<string> {
  const declared = Number(response.headers.get("content-length"))
  if (Number.isFinite(declared) && declared > METADATA_LIMIT_BYTES) {
    throw failure(connectorId, `${label} exceeded the metadata size limit`)
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
      if (total > METADATA_LIMIT_BYTES) {
        void reader.cancel().catch(() => {})
        throw failure(connectorId, `${label} exceeded the metadata size limit`)
      }
      chunks.push(value)
    }
  } catch (cause) {
    if (cause instanceof Error && cause.name === "EndpointVerificationError") throw cause
    throw failure(connectorId, `${label} could not be read safely`)
  }

  const joined = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    joined.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(joined)
}

function resourceMetadataFromChallenge(connectorId: string, header: string | null): string {
  const match = /\bresource_metadata\s*=\s*"([^"\r\n]+)"/i.exec(header ?? "")
  if (match?.[1] === undefined) {
    throw failure(connectorId, "MCP challenge did not advertise resource_metadata")
  }
  return match[1]
}

function assertEndpointField(
  connectorId: string,
  document: JsonRecord,
  field: string,
  expected: string,
): void {
  const actual = productionUrl(
    connectorId,
    stringField(connectorId, document, field, "authorization server metadata"),
    `discovered ${field}`,
  )
  if (actual !== expected) {
    throw failure(connectorId, `authorization metadata ${field} does not match the reviewed endpoint`)
  }
}

function stringField(
  connectorId: string,
  document: JsonRecord,
  field: string,
  label: string,
): string {
  const value = document[field]
  if (typeof value !== "string" || value.length === 0) {
    throw failure(connectorId, `${label} is missing ${field}`)
  }
  return value
}

function stringArrayField(
  connectorId: string,
  document: JsonRecord,
  field: string,
  label: string,
): string[] {
  const value = document[field]
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string")) {
    throw failure(connectorId, `${label} has an invalid ${field}`)
  }
  return value as string[]
}

function productionUrl(connectorId: string, raw: string | undefined, label: string): string {
  if (raw === undefined) throw failure(connectorId, `${label} is missing`)
  const url = parseProductionUrl(connectorId, raw, label)
  return url.href
}

function productionOrigin(connectorId: string, raw: string, label: string): string {
  const url = parseProductionUrl(connectorId, raw, label)
  if (url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    throw failure(connectorId, `${label} must be an origin, not a path`)
  }
  return url.origin
}

function parseProductionUrl(connectorId: string, raw: string, label: string): URL {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw failure(connectorId, `${label} is not an absolute URL`)
  }
  const originalHost = url.hostname.toLowerCase()
  const host = originalHost.replace(/\.+$/, "")
  if (host.length === 0) throw failure(connectorId, `${label} has no host`)
  if (host !== originalHost) url.hostname = host

  if (url.protocol !== "https:") throw failure(connectorId, `${label} must use HTTPS`)
  if (url.username !== "" || url.password !== "") {
    throw failure(connectorId, `${label} must not contain credentials`)
  }
  if (url.port !== "" && url.port !== "443") {
    throw failure(connectorId, `${label} must use the default HTTPS port`)
  }
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    !host.includes(".") ||
    /^\d+(?:\.\d+){3}$/.test(host) ||
    host.startsWith("[")
  ) {
    throw failure(connectorId, `${label} must use a reviewed public DNS name`)
  }
  if (url.hash !== "") throw failure(connectorId, `${label} must not contain a fragment`)
  return url
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function failure(connectorId: string, message: string): Error {
  const error = new Error(`${connectorId}: ${message}`)
  error.name = "EndpointVerificationError"
  return error
}

async function main(): Promise<void> {
  const results = await verifyRemoteEndpoints()
  for (const result of results) {
    console.log(
      `verified ${result.connectorId}: ${result.endpoint} -> ${result.authorizationServer}`,
    )
  }
  console.log(`verified ${results.length} fixed production endpoint(s) without credentials`)
}

if (import.meta.main) {
  main().catch((cause: unknown) => {
    const message = cause instanceof Error ? cause.message : "unknown endpoint verification failure"
    console.error(`remote endpoint verification failed: ${message}`)
    process.exitCode = 1
  })
}
