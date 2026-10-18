/**
 * Remote MCP Streamable HTTP client.
 *
 * It prefers the standard initialize -> notifications/initialized -> tools/call
 * lifecycle, propagates Mcp-Session-Id when a server issues one, and accepts
 * JSON or SSE responses. Older reviewed servers that explicitly do not expose
 * initialize (HTTP 404/405 or JSON-RPC method-not-found) retain the historical
 * single-shot tools/call compatibility path.
 */
import { GatewayError, normalizeUpstreamEndpointUrl, upstreamUrlPolicyFromEnvironment } from "@cg/core"
import { safeFetch } from "@cg/transport"
import type { FetchLike } from "@cg/transport"
import { parseRpcBody, readToolResult } from "./mcp-parse"

export const MCP_PROTOCOL_VERSION = "2025-06-18"
export const MAX_RESPONSE_BYTES = 1_048_576
export const MAX_LARGE_RESPONSE_BYTES = 8_388_608
const MAX_SESSION_ID_LENGTH = 256
let requestCounter = 0

export type RemoteMcpOptions = { fetcher?: FetchLike }

export type CredentialHeader = { name: string; value: string }
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/
const SESSION_ID = /^[\x21-\x7e]{1,256}$/

type RpcResponse = { response: Response; raw: string; id: number }
type InitResult = { mode: "session"; sessionId?: string } | { mode: "legacy" }

class RetryableRemoteMcpError extends GatewayError {}
export function isRetryableRemoteMcpError(cause: unknown): boolean {
  return cause instanceof RetryableRemoteMcpError
}

export function credentialHeaderFor(
  auth: { header?: string; scheme?: string } | undefined,
  token: string,
): CredentialHeader {
  const name = auth?.header?.trim() || "Authorization"
  if (!HEADER_NAME.test(name)) {
    throw new GatewayError("INVALID_INPUT", "The connector declares an unusable auth header.")
  }
  const fallback = name.toLowerCase() === "authorization" ? "Bearer " : ""
  const scheme = auth?.scheme ?? fallback
  return { name, value: `${scheme}${token}` }
}

export async function callTool(
  baseUrl: string,
  token: string,
  name: string,
  args: Record<string, unknown>,
  signal: AbortSignal,
  credentialHeader?: CredentialHeader,
  maxResponseBytes: number = MAX_RESPONSE_BYTES,
  options: RemoteMcpOptions = {},
): Promise<unknown> {
  const endpoint = endpointFor(baseUrl)
  const fetcher = options.fetcher ?? safeFetch
  const responseLimit = boundedResponseLimit(maxResponseBytes)
  if (signal.aborted) throw cancelled()
  const cred = credentialHeader ?? credentialHeaderFor(undefined, token)

  const initialized = await initialize(endpoint, cred, signal, responseLimit, fetcher)
  if (initialized.mode === "session") {
    await sendInitialized(endpoint, cred, signal, fetcher, initialized.sessionId)
  }
  const call = await postRpc(
    endpoint,
    cred,
    signal,
    {
      jsonrpc: "2.0",
      id: nextRequestId(),
      method: "tools/call",
      params: { name, arguments: args },
    },
    responseLimit,
    fetcher,
    initialized.mode === "session" ? initialized.sessionId : undefined,
  )
  assertUsableResponse(call.response)
  return readToolResult(parseRpcBody(call.raw, call.response.headers.get("content-type"), call.id), token)
}

async function initialize(
  endpoint: URL,
  cred: CredentialHeader,
  signal: AbortSignal,
  responseLimit: number,
  fetcher: FetchLike,
): Promise<InitResult> {
  const id = nextRequestId()
  const rpc = await postRpc(endpoint, cred, signal, {
    jsonrpc: "2.0",
    id,
    method: "initialize",
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "connectors-gateway", version: "0.4.0" },
    },
  }, responseLimit, fetcher, undefined, true)

  if (rpc.response.status === 404 || rpc.response.status === 405) return { mode: "legacy" }
  assertUsableResponse(rpc.response)
  const envelope = parseRpcBody(rpc.raw, rpc.response.headers.get("content-type"), id)
  if (isMethodNotFound(envelope)) return { mode: "legacy" }
  assertInitializeResult(envelope)
  const sessionId = readSessionId(rpc.response.headers.get("mcp-session-id"))
  return sessionId === undefined ? { mode: "session" } : { mode: "session", sessionId }
}

async function sendInitialized(
  endpoint: URL,
  cred: CredentialHeader,
  signal: AbortSignal,
  fetcher: FetchLike,
  sessionId?: string,
): Promise<void> {
  const response = await postNotification(endpoint, cred, signal, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  }, fetcher, sessionId)
  // Notifications normally return 202/204, but servers may return an empty 200.
  if (response.status >= 200 && response.status < 300) return
  assertUsableResponse(response)
}

async function postRpc(
  endpoint: URL,
  cred: CredentialHeader,
  signal: AbortSignal,
  payload: Record<string, unknown>,
  responseLimit: number,
  fetcher: FetchLike,
  sessionId?: string,
  allowLegacyStatus = false,
): Promise<RpcResponse> {
  const id = payload["id"] as number
  const response = await doFetch(endpoint, cred, signal, JSON.stringify(payload), fetcher, sessionId)
  if (allowLegacyStatus && (response.status === 404 || response.status === 405)) {
    return { response, raw: "", id }
  }
  if (isRedirect(response)) throw redirectError()
  if (!response.ok) return { response, raw: "", id }
  const raw = await readCappedBody(response, responseLimit)
  return { response, raw, id }
}

async function postNotification(
  endpoint: URL,
  cred: CredentialHeader,
  signal: AbortSignal,
  payload: Record<string, unknown>,
  fetcher: FetchLike,
  sessionId?: string,
): Promise<Response> {
  const response = await doFetch(endpoint, cred, signal, JSON.stringify(payload), fetcher, sessionId)
  if (isRedirect(response)) throw redirectError()
  return response
}

async function doFetch(
  endpoint: URL,
  cred: CredentialHeader,
  signal: AbortSignal,
  body: string,
  fetcher: FetchLike,
  sessionId?: string,
): Promise<Response> {
  if (signal.aborted) throw cancelled()
  const headers: Record<string, string> = {
    [cred.name]: cred.value,
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
  }
  if (sessionId !== undefined) headers["Mcp-Session-Id"] = sessionId
  try {
    return await fetcher(endpoint, { method: "POST", headers, body, signal, redirect: "manual" })
  } catch (cause) {
    throw transportError(cause)
  }
}

function assertInitializeResult(envelope: unknown): void {
  if (!isRecord(envelope) || !isRecord(envelope["result"])) {
    throw new GatewayError("UPSTREAM_ERROR", "The upstream MCP initialize response is malformed.")
  }
  const result = envelope["result"]
  if (typeof result["protocolVersion"] !== "string") {
    throw new GatewayError("UPSTREAM_ERROR", "The upstream MCP initialize response has no protocol version.")
  }
}

function isMethodNotFound(envelope: unknown): boolean {
  return isRecord(envelope) && isRecord(envelope["error"]) && envelope["error"]["code"] === -32601
}

function readSessionId(value: string | null): string | undefined {
  if (value === null) return undefined
  if (value.length > MAX_SESSION_ID_LENGTH || !SESSION_ID.test(value)) {
    throw new GatewayError("UPSTREAM_ERROR", "The upstream MCP server returned an invalid session identifier.")
  }
  return value
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function nextRequestId(): number { requestCounter += 1; return requestCounter }
function isRedirect(response: Response): boolean { return (response.status >= 300 && response.status < 400) || response.type === "opaqueredirect" }
function redirectError(): GatewayError { return new GatewayError("UPSTREAM_ERROR", "The upstream server redirected the call; the credential was not forwarded.") }
function assertUsableResponse(response: Response): void {
  if (isRedirect(response)) throw redirectError()
  if (!response.ok) {
    const message = `The upstream server refused the call (HTTP ${response.status}).`
    if (response.status === 502 || response.status === 503 || response.status === 504) {
      throw new RetryableRemoteMcpError("UPSTREAM_ERROR", message)
    }
    throw new GatewayError("UPSTREAM_ERROR", message)
  }
}

async function readCappedBody(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get("content-length"))
  if (Number.isFinite(declared) && declared > maxBytes) throw tooLarge()
  const body = response.body
  if (body === null) return ""
  const reader = body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (value === undefined) continue
      total += value.byteLength
      if (total > maxBytes) throw tooLarge()
      chunks.push(value)
    }
  } catch (cause) {
    void reader.cancel().catch(() => {})
    if (cause instanceof GatewayError) throw cause
    throw transportError(cause)
  }
  const joined = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength }
  return new TextDecoder().decode(joined)
}

function boundedResponseLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) return MAX_RESPONSE_BYTES
  return Math.min(value, MAX_LARGE_RESPONSE_BYTES)
}
function tooLarge(): GatewayError { return new GatewayError("UPSTREAM_ERROR", "The upstream server returned an oversized response.") }
function cancelled(): GatewayError { return new GatewayError("CANCELLED", "The upstream call was cancelled.") }

function endpointFor(baseUrl: string): URL {
  try {
    return new URL(normalizeUpstreamEndpointUrl(baseUrl, upstreamUrlPolicyFromEnvironment(process.env)))
  } catch {
    throw new GatewayError("UPSTREAM_ERROR", "The upstream endpoint is not allowed.")
  }
}

function transportError(cause: unknown): GatewayError {
  const name = cause instanceof Error ? cause.name : ""
  if (name === "AbortError") return cancelled()
  if (name === "TimeoutError") return new GatewayError("TIMEOUT", "The upstream call timed out.")
  return new RetryableRemoteMcpError("UPSTREAM_ERROR", "The upstream server is unreachable.")
}
