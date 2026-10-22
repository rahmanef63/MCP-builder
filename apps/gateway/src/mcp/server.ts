/**
 * MCP JSON-RPC adapter (docs/07). A protocol skin over the connector platform:
 * it maps tool calls onto the ONE execution pipeline and adds nothing else.
 *
 * Authentication happens first, before the envelope is even parsed, and the
 * catalog is built from the authenticated principal — a tool name that is not
 * in the caller's own catalog can never reach the pipeline.
 */
import { GatewayError, toGatewayError } from "@cg/core"
import type { ExecutionResult, Principal } from "@cg/core"
import { authenticateCaller } from "@cg/auth"
import type { RequestScope } from "../context"
import { resolveCatalog } from "../catalog"
import type { CatalogDeps } from "../catalog"
import { appendAudit, safeId } from "../pipeline/audit"
import { executeAction } from "../pipeline/execute"
import type { PipelineDeps } from "../pipeline/execute"
import { JSONRPC_ERRORS, jsonRpcError, jsonRpcResult, parseJsonRpcRequest } from "./jsonrpc"
import type { JsonRpcRequest, JsonRpcResponse } from "./jsonrpc"
import {
  completeModernResult,
  isModernMcpRequest,
  MCP_MODERN_PROTOCOL_VERSION,
  McpProtocolError,
  validateModernMcpRequest,
} from "./protocol"
import type { McpTransportHeaders } from "./protocol"
import { assertSkillUri, GATEWAY_SKILL_URI, loadGatewaySkill } from "./skill"
import { createToolIndex, lookupTool } from "./tool-names"
import { targetsFor, toolsFor } from "./tools"

/** Initialize-based protocol revisions, oldest first. */
export const MCP_PROTOCOL_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"] as const
/** What an unrecognised or absent legacy initialize request gets. */
export const MCP_PROTOCOL_VERSION = "2025-06-18"
/** Every transport revision this endpoint can serve, newest first. */
export const MCP_SUPPORTED_PROTOCOL_VERSIONS = [
  MCP_MODERN_PROTOCOL_VERSION,
  ...[...MCP_PROTOCOL_VERSIONS].reverse(),
] as const

export function negotiateProtocolVersion(requested: unknown): string {
  return typeof requested === "string" &&
    (MCP_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
    ? requested
    : MCP_PROTOCOL_VERSION
}

export const SERVER_INFO = { name: "connectors-gateway", version: "0.4.0" } as const

/** Shared guidance, front-loaded because ChatGPT prioritizes the first 512 chars. */
export const SERVER_INSTRUCTIONS =
  "Tool availability is per-user and changes with connected accounts and online devices. For multi-step MSO work, call mso_workflow_start once, pass workflow_id to later MSO calls, then finish or cancel it. Use search/schema tools before execution when available. APPROVAL_REQUIRED means stop for dashboard approval; never bypass POLICY_DENIED. Retry only TIMEOUT or UPSTREAM_ERROR. Explain destructive actions first."

const LEGACY_CAPABILITIES = Object.freeze({
  tools: { listChanged: false },
  resources: { listChanged: false },
  extensions: { "io.modelcontextprotocol/skills": {} },
})

const MODERN_CAPABILITIES = Object.freeze({
  tools: {},
  resources: {},
  extensions: { "io.modelcontextprotocol/skills": {} },
})

const EMPTY_TRANSPORT: McpTransportHeaders = Object.freeze({
  protocolVersion: null,
  method: null,
  name: null,
})

export type McpDeps = PipelineDeps & CatalogDeps

export type McpInput = {
  scope: RequestScope
  token: string | null
  body?: unknown
  /** HTTP body parsing is deferred until authentication succeeds. */
  readBody?: () => Promise<unknown>
  /** Canonical RFC 8707 resource for this MCP endpoint. */
  resource: string
  transport?: Partial<McpTransportHeaders>
}

export type McpOutcome = { status: number; body?: JsonRpcResponse }

function transportOf(input: McpInput): McpTransportHeaders {
  return {
    protocolVersion: input.transport?.protocolVersion ?? null,
    method: input.transport?.method ?? null,
    name: input.transport?.name ?? null,
  }
}

export async function handleMcpRequest(deps: McpDeps, input: McpInput): Promise<McpOutcome> {
  let principal: Principal
  try {
    if (input.token === null) throw new GatewayError("NOT_AUTHENTICATED", "Invalid credentials.")
    principal = await authenticateCaller(input.token, deps.apiKeys, Date.now(), input.resource)
  } catch {
    return { status: 401, body: jsonRpcError(null, JSONRPC_ERRORS.INVALID_REQUEST, "Unauthorized.") }
  }

  // Let transport reader failures retain their HTTP error mapping.
  const body = input.readBody ? await input.readBody() : input.body

  let request: JsonRpcRequest
  try {
    request = parseJsonRpcRequest(body)
  } catch (cause) {
    const error = toGatewayError(cause)
    return { status: 400, body: jsonRpcError(null, JSONRPC_ERRORS.INVALID_REQUEST, error.message) }
  }

  const transport = input.transport === undefined ? EMPTY_TRANSPORT : transportOf(input)
  const modern = isModernMcpRequest(request, transport)
  if (modern) {
    try {
      validateModernMcpRequest(request, transport)
    } catch (cause) {
      if (cause instanceof McpProtocolError) {
        return {
          status: cause.status,
          body: jsonRpcError(request.id ?? null, cause.code, cause.message, cause.data),
        }
      }
      throw cause
    }
  }

  // A notification expects no body. Modern notifications still pass transport
  // validation above so a proxy and the dispatcher cannot disagree on method.
  if (request.id === undefined) return { status: 202 }

  try {
    const result = await dispatch(deps, principal, input, request, modern)
    return { status: 200, body: jsonRpcResult(request.id, result) }
  } catch (cause) {
    if (cause instanceof McpProtocolError) {
      return {
        status: cause.status,
        body: jsonRpcError(request.id, cause.code, cause.message, cause.data),
      }
    }
    const error = toGatewayError(cause)
    const rpcCode = rpcCodeFor(error.code, request.method, modern)
    return {
      status: modern && rpcCode === JSONRPC_ERRORS.METHOD_NOT_FOUND ? 404 : 200,
      body: jsonRpcError(request.id, rpcCode, error.message),
    }
  }
}

/** Transport-level failures only; a tool's own failure is a RESULT (see below). */
function rpcCodeFor(code: string, method: string, modern: boolean): number {
  if (code === "ACTION_NOT_FOUND" || code === "CONNECTOR_NOT_FOUND") {
    // In the modern schema an unknown tool is invalid params; -32601 is reserved
    // for an RPC method the server itself does not implement.
    if (modern && method === "tools/call") return JSONRPC_ERRORS.INVALID_PARAMS
    return JSONRPC_ERRORS.METHOD_NOT_FOUND
  }
  if (code === "INVALID_INPUT") return JSONRPC_ERRORS.INVALID_PARAMS
  return JSONRPC_ERRORS.INTERNAL
}

async function dispatch(
  deps: McpDeps,
  principal: Principal,
  input: McpInput,
  request: JsonRpcRequest,
  modern: boolean,
): Promise<unknown> {
  switch (request.method) {
    case "server/discover":
      if (!modern) throw new GatewayError("ACTION_NOT_FOUND", "Unknown method.")
      return completeModernResult(
        {
          supportedVersions: [MCP_MODERN_PROTOCOL_VERSION],
          capabilities: MODERN_CAPABILITIES,
          instructions: SERVER_INSTRUCTIONS,
          ttlMs: 300_000,
          cacheScope: "private",
        },
        SERVER_INFO,
      )
    case "initialize":
      if (modern) throw new GatewayError("ACTION_NOT_FOUND", "Unknown method.")
      return {
        protocolVersion: negotiateProtocolVersion(request.params.protocolVersion),
        capabilities: LEGACY_CAPABILITIES,
        serverInfo: SERVER_INFO,
        instructions: SERVER_INSTRUCTIONS,
      }
    case "ping":
      return modern ? completeModernResult({}, SERVER_INFO) : {}
    case "tools/list":
      return await listTools(deps, principal, modern)
    case "tools/call":
      return await callTool(deps, principal, input, request, modern)
    case "skills/list":
      return await listSkills(request, modern)
    case "skills/get":
      return await getSkill(request, modern)
    case "resources/list":
      return await listResources(request, modern)
    case "resources/read":
      return await readResource(request, modern)
    default:
      throw new GatewayError("ACTION_NOT_FOUND", "Unknown method.")
  }
}

async function sha256Json(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(value))
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")
}

async function listTools(deps: McpDeps, principal: Principal, modern: boolean): Promise<unknown> {
  const tools = toolsFor(await resolveCatalog(deps, principal))
  const value: Record<string, unknown> = {
    tools,
    _meta: {
      "com.rahmanef.connectors/toolset": {
        version: SERVER_INFO.version,
        digest: `sha256:${await sha256Json(tools)}`,
      },
    },
  }
  if (!modern) return value
  return completeModernResult(
    { ...value, ttlMs: 60_000, cacheScope: "private" },
    SERVER_INFO,
  )
}

async function listSkills(request: JsonRpcRequest, modern: boolean): Promise<unknown> {
  const cursor = request.params.cursor
  if (cursor !== undefined && cursor !== "") {
    throw new GatewayError("INVALID_INPUT", "Unknown skills cursor.")
  }
  const skill = await loadGatewaySkill()
  const value = { skills: [skill.entry] }
  return modern ? completeModernResult(value, SERVER_INFO) : value
}

async function getSkill(request: JsonRpcRequest, modern: boolean): Promise<unknown> {
  assertSkillUri(request.params.uri)
  const skill = await loadGatewaySkill()
  const value = { skill: skill.entry }
  return modern ? completeModernResult(value, SERVER_INFO) : value
}

async function listResources(request: JsonRpcRequest, modern: boolean): Promise<unknown> {
  const cursor = request.params.cursor
  if (cursor !== undefined && cursor !== "") {
    throw new GatewayError("INVALID_INPUT", "Unknown resources cursor.")
  }
  const skill = await loadGatewaySkill()
  const value = {
    resources: [
      {
        uri: GATEWAY_SKILL_URI,
        name: "Connectors Gateway skill",
        title: "Connectors Gateway operating instructions",
        description: skill.entry.frontmatter.description,
        mimeType: "text/markdown",
      },
    ],
  }
  return modern
    ? completeModernResult({ ...value, ttlMs: 300_000, cacheScope: "private" }, SERVER_INFO)
    : value
}

async function readResource(request: JsonRpcRequest, modern: boolean): Promise<unknown> {
  assertSkillUri(request.params.uri)
  const skill = await loadGatewaySkill()
  const value = {
    contents: [{ uri: GATEWAY_SKILL_URI, mimeType: "text/markdown", text: skill.text }],
  }
  return modern
    ? completeModernResult({ ...value, ttlMs: 300_000, cacheScope: "private" }, SERVER_INFO)
    : value
}

async function callTool(
  deps: McpDeps,
  principal: Principal,
  input: McpInput,
  request: JsonRpcRequest,
  modern: boolean,
): Promise<unknown> {
  const entries = await resolveCatalog(deps, principal)

  let target
  try {
    target = lookupTool(createToolIndex(targetsFor(entries)), request.params.name)
  } catch (cause) {
    await auditCatalogMiss(deps, input, principal, request.params.name, cause)
    throw cause
  }

  const args = request.params.arguments

  const result = await executeAction(deps, {
    scope: input.scope,
    token: input.token,
    principal,
    connectorId: target.connectorId,
    actionId: target.actionId,
    input: typeof args === "object" && args !== null && !Array.isArray(args) ? args : {},
  })
  const value = toToolResult(result, { requestId: input.scope.requestId })
  return modern ? completeModernResult(value, SERVER_INFO) : value
}

/**
 * A tools/call for a name outside the caller's catalog is refused here, before
 * the execution pipeline. Record it so probing the primary entry point is not
 * invisible in the audit trail.
 */
async function auditCatalogMiss(
  deps: McpDeps,
  input: McpInput,
  principal: Principal,
  toolName: unknown,
  cause: unknown,
): Promise<void> {
  const error = toGatewayError(cause)
  try {
    await appendAudit(deps.audit, {
      requestId: input.scope.requestId,
      principal,
      connectorId: "unknown",
      actionId: safeId(typeof toolName === "string" ? toolName : ""),
      executorKind: "none",
      policyDecision: "DENY",
      status: "error",
      latencyMs: Math.max(0, Date.now() - input.scope.receivedAt),
      errorCode: error.code,
    })
  } catch (sinkFailure) {
    input.scope.logger.error("audit sink failed for an unknown tool name", {
      error: sinkFailure instanceof Error ? sinkFailure.message : "unknown",
    })
  }
}

/**
 * Upper bound on the human-readable text block handed to the model. Adapters
 * already cap upstream bodies (1–8 MiB); this keeps one tool result from
 * flooding the model context. structuredContent is left intact for clients
 * that parse it. Adopted from MSO's bounded-output tools.
 */
export const MAX_TOOL_TEXT_CHARS = 64 * 1024

/** Audit receipt echoed to the client so a result can be matched to its audit row. */
export interface ToolReceipt {
  requestId: string
}

function boundedText(text: string): { text: string; truncated: boolean } {
  if (text.length <= MAX_TOOL_TEXT_CHARS) return { text, truncated: false }
  const omitted = text.length - MAX_TOOL_TEXT_CHARS
  return {
    text: `${text.slice(0, MAX_TOOL_TEXT_CHARS)}\n…[truncated ${omitted} chars; full result in structuredContent]`,
    truncated: true,
  }
}

/** Tool failures are results so the model can react to the stable error code. */
export function toToolResult(result: ExecutionResult, receipt?: ToolReceipt): Record<string, unknown> {
  const meta: Record<string, unknown> = {}
  if (receipt) meta["cg/receipt"] = { requestId: receipt.requestId, timingMs: result.timingMs }
  if (result.status === "error") {
    const error = result.error ?? { code: "INTERNAL", message: "The action failed." }
    const body: Record<string, unknown> = {
      content: [{ type: "text", text: `${error.code}: ${error.message}` }],
      isError: true,
    }
    if (receipt) body._meta = meta
    return body
  }
  const output = result.output ?? null
  const bounded = boundedText(JSON.stringify(output) ?? "null")
  const body: Record<string, unknown> = {
    content: [{ type: "text", text: bounded.text }],
    isError: false,
  }
  // Every descriptor has an object outputSchema. Preserve object outputs and
  // wrap scalars/arrays/null so ChatGPT always receives schema-conforming
  // structuredContent in addition to the human-readable text block.
  body.structuredContent =
    typeof output === "object" && output !== null && !Array.isArray(output)
      ? output
      : { result: output }
  if (result.files && result.files.length > 0) body.files = result.files
  if (bounded.truncated) meta["cg/truncated"] = true
  if (Object.keys(meta).length > 0) body._meta = meta
  return body
}
