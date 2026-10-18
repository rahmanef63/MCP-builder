/**
 * POST /mcp — MCP JSON-RPC over HTTP. Bearer auth required.
 * The adapter itself lives in ../../mcp/server; this file is transport only.
 */
import { parseAuthorizationHeader } from "@cg/auth"
import { MCP_SCOPES } from "@cg/core"
import type { GatewayConfig } from "../../config"
import { handleMcpRequest } from "../../mcp/server"
import { readJsonBody } from "../body"
import { errorResponseFor, jsonResponse } from "../respond"
import type { RouteContext } from "../routes"
import { mcpResourceUrl } from "./well-known"

/**
 * RFC 9728 §5.1. The 401 is not the end of the conversation — it is the start
 * of discovery, and `resource_metadata` is the whole of what makes it one.
 *
 * A bare `WWW-Authenticate: Bearer` tells a client it needs a token and gives
 * it nowhere to get one; the client has no choice but to report the server as
 * unauthenticatable. With the pointer, an unauthenticated call walks itself to
 * the metadata, to the authorization server, and back with a token.
 */
export function challengeFor(config: GatewayConfig): string {
  return [
    `Bearer resource_metadata="${config.publicUrl}/.well-known/oauth-protected-resource"`,
    `scope="${MCP_SCOPES.join(" ")}"`,
  ].join(", ")
}

export async function handleMcp(context: RouteContext): Promise<Response> {
  try {
    const outcome = await handleMcpRequest(context.deps, {
      scope: context.scope,
      token: parseAuthorizationHeader(context.request.headers.get("authorization")),
      readBody: () => readJsonBody(context.request),
      resource: mcpResourceUrl(context.deps.config),
      transport: {
        protocolVersion: context.request.headers.get("mcp-protocol-version"),
        method: context.request.headers.get("mcp-method"),
        name: context.request.headers.get("mcp-name"),
      },
    })
    if (!outcome.body) return new Response(null, { status: outcome.status })

    const headers: Record<string, string> = {}
    if (outcome.status === 401) headers["www-authenticate"] = challengeFor(context.deps.config)
    return jsonResponse(outcome.body, outcome.status, headers)
  } catch (cause) {
    return errorResponseFor(cause)
  }
}
