/**
 * The generic remote-MCP cloud adapter: normalized action in, upstream MCP tool call out.
 *
 * There is exactly one of these for every remote MCP server we will ever connect. It owns
 * no auth, no policy, no audit (adapters/README.md) and nothing connector-specific — the
 * manifest supplies the action surface and the `x-upstream` names, while `baseUrl` and
 * `token` are resolved server-side from the caller's connection row and handed in by the
 * executor.
 */
import { GatewayError } from "@cg/core"
import type { ConnectorManifest } from "@cg/core"
import type { AdapterOutput, CloudAdapter, CloudAdapterContext } from "@cg/sdk"
import { defineCloudAdapter } from "@cg/sdk"
import {
  callTool,
  credentialHeaderFor,
  isRetryableRemoteMcpError,
  MAX_LARGE_RESPONSE_BYTES,
  MAX_RESPONSE_BYTES,
} from "./mcp-client"
import type { RemoteMcpOptions } from "./mcp-client"
import { resolveUpstreamTool } from "./upstream"
import {
  assertCircuitAllows,
  recordCircuitNonTransientOutcome,
  recordCircuitSuccess,
  recordCircuitTransientFailure,
  upstreamCircuitKey,
} from "./reliability"

export type { RemoteMcpOptions } from "./mcp-client"

/** Build the adapter that executes `manifest`. Data in, behaviour out. */
export function createRemoteMcpAdapter(
  manifest: ConnectorManifest,
  options: RemoteMcpOptions = {},
): CloudAdapter {
  // A `local` manifest routed through a cloud adapter would reach the upstream over the
  // public internet instead of the device relay. Cheap to check here, and the roadmap
  // has users authoring manifests (docs/16 step 3), where `executor` is attacker-chosen.
  if (manifest.executor !== "cloud") {
    throw new GatewayError("INVALID_INPUT", `Connector "${manifest.id}" is not a cloud connector.`)
  }

  return defineCloudAdapter({
    manifest,

    async execute(
      actionId: string,
      input: unknown,
      context: CloudAdapterContext,
    ): Promise<AdapterOutput> {
      const tool = resolveUpstreamTool(manifest, actionId)
      const args = toolArguments(input)
      const { baseUrl, token } = context.credential
      if (typeof baseUrl !== "string" || typeof token !== "string" || token.length === 0) {
        throw new GatewayError("CONNECTION_MISSING", "This connection is not configured.")
      }

      // How this upstream wants the credential is a property of the connector,
      // read from its manifest — not a constant baked into the transport.
      const cred = credentialHeaderFor(manifest.auth, token)
      // MSO screen_capture includes a PNG plus a short-lived preview/download
      // URL. Give only that reviewed tool a larger bounded envelope; every other
      // remote tool keeps the 1 MiB tenant-protection limit.
      const maxResponseBytes =
        manifest.id === "mso" && tool === "screen_capture"
          ? MAX_LARGE_RESPONSE_BYTES
          : MAX_RESPONSE_BYTES
      const action = manifest.actions.find((entry) => entry.id === actionId)
      const retrySafe = action?.annotations.readOnly === true || action?.annotations.idempotent === true
      const circuitKey = upstreamCircuitKey(manifest.id, baseUrl)
      assertCircuitAllows(manifest.id, circuitKey)
      let output: unknown
      try {
        output = await callTool(baseUrl, token, tool, args, context.signal, cred, maxResponseBytes, options)
      } catch (first) {
        const transient = isRetryableRemoteMcpError(first)
        if (!transient) {
          recordCircuitNonTransientOutcome(manifest.id, circuitKey)
          throw first
        }
        if (!retrySafe || context.signal.aborted) {
          recordCircuitTransientFailure(manifest.id, circuitKey)
          throw first
        }
        try {
          // No sleep: both attempts consume the SAME caller deadline. The retry
          // can never extend the execution budget configured by the executor.
          output = await callTool(baseUrl, token, tool, args, context.signal, cred, maxResponseBytes, options)
        } catch (second) {
          if (isRetryableRemoteMcpError(second)) recordCircuitTransientFailure(manifest.id, circuitKey)
          else recordCircuitNonTransientOutcome(manifest.id, circuitKey)
          throw second
        }
      }
      recordCircuitSuccess(manifest.id, circuitKey)
      // Invariant 5 (AGENTS.md): a connector credential must never reach tool output,
      // not even when the upstream server echoes the Authorization header back at us.
      if (JSON.stringify(output ?? null).includes(token)) {
        throw new GatewayError(
          "UPSTREAM_ERROR",
          "The upstream server echoed a credential; the response was discarded.",
        )
      }
      return { output }
    },
  })
}

/**
 * The pipeline has already validated `input` against `action.inputSchema`
 * (apps/gateway/src/pipeline/execute.ts step 3), so this is a shape narrowing for the
 * JSON-RPC `arguments` member, not a second validator. A second one would be worse than
 * none: two hand-maintained copies of one schema disagree, and the copy that rejects
 * first wins silently.
 */
function toolArguments(input: unknown): Record<string, unknown> {
  if (input === undefined || input === null) return {}
  if (typeof input !== "object" || Array.isArray(input)) {
    throw new GatewayError("INVALID_INPUT", "Input must be an object.")
  }
  return input as Record<string, unknown>
}
