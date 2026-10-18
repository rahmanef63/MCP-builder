import { describe, expect, test } from "bun:test"
import { EventEmitter } from "node:events"
import type { ClientRequest, IncomingMessage, RequestOptions } from "node:http"
import { PassThrough } from "node:stream"
import type { ConnectorManifest } from "@cg/core"
import { createSafeFetch } from "@cg/transport"
import type { ResolvedAddress } from "@cg/transport"
import { createRemoteMcpAdapter } from "./adapter"
import { callTool, MCP_PROTOCOL_VERSION } from "./mcp-client"

const ENDPOINT = "https://backend.composio.dev/v3/mcp/fixture_server?user_id=fixture_user"
const TOKEN = "fixture-upstream-credential"

function fixtureTransport(addresses: (attempt: number) => readonly ResolvedAddress[]) {
  const methods: string[] = []
  const requests: RequestOptions[] = []
  const pins: string[] = []
  let resolutions = 0
  const fetcher = createSafeFetch({
    resolve: async () => addresses(++resolutions),
    request: (options, respond) => {
      requests.push(options)
      const lookup = options.lookup as (
        host: string,
        options: { all: boolean },
        callback: (error: Error | null, records: ResolvedAddress[]) => void,
      ) => void
      lookup(String(options.hostname), { all: true }, (error, records) => {
        expect(error).toBeNull()
        pins.push(records[0]!.address)
      })
      const outgoing = new EventEmitter() as ClientRequest
      outgoing.destroy = () => outgoing
      outgoing.end = ((body?: string) => {
        const rpc = JSON.parse(body ?? "{}") as { id?: number; method: string }
        methods.push(rpc.method)
        const incoming = new PassThrough() as unknown as IncomingMessage & PassThrough
        incoming.statusCode = rpc.method === "notifications/initialized" ? 204 : 200
        incoming.rawHeaders = ["content-type", "application/json", "mcp-session-id", "fixture-session"]
        incoming.headers = { "content-type": "application/json" }
        const result = rpc.method === "initialize"
          ? { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {} }
          : { structuredContent: { ok: true } }
        queueMicrotask(() => {
          respond(incoming)
          if (incoming.statusCode !== 204) {
            incoming.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }))
          }
        })
        return outgoing
      }) as ClientRequest["end"]
      return outgoing
    },
  })
  return { fetcher, methods, requests, pins, resolutions: () => resolutions }
}

describe("remote MCP outbound boundary", () => {
  test("pins DNS and retains Composio identity for initialization, notification, and tool call", async () => {
    const transport = fixtureTransport(() => [{ address: "93.184.216.34", family: 4 }])
    const signal = new AbortController().signal
    await expect(callTool(ENDPOINT, TOKEN, "fixture_read", {}, signal, undefined, undefined, {
      fetcher: transport.fetcher,
    })).resolves.toEqual({ ok: true })

    expect(transport.methods).toEqual(["initialize", "notifications/initialized", "tools/call"])
    expect(transport.resolutions()).toBe(3)
    expect(transport.pins).toEqual(["93.184.216.34", "93.184.216.34", "93.184.216.34"])
    for (const request of transport.requests) {
      expect(request.hostname).toBe("backend.composio.dev")
      expect(request.path).toBe("/v3/mcp/fixture_server?user_id=fixture_user")
      expect(request.agent).toBe(false)
      expect((request.headers as Record<string, string>).host).toBe("backend.composio.dev")
      expect((request.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`)
    }
  })

  test.each([2, 3])("refuses a private DNS answer before MCP phase %s sends a credential", async (blockedPhase) => {
    const transport = fixtureTransport((attempt) => [{
      address: attempt === blockedPhase ? "127.0.0.1" : "93.184.216.34",
      family: 4,
    }])
    await expect(callTool(ENDPOINT, TOKEN, "fixture_read", {}, new AbortController().signal,
      undefined, undefined, { fetcher: transport.fetcher },
    )).rejects.toMatchObject({ code: "UPSTREAM_ERROR" })
    expect(transport.resolutions()).toBe(blockedPhase)
    expect(transport.requests).toHaveLength(blockedPhase - 1)
    expect(transport.methods).not.toContain(blockedPhase === 2 ? "notifications/initialized" : "tools/call")
  })

  test("the adapter passes its explicit pinned transport through the full lifecycle", async () => {
    const transport = fixtureTransport(() => [{ address: "93.184.216.34", family: 4 }])
    const manifest = {
      id: "outbound-fixture",
      name: "Outbound fixture",
      version: "0.1.0",
      executor: "cloud",
      auth: { type: "bearer" },
      actions: [{
        id: "outbound-fixture.read",
        title: "Read",
        description: "Read fixture data.",
        inputSchema: { type: "object" },
        risk: "R0",
        annotations: { readOnly: true, destructive: false },
        "x-upstream": "fixture_read",
      }],
    } as unknown as ConnectorManifest
    const result = await createRemoteMcpAdapter(manifest, { fetcher: transport.fetcher }).execute(
      "outbound-fixture.read", {}, {
        requestId: "outbound-fixture-request",
        credential: { connectionId: "fixture-connection", baseUrl: ENDPOINT, token: TOKEN },
        signal: new AbortController().signal,
      },
    )
    expect(result.output).toEqual({ ok: true })
    expect(transport.methods).toEqual(["initialize", "notifications/initialized", "tools/call"])
  })
})
