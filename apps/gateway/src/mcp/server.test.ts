import { describe, expect, test } from "bun:test"
import { fakeApiKeys, mcpDeps, scope, testApiKey, TEST_CONNECTOR } from "../__tests__/fixtures"
import {
  handleMcpRequest,
  MCP_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSIONS,
  SERVER_INFO,
  SERVER_INSTRUCTIONS,
  negotiateProtocolVersion,
  toToolResult,
  MAX_TOOL_TEXT_CHARS,
} from "./server"
import { MCP_META_KEYS, MCP_MODERN_PROTOCOL_VERSION } from "./protocol"
import { GATEWAY_SKILL_URI } from "./skill"

const MCP_RESOURCE = "https://gateway.test/mcp"

function rpc(method: string, params: Record<string, unknown> = {}, id: number | string = 1) {
  return { jsonrpc: "2.0", id, method, params }
}

function modernRpc(
  method: string,
  params: Record<string, unknown> = {},
  id: number | string = 1,
  version: string = MCP_MODERN_PROTOCOL_VERSION,
) {
  return rpc(
    method,
    {
      ...params,
      _meta: {
        [MCP_META_KEYS.protocolVersion]: version,
        [MCP_META_KEYS.clientCapabilities]: {},
      },
    },
    id,
  )
}

async function call(
  body: unknown,
  tokenOverride?: string | null,
  transport?: { protocolVersion: string | null; method: string | null; name: string | null },
) {
  const deps = await mcpDeps()
  const { token } = await testApiKey()
  const outcome = await handleMcpRequest(deps, {
    scope: scope(),
    token: tokenOverride === undefined ? token : tokenOverride,
    body,
    resource: MCP_RESOURCE,
    ...(transport === undefined ? {} : { transport }),
  })
  return { deps, outcome }
}

describe("handleMcpRequest — authentication", () => {
  test("a missing token is 401 before the body is even parsed", async () => {
    const { outcome } = await call({ garbage: true }, null)
    expect(outcome.status).toBe(401)
    expect(outcome.body?.error).toMatchObject({ message: "Unauthorized." })
  })

  test("an unknown key is 401", async () => {
    const deps = await mcpDeps({ apiKeys: fakeApiKeys(null) })
    const { token } = await testApiKey()
    const outcome = await handleMcpRequest(deps, { scope: scope(), token, body: rpc("ping"), resource: MCP_RESOURCE })
    expect(outcome.status).toBe(401)
  })
})

describe("handleMcpRequest — methods", () => {
  test("initialize advertises the protocol version and tool capability", async () => {
    const { outcome } = await call(rpc("initialize"))
    expect(outcome.status).toBe(200)
    expect(outcome.body?.result).toMatchObject({
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {
        tools: { listChanged: false },
        resources: { listChanged: false },
        extensions: { "io.modelcontextprotocol/skills": {} },
      },
      instructions: SERVER_INSTRUCTIONS,
    })
  })

  test("initialize echoes a revision the client asked for and we speak", async () => {
    // The point of negotiating: a 2024-11-05 client stays on 2024-11-05 instead
    // of being handed a newer number it never asked for.
    const { outcome } = await call(rpc("initialize", { protocolVersion: "2024-11-05" }))
    expect(outcome.body?.result).toMatchObject({ protocolVersion: "2024-11-05" })
  })

  test("ping answers with an empty result", async () => {
    const { outcome } = await call(rpc("ping"))
    expect(outcome.body?.result).toEqual({})
  })

  test("a notification gets no body", async () => {
    const { outcome } = await call({ jsonrpc: "2.0", method: "notifications/initialized" })
    expect(outcome.status).toBe(202)
    expect(outcome.body).toBeUndefined()
  })

  test("an unknown method is a JSON-RPC method-not-found", async () => {
    const { outcome } = await call(rpc("tools/delete"))
    expect(outcome.body?.error).toMatchObject({ code: -32601 })
  })

  test("a malformed envelope is 400 and never a 200 result", async () => {
    const { outcome } = await call({ jsonrpc: "1.0", method: "ping" })
    expect(outcome.status).toBe(400)
  })

  test("tools/list exposes the caller's catalog with faithful annotations", async () => {
    const { outcome } = await call(rpc("tools/list"))
    const tools = (outcome.body?.result as { tools: Record<string, unknown>[] }).tools
    const names = tools.map((tool) => tool.name)
    expect(names).toContain("testcloud_echo")
    // The local connector has no online device, so it is not in the catalog.
    expect(names.every((name) => !String(name).startsWith("testlocal"))).toBe(true)

    const echo = tools.find((tool) => tool.name === "testcloud_echo")
    expect(echo?.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false })
  })
})

describe("handleMcpRequest — tools/call", () => {
  test("executes a catalogued tool and returns structured content", async () => {
    const { deps, outcome } = await call(
      rpc("tools/call", { name: "testcloud_echo", arguments: { keep: "yes" } }),
    )
    expect(outcome.body?.result).toMatchObject({
      isError: false,
      structuredContent: { ok: true },
    })
    expect(deps.executor.requests[0]?.connector.id).toBe(TEST_CONNECTOR)
    expect(deps.audit.events).toHaveLength(1)
  })

  test("an unknown tool name never reaches the pipeline, but is audited", async () => {
    const { deps, outcome } = await call(rpc("tools/call", { name: "testcloud_python_execute" }))
    expect(outcome.body?.error).toMatchObject({ code: -32601 })
    expect(deps.executor.requests).toHaveLength(0)

    // docs/13 gap 4: this used to leave no trace at all, so probing tool names
    // over the primary entry point was invisible while REST logged the same miss.
    expect(deps.audit.events).toHaveLength(1)
    expect(deps.audit.events[0]).toMatchObject({
      actionId: "testcloud_python_execute",
      executorKind: "none",
      policyDecision: "DENY",
      status: "error",
    })
  })

  test("a hostile tool name is truncated and control-stripped before it is stored", async () => {
    // NUL and newline would both corrupt a JSON log line; `safeId` drops them.
    const hostile = `evil\u0000name\n${"x".repeat(500)}`
    const { deps } = await call(rpc("tools/call", { name: hostile }))
    expect(deps.audit.events).toHaveLength(1)
    const actionId = deps.audit.events[0]?.actionId ?? ""
    expect(actionId).toBe(`evilname${"x".repeat(120)}`)
    expect(actionId.length).toBe(128)
  })

  test("a denied action comes back as a tool RESULT, not a transport error", async () => {
    const { outcome } = await call(rpc("tools/call", { name: "testcloud_forbidden" }))
    const result = outcome.body?.result as { isError: boolean; content: { text: string }[] }
    expect(result.isError).toBe(true)
    expect(result.content[0]?.text).toContain("POLICY_DENIED")
  })

  test("non-object arguments degrade to an empty object", async () => {
    const { deps } = await call(rpc("tools/call", { name: "testcloud_echo", arguments: "oops" }))
    expect(deps.executor.requests[0]?.input).toEqual({})
  })
})


describe("handleMcpRequest — MCP 2026-07-28", () => {
  const transport = (
    method: string,
    name: string | null = null,
    version: string = MCP_MODERN_PROTOCOL_VERSION,
  ) => ({ protocolVersion: version, method, name })

  test("server/discover is stateless and advertises only modern per-request versions", async () => {
    const { outcome } = await call(
      modernRpc("server/discover"),
      undefined,
      transport("server/discover"),
    )
    expect(outcome.status).toBe(200)
    expect(outcome.body?.result).toMatchObject({
      supportedVersions: [MCP_MODERN_PROTOCOL_VERSION],
      capabilities: {
        tools: {},
        resources: {},
        extensions: { "io.modelcontextprotocol/skills": {} },
      },
      instructions: SERVER_INSTRUCTIONS,
      ttlMs: 300_000,
      cacheScope: "private",
      resultType: "complete",
      _meta: {
        [MCP_META_KEYS.serverInfo]: SERVER_INFO,
      },
    })
  })

  test("tools/list is cache-safe per authorization context and carries a deterministic toolset digest", async () => {
    const { outcome } = await call(
      modernRpc("tools/list"),
      undefined,
      transport("tools/list"),
    )
    const result = outcome.body?.result as {
      tools: Array<Record<string, unknown>>
      ttlMs: number
      cacheScope: string
      resultType: string
      _meta: Record<string, unknown>
    }
    expect(result.ttlMs).toBe(60_000)
    expect(result.cacheScope).toBe("private")
    expect(result.resultType).toBe("complete")
    expect(result._meta["com.rahmanef.connectors/toolset"]).toMatchObject({
      version: SERVER_INFO.version,
    })
    const echo = result.tools.find((tool) => tool.name === "testcloud_echo")
    expect(echo).toMatchObject({
      title: "Echo",
      outputSchema: { type: "object", additionalProperties: true },
      securitySchemes: [{ type: "oauth2", scopes: [] }],
      _meta: {
        securitySchemes: [{ type: "oauth2", scopes: [] }],
        "openai/toolInvocation/invoking": "Running Echo…",
        "openai/toolInvocation/invoked": "Completed Echo",
      },
    })
  })

  test("a modern tool call remains on the same policy, execution and audit pipeline", async () => {
    const { deps, outcome } = await call(
      modernRpc("tools/call", { name: "testcloud_echo", arguments: { keep: "yes" } }),
      undefined,
      transport("tools/call", "testcloud_echo"),
    )
    expect(outcome.body?.result).toMatchObject({
      isError: false,
      structuredContent: { ok: true },
      resultType: "complete",
    })
    expect(deps.executor.requests[0]?.connector.id).toBe(TEST_CONNECTOR)
    expect(deps.audit.events).toHaveLength(1)
  })

  test("header/body mismatches are rejected before dispatch", async () => {
    const { deps, outcome } = await call(
      modernRpc("tools/call", { name: "testcloud_echo" }),
      undefined,
      transport("tools/call", "testcloud_strict"),
    )
    expect(outcome.status).toBe(400)
    expect(outcome.body?.error).toMatchObject({ code: -32020 })
    expect(deps.executor.requests).toHaveLength(0)
    expect(deps.audit.events).toHaveLength(0)
  })

  test("an unsupported version is a 400 with the dedicated error and fallback data", async () => {
    const version = "2099-01-01"
    const { outcome } = await call(
      modernRpc("tools/list", {}, 1, version),
      undefined,
      transport("tools/list", null, version),
    )
    expect(outcome.status).toBe(400)
    expect(outcome.body?.error).toEqual({
      code: -32022,
      message: "Unsupported MCP protocol version.",
      data: { supported: [MCP_MODERN_PROTOCOL_VERSION], requested: version },
    })
  })

  test("an unknown modern RPC method is HTTP 404 and JSON-RPC -32601", async () => {
    const { outcome } = await call(
      modernRpc("tools/delete"),
      undefined,
      transport("tools/delete"),
    )
    expect(outcome.status).toBe(404)
    expect(outcome.body?.error).toMatchObject({ code: -32601 })
  })

  test("an unknown modern tool is invalid params, audited, and never executed", async () => {
    const { deps, outcome } = await call(
      modernRpc("tools/call", { name: "testcloud_missing" }),
      undefined,
      transport("tools/call", "testcloud_missing"),
    )
    expect(outcome.status).toBe(200)
    expect(outcome.body?.error).toMatchObject({ code: -32602 })
    expect(deps.executor.requests).toHaveLength(0)
    expect(deps.audit.events).toHaveLength(1)
  })

  test("exports a bounded static skill through the extension and MCP resources", async () => {
    const listed = await call(rpc("skills/list"))
    const skills = (listed.outcome.body?.result as { skills: Array<Record<string, unknown>> }).skills
    expect(skills).toHaveLength(1)
    expect(skills[0]).toMatchObject({
      uri: GATEWAY_SKILL_URI,
      frontmatter: { name: "connectors-gateway" },
      resources: [{ uri: GATEWAY_SKILL_URI }],
    })
    const digest = ((skills[0]?.resources as Array<{ digest: string }>)[0]?.digest ?? "")
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/)

    const got = await call(rpc("skills/get", { uri: GATEWAY_SKILL_URI }))
    expect(got.outcome.body?.result).toMatchObject({ skill: skills[0] })

    const read = await call(
      modernRpc("resources/read", { uri: GATEWAY_SKILL_URI }),
      undefined,
      transport("resources/read", GATEWAY_SKILL_URI),
    )
    expect(read.outcome.body?.result).toMatchObject({
      contents: [{ uri: GATEWAY_SKILL_URI, mimeType: "text/markdown" }],
      ttlMs: 300_000,
      cacheScope: "private",
      resultType: "complete",
    })
    const text = (((read.outcome.body?.result as { contents: Array<{ text: string }> }).contents)[0]?.text ?? "")
    expect(text).toContain("# Connectors Gateway")
  })

  test("modern resources/list includes the mandatory cache hints", async () => {
    const { outcome } = await call(
      modernRpc("resources/list"),
      undefined,
      transport("resources/list"),
    )
    expect(outcome.body?.result).toMatchObject({
      resources: [{ uri: GATEWAY_SKILL_URI, mimeType: "text/markdown" }],
      ttlMs: 300_000,
      cacheScope: "private",
      resultType: "complete",
    })
  })
})


describe("negotiateProtocolVersion", () => {
  test("echoes every revision we claim to speak", () => {
    for (const version of MCP_PROTOCOL_VERSIONS) {
      expect(negotiateProtocolVersion(version)).toBe(version)
    }
  })

  test("falls back to the newest for an absent, unknown or non-string request", () => {
    for (const requested of [undefined, null, 42, {}, "2026-07-28", "nonsense"]) {
      expect(negotiateProtocolVersion(requested)).toBe(MCP_PROTOCOL_VERSION)
    }
  })

  test("the advertised default is one we actually speak", () => {
    expect(MCP_PROTOCOL_VERSIONS).toContain(MCP_PROTOCOL_VERSION)
  })
})

describe("toToolResult", () => {
  test("a scalar output is wrapped into schema-conforming structuredContent", () => {
    const body = toToolResult({ status: "success", output: 42, timingMs: 1 })
    expect(body.structuredContent).toEqual({ result: 42 })
    expect(body.isError).toBe(false)
  })

  test("an array and null output are also wrapped without changing their text form", () => {
    expect(
      toToolResult({ status: "success", output: [1, 2], timingMs: 1 }).structuredContent,
    ).toEqual({ result: [1, 2] })
    expect(
      toToolResult({ status: "success", output: null, timingMs: 1 }).structuredContent,
    ).toEqual({ result: null })
  })

  test("an object output remains the structured object itself", () => {
    expect(
      toToolResult({ status: "success", output: { ok: true }, timingMs: 1 })
        .structuredContent,
    ).toEqual({ ok: true })
  })

  test("an error result carries the code in the text", () => {
    const body = toToolResult({
      status: "error",
      error: { code: "DEVICE_OFFLINE", message: "No device." },
      timingMs: 1,
    })
    expect(body.isError).toBe(true)
    expect((body.content as { text: string }[])[0]?.text).toBe("DEVICE_OFFLINE: No device.")
  })

  test("an oversized output text is bounded and flagged; structuredContent stays whole", () => {
    const big = "x".repeat(MAX_TOOL_TEXT_CHARS * 2)
    const body = toToolResult({ status: "success", output: { big }, timingMs: 1 })
    const text = (body.content as { text: string }[])[0]?.text ?? ""
    expect(text.length).toBeLessThan(MAX_TOOL_TEXT_CHARS + 200)
    expect(text).toContain("[truncated ")
    expect((body._meta as Record<string, unknown>)["cg/truncated"]).toBe(true)
    expect((body.structuredContent as { big: string }).big.length).toBe(big.length)
  })

  test("a small output is not truncated and carries no _meta without a receipt", () => {
    const body = toToolResult({ status: "success", output: { ok: true }, timingMs: 1 })
    expect(body._meta).toBeUndefined()
  })

  test("a receipt echoes the request id on success and on error", () => {
    const ok = toToolResult({ status: "success", output: {}, timingMs: 7 }, { requestId: "req_1" })
    expect((ok._meta as Record<string, unknown>)["cg/receipt"]).toEqual({ requestId: "req_1", timingMs: 7 })
    const err = toToolResult(
      { status: "error", error: { code: "POLICY_DENIED", message: "no" }, timingMs: 2 },
      { requestId: "req_2" },
    )
    expect((err._meta as Record<string, unknown>)["cg/receipt"]).toEqual({ requestId: "req_2", timingMs: 2 })
  })
})
