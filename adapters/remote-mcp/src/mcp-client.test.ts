import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import type { FetchLike } from "@cg/transport"
import { GatewayError } from "@cg/core"
import {
  MAX_LARGE_RESPONSE_BYTES,
  MAX_RESPONSE_BYTES,
  MCP_PROTOCOL_VERSION,
  callTool as invokeTool,
} from "./mcp-client"

function callTool(...args: Parameters<typeof invokeTool>): ReturnType<typeof invokeTool> {
  args[7] = { fetcher: (input, init) => fixtureFetch(input, init) }
  return invokeTool(...args)
}

const TOKEN = "cp_live_9c2f4a1b7e6d8f3a5b0c1d2e3f4a5b6c"
const BASE_URL = "https://upstream.example.com/mcp"

let fixtureFetch: FetchLike = async () => { throw new Error("No fetch fixture configured.") }
let calls: { url: string; init: RequestInit }[] = []

function stubFetch(
  body: string,
  options: { status?: number; contentType?: string; headers?: Record<string, string> } = {},
): void {
  fixtureFetch = ((input: unknown, init?: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} })
    let method = ""
    try { method = (JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>)["method"] as string ?? "" } catch {}
    if (method === "initialize") {
      const request = JSON.parse(String(init?.body)) as Record<string, unknown>
      return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: request["id"], result: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, serverInfo: { name: "test", version: "1" } } }), { headers: { "content-type": "application/json" } }))
    }
    if (method === "notifications/initialized") return Promise.resolve(new Response(null, { status: 202 }))
    const request = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>
    const responseBody = body.replace(/"id":1(?=[,}])/, `"id":${String(request["id"])}`)
    return Promise.resolve(new Response(responseBody, {
      status: options.status ?? 200,
      headers: { "content-type": options.contentType ?? "application/json", ...options.headers },
    }))
  }) as FetchLike
}

function stubReject(error: Error): void {
  fixtureFetch = (() => Promise.reject(error)) as FetchLike
}

function rpc(result: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id: 1, result })
}

function call(baseUrl = BASE_URL, signal = new AbortController().signal): Promise<unknown> {
  return callTool(baseUrl, TOKEN, "thing_get", {}, signal)
}

beforeEach(() => {
  calls = []
})

afterEach(() => {
  fixtureFetch = async () => { throw new Error("No fetch fixture configured.") }
})

describe("callTool transport", () => {
  test("posts a JSON-RPC 2.0 tools/call with the MCP headers", async () => {
    stubFetch(rpc({ structuredContent: { ok: true } }))

    await call()

    const sent = calls.at(-1)
    expect(sent?.url).toBe(BASE_URL)
    expect(sent?.init.method).toBe("POST")
    expect((sent?.init.headers as Record<string, string>)["MCP-Protocol-Version"]).toBe(MCP_PROTOCOL_VERSION)
    const body = JSON.parse(String(sent?.init.body)) as Record<string, unknown>
    expect(body["jsonrpc"]).toBe("2.0")
    expect(typeof body["id"]).toBe("number")
    expect(body["method"]).toBe("tools/call")
  })

  test("rejects a non-loopback plaintext endpoint", async () => {
    stubFetch(rpc({ structuredContent: {} }))

    const error = await call("http://upstream.example.com/mcp").catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
    expect(calls).toHaveLength(0)
  })

  test("allows a loopback plaintext endpoint for local development", async () => {
    stubFetch(rpc({ structuredContent: { ok: true } }))

    const original = process.env.ALLOW_LOOPBACK_UPSTREAM
    process.env.ALLOW_LOOPBACK_UPSTREAM = "1"
    try {
      await expect(call("http://127.0.0.1:8787/mcp")).resolves.toEqual({ ok: true })
    } finally {
      if (original === undefined) delete process.env.ALLOW_LOOPBACK_UPSTREAM
      else process.env.ALLOW_LOOPBACK_UPSTREAM = original
    }
  })

  test("allows RFC localhost subdomains only as loopback development endpoints", async () => {
    stubFetch(rpc({ structuredContent: { ok: true } }))

    const original = process.env.ALLOW_LOOPBACK_UPSTREAM
    process.env.ALLOW_LOOPBACK_UPSTREAM = "1"
    try {
      await expect(call("http://bridge.localhost:8787/mcp")).resolves.toEqual({ ok: true })
    } finally {
      if (original === undefined) delete process.env.ALLOW_LOOPBACK_UPSTREAM
      else process.env.ALLOW_LOOPBACK_UPSTREAM = original
    }
  })

  for (const endpoint of [
    "https://10.0.0.1/mcp",
    "https://100.64.0.1/mcp",
    "https://169.254.169.254/latest/meta-data",
    "https://192.0.2.1/mcp",
    "https://198.18.0.1/mcp",
    "https://224.0.0.1/mcp",
    "https://[fc00::1]/mcp",
    "https://[fe80::1]/mcp",
    "https://[ff02::1]/mcp",
  ]) {
    test(`rejects non-global literal ${endpoint} before fetch`, async () => {
      stubFetch(rpc({ structuredContent: {} }))
      const error = await call(endpoint).catch((cause: unknown) => cause)
      expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
      expect((error as GatewayError).message).toContain("not allowed")
      expect(calls).toHaveLength(0)
    })
  }

  test("rejects an unparseable endpoint", async () => {
    stubFetch(rpc({ structuredContent: {} }))

    const error = await call("not-a-url").catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
  })

  test("a non-2xx response is UPSTREAM_ERROR carrying only the status", async () => {
    stubFetch(`unauthorized ${TOKEN}`, { status: 401 })

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
    expect((error as GatewayError).message).toContain("401")
    expect((error as GatewayError).message).not.toContain(TOKEN)
  })

  test("an AbortError from fetch maps to CANCELLED", async () => {
    const abort = new Error("aborted")
    abort.name = "AbortError"
    stubReject(abort)

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("CANCELLED")
  })

  test("a TimeoutError from fetch maps to TIMEOUT", async () => {
    const timeout = new Error("timed out")
    timeout.name = "TimeoutError"
    stubReject(timeout)

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("TIMEOUT")
  })

  test("any other network failure maps to UPSTREAM_ERROR without the cause message", async () => {
    stubReject(new Error(`ECONNREFUSED while sending Bearer ${TOKEN}`))

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
    expect((error as GatewayError).message).not.toContain(TOKEN)
  })
})

/**
 * Regression: the client used fetch's default `redirect: "follow"`. An upstream
 * endpoint that answered 302 — whether compromised, hijacked by DNS, or simply
 * misconfigured — would have had the Authorization header replayed to the host named
 * in Location, handing that host a live bearer for this connection.
 */
describe("callTool never follows a redirect", () => {
  const ATTACKER = "https://evil.example.com/collect"

  test("asks the runtime not to follow one", async () => {
    stubFetch(rpc({ structuredContent: {} }))

    await call()

    expect(calls[0]?.init.redirect).toBe("manual")
  })

  for (const status of [301, 302, 303, 307, 308]) {
    test(`a ${status} is a loud UPSTREAM_ERROR and stops at one request`, async () => {
      stubFetch("", { status, headers: { location: ATTACKER } })

      const error = await call().catch((cause: unknown) => cause)

      expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
      expect((error as GatewayError).message).toContain("redirect")
      // Neither the attacker's host nor the bearer is echoed back to the caller.
      expect((error as GatewayError).message).not.toContain("evil.example.com")
      expect((error as GatewayError).message).not.toContain(TOKEN)
      expect(calls).toHaveLength(3)
    })
  }
})

/**
 * Regression: the client did `await response.text()`, so a hostile or broken endpoint
 * could stream unbounded bytes into the gateway's memory — one call degrading every
 * other tenant on the process.
 */
describe("callTool caps the response body", () => {
  test("a body over the cap is UPSTREAM_ERROR, not a silent truncation", async () => {
    stubFetch("x".repeat(MAX_RESPONSE_BYTES + 1))

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
    expect((error as GatewayError).message).toContain("oversized")
  })

  test("a declared content-length over the cap is refused before reading", async () => {
    stubFetch(rpc({ structuredContent: { ok: true } }), {
      headers: { "content-length": String(MAX_RESPONSE_BYTES + 1) },
    })

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
    expect((error as GatewayError).message).toContain("oversized")
  })

  test("an endless stream that declares no length is cut off, not buffered", async () => {
    let chunksServed = 0
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        chunksServed += 1
        controller.enqueue(new Uint8Array(64 * 1024).fill(120))
      },
    })
    fixtureFetch = ((input: unknown, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} })
      const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>
      if (payload["method"] === "initialize") return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: payload["id"], result: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {} } }), { headers: { "content-type": "application/json" } }))
      if (payload["method"] === "notifications/initialized") return Promise.resolve(new Response(null, { status: 202 }))
      return Promise.resolve(new Response(endless, { headers: { "content-type": "application/json" } }))
    }) as FetchLike

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
    expect((error as GatewayError).message).toContain("oversized")
    // Stopped at the cap rather than reading a stream that never ends.
    expect(chunksServed).toBeLessThanOrEqual(MAX_RESPONSE_BYTES / (64 * 1024) + 2)
  })

  test("an explicitly reviewed larger envelope is still bounded", async () => {
    const text = "y".repeat(MAX_RESPONSE_BYTES + 128)
    stubFetch(rpc({ content: [{ type: "text", text }] }))

    await expect(
      callTool(
        BASE_URL,
        TOKEN,
        "screen_capture",
        {},
        new AbortController().signal,
        undefined,
        MAX_LARGE_RESPONSE_BYTES,
      ),
    ).resolves.toBe(text)
  })

  test("a caller cannot raise the hard ceiling beyond 8 MiB", async () => {
    stubFetch(rpc({ content: [{ type: "text", text: "small" }] }), {
      headers: { "content-length": String(MAX_LARGE_RESPONSE_BYTES + 1) },
    })

    const error = await callTool(
      BASE_URL,
      TOKEN,
      "screen_capture",
      {},
      new AbortController().signal,
      undefined,
      Number.MAX_SAFE_INTEGER,
    ).catch((cause: unknown) => cause)
    expect((error as GatewayError).message).toContain("oversized")
  })

  test("a normal body is still read whole", async () => {
    const headline = "y".repeat(4096)
    stubFetch(rpc({ structuredContent: { headline } }))

    await expect(call()).resolves.toEqual({ headline })
  })
})

describe("callTool response parsing", () => {
  test("reads an SSE framed response", async () => {
    const body = `event: message\ndata: ${rpc({ structuredContent: { headline: "SRE" } })}\n\n`
    stubFetch(body, { contentType: "text/event-stream" })

    await expect(call()).resolves.toEqual({ headline: "SRE" })
  })

  test("returns null when the result carries no content", async () => {
    stubFetch(rpc({ content: [] }))

    await expect(call()).resolves.toBeNull()
  })

  test("a malformed body is UPSTREAM_ERROR", async () => {
    stubFetch("<html>nope</html>")

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
  })

  test("an empty body is UPSTREAM_ERROR", async () => {
    stubFetch("   ")

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
  })

  test("a response without a result object is UPSTREAM_ERROR", async () => {
    stubFetch(JSON.stringify({ jsonrpc: "2.0", id: 1 }))

    const error = await call().catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
  })

  test("a pre-aborted signal never reaches the network", async () => {
    stubFetch(rpc({ structuredContent: {} }))
    const controller = new AbortController()
    controller.abort()

    const error = await call(BASE_URL, controller.signal).catch((cause: unknown) => cause)

    expect((error as GatewayError).code).toBe("CANCELLED")
    expect(calls).toHaveLength(0)
  })
})

describe("Streamable HTTP session lifecycle", () => {
  test("initialize session id is propagated to initialized notification and tools/call", async () => {
    fixtureFetch = ((input: unknown, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} })
      const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>
      if (payload["method"] === "initialize") {
        return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: payload["id"], result: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {} } }), {
          headers: { "content-type": "application/json", "mcp-session-id": "sess_abc123" },
        }))
      }
      if (payload["method"] === "notifications/initialized") return Promise.resolve(new Response(null, { status: 202 }))
      return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: payload["id"], result: { structuredContent: { ok: true } } }), { headers: { "content-type": "application/json" } }))
    }) as FetchLike

    await expect(call()).resolves.toEqual({ ok: true })
    expect(calls).toHaveLength(3)
    const initializedHeaders = calls[1]?.init.headers as Record<string, string>
    const callHeaders = calls[2]?.init.headers as Record<string, string>
    expect(initializedHeaders["Mcp-Session-Id"]).toBe("sess_abc123")
    expect(callHeaders["Mcp-Session-Id"]).toBe("sess_abc123")
  })

  test("legacy server with method-not-found falls back to direct tools/call", async () => {
    fixtureFetch = ((input: unknown, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} })
      const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>
      if (payload["method"] === "initialize") return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: payload["id"], error: { code: -32601, message: "method not found" } }), { headers: { "content-type": "application/json" } }))
      return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: payload["id"], result: { structuredContent: { legacy: true } } }), { headers: { "content-type": "application/json" } }))
    }) as FetchLike

    await expect(call()).resolves.toEqual({ legacy: true })
    expect(calls).toHaveLength(2)
    expect(JSON.parse(String(calls[1]?.init.body)).method).toBe("tools/call")
  })

  test("invalid session identifiers fail closed and are never echoed", async () => {
    const bad = "bad session id"
    fixtureFetch = ((input: unknown, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} })
      const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>
      return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: payload["id"], result: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {} } }), { headers: { "content-type": "application/json", "mcp-session-id": bad } }))
    }) as FetchLike
    const error = await call().catch((cause: unknown) => cause)
    expect((error as GatewayError).code).toBe("UPSTREAM_ERROR")
    expect((error as GatewayError).message).not.toContain(bad)
  })

  test("SSE ignores progress/notification events and selects the matching JSON-RPC id", async () => {
    fixtureFetch = ((input: unknown, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} })
      const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>
      if (payload["method"] === "initialize") return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: payload["id"], result: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {} } }), { headers: { "content-type": "application/json" } }))
      if (payload["method"] === "notifications/initialized") return Promise.resolve(new Response(null, { status: 202 }))
      const wanted = JSON.stringify({ jsonrpc: "2.0", id: payload["id"], result: { structuredContent: { done: true } } })
      const stream = `event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\n\nevent: message\ndata: ${wanted}\n\nevent: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":2}}\n\n`
      return Promise.resolve(new Response(stream, { headers: { "content-type": "text/event-stream" } }))
    }) as FetchLike
    await expect(call()).resolves.toEqual({ done: true })
  })
})
