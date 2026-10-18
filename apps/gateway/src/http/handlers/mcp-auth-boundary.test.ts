import { describe, expect, test } from "bun:test"
import {
  fakeApiKeys,
  httpDeps,
  scope,
  testApiKey,
  testConfig,
} from "../../__tests__/fixtures"
import type { TestGatewayDeps } from "../../__tests__/fixtures"
import { MAX_BODY_BYTES } from "../body"
import { challengeFor, handleMcp } from "./mcp"

const PING = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })
const RESOURCE = `${testConfig.publicUrl}/mcp`

const bodies: {
  name: string
  body: string
  headers: Record<string, string>
  error: string | null
}[] = [
  { name: "valid ping", body: PING, headers: {}, error: null },
  {
    name: "malformed JSON",
    body: '{"fixture":',
    headers: {},
    error: "The request body is not valid JSON.",
  },
  {
    name: "non-JSON content type",
    body: PING,
    headers: { "content-type": "text/plain" },
    error: "This endpoint accepts application/json only.",
  },
  {
    name: "declared oversized body",
    body: PING,
    headers: { "content-length": String(MAX_BODY_BYTES + 1) },
    error: "The request body is too large.",
  },
  {
    name: "undeclared oversized body",
    body: JSON.stringify({ fixture: "x".repeat(MAX_BODY_BYTES + 1) }),
    headers: {},
    error: "The request body is too large.",
  },
  {
    name: "JSON array",
    body: "[]",
    headers: {},
    error: "The request body must be a JSON object.",
  },
]

function request(body: string, headers: Record<string, string>, token: string | null): Request {
  return new Request(RESOURCE, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...headers,
      ...(token === null ? {} : { authorization: `Bearer ${token}` }),
    },
    body,
  })
}

async function call(deps: TestGatewayDeps, request: Request): Promise<Response> {
  return handleMcp({ request, deps, scope: scope(), params: {}, clientKey: "test.peer" })
}

describe("HTTP MCP authentication boundary", () => {
  for (const credential of [
    "missing",
    "malformed",
    "wrong-secret",
    "expired",
    "revoked",
    "wrong-audience",
  ] as const) {
    test.each(bodies)(`${credential} credential rejects $name before reading the body`, async (body) => {
      const fixture = await testApiKey()
      const record = {
        ...fixture.record,
        ...(credential === "expired" ? { expiresAt: Date.now() - 1 } : {}),
        ...(credential === "revoked" ? { status: "revoked" as const } : {}),
        ...(credential === "wrong-audience" ? { audience: "https://other.test/mcp" } : {}),
      }
      let lookups = 0
      const lookup = fakeApiKeys(record)
      const deps = await httpDeps({
        apiKeys: {
          async getApiKey(id) {
            lookups += 1
            return lookup.getApiKey(id)
          },
        },
      })
      const token =
        credential === "missing"
          ? null
          : credential === "malformed"
            ? "invalid-fixture-token"
            : credential === "wrong-secret"
              ? fixture.token.slice(0, -1) + (fixture.token.endsWith("a") ? "b" : "a")
              : fixture.token
      const input = request(body.body, body.headers, token)

      const response = await call(deps, input)

      expect(response.status).toBe(401)
      expect(response.headers.get("www-authenticate")).toBe(challengeFor(testConfig))
      expect(await response.json()).toEqual({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Unauthorized." },
      })
      expect(input.bodyUsed).toBe(false)
      expect(lookups).toBe(credential === "missing" || credential === "malformed" ? 0 : 1)
      expect(deps.executor.requests).toHaveLength(0)
      expect(deps.audit.events).toHaveLength(0)
    })
  }

  test.each(bodies.filter((body) => body.error !== null))(
    "authenticated $name keeps the HTTP body-reader error",
    async (body) => {
      const { token, record } = await testApiKey()
      const deps = await httpDeps({ apiKeys: fakeApiKeys({ ...record, audience: RESOURCE }) })

      const response = await call(deps, request(body.body, body.headers, token))

      expect(response.status).toBe(400)
      expect(response.headers.get("www-authenticate")).toBeNull()
      expect(await response.json()).toEqual({
        error: { code: "INVALID_INPUT", message: body.error },
      })
      expect(deps.executor.requests).toHaveLength(0)
    },
  )

  test("an authenticated ping reads the body and authenticates only once", async () => {
    const { token, record } = await testApiKey()
    let lookups = 0
    const deps = await httpDeps({
      apiKeys: {
        async getApiKey() {
          lookups += 1
          return { ...record, audience: RESOURCE }
        },
      },
    })
    const input = request(PING, {}, token)

    const response = await call(deps, input)

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ jsonrpc: "2.0", id: 1, result: {} })
    expect(input.bodyUsed).toBe(true)
    expect(lookups).toBe(1)
  })
})
