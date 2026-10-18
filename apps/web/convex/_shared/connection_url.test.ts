import { describe, expect, test } from "vitest"
import { assertConnectionUrl } from "./connection_url"
import { errorCodeOf } from "./errors"
import { assertUpstreamUrl } from "./upstream_url"

const ENDPOINT = "https://backend.composio.dev/v3/mcp/server_123"

function rejected(value: string): void {
  try {
    assertConnectionUrl("composio", value)
  } catch (error) {
    expect(errorCodeOf(error)).toBe("INVALID_INPUT")
    return
  }
  throw new Error("Expected INVALID_INPUT.")
}

describe("assertConnectionUrl", () => {
  test("preserves the hosted Composio user selector and removes fragments", () => {
    expect(assertConnectionUrl("composio", `${ENDPOINT}?user_id=selected-user#fragment`)).toBe(
      `${ENDPOINT}?user_id=selected-user`,
    )
    expect(assertConnectionUrl(
      "composio",
      " HTTPS://BACKEND.COMPOSIO.DEV.:443/v3/mcp/server_123?user_id=selected-user ",
    )).toBe(`${ENDPOINT}?user_id=selected-user`)
  })

  test.each([
    "https://backend.composio.dev/v3/mcp/server_123/?user_id=one",
    "https://backend.composio.dev/v3//mcp/server_123?user_id=one",
  ])("preserves identity when generic path normalization applies: %s", (value) => {
    expect(assertConnectionUrl("composio", value)).toBe(`${ENDPOINT}?user_id=one`)
  })

  test("preserves the decoded identifier while canonicalizing query escaping", () => {
    const value = "team+member@example.net&token=part-of-id"
    const supplied = `${ENDPOINT}?user_id=${encodeURIComponent(value)}`
    const normalized = assertConnectionUrl("composio", supplied)
    expect(new URL(normalized).searchParams.get("user_id")).toBe(value)
    expect([...new URL(normalized).searchParams]).toEqual([["user_id", value]])
    expect(assertConnectionUrl("composio", `${ENDPOINT}?user_id=${"a".repeat(256)}`)).toBe(
      `${ENDPOINT}?user_id=${"a".repeat(256)}`,
    )
  })

  test.each([
    "user_id=",
    "user_id=%20%20",
    `user_id=${"a".repeat(257)}`,
    "user_id=one&user_id=two",
    "user_id=one&%75ser_id=two",
    "user_id=one&token=secret",
    "user_id=one&access_token=secret",
    "user_id=one&api_key=secret",
    "user_id=one&authorization=secret",
    "token=secret",
    "USER_ID=one",
    "user_id=one&unknown=value",
    "user_id=%00",
    "user_id=one%0Atwo",
    "user_id=one%7Ftwo",
  ])("rejects an ambiguous or unsupported hosted query: %s", (query) => {
    rejected(`${ENDPOINT}?${query}`)
  })

  test("does not echo rejected query values", () => {
    expect(() => assertConnectionUrl("composio", `${ENDPOINT}?token=sensitive-fixture`))
      .toThrowError("Composio MCP URL must contain only one nonempty user_id.")
    try {
      assertConnectionUrl("composio", `${ENDPOINT}?token=sensitive-fixture`)
    } catch (error) {
      expect(String(error)).not.toContain("sensitive-fixture")
    }
  })

  test.each([
    ["careerpack", `${ENDPOINT}?user_id=one&token=secret`],
    ["composio", "https://backend.composio.dev.evil.example/v3/mcp/server_123?user_id=one"],
    ["composio", "https://other.example/v3/mcp/server_123?user_id=one"],
    ["composio", "https://backend.composio.dev:8443/v3/mcp/server_123?user_id=one"],
    ["composio", "https://backend.composio.dev/v3/mcp?user_id=one"],
    ["composio", "https://backend.composio.dev/v3/mcp/server_123/extra?user_id=one"],
    ["composio", "https://backend.composio.dev/v3/mcp/server%2F123?user_id=one"],
    ["composio", ENDPOINT],
  ])("keeps generic normalization outside the exact query context: %s %s", (connectorId, value) => {
    expect(assertConnectionUrl(connectorId, value)).toBe(assertUpstreamUrl(value))
    expect(new URL(assertConnectionUrl(connectorId, value)).search).toBe("")
  })

  test.each([
    "http://backend.composio.dev/v3/mcp/server_123?user_id=one",
    "https://user:pass@backend.composio.dev/v3/mcp/server_123?user_id=one",
    "https://127.0.0.1/v3/mcp/server_123?user_id=one",
    "https://169.254.169.254/v3/mcp/server_123?user_id=one",
    "https://connect.rahmanef.com/v3/mcp/server_123?user_id=one",
    "https://backend.composio.dev:8080/v3/mcp/server_123?user_id=one",
    `${ENDPOINT}?user_id=${"a".repeat(2048)}`,
  ])("still applies the generic URL safety gate: %s", (value) => {
    rejected(value)
  })
})
