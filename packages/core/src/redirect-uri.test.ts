import { describe, expect, test } from "bun:test"
import { isRegisteredRedirectUri, isValidRedirectUri } from "./redirect-uri"

describe("isValidRedirectUri", () => {
  test.each([
    "https://claude.ai/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "http://localhost:33418/callback",
    "http://127.0.0.1:8080/cb",
    "http://[::1]:9000/cb",
    "com.example.app:/oauth/callback",
  ])("accepts %s", (uri) => {
    expect(isValidRedirectUri(uri)).toBe(true)
  })

  test.each([
    ["non-string", 42],
    ["empty", ""],
    ["too long", `https://a.test/${"x".repeat(600)}`],
    ["unparseable", "not a uri"],
    ["fragment", "https://claude.ai/cb#frag"],
    ["non-normalised", "HTTPS://Claude.ai/cb"],
    ["http off loopback", "http://claude.ai/cb"],
    ["javascript scheme", "javascript:alert(1)"],
    ["data scheme", "data:text/html,hi"],
    ["userinfo host spoof", "https://claude.ai@evil.test/cb"],
    ["userinfo with password", "https://u:p@claude.ai/cb"],
  ])("rejects %s", (_label, uri) => {
    expect(isValidRedirectUri(uri)).toBe(false)
  })
})

describe("isRegisteredRedirectUri", () => {
  const registered = ["https://claude.ai/callback"]

  test("matches exactly", () => {
    expect(isRegisteredRedirectUri("https://claude.ai/callback", registered)).toBe(true)
  })

  test.each([
    "https://claude.ai/callback/../../evil",
    "https://claude.ai.evil.test/callback",
    "https://claude.ai/callback?x=1",
    "https://claude.ai/callback/",
  ])("refuses near-miss %s", (uri) => {
    expect(isRegisteredRedirectUri(uri, registered)).toBe(false)
  })
})
