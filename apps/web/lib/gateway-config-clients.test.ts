// @vitest-environment node
import { describe, expect, test } from "vitest"
import { API_KEY_PLACEHOLDER, mcpClientConfig, mcpEndpoint, type McpClient } from "./gateway-config"

const BASE = "https://gateway.example.test/base/"
const KEY = "cgk_fixture_0123456789abcdef0123456789abcdef"
const CLIENTS: McpClient[] = ["claude-code", "cursor", "claude-desktop"]

function server(client?: McpClient, key?: string | null): Record<string, unknown> {
  return JSON.parse(mcpClientConfig(BASE, key, client)).mcpServers["connectors-gateway"]
}

describe("client-specific MCP setup configuration", () => {
  test("the default preserves Claude Code HTTP configuration", () => {
    expect(server()).toEqual({
      type: "http", url: "https://gateway.example.test/base/mcp",
      headers: { Authorization: "Bearer " + API_KEY_PLACEHOLDER },
    })
    expect(server()).toEqual(server("claude-code"))
  })

  test("Cursor receives a remote URL and headers", () => {
    expect(server("cursor", KEY)).toEqual({
      url: "https://gateway.example.test/base/mcp",
      headers: { Authorization: "Bearer " + KEY },
    })
  })

  test("Claude Desktop receives a stdio bridge with its credential in an environment field", () => {
    const entry = server("claude-desktop", KEY)
    expect(entry).toEqual({
      command: "npx",
      args: [
        "-y", "mcp-remote", "https://gateway.example.test/base/mcp",
        "--header", "Authorization:" + "$" + "{AUTH_HEADER}",
      ],
      env: { AUTH_HEADER: "Bearer " + KEY },
    })
    expect(JSON.stringify(entry.args)).not.toContain(KEY)
  })

  test.each(CLIENTS)("%s configuration uses the placeholder until a valid key is supplied", (client) => {
    for (const key of [undefined, null, "", "cgk_fixture_short", "cgd_device_0123456789abcdef"]) {
      const config = mcpClientConfig(BASE, key, client)
      expect(config).toContain(API_KEY_PLACEHOLDER)
      if (key) expect(config).not.toContain(key)
    }
    expect(mcpClientConfig(BASE, KEY, client)).toContain("Bearer " + KEY)
  })

  test("MCP path joining removes trailing slashes without losing a reverse-proxy base path", () => {
    expect(mcpEndpoint("https://gateway.example.test/base///")).toBe(
      "https://gateway.example.test/base/mcp",
    )
  })
})
