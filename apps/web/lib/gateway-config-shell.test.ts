// @vitest-environment node
import { execFileSync } from "node:child_process"
import { describe, expect, test } from "vitest"
import { agentEnvSnippet, API_KEY_PLACEHOLDER, normalizeGatewayUrl, verifyCommand } from "./gateway-config"

function shellArguments(command: string): string[] {
  const output = execFileSync("/bin/sh", ["-c", "curl() { printf '%s\\0' \"$@\"; };\n" + command], {
    encoding: "utf8", timeout: 5_000,
  })
  return output.split("\0").slice(0, -1)
}

describe.skipIf(process.platform === "win32")("copy-ready command shell safety", () => {
  test.each([
    "https://example.test/gateway/$(printf${IFS}INJECTED)",
    "https://example.test/gateway/a&b",
    "https://example.test/gateway/it's-here",
    "https://example.test/gateway/\x60printf${IFS}INJECTED\x60",
  ])("preserves an accepted base path as one literal curl argument: %s", (raw) => {
    const base = normalizeGatewayUrl(raw)
    expect(base).not.toBeNull()
    expect(shellArguments(verifyCommand(base!))).toEqual([
      "-fsS", "-H", "Authorization: Bearer " + API_KEY_PLACEHOLDER, base + "/v1/catalog",
    ])
  })

  test("preserves an agent relay value without evaluating shell substitutions", () => {
    const base = normalizeGatewayUrl("https://example.test/gateway/$(printf${IFS}INJECTED)/it's-here")!
    const output = execFileSync("/bin/sh", [
      "-c", agentEnvSnippet(base) + "\nprintf '%s' \"$CG_GATEWAY_URL\"",
    ], { encoding: "utf8", timeout: 5_000 })
    expect(output).toBe(base.replace(/^http/, "ws") + "/device")
  })
})
