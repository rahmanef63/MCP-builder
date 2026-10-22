/** Provider token shapes adopted from SI-Coder lib/redact-env.js. Fakes are built at runtime. */
import { describe, expect, test } from "bun:test"
import { REDACTED, redactText, stripCredentials, stripCredentialsDeep } from "./redact"

const fakes = {
  github: "ghp" + "_" + "A1b2C3d4".repeat(5),
  githubPat: "github" + "_pat_" + "11ABCDEFG0".repeat(4),
  stripe: "sk" + "_live_" + "Zx9".repeat(8),
  openai: "sk" + "-proj-" + "q".repeat(32),
  slack: "xox" + "b-" + "123456789012-abcdef",
  pem: "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
}

describe("provider credential shapes", () => {
  for (const [name, token] of Object.entries(fakes)) {
    test(`${name} is stripped from tool output and from log text`, () => {
      expect(stripCredentials(`x ${token} y`)).toBe(`x ${REDACTED} y`)
      expect(redactText(`x ${token} y`)).not.toContain(token)
    })
  }

  test("commit SHAs, ids and ordinary prose survive", () => {
    const keep = "commit 3a24652f9e0c1b2d3e4f5a6b7c8d9e0f1a2b3c4d dpl_8f7e6d5c4b3a sk-short task-runner"
    expect(stripCredentials(keep)).toBe(keep)
  })

  test("deep strip covers nested arrays and objects", () => {
    const out = JSON.stringify(stripCredentialsDeep({ a: [{ b: fakes.github }], c: fakes.slack }))
    expect(out).not.toContain(fakes.github)
    expect(out).not.toContain(fakes.slack)
  })
})

describe("query-string secrets in log text", () => {
  test("token-like query params are blanked in logs but not in tool output", () => {
    const url = "https://x.test/cb?code=abc123def456&state=ok&access_token=zzz999yyy888"
    const logged = redactText(url)
    expect(logged).not.toContain("abc123def456")
    expect(logged).not.toContain("zzz999yyy888")
    expect(logged).toContain("state=ok")
    expect(stripCredentials(url)).toBe(url)
  })
})
