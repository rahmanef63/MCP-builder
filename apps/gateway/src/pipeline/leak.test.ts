/** End-to-end leak tests (pattern from SI-Coder test/mcp-redact-e2e.test.js). */
import { describe, expect, test } from "bun:test"
import { fakeExecutor, pipelineDeps, scope, testApiKey, TEST_CONNECTOR } from "../__tests__/fixtures"
import { toToolResult } from "../mcp/server"
import { executeAction } from "./execute"

const UPSTREAM = "ghp" + "_" + "Zz9Yy8Xx7W".repeat(3)

async function call(outcome: Parameters<typeof fakeExecutor>[0]) {
  const deps = await pipelineDeps({ executor: fakeExecutor(outcome) })
  const { token } = await testApiKey()
  const result = await executeAction(deps, {
    scope: scope(), token, connectorId: TEST_CONNECTOR, actionId: "testcloud.echo", input: {},
  })
  return { deps, result, token }
}

describe("no credential reaches the MCP client or the audit trail", () => {
  test("an upstream token echoed in output is stripped from the tool result", async () => {
    const { result, token } = await call({
      status: "success", output: { body: `auth ok ${UPSTREAM}`, nested: [UPSTREAM] }, timingMs: 1,
    })
    const wire = JSON.stringify(toToolResult(result, { requestId: "req_leak" }))
    expect(wire).not.toContain(UPSTREAM)
    expect(wire).not.toContain(token)
  })

  test("the caller's own gateway key echoed back is stripped", async () => {
    const deps = await pipelineDeps()
    const { token } = await testApiKey()
    deps.executor = fakeExecutor({ status: "success", output: { echo: token }, timingMs: 1 }) as never
    const result = await executeAction(deps, {
      scope: scope(), token, connectorId: TEST_CONNECTOR, actionId: "testcloud.echo", input: {},
    })
    expect(JSON.stringify(toToolResult(result))).not.toContain(token)
  })

  test("audit rows never carry the token", async () => {
    const { deps, token } = await call({
      status: "success", output: { body: UPSTREAM }, timingMs: 1,
    })
    const rows = JSON.stringify(deps.audit.events)
    expect(rows).not.toContain(UPSTREAM)
    expect(rows).not.toContain(token)
  })
})
