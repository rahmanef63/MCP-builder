import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { GatewayError } from "@cg/core"
import { validateManifest } from "./manifest"

const CONNECTORS_DIR = join(import.meta.dir, "..", "..", "..", "adapters", "remote-mcp", "connectors")

function loadShipped(name: string): unknown {
  return JSON.parse(readFileSync(join(CONNECTORS_DIR, name), "utf8"))
}

function baseManifest(): Record<string, unknown> {
  return {
    id: "demo",
    name: "Demo",
    version: "0.1.0",
    executor: "cloud",
    auth: { type: "none" },
    actions: [
      {
        id: "demo.thing.read",
        title: "Read thing",
        description: "Read a thing.",
        inputSchema: { type: "object", additionalProperties: false },
        risk: "R0",
        annotations: { readOnly: true, destructive: false },
      },
    ],
  }
}

function expectInvalid(value: unknown): GatewayError {
  try {
    validateManifest(value)
  } catch (error) {
    expect(error).toBeInstanceOf(GatewayError)
    return error as GatewayError
  }
  throw new Error("expected validateManifest to throw")
}

describe("validateManifest", () => {
  test("all shipped connector manifests validate against the frozen schema", () => {
    for (const file of ["careerpack.connector.json", "composio.connector.json", "mso.connector.json"]) {
      const manifest = validateManifest(loadShipped(file))
      expect(manifest.actions.length).toBeGreaterThan(0)
      for (const action of manifest.actions) {
        expect(typeof action.inputSchema).toBe("object")
      }
    }
  })

  test("accepts a minimal valid manifest", () => {
    expect(validateManifest(baseManifest()).id).toBe("demo")
  })

  test("validates the reviewed production discovery block", () => {
    const manifest = baseManifest()
    manifest["endpoint"] = "https://api.example.test/mcp"
    manifest["verification"] = {
      environment: "production",
      resourceMetadata: "https://api.example.test/.well-known/oauth-protected-resource",
      authorizationServer: "https://auth.example.test",
      authorizationEndpoint: "https://app.example.test/oauth/authorize",
      tokenEndpoint: "https://auth.example.test/oauth/token",
    }
    expect(validateManifest(manifest).verification?.environment).toBe("production")

    const broken = structuredClone(manifest)
    const verification = broken["verification"] as Record<string, unknown>
    verification["authorizationEndpoint"] = "http://careerpack.local/oauth/authorize"
    expect(expectInvalid(broken).message).toContain("/verification/authorizationEndpoint")
  })

  test("rejects an action with no inputSchema", () => {
    const manifest = baseManifest()
    const actions = manifest["actions"] as Record<string, unknown>[]
    delete actions[0]?.["inputSchema"]

    const error = expectInvalid(manifest)
    expect(error.code).toBe("INVALID_INPUT")
    expect(error.message).toContain("/actions/0")
    expect(error.message).toContain("required:inputSchema")
  })

  test("rejects a non-object inputSchema", () => {
    const manifest = baseManifest()
    const actions = manifest["actions"] as Record<string, unknown>[]
    if (actions[0]) actions[0]["inputSchema"] = "please just take anything"

    const error = expectInvalid(manifest)
    expect(error.code).toBe("INVALID_INPUT")
    expect(error.message).toContain("/actions/0/inputSchema type")
  })

  test("rejects an unknown risk class and an unknown executor", () => {
    const badRisk = baseManifest()
    const actions = badRisk["actions"] as Record<string, unknown>[]
    if (actions[0]) actions[0]["risk"] = "R9"
    expect(expectInvalid(badRisk).message).toContain("/actions/0/risk")

    const badExecutor = baseManifest()
    badExecutor["executor"] = "serverless"
    expect(expectInvalid(badExecutor).message).toContain("/executor")
  })

  test("rejects an inputSchema that is not a compilable JSON Schema", () => {
    const manifest = baseManifest()
    const actions = manifest["actions"] as Record<string, unknown>[]
    if (actions[0]) {
      actions[0]["inputSchema"] = {
        type: "object",
        properties: { value: { type: "not-a-json-type" } },
      }
    }

    const error = expectInvalid(manifest)
    expect(error.code).toBe("INVALID_INPUT")
    expect(error.message).toContain("schema-not-compilable")
  })

  test("rejects non-objects without leaking the value", () => {
    for (const value of [null, "manifest", 42, []]) {
      expect(expectInvalid(value).code).toBe("INVALID_INPUT")
    }
    expect(expectInvalid("sk-live-do-not-echo-me").message).not.toContain("sk-live")
  })

  test("the error message never echoes manifest field values", () => {
    const manifest = baseManifest()
    manifest["id"] = "NOT a valid connector id -- token_abc123"

    const error = expectInvalid(manifest)
    expect(error.message).toContain("/id pattern")
    expect(error.message).not.toContain("token_abc123")
  })
})
