import { describe, expect, test } from "bun:test"
import { GatewayError, findAction } from "@cg/core"
import type { ConnectorManifest } from "@cg/core"
import { validateManifest } from "@cg/schemas"
import type { CloudAdapterContext } from "@cg/sdk"
import type { FetchLike } from "@cg/transport"
import { createRemoteMcpAdapter } from "./adapter"
import { REMOTE_MCP_MANIFESTS } from "./connectors"
import { UPSTREAM_KEY, resolveUpstreamTool } from "./upstream"

const ACTION_PROFILE_READ = "careerpack.profile.read"
const ACTION_APPLICATION_CREATE = "careerpack.application.create"

function manifestFor(id: string): ConnectorManifest {
  const manifest = REMOTE_MCP_MANIFESTS.find((candidate) => candidate.id === id)
  if (!manifest) throw new Error(`no shipped manifest for ${id}`)
  return manifest
}

const careerpack = manifestFor("careerpack")

describe("every shipped remote-MCP connector", () => {
  test("is a cloud connector — the gateway must never execute a local one here", () => {
    for (const manifest of REMOTE_MCP_MANIFESTS) {
      expect(manifest.executor).toBe("cloud")
    }
  })

  test("names an upstream tool for every action it declares", () => {
    // Deliberately NOT `^[a-z][a-z0-9_]*$`, which is what this asserted until
    // the first third-party server arrived. Lowercase snake_case is the naming
    // rule for servers WE write; an upstream we merely consume picks its own,
    // and Composio ships `COMPOSIO_SEARCH_TOOLS`. A gateway that rejects a
    // remote tool for being spelled differently is a gateway that can only
    // talk to itself.
    //
    // What still matters is that the name is safe to put in a JSON-RPC
    // `params.name`: present, single-token, no whitespace or control bytes.
    for (const manifest of REMOTE_MCP_MANIFESTS) {
      for (const action of manifest.actions) {
        expect(resolveUpstreamTool(manifest, action.id)).toMatch(/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/)
      }
    }
  })

  test("carries an object JSON Schema on every action", () => {
    for (const manifest of REMOTE_MCP_MANIFESTS) {
      for (const action of manifest.actions) {
        expect(action.inputSchema["type"]).toBe("object")
        expect(action.inputSchema["additionalProperties"]).toBe(false)
      }
    }
  })
})

/**
 * The keyword is data now, so its type has to be enforced by the schema rather than by
 * the compiler. `packages/schemas/connector-manifest.schema.json` types it as a non-empty
 * string wherever it appears; absent stays legal, because a local connector has no
 * upstream tool surface at all.
 */
describe("the x-upstream keyword is schema-checked", () => {
  const base = {
    id: "probe",
    name: "Probe",
    version: "0.1.0",
    executor: "cloud",
    auth: { type: "bearer" },
  }
  const action = (upstream: unknown): Record<string, unknown> => ({
    id: "probe.thing.read",
    title: "T",
    description: "D",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    risk: "R0",
    annotations: { readOnly: true, destructive: false },
    ...(upstream === undefined ? {} : { [UPSTREAM_KEY]: upstream }),
  })

  test("a string is accepted and survives validation unchanged", () => {
    const validated = validateManifest({ ...base, actions: [action("thing_get")] })
    expect(resolveUpstreamTool(validated, "probe.thing.read")).toBe("thing_get")
  })

  test("an absent keyword still validates — local connectors declare none", () => {
    expect(() => validateManifest({ ...base, actions: [action(undefined)] })).not.toThrow()
  })

  test("a non-string is INVALID_INPUT at validation, not a runtime surprise", () => {
    for (const bad of [42, null, true, ["thing_get"], { name: "thing_get" }, ""]) {
      let thrown: unknown
      try {
        validateManifest({ ...base, actions: [action(bad)] })
      } catch (cause) {
        thrown = cause
      }
      expect(thrown).toBeInstanceOf(GatewayError)
      expect((thrown as GatewayError).code).toBe("INVALID_INPUT")
    }
  })
})

/**
 * The CareerPack assertions below are the point of this file. They are transcribed from
 * CareerPack's own tool definitions (convex/mcp/tools/profile.ts, .../applications.ts);
 * a manifest that drifts from them produces a call the live server rejects, which is
 * exactly the bug this connector shipped with.
 */
describe("careerpack, as shipped data", () => {
  test("is a cloud connector authenticated with a bearer token", () => {
    expect(careerpack.name).toBe("CareerPack")
    expect(careerpack.executor).toBe("cloud")
    expect(careerpack.auth.type).toBe("bearer")
  })

  test("declares exactly the two MVP actions", () => {
    expect(careerpack.actions.map((action) => action.id)).toEqual([
      ACTION_PROFILE_READ,
      ACTION_APPLICATION_CREATE,
    ])
  })

  /**
   * The published surface is <domain>_<verb>, not <verb>_<domain>. The connector
   * originally shipped the verb-first spellings, which no CareerPack deployment has ever
   * published; getting it backwards costs a "tool not found" on every call.
   */
  test("resolves to the tool names CareerPack actually publishes", () => {
    expect(resolveUpstreamTool(careerpack, ACTION_PROFILE_READ)).toBe("profile_get")
    expect(resolveUpstreamTool(careerpack, ACTION_APPLICATION_CREATE)).toBe("applications_create")
  })

  test("the verb-first spellings are gone for good", () => {
    const names = careerpack.actions.map((action) => resolveUpstreamTool(careerpack, action.id))
    expect(names).not.toContain("get_profile")
    expect(names).not.toContain("create_application")
  })

  test("profile_get takes no arguments at all", () => {
    const read = findAction(careerpack, ACTION_PROFILE_READ)
    expect(read?.inputSchema["properties"]).toEqual({})
    expect(read?.inputSchema["required"]).toBeUndefined()
  })

  test("applications_create requires exactly upstream's four fields", () => {
    const create = findAction(careerpack, ACTION_APPLICATION_CREATE)
    expect(create?.inputSchema["required"]).toEqual(["company", "position", "location", "source"])
  })

  test("applications_create accepts exactly upstream's properties — `position`, never `role`", () => {
    const create = findAction(careerpack, ACTION_APPLICATION_CREATE)
    const properties = create?.inputSchema["properties"] as Record<string, unknown>
    expect(Object.keys(properties).sort()).toEqual(
      ["company", "cv_id", "location", "notes", "position", "salary", "source", "status"].sort(),
    )
    expect(properties["role"]).toBeUndefined()
  })

  test("the status enum is upstream's whitelist, not a rewritten one", () => {
    const create = findAction(careerpack, ACTION_APPLICATION_CREATE)
    const properties = create?.inputSchema["properties"] as Record<string, Record<string, unknown>>
    expect(properties["status"]?.["enum"]).toEqual([
      "applied",
      "screening",
      "interview",
      "offer",
      "rejected",
      "withdrawn",
      "accepted",
    ])
  })

  test("every property carries the description a model reads before calling", () => {
    const create = findAction(careerpack, ACTION_APPLICATION_CREATE)
    const properties = create?.inputSchema["properties"] as Record<string, Record<string, unknown>>
    for (const [name, schema] of Object.entries(properties)) {
      expect(typeof schema["description"], `${name} needs a description`).toBe("string")
    }
  })
})

/**
 * The end of the proven chain (docs/16): the shipped DATA, driven through the generic
 * adapter, must put CareerPack's real tool name on the wire. Everything above checks the
 * manifest; this checks that the manifest is what actually gets called.
 */
test("shipped careerpack data reaches the wire as profile_get", async () => {
  let sent = "{}"
  const fetcher = ((_input: unknown, init?: RequestInit) => {
    sent = String(init?.body)
    const request = JSON.parse(sent) as Record<string, unknown>
    if (request["method"] === "initialize") {
      return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: request["id"], result: { protocolVersion: "2025-06-18", capabilities: {} } }), { headers: { "content-type": "application/json" } }))
    }
    if (request["method"] === "notifications/initialized") return Promise.resolve(new Response(null, { status: 202 }))
    const result = { structuredContent: { ok: true } }
    return Promise.resolve(new Response(JSON.stringify({ jsonrpc: "2.0", id: request["id"], result }), { headers: { "content-type": "application/json" } }))
  }) as FetchLike

  const context: CloudAdapterContext = {
    requestId: "req_test",
    credential: { connectionId: "conn_test", baseUrl: "https://cp.example.com/mcp", token: "cp_live_x9" },
    signal: new AbortController().signal,
  }
  const result = await createRemoteMcpAdapter(careerpack, { fetcher }).execute(ACTION_PROFILE_READ, {}, context)
  expect(result.output).toEqual({ ok: true })

  expect((JSON.parse(sent) as Record<string, Record<string, unknown>>)["params"]?.["name"]).toBe("profile_get")
})
