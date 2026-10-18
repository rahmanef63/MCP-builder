import { describe, expect, test } from "bun:test"
import { GatewayError } from "@cg/core"
import type { ConnectorManifest, JsonSchema } from "@cg/core"
import { validateManifest } from "./manifest"
import { compileSchema } from "./validator"

function manifest(inputSchema: JsonSchema = { type: "object" }): ConnectorManifest {
  return {
    id: "fixture", name: "Fixture", version: "1.0.0",
    executor: "cloud", auth: { type: "none" },
    actions: [{
      id: "fixture.items.list", title: "List items", description: "List fixture items.",
      inputSchema, risk: "R0", annotations: { readOnly: true, destructive: false },
    }],
  }
}

function rejection(value: unknown): GatewayError {
  try {
    validateManifest(value)
  } catch (error) {
    expect(error).toBeInstanceOf(GatewayError)
    expect((error as GatewayError).code).toBe("INVALID_INPUT")
    return error as GatewayError
  }
  throw new Error("Expected an invalid MCP manifest to fail at the manifest gate")
}

describe("manifest MCP boundary", () => {
  test.each([
    "fixture.items_list", "fixture/items/list", "fixture items list",
    ".fixture.items.list", "a".repeat(129),
  ])("rejects action ids that cannot become MCP tools: %s", (id) => {
    const value = manifest()
    value.actions[0]!.id = id
    expect(rejection(value).message).toContain("/actions/0/id")
  })

  test.each(["fixture.items.list", "fixture.items-list", "A", "a".repeat(128)])(
    "accepts an action id within the MCP tool-name contract: %s", (id) => {
      const value = manifest()
      value.actions[0]!.id = id
      expect(validateManifest(value).actions[0]!.id).toBe(id)
    },
  )

  test.each<JsonSchema>([
    {}, { type: "string" }, { type: "array", items: { type: "string" } },
    { type: ["object", "null"] },
  ])("rejects input without an unambiguous object root: %j", (schema) => {
    expect(rejection(manifest(schema)).message).toContain("/actions/0/inputSchema")
  })

  test.each<JsonSchema>([{}, { type: "number" }, { type: ["object", "null"] }])(
    "rejects output without an unambiguous object root: %j", (schema) => {
      const value = manifest()
      value.actions[0]!.outputSchema = schema
      expect(rejection(value).message).toContain("/actions/0/outputSchema")
    },
  )

  test("accepts object roots with nested scalar, array, nullable and referenced schemas", () => {
    const value = manifest({
      type: "object",
      $defs: { item: { type: "string", minLength: 1 } },
      properties: {
        label: { type: ["string", "null"] },
        items: { type: "array", items: { $ref: "#/$defs/item" } },
      },
      additionalProperties: false,
    })
    value.actions[0]!.outputSchema = {
      type: "object", properties: { count: { type: "integer", minimum: 0 } }, required: ["count"],
    }
    expect(validateManifest(value)).toBe(value)
  })

  test("still rejects invalid nested schemas after accepting the object root", () => {
    expect(rejection(manifest({
      type: "object", properties: { label: { type: "not-a-json-type" } },
    })).message).toContain("schema-not-compilable")
  })

  test("rejects asynchronous validators before they can bypass a synchronous gate", () => {
    expect(() => compileSchema({ $async: true, type: "object", required: ["value"] })).toThrow(GatewayError)
  })

  test.each(["inputSchema", "outputSchema"] as const)(
    "rejects an async action %s at the manifest gate", (field) => {
      const value = manifest()
      value.actions[0]![field] = { $async: true, type: "object", required: ["value"] }
      expect(rejection(value).message).toContain("schema-not-compilable")
    },
  )
})
