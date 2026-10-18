import { describe, expect, test } from "vitest"
import type { Id } from "../../_generated/dataModel"
import { api } from "../../_generated/api"
import { asUser, createUser, expectRejected, setupConvex } from "../../test.helpers"

const SEALED = `v1.${"A".repeat(16)}.${"B".repeat(24)}`
const ENDPOINT = "https://backend.composio.dev/v3/mcp/server_123"

describe("connection URL persistence", () => {
  test("stores and reconnects the selected Composio user without changing ownership", async () => {
    const t = setupConvex()
    const owner = await createUser(t)
    const other = await createUser(t)
    const client = asUser(t, owner)
    const first = await client.mutation(api.features.connections.mutations.upsert, {
      connectorId: "composio",
      baseUrl: `${ENDPOINT}?user_id=selected-user`,
      tokenCipher: SEALED,
      authType: "api_key",
    })

    let row = await t.run(async (ctx) => ctx.db.get(first.connectionId as Id<"connections">))
    expect(row).toMatchObject({
      ownerId: owner,
      baseUrl: `${ENDPOINT}?user_id=selected-user`,
      credentialVersion: 1,
    })
    expect(await asUser(t, other).query(api.features.connections.queries.listMine, {})).toEqual([])

    const second = await client.mutation(api.features.connections.mutations.upsert, {
      connectorId: "composio",
      baseUrl: `${ENDPOINT}/?user_id=reconnected-user`,
      tokenCipher: SEALED,
      authType: "api_key",
    })
    expect(second.connectionId).toBe(first.connectionId)
    row = await t.run(async (ctx) => ctx.db.get(first.connectionId as Id<"connections">))
    expect(row).toMatchObject({
      ownerId: owner,
      baseUrl: `${ENDPOINT}?user_id=reconnected-user`,
      credentialVersion: 2,
    })
  })

  test("rejects hosted auth or ambiguous query parameters before changing a stored connection", async () => {
    const t = setupConvex()
    const owner = await createUser(t)
    const client = asUser(t, owner)
    const saved = await client.mutation(api.features.connections.mutations.upsert, {
      connectorId: "composio",
      baseUrl: `${ENDPOINT}?user_id=selected-user`,
      tokenCipher: SEALED,
      authType: "api_key",
    })

    for (const query of ["user_id=one&user_id=two", "user_id=one&token=secret", "user_id="]) {
      await expectRejected(client.mutation(api.features.connections.mutations.upsert, {
        connectorId: "composio",
        baseUrl: `${ENDPOINT}?${query}`,
        tokenCipher: SEALED,
        authType: "api_key",
      }), "INVALID_INPUT")
    }
    const row = await t.run(async (ctx) => ctx.db.get(saved.connectionId as Id<"connections">))
    expect(row).toMatchObject({
      baseUrl: `${ENDPOINT}?user_id=selected-user`,
      credentialVersion: 1,
    })
  })

  test("keeps stripping queries for other connectors", async () => {
    const t = setupConvex()
    const owner = await createUser(t)
    const saved = await asUser(t, owner).mutation(api.features.connections.mutations.upsert, {
      connectorId: "careerpack",
      baseUrl: `${ENDPOINT}?user_id=selected-user&token=secret`,
      tokenCipher: SEALED,
      authType: "bearer",
    })
    const row = await t.run(async (ctx) => ctx.db.get(saved.connectionId as Id<"connections">))
    expect(row?.baseUrl).toBe(ENDPOINT)
  })
})
