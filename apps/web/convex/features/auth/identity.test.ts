import { describe, expect, test } from "vitest"
import { api } from "../../_generated/api"
import { asUser, createUser, expectRejected, setupConvex } from "../../test.helpers"

describe("features/auth/identity:currentUserId", () => {
  test("unauthenticated calls cannot resolve an owner", async () => {
    const t = setupConvex()
    await expectRejected(t.query(api.features.auth.identity.currentUserId, {}), "NOT_AUTHORIZED")
  })

  test("resolves the authenticated subject even when accounts share an email", async () => {
    const t = setupConvex()
    const a = await createUser(t, "same@example.test")
    const b = await createUser(t, "same@example.test")
    expect(await asUser(t, a).query(api.features.auth.identity.currentUserId, {})).toBe(a)
    expect(await asUser(t, b).query(api.features.auth.identity.currentUserId, {})).toBe(b)
  })

  test("the same user retains their owner id across session rotation without an email", async () => {
    const t = setupConvex()
    const userId = await createUser(t)
    const original = t.withIdentity({ subject: userId + "|session-original" })
    const refreshed = t.withIdentity({ subject: userId + "|session-refreshed" })
    expect(await original.query(api.features.auth.identity.currentUserId, {})).toBe(userId)
    expect(await refreshed.query(api.features.auth.identity.currentUserId, {})).toBe(userId)
  })

  test("caller-supplied owner overrides are rejected by the empty argument contract", async () => {
    const t = setupConvex()
    const a = await createUser(t)
    const b = await createUser(t)
    await expect(asUser(t, a).query(
      api.features.auth.identity.currentUserId, { userId: b } as never,
    )).rejects.toThrow()
  })
})
