// @vitest-environment node
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest"
import { open } from "@cg/auth"
import { getFunctionName } from "convex/server"

const KEY = Buffer.alloc(32, 19).toString("base64")
const cookieJar = new Map<string, string>()
const queries: { reference: unknown; token?: string }[] = []
const discoveryCalls: string[] = []
const mutations: unknown[] = []
let userId: unknown = "authoritative-user-a"
let queryError: Error | null = null
let token: string | undefined = "fixture-session-a"

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => cookieJar.has(name) ? { value: cookieJar.get(name) } : undefined,
    set: (name: string, value: string) => void cookieJar.set(name, value),
    delete: (options: { name: string } | string) =>
      void cookieJar.delete(typeof options === "string" ? options : options.name),
  }),
}))
vi.mock("next/navigation", () => ({
  redirect: (destination: string) => { throw new Error("FIXTURE_REDIRECT:" + destination) },
}))
vi.mock("@convex-dev/auth/nextjs/server", () => ({
  convexAuthNextjsToken: async () => token,
}))
vi.mock("convex/nextjs", () => ({
  fetchQuery: async (reference: unknown, _args: unknown, options: { token?: string }) => {
    queries.push({ reference, token: options.token })
    if (queryError !== null) throw queryError
    return userId
  },
  fetchMutation: async (...args: unknown[]) => { mutations.push(args) },
}))
vi.mock("@/lib/oauth/discovery", () => ({
  discoverAuthServer: async (resource: string) => {
    discoveryCalls.push(resource)
    return {
      issuer: "https://auth.fixture.test",
      authorizationEndpoint: "https://auth.fixture.test/authorize",
      tokenEndpoint: "https://auth.fixture.test/token",
      registrationEndpoint: null,
      grantTypes: ["authorization_code"],
      scope: "mcp.read",
      resource,
    }
  },
}))

const { startOAuthConnect } = await import("./actions")
const { OAUTH_STATE_COOKIE, parseFlowState } = await import("@/lib/oauth/state")

function form(): FormData {
  const value = new FormData()
  value.set("connectorId", "careerpack")
  value.set("clientId", "fixture-client")
  value.set("userId", "forged-user-b")
  return value
}

beforeEach(() => {
  vi.stubEnv("CREDENTIAL_ENCRYPTION_KEY", KEY)
  vi.stubEnv("APP_ORIGIN", "https://dashboard.fixture.test")
  vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("Unexpected fixture network call") }))
  cookieJar.clear()
  queries.length = 0
  discoveryCalls.length = 0
  mutations.length = 0
  userId = "authoritative-user-a"
  queryError = null
  token = "fixture-session-a"
})
afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe("OAuth start owner binding", () => {
  test("seals the authenticated owner rather than a form-supplied owner or session token", async () => {
    await expect(startOAuthConnect({ error: null }, form())).rejects.toThrow("FIXTURE_REDIRECT:")

    expect(queries).toHaveLength(1)
    expect(getFunctionName(queries[0]!.reference as never)).toBe("features/auth/identity:currentUserId")
    expect(queries[0]?.token).toBe("fixture-session-a")
    const cookie = cookieJar.get(OAUTH_STATE_COOKIE)
    expect(cookie).toMatch(/^v1\./)
    const plaintext = await open(cookie!, KEY)
    const flow = parseFlowState(plaintext, Date.now())
    expect(flow?.userId).toBe("authoritative-user-a")
    expect(plaintext).not.toContain("forged-user-b")
    expect(plaintext).not.toContain("fixture-session-a")
    expect(discoveryCalls).toHaveLength(1)
    expect(mutations).toHaveLength(0)
    expect(fetch).not.toHaveBeenCalled()
  })

  test.each([null, undefined, "", { email: "owner@fixture.test" }])(
    "unusable authoritative identity %j refuses discovery and cookie creation", async (identity) => {
      userId = identity
      expect(await startOAuthConnect({ error: null }, form())).toEqual({ error: "not_signed_in" })
      expect(discoveryCalls).toHaveLength(0)
      expect(cookieJar.size).toBe(0)
      expect(mutations).toHaveLength(0)
      expect(fetch).not.toHaveBeenCalled()
    },
  )

  test("identity lookup failure refuses discovery and cookie creation", async () => {
    queryError = new Error("fixture unavailable")
    expect(await startOAuthConnect({ error: null }, form())).toEqual({ error: "not_signed_in" })
    expect(discoveryCalls).toHaveLength(0)
    expect(cookieJar.size).toBe(0)
    expect(mutations).toHaveLength(0)
  })

  test.each([undefined, ""])("an absent session %j refuses identity lookup", async (session) => {
    token = session
    expect(await startOAuthConnect({ error: null }, form())).toEqual({ error: "not_signed_in" })
    expect(queries).toHaveLength(0)
    expect(discoveryCalls).toHaveLength(0)
    expect(cookieJar.size).toBe(0)
    expect(mutations).toHaveLength(0)
  })
})
