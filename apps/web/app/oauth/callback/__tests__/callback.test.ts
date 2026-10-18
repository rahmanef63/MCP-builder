// @vitest-environment node
/**
 * The callback is where a credential is created, so it is tested as a whole:
 * real sealing, real flow-state cookie, real token exchange over a stubbed
 * socket. Only the two boundaries this app does not own are mocked — the cookie
 * jar and the Convex client.
 *
 * What each case protects:
 *  - a wrong `state` must not store anything (a code delivered to a callback
 *    nobody started is an attacker's code);
 *  - the stored `baseUrl` comes from the MANIFEST, never from the cookie;
 *  - what reaches Convex is ciphertext, never the token.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest"

import { open, seal } from "@cg/auth"
import { parseOAuthRenewal } from "@cg/core"

const KEY = Buffer.alloc(32, 7).toString("base64")
/** CareerPack PRODUCTION — the manifest is the source of truth for this. */
const RESOURCE = "https://proficient-dove-151.convex.site/mcp"
const REDIRECT = "https://connectors.example.com/oauth/callback"

const cookieJar = new Map<string, string>()
const mutations: { args: Record<string, unknown>; token?: string }[] = []
const identityQueries: { token?: string }[] = []
const boundaryCalls: string[] = []
let currentUserId: unknown = "user_a"
let identityError: Error | null = null
let sessionToken: string | undefined = "session-token"

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => {
      const value = cookieJar.get(name)
      return value === undefined ? undefined : { name, value }
    },
    set: (name: string, value: string) => void cookieJar.set(name, value),
    delete: (options: { name: string } | string) =>
      void cookieJar.delete(typeof options === "string" ? options : options.name),
  }),
}))

vi.mock("convex/nextjs", () => ({
  fetchMutation: async (_reference: unknown, args: Record<string, unknown>, options?: { token?: string }) => {
    boundaryCalls.push("store")
    mutations.push({ args, token: options?.token })
    return { connectionId: "conn_1" }
  },
  fetchQuery: async (_reference: unknown, _args: unknown, options?: { token?: string }) => {
    boundaryCalls.push("identity")
    identityQueries.push(options ?? {})
    if (identityError !== null) throw identityError
    return currentUserId
  },
}))

vi.mock("@convex-dev/auth/nextjs/server", () => ({
  convexAuthNextjsToken: async () => sessionToken,
}))

vi.mock("@/lib/oauth/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/oauth/client")>()
  return {
    ...actual,
    exchangeCode: (params: Parameters<typeof actual.exchangeCode>[0]) =>
      actual.exchangeCode(params, { fetcher: fetch }),
  }
})

const { GET } = await import("../route")
const { writeFlowState, OAUTH_STATE_COOKIE } = await import("@/lib/oauth/state")

const FLOW = {
  userId: "user_a",
  connectorId: "careerpack",
  state: "state_1",
  verifier: "verifier_1",
  clientId: "client_1",
  clientSecret: null,
  tokenEndpoint: "https://careerpack.org/api/oauth/token",
  redirectUri: REDIRECT,
  resource: RESOURCE,
  scope: "mcp.read mcp.write",
}

function callback(query: string): Request {
  return new Request(`https://connectors.example.com/oauth/callback?${query}`)
}

function tokenServer(token = "cp_live_token"): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () => {
        boundaryCalls.push("exchange")
        return new Response(
          JSON.stringify({
            access_token: token,
            expires_in: 3_600,
            refresh_token: "cp_refresh_token",
          }),
          { status: 200 },
        )
      },
    ),
  )
}

beforeEach(() => {
  vi.stubEnv("CREDENTIAL_ENCRYPTION_KEY", KEY)
  cookieJar.clear()
  mutations.length = 0
  identityQueries.length = 0
  boundaryCalls.length = 0
  currentUserId = "user_a"
  identityError = null
  sessionToken = "session-token"
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe("oauth callback", () => {
  test("exchanges the code and stores a sealed credential", async () => {
    await writeFlowState(FLOW)
    tokenServer()

    const response = await GET(callback("code=abc&state=state_1"))

    expect(response.status).toBe(307)
    expect(response.headers.get("location")).toContain("connected=careerpack")
    expect(mutations).toHaveLength(1)

    const args = mutations[0]?.args ?? {}
    expect(args["connectorId"]).toBe("careerpack")
    // From the shipped manifest — not from the cookie, and not from the URL.
    expect(args["baseUrl"]).toBe(RESOURCE)
    expect(args["authType"]).toBe("bearer")
    // The token itself never reaches Convex.
    expect(args["tokenCipher"]).not.toBe("cp_live_token")
    expect(String(args["tokenCipher"])).toMatch(/^v1\./)
    expect(await open(String(args["tokenCipher"]), KEY)).toBe("cp_live_token")
    expect(args["tokenExpiresAt"]).toEqual(expect.any(Number))
    expect(Number(args["tokenExpiresAt"])).toBeGreaterThan(Date.now() + 3_500_000)
    expect(String(args["renewalCipher"])).toMatch(/^v1\./)
    const renewal = parseOAuthRenewal(await open(String(args["renewalCipher"]), KEY))
    expect(renewal).toEqual({
      v: 1,
      grantType: "refresh_token",
      tokenEndpoint: FLOW.tokenEndpoint,
      clientId: FLOW.clientId,
      clientSecret: null,
      refreshToken: "cp_refresh_token",
      scope: FLOW.scope,
      resource: RESOURCE,
    })
    expect(JSON.stringify(args)).not.toContain("cp_refresh_token")
  })

  test("the flow is single-use — a replayed callback finds nothing", async () => {
    await writeFlowState(FLOW)
    tokenServer()
    await GET(callback("code=abc&state=state_1"))

    const replay = await GET(callback("code=abc&state=state_1"))
    expect(replay.headers.get("location")).toContain("connect_error=flow_expired")
    expect(mutations).toHaveLength(1)
  })

  test("DENIED: a state that does not match the flow", async () => {
    await writeFlowState(FLOW)
    tokenServer()

    const response = await GET(callback("code=abc&state=someone_elses"))
    expect(response.headers.get("location")).toContain("connect_error=state_mismatch")
    expect(mutations).toHaveLength(0)
  })

  test("DENIED: the user refused consent", async () => {
    await writeFlowState(FLOW)
    const response = await GET(callback("error=access_denied&state=state_1"))
    expect(response.headers.get("location")).toContain("connect_error=consent_denied")
    expect(mutations).toHaveLength(0)
  })

  test("an upstream refusal stores nothing and says so", async () => {
    await writeFlowState(FLOW)
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 })),
    )

    const response = await GET(callback("code=abc&state=state_1"))
    expect(response.headers.get("location")).toContain("connect_error=exchange_failed")
    expect(mutations).toHaveLength(0)
  })

  test("DENIED: a tampered cookie is not a flow", async () => {
    await writeFlowState(FLOW)
    // Flip a character in the ciphertext: AES-GCM's tag check fails, and a
    // failed open is indistinguishable from no cookie at all.
    const [name, sealed] = [...cookieJar.entries()][0] ?? ["", ""]
    cookieJar.set(name, `${sealed.slice(0, -2)}${sealed.endsWith("A") ? "B" : "A"}=`)

    const response = await GET(callback("code=abc&state=state_1"))
    expect(response.headers.get("location")).toContain("connect_error=flow_expired")
    expect(mutations).toHaveLength(0)
  })
})

describe("oauth callback owner binding", () => {
  test("switching dashboard accounts refuses the code before exchange or storage", async () => {
    await writeFlowState(FLOW)
    currentUserId = "user_b"
    sessionToken = "session-for-user-b"
    tokenServer()

    const response = await GET(callback("code=abc&state=state_1"))

    expect(response.headers.get("location")).toContain("connect_error=state_mismatch")
    expect(identityQueries).toEqual([{ token: "session-for-user-b" }])
    expect(fetch).not.toHaveBeenCalled()
    expect(mutations).toHaveLength(0)
    expect(cookieJar.has(OAUTH_STATE_COOKIE)).toBe(false)
    expect(boundaryCalls).toEqual(["identity"])
  })

  test("the same user may finish with a refreshed dashboard session", async () => {
    await writeFlowState(FLOW)
    sessionToken = "refreshed-session-for-user-a"
    tokenServer()

    const response = await GET(callback("code=abc&state=state_1"))

    expect(response.headers.get("location")).toContain("connected=careerpack")
    expect(identityQueries).toEqual([{ token: "refreshed-session-for-user-a" }])
    expect(mutations).toHaveLength(1)
    expect(mutations[0]?.token).toBe("refreshed-session-for-user-a")
    expect(boundaryCalls).toEqual(["identity", "exchange", "store"])
    expect(await open(String(mutations[0]?.args.tokenCipher), KEY)).toBe("cp_live_token")
  })

  test.each([null, undefined, "", { email: "owner@example.com" }])(
    "an unusable identity result fails closed before exchange: %j", async (identity) => {
      await writeFlowState(FLOW)
      currentUserId = identity
      tokenServer()

      const response = await GET(callback("code=abc&state=state_1"))

      expect(response.headers.get("location")).toContain("connect_error=not_signed_in")
      expect(fetch).not.toHaveBeenCalled()
      expect(mutations).toHaveLength(0)
      expect(cookieJar.has(OAUTH_STATE_COOKIE)).toBe(false)
    },
  )

  test("an identity query failure fails closed without redeeming the code", async () => {
    await writeFlowState(FLOW)
    identityError = new Error("fixture identity unavailable")
    tokenServer()

    const response = await GET(callback("code=abc&state=state_1"))

    expect(response.headers.get("location")).toContain("connect_error=not_signed_in")
    expect(fetch).not.toHaveBeenCalled()
    expect(mutations).toHaveLength(0)
    expect(cookieJar.has(OAUTH_STATE_COOKIE)).toBe(false)
  })

  test.each([undefined, ""])("a missing dashboard session refuses the code: %j", async (token) => {
    await writeFlowState(FLOW)
    sessionToken = token
    tokenServer()

    const response = await GET(callback("code=abc&state=state_1"))

    expect(response.headers.get("location")).toContain("connect_error=not_signed_in")
    expect(identityQueries).toHaveLength(0)
    expect(fetch).not.toHaveBeenCalled()
    expect(mutations).toHaveLength(0)
  })

  test("a validly sealed pre-owner-binding cookie is rejected before identity lookup or exchange", async () => {
    const { userId: _legacyOwner, ...legacy } = FLOW
    cookieJar.set(OAUTH_STATE_COOKIE, await seal(JSON.stringify({
      v: 1, ...legacy, exp: Math.floor(Date.now() / 1000) + 600,
    }), KEY))
    tokenServer()

    const response = await GET(callback("code=abc&state=state_1"))

    expect(response.headers.get("location")).toContain("connect_error=flow_expired")
    expect(identityQueries).toHaveLength(0)
    expect(fetch).not.toHaveBeenCalled()
    expect(mutations).toHaveLength(0)
    expect(cookieJar.has(OAUTH_STATE_COOKIE)).toBe(false)
  })
})
