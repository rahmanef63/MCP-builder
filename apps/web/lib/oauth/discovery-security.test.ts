// @vitest-environment node
import { afterEach, describe, expect, test, vi } from "vitest"

import { discoverAuthServer as discoverWithTransport, DiscoveryError } from "./discovery"

const discoverAuthServer = (resource: string) => discoverWithTransport(resource, { fetcher: fetch })

const RESOURCE = "https://resource.example.com/mcp"
const ISSUER = "https://auth.example.com"
const PRM_PATH = "https://resource.example.com/.well-known/oauth-protected-resource/mcp"
const PRM_ROOT = "https://resource.example.com/.well-known/oauth-protected-resource"
const AS_PATH = `${ISSUER}/.well-known/oauth-authorization-server`
const OPENID_PATH = `${ISSUER}/.well-known/openid-configuration`
const MAX_BYTES = 64 * 1024
const PRM = { authorization_servers: [ISSUER], scopes_supported: ["mcp.read"] }
const AS_DOCUMENT = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  registration_endpoint: `${ISSUER}/register`,
  code_challenge_methods_supported: ["S256"],
}
const json = (value: unknown) => new Response(JSON.stringify(value))

function fixtures(overrides: Record<string, () => Response | Promise<Response>> = {}) {
  const calls: { url: string; init?: RequestInit }[] = []
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input)
    calls.push({ url, init })
    const override = overrides[url]
    if (override) return override()
    if (url === PRM_PATH || url === PRM_ROOT) return json(PRM)
    if (url === AS_PATH || url === OPENID_PATH) return json(AS_DOCUMENT)
    throw new Error("Unexpected fixture URL")
  }))
  return calls
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe("OAuth metadata fetch security", () => {
  test("discovers valid metadata using bounded byte streams", async () => {
    const bytes = new TextEncoder().encode(JSON.stringify(PRM))
    const calls = fixtures({
      [PRM_PATH]: () => new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes.subarray(0, 10))
          controller.enqueue(bytes.subarray(10))
          controller.close()
        },
      })),
    })
    await expect(discoverAuthServer(RESOURCE)).resolves.toMatchObject({
      issuer: ISSUER, resource: RESOURCE, scope: "mcp.read", tokenEndpoint: AS_DOCUMENT.token_endpoint,
    })
    expect(calls.map(({ url }) => url)).toEqual([PRM_PATH, AS_PATH])
    for (const { init } of calls) {
      expect(init?.redirect).toBe("manual")
      expect(init?.signal).toBeInstanceOf(AbortSignal)
    }
  })

  test.each([
    [301, "http://169.254.169.254/latest/meta-data/"],
    [302, "https://127.0.0.1/private"],
    [303, "https://10.0.0.1/private"],
    [307, "https://user:password@evil.example.com/metadata"],
    [308, "https://redirect.example.com/metadata"],
  ])("does not follow a %s protected-resource redirect to %s", async (status, target) => {
    const visited: string[] = []
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input)
      visited.push(url)
      if (url === PRM_PATH) {
        // Model fetch's redirect behavior without opening any network socket.
        if (init?.redirect === "follow") {
          visited.push(target)
          return json(PRM)
        }
        return new Response(null, { status, headers: { location: target } })
      }
      if (url === AS_PATH) return json(AS_DOCUMENT)
      return new Response(null, { status: 404 })
    }))
    await expect(discoverAuthServer(RESOURCE)).rejects.toMatchObject({
      reason: "no protected-resource metadata",
    })
    expect(visited).toEqual([PRM_PATH, PRM_ROOT])
  })

  test("refuses an authorization-server redirect and tries the next metadata form", async () => {
    const calls = fixtures({
      [AS_PATH]: () => new Response(null, {
        status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" },
      }),
    })
    await expect(discoverAuthServer(RESOURCE)).resolves.toMatchObject({ issuer: ISSUER })
    expect(calls.map(({ url }) => url)).toEqual([PRM_PATH, AS_PATH, OPENID_PATH])
    expect(calls.find(({ url }) => url === AS_PATH)?.init?.redirect).toBe("manual")
  })

  test("cancels a declared oversized response without reading it and recovers", async () => {
    let pulls = 0
    const cancel = vi.fn()
    const calls = fixtures({
      [PRM_PATH]: () => new Response(new ReadableStream<Uint8Array>({
        pull(controller) {
          pulls++
          controller.enqueue(new TextEncoder().encode(JSON.stringify(PRM)))
          controller.close()
        },
        cancel,
      }, { highWaterMark: 0 }), { headers: { "content-length": String(MAX_BYTES + 1) } }),
    })
    await expect(discoverAuthServer(RESOURCE)).resolves.toMatchObject({ issuer: ISSUER })
    expect(pulls).toBe(0)
    expect(cancel).toHaveBeenCalledOnce()
    expect(calls.map(({ url }) => url)).toEqual([PRM_PATH, PRM_ROOT, AS_PATH])
  })

  test.each([undefined, "1"])("bounds actual stream bytes with content-length %s", async (length) => {
    const bytes = new TextEncoder().encode(JSON.stringify(PRM).padEnd(MAX_BYTES + 1))
    let pulls = 0
    const cancel = vi.fn()
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls++
        if (pulls === 1) controller.enqueue(bytes.subarray(0, MAX_BYTES / 2))
        else if (pulls === 2) controller.enqueue(bytes.subarray(MAX_BYTES / 2, MAX_BYTES))
        else if (pulls === 3) controller.enqueue(bytes.subarray(MAX_BYTES))
        else controller.close()
      },
      cancel,
    }, { highWaterMark: 0 })
    const calls = fixtures({
      [PRM_PATH]: () => new Response(body, {
        headers: length === undefined ? {} : { "content-length": length },
      }),
    })
    await expect(discoverAuthServer(RESOURCE)).resolves.toMatchObject({ issuer: ISSUER })
    expect(pulls).toBe(3)
    expect(cancel).toHaveBeenCalledOnce()
    expect(body.locked).toBe(false)
    expect(calls.map(({ url }) => url)).toEqual([PRM_PATH, PRM_ROOT, AS_PATH])
  })

  test("counts UTF-8 bytes instead of characters", async () => {
    const bytes = new TextEncoder().encode(JSON.stringify({ ...PRM, padding: "é".repeat(MAX_BYTES / 2) }))
    expect(bytes.byteLength).toBeGreaterThan(MAX_BYTES)
    const calls = fixtures({ [PRM_PATH]: () => new Response(bytes) })
    await expect(discoverAuthServer(RESOURCE)).resolves.toMatchObject({ issuer: ISSUER })
    expect(calls.map(({ url }) => url)).toContain(PRM_ROOT)
  })

  test("accepts a metadata document at the byte limit", async () => {
    const calls = fixtures({
      [PRM_PATH]: () => new Response(JSON.stringify(PRM).padEnd(MAX_BYTES)),
    })
    await expect(discoverAuthServer(RESOURCE)).resolves.toMatchObject({ issuer: ISSUER })
    expect(calls.map(({ url }) => url)).toEqual([PRM_PATH, AS_PATH])
  })

  test("recovers from a stream read error", async () => {
    const calls = fixtures({
      [PRM_PATH]: () => new Response(new ReadableStream<Uint8Array>({
        pull(controller) { controller.error(new Error("fixture stream failure")) },
      })),
    })
    await expect(discoverAuthServer(RESOURCE)).resolves.toMatchObject({ issuer: ISSUER })
    expect(calls.map(({ url }) => url)).toEqual([PRM_PATH, PRM_ROOT, AS_PATH])
  })

  test("a body timeout aborts its read and recovers through the next URL", async () => {
    const controller = new AbortController()
    const timeout = vi.spyOn(AbortSignal, "timeout").mockReturnValueOnce(controller.signal)
    let readStarted!: () => void
    const reading = new Promise<void>((resolve) => { readStarted = resolve })
    let signal: AbortSignal | null | undefined
    const calls = fixtures({
      [PRM_PATH]: () => new Response(new ReadableStream<Uint8Array>({
        pull(stream) {
          signal = calls[0]?.init?.signal
          signal?.addEventListener("abort", () => stream.error(signal?.reason), { once: true })
          readStarted()
        },
      }, { highWaterMark: 0 })),
    })
    const result = discoverAuthServer(RESOURCE)
    await reading
    controller.abort(new DOMException("fixture timeout", "TimeoutError"))
    await expect(result).resolves.toMatchObject({ issuer: ISSUER })
    expect(timeout).toHaveBeenCalledWith(8000)
    expect(signal?.aborted).toBe(true)
    expect(calls.map(({ url }) => url)).toEqual([PRM_PATH, PRM_ROOT, AS_PATH])
    expect(calls[1]?.init?.signal).not.toBe(signal)
  })

  test("all failed body reads produce a typed discovery failure", async () => {
    const failed = () => new Response(new ReadableStream<Uint8Array>({
      start(controller) { controller.error(new Error("fixture stream failure")) },
    }))
    fixtures({ [PRM_PATH]: failed, [PRM_ROOT]: failed })
    await expect(discoverAuthServer(RESOURCE)).rejects.toBeInstanceOf(DiscoveryError)
  })
})
