import { describe, expect, test } from "bun:test"
import { EventEmitter } from "node:events"
import { createServer } from "node:http"
import type { ClientRequest, IncomingMessage, RequestOptions, Server } from "node:http"
import { PassThrough } from "node:stream"
import { createSafeFetch } from "./index"
import type { Requester, ResolvedAddress } from "./index"

const PUBLIC = { address: "8.8.8.8", family: 4 as const }
const URL_ = "https://upstream.example/path?q=fixture"

function fixture(status = 200, headers: Record<string, string> = {}) {
  const message = Object.assign(new PassThrough(), {
    statusCode: status,
    headers,
    rawHeaders: Object.entries(headers).flat(),
  }) as unknown as IncomingMessage & PassThrough
  let requests = 0
  let destroyed = false
  let captured: RequestOptions | undefined
  let outgoing: ClientRequest | undefined
  const request: Requester = (options, callback) => {
    requests += 1
    captured = options
    const emitter = new EventEmitter() as ClientRequest
    emitter.destroy = () => {
      destroyed = true
      return emitter
    }
    emitter.end = (() => {
      queueMicrotask(() => callback(message))
      return emitter
    }) as ClientRequest["end"]
    outgoing = emitter
    return emitter
  }
  return {
    message,
    request,
    get requests() { return requests },
    get destroyed() { return destroyed },
    get captured() { return captured! },
    get outgoing() { return outgoing! },
  }
}

function fetchFixture(f: ReturnType<typeof fixture>, extra = {}) {
  return createSafeFetch({
    policy: { allowLoopback: false },
    resolve: async () => [PUBLIC],
    request: f.request,
    ...extra,
  })
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const address = server.address()
  if (address === null || typeof address === "string") throw new Error("Missing fixture port")
  return address.port
}

function close(server: Server): void {
  server.closeAllConnections()
  server.close()
}

describe("safeFetch DNS pinning", () => {
  test.each([
    "127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.0.1",
    "100.64.0.1", "192.0.2.1", "198.18.0.1", "::1", "::ffff:127.0.0.1",
    "fc00::1", "fe80::1", "ff02::1", "not-an-address", "fe80::1%eth0",
  ])("rejects any DNS answer containing %s before opening a socket", async (address) => {
    const f = fixture()
    const fetch = fetchFixture(f, {
      resolve: async () => [
        PUBLIC,
        { address, family: address.includes(":") ? 6 : 4 },
      ],
    })
    await expect(fetch(URL_)).rejects.toMatchObject({ code: "UPSTREAM_ERROR" })
    expect(f.requests).toBe(0)
  })

  test("rejects a family mismatch and empty DNS result", async () => {
    for (const answers of [[], [{ address: "8.8.8.8", family: 6 }]]) {
      const f = fixture()
      await expect(fetchFixture(f, { resolve: async () => answers })(URL_)).rejects.toThrow()
      expect(f.requests).toBe(0)
    }
  })

  test("pins one answer for both lookup callback forms and preserves TLS/HTTP identity", async () => {
    const f = fixture()
    let lookups = 0
    const fetch = fetchFixture(f, {
      resolve: async () => {
        lookups += 1
        return [PUBLIC, { address: "1.1.1.1", family: 4 }]
      },
    })
    const response = await fetch(URL_, { redirect: "manual", cache: "no-store" } as RequestInit)
    expect(lookups).toBe(1)
    const options = f.captured as RequestOptions & { servername: string; rejectUnauthorized: boolean }
    expect(options).toMatchObject({
      hostname: "upstream.example",
      path: "/path?q=fixture",
      agent: false,
      autoSelectFamily: false,
      servername: "upstream.example",
      rejectUnauthorized: true,
      headers: { host: "upstream.example", "accept-encoding": "identity" },
    })
    const invoke = options.lookup as unknown as (
      host: string, options: { all?: boolean },
      callback: (...args: unknown[]) => void,
    ) => void
    invoke("ignored.example", {}, (...args) => expect(args).toEqual([null, PUBLIC.address, 4]))
    invoke("ignored.example", { all: true }, (...args) => expect(args).toEqual([null, [PUBLIC]]))
    f.message.end("fixture")
    expect(await response.text()).toBe("fixture")
    expect(lookups).toBe(1)
  })

  test("a public hostname cannot resolve to loopback even with development opt-in", async () => {
    const f = fixture()
    await expect(fetchFixture(f, {
      policy: { allowLoopback: true },
      resolve: async () => [{ address: "127.0.0.1", family: 4 }],
    })(URL_)).rejects.toThrow()
    expect(f.requests).toBe(0)
  })

  test("literal public addresses need no resolver", async () => {
    const f = fixture()
    const response = await fetchFixture(f, {
      resolve: async () => { throw new Error("must not resolve") },
    })("https://8.8.8.8/")
    f.message.end()
    expect(response.status).toBe(200)
    await response.text()
  })
})

describe("safeFetch lifecycle", () => {
  test("aborts slow DNS promptly and never sends after late resolution", async () => {
    const f = fixture()
    let finish!: (answers: ResolvedAddress[]) => void
    const controller = new AbortController()
    const fetch = fetchFixture(f, {
      resolve: () => new Promise<ResolvedAddress[]>((resolve) => { finish = resolve }),
    })
    const pending = fetch(URL_, { signal: controller.signal })
    controller.abort()
    await expect(pending).rejects.toMatchObject({ name: "AbortError" })
    finish([PUBLIC])
    await Promise.resolve()
    await Promise.resolve()
    expect(f.requests).toBe(0)
  })

  test("preserves a pre-aborted caller timeout without exposing its reason", async () => {
    const f = fixture()
    const controller = new AbortController()
    controller.abort(new DOMException("private reason", "TimeoutError"))
    await expect(fetchFixture(f)(URL_, { signal: controller.signal })).rejects.toMatchObject({
      name: "TimeoutError", message: "The upstream call timed out.",
    })
    expect(f.requests).toBe(0)
  })

  test("preserves a caller timeout during DNS", async () => {
    const f = fixture()
    const fetch = fetchFixture(f, {
      resolve: () => new Promise<ResolvedAddress[]>(() => {}),
    })
    await expect(fetch(URL_, { signal: AbortSignal.timeout(5) })).rejects.toMatchObject({
      name: "TimeoutError",
    })
    expect(f.requests).toBe(0)
  })

  test("preserves a caller timeout while reading a response", async () => {
    const f = fixture()
    const response = await fetchFixture(f)(URL_, { signal: AbortSignal.timeout(5) })
    await expect(response.text()).rejects.toMatchObject({ name: "TimeoutError" })
    expect(f.destroyed).toBe(true)
  })

  test("turns unexpected response header exceptions into a safe rejection", async () => {
    const f = fixture()
    f.message.rawHeaders = ["bad\r\nheader", "fixture"]
    await expect(fetchFixture(f)(URL_)).rejects.toMatchObject({ code: "UPSTREAM_ERROR" })
    expect(f.destroyed).toBe(true)
  })

  test("rejects socket upgrades and destroys the upgraded socket", async () => {
    const f = fixture()
    const response = await fetchFixture(f)(URL_)
    let destroyed = false
    f.outgoing.emit("upgrade", {}, { destroy() { destroyed = true } })
    await expect(response.text()).rejects.toThrow()
    expect(destroyed).toBe(true)
    expect(f.destroyed).toBe(true)
  })

  test("default bound also covers DNS", async () => {
    const f = fixture()
    const fetch = fetchFixture(f, {
      timeoutMs: 5,
      resolve: () => new Promise<ResolvedAddress[]>(() => {}),
    })
    await expect(fetch(URL_)).rejects.toMatchObject({ name: "TimeoutError" })
    expect(f.requests).toBe(0)
  })

  test("caller abort remains effective after headers", async () => {
    const f = fixture()
    const controller = new AbortController()
    const response = await fetchFixture(f)(URL_, { signal: controller.signal })
    controller.abort()
    await expect(response.text()).rejects.toMatchObject({ name: "AbortError" })
    expect(f.destroyed).toBe(true)
    expect(f.message.destroyed).toBe(true)
  })

  test("a caller deadline is not shortened by the fallback timeout", async () => {
    const f = fixture()
    const controller = new AbortController()
    const response = await fetchFixture(f, { timeoutMs: 1 })(URL_, { signal: controller.signal })
    await new Promise((resolve) => setTimeout(resolve, 5))
    f.message.end("fixture")
    expect(await response.text()).toBe("fixture")
  })

  test("an incomplete response close fails the body reader", async () => {
    const f = fixture()
    const response = await fetchFixture(f)(URL_)
    f.message.destroy()
    await expect(response.text()).rejects.toMatchObject({ code: "UPSTREAM_ERROR" })
    expect(f.destroyed).toBe(true)
  })

  test("timeout remains effective while reading the body", async () => {
    const f = fixture()
    const response = await fetchFixture(f, { timeoutMs: 5 })(URL_)
    await expect(response.text()).rejects.toMatchObject({ name: "TimeoutError" })
    expect(f.destroyed).toBe(true)
  })

  test("stream cancellation destroys the response and request", async () => {
    const f = fixture()
    const response = await fetchFixture(f)(URL_)
    await response.body!.cancel()
    expect(f.destroyed).toBe(true)
    expect(f.message.destroyed).toBe(true)
  })

  test("an early response error is retained until a reader attaches", async () => {
    const f = fixture()
    const response = await fetchFixture(f)(URL_)
    f.message.emit("error", new Error("private fixture detail"))
    await expect(response.text()).rejects.toMatchObject({
      code: "UPSTREAM_ERROR",
      message: "The upstream server is unreachable.",
    })
    expect(f.destroyed).toBe(true)
  })

  test.each([204, 205, 304])("%s has a null body", async (status) => {
    const f = fixture(status)
    const response = await fetchFixture(f)(URL_)
    expect(response.status).toBe(status)
    expect(response.body).toBeNull()
    expect(f.destroyed).toBe(true)
  })

  test("HEAD has a null body", async () => {
    const f = fixture()
    const response = await fetchFixture(f)(URL_, { method: "HEAD" })
    expect(response.body).toBeNull()
    expect(f.destroyed).toBe(true)
  })

  test("returns redirects without following them", async () => {
    const f = fixture(302, { location: "https://127.0.0.1/private" })
    const response = await fetchFixture(f)(URL_, { redirect: "manual" })
    expect(response.status).toBe(302)
    expect(f.requests).toBe(1)
    await response.body!.cancel()
  })

  test("rejects encoded responses and destroys the socket", async () => {
    const f = fixture(200, { "content-encoding": "gzip" })
    await expect(fetchFixture(f)(URL_)).rejects.toThrow()
    expect(f.destroyed).toBe(true)
    expect(f.message.destroyed).toBe(true)
  })

  test.each([
    { headers: { Host: "private.example" } },
    { headers: { "accept-encoding": "gzip" } },
    { headers: { Upgrade: "websocket" } },
    { method: "CONNECT" },
    { redirect: "follow" },
    { body: new Uint8Array([1]) },
    { credentials: "include" },
  ])("rejects unsupported options before requesting", async (init) => {
    const f = fixture()
    await expect(fetchFixture(f)(URL_, init as unknown as RequestInit)).rejects.toThrow()
    expect(f.requests).toBe(0)
  })
})

describe("safeFetch real local socket", () => {
  test("uses the pinned DNS answer while retaining the original Host and request body", async () => {
    let seenHost: string | undefined
    let seenBody = ""
    const server = createServer((request, response) => {
      seenHost = request.headers.host
      request.setEncoding("utf8")
      request.on("data", (chunk) => { seenBody += chunk })
      request.on("end", () => response.end("local fixture"))
    })
    const port = await listen(server)
    try {
      let resolves = 0
      const fetch = createSafeFetch({
        policy: { allowLoopback: true },
        resolve: async () => {
          resolves += 1
          return [{ address: "127.0.0.1", family: 4 }]
        },
      })
      const response = await fetch(`http://fixture.localhost:${port}/echo`, {
        method: "POST",
        body: new URLSearchParams({ fixture: "yes" }),
      })
      expect(await response.text()).toBe("local fixture")
      expect(seenHost).toBe(`fixture.localhost:${port}`)
      expect(seenBody).toBe("fixture=yes")
      expect(resolves).toBe(1)
    } finally { close(server) }
  })

  test("cancelling a streaming response closes the upstream socket", async () => {
    let finish!: () => void
    const closed = new Promise<void>((resolve) => { finish = resolve })
    const server = createServer((_request, response) => {
      response.write("first chunk")
      response.on("close", finish)
    })
    const port = await listen(server)
    try {
      const fetch = createSafeFetch({ policy: { allowLoopback: true } })
      const response = await fetch(`http://127.0.0.1:${port}/stream`)
      const reader = response.body!.getReader()
      expect((await reader.read()).done).toBe(false)
      await reader.cancel()
      await closed
    } finally { close(server) }
  })
})
