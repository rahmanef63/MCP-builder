import assert from "node:assert/strict"
import { once } from "node:events"
import { createServer } from "node:http"
import type { RequestListener, Server } from "node:http"
import { createSafeFetch } from "./index"

async function withServer(
  callback: RequestListener,
  run: (port: number) => Promise<void>,
): Promise<void> {
  const server: Server = createServer(callback)
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const address = server.address()
  assert(address !== null && typeof address === "object")
  try { await run(address.port) }
  finally {
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
}

let deniedRequests = 0
await assert.rejects(createSafeFetch({
  policy: { allowLoopback: false },
  resolve: async () => [
    { address: "8.8.8.8", family: 4 },
    { address: "127.0.0.1", family: 4 },
  ],
  request: () => { deniedRequests += 1; throw new Error("must not connect") },
})("https://fixture.example/"), { code: "UPSTREAM_ERROR" })
assert.equal(deniedRequests, 0)

let host = ""
let body = ""
let encoding = ""
await withServer((request, response) => {
  host = request.headers.host ?? ""
  encoding = request.headers["accept-encoding"] ?? ""
  request.setEncoding("utf8")
  request.on("data", (chunk: string) => { body += chunk })
  request.on("end", () => response.end("local fixture"))
}, async (port) => {
  let lookups = 0
  const fetch = createSafeFetch({
    policy: { allowLoopback: true },
    resolve: async () => {
      lookups += 1
      return [{ address: "127.0.0.1", family: 4 }]
    },
  })
  const response = await fetch(`http://fixture.localhost:${port}/path?q=fixture`, {
    method: "POST", body: "fixture request",
  })
  assert.equal(await response.text(), "local fixture")
  assert.equal(host, `fixture.localhost:${port}`)
  assert.equal(encoding, "identity")
  assert.equal(body, "fixture request")
  assert.equal(lookups, 1)
})

for (const action of ["cancel", "abort"] as const) {
  let closed: Promise<unknown[]> | undefined
  await withServer((_request, response) => {
    closed = once(response, "close")
    response.write("first chunk")
  }, async (port) => {
    const controller = new AbortController()
    const response = await createSafeFetch({ policy: { allowLoopback: true } })(
      `http://127.0.0.1:${port}/stream`,
      { signal: controller.signal },
    )
    const reader = response.body!.getReader()
    assert.equal((await reader.read()).done, false)
    if (action === "cancel") await reader.cancel()
    else {
      controller.abort()
      await assert.rejects(reader.read(), { name: "AbortError" })
    }
    assert(closed !== undefined)
    await closed
  })
}
console.log("safeFetch runtime smoke passed: DNS denial, pinned HTTP, Host, body, abort, cancellation.")
