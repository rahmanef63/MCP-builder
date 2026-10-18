import { lookup } from "node:dns/promises"
import { request as httpRequest } from "node:http"
import type { ClientRequest, IncomingMessage, RequestOptions } from "node:http"
import { request as httpsRequest } from "node:https"
import { isIP } from "node:net"
import type { LookupFunction } from "node:net"
import {
  blockedRange,
  GatewayError,
  isLoopback,
  normalizeUpstreamEndpointUrl,
  upstreamUrlPolicyFromEnvironment,
} from "@cg/core"
import type { UpstreamUrlPolicy } from "@cg/core"

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>
export type ResolvedAddress = { address: string; family: 4 | 6 }
export type Requester = (
  options: RequestOptions,
  onResponse: (response: IncomingMessage) => void,
) => ClientRequest

export type SafeFetchOptions = {
  policy?: UpstreamUrlPolicy
  resolve?: (hostname: string) => Promise<readonly ResolvedAddress[]>
  request?: Requester
  timeoutMs?: number
}

function unreachable(): GatewayError {
  return new GatewayError("UPSTREAM_ERROR", "The upstream server is unreachable.")
}

function refused(): GatewayError {
  return new GatewayError("UPSTREAM_ERROR", "The upstream address is not allowed.")
}

function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host
}

function abortError(timedOut: boolean): DOMException {
  return new DOMException(
    timedOut ? "The upstream call timed out." : "The upstream call was cancelled.",
    timedOut ? "TimeoutError" : "AbortError",
  )
}

const defaultResolver = async (hostname: string): Promise<ResolvedAddress[]> =>
  (await lookup(hostname, { all: true, verbatim: true })) as ResolvedAddress[]

const defaultRequester: Requester = (options, callback) =>
  options.protocol === "https:"
    ? httpsRequest(options, callback)
    : httpRequest(options, callback)

function prepare(init: RequestInit): { method: string; headers: Headers; body: string | undefined } {
  const allowed = new Set(["method", "headers", "body", "signal", "redirect", "cache"])
  if (Object.keys(init).some((key) => !allowed.has(key) && init[key as keyof RequestInit] !== undefined)) {
    throw new GatewayError("UPSTREAM_ERROR", "Unsupported upstream request option.")
  }
  if (init.redirect !== undefined && init.redirect !== "manual" && init.redirect !== "error") {
    throw new GatewayError("UPSTREAM_ERROR", "Upstream redirects must not be followed.")
  }
  const method = (init.method ?? "GET").toUpperCase()
  if (!/^[!#$%&'*+.^_`|~0-9A-Z-]+$/.test(method) || ["CONNECT", "TRACE", "TRACK"].includes(method)) {
    throw new GatewayError("UPSTREAM_ERROR", "Unsupported upstream request method.")
  }
  if (init.body != null && typeof init.body !== "string" && !(init.body instanceof URLSearchParams)) {
    throw new GatewayError("UPSTREAM_ERROR", "Unsupported upstream request body.")
  }
  const body = init.body == null ? undefined : String(init.body)
  if (body !== undefined && (method === "GET" || method === "HEAD")) {
    throw new GatewayError("UPSTREAM_ERROR", "This upstream request method cannot have a body.")
  }
  const headers = new Headers(init.headers)
  for (const name of [
    "host", "connection", "transfer-encoding", "upgrade", "proxy-authorization",
    "proxy-connection", "content-length",
  ]) {
    if (headers.has(name)) {
      throw new GatewayError("UPSTREAM_ERROR", "Unsupported upstream request header.")
    }
  }
  if (headers.has("accept-encoding") && headers.get("accept-encoding") !== "identity") {
    throw new GatewayError("UPSTREAM_ERROR", "Unsupported upstream content encoding.")
  }
  headers.set("accept-encoding", "identity")
  if (init.body instanceof URLSearchParams && !headers.has("content-type")) {
    headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8")
  }
  return { method, headers, body }
}

/** Resolve once, validate every answer, then connect only to the selected IP. */
export function createSafeFetch(options: SafeFetchOptions = {}): FetchLike {
  const resolve = options.resolve ?? defaultResolver
  const requester = options.request ?? defaultRequester
  const timeoutMs = options.timeoutMs ?? 10_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) {
    throw new Error("Invalid safeFetch timeout.")
  }

  return async (input, init = {}) => {
    const policy = options.policy ?? upstreamUrlPolicyFromEnvironment(process.env)
    const url = new URL(normalizeUpstreamEndpointUrl(String(input), policy))
    const hostname = stripBrackets(url.hostname)
    const prepared = prepare(init)
    const signal = init.signal
    if (signal?.aborted) throw abortError(signal.reason instanceof Error && signal.reason.name === "TimeoutError")

    return new Promise<Response>((resolveResponse, rejectResponse) => {
      let outgoing: ClientRequest | undefined
      let incoming: IncomingMessage | undefined
      let controller: ReadableStreamDefaultController<Uint8Array> | undefined
      let settled = false
      let finished = false
      let failed = false
      let timedOut = false
      const cleanup = () => {
        clearTimeout(timer)
        signal?.removeEventListener("abort", abort)
      }
      const fail = (cause: unknown) => {
        if (finished || failed) return
        failed = true
        cleanup()
        const error =
          cause instanceof GatewayError ||
          (cause instanceof Error && (cause.name === "AbortError" || cause.name === "TimeoutError"))
            ? cause
            : unreachable()
        incoming?.destroy()
        outgoing?.destroy()
        if (!settled) rejectResponse(error)
        else {
          try { controller?.error(error) } catch {}
        }
      }
      const abort = () => fail(abortError(
        timedOut || (signal?.reason instanceof Error && signal.reason.name === "TimeoutError"),
      ))
      const timer = signal ? undefined : setTimeout(() => {
        timedOut = true
        abort()
      }, timeoutMs)
      signal?.addEventListener("abort", abort, { once: true })

      const run = async () => {
        const family = isIP(hostname)
        const addresses = family
          ? [{ address: hostname, family: family as 4 | 6 }]
          : await resolve(hostname)
        if (failed || signal?.aborted) {
          abort()
          return
        }
        if (addresses.length === 0) throw refused()
        const local = policy.allowLoopback === true && isLoopback(url.hostname)
        for (const address of addresses) {
          if (
            (address.family !== 4 && address.family !== 6) ||
            isIP(address.address) !== address.family ||
            address.address.includes("%") ||
            (blockedRange(address.address) !== null && !(local && isLoopback(address.address))) ||
            (local && !isLoopback(address.address))
          ) {
            throw refused()
          }
        }
        const selected = addresses[0]!
        const pinnedLookup = ((
          _host: string,
          lookupOptions: { all?: boolean } | number,
          callback: (error: null, result: string | ResolvedAddress[], family?: number) => void,
        ) => {
          if (typeof lookupOptions === "object" && lookupOptions.all) {
            callback(null, [{ ...selected }])
          } else {
            callback(null, selected.address, selected.family)
          }
        }) as LookupFunction
        const headers: Record<string, string> = {}
        prepared.headers.forEach((value, key) => { headers[key] = value })
        headers.host = url.host
        if (prepared.body !== undefined) {
          headers["content-length"] = String(Buffer.byteLength(prepared.body))
        }
        const requestOptions: RequestOptions & {
          autoSelectFamily: boolean
          servername?: string
          rejectUnauthorized: boolean
        } = {
          protocol: url.protocol,
          hostname,
          port: url.port || undefined,
          path: url.pathname + url.search,
          method: prepared.method,
          headers,
          agent: false,
          autoSelectFamily: false,
          family: selected.family,
          lookup: pinnedLookup,
          rejectUnauthorized: true,
          ...(url.protocol === "https:" && !isIP(hostname) ? { servername: hostname } : {}),
        }
        if (failed || signal?.aborted) {
          abort()
          return
        }
        outgoing = requester(requestOptions, (message) => {
          try {
            incoming = message
            incoming.on("error", fail)
            incoming.on("aborted", () => fail(unreachable()))
            incoming.on("close", () => {
              if (!finished && !failed) fail(unreachable())
            })
            if (failed) {
              incoming.destroy()
              return
            }
            const status = incoming.statusCode ?? 0
            const encoding = incoming.headers["content-encoding"]
            if (
              status < 200 || status > 599 ||
              (encoding !== undefined && encoding.trim().toLowerCase() !== "identity") ||
              (init.redirect === "error" && [301, 302, 303, 307, 308].includes(status))
            ) {
              fail(unreachable())
              return
            }
            const responseHeaders = new Headers()
            for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
              responseHeaders.append(incoming.rawHeaders[index]!, incoming.rawHeaders[index + 1]!)
            }
            if (prepared.method === "HEAD" || [204, 205, 304].includes(status)) {
              const response = new Response(null, { status, headers: responseHeaders })
              finished = true
              cleanup()
              incoming.destroy()
              outgoing?.destroy()
              settled = true
              resolveResponse(response)
              return
            }
            const stream = new ReadableStream<Uint8Array>({
              start(value) {
                controller = value
                message.on("data", (chunk: Buffer) => {
                  if (failed || finished) return
                  controller!.enqueue(new Uint8Array(chunk))
                  if ((controller!.desiredSize ?? 0) <= 0) message.pause()
                })
                message.on("end", () => {
                  if (failed || finished) return
                  finished = true
                  cleanup()
                  controller!.close()
                })
              },
              pull() { message.resume() },
              cancel() {
                if (finished || failed) return
                finished = true
                cleanup()
                message.destroy()
                outgoing?.destroy()
              },
            })
            const response = new Response(stream, { status, headers: responseHeaders })
            settled = true
            resolveResponse(response)
          } catch (cause) { fail(cause) }
        })
        outgoing.on("error", fail)
        outgoing.on("upgrade", (_response, socket) => {
          socket.destroy()
          fail(unreachable())
        })
        outgoing.on("connect", (_response, socket) => {
          socket.destroy()
          fail(unreachable())
        })
        if (failed) {
          outgoing.destroy()
          return
        }
        outgoing.end(prepared.body)
      }
      void run().catch(fail)
    })
  }
}

export const safeFetch: FetchLike = createSafeFetch()
