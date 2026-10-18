# @cg/transport

Public upstream HTTP transport shared by Node and Bun hosts.

`safeFetch(url, init)` validates the URL using `@cg/core`, resolves a hostname
once, rejects the entire answer set if any address is malformed or non-global,
and pins a fresh connection to one approved address. HTTP Host and HTTPS SNI keep
the original hostname; certificate verification stays enabled. Redirects are
returned for callers to reject. Compressed responses are refused.

Requests accept strings or URLSearchParams as bodies. Unsupported fetch options,
caller-supplied Host/framing/proxy headers, and automatic redirects are refused.
Responses stream with backpressure. Cancelling or aborting destroys the request
and response socket. Caller AbortSignals remain active throughout the body read
and own the request deadline; without one, a 10-second deadline applies.

Development loopback access requires the core policy's explicit environment
opt-in. A public hostname resolving to loopback remains forbidden even with that
opt-in. No runtime connects through global fetch or a pooled agent.

`createSafeFetch({ policy, resolve, request, timeoutMs })` exposes explicit
configuration and deterministic test seams. Production defaults always use the
real resolver and node:http/node:https.

Run tests with `bun test packages/transport`. For runtime compatibility checks:

```sh
bun build packages/transport/src/node-smoke.ts --target=node --outfile=/tmp/transport-smoke.mjs
node /tmp/transport-smoke.mjs
```

The smoke uses only local HTTP fixtures and injected DNS answers.
