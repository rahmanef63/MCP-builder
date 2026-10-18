import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const here = dirname(fileURLToPath(import.meta.url))
const workspaceRoot = join(here, "../..")

/**
 * `output: "standalone"` is for the Docker image only.
 *
 * On Vercel it is actively wrong: the platform builds its own serverless output
 * and a standalone server directory is dead weight it has to trace anyway. The
 * Dockerfile sets NEXT_OUTPUT=standalone; Vercel sets VERCEL=1 and nothing else,
 * so the default here is the platform-native build.
 */
const output = process.env.NEXT_OUTPUT === "standalone" ? { output: "standalone" } : {}

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Workspace packages ship TypeScript source, no build step.
  transpilePackages: [
    "@cg/core",
    "@cg/transport",
    // Server-side sealing of connection credentials (lib/credentials.ts).
    "@cg/auth",
    "@cg/adapter-remote-mcp",
    "@cg/adapter-blender",
    "@cg/schemas",
    // The gateway edge, mounted on this app's routes (docs/20). Only the
    // ./edge entry point is reachable — apps/gateway/src/main.ts, the one
    // module that touches Bun, is not exported.
    "@cg/gateway",
    "@cg/executor",
    "@cg/observability",
    "@cg/policy",
    "@cg/protocol",
    "@cg/registry",
  ],
  reactStrictMode: true,
  // In a monorepo the tracing root has to be the workspace root, or Next traces
  // only apps/web: the Docker image then boots without the hoisted
  // node_modules, and on Vercel the @cg/* sources are missing from the lambda.
  outputFileTracingRoot: workspaceRoot,
  /**
   * The bundled MCP skill is opened at runtime through a `new URL(…,
   * import.meta.url)` (apps/gateway/src/mcp/skill.ts). A tracer cannot see a
   * filename that is only computed, so it must be named here or
   * `resources/read` fails with ENOENT on the first call — in production only.
   */
  outputFileTracingIncludes: {
    "/mcp": ["../../plugin/skills/connectors-gateway/SKILL.md"],
  },
  ...output,
  /**
   * `.well-known` cannot be a folder in `app/`: Next's file-system router skips
   * dot-prefixed segments. The documents are dynamic (they embed this
   * deployment's own origin), so a static file in `public/` is not an option
   * either — these rewrites are what makes the gateway discoverable.
   *
   * Order matters: the longer `/mcp` suffix is listed first so it is not
   * swallowed by the bare resource path.
   */
  async rewrites() {
    return [
      {
        source: "/.well-known/oauth-protected-resource/mcp",
        destination: "/well-known/oauth-protected-resource/mcp",
      },
      {
        source: "/.well-known/oauth-protected-resource",
        destination: "/well-known/oauth-protected-resource",
      },
      {
        source: "/.well-known/oauth-authorization-server",
        destination: "/well-known/oauth-authorization-server",
      },
    ]
  },
  // ponytail: Cache Components deliberately off — every screen here is authed
  // and dynamic (preloadQuery). Turn it on when a public marketing page lands.
}

export default nextConfig
