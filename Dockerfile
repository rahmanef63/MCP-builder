# Dashboard image (apps/web). Dokploy builds this one from the repo root.
# The gateway has its own image at apps/gateway/Dockerfile.
FROM oven/bun:1.4.2-alpine AS builder
WORKDIR /app

# ponytail: whole-tree copy before install. A per-package.json copy would cache
# dependencies better, but bun workspaces + 14 manifests make the glob dance
# fragile; revisit when build time actually hurts.
COPY . .
# --linker=hoisted is load-bearing: bun's default isolated layout puts packages
# under node_modules/.bun/<pkg>@<ver>/node_modules/ behind symlinks, and Next's
# standalone file tracer does not follow that into transitive deps — the image
# builds fine and then dies at boot on a missing @swc/helpers. A flat
# node_modules is what the tracer expects. Does not affect bun.lock.
RUN bun install --frozen-lockfile --linker=hoisted

# NEXT_PUBLIC_* is inlined at build time, so it must arrive as a build arg.
# Neither value is a secret: one is the public Convex origin, the other the
# public gateway origin (AGENTS.md invariant 12 — no secret in an image layer).
ARG NEXT_PUBLIC_CONVEX_URL
ARG NEXT_PUBLIC_GATEWAY_URL
ENV NEXT_PUBLIC_CONVEX_URL=$NEXT_PUBLIC_CONVEX_URL
ENV NEXT_PUBLIC_GATEWAY_URL=$NEXT_PUBLIC_GATEWAY_URL
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
# This image runs its own Node server, so it needs the standalone bundle. Vercel
# builds the same app without it (next.config.mjs) — the platform produces its
# own serverless output and a standalone server there is dead weight.
ENV NEXT_OUTPUT=standalone

RUN cd apps/web && bun run build

# Next's standalone server targets Node, so the runner is Node, not Bun.
FROM node:22-alpine AS runner
ARG APP_REVISION=unknown
ARG APP_VERSION=unknown
LABEL org.opencontainers.image.revision=$APP_REVISION \
      org.opencontainers.image.version=$APP_VERSION
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001

COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/static ./apps/web/.next/static

USER nextjs
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
