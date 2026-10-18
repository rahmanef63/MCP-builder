# Gateway image: HTTP (MCP + REST) and the device-relay WebSocket in one Bun
# process. Build context is the repo ROOT, not this directory.
#
# There is no build step — Bun runs the TypeScript source directly, so the
# image is the workspace plus its dependencies.
FROM oven/bun:1.4.2-alpine
ARG GATEWAY_REVISION=unknown
ARG APP_VERSION=unknown
LABEL org.opencontainers.image.revision=$GATEWAY_REVISION \
      org.opencontainers.image.version=$APP_VERSION
RUN addgroup -g 1001 -S gateway && adduser -S gateway -u 1001
WORKDIR /app

# ponytail: installs the whole workspace, so apps/web's Next/React land in this
# image too (~unused weight). Split the lockfile per app if image size matters.
# Ownership is assigned while copying: recursively chowning node_modules after
# install added ~74s to every release on the production builder.
COPY --chown=gateway:gateway . .
RUN bun install --frozen-lockfile
USER gateway

ENV NODE_ENV=production
ENV GATEWAY_PORT=8787

# Everything else (CONVEX_URL, GATEWAY_SERVICE_TOKEN, JOB_SIGNING_*,
# CREDENTIAL_ENCRYPTION_KEY) is a secret and arrives from the Dokploy
# environment at runtime — never as a build arg, never baked into a layer.

EXPOSE 8787

# /healthz is unauthenticated and returns no data (see src/http/handlers).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
  CMD wget -q -O - http://127.0.0.1:8787/healthz || exit 1

CMD ["bun", "apps/gateway/src/main.ts"]
