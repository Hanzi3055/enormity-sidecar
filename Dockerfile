# syntax=docker/dockerfile:1.7

# Keep npm and the compiler in a disposable build stage. The production image
# is distroless so it contains no shell, package manager, or unused OS tools.
ARG NODE_IMAGE=node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d
FROM ${NODE_IMAGE} AS build
ENV NODE_ENV=production
WORKDIR /app

# Production database identity files are root-owned, read-only, and shared
# only with this dedicated runtime group. Keep the build-stage identity aligned
# with that host contract for local smoke tests and file ownership.
RUN groupmod --gid 65533 node

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

COPY server.js kpm-engine.js realtime-scope.js openapi.yaml package.json ./

# Debian 13.6 is the current patched distroless Node 24 runtime. Numeric group
# 65533 is intentional: the host-mounted Nexus identity files are root:65533
# with mode 0440, while the process remains the non-root distroless user.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:774b7d020b24214835769e24c3544835526cd0288f0b094eae48e8b2c2429a79
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3100
ENV WS_PORT=3101
COPY --from=build --chown=65532:65532 /app/node_modules ./node_modules
COPY --from=build --chown=65532:65532 /app/server.js /app/kpm-engine.js /app/realtime-scope.js /app/openapi.yaml /app/package.json ./
USER 65532:65533
EXPOSE 3100 3101

CMD ["server.js"]
