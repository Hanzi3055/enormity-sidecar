ARG NODE_IMAGE=node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d
FROM ${NODE_IMAGE}

ENV NODE_ENV=production
WORKDIR /app

# Production database identity files are root-owned, read-only, and shared
# only with this dedicated runtime group. Keep the image identity aligned with
# that host contract so a clean GitHub build can read the least-privilege
# credentials without running as root.
RUN groupmod --gid 65533 node

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

COPY . ./
RUN mkdir -p /app/reports/archive \
    && chown -R node:node /app

USER node
EXPOSE 3100 3101

CMD ["node", "server.js"]
