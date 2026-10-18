# ==========================================
# BASE
# ==========================================
FROM node:24-alpine AS base

WORKDIR /app

RUN corepack enable
RUN apk update && apk upgrade --no-cache

# ==========================================
# DEPENDENCIES
# ==========================================
FROM base AS deps

COPY package.json pnpm-lock.yaml ./
COPY cms-lib-database-0.0.1.tgz ./
COPY cms-lib-resources-0.0.1.tgz ./

RUN pnpm install --frozen-lockfile

# ==========================================
# BUILD
# ==========================================
FROM deps AS builder

COPY . .

RUN pnpm build

# ==========================================
# PRODUCTION
# ==========================================
FROM base AS production

ENV NODE_ENV=production

COPY package.json pnpm-lock.yaml ./
COPY cms-lib-database-0.0.1.tgz ./
COPY cms-lib-resources-0.0.1.tgz ./

RUN pnpm install --prod --frozen-lockfile \
    && pnpm store prune

COPY --from=builder /app/dist ./dist

EXPOSE 3000

CMD ["node", "dist/main.js"]
