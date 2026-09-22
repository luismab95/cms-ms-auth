# ==========================================
# BUILD
# ==========================================
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY lib-database-1.0.0.tar.gz ./

RUN npm ci

COPY . .

RUN npm run build


# ==========================================
# PRODUCTION
# ==========================================
FROM node:22-alpine AS production

WORKDIR /app

ENV NODE_ENV=production

COPY package*.json ./
COPY lib-database-1.0.0.tar.gz ./

RUN npm ci --omit=dev \
    && npm cache clean --force

COPY --from=builder /app/dist ./dist

EXPOSE 3000

CMD ["node", "dist/main.js"]