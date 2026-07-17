FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3000
USER node
# Official single-command runtime: migrations run first (safe under
# concurrency — the runner takes a PostgreSQL advisory lock, so multiple
# app instances starting together apply them exactly once), then the app.
ENTRYPOINT ["sh", "-c", "node scripts/migrate.js && exec node server.js"]
