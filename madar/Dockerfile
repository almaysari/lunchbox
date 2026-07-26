FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
# attachment volume mountpoint must be writable by the non-root user —
# a named volume inherits this ownership on first use
RUN mkdir -p /var/lib/madar/attachments && chown -R node:node /var/lib/madar
EXPOSE 3000
USER node
# Official single-command runtime: migrations run first (safe under
# concurrency — the runner takes a PostgreSQL advisory lock, so multiple
# app instances starting together apply them exactly once), then the app.
ENTRYPOINT ["sh", "-c", "node scripts/migrate.js && exec node server.js"]
