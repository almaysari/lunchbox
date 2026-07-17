#!/usr/bin/env bash
# Madar — local live status (prints NO secrets).
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== الحاويات =="
docker compose ps 2>/dev/null || echo "(docker compose غير متاح هنا)"
echo "== live ==";  curl -fsS http://localhost:3000/health/live  || echo "FAIL"
echo; echo "== ready =="; curl -fsS http://localhost:3000/health/ready || echo "FAIL"
echo; echo "== migrations =="
docker compose exec -T app node -e "
  const {loadEnv}=require('./core/env'); loadEnv('.');
  require('./core/db').all('SELECT name FROM schema_migrations ORDER BY name')
    .then(r=>{console.log(r.map(x=>x.name).join('\n'));process.exit(0)})
    .catch(e=>{console.error('FAIL:',e.message);process.exit(1)});" 2>/dev/null \
  || node -e "
  const {loadEnv}=require('./core/env'); loadEnv('.');
  require('./core/db').all('SELECT name FROM schema_migrations ORDER BY name')
    .then(r=>{console.log(r.map(x=>x.name).join('\n'));process.exit(0)})
    .catch(e=>{console.error('FAIL:',e.message);process.exit(1)});"
echo "== MODE ==";  grep -E '^MODE=' .env | cut -d= -f2
echo "== لوحة الإدارة =="; echo "http://localhost:3000/?tab=admin"
