#!/usr/bin/env bash
# Madar — local live status (prints NO secrets).
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== الحاويات =="
docker compose ps 2>/dev/null || echo "(docker compose غير متاح هنا)"
echo "== live ==";  curl -fsS http://localhost:3000/health/live  || echo "FAIL"
echo; echo "== ready =="; curl -fsS http://localhost:3000/health/ready || echo "FAIL"
echo; echo "== migrations =="
if docker compose ps app 2>/dev/null | grep -q Up; then
  docker compose exec -T app node -e "
    require('./core/db').all('SELECT name FROM schema_migrations ORDER BY name')
      .then(r=>{console.log(r.map(x=>x.name).join('\n'));process.exit(0)})
      .catch(e=>{console.error('FAIL:',e.message);process.exit(1)});"
elif docker compose version >/dev/null 2>&1; then
  echo "حاوية app غير جاهزة — آخر السجلات:"
  docker compose logs --tail 15 app 2>/dev/null || true
elif [ -d node_modules ]; then
  node -e "
    const {loadEnv}=require('./core/env'); loadEnv('.');
    require('./core/db').all('SELECT name FROM schema_migrations ORDER BY name')
      .then(r=>{console.log(r.map(x=>x.name).join('\n'));process.exit(0)})
      .catch(e=>{console.error('FAIL:',e.message);process.exit(1)});"
else
  echo "(لا Docker ولا node_modules محلية — لا يمكن فحص migrations)"
fi
echo "== MODE =="
if [ -f .env ]; then grep -E '^MODE=' .env | cut -d= -f2 || echo "unset"; else echo "${MODE:-unset (env-provided)}"; fi
echo "== لوحة الإدارة =="; echo "http://localhost:3000/?tab=admin"
