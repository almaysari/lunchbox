#!/usr/bin/env bash
# Madar — one-command local live setup (macOS/Linux).
# Generates all secrets locally (never printed), brings up the official
# Docker stack, waits for readiness, and creates the first admin
# INTERACTIVELY (hidden password prompt — nothing stored on disk).
# Never overwrites an existing .env without explicit consent.
# Zoho Client ID/Secret are NEVER handled here — enter them only in the
# admin panel UI after startup.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v docker >/dev/null || { echo "Docker غير مثبت — ثبّت Docker Desktop أولًا"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon لا يعمل — شغّل Docker Desktop ثم أعد المحاولة"; exit 1; }

if [ -f .env ]; then
  echo ".env موجود بالفعل — لن يُستبدل."
  if [ "${MADAR_SETUP_FORCE_ENV:-}" != "1" ]; then
    read -r -p "استخدامه كما هو؟ [Y/n] " ans
    case "${ans:-Y}" in n|N) echo "أوقفت الإعداد — عدّل .env يدويًا ثم أعد التشغيل"; exit 1;; esac
  fi
else
  umask 077
  cat > .env <<EOF
MODE=live
PORT=3000
BASE_URL=http://localhost:3000
POSTGRES_PASSWORD=$(openssl rand -hex 24)
MADAR_ENCRYPTION_KEY=$(openssl rand -hex 32)
MADAR_SESSION_SECRET=$(openssl rand -hex 32)
MADAR_CSRF_SECRET=$(openssl rand -hex 32)
SYNC_INTERVAL_MINUTES=10
MADAR_MAX_RPM=25
MAX_ATTACHMENT_MB=25
EOF
  echo "أُنشئ .env بأسرار مولّدة محليًا (لن تُطبع)."
fi
chmod 600 .env

echo "بناء وتشغيل الحاويات..."
docker compose up -d --build

echo "انتظار الجاهزية..."
for i in $(seq 1 60); do
  if curl -fsS http://localhost:3000/health/ready >/dev/null 2>&1; then READY=1; break; fi
  sleep 2
done
[ "${READY:-}" = "1" ] || { echo "لم تصل المنصة للجاهزية — راجع: docker compose logs app"; exit 1; }
echo "المنصة جاهزة (health/ready ✓ — migrations طُبّقت تلقائيًا)."

if [ -n "${MADAR_ADMIN_EMAIL:-}" ] && [ -n "${MADAR_ADMIN_PASSWORD:-}" ]; then
  # non-interactive path (CI only — never use real credentials here)
  docker compose exec -T -e MADAR_ADMIN_EMAIL -e MADAR_ADMIN_NAME="${MADAR_ADMIN_NAME:-Admin}" \
    -e MADAR_ADMIN_PASSWORD app npm run create-admin || true
else
  echo "إنشاء أول Admin (كلمة المرور مخفية ولا تُخزن — وسيُطلب تغييرها عند أول دخول):"
  docker compose exec app npm run create-admin || echo "(إن كان Admin موجودًا بالفعل فهذا طبيعي)"
fi

echo ""
echo "✅ لوحة الإدارة: http://localhost:3000/?tab=admin"
echo "أدخل Zoho Client ID/Secret من داخل اللوحة فقط (لا تُدخلهما في الطرفية أبدًا)."
