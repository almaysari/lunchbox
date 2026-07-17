#!/usr/bin/env bash
# Securely remove the initial admin password file after first sign-in.
set -euo pipefail
cd "$(dirname "$0")/.."
F=data/initial-admin-password.txt
[ -f "$F" ] || { echo "لا يوجد ملف كلمة مرور مبدئية — لا شيء للحذف"; exit 0; }
dd if=/dev/urandom of="$F" bs=256 count=4 conv=notrunc 2>/dev/null || true
rm -f "$F"
echo "حُذف ملف كلمة المرور المبدئية بأمان."
