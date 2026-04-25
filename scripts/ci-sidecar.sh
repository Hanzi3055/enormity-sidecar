#!/usr/bin/env bash
set -euo pipefail

if [ -d /opt/enormity-sidecar ]; then
  cd /opt/enormity-sidecar
fi

echo "=== Enormity Sidecar CI ==="
node --check server.js
node --check kpm-engine.js

echo "=== Required Evidence Files ==="
test -s README.md
test -s OWNERSHIP.md
test -s ENGINEERING_STANDARD.md
test -s openapi.yaml
test -s .env.example
test -x scripts/smoke-test.sh

echo "=== Route Inventory ==="
grep -n "app\\.get\\|app\\.post\\|app\\.put\\|app\\.delete" server.js | grep -v '//' | wc -l

echo "sidecar-ci=passed"
