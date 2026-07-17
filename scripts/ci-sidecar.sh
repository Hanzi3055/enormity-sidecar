#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

echo "=== Enormity Sidecar CI ==="
node --check server.js
node --check kpm-engine.js
node --check realtime-scope.js
node --check scripts/test-nexus-core-v2.js
bash -n scripts/migrate-nexus-foundation.sh
bash -n scripts/provision-nexus-db-identities.sh
node scripts/test-tenant-scope.js

echo "=== Required Evidence Files ==="
test -s README.md
test -s OWNERSHIP.md
test -s ENGINEERING_STANDARD.md
test -s openapi.yaml
test -s .env.example
test -s migrations/001_nexus_foundation_up.sql
test -s migrations/001_nexus_foundation_down.sql
test -s INDEPENDENCE_ROLLOUT.md
test -x scripts/smoke-test.sh
test -x scripts/migrate-nexus-foundation.sh
test -x scripts/provision-nexus-db-identities.sh

echo "=== Route Inventory ==="
grep -n "app\\.get\\|app\\.post\\|app\\.put\\|app\\.delete" server.js | grep -v '//' | wc -l

echo "sidecar-ci=passed"
