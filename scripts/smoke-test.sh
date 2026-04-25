#!/usr/bin/env bash
set -u

BASE_URL="${BASE_URL:-http://127.0.0.1:3100}"
ENV_FILE="${ENV_FILE:-/opt/enormity-sidecar/.env}"
FAILURES=0

fail() {
  echo "FAIL: $*"
  FAILURES=$((FAILURES + 1))
}

pass() {
  echo "PASS: $*"
}

if [ ! -r "$ENV_FILE" ]; then
  fail "missing env file: $ENV_FILE"
  exit 1
fi

API_KEY="$(grep '^ENORMITY_API_KEYS=' "$ENV_FILE" | cut -d= -f2- | cut -d, -f1 | tr -d '[:space:]')"
if [ -z "$API_KEY" ]; then
  fail "ENORMITY_API_KEYS is empty"
  exit 1
fi

HEALTH_CODE="$(curl -s -o /tmp/enormity-smoke-health.json -w '%{http_code}' "$BASE_URL/api/enormity/health")"
if [ "$HEALTH_CODE" = "200" ]; then
  pass "health=200"
else
  fail "health expected 200 got $HEALTH_CODE"
fi

TOKEN_RESPONSE="$(curl -s -X POST "$BASE_URL/api/enormity/auth/token" \
  -H 'Content-Type: application/json' \
  -d "{\"apiKey\":\"$API_KEY\"}")"
TOKEN="$(printf '%s' "$TOKEN_RESPONSE" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("data",{}).get("token",""))' 2>/dev/null)"
if [ -n "$TOKEN" ]; then
  pass "auth/token returned token"
else
  fail "auth/token did not return token"
fi

if [ -n "$TOKEN" ]; then
  SUMMARY_CODE="$(curl -s -o /tmp/enormity-smoke-summary.json -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/api/enormity/patrol/summary")"
  if [ "$SUMMARY_CODE" = "200" ]; then
    pass "patrol/summary=200"
  else
    fail "patrol/summary expected 200 got $SUMMARY_CODE"
  fi

  PDF_META="$(curl -s -o /tmp/enormity-smoke-pkk4.pdf -w '%{http_code} %{content_type}' \
    -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/api/enormity/reports/pkk4/pdf")"
  PDF_CODE="$(printf '%s' "$PDF_META" | awk '{print $1}')"
  PDF_TYPE="$(printf '%s' "$PDF_META" | cut -d' ' -f2-)"
  if [ "$PDF_CODE" = "200" ] && printf '%s' "$PDF_TYPE" | grep -qi 'application/pdf'; then
    pass "reports/pkk4/pdf=200 application/pdf"
  else
    fail "reports/pkk4/pdf expected 200 application/pdf got $PDF_META"
  fi
fi

if [ "$FAILURES" -eq 0 ]; then
  echo "Smoke test passed."
  exit 0
fi

echo "Smoke test failed: $FAILURES failure(s)."
exit 1
