#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
MIGRATION="$ROOT_DIR/migrations/001_nexus_foundation_up.sql"
MODE="${1:---dry-run}"
DATABASE="${MYSQL_DATABASE:-cloudpatrol}"
ADMIN_DEFAULTS="${MYSQL_ADMIN_DEFAULTS_FILE:-}"
MIGRATION_SHA256="$(sha256sum "$MIGRATION" | awk '{print $1}')"

printf '%s  %s\n' "$MIGRATION_SHA256" "$MIGRATION"

if ! printf '%s' "$DATABASE" | grep -Eq '^[A-Za-z0-9_]{1,64}$'; then
  printf '%s\n' 'Refusing migration: MYSQL_DATABASE has an invalid identifier.' >&2
  exit 1
fi

if [ "$MODE" = "--dry-run" ]; then
  printf '%s\n' 'DRY RUN: additive Nexus foundation migration was not applied.'
  printf '%s\n' 'Set a root-controlled MYSQL_ADMIN_DEFAULTS_FILE and verified backup, then use --apply with the explicit confirmation guard.'
  exit 0
fi

if [ "$MODE" != "--apply" ]; then
  printf '%s\n' 'Usage: migrate-nexus-foundation.sh [--dry-run|--apply]' >&2
  exit 2
fi

if [ "${CONFIRM_NEXUS_FOUNDATION_MIGRATION:-}" != "YES" ]; then
  printf '%s\n' 'Refusing migration: CONFIRM_NEXUS_FOUNDATION_MIGRATION=YES is required.' >&2
  exit 1
fi

if ! printf '%s' "${NEXUS_FOUNDATION_MIGRATION_SHA256:-}" | grep -Eq '^[a-fA-F0-9]{64}$' \
  || [ "$(printf '%s' "$NEXUS_FOUNDATION_MIGRATION_SHA256" | tr 'A-F' 'a-f')" != "$MIGRATION_SHA256" ]; then
  printf '%s\n' 'Refusing migration: approve the exact printed migration hash in NEXUS_FOUNDATION_MIGRATION_SHA256.' >&2
  exit 1
fi

if [ -z "$ADMIN_DEFAULTS" ] || [ ! -f "$ADMIN_DEFAULTS" ]; then
  printf '%s\n' 'Refusing migration: MYSQL_ADMIN_DEFAULTS_FILE must name an existing root-controlled MySQL option file.' >&2
  exit 1
fi

if [ -z "${NEXUS_VERIFIED_BACKUP:-}" ] || [ ! -f "$NEXUS_VERIFIED_BACKUP" ]; then
  printf '%s\n' 'Refusing migration: NEXUS_VERIFIED_BACKUP must name a verified backup artifact.' >&2
  exit 1
fi

if ! printf '%s' "${NEXUS_VERIFIED_BACKUP_SHA256:-}" | grep -Eq '^[a-fA-F0-9]{64}$'; then
  printf '%s\n' 'Refusing migration: NEXUS_VERIFIED_BACKUP_SHA256 must contain the verified backup SHA-256.' >&2
  exit 1
fi

actual_backup_sha="$(sha256sum "$NEXUS_VERIFIED_BACKUP" | awk '{print $1}')"
if [ "$actual_backup_sha" != "$(printf '%s' "$NEXUS_VERIFIED_BACKUP_SHA256" | tr 'A-F' 'a-f')" ]; then
  printf '%s\n' 'Refusing migration: verified backup hash does not match the artifact.' >&2
  exit 1
fi

case "$(stat -c '%a' "$ADMIN_DEFAULTS")" in
  400|440|600|640) ;;
  *) printf '%s\n' 'Refusing migration: MySQL option file permissions are too broad.' >&2; exit 1 ;;
esac

mysql --defaults-extra-file="$ADMIN_DEFAULTS" --database="$DATABASE" < "$MIGRATION"

count="$(mysql --defaults-extra-file="$ADMIN_DEFAULTS" --database="$DATABASE" --batch --skip-column-names \
  --execute="SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('nexus_identity_credentials','nexus_identity_reset_tokens','nexus_command_journal','nexus_outbox','nexus_audit_events')")"
if [ "$count" != "5" ]; then
  printf '%s\n' 'Migration verification failed: expected five Nexus foundation tables.' >&2
  exit 1
fi

printf '%s\n' 'PASS: five additive Nexus foundation tables are present.'
