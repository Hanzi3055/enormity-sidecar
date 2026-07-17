#!/usr/bin/env sh
set -eu

MODE="${1:---dry-run}"
DATABASE="${MYSQL_DATABASE:-cloudpatrol}"
ADMIN_DEFAULTS="${MYSQL_ADMIN_DEFAULTS_FILE:-}"

if ! printf '%s' "$DATABASE" | grep -Eq '^[A-Za-z0-9_]{1,64}$'; then
  printf '%s\n' 'Refusing provisioning: MYSQL_DATABASE has an invalid identifier.' >&2
  exit 1
fi

if [ "$MODE" = "--dry-run" ]; then
  printf '%s\n' 'DRY RUN: no MySQL user or grant was changed.'
  printf '%s\n' 'Planned principals: nexus_query (SELECT only), nexus_command (Nexus journal/outbox/audit only), nexus_identity (identity tables), nexus_biometric (fingerprint plus atomic Nexus evidence tables).'
  printf '%s\n' 'Apply requires five migrated Nexus tables, four root-only password files, a verified backup hash, and CONFIRM_NEXUS_DB_IDENTITIES=YES.'
  exit 0
fi

if [ "$MODE" != "--apply" ]; then
  printf '%s\n' 'Usage: provision-nexus-db-identities.sh [--dry-run|--apply]' >&2
  exit 2
fi

if [ "${CONFIRM_NEXUS_DB_IDENTITIES:-}" != "YES" ]; then
  printf '%s\n' 'Refusing provisioning: CONFIRM_NEXUS_DB_IDENTITIES=YES is required.' >&2
  exit 1
fi

if [ -z "$ADMIN_DEFAULTS" ] || [ ! -f "$ADMIN_DEFAULTS" ]; then
  printf '%s\n' 'Refusing provisioning: MYSQL_ADMIN_DEFAULTS_FILE must name a root-controlled MySQL option file.' >&2
  exit 1
fi

case "$(stat -c '%a' "$ADMIN_DEFAULTS")" in
  400|440|600|640) ;;
  *) printf '%s\n' 'Refusing provisioning: MySQL option file permissions are too broad.' >&2; exit 1 ;;
esac

if [ -z "${NEXUS_VERIFIED_BACKUP:-}" ] || [ ! -f "$NEXUS_VERIFIED_BACKUP" ]; then
  printf '%s\n' 'Refusing provisioning: NEXUS_VERIFIED_BACKUP is required.' >&2
  exit 1
fi
if ! printf '%s' "${NEXUS_VERIFIED_BACKUP_SHA256:-}" | grep -Eq '^[a-fA-F0-9]{64}$'; then
  printf '%s\n' 'Refusing provisioning: NEXUS_VERIFIED_BACKUP_SHA256 is required.' >&2
  exit 1
fi
backup_sha="$(sha256sum "$NEXUS_VERIFIED_BACKUP" | awk '{print $1}')"
if [ "$backup_sha" != "$(printf '%s' "$NEXUS_VERIFIED_BACKUP_SHA256" | tr 'A-F' 'a-f')" ]; then
  printf '%s\n' 'Refusing provisioning: verified backup hash does not match.' >&2
  exit 1
fi

read_secret() {
  file="$1"
  label="$2"
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    printf 'Refusing provisioning: %s password file is missing.\n' "$label" >&2
    exit 1
  fi
  case "$(stat -c '%a' "$file")" in
    400|440|600|640) ;;
    *) printf 'Refusing provisioning: %s password file permissions are too broad.\n' "$label" >&2; exit 1 ;;
  esac
  bytes="$(wc -c < "$file" | tr -d ' ')"
  if [ "$bytes" -lt 17 ] || [ "$bytes" -gt 257 ]; then
    printf 'Refusing provisioning: %s password file size is invalid.\n' "$label" >&2
    exit 1
  fi
  value="$(tr -d '\r\n' < "$file")"
  if ! printf '%s' "$value" | grep -Eq '^[A-Za-z0-9._~!@#%^+=:-]{16,256}$'; then
    printf 'Refusing provisioning: %s password must use the approved non-SQL character set.\n' "$label" >&2
    exit 1
  fi
  printf '%s' "$value"
}

QUERY_PASSWORD="$(read_secret "${NEXUS_QUERY_MYSQL_PASSWORD_FILE:-}" nexus_query)"
COMMAND_PASSWORD="$(read_secret "${NEXUS_COMMAND_MYSQL_PASSWORD_FILE:-}" nexus_command)"
IDENTITY_PASSWORD="$(read_secret "${NEXUS_IDENTITY_MYSQL_PASSWORD_FILE:-}" nexus_identity)"
BIOMETRIC_PASSWORD="$(read_secret "${NEXUS_BIOMETRIC_MYSQL_PASSWORD_FILE:-}" nexus_biometric)"

if [ "$QUERY_PASSWORD" = "$COMMAND_PASSWORD" ] \
  || [ "$QUERY_PASSWORD" = "$IDENTITY_PASSWORD" ] \
  || [ "$QUERY_PASSWORD" = "$BIOMETRIC_PASSWORD" ] \
  || [ "$COMMAND_PASSWORD" = "$IDENTITY_PASSWORD" ] \
  || [ "$COMMAND_PASSWORD" = "$BIOMETRIC_PASSWORD" ] \
  || [ "$IDENTITY_PASSWORD" = "$BIOMETRIC_PASSWORD" ]; then
  printf '%s\n' 'Refusing provisioning: all four database identities require distinct passwords.' >&2
  exit 1
fi

table_count="$(mysql --defaults-extra-file="$ADMIN_DEFAULTS" --database="$DATABASE" --batch --skip-column-names \
  --execute="SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('nexus_identity_credentials','nexus_identity_reset_tokens','nexus_command_journal','nexus_outbox','nexus_audit_events')")"
if [ "$table_count" != "5" ]; then
  printf '%s\n' 'Refusing provisioning: apply the additive Nexus foundation migration first.' >&2
  exit 1
fi

{
  printf "CREATE USER IF NOT EXISTS 'nexus_query'@'%%' IDENTIFIED BY '%s';\n" "$QUERY_PASSWORD"
  printf "CREATE USER IF NOT EXISTS 'nexus_command'@'%%' IDENTIFIED BY '%s';\n" "$COMMAND_PASSWORD"
  printf "CREATE USER IF NOT EXISTS 'nexus_identity'@'%%' IDENTIFIED BY '%s';\n" "$IDENTITY_PASSWORD"
  printf "CREATE USER IF NOT EXISTS 'nexus_biometric'@'%%' IDENTIFIED BY '%s';\n" "$BIOMETRIC_PASSWORD"
  printf "ALTER USER 'nexus_query'@'%%' IDENTIFIED BY '%s';\n" "$QUERY_PASSWORD"
  printf "ALTER USER 'nexus_command'@'%%' IDENTIFIED BY '%s';\n" "$COMMAND_PASSWORD"
  printf "ALTER USER 'nexus_identity'@'%%' IDENTIFIED BY '%s';\n" "$IDENTITY_PASSWORD"
  printf "ALTER USER 'nexus_biometric'@'%%' IDENTIFIED BY '%s';\n" "$BIOMETRIC_PASSWORD"
  printf "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'nexus_query'@'%%', 'nexus_command'@'%%', 'nexus_identity'@'%%', 'nexus_biometric'@'%%';\n"
  printf "GRANT SELECT ON \`%s\`.* TO 'nexus_query'@'%%';\n" "$DATABASE"
  for table in nexus_command_journal nexus_outbox nexus_audit_events; do
    printf "GRANT SELECT, INSERT, UPDATE ON \`%s\`.\`%s\` TO 'nexus_command'@'%%';\n" "$DATABASE" "$table"
  done
  for table in companys depts users userdepts userroles roles rolemodules modules loginuser loginuserrecords; do
    printf "GRANT SELECT ON \`%s\`.\`%s\` TO 'nexus_identity'@'%%';\n" "$DATABASE" "$table"
  done
  for table in nexus_identity_credentials nexus_identity_reset_tokens nexus_audit_events; do
    printf "GRANT SELECT, INSERT, UPDATE, DELETE ON \`%s\`.\`%s\` TO 'nexus_identity'@'%%';\n" "$DATABASE" "$table"
  done
  for table in guards depts readers; do
    printf "GRANT SELECT ON \`%s\`.\`%s\` TO 'nexus_biometric'@'%%';\n" "$DATABASE" "$table"
  done
  for table in fingerinfo readerfinger; do
    printf "GRANT SELECT, INSERT, UPDATE, DELETE ON \`%s\`.\`%s\` TO 'nexus_biometric'@'%%';\n" "$DATABASE" "$table"
  done
  for table in nexus_command_journal nexus_outbox nexus_audit_events; do
    printf "GRANT SELECT, INSERT, UPDATE ON \`%s\`.\`%s\` TO 'nexus_biometric'@'%%';\n" "$DATABASE" "$table"
  done
} | mysql --defaults-extra-file="$ADMIN_DEFAULTS" --database="$DATABASE"

unset QUERY_PASSWORD COMMAND_PASSWORD IDENTITY_PASSWORD BIOMETRIC_PASSWORD

principal_count="$(mysql --defaults-extra-file="$ADMIN_DEFAULTS" --batch --skip-column-names \
  --execute="SELECT COUNT(*) FROM mysql.user WHERE User IN ('nexus_query','nexus_command','nexus_identity','nexus_biometric')")"
if [ "$principal_count" != "4" ]; then
  printf '%s\n' 'Provisioning verification failed: expected four Nexus database principals.' >&2
  exit 1
fi

printf '%s\n' 'PASS: four distinct least-privilege Nexus database identities were provisioned.'
