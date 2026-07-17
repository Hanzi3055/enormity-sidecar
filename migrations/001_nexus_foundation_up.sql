-- Nexus V2 additive foundation migration.
-- Apply through the guarded migration runner only after a verified logical
-- backup. This migration does not alter or delete any OEM CloudPatrol table.

CREATE TABLE IF NOT EXISTS nexus_identity_credentials (
  company_id INT NOT NULL,
  user_id INT NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  algorithm VARCHAR(32) NOT NULL DEFAULT 'argon2id',
  algorithm_version SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  migrated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  credential_version INT UNSIGNED NOT NULL DEFAULT 1,
  legacy_fallback_until TIMESTAMP(3) NULL,
  password_changed_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (company_id, user_id),
  CONSTRAINT chk_nexus_identity_algorithm CHECK (algorithm = 'argon2id'),
  CONSTRAINT chk_nexus_identity_credential_version CHECK (credential_version > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS nexus_identity_reset_tokens (
  token_hash BINARY(32) NOT NULL,
  company_id INT NOT NULL,
  user_id INT NOT NULL,
  credential_version INT UNSIGNED NOT NULL,
  expires_at TIMESTAMP(3) NOT NULL,
  used_at TIMESTAMP(3) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (token_hash),
  KEY idx_nexus_reset_owner (company_id, user_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS nexus_command_journal (
  journal_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  company_id INT NOT NULL,
  user_id INT NOT NULL,
  domain_name VARCHAR(64) NOT NULL,
  action_name VARCHAR(96) NOT NULL,
  permission_name VARCHAR(128) NOT NULL,
  idempotency_hash BINARY(32) NOT NULL,
  request_hash BINARY(32) NOT NULL,
  expected_row_hash BINARY(32) NOT NULL,
  before_row_hash BINARY(32) NULL,
  after_row_hash BINARY(32) NULL,
  reason VARCHAR(500) NOT NULL,
  status ENUM('started','committed','rolled_back','rejected') NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  committed_at TIMESTAMP(3) NULL,
  PRIMARY KEY (journal_id),
  UNIQUE KEY uq_nexus_command_idempotency (company_id, idempotency_hash),
  KEY idx_nexus_command_domain_time (company_id, domain_name, created_at),
  CONSTRAINT chk_nexus_command_reason CHECK (CHAR_LENGTH(TRIM(reason)) >= 3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS nexus_outbox (
  outbox_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  journal_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  company_id INT NOT NULL,
  aggregate_type VARCHAR(64) NOT NULL,
  aggregate_id VARCHAR(128) NOT NULL,
  event_type VARCHAR(128) NOT NULL,
  payload JSON NOT NULL,
  status ENUM('pending','processing','delivered','dead_letter') NOT NULL DEFAULT 'pending',
  attempt_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  available_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  delivered_at TIMESTAMP(3) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (outbox_id),
  UNIQUE KEY uq_nexus_outbox_journal_event (journal_id, event_type),
  KEY idx_nexus_outbox_delivery (status, available_at, outbox_id),
  CONSTRAINT fk_nexus_outbox_journal FOREIGN KEY (journal_id)
    REFERENCES nexus_command_journal (journal_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS nexus_audit_events (
  event_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  company_id INT NOT NULL,
  user_id INT NOT NULL,
  session_hash BINARY(32) NOT NULL,
  action_name VARCHAR(128) NOT NULL,
  target_hash BINARY(32) NULL,
  result_count INT UNSIGNED NULL,
  result_code VARCHAR(32) NOT NULL,
  metadata JSON NULL,
  occurred_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (event_id),
  KEY idx_nexus_audit_company_time (company_id, occurred_at),
  KEY idx_nexus_audit_action_time (action_name, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
