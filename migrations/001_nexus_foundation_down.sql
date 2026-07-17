-- Reverses only objects introduced by 001_nexus_foundation_up.sql.
-- Existing OEM CloudPatrol tables are never touched.

DROP TABLE IF EXISTS nexus_outbox;
DROP TABLE IF EXISTS nexus_command_journal;
DROP TABLE IF EXISTS nexus_audit_events;
DROP TABLE IF EXISTS nexus_identity_reset_tokens;
DROP TABLE IF EXISTS nexus_identity_credentials;
