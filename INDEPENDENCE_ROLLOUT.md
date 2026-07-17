# Nexus V2 independence rollout gates

This branch establishes the internal Nexus Core V2 boundary without changing
the live source of truth. CloudPatrol MySQL remains authoritative. The stale
shadow database and owned gateway are not part of this rollout.

## Safe initial state

- `ENORMITY_BACKGROUND_WRITES_ENABLED=0` keeps every Core mutation locked.
- `NEXUS_DB_IDENTITY_STRICT=1` requires four distinct database users before the
  service can become healthy.
- Assistant location, metric, and fingerprint-metadata reads use
  `nexus_query`; they return company-scoped, bounded contracts only.
- Fingerprint templates are excluded from queries, responses, audits, and
  contract probes.
- Direct command and biometric routes have no OEM fallback. Uninstalled
  handlers fail closed.

## Ordered rollout

1. Capture and verify a logical CloudPatrol backup.
2. Dry-run, review, then apply `001_nexus_foundation_up.sql` with
   `scripts/migrate-nexus-foundation.sh`. Applying requires the operator to
   bind `NEXUS_FOUNDATION_MIGRATION_SHA256` to the exact hash printed by the
   dry run.
3. Generate four independent password files, dry-run, then apply
   `scripts/provision-nexus-db-identities.sh`.
4. Start Core with strict identities and writes disabled. Run
   `npm run test:nexus-v2-contract` from the isolated read-only QA container.
5. Keep unfinished read domains in OEM mode. A domain may enter `compare` only
   after its typed direct contract exists. Seven consecutive clean days are
   required before `direct`.
6. A command domain may become direct only when its handler, table-specific
   grants, clone tests, canary evidence, Git SHA, and release ID are bound.
   Mutations never use comparison or fallback.
7. Keep biometric writes locked until the nine physical checks pass against
   the exact release. Scanner templates may travel only inside the protected
   enrollment request.
8. Cut authentication over last, after the browser-reachable OEM dependency
   inventory reaches zero and the 30-day credential migration/reset program is
   approved.

The migration down file removes only the additive Nexus tables. It does not
alter an OEM table or delete production records.
