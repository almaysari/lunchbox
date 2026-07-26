# CLAUDE.md — Madar Platform (lunchbox)

Project-level working agreement, derived from the global Graphify workflow
(`~/.claude/skills/graphify-workflow/SKILL.md`) and adapted to this
repository. Every safety rule from the global workflow is preserved here;
project-specific rules only add constraints, never relax them.

## What this repository is

Madar (مدار) — a unified company platform; **mail is the first module**.
A dependency-light Node.js monolith (`madar/`): raw `http` server, single-page
frontend (`madar/public/index.html`), PostgreSQL 16 as the only runtime
database, and `pg` as the only production dependency. Mail syncs from Zoho
via OAuth REST. The official runtime is **Docker only**
(`madar/docker-compose.yml`; migrations run on container boot under a
PostgreSQL advisory lock).

Key directories:

- `madar/server.js` — HTTP entry: sessions, CSRF, RBAC, admin routes.
- `madar/core/` — crypto (AES-256-GCM keyring), auth + lockout, db pool,
  audit, content-addressed attachment storage, health.
- `madar/modules/mail/` — Zoho client, discovery, sync/ingestion (canonical
  fingerprint + routing), live-sync worker, collector ledger + organizer,
  group mirrors, integration API, acceptance harness.
- `madar/migrations/` — sequential SQL migrations (**append-only**).
- `madar/scripts/` — operator CLIs (setup, diagnostics, acceptance, verify gates).
- `madar/test/` — integration tests against real PostgreSQL + a mock Zoho
  server (`test/mock-zoho.js`). The suite is order-dependent; the file is the
  unit — run it whole.
- `madar/docs/` — living records: `DECISIONS.md` (decision log),
  `POSTGRES-SCHEMA-VERIFIED.md` (schema doc, CI-enforced),
  `COLLECTOR-ARCHITECTURE.md` (collector contracts), production-readiness docs.

## Project understanding requirements (before ANY change)

1. Understand the project architecture first — read the relevant module and
   `docs/DECISIONS.md` entries that shaped it. Decisions there were bought
   with production evidence; do not re-litigate them casually.
2. Review dependencies and affected components before editing.
3. Use Graphify context when available (architecture map, impact analysis).
4. Identify risks before changing code, and name the failure scenario.
5. Do not make large changes without explaining impact first.
6. Preserve existing architecture unless a change is genuinely required.

## Architecture analysis requirements

- Highest-risk touch points — treat edits here as risky modifications and
  explain impact before coding:
  - `modules/mail/sync.js` — canonical fingerprint (v3) and routing; the
    duplicate-prevention invariant `UNIQUE(mailbox_id, canonical_message_id)`
    and the provider-identity guard live here.
  - `core/crypto.js` — encryption keyring; a mistake here can orphan every
    encrypted secret in the database.
  - `migrations/` — append-only. Never edit an applied migration; add a new
    one. Migrations must stay idempotent and safe under concurrent apply.
- The worker (live-sync, collector organizer, acceptance sampler) keeps ALL
  durable state in PostgreSQL. Never introduce state that only lives in
  process memory and matters across restarts.
- Evidence-first ownership: green tests alone never prove a feature works;
  behaviour on the real tenant is the only production proof. Do not declare
  success from the mock alone.

## Dependency review rules

- Production dependencies are intentionally minimal (`pg` only). Adding a
  dependency is an architecture decision: justify it, record it in
  `docs/DECISIONS.md`, and prefer the standard library.
- Review the blast radius of any change to `core/` — every module depends on it.
- Zoho API surface changes (endpoints, scopes, payloads) must be
  evidence-based (probed and classified), never assumed from documentation
  memory.

## Security review requirements

- Never print secrets, passwords, or tokens in chat, logs, CLI output, or
  reports. Evidence and audit payloads go through the central sanitizers.
- No message subjects/bodies of real mail in CLI outputs or stored evidence
  (operator-chosen canary subjects are the exception). No PII in stored
  evidence.
- This is a public repository: do not add real mailbox identities or
  employee addresses to documentation.
- Least privilege on OAuth connections: the admin connection stays
  **read-only**. Write scopes exist only on dedicated, owner-consented
  connections (collector writes; group mirrors), each with the narrowest
  scope. Never widen an existing connection's scopes.
- Group-mirror writes require an explicit allowlist; policy-excluded groups
  are refused even when allowlisted (`modules/mail/mirror.js`). Do not
  weaken this safeguard.
- Admin users cannot read mail content without an explicit, audited grant —
  preserve this in any route change.
- `npm run verify:security` must pass locally; CI additionally runs gitleaks
  over the full history.

## Production safety rules

- **Never modify production directly.** The official run path is Docker;
  production changes ship only through this repo's branch → CI → the owner's
  manual `git pull && docker compose build && up -d`.
- Do not modify production-related configuration (docker-compose, Dockerfile,
  `.env` expectations, CI workflow) without explicit confirmation from the
  owner.
- Respect active acceptance runs: while a 72-hour soak is running, code
  freeze applies — no deploys, restarts, config changes, migrations, or
  OAuth rotation unless production is genuinely broken.
- Original (shared) mailboxes are the system of record: no code path may
  move, delete, or mutate messages there. Collector-side writes are confined
  to the collector mailbox. Historical archives never enter through the
  collector.
- Quick fixes are rejected by policy: fix causes, not verdicts
  (e.g. fix the harness honestly rather than patching a report to pass).

## Git workflow rules

- Prefer feature branches; develop on the designated `claude/*` branch for
  the session and push there. Never push to a different branch without
  explicit permission.
- **No force-push, no history rewrite.**
- If a push is rejected, rebase on the remote branch and push again.
- Commit messages describe the change and its reasoning; do not include
  model identifiers in commits, code, or PR bodies.
- Third-party skill files stay out of Git.

## Testing requirements

- Run tests before finalizing ANY change: `cd madar && npm test`
  (integration tests against a real PostgreSQL — `TEST_DATABASE_URL`,
  defaults to `postgresql://madar:madar_dev@localhost:5432/madar_test`).
- TDD is the working style here: write the failing test first (red), then
  implement (green). New behaviour without a test is not done.
- The mock Zoho server mirrors observed live-tenant behaviour, including its
  quirks and rejection fixtures — extend it faithfully when adding API surface.
- Schema changes require `npm run migrate` plus
  `npm run verify:schema -- --update` so the schema doc matches; CI fails on
  drift.
- CI (`.github/workflows/ci.yml`) is the gate authority: syntax lint,
  migrations from empty + idempotency + concurrent-apply safety, the full
  test suite, verify:schema, verify:security, gitleaks. All must be green
  before work is called complete.

## Documentation requirements

- Document important changes: significant decisions get an entry in
  `madar/docs/DECISIONS.md` (what, why, and the evidence).
- Operator-facing behaviour changes update the relevant runbook/docs
  (`COLLECTOR-ARCHITECTURE.md`, `PRODUCTION-READINESS.md`, …).
- Keep documentation identity-clean (public repo — see security section).

## Secret and credential protection rules

- Protect secrets and credentials: secrets reach the app only via `.env` →
  environment; `.env` never enters the build context, the image, or Git.
- OAuth client secrets and tokens are stored AES-256-GCM encrypted in
  PostgreSQL under the keyring; never decrypt-and-print.
- Never request or handle the owner's passwords, MFA codes, or raw tokens;
  OAuth consent is always performed by the owner in their own browser.
- Test keys are random per run; CI database credentials are CI-only values.

## Before making any code changes (checklist)

- Understand the architecture first.
- Identify the affected files and name them.
- Explain risks and impact (what breaks if this is wrong?).
- Review dependencies (callers, callees, schema, docs, tests).
- Use Graphify when available.
- Do not modify production-related configurations without confirmation.
