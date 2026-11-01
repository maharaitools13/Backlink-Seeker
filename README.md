# Backlink Management SaaS

A complete backlink management web app for an SEO agency team: real SQL database, real authentication, server-side roles and client-level access, and all 10 advanced modules wired to real backend functionality. English only. Starts empty — the first person to sign up becomes the Owner, then public sign up closes.

Zero runtime dependencies: it uses Node.js built-ins only (`http`, `crypto`, `node:sqlite`, global `fetch`), so there is nothing to `npm install`.

## Setup

```bash
# Requires Node.js 22 or newer (uses the built-in node:sqlite module)
cp .env.example .env   # optional — defaults work without it
npm start              # http://localhost:3000
npm test               # runs the full API test suite (21 tests)
```

- First visit: create the **Owner** account (name, email, password 8+ characters).
- Owner/Admin then invite members from **Team & Invites**. Each invite is a one-time link (7-day expiry); the member sets their own password. If `SMTP_HOST` is not set, no email is sent — the UI returns the invite link to share directly, and says so. Nothing is faked.
- Data lives in `data/app.db` (SQLite, WAL mode). Backups are written to `backups/`.
- Environment variables: `PORT`, `DATABASE_PATH`, `BACKUP_DIR`, `NODE_ENV` (`production` marks the session cookie `Secure`, so use HTTPS), `APP_BASE_URL`, optional `SMTP_*`.

## How the code is organized

| Path | Purpose |
|---|---|
| `src/server.js` | Entry point: `.env` loading, security headers, static files, API wiring |
| `src/app.js` | All API routes: auth, users/invites, scoped CRUD, search, views, tasks, security, owner center, budgets, backups, import/export, links-only detection |
| `src/db.js` | SQL schema + indexes, settings store. All SQL is parameterized; standard SQL only, so this module is the seam for a future Postgres swap |
| `src/auth.js` | scrypt password hashing, sessions, TOTP 2FA (RFC 6238), role checks, client scoping, audit/security-event/notification writers |
| `src/utils.js` | Validation, CSV parser/writer, XLSX writer (real zip, verified with openpyxl), printable PDF writer |
| `public/` | Single-page UI (English only) — renders API data only; every permission is enforced again on the server |
| `tests/api.test.js` | End-to-end tests against a spawned server + temp database, including failure cases |

## Security model

- Passwords: scrypt with per-user salt, timing-safe compare. Sessions: random tokens, only SHA-256 hashes stored, HttpOnly + SameSite=Lax cookies, lifetime set by the Owner.
- Roles **Owner / Admin / Member / Viewer** are checked on the server for every route. Viewers are read-only.
- **Client-level access:** Members/ Viewers only ever see clients the Owner assigned to them — enforced in lists, global search, tasks, exports, link detection, and direct URLs (403). The Owner account cannot be demoted or archived by anyone.
- Login throttling after 10 failed attempts in 15 minutes; suspicious-login events (new IP) with notifications; append-only audit log and security event log.
- Archive-first deletion everywhere; bulk actions are archive-only. Permanent purge is Owner-only, archived records only, typed `DELETE` + a reason, audit-logged before the row is removed.
- Backlink event history (created / status changed / edited / archived / restored) is preserved through archive and restore.

## Modules

1. **Global Search** — backlinks, domains, clients, submissions, users, campaigns, outreach; type + client filters; permission-scoped.
2. **Backup & Recovery** — Owner-only; scheduled backups (off/daily/weekly), checksum + size history, retention pruning, restore-test recording, restore requires typed `RESTORE`.
3. **Tasks & Workload** — assignment (Owner/Admin assign to others), priority/status/deadline, client+campaign links, overdue notifications deduped to one per task per day, per-member workload + completion counts.
4. **Filtering & Saved Views** — filters, sorting, pagination, bulk select → archive on all main tables; personal views; Owner-created shared views (data still scoped per viewer).
5. **Security & Sessions** — active sessions with revoke (own; Owner: any), real TOTP 2FA, Owner can require 2FA (enforced on the API), suspicious-login alerts, security audit.
6. **Import & Export** — exports by client/member in CSV, XLSX and PDF; CSV import preview (writes nothing) → validation → confirm; failed-row report download; resumable imports without duplicates.
7. **Links-Only Import** — up to 50 page URLs + a client; the server fetches each page and detects domain, live/lost, target URL, anchor text and link type from the real outbound link's `rel`. No client link → "target link not found" in the failed-row report. DR is never invented: blank = "not available".
8. **API Budgets** — per-provider monthly limits, alert %, optional pause-at-limit (429), real request counts (link detection counts toward `page-fetch`); estimated cost only when a per-request price is configured, otherwise "not available".
9. **Owner Control Center** — General, Security, Notifications, Backup, Import settings that persist and are actually read (workspace name in the header, session lifetime on login, require-2FA enforcement, retention on backup creation…), API budgets, and System Monitoring with real counts only.
10. **Data Integrity** — soft-delete + restore everywhere, audit log with before/after, no bulk delete.

**Future seams only (not built):** `clients.portal_enabled` (Client Portal), `backlinks.source` (manual/import/detection/extension), scoped API tokens (`api_tokens`, hashes only) for a Browser Extension, plus the audit/usage data white-label reporting and workload analytics would read.

## Known limits / risks

- **SQLite scale:** indexes, WAL and pagination are in place and this is comfortable for a single-server agency team. At sustained multi-instance or very high write concurrency, swap `src/db.js` for Postgres (queries are standard, parameterized SQL).
- **Email delivery** needs real SMTP credentials in `.env`; without them invites are shareable links (the UI says exactly this).
- **Hosting:** run it on a host with a persistent disk (VPS, Render/Railway with a volume). Serverless filesystems that reset (e.g. plain Vercel) will lose the database file.
- A database restore replaces the current DB, so the "restore" audit entry written just before it lives in the pre-restore database; the backup history inside the restored DB is the record that survives. Test restores (recorded, non-destructive) are the handover-safe path.
- Link detection fetches arbitrary user-supplied URLs server-side (SSRF-sensitive by nature): it is limited to http/https, 50 URLs, 8s timeouts and 1 MB per page, and requires an authenticated, client-authorized user.

## Git

Small, focused commits per stage (scaffold/auth → backend → UI → tests/README). `.env`, `data/` and backup files are git-ignored and are never committed.
