'use strict';
/* Database layer — real SQL (SQLite via node:sqlite), WAL mode, foreign keys,
   indexes on every lookup column. All SQL in the app is parameterized.
   Migration seam: queries use standard SQL only; swapping this module for a
   Postgres implementation keeps routes unchanged. */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, '..', 'data', 'app.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

let db = null;
function openDb() {
  db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  return db;
}
function getDb() { return db || openDb(); }
function closeDb() { if (db) { try { db.close(); } catch {} db = null; } }
function reopenDb() { closeDb(); return openDb(); }

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pass_hash TEXT NOT NULL, pass_salt TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Owner','Admin','Member','Viewer')),
  status TEXT NOT NULL DEFAULT 'active',
  twofa_secret TEXT, twofa_enabled INTEGER NOT NULL DEFAULT 0,
  last_login_ip TEXT, archived_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
  id TEXT PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE, role TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE, created_by TEXT REFERENCES users(id),
  expires_at TEXT NOT NULL, accepted_at TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL REFERENCES users(id),
  ip TEXT, user_agent TEXT, created_at TEXT NOT NULL, last_seen TEXT NOT NULL,
  expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, website TEXT NOT NULL, domain TEXT NOT NULL,
  contact_name TEXT, contact_email TEXT, status TEXT NOT NULL DEFAULT 'active', notes TEXT,
  portal_enabled INTEGER NOT NULL DEFAULT 0,
  created_by TEXT REFERENCES users(id), archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clients_domain ON clients(domain);
CREATE TABLE IF NOT EXISTS client_access (
  user_id TEXT NOT NULL REFERENCES users(id), client_id TEXT NOT NULL REFERENCES clients(id),
  PRIMARY KEY (user_id, client_id)
);
CREATE INDEX IF NOT EXISTS idx_access_client ON client_access(client_id);
CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY, domain TEXT NOT NULL, dr REAL, notes TEXT,
  created_by TEXT REFERENCES users(id), archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES clients(id), name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', start_date TEXT, end_date TEXT,
  created_by TEXT REFERENCES users(id), archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_campaigns_client ON campaigns(client_id);
CREATE TABLE IF NOT EXISTS backlinks (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES clients(id),
  campaign_id TEXT REFERENCES campaigns(id),
  source_url TEXT NOT NULL, source_domain TEXT NOT NULL, target_url TEXT NOT NULL,
  anchor_text TEXT, link_type TEXT NOT NULL DEFAULT 'dofollow' CHECK(link_type IN ('dofollow','nofollow','sponsored','ugc')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('live','lost','pending','rejected')),
  dr REAL, placement TEXT, notes TEXT, source TEXT NOT NULL DEFAULT 'manual',
  created_by TEXT REFERENCES users(id), archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backlinks_client ON backlinks(client_id);
CREATE INDEX IF NOT EXISTS idx_backlinks_domain ON backlinks(source_domain);
CREATE INDEX IF NOT EXISTS idx_backlinks_status ON backlinks(status);
CREATE TABLE IF NOT EXISTS backlink_events (
  id TEXT PRIMARY KEY, backlink_id TEXT NOT NULL REFERENCES backlinks(id),
  actor_id TEXT REFERENCES users(id), type TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_backlink ON backlink_events(backlink_id, created_at);
CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES clients(id), site_url TEXT NOT NULL,
  type TEXT, status TEXT NOT NULL DEFAULT 'pending', submitted_by TEXT REFERENCES users(id),
  submitted_date TEXT, archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_submissions_client ON submissions(client_id);
CREATE TABLE IF NOT EXISTS outreach (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES clients(id), name TEXT NOT NULL,
  email TEXT, website TEXT, domain TEXT, status TEXT NOT NULL DEFAULT 'new',
  archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outreach_client ON outreach(client_id);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT,
  assignee_id TEXT REFERENCES users(id), created_by TEXT REFERENCES users(id),
  client_id TEXT REFERENCES clients(id), campaign_id TEXT REFERENCES campaigns(id),
  deadline TEXT, priority TEXT NOT NULL DEFAULT 'medium' CHECK(priority IN ('low','medium','high','urgent')),
  status TEXT NOT NULL DEFAULT 'todo' CHECK(status IN ('todo','in_progress','blocked','done')),
  archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee_id);
CREATE INDEX IF NOT EXISTS idx_tasks_client ON tasks(client_id);
CREATE INDEX IF NOT EXISTS idx_tasks_deadline ON tasks(deadline);
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), type TEXT NOT NULL,
  ref_type TEXT, ref_id TEXT, message TEXT NOT NULL, dedupe_key TEXT UNIQUE,
  read_at TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, created_at);
CREATE TABLE IF NOT EXISTS saved_views (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), shared INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL, entity TEXT NOT NULL, filters_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY, actor_id TEXT, action TEXT NOT NULL, entity TEXT NOT NULL,
  entity_id TEXT, before_json TEXT, after_json TEXT, reason TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY, user_id TEXT, email TEXT, type TEXT NOT NULL, ip TEXT, detail TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sec_created ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_sec_email ON security_events(email, created_at);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS api_budgets (
  id TEXT PRIMARY KEY, provider TEXT NOT NULL UNIQUE, monthly_limit INTEGER NOT NULL,
  alert_pct INTEGER NOT NULL DEFAULT 80, per_request_price REAL, pause_at_limit INTEGER NOT NULL DEFAULT 0,
  archived_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_usage (
  id TEXT PRIMARY KEY, provider TEXT NOT NULL, month TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
  UNIQUE(provider, month)
);
CREATE TABLE IF NOT EXISTS backups (
  id TEXT PRIMARY KEY, filename TEXT NOT NULL, size INTEGER NOT NULL, checksum TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'manual', created_by TEXT, created_at TEXT NOT NULL,
  restore_test_at TEXT, restore_test_result TEXT
);
CREATE TABLE IF NOT EXISTS import_jobs (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, client_id TEXT,
  total_rows INTEGER NOT NULL DEFAULT 0, processed_rows INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'preview', rows_json TEXT NOT NULL, failed_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, revoked_at TEXT
);
`;

const DEFAULT_SETTINGS = {
  workspace_name: 'Backlink Management',
  timezone: 'UTC',
  default_link_type: 'dofollow',
  session_lifetime_hours: '24',
  require_2fa: 'false',
  suspicious_login_alerts: 'true',
  backup_schedule: 'off', // off | daily | weekly
  backup_retention_days: '30',
  import_max_rows: '1000',
  notify_overdue_tasks: 'true',
};

function migrate() {
  const d = getDb();
  d.exec(SCHEMA);
  const ins = d.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) ins.run(k, v);
}
function getSetting(key) {
  const r = getDb().prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return r ? r.value : (DEFAULT_SETTINGS[key] ?? null);
}
function setSetting(key, value) {
  getDb().prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, String(value));
}
function allSettings() {
  const out = { ...DEFAULT_SETTINGS };
  for (const r of getDb().prepare('SELECT key, value FROM settings').all()) out[r.key] = r.value;
  return out;
}

module.exports = { getDb, openDb, closeDb, reopenDb, migrate, getSetting, setSetting, allSettings, DB_PATH };
