'use strict';
/* HTTP API — all routes, server-side authorization on every route. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getDb, getSetting, setSetting, allSettings, reopenDb, DB_PATH } = require('./db');
const A = require('./auth');
const U = require('./utils');

const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, '..', 'backups');

function send(res, status, data, headers = {}) {
  const body = typeof data === 'string' || Buffer.isBuffer(data) ? data : JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': Buffer.isBuffer(data) ? 'application/octet-stream' : (typeof data === 'string' ? 'text/plain; charset=utf-8' : 'application/json'), ...headers });
  res.end(body);
}
const err = (res, status, message) => send(res, status, { error: message });
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', (c) => { size += c.length; if (size > 5 * 1024 * 1024) { reject(new Error('Request body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { const raw = Buffer.concat(chunks).toString('utf8'); if (!raw) return resolve({}); try { resolve(JSON.parse(raw)); } catch { reject(new Error('Invalid JSON body')); } });
    req.on('error', reject);
  });
}
function getCookie(req, name) {
  const m = String(req.headers.cookie || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function sessionCookie(token, maxAgeSec) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `sid=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}${secure}`;
}
const clientIp = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

function requireAuth(req, res, pathname) {
  const auth = A.userFromToken(getCookie(req, 'sid'));
  if (!auth) { err(res, 401, 'Not signed in'); return null; }
  const exempt = pathname.startsWith('/api/auth/') || pathname.startsWith('/api/security/');
  if (!exempt && getSetting('require_2fa') === 'true' && !auth.user.twofa_enabled) {
    err(res, 403, 'Two-factor authentication is required by the Owner. Enable it in Security to continue.');
    return null;
  }
  return auth;
}
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, status: u.status, twofa_enabled: !!u.twofa_enabled, created_at: u.created_at });

/* ---------------- Overdue tasks (dedupe: one notification per task per day) ---------------- */
function checkOverdueTasks() {
  if (getSetting('notify_overdue_tasks') !== 'true') return;
  const today = new Date().toISOString().slice(0, 10);
  const rows = getDb().prepare(`SELECT * FROM tasks WHERE archived_at IS NULL AND status != 'done' AND deadline IS NOT NULL AND deadline < date('now')`).all();
  for (const t of rows) {
    if (t.assignee_id) A.notify(t.assignee_id, 'task_overdue', 'task', t.id, `Task "${t.title}" is overdue (deadline ${t.deadline}).`, `overdue:${t.id}:${t.assignee_id}:${today}`);
  }
}

/* ---------------- API budgets ---------------- */
function monthKey() { return new Date().toISOString().slice(0, 7); }
function usageFor(provider) {
  const r = getDb().prepare('SELECT requests FROM api_usage WHERE provider = ? AND month = ?').get(provider, monthKey());
  return r ? r.requests : 0;
}
function budgetFor(provider) { return getDb().prepare('SELECT * FROM api_budgets WHERE provider = ? AND archived_at IS NULL').get(provider); }
function checkBudget(provider, n) { // returns error string or null
  const b = budgetFor(provider); if (!b) return null;
  if (b.pause_at_limit && usageFor(provider) + n > b.monthly_limit) return `API budget reached for ${provider}: limit ${b.monthly_limit} requests/month. Requests are paused by the Owner's budget setting.`;
  return null;
}
function recordUsage(provider, n) {
  if (!n) return;
  getDb().prepare('INSERT INTO api_usage (id, provider, month, requests) VALUES (?,?,?,?) ON CONFLICT(provider, month) DO UPDATE SET requests = requests + excluded.requests')
    .run(U.uid(), provider, monthKey(), n);
  const b = budgetFor(provider); if (!b) return;
  const used = usageFor(provider);
  if (used >= b.monthly_limit * b.alert_pct / 100) {
    for (const o of getDb().prepare("SELECT id FROM users WHERE role = 'Owner' AND archived_at IS NULL").all()) {
      A.notify(o.id, 'api_budget_alert', 'api_budget', b.id, `API usage for ${provider} is at ${used}/${b.monthly_limit} (${Math.round(used / b.monthly_limit * 100)}%, alert at ${b.alert_pct}%).`, `budget-alert:${provider}:${monthKey()}:${b.alert_pct}`);
    }
  }
}

/* ---------------- Backups ---------------- */
function fileChecksum(p) { return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); }
function createBackup(actorId, kind) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  getDb().exec('PRAGMA wal_checkpoint(TRUNCATE);');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `backup-${stamp}.db`;
  const dest = path.join(BACKUP_DIR, filename);
  fs.copyFileSync(DB_PATH, dest);
  const row = { id: U.uid(), filename, size: fs.statSync(dest).size, checksum: fileChecksum(dest), kind, created_by: actorId || null, created_at: U.now() };
  getDb().prepare('INSERT INTO backups (id, filename, size, checksum, kind, created_by, created_at) VALUES (?,?,?,?,?,?,?)').run(row.id, row.filename, row.size, row.checksum, row.kind, row.created_by, row.created_at);
  // Retention: remove backups older than the configured retention window.
  const days = Math.max(1, parseInt(getSetting('backup_retention_days'), 10) || 30);
  const cutoff = new Date(Date.now() - days * 86400e3).toISOString();
  for (const old of getDb().prepare('SELECT * FROM backups WHERE created_at < ? AND id != ?').all(cutoff, row.id)) {
    try { fs.unlinkSync(path.join(BACKUP_DIR, old.filename)); } catch {}
    getDb().prepare('DELETE FROM backups WHERE id = ?').run(old.id);
  }
  return row;
}
function maybeAutoBackup() {
  const sched = getSetting('backup_schedule'); if (sched === 'off') return;
  const last = getDb().prepare('SELECT created_at FROM backups ORDER BY created_at DESC LIMIT 1').get();
  const interval = sched === 'weekly' ? 7 * 86400e3 : 86400e3;
  if (!last || (Date.now() - new Date(last.created_at).getTime() > interval)) createBackup(null, 'scheduled');
}

/* ---------------- Generic scoped listing ---------------- */
function paging(req, url) {
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(url.searchParams.get('pageSize') || '25', 10) || 25));
  return { page, pageSize, offset: (page - 1) * pageSize };
}
function listResponse(res, table, where, params, sortCol, sortDir, paging, select = '*') {
  const total = getDb().prepare(`SELECT COUNT(*) AS c FROM ${table} WHERE ${where}`).get(...params).c;
  const rows = getDb().prepare(`SELECT ${select} FROM ${table} WHERE ${where} ORDER BY ${sortCol} ${sortDir} LIMIT ? OFFSET ?`).all(...params, paging.pageSize, paging.offset);
  send(res, 200, { rows, total, page: paging.page, pageSize: paging.pageSize });
}
function scopeWhere(user, alias, clientCol = 'client_id') {
  // Returns [sql, params] restricting rows to clients the user can access.
  if (A.isAdminUp(user)) return [`${alias}.archived_at IS NULL`, []];
  const ids = A.accessibleClientIds(user);
  if (!ids.length) return ['1 = 0', []];
  return [`${alias}.archived_at IS NULL AND ${alias}.${clientCol} IN (${ids.map(() => '?').join(',')})`, ids];
}

/* ================= AUTH ROUTES ================= */
async function authRoutes(req, res, url, pathname) {
  const db = getDb();
  if (pathname === '/api/auth/setup' && req.method === 'GET') {
    const c = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
    return send(res, 200, { ownerExists: c > 0, workspaceName: getSetting('workspace_name') });
  }
  if (pathname === '/api/auth/signup' && req.method === 'POST') {
    const b = await readBody(req);
    const name = U.str(b.name, 120), email = U.str(b.email, 254).toLowerCase(), password = String(b.password || '');
    if (!name || !U.isEmail(email) || password.length < 8) return err(res, 400, 'Name, a valid email, and a password of at least 8 characters are required.');
    const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
    if (count > 0) return err(res, 403, 'Public sign up is closed. Ask the Owner or an Admin to invite you.');
    const { salt, hash } = A.hashPassword(password);
    const user = { id: U.uid(), name, email, role: 'Owner', created_at: U.now() };
    try { db.prepare('INSERT INTO users (id, name, email, pass_hash, pass_salt, role, created_at) VALUES (?,?,?,?,?,?,?)').run(user.id, name, email, hash, salt, 'Owner', user.created_at); }
    catch { return err(res, 409, 'An account with this email already exists.'); }
    A.audit(user.id, 'create', 'user', user.id, null, { email, role: 'Owner' });
    A.securityEvent(user.id, email, 'signup_owner', clientIp(req), null);
    const token = A.createSession(user.id, clientIp(req), req.headers['user-agent']);
    return send(res, 201, { user: publicUser({ ...user, status: 'active', twofa_enabled: 0 }) }, { 'Set-Cookie': sessionCookie(token, 86400) });
  }
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    const b = await readBody(req);
    const email = U.str(b.email, 254).toLowerCase(), password = String(b.password || '');
    const ip = clientIp(req);
    const fails = db.prepare("SELECT COUNT(*) AS c FROM security_events WHERE email = ? AND type = 'login_failed' AND created_at > datetime('now','-15 minutes')").get(email).c;
    if (fails >= 10) return err(res, 429, 'Too many failed login attempts. Try again in 15 minutes.');
    const user = db.prepare('SELECT * FROM users WHERE email = ? AND archived_at IS NULL').get(email);
    if (!user || user.status !== 'active' || !A.verifyPassword(password, user)) {
      A.securityEvent(user ? user.id : null, email, 'login_failed', ip, null);
      return err(res, 401, 'Invalid email or password.');
    }
    if (user.twofa_enabled) {
      if (!b.code) return send(res, 200, { needs2fa: true });
      if (!A.totpVerify(user.twofa_secret, b.code)) { A.securityEvent(user.id, email, 'login_failed', ip, 'bad 2FA code'); return err(res, 401, 'Invalid two-factor code.'); }
    }
    if (user.last_login_ip && user.last_login_ip !== ip && getSetting('suspicious_login_alerts') === 'true') {
      A.securityEvent(user.id, email, 'suspicious_login', ip, `New IP (previous ${user.last_login_ip})`);
      A.notify(user.id, 'suspicious_login', 'user', user.id, `A sign-in to your account came from a new IP address (${ip}). If this was not you, revoke your sessions in Security.`, null);
    }
    db.prepare('UPDATE users SET last_login_ip = ? WHERE id = ?').run(ip, user.id);
    A.securityEvent(user.id, email, 'login', ip, null);
    const token = A.createSession(user.id, ip, req.headers['user-agent']);
    const hours = Math.max(1, parseInt(getSetting('session_lifetime_hours'), 10) || 24);
    return send(res, 200, { user: publicUser(user) }, { 'Set-Cookie': sessionCookie(token, hours * 3600) });
  }
  if (pathname === '/api/auth/accept-invite' && req.method === 'POST') {
    const b = await readBody(req);
    const name = U.str(b.name, 120), password = String(b.password || '');
    if (!b.token || !name || password.length < 8) return err(res, 400, 'Invite token, your name, and a password of at least 8 characters are required.');
    const inv = db.prepare('SELECT * FROM invites WHERE token_hash = ? AND accepted_at IS NULL').get(U.sha256(String(b.token)));
    if (!inv || inv.expires_at < U.now()) return err(res, 400, 'This invite is invalid or has expired. Ask for a new invite.');
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(inv.email)) return err(res, 409, 'An account with this email already exists. Sign in instead.');
    const { salt, hash } = A.hashPassword(password);
    const id = U.uid();
    db.prepare('INSERT INTO users (id, name, email, pass_hash, pass_salt, role, created_at) VALUES (?,?,?,?,?,?,?)').run(id, name, inv.email, hash, salt, inv.role, U.now());
    db.prepare('UPDATE invites SET accepted_at = ? WHERE id = ?').run(U.now(), inv.id);
    A.audit(id, 'create', 'user', id, null, { email: inv.email, role: inv.role, via: 'invite' });
    const token = A.createSession(id, clientIp(req), req.headers['user-agent']);
    const fresh = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return send(res, 201, { user: publicUser(fresh) }, { 'Set-Cookie': sessionCookie(token, 86400) });
  }
  if (pathname === '/api/auth/logout' && req.method === 'POST') {
    const t = getCookie(req, 'sid');
    if (t) db.prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ?').run(U.now(), U.sha256(t));
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
  }
  return false;
}

/* ================= USERS / INVITES ================= */
async function userRoutes(req, res, url, pathname, ctx) {
  const db = getDb(); const me = ctx.user;
  if (pathname === '/api/auth/me' && req.method === 'GET') return send(res, 200, { user: publicUser(me), workspaceName: getSetting('workspace_name'), timezone: getSetting('timezone') });
  if (pathname === '/api/users' && req.method === 'GET') {
    const rows = db.prepare('SELECT id, name, email, role, status, twofa_enabled, created_at FROM users WHERE archived_at IS NULL ORDER BY created_at').all();
    if (!A.isAdminUp(me)) return send(res, 200, { rows: rows.map((r) => ({ id: r.id, name: r.name, role: r.role })) });
    for (const r of rows) r.clientIds = db.prepare('SELECT client_id FROM client_access WHERE user_id = ?').all(r.id).map((x) => x.client_id);
    return send(res, 200, { rows });
  }
  if (pathname === '/api/invites' && req.method === 'POST') {
    if (!A.isAdminUp(me)) return err(res, 403, 'Only the Owner or an Admin can invite team members.');
    const b = await readBody(req);
    const email = U.str(b.email, 254).toLowerCase();
    const role = U.oneOf(b.role, ['Admin', 'Member', 'Viewer'], 'Member');
    if (!U.isEmail(email)) return err(res, 400, 'A valid email is required.');
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return err(res, 409, 'A user with this email already exists.');
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 7 * 86400e3).toISOString();
    db.prepare('INSERT INTO invites (id, email, role, token_hash, created_by, expires_at, created_at) VALUES (?,?,?,?,?,?,?)').run(U.uid(), email, role, U.sha256(token), me.id, expires, U.now());
    A.audit(me.id, 'invite', 'user', null, null, { email, role });
    const base = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    const emailConfigured = !!process.env.SMTP_HOST;
    return send(res, 201, { inviteLink: `${base}/?invite=${token}`, email, role, expiresAt: expires, emailSent: emailConfigured, note: emailConfigured ? 'Invite email sent.' : 'Email is not configured (SMTP_HOST is not set), so share this invite link with the member directly. The member sets their own password.' });
  }
  if (pathname === '/api/invites' && req.method === 'GET') {
    if (!A.isAdminUp(me)) return err(res, 403, 'Only the Owner or an Admin can view invites.');
    return send(res, 200, { rows: db.prepare('SELECT id, email, role, expires_at, accepted_at, created_at FROM invites ORDER BY created_at DESC').all() });
  }
  const um = pathname.match(/^\/api\/users\/([^/]+)(\/clients|\/archive)?$/);
  if (um) {
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(um[1]);
    if (!target) return err(res, 404, 'User not found.');
    if (um[2] === '/clients' && req.method === 'PUT') {
      if (!A.isAdminUp(me)) return err(res, 403, 'Only the Owner or an Admin can assign clients.');
      const b = await readBody(req);
      const ids = Array.isArray(b.clientIds) ? b.clientIds.filter((x) => typeof x === 'string') : [];
      db.exec('BEGIN'); try {
        db.prepare('DELETE FROM client_access WHERE user_id = ?').run(target.id);
        const ins = db.prepare('INSERT INTO client_access (user_id, client_id) VALUES (?, ?)');
        for (const cid of ids) { if (db.prepare('SELECT id FROM clients WHERE id = ? AND archived_at IS NULL').get(cid)) ins.run(target.id, cid); }
        db.exec('COMMIT');
      } catch (e) { db.exec('ROLLBACK'); throw e; }
      A.audit(me.id, 'assign_clients', 'user', target.id, null, { clientIds: ids });
      return send(res, 200, { ok: true });
    }
    if (um[2] === '/archive' && req.method === 'POST') {
      if (!A.isAdminUp(me)) return err(res, 403, 'Only the Owner or an Admin can archive users.');
      if (target.role === 'Owner') return err(res, 403, 'The Owner account cannot be archived or deleted.');
      db.prepare('UPDATE users SET archived_at = ?, status = ? WHERE id = ?').run(U.now(), 'disabled', target.id);
      db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(U.now(), target.id);
      A.audit(me.id, 'archive', 'user', target.id, { email: target.email }, null);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'PATCH') {
      if (!A.isAdminUp(me)) return err(res, 403, 'Only the Owner or an Admin can change users.');
      if (target.role === 'Owner') return err(res, 403, 'The Owner account cannot be demoted or changed by anyone.');
      const b = await readBody(req);
      const role = U.oneOf(b.role, ['Admin', 'Member', 'Viewer'], target.role);
      const status = U.oneOf(b.status, ['active', 'disabled'], target.status);
      db.prepare('UPDATE users SET role = ?, status = ? WHERE id = ?').run(role, status, target.id);
      A.audit(me.id, 'update', 'user', target.id, { role: target.role, status: target.status }, { role, status });
      return send(res, 200, { ok: true });
    }
  }
  return false;
}

/* ================= CORE ENTITIES ================= */
const ENTITY = {
  clients: { table: 'clients', scoped: false, sort: ['name', 'created_at'], searchCols: ['name', 'website', 'contact_name', 'contact_email'] },
  domains: { table: 'domains', scoped: false, global: true, sort: ['domain', 'created_at', 'dr'], searchCols: ['domain'] },
  campaigns: { table: 'campaigns', scoped: true, sort: ['name', 'created_at', 'start_date'], searchCols: ['name'] },
  backlinks: { table: 'backlinks', scoped: true, sort: ['created_at', 'source_domain', 'status', 'dr'], searchCols: ['source_url', 'source_domain', 'target_url', 'anchor_text'] },
  submissions: { table: 'submissions', scoped: true, sort: ['created_at', 'submitted_date'], searchCols: ['site_url', 'type'] },
  outreach: { table: 'outreach', scoped: true, sort: ['created_at', 'name'], searchCols: ['name', 'email', 'website', 'domain'] },
  tasks: { table: 'tasks', scoped: 'task', sort: ['created_at', 'deadline', 'priority', 'status'], searchCols: ['title', 'description'] },
};
function getScopedRow(user, entityName, id) {
  const cfg = ENTITY[entityName]; const db = getDb();
  const row = db.prepare(`SELECT * FROM ${cfg.table} WHERE id = ?`).get(id);
  if (!row) return { status: 404 };
  if (row.archived_at) return { status: 404, archived: row };
  if (entityName === 'clients' && !A.canAccessClient(user, row.id)) return { status: 403 };
  if (cfg.scoped === true && !A.canAccessClient(user, row.client_id)) return { status: 403 };
  if (cfg.scoped === 'task' && row.client_id && !A.canAccessClient(user, row.client_id)) return { status: 403 };
  return { row };
}
function validateEntity(entityName, b, isCreate) {
  const e = {};
  const need = (cond, msg) => { if (cond) e.error = msg; };
  if (entityName === 'clients') {
    need(isCreate && !U.str(b.name, 160), 'Client name is required.'); need(isCreate && !U.isUrl(String(b.website || '')), 'A valid client website URL is required.');
    if (b.contact_email && !U.isEmail(String(b.contact_email))) e.error = 'Contact email is not valid.';
  }
  if (entityName === 'domains') need(isCreate && !U.str(b.domain, 253), 'Domain is required.');
  if (entityName === 'campaigns') { need(isCreate && !U.str(b.name, 160), 'Campaign name is required.'); need(isCreate && !b.client_id, 'A client is required.'); }
  if (entityName === 'backlinks') {
    need(isCreate && !U.isUrl(String(b.source_url || '')), 'A valid source/page URL is required.');
    need(isCreate && !U.isUrl(String(b.target_url || '')), 'A valid target URL is required.');
    need(isCreate && !b.client_id, 'A client is required.');
    if (b.link_type && !['dofollow', 'nofollow', 'sponsored', 'ugc'].includes(b.link_type)) e.error = 'Invalid link type.';
    if (b.status && !['live', 'lost', 'pending', 'rejected'].includes(b.status)) e.error = 'Invalid status.';
    if (b.dr !== undefined && b.dr !== null && b.dr !== '' && (isNaN(Number(b.dr)) || Number(b.dr) < 0)) e.error = 'DR must be a number or blank.';
  }
  if (entityName === 'submissions') { need(isCreate && !U.isUrl(String(b.site_url || '')), 'A valid site/directory URL is required.'); need(isCreate && !b.client_id, 'A client is required.'); }
  if (entityName === 'outreach') { need(isCreate && !U.str(b.name, 160), 'Contact name is required.'); need(isCreate && !b.client_id, 'A client is required.'); if (b.email && !U.isEmail(String(b.email))) e.error = 'Email is not valid.'; }
  if (entityName === 'tasks') {
    need(isCreate && !U.str(b.title, 200), 'Task title is required.');
    if (b.priority && !['low', 'medium', 'high', 'urgent'].includes(b.priority)) e.error = 'Invalid priority.';
    if (b.status && !['todo', 'in_progress', 'blocked', 'done'].includes(b.status)) e.error = 'Invalid task status.';
  }
  return e.error;
}
function buildRow(entityName, b, user, existing) {
  const t = U.now(); const base = existing ? { ...existing } : { id: U.uid(), created_at: t, created_by: user.id, archived_at: null };
  const s = (v, m) => (v === undefined ? (existing ? existing[Object.keys({})] : null) : v);
  if (entityName === 'clients') Object.assign(base, { name: U.str(b.name ?? base.name, 160), website: String(b.website ?? base.website), domain: U.hostnameOf(String(b.website ?? base.website)), contact_name: U.str(b.contact_name ?? base.contact_name ?? '', 160) || null, contact_email: U.str(b.contact_email ?? base.contact_email ?? '', 254) || null, status: U.oneOf(b.status ?? base.status, ['active', 'paused'], 'active'), notes: U.str(b.notes ?? base.notes ?? '', 2000) || null, portal_enabled: b.portal_enabled === undefined ? (base.portal_enabled || 0) : (b.portal_enabled ? 1 : 0) });
  if (entityName === 'domains') Object.assign(base, { domain: U.hostnameOf('https://' + String(b.domain ?? base.domain).replace(/^https?:\/\//, '')) || U.str(b.domain ?? base.domain, 253), dr: (b.dr === '' || b.dr === undefined) ? (base.dr ?? null) : (b.dr === null ? null : Number(b.dr)), notes: U.str(b.notes ?? base.notes ?? '', 2000) || null });
  if (entityName === 'campaigns') Object.assign(base, { client_id: b.client_id ?? base.client_id, name: U.str(b.name ?? base.name, 160), status: U.str(b.status ?? base.status ?? 'active', 40), start_date: b.start_date ?? base.start_date ?? null, end_date: b.end_date ?? base.end_date ?? null });
  if (entityName === 'backlinks') Object.assign(base, { client_id: b.client_id ?? base.client_id, campaign_id: b.campaign_id ?? base.campaign_id ?? null, source_url: String(b.source_url ?? base.source_url), source_domain: U.hostnameOf(String(b.source_url ?? base.source_url)), target_url: String(b.target_url ?? base.target_url), anchor_text: U.str(b.anchor_text ?? base.anchor_text ?? '', 500) || null, link_type: b.link_type ?? base.link_type ?? (getSetting('default_link_type') || 'dofollow'), status: b.status ?? base.status ?? 'pending', dr: (b.dr === '' ) ? null : (b.dr === undefined ? (base.dr ?? null) : (b.dr === null ? null : Number(b.dr))), placement: U.str(b.placement ?? base.placement ?? '', 200) || null, notes: U.str(b.notes ?? base.notes ?? '', 2000) || null, source: base.source || 'manual' });
  if (entityName === 'submissions') Object.assign(base, { client_id: b.client_id ?? base.client_id, site_url: String(b.site_url ?? base.site_url), type: U.str(b.type ?? base.type ?? '', 80) || null, status: U.str(b.status ?? base.status ?? 'pending', 40), submitted_by: b.submitted_by ?? base.submitted_by ?? user.id, submitted_date: b.submitted_date ?? base.submitted_date ?? null });
  if (entityName === 'outreach') Object.assign(base, { client_id: b.client_id ?? base.client_id, name: U.str(b.name ?? base.name, 160), email: U.str(b.email ?? base.email ?? '', 254) || null, website: U.str(b.website ?? base.website ?? '', 500) || null, domain: U.hostnameOf(String(b.website ?? base.website ?? '')) || U.str(b.domain ?? base.domain ?? '', 253) || null, status: U.str(b.status ?? base.status ?? 'new', 40) });
  if (entityName === 'tasks') Object.assign(base, { title: U.str(b.title ?? base.title, 200), description: U.str(b.description ?? base.description ?? '', 4000) || null, assignee_id: b.assignee_id ?? base.assignee_id ?? null, client_id: b.client_id ?? base.client_id ?? null, campaign_id: b.campaign_id ?? base.campaign_id ?? null, deadline: b.deadline ?? base.deadline ?? null, priority: b.priority ?? base.priority ?? 'medium', status: b.status ?? base.status ?? 'todo' });
  base.updated_at = t; return base;
}
function insertRow(table, row) {
  const cols = Object.keys(row).filter((c) => c !== 'backlink_count');
  getDb().prepare(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).run(...cols.map((c) => row[c] ?? null));
}
function updateRow(table, row) {
  const cols = Object.keys(row).filter((c) => !['id', 'created_at', 'backlink_count'].includes(c));
  getDb().prepare(`UPDATE ${table} SET ${cols.map((c) => c + ' = ?').join(',')} WHERE id = ?`).run(...cols.map((c) => row[c] ?? null), row.id);
}
function backlinkEvent(backlinkId, actorId, type, detail) {
  getDb().prepare('INSERT INTO backlink_events (id, backlink_id, actor_id, type, detail, created_at) VALUES (?,?,?,?,?,?)').run(U.uid(), backlinkId, actorId, type, detail ? JSON.stringify(detail) : null, U.now());
}

async function entityRoutes(req, res, url, pathname, ctx) {
  const m = pathname.match(/^\/api\/(clients|domains|campaigns|backlinks|submissions|outreach|tasks)(?:\/([^/]+)(?:\/(archive|restore|purge|events))?)?$/);
  if (!m) return false;
  const [, entityName, id, action] = m; const cfg = ENTITY[entityName]; const user = ctx.user; const db = getDb();

  if (!id && req.method === 'GET') {
    checkOverdueTasksIfTasks(entityName);
    let where, params;
    if (entityName === 'clients') {
      if (A.isAdminUp(user)) { where = 'c.archived_at IS NULL'; params = []; }
      else { const ids = A.accessibleClientIds(user); if (!ids.length) return send(res, 200, { rows: [], total: 0, page: 1, pageSize: 25 }); where = `c.archived_at IS NULL AND c.id IN (${ids.map(() => '?').join(',')})`; params = ids; }
    } else if (cfg.global) { where = 'c.archived_at IS NULL'; params = []; }
    else if (cfg.scoped === 'task') {
      if (A.isAdminUp(user)) { where = 'c.archived_at IS NULL'; params = []; }
      else { const ids = A.accessibleClientIds(user); where = `c.archived_at IS NULL AND (c.client_id IS NULL OR c.client_id IN (${ids.length ? ids.map(() => '?').join(',') : "''"}))`; params = ids; }
    } else { [where, params] = scopeWhere(user, 'c'); }
    const q = url.searchParams.get('q'); const status = url.searchParams.get('status'); const clientId = url.searchParams.get('clientId'); const linkType = url.searchParams.get('linkType'); const assigneeId = url.searchParams.get('assigneeId'); const includeArchived = url.searchParams.get('includeArchived') === 'true';
    if (includeArchived) where = where.replace('c.archived_at IS NULL', '(c.archived_at IS NULL OR c.archived_at IS NOT NULL)');
    if (q) { where += ` AND (${cfg.searchCols.map((c) => `c.${c} LIKE ?`).join(' OR ')})`; cfg.searchCols.forEach(() => params.push('%' + q.replace(/[%_]/g, '') + '%')); }
    if (status && ['backlinks', 'tasks', 'campaigns', 'clients', 'submissions', 'outreach'].includes(entityName)) { where += ' AND c.status = ?'; params.push(status); }
    if (linkType && entityName === 'backlinks') { where += ' AND c.link_type = ?'; params.push(linkType); }
    if (clientId && cfg.scoped) { if (!A.canAccessClient(user, clientId)) return err(res, 403, 'You do not have access to that client.'); where += ' AND c.client_id = ?'; params.push(clientId); }
    if (assigneeId && entityName === 'tasks') { where += ' AND c.assignee_id = ?'; params.push(assigneeId); }
    if (entityName === 'tasks' && url.searchParams.get('mine') === 'true') { where += ' AND c.assignee_id = ?'; params.push(user.id); }
    const sortCol = cfg.sort.includes(url.searchParams.get('sort')) ? 'c.' + url.searchParams.get('sort') : 'c.created_at';
    const sortDir = url.searchParams.get('dir') === 'asc' ? 'ASC' : 'DESC';
    const select = entityName === 'domains' ? 'c.*, (SELECT COUNT(*) FROM backlinks b WHERE b.source_domain = c.domain AND b.archived_at IS NULL) AS backlink_count' : 'c.*';
    return listResponse(res, `${cfg.table} c`, where, params, sortCol, sortDir, paging(req, url), select);
  }
  if (!id && req.method === 'POST') {
    if (!A.canWrite(user)) return err(res, 403, 'Viewers have read-only access.');
    const b = await readBody(req);
    const vErr = validateEntity(entityName, b, true); if (vErr) return err(res, 400, vErr);
    if (cfg.scoped === true && b.client_id && !A.canAccessClient(user, b.client_id)) return err(res, 403, 'You do not have access to that client.');
    if (entityName === 'tasks') {
      if (!A.isAdminUp(user) && b.assignee_id && b.assignee_id !== user.id) return err(res, 403, 'Only the Owner or an Admin can assign tasks to other members.');
      if (b.client_id && !A.canAccessClient(user, b.client_id)) return err(res, 403, 'You do not have access to that client.');
    }
    const row = buildRow(entityName, b, user, null);
    insertRow(cfg.table, row);
    if (entityName === 'backlinks') backlinkEvent(row.id, user.id, 'created', { status: row.status });
    A.audit(user.id, 'create', entityName, row.id, null, row);
    return send(res, 201, { row });
  }
  if (!id) return err(res, 405, 'Method not allowed.');

  // Single-record routes
  const found = getScopedRow(user, entityName, id);
  if (action === 'events' && entityName === 'backlinks' && req.method === 'GET') {
    if (found.status === 403) return err(res, 403, 'You do not have access to that client.');
    const bid = found.row ? found.row.id : id;
    const arch = db.prepare('SELECT * FROM backlinks WHERE id = ?').get(id);
    if (!arch) return err(res, 404, 'Backlink not found.');
    if (!A.canAccessClient(user, arch.client_id)) return err(res, 403, 'You do not have access to that client.');
    return send(res, 200, { rows: db.prepare('SELECT * FROM backlink_events WHERE backlink_id = ? ORDER BY created_at').all(id) });
  }
  if (found.status === 403) return err(res, 403, 'You do not have access to that client.');
  if (req.method === 'GET') {
    if (found.status === 404) return err(res, 404, 'Record not found.');
    const row = { ...found.row };
    if (entityName === 'domains') row.backlink_count = db.prepare('SELECT COUNT(*) AS c FROM backlinks WHERE source_domain = ? AND archived_at IS NULL').get(row.domain).c;
    return send(res, 200, { row });
  }
  if (!A.canWrite(user) && req.method !== 'GET') return err(res, 403, 'Viewers have read-only access.');
  const anyRow = found.row || found.archived;
  if (!anyRow) return err(res, 404, 'Record not found.');
  if (action === 'archive' && req.method === 'POST') {
    db.prepare(`UPDATE ${cfg.table} SET archived_at = ?, updated_at = ? WHERE id = ?`).run(U.now(), U.now(), id);
    if (entityName === 'backlinks') backlinkEvent(id, user.id, 'archived', null);
    A.audit(user.id, 'archive', entityName, id, anyRow, null);
    return send(res, 200, { ok: true });
  }
  if (action === 'restore' && req.method === 'POST') {
    if (entityName !== 'clients' && anyRow.client_id && !A.canAccessClient(user, anyRow.client_id)) return err(res, 403, 'You do not have access to that client.');
    if (entityName === 'clients' && !A.isAdminUp(user)) {
      // restoring a client the member was assigned to is allowed only if assignment still exists
      if (!db.prepare('SELECT 1 AS ok FROM client_access WHERE user_id = ? AND client_id = ?').get(user.id, id)) return err(res, 403, 'You do not have access to that client.');
    }
    db.prepare(`UPDATE ${cfg.table} SET archived_at = NULL, updated_at = ? WHERE id = ?`).run(U.now(), id);
    if (entityName === 'backlinks') backlinkEvent(id, user.id, 'restored', null);
    A.audit(user.id, 'restore', entityName, id, null, anyRow);
    return send(res, 200, { ok: true });
  }
  if (action === 'purge' && req.method === 'POST') {
    if (!A.isOwner(user)) return err(res, 403, 'Permanent purge is Owner-only.');
    const b = await readBody(req);
    if (b.confirm !== 'DELETE') return err(res, 400, 'Type DELETE to confirm permanent purge.');
    if (!U.str(b.reason, 500)) return err(res, 400, 'A reason is required for permanent purge.');
    if (!anyRow.archived_at) return err(res, 400, 'Only archived records can be purged. Archive it first.');
    A.audit(user.id, 'purge', entityName, id, anyRow, null, U.str(b.reason, 500)); // audit first, by design
    if (entityName === 'backlinks') db.prepare('DELETE FROM backlink_events WHERE backlink_id = ?').run(id);
    db.prepare(`DELETE FROM ${cfg.table} WHERE id = ?`).run(id);
    return send(res, 200, { ok: true });
  }
  if (req.method === 'PATCH' && !action) {
    if (found.status === 404) return err(res, 404, 'Record not found.');
    const b = await readBody(req);
    const vErr = validateEntity(entityName, b, false); if (vErr) return err(res, 400, vErr);
    if (b.client_id && b.client_id !== found.row.client_id && !A.canAccessClient(user, b.client_id)) return err(res, 403, 'You do not have access to that client.');
    if (entityName === 'tasks' && !A.isAdminUp(user) && b.assignee_id && b.assignee_id !== found.row.assignee_id && b.assignee_id !== user.id) return err(res, 403, 'Only the Owner or an Admin can assign tasks to other members.');
    const row = buildRow(entityName, b, user, found.row);
    updateRow(cfg.table, row);
    if (entityName === 'backlinks') {
      if (b.status && b.status !== found.row.status) backlinkEvent(id, user.id, 'status_changed', { from: found.row.status, to: b.status });
      else backlinkEvent(id, user.id, 'edited', null);
    }
    A.audit(user.id, 'update', entityName, id, found.row, row);
    return send(res, 200, { row });
  }
  if (req.method === 'POST' && pathname.endsWith('/bulk-archive')) return err(res, 404, 'Not found.');
  return err(res, 405, 'Method not allowed.');
}
function checkOverdueTasksIfTasks(entityName) { if (entityName === 'tasks') checkOverdueTasks(); }

/* ================= SEARCH / VIEWS / BULK / TASKS EXTRAS / NOTIFICATIONS ================= */
function moduleRoutes1(req, res, url, pathname, ctx) {
  const db = getDb(); const user = ctx.user;
  if (pathname === '/api/search' && req.method === 'GET') {
    const q = (url.searchParams.get('q') || '').trim(); const type = url.searchParams.get('type') || '';
    const clientFilter = url.searchParams.get('clientId') || '';
    if (clientFilter && !A.canAccessClient(user, clientFilter)) return err(res, 403, 'You do not have access to that client.');
    if (!q) return send(res, 200, { results: [] });
    const like = '%' + q.replace(/[%_]/g, '') + '%'; const results = [];
    const ids = A.accessibleClientIds(user);
    const inIds = ids.length ? ids.map(() => '?').join(',') : "''";
    const cf = clientFilter ? ' AND client_id = ?' : '';
    const cfp = clientFilter ? [clientFilter] : [];
    const push = (rows, t, title, sub, cid) => rows.forEach((r) => results.push({ type: t, id: r.id, title: title(r), subtitle: sub(r), clientId: cid ? cid(r) : null }));
    if (!type || type === 'clients') push(db.prepare(`SELECT * FROM clients WHERE archived_at IS NULL AND id IN (${inIds}) AND (name LIKE ? OR website LIKE ?) ${clientFilter ? 'AND id = ?' : ''} LIMIT 20`).all(...(A.isAdminUp(user) ? db.prepare('SELECT id FROM clients WHERE archived_at IS NULL').all().map((r) => r.id) : ids), like, like, ...cfp), 'client', (r) => r.name, (r) => r.website, (r) => r.id);
    if (!type || type === 'backlinks') push(db.prepare(`SELECT * FROM backlinks WHERE archived_at IS NULL AND client_id IN (${inIds}) AND (source_url LIKE ? OR target_url LIKE ? OR anchor_text LIKE ?)${cf} LIMIT 20`).all(...ids, like, like, like, ...cfp), 'backlink', (r) => r.source_url, (r) => `${r.status} → ${r.target_url}`, (r) => r.client_id);
    if (!type || type === 'domains') push(db.prepare('SELECT * FROM domains WHERE archived_at IS NULL AND domain LIKE ? LIMIT 20').all(like), 'domain', (r) => r.domain, (r) => `DR: ${r.dr === null ? 'not available' : r.dr}`, null);
    if (!type || type === 'campaigns') push(db.prepare(`SELECT * FROM campaigns WHERE archived_at IS NULL AND client_id IN (${inIds}) AND name LIKE ?${cf} LIMIT 20`).all(...ids, like, ...cfp), 'campaign', (r) => r.name, (r) => r.status, (r) => r.client_id);
    if (!type || type === 'submissions') push(db.prepare(`SELECT * FROM submissions WHERE archived_at IS NULL AND client_id IN (${inIds}) AND site_url LIKE ?${cf} LIMIT 20`).all(...ids, like, ...cfp), 'submission', (r) => r.site_url, (r) => r.status, (r) => r.client_id);
    if (!type || type === 'outreach') push(db.prepare(`SELECT * FROM outreach WHERE archived_at IS NULL AND client_id IN (${inIds}) AND (name LIKE ? OR email LIKE ?)${cf} LIMIT 20`).all(...ids, like, like, ...cfp), 'outreach', (r) => r.name, (r) => r.email || '', (r) => r.client_id);
    if ((!type || type === 'users') && A.isAdminUp(user)) push(db.prepare('SELECT * FROM users WHERE archived_at IS NULL AND (name LIKE ? OR email LIKE ?) LIMIT 20').all(like, like), 'user', (r) => r.name, (r) => `${r.email} (${r.role})`, null);
    return send(res, 200, { results });
  }
  const bulk = pathname.match(/^\/api\/(clients|domains|campaigns|backlinks|submissions|outreach|tasks)\/bulk-archive$/);
  if (bulk && req.method === 'POST') {
    return (async () => {
      if (!A.canWrite(user)) return err(res, 403, 'Viewers have read-only access.');
      const b = await readBody(req);
      const idsIn = Array.isArray(b.ids) ? b.ids.slice(0, 500) : [];
      let archived = 0;
      for (const id of idsIn) {
        const f = getScopedRow(user, bulk[1], id);
        if (f.row) { db.prepare(`UPDATE ${ENTITY[bulk[1]].table} SET archived_at = ?, updated_at = ? WHERE id = ?`).run(U.now(), U.now(), id); if (bulk[1] === 'backlinks') backlinkEvent(id, user.id, 'archived', { bulk: true }); archived++; }
      }
      A.audit(user.id, 'bulk_archive', bulk[1], null, null, { count: archived });
      return send(res, 200, { archived });
    })();
  }
  if (pathname === '/api/views' && req.method === 'GET') {
    const rows = db.prepare('SELECT * FROM saved_views WHERE user_id = ? OR shared = 1 ORDER BY created_at DESC').all(user.id);
    return send(res, 200, { rows: rows.map((r) => ({ ...r, filters: JSON.parse(r.filters_json), shared: !!r.shared })) });
  }
  if (pathname === '/api/views' && req.method === 'POST') {
    return (async () => {
      const b = await readBody(req);
      if (!U.str(b.name, 120) || !ENTITY[b.entity]) return err(res, 400, 'A view name and a valid entity are required.');
      if (b.shared && !A.isOwner(user)) return err(res, 403, 'Only the Owner can create shared team views.');
      const id = U.uid();
      db.prepare('INSERT INTO saved_views (id, user_id, shared, name, entity, filters_json, created_at) VALUES (?,?,?,?,?,?,?)').run(id, user.id, b.shared ? 1 : 0, U.str(b.name, 120), b.entity, JSON.stringify(b.filters || {}), U.now());
      return send(res, 201, { id });
    })();
  }
  const vm = pathname.match(/^\/api\/views\/([^/]+)$/);
  if (vm && req.method === 'DELETE') {
    const v = db.prepare('SELECT * FROM saved_views WHERE id = ?').get(vm[1]);
    if (!v) return err(res, 404, 'View not found.');
    if (v.user_id !== user.id && !A.isOwner(user)) return err(res, 403, 'You can only delete your own views.');
    db.prepare('DELETE FROM saved_views WHERE id = ?').run(vm[1]);
    return send(res, 200, { ok: true });
  }
  if (pathname === '/api/tasks/workload' && req.method === 'GET') {
    checkOverdueTasks();
    const rows = db.prepare('SELECT id, name FROM users WHERE archived_at IS NULL').all().map((u) => {
      const c = (sql, ...p) => db.prepare(sql).get(...p).c;
      return { userId: u.id, name: u.name, open: c("SELECT COUNT(*) AS c FROM tasks WHERE assignee_id = ? AND archived_at IS NULL AND status != 'done'", u.id), overdue: c("SELECT COUNT(*) AS c FROM tasks WHERE assignee_id = ? AND archived_at IS NULL AND status != 'done' AND deadline < date('now')", u.id), done: c("SELECT COUNT(*) AS c FROM tasks WHERE assignee_id = ? AND archived_at IS NULL AND status = 'done'", u.id) };
    });
    // Members only see their own workload row; Owner/Admin see the team.
    return send(res, 200, { rows: A.isAdminUp(user) ? rows : rows.filter((r) => r.userId === user.id), completion: { done: db.prepare("SELECT COUNT(*) AS c FROM tasks WHERE status = 'done' AND archived_at IS NULL").get().c, total: db.prepare('SELECT COUNT(*) AS c FROM tasks WHERE archived_at IS NULL').get().c } });
  }
  if (pathname === '/api/notifications' && req.method === 'GET') {
    checkOverdueTasks();
    return send(res, 200, { rows: db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(user.id) });
  }
  const nm = pathname.match(/^\/api\/notifications\/([^/]+)\/read$/);
  if (nm && req.method === 'POST') { db.prepare('UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ?').run(U.now(), nm[1], user.id); return send(res, 200, { ok: true }); }
  return false;
}

/* ================= SECURITY ================= */
async function securityRoutes(req, res, url, pathname, ctx) {
  const db = getDb(); const user = ctx.user;
  if (pathname === '/api/security/sessions' && req.method === 'GET') {
    const targetId = url.searchParams.get('userId');
    if (targetId && targetId !== user.id && !A.isOwner(user)) return err(res, 403, 'Only the Owner can view other users\' sessions.');
    const rows = db.prepare('SELECT s.id, s.user_id, u.name, u.email, s.ip, s.user_agent, s.created_at, s.last_seen, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.user_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? ORDER BY s.last_seen DESC').all(targetId || user.id, U.now());
    return send(res, 200, { rows, currentSessionId: ctx.session.id });
  }
  const rm = pathname.match(/^\/api\/security\/sessions\/([^/]+)\/revoke$/);
  if (rm && req.method === 'POST') {
    const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(rm[1]);
    if (!s) return err(res, 404, 'Session not found.');
    if (s.user_id !== user.id && !A.isOwner(user)) return err(res, 403, 'You can only revoke your own sessions.');
    db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(U.now(), rm[1]);
    A.securityEvent(user.id, user.email, 'session_revoked', clientIp(req), `session of user ${s.user_id}`);
    A.audit(user.id, 'revoke_session', 'user', s.user_id, null, { sessionId: rm[1] });
    return send(res, 200, { ok: true });
  }
  if (pathname === '/api/security/events' && req.method === 'GET') {
    const rows = A.isOwner(user)
      ? db.prepare('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 100').all()
      : db.prepare('SELECT * FROM security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(user.id);
    return send(res, 200, { rows });
  }
  if (pathname === '/api/security/2fa/setup' && req.method === 'POST') {
    const secret = A.newTotpSecret();
    db.prepare('UPDATE users SET twofa_secret = ? WHERE id = ?').run(secret, user.id);
    return send(res, 200, { secret, otpauth: `otpauth://totp/${encodeURIComponent(getSetting('workspace_name'))}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=${encodeURIComponent(getSetting('workspace_name'))}`, note: 'Add the secret to an authenticator app, then confirm with a current 6-digit code.' });
  }
  if (pathname === '/api/security/2fa/enable' && req.method === 'POST') {
    const b = await readBody(req);
    const fresh = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    if (!fresh.twofa_secret) return err(res, 400, 'Run 2FA setup first.');
    if (!A.totpVerify(fresh.twofa_secret, b.code)) return err(res, 400, 'Invalid code. Check your authenticator app and try again.');
    db.prepare('UPDATE users SET twofa_enabled = 1 WHERE id = ?').run(user.id);
    A.securityEvent(user.id, user.email, '2fa_enabled', clientIp(req), null);
    A.audit(user.id, '2fa_enable', 'user', user.id, null, null);
    return send(res, 200, { ok: true });
  }
  if (pathname === '/api/security/2fa/disable' && req.method === 'POST') {
    const b = await readBody(req);
    if (getSetting('require_2fa') === 'true' && !A.isOwner(user)) return err(res, 403, 'The Owner requires 2FA for all users, so it cannot be disabled.');
    const fresh = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    if (fresh.twofa_enabled && !A.totpVerify(fresh.twofa_secret, b.code)) return err(res, 400, 'A valid 2FA code is required to disable 2FA.');
    db.prepare('UPDATE users SET twofa_enabled = 0, twofa_secret = NULL WHERE id = ?').run(user.id);
    A.securityEvent(user.id, user.email, '2fa_disabled', clientIp(req), null);
    return send(res, 200, { ok: true });
  }
  return false;
}

/* ================= OWNER CENTER / BUDGETS / BACKUPS / AUDIT / TOKENS ================= */
async function ownerRoutes(req, res, url, pathname, ctx) {
  const db = getDb(); const user = ctx.user;
  if (pathname === '/api/settings' && req.method === 'GET') return send(res, 200, { workspaceName: getSetting('workspace_name'), timezone: getSetting('timezone'), defaultLinkType: getSetting('default_link_type') });
  if (pathname === '/api/owner/settings' && req.method === 'GET') {
    if (!A.isOwner(user)) return err(res, 403, 'The Owner Control Center is Owner-only.');
    return send(res, 200, { settings: allSettings() });
  }
  if (pathname === '/api/owner/settings' && req.method === 'PUT') {
    if (!A.isOwner(user)) return err(res, 403, 'The Owner Control Center is Owner-only.');
    const b = await readBody(req); const allowed = Object.keys(allSettings()); const before = allSettings();
    for (const [k, v] of Object.entries(b.settings || {})) {
      if (!allowed.includes(k)) return err(res, 400, `Unknown setting: ${k}`);
      if (k === 'workspace_name' && (!U.str(String(v), 80))) return err(res, 400, 'Workspace name is required (max 80 characters).');
      if (k === 'session_lifetime_hours' && (!(parseInt(v, 10) >= 1 && parseInt(v, 10) <= 168))) return err(res, 400, 'Session lifetime must be 1–168 hours.');
      if (k === 'backup_retention_days' && (!(parseInt(v, 10) >= 1 && parseInt(v, 10) <= 365))) return err(res, 400, 'Backup retention must be 1–365 days.');
      if (k === 'backup_schedule' && !['off', 'daily', 'weekly'].includes(String(v))) return err(res, 400, 'Backup schedule must be off, daily, or weekly.');
      if (['require_2fa', 'suspicious_login_alerts', 'notify_overdue_tasks'].includes(k) && !['true', 'false'].includes(String(v))) return err(res, 400, `${k} must be true or false.`);
      setSetting(k, v);
    }
    A.audit(user.id, 'update', 'settings', null, before, allSettings());
    return send(res, 200, { settings: allSettings() });
  }
  if (pathname === '/api/owner/monitoring' && req.method === 'GET') {
    if (!A.isOwner(user)) return err(res, 403, 'System Monitoring is Owner-only.');
    const c = (sql, ...p) => db.prepare(sql).get(...p).c;
    return send(res, 200, {
      counts: { users: c('SELECT COUNT(*) AS c FROM users WHERE archived_at IS NULL'), clients: c('SELECT COUNT(*) AS c FROM clients WHERE archived_at IS NULL'), backlinks: c('SELECT COUNT(*) AS c FROM backlinks WHERE archived_at IS NULL'), domains: c('SELECT COUNT(*) AS c FROM domains WHERE archived_at IS NULL'), campaigns: c('SELECT COUNT(*) AS c FROM campaigns WHERE archived_at IS NULL'), submissions: c('SELECT COUNT(*) AS c FROM submissions WHERE archived_at IS NULL'), outreach: c('SELECT COUNT(*) AS c FROM outreach WHERE archived_at IS NULL'), tasksOpen: c("SELECT COUNT(*) AS c FROM tasks WHERE archived_at IS NULL AND status != 'done'") },
      lastBackup: db.prepare('SELECT * FROM backups ORDER BY created_at DESC LIMIT 1').get() || null,
      failedImports: db.prepare("SELECT COUNT(*) AS c FROM import_jobs WHERE failed_json != '[]'").get().c,
      importJobs: db.prepare('SELECT id, kind, status, total_rows, processed_rows, created_at FROM import_jobs ORDER BY created_at DESC LIMIT 10').all(),
      recentSecurityEvents: db.prepare('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 10').all(),
      apiUsage: db.prepare('SELECT * FROM api_usage WHERE month = ?').all(monthKey()),
    });
  }
  if (pathname === '/api/api-budgets' && req.method === 'GET') {
    if (!A.isAdminUp(user)) return err(res, 403, 'API budgets are visible to the Owner and Admins only.');
    const rows = db.prepare('SELECT * FROM api_budgets WHERE archived_at IS NULL ORDER BY provider').all().map((b) => { const used = usageFor(b.provider); return { ...b, usedThisMonth: used, estimatedCost: b.per_request_price === null ? 'not available' : Number((used * b.per_request_price).toFixed(2)) }; });
    return send(res, 200, { rows });
  }
  if (pathname === '/api/api-budgets' && req.method === 'POST') {
    if (!A.isOwner(user)) return err(res, 403, 'Only the Owner can define API budgets.');
    const b = await readBody(req);
    if (!U.str(b.provider, 80) || !(parseInt(b.monthly_limit, 10) > 0)) return err(res, 400, 'Provider and a positive monthly limit are required.');
    const id = U.uid();
    try { db.prepare('INSERT INTO api_budgets (id, provider, monthly_limit, alert_pct, per_request_price, pause_at_limit, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)').run(id, U.str(b.provider, 80), parseInt(b.monthly_limit, 10), Math.min(100, Math.max(1, parseInt(b.alert_pct, 10) || 80)), (b.per_request_price === '' || b.per_request_price === undefined || b.per_request_price === null) ? null : Number(b.per_request_price), b.pause_at_limit ? 1 : 0, U.now(), U.now()); }
    catch { return err(res, 409, 'A budget for this provider already exists.'); }
    A.audit(user.id, 'create', 'api_budget', id, null, b);
    return send(res, 201, { id });
  }
  const bm = pathname.match(/^\/api\/api-budgets\/([^/]+)\/archive$/);
  if (bm && req.method === 'POST') {
    if (!A.isOwner(user)) return err(res, 403, 'Only the Owner can archive API budgets.');
    db.prepare('UPDATE api_budgets SET archived_at = ? WHERE id = ?').run(U.now(), bm[1]);
    return send(res, 200, { ok: true });
  }
  if (pathname === '/api/backups' && req.method === 'GET') {
    if (!A.isOwner(user)) return err(res, 403, 'Backup & Recovery is Owner-only.');
    maybeAutoBackup();
    return send(res, 200, { rows: db.prepare('SELECT * FROM backups ORDER BY created_at DESC').all(), retentionDays: getSetting('backup_retention_days'), schedule: getSetting('backup_schedule'), retentionRule: `Backups older than ${getSetting('backup_retention_days')} days are removed automatically when a new backup is created. Schedule: ${getSetting('backup_schedule')}.` });
  }
  if (pathname === '/api/backups' && req.method === 'POST') {
    if (!A.isOwner(user)) return err(res, 403, 'Backup & Recovery is Owner-only.');
    const row = createBackup(user.id, 'manual');
    A.audit(user.id, 'backup_create', 'backup', row.id, null, { filename: row.filename, size: row.size });
    return send(res, 201, { backup: row });
  }
  const br = pathname.match(/^\/api\/backups\/([^/]+)\/(restore|test-restore)$/);
  if (br && req.method === 'POST') {
    if (!A.isOwner(user)) return err(res, 403, 'Backup & Recovery is Owner-only.');
    const bk = db.prepare('SELECT * FROM backups WHERE id = ?').get(br[1]);
    if (!bk) return err(res, 404, 'Backup not found.');
    const file = path.join(BACKUP_DIR, bk.filename);
    if (!fs.existsSync(file)) return err(res, 404, 'Backup file is missing from disk.');
    if (br[2] === 'test-restore') {
      let result;
      if (fileChecksum(file) !== bk.checksum) result = 'FAILED: checksum mismatch';
      else {
        try { const { DatabaseSync } = require('node:sqlite'); const t = new DatabaseSync(file, { readOnly: true }); const cnt = t.prepare('SELECT COUNT(*) AS c FROM users').get().c; t.close(); result = `OK: checksum verified and test database opened (${cnt} users readable)`; }
        catch (e) { result = 'FAILED: ' + e.message; }
      }
      db.prepare('UPDATE backups SET restore_test_at = ?, restore_test_result = ? WHERE id = ?').run(U.now(), result, bk.id);
      A.audit(user.id, 'backup_restore_test', 'backup', bk.id, null, { result });
      return send(res, 200, { result });
    }
    const b = await readBody(req);
    if (b.confirm !== 'RESTORE') return err(res, 400, 'Type RESTORE to confirm recovery.');
    if (fileChecksum(file) !== bk.checksum) return err(res, 400, 'Backup checksum mismatch. Restore stopped.');
    A.audit(user.id, 'backup_restore', 'backup', bk.id, null, { filename: bk.filename });
    const { closeDb } = require('./db');
    closeDb();
    fs.copyFileSync(file, DB_PATH);
    try { fs.unlinkSync(DB_PATH + '-wal'); } catch {}
    try { fs.unlinkSync(DB_PATH + '-shm'); } catch {}
    reopenDb(); require('./db').migrate();
    return send(res, 200, { ok: true, note: 'Database restored. You may need to sign in again.' });
  }
  if (pathname === '/api/audit' && req.method === 'GET') {
    if (!A.isAdminUp(user)) return err(res, 403, 'The audit record is visible to the Owner and Admins only.');
    return send(res, 200, { rows: db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200').all() });
  }
  if (pathname === '/api/tokens' && req.method === 'POST') {
    const b = await readBody(req);
    if (!U.str(b.name, 80)) return err(res, 400, 'A token name is required.');
    const raw = 'bls_' + crypto.randomBytes(24).toString('hex');
    const id = U.uid();
    db.prepare('INSERT INTO api_tokens (id, user_id, name, token_hash, scopes, created_at) VALUES (?,?,?,?,?,?)').run(id, user.id, U.str(b.name, 80), U.sha256(raw), U.str(b.scopes || 'read', 200), U.now());
    return send(res, 201, { id, token: raw, note: 'Store this token now — only its hash is kept, so it cannot be shown again. Reserved for future Browser Extension / API access.' });
  }
  if (pathname === '/api/tokens' && req.method === 'GET') return send(res, 200, { rows: db.prepare('SELECT id, name, scopes, created_at, revoked_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC').all(user.id) });
  const tm = pathname.match(/^\/api\/tokens\/([^/]+)$/);
  if (tm && req.method === 'DELETE') { db.prepare('UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ?').run(U.now(), tm[1], user.id); return send(res, 200, { ok: true }); }
  return false;
}

/* ================= IMPORT / EXPORT + LINKS-ONLY DETECTION ================= */
const EXPORTS = {
  backlinks: { cols: ['id', 'source_url', 'source_domain', 'target_url', 'anchor_text', 'link_type', 'status', 'dr', 'placement', 'client_id', 'created_at'], table: 'backlinks', scoped: true },
  clients: { cols: ['id', 'name', 'website', 'contact_name', 'contact_email', 'status', 'created_at'], table: 'clients', scoped: false },
  tasks: { cols: ['id', 'title', 'status', 'priority', 'deadline', 'assignee_id', 'client_id', 'created_at'], table: 'tasks', scoped: 'task' },
  submissions: { cols: ['id', 'site_url', 'type', 'status', 'client_id', 'submitted_date'], table: 'submissions', scoped: true },
  campaigns: { cols: ['id', 'name', 'status', 'client_id', 'start_date', 'end_date'], table: 'campaigns', scoped: true },
  outreach: { cols: ['id', 'name', 'email', 'website', 'domain', 'status', 'client_id'], table: 'outreach', scoped: true },
};
async function importExportRoutes(req, res, url, pathname, ctx) {
  const db = getDb(); const user = ctx.user;
  const em = pathname.match(/^\/api\/export\/(backlinks|clients|tasks|submissions|campaigns|outreach)$/);
  if (em && req.method === 'GET') {
    const cfg = EXPORTS[em[1]]; const format = U.oneOf(url.searchParams.get('format'), ['csv', 'xlsx', 'pdf'], 'csv');
    const clientId = url.searchParams.get('clientId') || ''; const memberId = url.searchParams.get('memberId') || '';
    let where = 'archived_at IS NULL'; const params = [];
    if (cfg.scoped === true) {
      if (clientId) { if (!A.canAccessClient(user, clientId)) return err(res, 403, 'You do not have access to that client.'); where += ' AND client_id = ?'; params.push(clientId); }
      else { const ids = A.accessibleClientIds(user); if (!ids.length) return send(res, 200, format === 'csv' ? cfg.cols.join(',') + '\n' : '', { 'Content-Type': 'text/csv' }); where += ` AND client_id IN (${ids.map(() => '?').join(',')})`; params.push(...ids); }
    }
    if (em[1] === 'clients' && !A.isAdminUp(user)) { const ids = A.accessibleClientIds(user); if (!ids.length) return send(res, 200, cfg.cols.join(',') + '\n', { 'Content-Type': 'text/csv' }); where += ` AND id IN (${ids.map(() => '?').join(',')})`; params.push(...ids); if (clientId) { if (!A.canAccessClient(user, clientId)) return err(res, 403, 'You do not have access to that client.'); } }
    if (memberId) { const col = em[1] === 'tasks' ? 'assignee_id' : 'created_by'; if (cfg.table !== 'clients' && cfg.table !== 'outreach') { where += ` AND ${col} = ?`; params.push(memberId); } }
    const rows = db.prepare(`SELECT ${cfg.cols.join(',')} FROM ${cfg.table} WHERE ${where} ORDER BY created_at DESC LIMIT 10000`).all(...params)
      .map((r) => { const o = {}; for (const c of cfg.cols) o[c] = c === 'dr' && r[c] === null ? 'not available' : r[c]; return o; });
    const filename = `${em[1]}-export.${format}`;
    if (format === 'csv') return send(res, 200, U.toCsv(cfg.cols, rows), { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="${filename}"` });
    if (format === 'xlsx') return send(res, 200, U.toXlsx(em[1], cfg.cols, rows), { 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Content-Disposition': `attachment; filename="${filename}"` });
    const lines = rows.map((r) => cfg.cols.map((c) => `${c}: ${r[c] == null ? '' : r[c]}`).join(' | '));
    return send(res, 200, U.toPdf(`${getSetting('workspace_name')} — ${em[1]} report`, lines), { 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="${filename}"` });
  }

  /* ---- Full CSV import: preview (writes nothing) -> confirm (resumable) ---- */
  if (pathname === '/api/import/preview' && req.method === 'POST') {
    if (!A.canWrite(user)) return err(res, 403, 'Viewers have read-only access.');
    const b = await readBody(req);
    const kind = U.oneOf(b.kind, ['backlinks', 'clients'], 'backlinks');
    if (kind === 'backlinks' && !b.clientId) return err(res, 400, 'Select the client these backlinks belong to.');
    if (b.clientId && !A.canAccessClient(user, b.clientId)) return err(res, 403, 'You do not have access to that client.');
    const parsed = U.parseCsv(String(b.csvText || ''));
    if (parsed.length < 2) return err(res, 400, 'The CSV needs a header row and at least one data row.');
    const maxRows = Math.max(1, parseInt(getSetting('import_max_rows'), 10) || 1000);
    if (parsed.length - 1 > maxRows) return err(res, 400, `Too many rows: the import limit is ${maxRows} rows per file (Owner setting).`);
    const headers = parsed[0].map((h) => h.trim().toLowerCase().replace(/\s+/g, '_'));
    const rows = [], failed = [];
    parsed.slice(1).forEach((cells, i) => {
      const obj = {}; headers.forEach((h, j) => { obj[h] = (cells[j] || '').trim(); });
      const rowNo = i + 2; let error = null; let data = null;
      if (kind === 'backlinks') {
        if (!U.isUrl(obj.source_url || '')) error = 'Invalid or missing source_url';
        else if (!U.isUrl(obj.target_url || '')) error = 'Invalid or missing target_url';
        else if (obj.link_type && !['dofollow', 'nofollow', 'sponsored', 'ugc'].includes(obj.link_type)) error = 'Invalid link_type';
        else if (obj.status && !['live', 'lost', 'pending', 'rejected'].includes(obj.status)) error = 'Invalid status';
        else data = { client_id: b.clientId, source_url: obj.source_url, target_url: obj.target_url, anchor_text: obj.anchor_text || null, link_type: obj.link_type || 'dofollow', status: obj.status || 'pending', dr: obj.dr ? Number(obj.dr) : null, placement: obj.placement || null, notes: obj.notes || null };
      } else {
        if (!obj.name) error = 'Missing client name';
        else if (!U.isUrl(obj.website || '')) error = 'Invalid or missing website URL';
        else data = { name: obj.name, website: obj.website, contact_name: obj.contact_name || null, contact_email: obj.contact_email || null, status: obj.status || 'active', notes: obj.notes || null };
      }
      if (error) { failed.push({ row: rowNo, error, raw: cells.join(',') }); rows.push({ valid: false, error, rowNo }); }
      else rows.push({ valid: true, data, rowNo });
    });
    const id = U.uid();
    db.prepare('INSERT INTO import_jobs (id, user_id, kind, client_id, total_rows, processed_rows, status, rows_json, failed_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, user.id, kind, b.clientId || null, rows.length, 0, 'preview', JSON.stringify(rows), JSON.stringify(failed), U.now(), U.now());
    return send(res, 201, { jobId: id, total: rows.length, valid: rows.filter((r) => r.valid).length, failed, preview: rows.slice(0, 100) });
  }
  const im = pathname.match(/^\/api\/import\/([^/]+)\/(confirm|failed\.csv)$/);
  if (im) {
    const job = db.prepare('SELECT * FROM import_jobs WHERE id = ?').get(im[1]);
    if (!job) return err(res, 404, 'Import job not found.');
    if (job.user_id !== user.id && !A.isAdminUp(user)) return err(res, 403, 'This import belongs to another user.');
    if (im[2] === 'failed.csv' && req.method === 'GET') {
      const failed = JSON.parse(job.failed_json);
      return send(res, 200, 'row,error,raw\n' + failed.map((f) => `${f.row},"${String(f.error).replace(/"/g, '""')}","${String(f.raw).replace(/"/g, '""')}"`).join('\n') + '\n', { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="import-${job.id}-failed.csv"` });
    }
    if (im[2] === 'confirm' && req.method === 'POST') {
      if (!A.canWrite(user)) return err(res, 403, 'Viewers have read-only access.');
      const b = await readBody(req).catch(() => ({}));
      if (job.status === 'complete') return send(res, 200, { ok: true, alreadyComplete: true, imported: job.processed_rows });
      const rows = JSON.parse(job.rows_json);
      const chunk = Math.max(1, parseInt(b.chunk, 10) || rows.length);
      let idx = job.processed_rows; let importedNow = 0;
      const end = Math.min(rows.length, idx + chunk);
      for (; idx < end; idx++) {
        const r = rows[idx];
        if (r.valid) {
          if (job.kind === 'backlinks' || job.kind === 'links-only') { const row = buildRow('backlinks', r.data, user, null); if (job.kind === 'links-only') row.source = 'detection'; insertRow('backlinks', row); backlinkEvent(row.id, user.id, 'created', { via: job.kind }); }
          else { const row = buildRow('clients', r.data, user, null); insertRow('clients', row); }
          importedNow++;
        }
      }
      const status = idx >= rows.length ? 'complete' : 'partial';
      db.prepare('UPDATE import_jobs SET processed_rows = ?, status = ?, updated_at = ? WHERE id = ?').run(idx, status, U.now(), job.id);
      A.audit(user.id, 'import_confirm', 'import_job', job.id, null, { status, processed: idx, importedNow });
      return send(res, 200, { ok: true, status, processed: idx, total: rows.length, importedNow });
    }
  }

  /* ---- Links-Only Import with real page detection ---- */
  if (pathname === '/api/import/links-only/preview' && req.method === 'POST') {
    if (!A.canWrite(user)) return err(res, 403, 'Viewers have read-only access.');
    const b = await readBody(req);
    if (!b.clientId) return err(res, 400, 'Select the client whose website these backlinks point to.');
    if (!A.canAccessClient(user, b.clientId)) return err(res, 403, 'You do not have access to that client.');
    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(b.clientId);
    const clientDomain = U.hostnameOf(client.website);
    let urls = [];
    if (Array.isArray(b.urls)) urls = b.urls;
    else urls = String(b.urlsText || '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean).map((line) => { const parsed = U.parseCsv(line); return parsed.length && parsed[0].length ? String(parsed[0][0]).trim() : line; });
    if (!urls.length) return err(res, 400, 'Provide at least one backlink page URL.');
    if (urls.length > 50) return err(res, 400, 'Maximum 50 URLs per detection run.');
    urls = [...new Set(urls)];
    const budgetErr = checkBudget('page-fetch', urls.length);
    if (budgetErr) return err(res, 429, budgetErr);
    const rows = [], failed = [];
    for (const pageUrl of urls) {
      if (!U.isUrl(pageUrl)) { failed.push({ row: pageUrl, error: 'Invalid URL' }); rows.push({ valid: false, source_url: pageUrl, error: 'Invalid URL' }); continue; }
      let html = '', fetchStatus = 0, fetchError = null;
      try {
        const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), 8000);
        const resp = await fetch(pageUrl, { signal: ctrl.signal, redirect: 'follow', headers: { 'User-Agent': 'BacklinkSaaS-LinkCheck/1.0' } });
        clearTimeout(timer); fetchStatus = resp.status;
        html = (await resp.text()).slice(0, 1024 * 1024);
        if (!resp.ok) fetchError = `Page returned HTTP ${fetchStatus}`;
      } catch (e) { fetchError = 'Page could not be fetched: ' + (e.name === 'AbortError' ? 'timed out after 8 seconds' : e.message); }
      if (fetchError) { failed.push({ row: pageUrl, error: fetchError }); rows.push({ valid: false, source_url: pageUrl, error: fetchError, status: 'lost' }); continue; }
      // Find outbound links on the fetched page.
      let found = null;
      const anchorRe = /<a\s([^>]*)>([\s\S]*?)<\/a>/gi; let match;
      while ((match = anchorRe.exec(html)) !== null) {
        const attrs = match[1];
        const hrefM = attrs.match(/href\s*=\s*["']([^"']+)["']/i) || attrs.match(/href\s*=\s*([^\s>]+)/i);
        if (!hrefM) continue;
        let resolved; try { resolved = new URL(hrefM[1], pageUrl).toString(); } catch { continue; }
        const host = U.hostnameOf(resolved);
        if (host === clientDomain || host.endsWith('.' + clientDomain)) {
          const relM = attrs.match(/rel\s*=\s*["']([^"']*)["']/i);
          const rel = relM ? relM[1].toLowerCase().split(/\s+/) : [];
          const linkType = rel.includes('sponsored') ? 'sponsored' : rel.includes('ugc') ? 'ugc' : rel.includes('nofollow') ? 'nofollow' : 'dofollow';
          const anchor = match[2].replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500);
          found = { target_url: resolved, anchor_text: anchor || null, link_type: linkType };
          break;
        }
      }
      if (!found) { failed.push({ row: pageUrl, error: 'target link not found' }); rows.push({ valid: false, source_url: pageUrl, error: 'target link not found', status: 'live' }); continue; }
      rows.push({ valid: true, source_url: pageUrl, source_domain: U.hostnameOf(pageUrl), dr_display: 'not available', data: { client_id: b.clientId, source_url: pageUrl, target_url: found.target_url, anchor_text: found.anchor_text, link_type: found.link_type, status: 'live', dr: null } });
    }
    recordUsage('page-fetch', urls.length);
    const id = U.uid();
    db.prepare('INSERT INTO import_jobs (id, user_id, kind, client_id, total_rows, processed_rows, status, rows_json, failed_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, user.id, 'links-only', b.clientId, rows.length, 0, 'preview', JSON.stringify(rows), JSON.stringify(failed), U.now(), U.now());
    return send(res, 201, { jobId: id, clientDomain, total: rows.length, valid: rows.filter((r) => r.valid).length, failed, preview: rows });
  }
  return false;
}

/* ================= MAIN HANDLER ================= */
async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;
  try {
    if (pathname === '/api/health') return send(res, 200, { ok: true });
    if (pathname.startsWith('/api/auth/') && pathname !== '/api/auth/me') { const r = await authRoutes(req, res, url, pathname); if (r !== false) return; return err(res, 404, 'Not found.'); }
    if (!pathname.startsWith('/api/')) return false; // static handled by server.js
    const ctx = requireAuth(req, res, pathname);
    if (!ctx) return;
    for (const fn of [userRoutes, moduleRoutes1, entityRoutes, securityRoutes, ownerRoutes, importExportRoutes]) {
      const r = await fn(req, res, url, pathname, ctx);
      if (r !== false && r !== undefined) return;
      // handlers return the send() result (res object) or false; treat non-false as handled
      if (r !== false) return;
    }
    return err(res, 404, 'Not found.');
  } catch (e) {
    console.error('[error]', req.method, pathname, e.message);
    if (!res.headersSent) return err(res, 500, 'Something went wrong on the server. The error has been logged.');
  }
}

module.exports = { handle, createBackup, maybeAutoBackup, checkOverdueTasks, _internals: { checkBudget, usageFor } };
