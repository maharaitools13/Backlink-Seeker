'use strict';
/* Authentication, sessions, TOTP 2FA, authorization and client scoping.
   Every authorization decision lives here and is enforced server-side. */
const crypto = require('crypto');
const { getDb, getSetting } = require('./db');
const { now, uid, sha256 } = require('./utils');

/* ---------- Passwords (scrypt, per-user salt, timing-safe compare) ---------- */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, user) {
  const h = crypto.scryptSync(String(password), user.pass_salt, 64);
  const stored = Buffer.from(user.pass_hash, 'hex');
  return h.length === stored.length && crypto.timingSafeEqual(h, stored);
}

/* ---------- TOTP (RFC 6238, HMAC-SHA1, 30s step, base32 secrets) ---------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, val = 0, out = '';
  for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function base32Decode(s) {
  const clean = String(s).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, val = 0; const out = [];
  for (const c of clean) { val = (val << 5) | B32.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function totpCode(secretB32, counter) {
  const msg = Buffer.alloc(8); msg.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', base32Decode(secretB32)).update(msg).digest();
  const o = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[o] & 0x7f) << 24) | (hmac[o + 1] << 16) | (hmac[o + 2] << 8) | hmac[o + 3];
  return String(code % 1000000).padStart(6, '0');
}
function totpNow(secretB32) { return totpCode(secretB32, Math.floor(Date.now() / 30000)); }
function totpVerify(secretB32, code) {
  const counter = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some((w) => totpCode(secretB32, counter + w) === String(code || '').padStart(6, '0'));
}
function newTotpSecret() { return base32Encode(crypto.randomBytes(20)); }

/* ---------- Audit / security events / notifications (append-only) ---------- */
function audit(actorId, action, entity, entityId, before, after, reason) {
  getDb().prepare('INSERT INTO audit_log (id, actor_id, action, entity, entity_id, before_json, after_json, reason, created_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(uid(), actorId || null, action, entity, entityId || null, before ? JSON.stringify(before) : null, after ? JSON.stringify(after) : null, reason || null, now());
}
function securityEvent(userId, email, type, ip, detail) {
  getDb().prepare('INSERT INTO security_events (id, user_id, email, type, ip, detail, created_at) VALUES (?,?,?,?,?,?,?)')
    .run(uid(), userId || null, email || null, type, ip || null, detail || null, now());
}
function notify(userId, type, refType, refId, message, dedupeKey) {
  if (!userId) return;
  try {
    getDb().prepare('INSERT INTO notifications (id, user_id, type, ref_type, ref_id, message, dedupe_key, created_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(uid(), userId, type, refType, refId, message, dedupeKey || null, now());
  } catch { /* duplicate dedupe_key: one notification per key, by design */ }
}

/* ---------- Sessions ---------- */
function createSession(userId, ip, ua) {
  const token = crypto.randomBytes(32).toString('hex');
  const hours = Math.max(1, parseInt(getSetting('session_lifetime_hours'), 10) || 24);
  const expires = new Date(Date.now() + hours * 3600e3).toISOString();
  getDb().prepare('INSERT INTO sessions (id, token_hash, user_id, ip, user_agent, created_at, last_seen, expires_at) VALUES (?,?,?,?,?,?,?,?)')
    .run(uid(), sha256(token), userId, ip || null, String(ua || '').slice(0, 300), now(), now(), expires);
  return token;
}
function userFromToken(token) {
  if (!token) return null;
  const s = getDb().prepare('SELECT * FROM sessions WHERE token_hash = ? AND revoked_at IS NULL').get(sha256(token));
  if (!s || s.expires_at < now()) return null;
  getDb().prepare('UPDATE sessions SET last_seen = ? WHERE id = ?').run(now(), s.id);
  const user = getDb().prepare('SELECT * FROM users WHERE id = ? AND archived_at IS NULL').get(s.user_id);
  if (!user || user.status !== 'active') return null;
  return { user, session: s };
}

/* ---------- Roles & client scoping ---------- */
const isOwner = (u) => u.role === 'Owner';
const isAdminUp = (u) => u.role === 'Owner' || u.role === 'Admin';
const canWrite = (u) => u.role !== 'Viewer'; // Viewer is read-only everywhere

function accessibleClientIds(user) {
  if (isAdminUp(user)) {
    return getDb().prepare('SELECT id FROM clients WHERE archived_at IS NULL').all().map((r) => r.id);
  }
  return getDb().prepare('SELECT client_id FROM client_access WHERE user_id = ?').all(user.id).map((r) => r.client_id);
}
function canAccessClient(user, clientId) {
  if (!clientId) return false;
  if (isAdminUp(user)) {
    return !!getDb().prepare('SELECT id FROM clients WHERE id = ? AND archived_at IS NULL').get(clientId);
  }
  return !!getDb().prepare('SELECT 1 AS ok FROM client_access WHERE user_id = ? AND client_id = ?').get(user.id, clientId);
}

module.exports = {
  hashPassword, verifyPassword, totpCode, totpNow, totpVerify, newTotpSecret,
  audit, securityEvent, notify, createSession, userFromToken,
  isOwner, isAdminUp, canWrite, accessibleClientIds, canAccessClient,
};
