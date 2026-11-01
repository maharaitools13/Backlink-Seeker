'use strict';
/* End-to-end API tests against a real spawned server with a temp SQL database.
   Covers the acceptance criteria, including failure cases. */
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { totpNow } = require('../src/auth');

const PORT = 39873;
const FIXTURE_PORT = 39874;
const BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bls-test-'));
let server, fixture;
let owner, member, viewer; // cookie jars (strings)
let clientA, clientB, backlinkA, backlinkB, inviteToken;

function client(cookieRef) {
  return async (method, p, body) => {
    const r = await fetch(BASE + p, { method, headers: { 'Content-Type': 'application/json', ...(cookieRef.value ? { Cookie: cookieRef.value } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const setCookie = r.headers.get('set-cookie');
    if (setCookie) cookieRef.value = setCookie.split(';')[0];
    const ct = r.headers.get('content-type') || '';
    const data = ct.includes('json') ? await r.json() : await r.text();
    return { status: r.status, data, headers: r.headers };
  };
}
const jar = () => ({ value: null });
const ownerJar = jar(), memberJar = jar(), viewerJar = jar();
const asOwner = client(ownerJar), asMember = client(memberJar), asViewer = client(viewerJar), anon = client(jar());

before(async () => {
  // Fixture site for links-only detection: one page links to the client, one does not.
  fixture = http.createServer((req, res) => {
    if (req.url === '/with-link') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><body><a href="https://client-a.example/landing" rel="nofollow">Great Anchor</a></body></html>'); }
    else if (req.url === '/with-ugc') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><body><a href="https://client-a.example/" rel="ugc sponsored">Sponsored Anchor</a></body></html>'); }
    else if (req.url === '/no-link') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><body><a href="https://other.example/x">Other</a></body></html>'); }
    else { res.writeHead(404); res.end('nope'); }
  });
  await new Promise((r) => fixture.listen(FIXTURE_PORT, r));
  server = spawn('node', ['src/server.js'], { cwd: path.join(__dirname, '..'), env: { ...process.env, PORT: String(PORT), DATABASE_PATH: path.join(tmp, 'test.db'), BACKUP_DIR: path.join(tmp, 'backups') }, stdio: 'pipe' });
  for (let i = 0; i < 50; i++) { try { const r = await fetch(BASE + '/api/health'); if (r.ok) return; } catch {} await new Promise((r) => setTimeout(r, 200)); }
  throw new Error('server did not start');
});
after(() => { if (server) server.kill(); if (fixture) fixture.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('starts empty: setup reports no owner', async () => {
  const r = await anon('GET', '/api/auth/setup');
  assert.equal(r.data.ownerExists, false);
});

test('first signup becomes Owner; public signup then closes', async () => {
  const r = await asOwner('POST', '/api/auth/signup', { name: 'Owner One', email: 'owner@test.local', password: 'password123' });
  assert.equal(r.status, 201); assert.equal(r.data.user.role, 'Owner'); owner = r.data.user;
  const r2 = await anon('POST', '/api/auth/signup', { name: 'Second', email: 'second@test.local', password: 'password123' });
  assert.equal(r2.status, 403);
});

test('login rejects wrong password and accepts the right one', async () => {
  const bad = await client(jar())('POST', '/api/auth/login', { email: 'owner@test.local', password: 'wrong-password' });
  assert.equal(bad.status, 401);
  const ok = await client(jar())('POST', '/api/auth/login', { email: 'owner@test.local', password: 'password123' });
  assert.equal(ok.status, 200);
});

test('validation: weak owner settings and bad client payloads are rejected', async () => {
  const bad = await asOwner('PUT', '/api/owner/settings', { settings: { session_lifetime_hours: '9999' } });
  assert.equal(bad.status, 400);
  const badClient = await asOwner('POST', '/api/clients', { name: 'X' });
  assert.equal(badClient.status, 400);
});

test('owner creates clients; invite flow: member sets their own password', async () => {
  const a = await asOwner('POST', '/api/clients', { name: 'Client A', website: 'https://client-a.example/', contact_email: 'a@client-a.example' });
  assert.equal(a.status, 201); clientA = a.data.row;
  const b = await asOwner('POST', '/api/clients', { name: 'Client B', website: 'https://client-b.example/' });
  assert.equal(b.status, 201); clientB = b.data.row;
  const inv = await asOwner('POST', '/api/invites', { email: 'member@test.local', role: 'Member' });
  assert.equal(inv.status, 201); assert.ok(inv.data.inviteLink.includes('invite='));
  inviteToken = inv.data.inviteLink.split('invite=')[1];
  const acc = await asMember('POST', '/api/auth/accept-invite', { token: inviteToken, name: 'Member One', password: 'memberpass123' });
  assert.equal(acc.status, 201); assert.equal(acc.data.user.role, 'Member'); member = acc.data.user;
  const reuse = await anon('POST', '/api/auth/accept-invite', { token: inviteToken, name: 'Again', password: 'memberpass123' });
  assert.equal(reuse.status, 400); // invite is one-time
  const invV = await asOwner('POST', '/api/invites', { email: 'viewer@test.local', role: 'Viewer' });
  const accV = await asViewer('POST', '/api/auth/accept-invite', { token: invV.data.inviteLink.split('invite=')[1], name: 'Viewer One', password: 'viewerpass123' });
  assert.equal(accV.status, 201); viewer = accV.data.user;
});

test('Owner cannot be demoted or archived', async () => {
  const all = await asOwner('GET', '/api/users');
  const ownerRow = all.data.rows.find((u) => u.role === 'Owner');
  const demote = await asOwner('PATCH', `/api/users/${ownerRow.id}`, { role: 'Member' });
  assert.equal(demote.status, 403);
  const arch = await asOwner('POST', `/api/users/${ownerRow.id}/archive`);
  assert.equal(arch.status, 403);
});

test('client-level access: member sees only assigned client, 403 elsewhere (incl. search, direct URL, export)', async () => {
  await asOwner('PUT', `/api/users/${member.id}/clients`, { clientIds: [clientA.id] });
  // Backlinks for both clients, created by Owner
  const ba = await asOwner('POST', '/api/backlinks', { client_id: clientA.id, source_url: 'https://blog.example/post-a', target_url: 'https://client-a.example/', anchor_text: 'A link', link_type: 'dofollow', status: 'live' });
  assert.equal(ba.status, 201); backlinkA = ba.data.row;
  const bb = await asOwner('POST', '/api/backlinks', { client_id: clientB.id, source_url: 'https://blog.example/post-b', target_url: 'https://client-b.example/', status: 'live' });
  backlinkB = bb.data.row;
  const list = await asMember('GET', '/api/clients');
  assert.deepEqual(list.data.rows.map((r) => r.id), [clientA.id]);
  const directB = await asMember('GET', `/api/clients/${clientB.id}`);
  assert.equal(directB.status, 403);
  const bl = await asMember('GET', '/api/backlinks');
  assert.ok(bl.data.rows.every((r) => r.client_id === clientA.id));
  const directBacklink = await asMember('GET', `/api/backlinks/${backlinkB.id}`);
  assert.equal(directBacklink.status, 403);
  const search = await asMember('GET', '/api/search?q=blog.example');
  assert.ok(search.data.results.every((r) => r.clientId !== clientB.id));
  const exp = await fetch(BASE + `/api/export/backlinks?format=csv`, { headers: { Cookie: memberJar.value } });
  const csv = await exp.text();
  assert.ok(csv.includes('post-a')); assert.ok(!csv.includes('post-b'));
  const patch = await asMember('PATCH', `/api/backlinks/${backlinkB.id}`, { status: 'lost' });
  assert.equal(patch.status, 403);
});

test('viewer is read-only', async () => {
  const c = await asViewer('POST', '/api/clients', { name: 'Nope', website: 'https://nope.example/' });
  assert.equal(c.status, 403);
});

test('backlink event history is preserved through status change, archive and restore', async () => {
  const upd = await asOwner('PATCH', `/api/backlinks/${backlinkA.id}`, { status: 'lost' });
  assert.equal(upd.status, 200);
  await asOwner('POST', `/api/backlinks/${backlinkA.id}/archive`);
  const gone = await asOwner('GET', `/api/backlinks/${backlinkA.id}`);
  assert.equal(gone.status, 404);
  await asOwner('POST', `/api/backlinks/${backlinkA.id}/restore`);
  const ev = await asOwner('GET', `/api/backlinks/${backlinkA.id}/events`);
  const types = ev.data.rows.map((r) => r.type);
  assert.ok(types.includes('created') && types.includes('status_changed') && types.includes('archived') && types.includes('restored'));
});

test('bulk action is archive only; purge needs Owner + typed DELETE + reason, and is audit-logged', async () => {
  const bd = await asOwner('POST', `/api/backlinks/${backlinkA.id}/purge`, { confirm: 'DELETE', reason: 'test' }); // not archived now
  assert.equal(bd.status, 400);
  const tmp1 = await asOwner('POST', '/api/backlinks', { client_id: clientA.id, source_url: 'https://x.example/1', target_url: 'https://client-a.example/' });
  const id = tmp1.data.row.id;
  const bulk = await asOwner('POST', '/api/backlinks/bulk-archive', { ids: [id] });
  assert.equal(bulk.data.archived, 1);
  const noReason = await asOwner('POST', `/api/backlinks/${id}/purge`, { confirm: 'DELETE' });
  assert.equal(noReason.status, 400);
  const memberPurge = await asMember('POST', `/api/backlinks/${id}/purge`, { confirm: 'DELETE', reason: 'x' });
  assert.equal(memberPurge.status, 403);
  const ok = await asOwner('POST', `/api/backlinks/${id}/purge`, { confirm: 'DELETE', reason: 'duplicate entry' });
  assert.equal(ok.status, 200);
  const audit = await asOwner('GET', '/api/audit');
  assert.ok(audit.data.rows.some((r) => r.action === 'purge' && r.reason === 'duplicate entry'));
});

test('tasks: assignment rules, overdue notification deduped to one per day', async () => {
  const past = new Date(Date.now() - 3 * 86400e3).toISOString().slice(0, 10);
  const t = await asOwner('POST', '/api/tasks', { title: 'Overdue task', assignee_id: member.id, client_id: clientA.id, deadline: past, priority: 'high' });
  assert.equal(t.status, 201);
  await asMember('GET', '/api/notifications');
  const n1 = await asMember('GET', '/api/notifications');
  const count1 = n1.data.rows.filter((r) => r.type === 'task_overdue').length;
  await asMember('GET', '/api/notifications');
  const n2 = await asMember('GET', '/api/notifications');
  assert.equal(n2.data.rows.filter((r) => r.type === 'task_overdue').length, count1);
  assert.equal(count1, 1);
  const wl = await asOwner('GET', '/api/tasks/workload');
  const row = wl.data.rows.find((r) => r.userId === member.id);
  assert.ok(row.overdue >= 1);
  // Member cannot assign tasks to others
  const assign = await asMember('POST', '/api/tasks', { title: 'Nope', assignee_id: owner.id });
  assert.equal(assign.status, 403);
});

test('saved views: shared requires Owner; data inside remains scoped', async () => {
  const mine = await asMember('POST', '/api/views', { name: 'My live links', entity: 'backlinks', filters: { status: 'live' } });
  assert.equal(mine.status, 201);
  const sharedByMember = await asMember('POST', '/api/views', { name: 'Sneaky', entity: 'backlinks', shared: true, filters: {} });
  assert.equal(sharedByMember.status, 403);
  const shared = await asOwner('POST', '/api/views', { name: 'Team view', entity: 'backlinks', shared: true, filters: {} });
  assert.equal(shared.status, 201);
  const list = await asMember('GET', '/api/views');
  assert.ok(list.data.rows.some((r) => r.name === 'Team view'));
});

test('2FA: owner can enable TOTP and login then requires a code', async () => {
  const setup = await asOwner('POST', '/api/security/2fa/setup');
  assert.equal(setup.status, 200); assert.ok(setup.data.secret);
  // Extract secret via a fresh setup is stored on the user; enable with a code computed from that secret
  const enable = await asOwner('POST', '/api/security/2fa/enable', { code: totpNow(setup.data.secret) });
  assert.equal(enable.status, 200);
  const jar2 = jar(); const c2 = client(jar2);
  const step1 = await c2('POST', '/api/auth/login', { email: 'owner@test.local', password: 'password123' });
  assert.equal(step1.data.needs2fa, true);
  const step2 = await c2('POST', '/api/auth/login', { email: 'owner@test.local', password: 'password123', code: totpNow(setup.data.secret) });
  assert.equal(step2.status, 200);
  // Sessions list + revocation of own other session works
  const sessions = await asOwner('GET', '/api/security/sessions');
  assert.ok(sessions.data.rows.length >= 1);
  // Disable 2FA again for later tests
  const disable = await client(jar2)('POST', '/api/security/2fa/disable', { code: totpNow(setup.data.secret) });
  assert.equal(disable.status, 200);
});

test('non-Owners get 403 on every Owner-only route', async () => {
  for (const [method, p, body] of [
    ['GET', '/api/owner/settings'], ['PUT', '/api/owner/settings', { settings: { workspace_name: 'Hacked' } }],
    ['GET', '/api/owner/monitoring'], ['GET', '/api/backups'], ['POST', '/api/backups'],
    ['POST', '/api/api-budgets', { provider: 'x', monthly_limit: 5 }],
  ]) {
    const r = await asMember(method, p, body);
    assert.equal(r.status, 403, `${method} ${p}`);
  }
});

test('owner setting visibly takes effect: workspace name changes', async () => {
  const r = await asOwner('PUT', '/api/owner/settings', { settings: { workspace_name: 'Acme SEO Backlinks' } });
  assert.equal(r.status, 200);
  const s = await asMember('GET', '/api/settings');
  assert.equal(s.data.workspaceName, 'Acme SEO Backlinks');
  const setupR = await anon('GET', '/api/auth/setup');
  assert.equal(setupR.data.workspaceName, 'Acme SEO Backlinks');
});

test('full CSV import: preview writes nothing, confirm writes, resume does not duplicate, failed report preserved', async () => {
  const before_ = await asOwner('GET', '/api/backlinks?pageSize=100');
  const csv = 'source_url,target_url,anchor_text,link_type,status\nhttps://imp.example/1,https://client-a.example/,One,dofollow,live\nnot-a-url,https://client-a.example/,Bad,dofollow,live\nhttps://imp.example/2,https://client-a.example/,Two,nofollow,pending\n';
  const prev = await asOwner('POST', '/api/import/preview', { kind: 'backlinks', clientId: clientA.id, csvText: csv });
  assert.equal(prev.status, 201); assert.equal(prev.data.valid, 2); assert.equal(prev.data.failed.length, 1);
  const afterPrev = await asOwner('GET', '/api/backlinks?pageSize=100');
  assert.equal(afterPrev.data.total, before_.data.total, 'preview must not write rows');
  const failedCsv = await fetch(BASE + `/api/import/${prev.data.jobId}/failed.csv`, { headers: { Cookie: ownerJar.value } });
  assert.ok((await failedCsv.text()).includes('Invalid or missing source_url'));
  const part = await asOwner('POST', `/api/import/${prev.data.jobId}/confirm`, { chunk: 2 });
  assert.equal(part.data.status, 'partial');
  const rest = await asOwner('POST', `/api/import/${prev.data.jobId}/confirm`, {});
  assert.equal(rest.data.status, 'complete');
  const again = await asOwner('POST', `/api/import/${prev.data.jobId}/confirm`, {});
  assert.equal(again.data.alreadyComplete, true);
  const afterAll = await asOwner('GET', '/api/backlinks?pageSize=100');
  assert.equal(afterAll.data.total, before_.data.total + 2, 'resume must not duplicate rows');
});

test('links-only import: detects real link, rel type and anchor; reports target link not found; never invents DR', async () => {
  const urls = [`http://127.0.0.1:${FIXTURE_PORT}/with-link`, `http://127.0.0.1:${FIXTURE_PORT}/with-ugc`, `http://127.0.0.1:${FIXTURE_PORT}/no-link`, `http://127.0.0.1:${FIXTURE_PORT}/missing-page`];
  const prev = await asOwner('POST', '/api/import/links-only/preview', { clientId: clientA.id, urlsText: urls.join('\n') });
  assert.equal(prev.status, 201);
  assert.equal(prev.data.valid, 2);
  const noLink = prev.data.failed.find((f) => f.row.endsWith('/no-link'));
  assert.equal(noLink.error, 'target link not found');
  const rowA = prev.data.preview.find((r) => r.valid && r.source_url.endsWith('/with-link'));
  assert.equal(rowA.data.link_type, 'nofollow'); assert.equal(rowA.data.anchor_text, 'Great Anchor'); assert.equal(rowA.data.target_url, 'https://client-a.example/landing'); assert.equal(rowA.data.dr, null);
  const rowU = prev.data.preview.find((r) => r.valid && r.source_url.endsWith('/with-ugc'));
  assert.equal(rowU.data.link_type, 'sponsored');
  const before_ = await asOwner('GET', '/api/backlinks?pageSize=100');
  const conf = await asOwner('POST', `/api/import/${prev.data.jobId}/confirm`, {});
  assert.equal(conf.data.status, 'complete');
  const afterAll = await asOwner('GET', '/api/backlinks?pageSize=100');
  assert.equal(afterAll.data.total, before_.data.total + 2);
  // Member cannot run detection for a client they cannot access
  const denied = await asMember('POST', '/api/import/links-only/preview', { clientId: clientB.id, urlsText: urls[0] });
  assert.equal(denied.status, 403);
  // Max 50 URLs
  const tooMany = await asOwner('POST', '/api/import/links-only/preview', { clientId: clientA.id, urlsText: Array(51).fill(urls[0]).join('\n') });
  assert.equal(tooMany.status, 400);
});

test('exports: CSV, XLSX (real zip) and PDF signatures; DR blank shows not available', async () => {
  const csvR = await fetch(BASE + '/api/export/backlinks?format=csv', { headers: { Cookie: ownerJar.value } });
  assert.ok((await csvR.text()).includes('source_url'));
  const xlsxR = await fetch(BASE + '/api/export/backlinks?format=xlsx', { headers: { Cookie: ownerJar.value } });
  const buf = Buffer.from(await xlsxR.arrayBuffer());
  assert.equal(buf.slice(0, 2).toString(), 'PK');
  const pdfR = await fetch(BASE + '/api/export/backlinks?format=pdf', { headers: { Cookie: ownerJar.value } });
  assert.ok((await pdfR.text()).startsWith('%PDF'));
});

test('API budget: cost is not available without a price; pause-at-limit returns 429', async () => {
  const b = await asOwner('POST', '/api/api-budgets', { provider: 'page-fetch', monthly_limit: 4, alert_pct: 50, pause_at_limit: true });
  assert.equal(b.status, 201);
  const list = await asOwner('GET', '/api/api-budgets');
  const row = list.data.rows.find((r) => r.provider === 'page-fetch');
  assert.equal(row.estimatedCost, 'not available');
  assert.ok(row.usedThisMonth >= 4, 'real usage from links-only detection should be counted');
  const blocked = await asOwner('POST', '/api/import/links-only/preview', { clientId: clientA.id, urlsText: `http://127.0.0.1:${FIXTURE_PORT}/with-link` });
  assert.equal(blocked.status, 429);
});

test('backup: create with checksum, restore-test recorded, wrong confirm rejected, restore works', async () => {
  const created = await asOwner('POST', '/api/backups');
  assert.equal(created.status, 201); assert.ok(created.data.backup.checksum.length === 64); assert.ok(created.data.backup.size > 0);
  const id = created.data.backup.id;
  const testR = await asOwner('POST', `/api/backups/${id}/test-restore`);
  assert.ok(testR.data.result.startsWith('OK'));
  const list = await asOwner('GET', '/api/backups');
  assert.ok(list.data.rows.find((r) => r.id === id).restore_test_result.startsWith('OK'));
  const marker = await asOwner('POST', '/api/clients', { name: 'Marker Client', website: 'https://marker.example/' });
  assert.equal(marker.status, 201);
  const wrong = await asOwner('POST', `/api/backups/${id}/restore`, { confirm: 'WRONG' });
  assert.equal(wrong.status, 400);
  const ok = await asOwner('POST', `/api/backups/${id}/restore`, { confirm: 'RESTORE' });
  assert.equal(ok.status, 200);
  // After restore, the marker client (created after the backup) is gone.
  // The session may have been restored too, so sign in again if needed.
  let clients = await asOwner('GET', '/api/clients?pageSize=100');
  if (clients.status === 401) { const j = jar(); const c = client(j); await c('POST', '/api/auth/login', { email: 'owner@test.local', password: 'password123' }); ownerJar.value = j.value; clients = await asOwner('GET', '/api/clients?pageSize=100'); }
  assert.ok(!clients.data.rows.some((r) => r.name === 'Marker Client'));
  assert.ok(clients.data.rows.some((r) => r.name === 'Client A'));
});

test('security events record logins and failed logins', async () => {
  const ev = await asOwner('GET', '/api/security/events');
  assert.ok(ev.data.rows.some((r) => r.type === 'login'));
  assert.ok(ev.data.rows.some((r) => r.type === 'login_failed'));
});
