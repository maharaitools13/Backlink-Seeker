'use strict';
/* Backlink Management SaaS — single-page UI. All data comes from the API;
   authorization is enforced on the server, this file only renders. */
const $ = (s, el) => (el || document).querySelector(s);
const $$ = (s, el) => [...(el || document).querySelectorAll(s)];
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let me = null, clientsCache = [], usersCache = [], currentTab = 'dashboard';

async function api(method, path, body) {
  const r = await fetch(path, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || `Request failed (${r.status})`);
  return data;
}
async function tryApi(method, path, body) { try { return await api(method, path, body); } catch (e) { alert(e.message); throw e; } }

/* ---------------- Auth ---------------- */
const inviteToken = new URLSearchParams(location.search).get('invite');
async function init() {
  let setup = { ownerExists: true };
  try { setup = await api('GET', '/api/auth/setup'); } catch {}
  try { const m = await api('GET', '/api/auth/me'); me = m.user; return showApp(m.workspaceName); } catch {}
  showAuth(setup);
}
function showAuth(setup) {
  $('#appView').hidden = true; $('#authView').hidden = false;
  const form = $('#authForm');
  if (inviteToken) {
    $('#authTitle').textContent = 'Accept your invite';
    $('#authHint').textContent = 'Set your name and your own password to join the team.';
    $('#authEmail').parentElement.classList.add('hidden'); $('#authEmail').required = false;
    $('#nameField').classList.remove('hidden'); $('#authSubmit').textContent = 'Create my account';
    form.onsubmit = async (e) => { e.preventDefault(); try { const r = await api('POST', '/api/auth/accept-invite', { token: inviteToken, name: $('#authName').value, password: $('#authPassword').value }); me = r.user; history.replaceState({}, '', '/'); showApp(); } catch (err) { $('#authError').textContent = err.message; } };
    return;
  }
  if (!setup.ownerExists) {
    $('#authTitle').textContent = 'Create the Owner account';
    $('#authHint').textContent = 'This is the first account, so it becomes the Owner. After this, sign up closes and new members join by invite only.';
    $('#nameField').classList.remove('hidden'); $('#authSubmit').textContent = 'Create Owner account';
    form.onsubmit = async (e) => { e.preventDefault(); try { const r = await api('POST', '/api/auth/signup', { name: $('#authName').value, email: $('#authEmail').value, password: $('#authPassword').value }); me = r.user; showApp(); } catch (err) { $('#authError').textContent = err.message; } };
    return;
  }
  $('#authTitle').textContent = setup.workspaceName || 'Sign in';
  $('#authHint').textContent = 'Sign in with your team account. New members join by invite only.';
  $('#nameField').classList.add('hidden'); $('#authSubmit').textContent = 'Sign in';
  form.onsubmit = async (e) => {
    e.preventDefault();
    try {
      const r = await api('POST', '/api/auth/login', { email: $('#authEmail').value, password: $('#authPassword').value, code: $('#authCode').value || undefined });
      if (r.needs2fa) { $('#codeField').hidden = false; $('#authError').textContent = 'Enter the 6-digit code from your authenticator app.'; return; }
      me = r.user; showApp();
    } catch (err) { $('#authError').textContent = err.message; }
  };
}
async function showApp(workspaceName) {
  $('#authView').hidden = true; $('#appView').hidden = false;
  if (workspaceName) $('#workspaceName').textContent = workspaceName;
  else { try { const s = await api('GET', '/api/settings'); $('#workspaceName').textContent = s.workspaceName; } catch {} }
  $('#userInfo').textContent = `${me.name} · ${me.role}`;
  $('#logoutBtn').onclick = async () => { await api('POST', '/api/auth/logout'); location.reload(); };
  await refreshCaches(); buildNav(); updateNotifBadge(); go('dashboard');
}
async function refreshCaches() {
  try { clientsCache = (await api('GET', '/api/clients?pageSize=100')).rows; } catch { clientsCache = []; }
  try { usersCache = (await api('GET', '/api/users')).rows; } catch { usersCache = []; }
}
async function updateNotifBadge() { try { const n = await api('GET', '/api/notifications'); const unread = n.rows.filter((r) => !r.read_at).length; $('#notifBadge').textContent = unread ? `${unread} new` : ''; } catch {} }
const clientName = (id) => { const c = clientsCache.find((x) => x.id === id); return c ? c.name : (id || '—'); };
const userName = (id) => { const u = usersCache.find((x) => x.id === id); return u ? u.name : (id || '—'); };

function buildNav() {
  const tabs = [['dashboard', 'Dashboard'], ['backlinks', 'Backlinks'], ['clients', 'Clients'], ['domains', 'Referring Domains'], ['campaigns', 'Campaigns'], ['submissions', 'Submissions'], ['outreach', 'Outreach Contacts'], ['tasks', 'Tasks'], ['search', 'Global Search'], ['import', 'Import & Export'], ['links', 'Links-Only Import'], ['views', 'Saved Views'], ['notifications', 'Notifications'], ['security', 'Security']];
  if (me.role === 'Owner' || me.role === 'Admin') tabs.push(['team', 'Team & Invites'], ['audit', 'Audit Log']);
  if (me.role === 'Owner') tabs.push(['backups', 'Backup & Recovery'], ['owner', 'Owner Control Center']);
  $('#sidebar').innerHTML = tabs.map(([id, label]) => `<button data-tab="${id}" class="${id === currentTab ? 'active' : ''}">${label}</button>`).join('');
  $$('#sidebar button').forEach((b) => { b.onclick = () => go(b.dataset.tab); });
}
function go(tab) { currentTab = tab; $$('#sidebar button').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab)); render(); }
function render() {
  const fn = { dashboard: renderDashboard, backlinks: () => renderEntity('backlinks'), clients: () => renderEntity('clients'), domains: () => renderEntity('domains'), campaigns: () => renderEntity('campaigns'), submissions: () => renderEntity('submissions'), outreach: () => renderEntity('outreach'), tasks: () => renderEntity('tasks'), search: renderSearch, import: renderImport, links: renderLinksOnly, views: renderViews, notifications: renderNotifications, security: renderSecurity, team: renderTeam, audit: renderAudit, backups: renderBackups, owner: renderOwner }[currentTab];
  (fn || renderDashboard)();
}
const main = () => $('#main');

/* ---------------- Generic entity tables ---------------- */
const ENTITY_UI = {
  backlinks: { title: 'Backlinks', cols: ['source_url', 'target_url', 'anchor_text', 'link_type', 'status', 'dr', 'client_id'], fields: [['source_url', 'Source / page URL', 'url'], ['target_url', 'Target URL', 'url'], ['anchor_text', 'Anchor text'], ['link_type', 'Link type', 'select:dofollow,nofollow,sponsored,ugc'], ['status', 'Status', 'select:live,lost,pending,rejected'], ['dr', 'DR (blank = not available)', 'number'], ['placement', 'Placement'], ['client_id', 'Client', 'client'], ['campaign_id', 'Campaign ID (optional)'], ['notes', 'Notes', 'textarea']], statusFilter: ['live', 'lost', 'pending', 'rejected'] },
  clients: { title: 'Clients', cols: ['name', 'website', 'contact_name', 'contact_email', 'status'], fields: [['name', 'Name'], ['website', 'Website URL', 'url'], ['contact_name', 'Contact name'], ['contact_email', 'Contact email', 'email'], ['status', 'Status', 'select:active,paused'], ['notes', 'Notes', 'textarea']], statusFilter: ['active', 'paused'] },
  domains: { title: 'Referring Domains', cols: ['domain', 'dr', 'backlink_count'], fields: [['domain', 'Domain'], ['dr', 'DR (blank = not available)', 'number'], ['notes', 'Notes', 'textarea']] },
  campaigns: { title: 'Campaigns', cols: ['name', 'client_id', 'status', 'start_date', 'end_date'], fields: [['name', 'Name'], ['client_id', 'Client', 'client'], ['status', 'Status'], ['start_date', 'Start date', 'date'], ['end_date', 'End date', 'date']] },
  submissions: { title: 'Submissions', cols: ['site_url', 'type', 'status', 'client_id', 'submitted_date'], fields: [['site_url', 'Site / directory URL', 'url'], ['type', 'Type'], ['status', 'Status'], ['client_id', 'Client', 'client'], ['submitted_date', 'Submitted date', 'date']] },
  outreach: { title: 'Outreach Contacts', cols: ['name', 'email', 'website', 'domain', 'status', 'client_id'], fields: [['name', 'Name'], ['email', 'Email', 'email'], ['website', 'Website'], ['status', 'Status'], ['client_id', 'Client', 'client']] },
  tasks: { title: 'Tasks', cols: ['title', 'assignee_id', 'client_id', 'deadline', 'priority', 'status'], fields: [['title', 'Title'], ['description', 'Description', 'textarea'], ['assignee_id', 'Assignee', 'user'], ['client_id', 'Client', 'client'], ['deadline', 'Deadline', 'date'], ['priority', 'Priority', 'select:low,medium,high,urgent'], ['status', 'Status', 'select:todo,in_progress,blocked,done']], statusFilter: ['todo', 'in_progress', 'blocked', 'done'] },
};
const drDisplay = (v) => (v === null || v === undefined || v === '' ? 'not available' : v);

async function renderEntity(entity) {
  const cfg = ENTITY_UI[entity]; const canWrite = me.role !== 'Viewer';
  main().innerHTML = `<div class="card"><h2>${cfg.title}</h2>
    <div class="row">
      <label>Search <input id="fQ" placeholder="Filter text"></label>
      ${cfg.statusFilter ? `<label>Status <select id="fStatus"><option value="">All</option>${cfg.statusFilter.map((s) => `<option>${s}</option>`).join('')}</select></label>` : ''}
      ${entity !== 'clients' && entity !== 'domains' ? `<label>Client <select id="fClient"><option value="">All my clients</option>${clientsCache.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></label>` : ''}
      <label>Sort <select id="fSort"><option value="created_at">Newest</option><option value="${entity === 'domains' ? 'domain' : entity === 'backlinks' ? 'source_domain' : 'name' in Object(ENTITY_UI[entity]) ? 'name' : 'created_at'}">Name / domain</option></select></label>
      <button id="fApply" class="primary">Apply filters</button>
      ${canWrite ? '<button id="bulkBtn">Archive selected</button>' : ''}
      <button id="saveViewBtn">Save as view</button>
      <span class="row">${['csv', 'xlsx', 'pdf'].map((f) => `<button data-export="${f}">Export ${f.toUpperCase()}</button>`).join('')}</span>
    </div>
    <div id="tableWrap"><p class="muted">Loading…</p></div>
    <div class="row"><button id="prevPage">Previous</button><span id="pageInfo" class="muted"></span><button id="nextPage">Next</button><label><input type="checkbox" id="showArchived" style="width:auto"> Show archived</label></div>
  </div>
  ${canWrite ? `<div class="card"><h3>Add ${cfg.title.slice(0, -1)}</h3><form id="addForm">${cfg.fields.map(([k, label, type]) => fieldHtml(k, label, type)).join('')}<button class="primary" type="submit">Add</button></form></div>` : ''}
  <div class="card hidden" id="detailCard"><h3>Details</h3><div id="detailBody"></div></div>`;
  let page = 1;
  const load = async () => {
    const qs = new URLSearchParams({ page, pageSize: 25 });
    if ($('#fQ').value) qs.set('q', $('#fQ').value);
    if (cfg.statusFilter && $('#fStatus').value) qs.set('status', $('#fStatus').value);
    const fc = $('#fClient'); if (fc && fc.value) qs.set('clientId', fc.value);
    if ($('#fSort').value) { qs.set('sort', $('#fSort').value); qs.set('dir', 'asc'); }
    if ($('#showArchived').checked) qs.set('includeArchived', 'true');
    try {
      const data = await api('GET', `/api/${entity}?${qs}`);
      $('#pageInfo').textContent = `Page ${data.page} — ${data.total} records`;
      $('#tableWrap').innerHTML = data.rows.length ? `<table><thead><tr><th></th>${cfg.cols.map((c) => `<th>${esc(c)}</th>`).join('')}<th>Actions</th></tr></thead><tbody>${data.rows.map((r) => `<tr>${'<td><input type="checkbox" class="sel" value="' + r.id + '" style="width:auto"></td>'}${cfg.cols.map((c) => `<td>${esc(c === 'dr' ? drDisplay(r[c]) : c === 'client_id' ? clientName(r[c]) : c === 'assignee_id' ? userName(r[c]) : r[c] ?? '')}</td>`).join('')}<td>${r.archived_at ? '<span class="pill">archived</span> ' : ''}<button data-act="view" data-id="${r.id}">View</button> ${canWrite && !r.archived_at ? `<button data-act="edit" data-id="${r.id}">Edit</button> <button data-act="archive" data-id="${r.id}">Archive</button>` : ''} ${canWrite && r.archived_at ? `<button data-act="restore" data-id="${r.id}">Restore</button>` : ''} ${me.role === 'Owner' && r.archived_at ? `<button data-act="purge" data-id="${r.id}" class="danger">Purge</button>` : ''}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No records match.</p>';
      $$('#tableWrap [data-act]').forEach((b) => { b.onclick = () => rowAction(entity, b.dataset.act, b.dataset.id, data.rows.find((r) => r.id === b.dataset.id)); });
    } catch (e) { $('#tableWrap').innerHTML = `<p class="error">${esc(e.message)}</p>`; }
  };
  $('#fApply').onclick = () => { page = 1; load(); };
  $('#prevPage').onclick = () => { if (page > 1) { page--; load(); } };
  $('#nextPage').onclick = () => { page++; load(); };
  $('#showArchived').onchange = load;
  const bulk = $('#bulkBtn'); if (bulk) bulk.onclick = async () => { const ids = $$('.sel').filter((c) => c.checked).map((c) => c.value); if (!ids.length) return alert('Select at least one record. Bulk delete is not available — archive only.'); await tryApi('POST', `/api/${entity}/bulk-archive`, { ids }); load(); };
  $('#saveViewBtn').onclick = async () => { const name = prompt('Name for this saved view:'); if (!name) return; const shared = me.role === 'Owner' && confirm('Make this a shared team view? (Data inside is still scoped by each viewer\'s client access.)'); await tryApi('POST', '/api/views', { name, entity, shared, filters: { q: $('#fQ').value, status: cfg.statusFilter ? $('#fStatus').value : '', clientId: $('#fClient') ? $('#fClient').value : '' } }); alert('View saved.'); };
  $$('[data-export]').forEach((b) => { b.onclick = () => { const qs = new URLSearchParams({ format: b.dataset.export }); const fc = $('#fClient'); if (fc && fc.value) qs.set('clientId', fc.value); location.href = `/api/export/${entity}?${qs}`; }; });
  const form = $('#addForm');
  if (form) form.onsubmit = async (e) => { e.preventDefault(); const body = {}; cfg.fields.forEach(([k]) => { const el = form.elements[k]; if (el) body[k] = el.value === '' ? undefined : el.value; }); await tryApi('POST', `/api/${entity}`, body); await refreshCaches(); load(); };
  load();
}
function fieldHtml(k, label, type) {
  if (type === 'client') return `<label>${label} <select name="${k}"><option value="">— select —</option>${clientsCache.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></label>`;
  if (type === 'user') return `<label>${label} <select name="${k}"><option value="">— unassigned —</option>${usersCache.map((u) => `<option value="${u.id}">${esc(u.name)}</option>`).join('')}</select></label>`;
  if (type && type.startsWith('select:')) return `<label>${label} <select name="${k}">${type.slice(7).split(',').map((o) => `<option>${o}</option>`).join('')}</select></label>`;
  if (type === 'textarea') return `<label>${label} <textarea name="${k}"></textarea></label>`;
  return `<label>${label} <input name="${k}" type="${type || 'text'}"></label>`;
}
async function rowAction(entity, act, id, row) {
  if (act === 'view') {
    const card = $('#detailCard'); card.classList.remove('hidden');
    let html = `<pre>${esc(JSON.stringify(row, null, 2))}</pre>`;
    if (entity === 'backlinks') { const ev = await api('GET', `/api/backlinks/${id}/events`); html += '<h4>Event history</h4>' + (ev.rows.length ? ev.rows.map((e) => `<p class="small">${esc(e.created_at)} — ${esc(e.type)} by ${esc(userName(e.actor_id))} ${esc(e.detail || '')}</p>`).join('') : '<p class="muted">No events yet.</p>'); }
    $('#detailBody').innerHTML = html; card.scrollIntoView();
    return;
  }
  if (act === 'archive') { if (confirm('Archive this record? It can be restored later.')) { await tryApi('POST', `/api/${entity}/${id}/archive`); renderEntity(entity); } return; }
  if (act === 'restore') { await tryApi('POST', `/api/${entity}/${id}/restore`); renderEntity(entity); return; }
  if (act === 'purge') { const reason = prompt('Permanent purge is Owner-only and audit-logged. Give a reason:'); if (!reason) return; const confirmText = prompt('Type DELETE to confirm permanent purge:'); if (confirmText !== 'DELETE') return alert('Purge cancelled — confirmation did not match.'); await tryApi('POST', `/api/${entity}/${id}/purge`, { confirm: confirmText, reason }); renderEntity(entity); return; }
  if (act === 'edit') {
    const cfg = ENTITY_UI[entity]; const card = $('#detailCard'); card.classList.remove('hidden');
    $('#detailBody').innerHTML = `<form id="editForm">${cfg.fields.map(([k, label, type]) => fieldHtml(k, label, type)).join('')}<button class="primary" type="submit">Save changes</button></form>`;
    const form = $('#editForm'); cfg.fields.forEach(([k]) => { if (form.elements[k] && row[k] != null) form.elements[k].value = row[k]; });
    form.onsubmit = async (e) => { e.preventDefault(); const body = {}; cfg.fields.forEach(([k]) => { if (form.elements[k]) body[k] = form.elements[k].value === '' ? undefined : form.elements[k].value; }); await tryApi('PATCH', `/api/${entity}/${id}`, body); renderEntity(entity); };
    card.scrollIntoView();
  }
}

/* ---------------- Dashboard / Search / Views / Notifications ---------------- */
async function renderDashboard() {
  main().innerHTML = '<div class="card"><h2>Dashboard</h2><p class="muted">Loading…</p></div>';
  try {
    const counts = {};
    for (const e of ['backlinks', 'clients', 'domains', 'campaigns', 'submissions', 'outreach', 'tasks']) counts[e] = (await api('GET', `/api/${e}?pageSize=1`)).total;
    const wl = await api('GET', '/api/tasks/workload');
    const myRow = wl.rows.find((r) => r.userId === me.id) || { open: 0, overdue: 0, done: 0 };
    main().innerHTML = `<div class="card"><h2>Dashboard</h2><div class="grid">${Object.entries(counts).map(([k, v]) => `<div class="card"><div class="stat">${v}</div><div class="muted">${k}</div></div>`).join('')}</div></div>
    <div class="card"><h3>My workload</h3><p>Open: <strong>${myRow.open}</strong> · Overdue: <strong>${myRow.overdue}</strong> · Done: <strong>${myRow.done}</strong></p>
    ${wl.rows.length > 1 ? '<h4>Team workload</h4>' + wl.rows.map((r) => `<p class="small">${esc(r.name)} — open ${r.open}, overdue ${r.overdue}, done ${r.done}</p>`).join('') : ''}
    <p class="muted small">Task completion overall: ${wl.completion.done} of ${wl.completion.total} tasks done.</p></div>`;
  } catch (e) { main().innerHTML = `<div class="card"><p class="error">${esc(e.message)}</p></div>`; }
}
async function renderSearch() {
  main().innerHTML = `<div class="card"><h2>Global Search</h2><p class="muted">Results respect your role and client access — you never see data for clients you are not assigned to.</p>
  <div class="row"><label>Search <input id="sQ" placeholder="Domain, URL, name, email…"></label>
  <label>Type <select id="sType"><option value="">All types</option><option value="backlinks">Backlinks</option><option value="domains">Domains</option><option value="clients">Clients</option><option value="submissions">Submissions</option><option value="campaigns">Campaigns</option><option value="outreach">Outreach</option>${me.role === 'Owner' || me.role === 'Admin' ? '<option value="users">Users</option>' : ''}</select></label>
  <label>Client <select id="sClient"><option value="">All my clients</option>${clientsCache.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></label>
  <button id="sGo" class="primary">Search</button></div><div id="sResults"></div></div>`;
  $('#sGo').onclick = async () => {
    const qs = new URLSearchParams({ q: $('#sQ').value, type: $('#sType').value, clientId: $('#sClient').value });
    try { const r = await api('GET', `/api/search?${qs}`); $('#sResults').innerHTML = r.results.length ? r.results.map((x) => `<p><a href="#" data-open="${x.type}:${x.id}">${esc(x.title)}</a> <span class="pill">${esc(x.type)}</span> <span class="muted">${esc(x.subtitle || '')}</span></p>`).join('') : '<p class="muted">No results.</p>';
      $$('#sResults [data-open]').forEach((a) => { a.onclick = (e) => { e.preventDefault(); const [t] = a.dataset.open.split(':'); go({ client: 'clients', backlink: 'backlinks', domain: 'domains', campaign: 'campaigns', submission: 'submissions', outreach: 'outreach', user: 'team' }[t] || 'dashboard'); }; });
    } catch (e) { $('#sResults').innerHTML = `<p class="error">${esc(e.message)}</p>`; }
  };
}
async function renderViews() {
  main().innerHTML = '<div class="card"><h2>Saved Views</h2><p class="muted">Personal views are yours. Shared views (Owner-created) are visible to everyone, but the data inside is still scoped by each viewer\'s client access.</p><div id="vList">Loading…</div></div>';
  const r = await api('GET', '/api/views');
  $('#vList').innerHTML = r.rows.length ? r.rows.map((v) => `<p><strong>${esc(v.name)}</strong> <span class="pill">${esc(v.entity)}</span> ${v.shared ? '<span class="pill">shared</span>' : '<span class="pill">personal</span>'} <span class="muted small">${esc(JSON.stringify(v.filters))}</span> <button data-del="${v.id}">Delete</button> <button data-open="${v.entity}">Open ${esc(v.entity)}</button></p>`).join('') : '<p class="muted">No saved views yet. Save one from any table\'s "Save as view" button.</p>';
  $$('#vList [data-del]').forEach((b) => { b.onclick = async () => { await tryApi('DELETE', `/api/views/${b.dataset.del}`); renderViews(); }; });
  $$('#vList [data-open]').forEach((b) => { b.onclick = () => go(b.dataset.open); });
}
async function renderNotifications() {
  main().innerHTML = '<div class="card"><h2>Notifications</h2><div id="nList">Loading…</div></div>';
  const r = await api('GET', '/api/notifications');
  $('#nList').innerHTML = r.rows.length ? r.rows.map((n) => `<p>${n.read_at ? '' : '<strong>●</strong> '} ${esc(n.message)} <span class="muted small">${esc(n.created_at)}</span> ${n.read_at ? '' : `<button data-read="${n.id}">Mark read</button>`}</p>`).join('') : '<p class="muted">No notifications.</p>';
  $$('#nList [data-read]').forEach((b) => { b.onclick = async () => { await tryApi('POST', `/api/notifications/${b.dataset.read}/read`); updateNotifBadge(); renderNotifications(); }; });
}

/* ---------------- Import & Export / Links-Only ---------------- */
async function renderImport() {
  main().innerHTML = `<div class="card"><h2>Import & Export</h2>
  <h3>Full CSV import</h3><p class="muted small">Preview validates every row and writes nothing. Confirm writes the valid rows. An interrupted import can be resumed from where it stopped — already-imported rows are not duplicated. Backlink columns: source_url, target_url, anchor_text, link_type, status, dr, placement, notes.</p>
  <label>Import type <select id="iKind"><option value="backlinks">Backlinks</option><option value="clients">Clients</option></select></label>
  <label>Client (for backlinks) <select id="iClient">${clientsCache.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></label>
  <label>CSV file <input id="iFile" type="file" accept=".csv,text/csv"></label>
  <label>…or paste CSV <textarea id="iText"></textarea></label>
  <button id="iPreview" class="primary">Preview import</button>
  <div id="iResult"></div></div>
  <div class="card"><h3>Exports</h3><p class="muted small">Use the Export buttons on each table (CSV / XLSX / PDF), filtered by client and scoped to your access.</p></div>`;
  $('#iPreview').onclick = async () => {
    let text = $('#iText').value;
    const f = $('#iFile').files[0]; if (f) text = await f.text();
    if (!text) return alert('Choose a CSV file or paste CSV text.');
    try {
      const r = await api('POST', '/api/import/preview', { kind: $('#iKind').value, clientId: $('#iKind').value === 'backlinks' ? $('#iClient').value : undefined, csvText: text });
      $('#iResult').innerHTML = `<p>Total: ${r.total} · Valid: ${r.valid} · Failed: ${r.failed.length}</p>
      ${r.failed.length ? `<p><a href="/api/import/${r.jobId}/failed.csv">Download failed-row report</a></p>` : ''}
      <button id="iConfirm" class="primary">Confirm import (${r.valid} valid rows)</button> <span id="iStatus" class="muted"></span>`;
      $('#iConfirm').onclick = async () => { const c = await tryApi('POST', `/api/import/${r.jobId}/confirm`, {}); $('#iStatus').textContent = `Status: ${c.status} — processed ${c.processed}/${c.total}.`; await refreshCaches(); };
    } catch (e) { $('#iResult').innerHTML = `<p class="error">${esc(e.message)}</p>`; }
  };
}
async function renderLinksOnly() {
  main().innerHTML = `<div class="card"><h2>Links-Only Import with Auto-Detection</h2>
  <p class="muted">Paste backlink page URLs (one per line, max 50) and select the client they point to. The system fetches each page and detects the referring domain, live/lost status, target URL, anchor text and link type from the real outbound link. Pages with no link to the client are marked "target link not found" and are not imported. DR is never invented — with no SEO API configured it stays "not available".</p>
  <label>Client <select id="lClient">${clientsCache.map((c) => `<option value="${c.id}">${esc(c.name)} — ${esc(c.website)}</option>`).join('')}</select></label>
  <label>Backlink page URLs <textarea id="lUrls" placeholder="https://example.com/blog/post-1&#10;https://anothersite.org/article"></textarea></label>
  <label>…or upload a single-column .csv / .txt file <input id="lFile" type="file" accept=".csv,.txt,text/plain,text/csv"></label>
  <button id="lDetect" class="primary">Detect links</button><div id="lResult"></div></div>`;
  $('#lDetect').onclick = async () => {
    let text = $('#lUrls').value; const f = $('#lFile').files[0]; if (f) text = await f.text();
    $('#lResult').innerHTML = '<p class="muted">Fetching pages and detecting links…</p>';
    try {
      const r = await api('POST', '/api/import/links-only/preview', { clientId: $('#lClient').value, urlsText: text });
      $('#lResult').innerHTML = `<p>Client domain: <strong>${esc(r.clientDomain)}</strong> · Total: ${r.total} · Detected: ${r.valid} · Failed: ${r.failed.length}</p>
      <table><thead><tr><th>Source URL</th><th>Domain</th><th>Status</th><th>Target URL</th><th>Anchor</th><th>Type</th><th>DR</th><th>Result</th></tr></thead><tbody>
      ${r.preview.map((row) => `<tr><td>${esc(row.source_url)}</td><td>${esc(row.source_domain || (row.data ? '' : ''))}</td><td>${esc(row.valid ? row.data.status : row.status || '')}</td><td>${esc(row.valid ? row.data.target_url : '')}</td><td>${esc(row.valid ? row.data.anchor_text || '' : '')}</td><td>${esc(row.valid ? row.data.link_type : '')}</td><td>not available</td><td>${row.valid ? 'Ready' : esc(row.error || '')}</td></tr>`).join('')}
      </tbody></table>
      ${r.failed.length ? `<p><a href="/api/import/${r.jobId}/failed.csv">Download failed-row report</a></p>` : ''}
      ${r.valid ? `<button id="lConfirm" class="primary">Import ${r.valid} detected backlinks</button>` : ''} <span id="lStatus" class="muted"></span>`;
      const btn = $('#lConfirm'); if (btn) btn.onclick = async () => { const c = await tryApi('POST', `/api/import/${r.jobId}/confirm`, {}); $('#lStatus').textContent = `Import ${c.status}: ${c.processed}/${c.total} rows processed.`; };
    } catch (e) { $('#lResult').innerHTML = `<p class="error">${esc(e.message)}</p>`; }
  };
}

/* ---------------- Security / Team / Audit ---------------- */
async function renderSecurity() {
  main().innerHTML = '<div class="card"><h2>Security & Sessions</h2><div id="secBody">Loading…</div></div>';
  const [sess, events] = await Promise.all([api('GET', '/api/security/sessions'), api('GET', '/api/security/events')]);
  $('#secBody').innerHTML = `
  <h3>Two-factor authentication (TOTP)</h3>
  <p>Status: <strong>${me.twofa_enabled ? 'Enabled' : 'Not enabled'}</strong></p>
  ${me.twofa_enabled ? '<label>Current 6-digit code <input id="tfaCode"></label><button id="tfaDisable">Disable 2FA</button>' : '<button id="tfaSetup" class="primary">Set up 2FA</button><div id="tfaSetupBox"></div>'}
  <h3>Active sessions</h3>
  ${sess.rows.map((s) => `<p class="small">${esc(s.ip || '')} — ${esc(s.user_agent || '')} · last seen ${esc(s.last_seen)} ${s.id === sess.currentSessionId ? '<span class="pill">this device</span>' : `<button data-revoke="${s.id}">Revoke</button>`}</p>`).join('') || '<p class="muted">No active sessions.</p>'}
  ${me.role === 'Owner' ? '<p class="muted small">As Owner you can view and revoke any user\'s sessions by adding their user ID in Team & Invites (API: /api/security/sessions?userId=…).</p>' : ''}
  <h3>Security events</h3>
  ${events.rows.slice(0, 30).map((e) => `<p class="small">${esc(e.created_at)} — ${esc(e.type)} — ${esc(e.email || '')} — ${esc(e.ip || '')} ${esc(e.detail || '')}</p>`).join('') || '<p class="muted">No events.</p>'}`;
  const setup = $('#tfaSetup');
  if (setup) setup.onclick = async () => { const r = await tryApi('POST', '/api/security/2fa/setup'); $('#tfaSetupBox').innerHTML = `<p>Add this secret to your authenticator app:</p><p><code>${esc(r.secret)}</code></p><p class="muted small">${esc(r.otpauth)}</p><label>Enter a current code <input id="tfaEnableCode"></label><button id="tfaEnable" class="primary">Enable 2FA</button>`; $('#tfaEnable').onclick = async () => { await tryApi('POST', '/api/security/2fa/enable', { code: $('#tfaEnableCode').value }); me.twofa_enabled = true; renderSecurity(); }; };
  const dis = $('#tfaDisable');
  if (dis) dis.onclick = async () => { await tryApi('POST', '/api/security/2fa/disable', { code: $('#tfaCode').value }); me.twofa_enabled = false; renderSecurity(); };
  $$('#secBody [data-revoke]').forEach((b) => { b.onclick = async () => { await tryApi('POST', `/api/security/sessions/${b.dataset.revoke}/revoke`); renderSecurity(); }; });
}
async function renderTeam() {
  main().innerHTML = '<div class="card"><h2>Team & Invites</h2><div id="teamBody">Loading…</div></div>';
  const users = (await api('GET', '/api/users')).rows; usersCache = users;
  let invites = { rows: [] }; try { invites = await api('GET', '/api/invites'); } catch {}
  $('#teamBody').innerHTML = `
  <h3>Invite a member</h3><div class="row"><label>Email <input id="invEmail" type="email"></label><label>Role <select id="invRole"><option>Member</option><option>Admin</option><option>Viewer</option></select></label><button id="invSend" class="primary">Create invite</button></div><div id="invResult"></div>
  <h3>Members</h3>
  ${users.map((u) => `<div class="card"><p><strong>${esc(u.name)}</strong> — ${esc(u.email || '')} <span class="pill">${esc(u.role)}</span> <span class="pill">${esc(u.status || '')}</span> ${u.twofa_enabled ? '<span class="pill">2FA on</span>' : ''}</p>
    ${u.role !== 'Owner' ? `<div class="row"><label>Role <select id="role-${u.id}"><option ${u.role === 'Admin' ? 'selected' : ''}>Admin</option><option ${u.role === 'Member' ? 'selected' : ''}>Member</option><option ${u.role === 'Viewer' ? 'selected' : ''}>Viewer</option></select></label><button data-saveuser="${u.id}">Save role/status</button><button data-archiveuser="${u.id}" class="danger">Archive user</button></div>
    <p class="small muted">Client access (the member only sees assigned clients):</p>
    ${clientsCache.map((c) => `<label class="small" style="display:inline-block;margin-right:12px"><input type="checkbox" style="width:auto" data-access="${u.id}:${c.id}" ${u.clientIds && u.clientIds.includes(c.id) ? 'checked' : ''}> ${esc(c.name)}</label>`).join('')} <button data-saveaccess="${u.id}">Save client access</button>` : '<p class="small muted">The Owner account cannot be demoted, archived, or deleted.</p>'}
  </div>`).join('')}
  <h3>Invites</h3>${invites.rows.map((i) => `<p class="small">${esc(i.email)} — ${esc(i.role)} — ${i.accepted_at ? 'accepted' : 'pending, expires ' + esc(i.expires_at)}</p>`).join('') || '<p class="muted">No invites.</p>'}`;
  $('#invSend').onclick = async () => { try { const r = await api('POST', '/api/invites', { email: $('#invEmail').value, role: $('#invRole').value }); $('#invResult').innerHTML = `<p>Invite created for ${esc(r.email)} (${esc(r.role)}), expires ${esc(r.expiresAt)}.</p><p>${esc(r.note)}</p><p>Invite link: <code>${esc(r.inviteLink)}</code></p>`; } catch (e) { $('#invResult').innerHTML = `<p class="error">${esc(e.message)}</p>`; } };
  $$('#teamBody [data-saveuser]').forEach((b) => { b.onclick = async () => { await tryApi('PATCH', `/api/users/${b.dataset.saveuser}`, { role: $('#role-' + b.dataset.saveuser).value }); renderTeam(); }; });
  $$('#teamBody [data-archiveuser]').forEach((b) => { b.onclick = async () => { if (confirm('Archive this user and revoke their sessions?')) { await tryApi('POST', `/api/users/${b.dataset.archiveuser}/archive`); renderTeam(); } }; });
  $$('#teamBody [data-saveaccess]').forEach((b) => { b.onclick = async () => { const ids = $$(`#teamBody [data-access^="${b.dataset.saveaccess}:"]`).filter((c) => c.checked).map((c) => c.dataset.access.split(':')[1]); await tryApi('PUT', `/api/users/${b.dataset.saveaccess}/clients`, { clientIds: ids }); alert('Client access saved.'); }; });
}
async function renderAudit() {
  main().innerHTML = '<div class="card"><h2>Audit Log</h2><div id="aList">Loading…</div></div>';
  const r = await api('GET', '/api/audit');
  $('#aList').innerHTML = r.rows.length ? r.rows.map((a) => `<p class="small">${esc(a.created_at)} — ${esc(userName(a.actor_id))} — <strong>${esc(a.action)}</strong> ${esc(a.entity)} ${esc(a.entity_id || '')} ${a.reason ? '· reason: ' + esc(a.reason) : ''}</p>`).join('') : '<p class="muted">No audit entries yet.</p>';
}

/* ---------------- Backups / Owner Center ---------------- */
async function renderBackups() {
  main().innerHTML = '<div class="card"><h2>Backup & Recovery</h2><div id="bBody">Loading…</div></div>';
  const r = await api('GET', '/api/backups');
  $('#bBody').innerHTML = `<p class="muted">${esc(r.retentionRule)}</p><p class="muted small">Before production handover, create a backup and run "Test restore" — the result is recorded on the backup. A real restore replaces the current database and requires typing RESTORE.</p>
  <button id="bCreate" class="primary">Create backup now</button>
  ${r.rows.map((b) => `<p class="small"><strong>${esc(b.filename)}</strong> — ${b.size} bytes — checksum ${esc(String(b.checksum).slice(0, 12))}… — ${esc(b.kind)} — ${esc(b.created_at)} ${b.restore_test_result ? `<br>Restore test: ${esc(b.restore_test_result)} (${esc(b.restore_test_at)})` : '<br>No restore test recorded yet.'} <button data-test="${b.id}">Test restore</button> <button data-restore="${b.id}" class="danger">Restore</button></p>`).join('') || '<p class="muted">No backups yet.</p>'}`;
  $('#bCreate').onclick = async () => { await tryApi('POST', '/api/backups'); renderBackups(); };
  $$('#bBody [data-test]').forEach((b) => { b.onclick = async () => { const r2 = await tryApi('POST', `/api/backups/${b.dataset.test}/test-restore`); alert(r2.result); renderBackups(); }; });
  $$('#bBody [data-restore]').forEach((b) => { b.onclick = async () => { const c = prompt('This replaces the current database with the backup. Type RESTORE to confirm:'); if (c !== 'RESTORE') return alert('Restore cancelled.'); await tryApi('POST', `/api/backups/${b.dataset.restore}/restore`, { confirm: c }); alert('Database restored. You may need to sign in again.'); location.reload(); }; });
}
async function renderOwner() {
  main().innerHTML = '<div class="card"><h2>Owner Control Center</h2><div id="oBody">Loading…</div></div>';
  const [s, mon, budgets] = await Promise.all([api('GET', '/api/owner/settings'), api('GET', '/api/owner/monitoring'), api('GET', '/api/api-budgets')]);
  const st = s.settings;
  $('#oBody').innerHTML = `
  <form id="settingsForm">
  <h3>General Settings</h3>
  <label>Workspace name (appears in the app header) <input name="workspace_name" value="${esc(st.workspace_name)}"></label>
  <label>Timezone <input name="timezone" value="${esc(st.timezone)}"></label>
  <label>Default link type <select name="default_link_type">${['dofollow', 'nofollow', 'sponsored', 'ugc'].map((o) => `<option ${st.default_link_type === o ? 'selected' : ''}>${o}</option>`).join('')}</select></label>
  <h3>Security Settings</h3>
  <label>Session lifetime (hours) <input name="session_lifetime_hours" type="number" min="1" max="168" value="${esc(st.session_lifetime_hours)}"></label>
  <label>Require 2FA for all users <select name="require_2fa"><option value="false" ${st.require_2fa === 'false' ? 'selected' : ''}>No</option><option value="true" ${st.require_2fa === 'true' ? 'selected' : ''}>Yes</option></select></label>
  <label>Suspicious-login alerts <select name="suspicious_login_alerts"><option value="true" ${st.suspicious_login_alerts === 'true' ? 'selected' : ''}>On</option><option value="false" ${st.suspicious_login_alerts === 'false' ? 'selected' : ''}>Off</option></select></label>
  <h3>Notification Settings</h3>
  <label>Overdue task notifications <select name="notify_overdue_tasks"><option value="true" ${st.notify_overdue_tasks === 'true' ? 'selected' : ''}>On</option><option value="false" ${st.notify_overdue_tasks === 'false' ? 'selected' : ''}>Off</option></select></label>
  <h3>Backup & Recovery</h3>
  <label>Backup schedule <select name="backup_schedule">${['off', 'daily', 'weekly'].map((o) => `<option ${st.backup_schedule === o ? 'selected' : ''}>${o}</option>`).join('')}</select></label>
  <label>Backup retention (days) <input name="backup_retention_days" type="number" min="1" max="365" value="${esc(st.backup_retention_days)}"></label>
  <h3>Import & Export Settings</h3>
  <label>Maximum rows per import file <input name="import_max_rows" type="number" min="1" value="${esc(st.import_max_rows)}"></label>
  <button class="primary" type="submit">Save all settings</button> <span id="oSaved" class="muted"></span>
  </form>
  <div class="card"><h3>Team & Permissions / Client Settings</h3><p class="muted">Managed in Team & Invites (roles and per-member client assignment) and in the Clients table (including the client-portal access flag on each client record, reserved for the future Client Portal).</p></div>
  <div class="card"><h3>API & Integrations — budgets</h3>
  ${budgets.rows.map((b) => `<p class="small"><strong>${esc(b.provider)}</strong> — used ${b.usedThisMonth} / ${b.monthly_limit} this month · alert at ${b.alert_pct}% · pause at limit: ${b.pause_at_limit ? 'yes' : 'no'} · estimated cost: ${esc(String(b.estimatedCost))} <button data-budget-archive="${b.id}">Archive</button></p>`).join('') || '<p class="muted">No budgets defined. Usage and cost are never invented — cost shows "not available" until a per-request price is set.</p>'}
  <div class="row"><label>Provider <input id="bpProvider" placeholder="page-fetch"></label><label>Monthly limit <input id="bpLimit" type="number"></label><label>Alert % <input id="bpAlert" type="number" value="80"></label><label>Price per request (optional) <input id="bpPrice" type="number" step="0.0001"></label><label>Pause at limit <input id="bpPause" type="checkbox" style="width:auto"></label><button id="bpAdd" class="primary">Add budget</button></div>
  <p class="muted small">Scoped API tokens for future integrations (Browser Extension etc.) can be created in Security/API tokens via the API — only token hashes are stored.</p></div>
  <div class="card"><h3>Data Management</h3><p class="muted">Archive-first deletion, Owner-only purge with typed DELETE + reason, and the append-only audit log are enforced across all tables. See Audit Log.</p></div>
  <div class="card"><h3>System Monitoring (real data only)</h3>
  <div class="grid">${Object.entries(mon.counts).map(([k, v]) => `<div><div class="stat">${v}</div><div class="muted">${k}</div></div>`).join('')}</div>
  <p class="small">Last backup: ${mon.lastBackup ? esc(mon.lastBackup.filename + ' · ' + mon.lastBackup.created_at) : 'none yet'} · Import jobs with failed rows: ${mon.failedImports}</p>
  <h4>Recent security events</h4>${mon.recentSecurityEvents.map((e) => `<p class="small">${esc(e.created_at)} — ${esc(e.type)} — ${esc(e.email || '')}</p>`).join('') || '<p class="muted">None.</p>'}
  <h4>API usage this month</h4>${mon.apiUsage.map((u) => `<p class="small">${esc(u.provider)}: ${u.requests} requests</p>`).join('') || '<p class="muted">No API usage recorded.</p>'}</div>`;
  $('#settingsForm').onsubmit = async (e) => { e.preventDefault(); const settings = {}; $$('#settingsForm [name]').forEach((el) => { settings[el.name] = el.value; }); await tryApi('PUT', '/api/owner/settings', { settings }); $('#oSaved').textContent = 'Saved — settings take effect immediately.'; const s2 = await api('GET', '/api/settings'); $('#workspaceName').textContent = s2.workspaceName; };
  $('#bpAdd').onclick = async () => { await tryApi('POST', '/api/api-budgets', { provider: $('#bpProvider').value, monthly_limit: Number($('#bpLimit').value), alert_pct: Number($('#bpAlert').value), per_request_price: $('#bpPrice').value === '' ? null : Number($('#bpPrice').value), pause_at_limit: $('#bpPause').checked }); renderOwner(); };
  $$('#oBody [data-budget-archive]').forEach((b) => { b.onclick = async () => { await tryApi('POST', `/api/api-budgets/${b.dataset.budgetArchive}/archive`); renderOwner(); }; });
}

init();
