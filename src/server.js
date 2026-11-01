'use strict';
/* Entry point: static files + API, security headers, env config. */
const fs = require('fs');
const path = require('path');

// Minimal .env loader (no dependency): KEY=VALUE lines, never overrides real env.
const envFile = path.join(__dirname, '..', '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}
const http = require('http');
const { migrate } = require('./db');
const app = require('./app');

migrate();
app.maybeAutoBackup();

const PUBLIC = path.join(__dirname, '..', 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) return app.handle(req, res);
  let file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  if (!['index.html', 'app.js', 'style.css'].includes(file)) file = 'index.html'; // SPA fallback, no path traversal
  const full = path.join(PUBLIC, file);
  fs.readFile(full, (e, data) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
});

const PORT = parseInt(process.env.PORT || '3000', 10);
if (require.main === module) server.listen(PORT, () => console.log(`Backlink Management SaaS listening on http://localhost:${PORT}`));
module.exports = server;
