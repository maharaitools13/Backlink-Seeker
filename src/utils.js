'use strict';
/* Shared helpers: HTTP, validation, CSV, XLSX, PDF. No external dependencies. */
const crypto = require('crypto');

const now = () => new Date().toISOString();
const uid = () => crypto.randomUUID();
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function isEmail(s) { return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 254; }
function isUrl(s) { try { const u = new URL(s); return u.protocol === 'http:' || u.protocol === 'https:'; } catch { return false; } }
function hostnameOf(s) { try { return new URL(s).hostname.toLowerCase().replace(/^www\./, ''); } catch { return ''; } }
function str(v, max = 500) { return typeof v === 'string' ? v.trim().slice(0, max) : ''; }
function oneOf(v, list, fallback) { return list.includes(v) ? v : fallback; }

/* ---------- CSV ---------- */
function parseCsv(text) {
  const rows = []; let row = [], cell = '', inQ = false;
  const src = String(text || '').replace(/\r\n/g, '\n');
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inQ) {
      if (c === '"') { if (src[i + 1] === '"') { cell += '"'; i++; } else inQ = false; }
      else cell += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; }
    else cell += c;
  }
  row.push(cell); if (row.length > 1 || row[0] !== '') rows.push(row);
  return rows.filter((r) => !(r.length === 1 && r[0] === ''));
}
function csvEscape(v) { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
function toCsv(headers, rows) {
  return [headers.join(','), ...rows.map((r) => headers.map((h) => csvEscape(r[h])).join(','))].join('\n') + '\n';
}

/* ---------- Minimal ZIP (store) + XLSX ---------- */
function crc32(buf) {
  let table = crc32.table;
  if (!table) { table = crc32.table = new Int32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; table[n] = c; } }
  let c = 0xffffffff; for (let i = 0; i < buf.length; i++) c = table[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0;
}
function zipStore(files) { // files: [{name, data:Buffer}]
  const chunks = [], central = []; let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name); const crc = crc32(f.data);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(f.data.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(name.length, 26);
    chunks.push(lh, name, f.data);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(f.data.length, 20); ch.writeUInt32LE(f.data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
    central.push(ch, name); offset += 30 + name.length + f.data.length;
  }
  const cd = Buffer.concat(central); const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...chunks, cd, end]);
}
function toXlsx(sheetName, headers, rows) {
  const esc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const cell = (v) => `<c t="inlineStr"><is><t>${esc(v)}</t></is></c>`;
  const sheetRows = [[...headers], ...rows.map((r) => headers.map((h) => r[h]))]
    .map((r) => `<row>${r.map(cell).join('')}</row>`).join('');
  const files = [
    { name: '[Content_Types].xml', data: Buffer.from('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>') },
    { name: '_rels/.rels', data: Buffer.from('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>') },
    { name: 'xl/workbook.xml', data: Buffer.from(`<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="${esc(sheetName).slice(0, 31)}" sheetId="1" r:id="rId1"/></sheets></workbook>`) },
    { name: 'xl/_rels/workbook.xml.rels', data: Buffer.from('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>') },
    { name: 'xl/worksheets/sheet1.xml', data: Buffer.from(`<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${sheetRows}</sheetData></worksheet>`) },
  ];
  return zipStore(files);
}

/* ---------- Minimal printable PDF (text lines) ---------- */
function toPdf(title, lines) {
  const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)').slice(0, 160);
  const pages = []; const perPage = 45;
  const all = [title, '', ...lines];
  for (let i = 0; i < all.length; i += perPage) {
    const chunk = all.slice(i, i + perPage);
    const content = 'BT /F1 10 Tf 50 790 Td 14 TL ' + chunk.map((l) => `(${esc(l)}) Tj T*`).join(' ') + ' ET';
    pages.push(content);
  }
  if (!pages.length) pages.push('BT /F1 10 Tf 50 790 Td (No data) Tj ET');
  const objs = ['<< /Type /Catalog /Pages 2 0 R >>'];
  const kids = pages.map((_, i) => `${4 + i * 2} 0 R`).join(' ');
  objs.push(`<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>`);
  objs.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  pages.forEach((content, i) => {
    objs.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${5 + i * 2} 0 R >>`);
    objs.push(`<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`);
  });
  let pdf = '%PDF-1.4\n'; const offsets = [0];
  objs.forEach((o, i) => { offsets.push(Buffer.byteLength(pdf)); pdf += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xrefPos = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offsets.slice(1).map((o) => String(o).padStart(10, '0') + ' 00000 n \n').join('');
  pdf += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF`;
  return Buffer.from(pdf);
}

module.exports = { now, uid, sha256, escapeHtml, isEmail, isUrl, hostnameOf, str, oneOf, parseCsv, toCsv, toXlsx, toPdf };
