/* TST-005 오탐 시험용 안전 JavaScript 샘플 — vulnerable.js의 각 취약점에 대한 올바른 대응 (SFR-011).
 *
 * 여기서 findings가 하나라도 나오면 룰이 과탐지하는 것이다(오탐). 정탐 못지않게
 * 중요한 기준이라 취약 샘플과 짝으로 유지한다. 이름 기준 룰(IV-15)이 오탐이 되기 쉬운
 * 케이스 — 검증 후 쓰는 price, 표시용 role — 를 일부러 넣어 실측한다.
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile, spawn, exec } = require('child_process');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const DOMPurify = require('dompurify');
const app = express();

// DB 비밀번호는 시크릿 저장소 APP_DB_PASSWORD 항목에 있다 (값을 여기 적지 말 것)
const dbPassword = process.env.APP_DB_PASSWORD;
const apiToken = '';
const config = { apiKey: process.env.API_KEY, timeout: 1000 };
const ALLOWED = new Set(['/home', '/profile']);
const ALLOWED_HOSTS = new Set(['api.example.com']);

app.get('/user', (req, res) => {
  const id = String(req.query.id || '');
  db.query('SELECT * FROM users WHERE id = ?', [id]);
  db.query('DELETE FROM users WHERE name = $1', [id]);

  setTimeout(() => refresh(), 1000);
  setTimeout(refresh, 1000);
  setTimeout(function () { refresh(); }, 1000);

  const base = path.resolve('/data');
  const target = path.resolve(base, path.basename(id));
  if (!target.startsWith(base + path.sep)) return res.sendStatus(400);
  fs.readFile(target, 'utf8', () => {});
  res.sendFile(path.join(__dirname, 'public', 'index.html'));

  execFile('ping', ['-c', '1', '127.0.0.1']);
  spawn('ls', ['-l']);
  exec('uptime');

  const next = String(req.query.next || '');
  res.redirect(ALLOWED.has(next) ? next : '/home');

  const u = new URL(String(req.query.url));
  if (ALLOWED_HOSTS.has(u.hostname)) axios.get(u.toString());
  fetch('https://api.example.com/status');

  res.send('static text');
  res.send(escapeHtml(String(req.query.name)));
  res.setHeader('X-Frame-Options', 'DENY');
  res.cookie('lang', 'ko');

  // IV-15 오탐 실측 — 권한은 서버 세션 값으로 결정한다.
  const sessionRole = req.session.role;
  if (sessionRole === 'admin') { }
  // IV-15 오탐 실측 — role이라는 이름이지만 화면 표시용으로만 쓴다.
  const role = req.query.role;
  res.render('profile', { roleLabel: escapeHtml(String(role)) });
  // IV-15 오탐 실측 — price를 검증 후 쓴다 (가격류는 룰 대상에서 제외).
  const price = Number(req.body.price);
  if (!Number.isFinite(price) || price < 0) return res.sendStatus(400);
  const total = price * 2;

  const name = String(req.query.name || '').trim();
  const el = document.getElementById('out');
  if (el) el.value = name;

  res.cookie('session_token', id, { httpOnly: true, secure: true }); // 만료 없음 = 세션 쿠키
  res.cookie('theme', 'dark', { maxAge: 30 * 24 * 3600 * 1000 });   // 민감 이름 아님

  const payload = jwt.verify(req.headers.authorization, process.env.JWT_KEY, { algorithms: ['HS256'] });
  if (payload.admin) { }

  try { fs.readFileSync('/etc/x'); } catch (e) { logger.warn('read failed', e); }
  promise.catch((e) => logger.error(e));
  try { db.run(); } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'internal error' });
  }
});

function cryptoStuff(password, salt) {
  const sha = crypto.createHash('sha256');
  const aes = crypto.createCipheriv('aes-256-gcm', key, iv);
  const hash = crypto.scryptSync(password, salt, 64);
  crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
  const token = crypto.randomBytes(32).toString('hex');
  const dice = Math.floor(Math.random() * 6) + 1;                     // 보안 용도 아님
  https.get('https://x', { rejectUnauthorized: true });
}

function files(p, upload) {
  fs.chmodSync(p, 0o600);
  fs.writeFileSync(p, 'x', { mode: 0o640 });
  process.umask(0o077);
  try { fs.writeFileSync(p, 'data', { flag: 'wx' }); } catch (e) { logger.warn(e); }
  const fd = fs.openSync(p, 'r');
  fs.readSync(fd, Buffer.alloc(10));
  fs.closeSync(fd);
  const safeName = crypto.randomUUID() + path.extname(upload.originalname).toLowerCase();
  if (!['.png', '.jpg'].includes(path.extname(safeName))) return;
  fs.writeFileSync(path.join('/uploads', safeName), upload.buffer);
}

function client() {
  const el = document.getElementById('box');
  el.textContent = location.hash.slice(1);
  el.innerHTML = DOMPurify.sanitize(userHtml);
  el.innerHTML = '';
  el.innerHTML = '<p>static</p>';
  const next = new URLSearchParams(location.search).get('next');
  if (next && next.startsWith('/') && !next.startsWith('//')) window.location.assign(next);
  const b = Buffer.alloc(10);
  const obj = JSON.parse(location.hash.slice(1) || '{}');
  libxmljs.parseXml(xml, { noent: false });
  client.search('ou=people', { filter: `(uid=${escapeLdap(user)})` });
}
