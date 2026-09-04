/* TST-005 정탐 시험용 취약 JavaScript 샘플 — 의도적으로 취약하게 작성된 코드다 (SFR-011).
 *
 * 실행하거나 참고용으로 복사하지 말 것. catalog/rules/js_*.yaml의 KISA 룰 30개가 각각
 * 정확히 걸리는지 확인하는 고정 자산이며, 안전한 대응 코드는 safe.js에 있다. Node(Express)
 * 서버 코드와 브라우저 코드를 한 파일에 둔다. 기대 건수는 catalog/tests.py
 * EXPECTED_JS_SAMPLE_FINDINGS.
 *
 * 우리 SAST로 우리 코드를 분석할 때(도그푸딩·CI 게이트) 당연히 탐지된다 —
 * 분석 대상에서 catalog/samples/를 제외하고 돌려야 한다.
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec, spawn } = require('child_process');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const serialize = require('node-serialize');
const app = express();

// 운영 DB: password = Passw0rd!                                   // SF-13
const dbPassword = 'hunter2';                                        // SF-06 #1
const config = { apiKey: 'AKIA0123456789EXAMPLE' };                  // SF-06 #2

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = ' + id);                  // IV-01 #1
  db.query(`DELETE FROM users WHERE name = '${id}'`);                // IV-01 #2

  eval(req.query.expr);                                              // IV-02 #1
  new Function('a', req.body.code);                                  // IV-02 #2

  fs.readFile(req.query.file, 'utf8', () => {});                     // IV-03 #1
  res.sendFile(path.join(__dirname, req.params.name));               // IV-03 #2

  exec('ping -c 1 ' + req.query.host);                               // IV-05 #1
  spawn('sh', ['-c', req.body.cmd]);                                 // IV-05 #2

  res.redirect(req.query.next);                                      // IV-07 #1

  axios.get(req.query.url);                                          // IV-12 #1
  fetch('http://internal/' + id);                                    // IV-12 #2

  res.send('<h1>Hello ' + req.query.name + '</h1>');                 // IV-04 #1
  res.write(req.body.html);                                          // IV-04 #2

  res.setHeader('X-User', req.query.user);                           // IV-13 #1
  res.cookie('lang', req.body.lang);                                 // IV-13 #2

  if (req.query.role === 'admin') { }                                // IV-15 #1 (동등 비교)
  if (req.body.isAdmin) { }                                          // IV-15 #2 (진리값 분기)
  const name = req.query.name.trim();                                // CE-01 #1
  document.getElementById('out').value = name;                      // CE-01 #2

  res.cookie('session_token', id, { maxAge: 30 * 24 * 3600 * 1000 }); // SF-12

  const decoded = jwt.decode(req.headers.authorization);
  if (decoded.admin) { }                                             // SF-10 #1
  jwt.verify(id, 'k', { algorithms: ['HS256', 'none'] });            // SF-10 #2

  try { fs.readFileSync('/etc/x'); } catch (e) { }                   // EH-03 #1
  promise.catch(() => {});                                           // EH-03 #2
  try { db.run(); } catch (err) {
    res.status(500).send(err.stack);                                 // EH-01 #1
    res.json({ error: err.message });                                // EH-01 #2
  }
});

function cryptoStuff(password) {
  const md5 = crypto.createHash('md5');                              // SF-04 #1
  const des = crypto.createCipheriv('des-cbc', key, iv);             // SF-04 #2
  const hash = crypto.createHash('sha256').update(password).digest('hex'); // SF-14
  crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });        // SF-07
  const token = Math.random().toString(36).slice(2);                 // SF-08 #1
  session.secret = Math.random();                                    // SF-08 #2
  https.get('https://x', { rejectUnauthorized: false });             // SF-11 #1
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';                    // SF-11 #2
}

function files(p, upload) {
  fs.chmodSync(p, 0o777);                                            // SF-03 #1
  fs.writeFileSync(p, 'x', { mode: 0o666 });                         // SF-03 #2
  process.umask(0);                                                  // SF-03 #3
  if (fs.existsSync(p)) {
    fs.writeFileSync(p, 'data');                                     // TS-01
  }
  const fd = fs.openSync(p, 'r');                                    // CE-02
  fs.readSync(fd, Buffer.alloc(10));
  fs.writeFileSync(path.join('/uploads', upload.originalname), upload.buffer); // IV-06
}

function client() {
  const el = document.getElementById('box');
  el.innerHTML = location.hash.slice(1);                             // IV-04 #3
  document.write(location.search);                                  // IV-04 #4
  window.location.href = new URLSearchParams(location.search).get('next'); // IV-07 #2
  debugger;                                                          // EN-02
  const b = new Buffer(10);                                          // AA-02
  const obj = serialize.unserialize(location.hash);                  // CE-05
  libxmljs.parseXml(xml, { noent: true });                           // IV-08
  client.search('ou=people', { filter: '(uid=' + user + ')' });      // IV-10
}
