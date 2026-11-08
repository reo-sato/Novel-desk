// Novel Desk - Featherless API を使った小説執筆ツール（ローカル専用サーバー）
// 追加インストール不要。Node.js 18 以上で動きます。
//   node server.js        … このPCからだけ開ける（start.bat）
//   node server.js --lan  … 同じWi-Fiのスマホからも開ける。パスワード必須（start-lan.bat）
'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');

const LAN = process.argv.includes('--lan') || process.env.LAN === '1';
const PORT = Number(process.env.PORT) || 8010;
const HOST = LAN ? '0.0.0.0' : '127.0.0.1';
const UPSTREAM = (process.env.FEATHERLESS_BASE || 'https://api.featherless.ai/v1').replace(/\/+$/, '');
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'novel-desk.json');
const BACKUP_FILE = path.join(DATA_DIR, 'novel-desk.backup.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const COOKIE = 'nd_session';
const VERSION_FILE = path.join(ROOT, 'version.json');
const RESTART_CODE = 75; // start.bat / start-lan.bat はこの終了コードで再起動する

if (typeof fetch !== 'function') {
  console.error('Node.js 18 以上が必要です。今のバージョン: ' + process.version);
  process.exit(1);
}

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------------- 共通 ---------------- */
function readBody(req, limit = 50 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('データが大きすぎます')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function sendJson(res, status, obj, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function readJsonFile(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return fallback; }
}
function writeJsonFile(file, obj) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, typeof obj === 'string' ? obj : JSON.stringify(obj), 'utf8');
  fs.renameSync(tmp, file);
}
function isLocal(req) {
  const a = req.socket.remoteAddress || '';
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
}
function lanUrls() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const n of list || []) {
      if (n.family === 'IPv4' && !n.internal) out.push('http://' + n.address + ':' + PORT + '/');
    }
  }
  return out;
}

/* ---------------- パスワード・ログイン ---------------- */
function loadAuth() { return readJsonFile(AUTH_FILE, { salt: '', hash: '', tokens: [] }); }
function hashPw(pw, salt) { return crypto.scryptSync(String(pw), salt, 32).toString('hex'); }
function passwordSet() { const a = loadAuth(); return !!(a.salt && a.hash); }
function checkPw(pw) {
  const a = loadAuth();
  if (!a.salt || !a.hash) return false;
  const h = Buffer.from(hashPw(pw, a.salt), 'hex');
  const s = Buffer.from(a.hash, 'hex');
  return h.length === s.length && crypto.timingSafeEqual(h, s);
}
function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
}
function validSession(req) {
  const t = getCookie(req, COOKIE);
  if (!t) return false;
  const a = loadAuth();
  const th = crypto.createHash('sha256').update(t).digest('hex');
  return (a.tokens || []).includes(th);
}
function newSession() {
  const a = loadAuth();
  const t = crypto.randomBytes(24).toString('hex');
  a.tokens = [crypto.createHash('sha256').update(t).digest('hex'), ...(a.tokens || [])].slice(0, 20);
  writeJsonFile(AUTH_FILE, a);
  return t;
}
const fails = new Map(); // ip -> { n, until }
function locked(ip) { const f = fails.get(ip); return f && f.until > Date.now(); }
function addFail(ip) {
  const f = fails.get(ip) || { n: 0, until: 0 };
  f.n += 1;
  if (f.n >= 5) { f.until = Date.now() + 5 * 60 * 1000; f.n = 0; }
  fails.set(ip, f);
}

function loginPage(message) {
  const ready = passwordSet();
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Novel Desk</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#16151a;color:#e8e4dc;
font-family:"Yu Gothic UI","Hiragino Sans","Meiryo",system-ui,sans-serif;padding:16px;box-sizing:border-box}
.box{width:100%;max-width:360px;background:#1e1d23;border:1px solid #34323b;border-radius:14px;padding:24px}
h1{font-family:"Yu Mincho","Hiragino Mincho ProN",serif;color:#c9a26b;font-weight:400;letter-spacing:.08em;margin:0 0 18px;font-size:22px}
input{width:100%;box-sizing:border-box;font-size:16px;padding:10px 12px;background:#1b1a1f;color:inherit;border:1px solid #34323b;border-radius:8px}
button{width:100%;margin-top:12px;font-size:16px;padding:10px;border-radius:8px;border:1px solid #c9a26b;background:#c9a26b;color:#1b1710;font-weight:700}
p{color:#9a958c;font-size:14px;line-height:1.7}.err{color:#d4766b}
</style></head><body><div class="box"><h1>Novel Desk</h1>
${ready ? `<form method="post" action="/login">
<p>パスワードを入力してください。</p>
<input type="password" name="password" autocomplete="current-password" autofocus required>
<button type="submit">ログイン</button></form>` :
`<p>まだパスワードが設定されていません。<br>PCで Novel Desk を開き、「⚙ 接続設定」→「スマホから使う」でパスワードを設定してから、このページを開き直してください。</p>`}
${message ? `<p class="err">${message}</p>` : ''}
</div></body></html>`;
}

async function handleLogin(req, res) {
  const ip = req.socket.remoteAddress || '';
  if (locked(ip)) {
    res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(loginPage('失敗が続いたため、5分間ログインできません。'));
  }
  const body = await readBody(req, 10000);
  const pw = new URLSearchParams(body).get('password') || '';
  if (checkPw(pw)) {
    fails.delete(ip);
    const t = newSession();
    res.writeHead(303, {
      'Set-Cookie': `${COOKIE}=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${60 * 60 * 24 * 365}`,
      Location: '/',
    });
    return res.end();
  }
  addFail(ip);
  res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(loginPage('パスワードが違います。'));
}

async function handleSetPassword(req, res) {
  if (!isLocal(req)) return sendJson(res, 403, { error: { message: 'パスワードの変更はPCからだけできます' } });
  const { password } = JSON.parse(await readBody(req, 10000) || '{}');
  if (!password || String(password).length < 6) return sendJson(res, 400, { error: { message: 'パスワードは6文字以上にしてください' } });
  const salt = crypto.randomBytes(16).toString('hex');
  writeJsonFile(AUTH_FILE, { salt, hash: hashPw(password, salt), tokens: [] }); // 変更したら全端末ログアウト
  sendJson(res, 200, { ok: true });
}

/* ---------------- データ ---------------- */
function loadData() { return readJsonFile(DATA_FILE, null); }
function storedKey() { const d = loadData(); return (d && d.settings && d.settings.apiKey) || ''; }

// 作品ごとに保存する項目（ここにない項目は保存しない）
const WORK_FIELDS = ['title', 'style', 'sample', 'world', 'characters', 'plot', 'plotRequest', 'outline', 'outlineRequest', 'summary',
  'body', 'instruction', 'target', 'goal'];

function normalized(d) {
  d = d || {};
  return {
    rev: d.rev || 0,
    settings: d.settings || {},
    works: Array.isArray(d.works) ? d.works : [],
    deleted: Array.isArray(d.deleted) ? d.deleted : [],
    currentId: d.currentId || null, // 旧バージョンのデータとの互換用
  };
}
function publicData(d) {
  // APIキーとGitHubトークンはブラウザに渡さない
  const settings = { ...d.settings, apiKeySet: !!d.settings.apiKey, apiKey: '',
    githubTokenSet: !!d.settings.githubToken, githubToken: '' };
  return { rev: d.rev, settings, works: d.works, currentId: d.currentId };
}

function handleLoad(res) {
  const raw = loadData();
  if (!raw) return sendJson(res, 200, null);
  sendJson(res, 200, publicData(normalized(raw)));
}

// 端末から「変更した項目だけ」を受け取り、最新の保存データに合流させる。
// 古い画面の端末が、別の端末で書き換えた項目を上書きしないようにするため。
async function handleSync(req, res) {
  let inc;
  try { inc = JSON.parse(await readBody(req)); } catch (e) {
    return sendJson(res, 400, { error: { message: '保存データの形式が正しくありません' } });
  }
  const d = normalized(loadData());
  let changed = false;

  for (const id of inc.deleted || []) {
    const before = d.works.length;
    d.works = d.works.filter((w) => w.id !== id);
    if (!d.deleted.includes(id)) d.deleted.push(id);
    if (d.works.length !== before) changed = true;
  }
  d.deleted = d.deleted.slice(-500);

  for (const ch of inc.changes || []) {
    if (!ch || typeof ch.id !== 'string' || d.deleted.includes(ch.id)) continue;
    let w = d.works.find((x) => x.id === ch.id);
    let touched = false;
    if (!w) { w = { id: ch.id }; d.works.push(w); touched = true; }
    for (const f of WORK_FIELDS) {
      if (ch.fields && Object.prototype.hasOwnProperty.call(ch.fields, f) && w[f] !== ch.fields[f]) {
        w[f] = ch.fields[f];
        touched = true;
      }
    }
    if (touched) { w.updatedAt = Date.now(); changed = true; }
  }

  for (const [k, v] of Object.entries(inc.settings || {})) {
    if (k === 'apiKeySet') continue;
    if (k === 'apiKey' || k === 'githubToken') {
      const key = String(v || '').trim();
      if (key === '-') { if (d.settings[k]) { d.settings[k] = ''; changed = true; } continue; } // 「-」で削除
      if (key && key !== d.settings[k]) { d.settings[k] = key; changed = true; }
      continue;
    }
    if (k === 'githubTokenSet') continue;
    if (d.settings[k] !== v) { d.settings[k] = v; changed = true; }
  }

  if (changed) {
    d.rev += 1;
    try {
      if (fs.existsSync(DATA_FILE)) fs.copyFileSync(DATA_FILE, BACKUP_FILE);
      writeJsonFile(DATA_FILE, JSON.stringify(d));
    } catch (e) {
      return sendJson(res, 500, { error: { message: '保存できませんでした: ' + e.message } });
    }
  }
  if (!changed && inc.knownRev === d.rev) return sendJson(res, 200, { same: true, rev: d.rev });
  sendJson(res, 200, publicData(d));
}

async function handleChat(req, res) {
  let parsed;
  try { parsed = JSON.parse(await readBody(req)); } catch (e) {
    return sendJson(res, 400, { error: { message: 'リクエストの形式が正しくありません' } });
  }
  const payload = parsed && parsed.payload;
  const apiKey = String((parsed && parsed.apiKey) || '').trim() || storedKey();
  if (!apiKey) return sendJson(res, 400, { error: { message: 'APIキーが設定されていません（「⚙ 接続設定」から入力してください）' } });
  if (!payload || !payload.model) return sendJson(res, 400, { error: { message: 'モデルIDが設定されていません' } });

  const ac = new AbortController();
  res.on('close', () => { if (!res.writableEnded) ac.abort(); }); // 「停止」で Featherless 側も止める

  let upstream;
  try {
    upstream = await fetch(UPSTREAM + '/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + apiKey,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'http://127.0.0.1:' + PORT + '/',
        'X-Title': 'Novel Desk',
      },
      body: JSON.stringify(payload),
      signal: ac.signal,
    });
  } catch (e) {
    if (ac.signal.aborted) return;
    return sendJson(res, 502, { error: { message: 'Featherless に接続できませんでした: ' + e.message } });
  }
  res.writeHead(upstream.status, {
    'Content-Type': upstream.headers.get('content-type') || 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Accel-Buffering': 'no',
  });
  try {
    if (upstream.body) for await (const chunk of upstream.body) res.write(chunk);
    res.end();
  } catch (e) {
    if (!res.writableEnded) res.end();
  }
}

/* ---------------- アップデート（GitHubから最新版を取得） ---------------- */
function localVersion() { return readJsonFile(VERSION_FILE, { version: '0.0.0', repo: '', branch: 'main', files: [] }); }
function cmpVer(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
}
async function ghFile(repo, branch, name) {
  const d = loadData();
  const token = d && d.settings && d.settings.githubToken;
  const headers = { Accept: 'application/vnd.github.raw', 'User-Agent': 'novel-desk-updater' };
  if (token) headers.Authorization = 'Bearer ' + token;
  const url = (process.env.GH_API || 'https://api.github.com') + '/repos/' + repo + '/contents/' + encodeURIComponent(name) + '?ref=' + encodeURIComponent(branch);
  const r = await fetch(url, { headers });
  if (r.status === 404) throw new Error(token ? 'GitHubにファイルが見つかりません（リポジトリ名かトークンの権限を確認）' : 'GitHubにファイルが見つかりません（非公開リポジトリならトークンが必要です）');
  if (r.status === 401) throw new Error('GitHubトークンが正しくありません');
  if (r.status === 403) throw new Error('GitHubへの問い合わせ回数の上限です。しばらく待ってから試してください');
  if (!r.ok) throw new Error('GitHubからの取得に失敗しました（' + r.status + '）');
  return Buffer.from(await r.arrayBuffer());
}
async function remoteVersion() {
  const lv = localVersion();
  if (!lv.repo) throw new Error('version.json に更新元のリポジトリが書かれていません');
  const rv = JSON.parse((await ghFile(lv.repo, lv.branch || 'main', 'version.json')).toString('utf8'));
  return { lv, rv };
}
async function handleUpdateCheck(res) {
  try {
    const { lv, rv } = await remoteVersion();
    sendJson(res, 200, { current: lv.version, latest: rv.version, notes: rv.notes || '', available: cmpVer(rv.version, lv.version) > 0 });
  } catch (e) {
    sendJson(res, 200, { current: localVersion().version, error: e.message });
  }
}
let updating = false;
async function handleUpdateApply(res) {
  if (updating) return sendJson(res, 409, { error: { message: 'アップデート中です' } });
  updating = true;
  try {
    const { lv, rv } = await remoteVersion();
    if (cmpVer(rv.version, lv.version) <= 0) { updating = false; return sendJson(res, 200, { ok: true, upToDate: true }); }
    // ファイル名だけを許可（フォルダの外や data フォルダには書かない）。.bat は動いている最中に書き換えると壊れるので対象外
    const names = (rv.files || []).filter((n) => /^[\w.-]+$/.test(n) && !/\.bat$/i.test(n) && n !== 'data');
    if (!names.includes('version.json')) names.push('version.json');
    const got = {};
    for (const n of names) got[n] = await ghFile(lv.repo, lv.branch || 'main', n);
    for (const [n, buf] of Object.entries(got)) if (!buf.length) throw new Error(n + ' が空でした');
    // 新しい server.js が壊れていないか確認してから入れ替える
    if (got['server.js']) {
      const tmp = path.join(DATA_DIR, 'server.check.js');
      fs.writeFileSync(tmp, got['server.js']);
      const r = require('child_process').spawnSync(process.execPath, ['--check', tmp]);
      fs.unlinkSync(tmp);
      if (r.status !== 0) throw new Error('新しい server.js に問題があるため、更新を中止しました');
    }
    const bdir = path.join(DATA_DIR, 'old-version-' + lv.version);
    fs.mkdirSync(bdir, { recursive: true });
    for (const n of Object.keys(got)) {
      const f = path.join(ROOT, n);
      if (fs.existsSync(f)) fs.copyFileSync(f, path.join(bdir, n));
    }
    for (const [n, buf] of Object.entries(got)) {
      const f = path.join(ROOT, n);
      fs.writeFileSync(f + '.new', buf);
      fs.renameSync(f + '.new', f);
    }
    const batChanged = !!rv.batVersion && rv.batVersion !== lv.batVersion; // 起動ファイルは手動で入れ替えが必要
    sendJson(res, 200, { ok: true, version: rv.version, restarting: true, batChanged: !!batChanged });
    console.log('');
    console.log('  バージョン ' + rv.version + ' に更新しました。再起動します…（以前のファイルは data/' + path.basename(bdir) + ' にあります）');
    setTimeout(() => process.exit(RESTART_CODE), 600);
  } catch (e) {
    updating = false;
    sendJson(res, 500, { error: { message: e.message } });
  }
}

/* ---------------- ルーティング ---------------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  try {
    // 他のサイトから勝手に操作されないようにする
    if (req.method === 'POST' && req.headers.origin) {
      let ok = false;
      try { ok = new URL(req.headers.origin).host === req.headers.host; } catch (_) {}
      if (!ok) return sendJson(res, 403, { error: { message: 'forbidden' } });
    }

    // 同じWi-Fiモードでは、PC以外からのアクセスにログインを求める
    const authed = !LAN || isLocal(req) || validSession(req);
    if (p === '/login') {
      if (req.method === 'POST') return await handleLogin(req, res);
      if (authed) { res.writeHead(303, { Location: '/' }); return res.end(); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(loginPage(''));
    }
    if (!authed) {
      if (p.startsWith('/api/')) return sendJson(res, 401, { needLogin: true, error: { message: 'ログインが必要です' } });
      res.writeHead(303, { Location: '/login' });
      return res.end();
    }

    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(fs.readFileSync(path.join(ROOT, 'index.html')));
    }
    if (req.method === 'GET' && p === '/api/info') {
      return sendJson(res, 200, { lan: LAN, urls: LAN ? lanUrls() : [], passwordSet: passwordSet(), isLocal: isLocal(req),
        version: localVersion().version, repo: localVersion().repo });
    }
    if (req.method === 'POST' && p === '/api/password') return await handleSetPassword(req, res);
    if (req.method === 'GET' && p === '/api/update/check') return await handleUpdateCheck(res);
    if (req.method === 'POST' && p === '/api/update/apply') return await handleUpdateApply(res);
    if (req.method === 'POST' && p === '/api/chat') return await handleChat(req, res);
    if (req.method === 'GET' && p === '/api/load') return handleLoad(res);
    if (req.method === 'POST' && p === '/api/sync') return await handleSync(req, res);
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  } catch (e) {
    if (!res.headersSent) sendJson(res, 500, { error: { message: e.message } });
    else if (!res.writableEnded) res.end();
  }
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error('ポート ' + PORT + ' はすでに使われています。Novel Desk がもう起動していないか確認してください。');
    console.error('（start.bat と start-lan.bat は同時に起動できません。片方を閉じてください）');
  } else {
    console.error(e);
  }
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  const local = 'http://127.0.0.1:' + PORT + '/';
  console.log('');
  console.log('  Novel Desk を起動しました: ' + local);
  if (LAN) {
    console.log('');
    console.log('  【同じWi-Fiモード】スマホのブラウザでは次のどれかを開いてください:');
    const urls = lanUrls();
    if (urls.length) urls.forEach((u) => console.log('    ' + u));
    else console.log('    （ネットワークが見つかりません。Wi-Fiにつながっているか確認してください）');
    if (!passwordSet()) {
      console.log('');
      console.log('  ※まだパスワードがありません。PCの画面で「⚙ 接続設定」→「スマホから使う」で設定してください。');
    }
    console.log('  ※Windowsのファイアウォールの確認が出たら「プライベート ネットワーク」で「許可」を押してください。');
  }
  console.log('');
  console.log('  この黒い画面は閉じないでください（閉じると止まります）。');
  console.log('  ※画面内をクリックすると一時停止することがあります。その時は Esc キーで再開します。');
  console.log('');
  if (!process.env.NO_OPEN) {
    const cmd = process.platform === 'win32' ? 'start "" "' + local + '"'
      : process.platform === 'darwin' ? 'open "' + local + '"'
      : 'xdg-open "' + local + '"';
    exec(cmd, () => {});
  }
});
