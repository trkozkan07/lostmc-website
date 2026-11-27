import { getStore } from '@netlify/blobs';
import { randomBytes, scryptSync, timingSafeEqual, createHmac, randomUUID } from 'node:crypto';

export const config = { path: '/api/*' };

const COLS = ['users', 'posts', 'gallery', 'tickets', 'chat', 'settings'];
const MANAGER_MIN = 5;
const PRESIDENT = 9;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const fail = (status, error) => json({ error }, status);

const store = () => getStore({ name: 'lostmc', consistency: 'strong' });

async function getSecret(s) {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  let sec = await s.get('meta/secret');
  if (!sec) { sec = randomBytes(32).toString('hex'); await s.set('meta/secret', sec); }
  return sec;
}
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function sign(secret, uid) {
  const body = b64({ uid, exp: Date.now() + 1000 * 60 * 60 * 24 * 30 });
  return body + '.' + createHmac('sha256', secret).update(body).digest('base64url');
}
function verify(secret, token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const exp = createHmac('sha256', secret).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(exp);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p.uid : null; } catch { return null; }
}
function hashPw(pw) {
  const salt = randomBytes(16).toString('hex');
  return salt + ':' + scryptSync(pw, salt, 32).toString('hex');
}
function checkPw(pw, stored) {
  const [salt, h] = String(stored || '').split(':');
  if (!salt || !h) return false;
  const a = Buffer.from(scryptSync(pw, salt, 32).toString('hex')), b = Buffer.from(h);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function readCol(s, col) {
  const { blobs } = await s.list({ prefix: `col/${col}/` });
  const rows = await Promise.all(blobs.map(async (b) => {
    const d = await s.get(b.key, { type: 'json' });
    return d ? { id: b.key.split('/')[2], ...d } : null;
  }));
  return rows.filter(Boolean);
}
const getRev = async (s, col) => (await s.get(`rev/${col}`)) || '0';
const bump = (s, col) => s.set(`rev/${col}`, String(Date.now()) + Math.random().toString(36).slice(2, 6));
const readDoc = (s, col, id) => s.get(`col/${col}/${id}`, { type: 'json' });
const writeDoc = async (s, col, id, data) => { await s.setJSON(`col/${col}/${id}`, data); await bump(s, col); };

const publicUser = (u) => { if (!u) return u; const { passwordHash, ...rest } = u; return rest; };
const clean = (col, rows) => (col === 'users' ? rows.map(publicUser) : rows);
const isManager = (u) => u && Number(u.rank) >= MANAGER_MIN;
const validId = (id) => /^[A-Za-z0-9_-]{1,80}$/.test(id || '');

export default async (req) => {
  const s = store();
  const url = new URL(req.url);
  const parts = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
  const method = req.method;
  const secret = await getSecret(s);

  if (parts[0] === 'ping') return json({ ok: true });

  let body = {};
  if (method !== 'GET' && method !== 'DELETE') { try { body = await req.json(); } catch {} }

  // Giriş / Kayıt
  if (parts[0] === 'register' && method === 'POST') {
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const rpName = String(body.rpName || '').trim().slice(0, 60);
    if (!/^\S+@\S+\.\S+$/.test(email)) return fail(400, 'Geçerli bir e-posta girin.');
    if (password.length < 4) return fail(400, 'Şifre en az 4 karakter olmalı.');
    if (!rpName) return fail(400, 'Karakter adı girin.');
    const users = await readCol(s, 'users');
    if (users.some((u) => (u.email || '').toLowerCase() === email)) return fail(409, 'Bu e-posta zaten kayıtlı.');
    const hasPres = users.some((u) => !u.isDemo && Number(u.rank) === PRESIDENT);
    const id = randomUUID();
    const user = {
      email, passwordHash: hashPw(password), rpName,
      avatar: String(body.avatar || ''), rank: hasPres ? 0 : PRESIDENT,
      showOnPolaroid: false, polaroidImage: '', polaroidNote: '', isDemo: false, createdAt: Date.now(),
    };
    await writeDoc(s, 'users', id, user);
    return json({ token: sign(secret, id), user: publicUser({ id, ...user }) });
  }
  if (parts[0] === 'login' && method === 'POST') {
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const users = await readCol(s, 'users');
    const u = users.find((x) => (x.email || '').toLowerCase() === email);
    if (!u) return fail(401, 'Hesap bulunamadı.');
    if (!checkPw(password, u.passwordHash)) return fail(401, 'Şifre hatalı.');
    return json({ token: sign(secret, u.id), user: publicUser(u) });
  }

  // Kimlik gerekli
  const auth = req.headers.get('authorization') || '';
  const uid = verify(secret, auth.replace(/^Bearer\s+/i, ''));
  const me = uid && validId(uid) ? await readDoc(s, 'users', uid) : null;
  const actor = me ? { id: uid, ...me } : null;

  if (parts[0] === 'me') return actor ? json({ user: publicUser(actor) }) : fail(401, 'Oturum geçersiz.');

  if (parts[0] === 'sync' && method === 'GET') {
    let revs = {};
    try { revs = JSON.parse(url.searchParams.get('revs') || '{}'); } catch {}
    const out = {};
    await Promise.all(COLS.map(async (col) => {
      const rev = await getRev(s, col);
      if (revs[col] !== rev) out[col] = { rev, rows: clean(col, await readCol(s, col)) };
    }));
    return json(out);
  }

  const col = parts[1];
  if (!COLS.includes(col)) return fail(404, 'Bulunamadı.');
  if (!actor) return fail(401, 'Önce giriş yapın.');

  // Yeni kayıt ekle
  if (parts[0] === 'col' && method === 'POST') {
    if (col === 'users') return fail(403, 'Üyelik için kayıt olun.');
    if (col === 'settings' && !isManager(actor)) return fail(403, 'Yetkiniz yok.');
    const id = randomUUID();
    const data = { ...body, authorId: actor.id };
    delete data.id;
    await writeDoc(s, col, id, data);
    return json({ id });
  }

  if (parts[0] === 'doc' && validId(parts[2])) {
    const id = parts[2];
    const cur = await readDoc(s, col, id);

    if (method === 'DELETE') {
      if (!cur) return json({ ok: true });
      if (col === 'users' || col === 'settings') return fail(403, 'Yetkiniz yok.');
      const own = cur.authorId === actor.id || cur.userId === actor.id;
      if (!own && !isManager(actor)) return fail(403, 'Yetkiniz yok.');
      await s.delete(`col/${col}/${id}`); await bump(s, col);
      return json({ ok: true });
    }

    if (method === 'PUT') {
      const patch = { ...(body.data || {}) };
      delete patch.id; delete patch.passwordHash; delete patch.email;
      if (col === 'settings') {
        if (!isManager(actor)) return fail(403, 'Yetkiniz yok.');
      } else if (col === 'users') {
        if (!cur) return fail(404, 'Üye yok.');
        if ('rank' in patch) {
          const nr = Number(patch.rank);
          const isSelf = id === actor.id;
          const ok = isManager(actor) && !isSelf && Number(cur.rank) < Number(actor.rank) + (Number(actor.rank) === PRESIDENT ? 1 : 0)
            && (nr < Number(actor.rank) || Number(actor.rank) === PRESIDENT);
          if (!ok) return fail(403, 'Rütbe değiştirme yetkiniz yok.');
          patch.rank = nr;
        }
        if (id !== actor.id) {
          const keys = Object.keys(patch).filter((k) => k !== 'rank');
          if (keys.length && !isManager(actor)) return fail(403, 'Yetkiniz yok.');
        }
      } else if (cur && col !== 'chat') {
        // Yorum/cevap eklemek herkese açık; başlık/içerik/durum düzenleme sahibi veya yöneticiye ait
        const own = cur.authorId === actor.id || cur.userId === actor.id;
        const onlyThread = Object.keys(patch).every((k) => k === 'comments' || k === 'replies');
        if (!own && !isManager(actor) && !onlyThread) return fail(403, 'Yetkiniz yok.');
      }
      const next = { ...(cur || {}), ...patch };
      if (!cur && col !== 'settings') return fail(404, 'Kayıt yok.');
      await writeDoc(s, col, id, next);
      return json({ ok: true });
    }
  }
  return fail(404, 'Bulunamadı.');
};
