const NAMES = new Set(['deberc']);
const MAX_BODY = 4 * 1024 * 1024;

const json = (status, body) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});

let keyHash = null;

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function authorised(request, env) {
  const key = env.DEBERC_KEY || '';
  if (!key) return false;
  if (keyHash === null) keyHash = await sha256Hex(key);
  const given = request.headers.get('x-deberc-key') || '';
  if (given.length !== keyHash.length) return false;
  let diff = 0;
  for (let i = 0; i < keyHash.length; i++) diff |= given.charCodeAt(i) ^ keyHash.charCodeAt(i);
  return diff === 0;
}

let tableReady = false;
async function ensureTable(env) {
  if (tableReady) return;
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS journal (
    name TEXT PRIMARY KEY, updated_at TEXT NOT NULL, doc TEXT NOT NULL)`).run();
  tableReady = true;
}

async function readDoc(env, name) {
  const row = await env.DB.prepare('SELECT doc FROM journal WHERE name = ?').bind(name).first();
  if (!row) return {};
  try {
    const doc = JSON.parse(row.doc);
    return doc && typeof doc === 'object' && !Array.isArray(doc) ? doc : {};
  } catch {
    return {};
  }
}

async function guard({ request, env, params }) {
  if (!NAMES.has(params.name)) return json(404, { error: 'unknown journal' });
  if (!(await authorised(request, env))) return json(401, { error: 'need key' });
  return null;
}

export async function onRequestGet(context) {
  const denied = await guard(context);
  if (denied) return denied;
  await ensureTable(context.env);
  return json(200, await readDoc(context.env, context.params.name));
}

export async function onRequestPut(context) {
  const denied = await guard(context);
  if (denied) return denied;
  const { request, env, params } = context;
  await ensureTable(env);
  if (Number(request.headers.get('content-length') || 0) > MAX_BODY) return json(413, { error: 'bad body length' });
  let incoming;
  try {
    incoming = await request.json();
  } catch {
    return json(400, { error: 'not json' });
  }
  if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) return json(400, { error: 'not an object' });
  const current = await readDoc(env, params.name);
  if (String(incoming.updatedAt || '') < String(current.updatedAt || '')) return json(409, current);
  await env.DB
    .prepare(`INSERT INTO journal (name, updated_at, doc) VALUES (?, ?, ?)
              ON CONFLICT(name) DO UPDATE SET updated_at = excluded.updated_at, doc = excluded.doc`)
    .bind(params.name, String(incoming.updatedAt || ''), JSON.stringify(incoming))
    .run();
  return json(200, { ok: true });
}