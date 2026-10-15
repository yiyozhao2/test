import {
  hashPassword, signToken, verifyToken, getCookie, sessionCookie, json, isAuthed,
} from './lib.js';

// ---------- API 处理 ----------

async function handleRegister(request, env) {
  const existing = await env.NAV_KV.get('user');
  if (existing) {
    return json({ error: '注册已关闭，账号已存在，请直接登录' }, 403);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: '请求格式错误' }, 400);
  }
  const username = (body.username || '').trim();
  const password = body.password || '';
  if (!username || !password) return json({ error: '用户名和密码必填' }, 400);
  if (password.length < 6) return json({ error: '密码至少 6 位' }, 400);

  const salt = crypto.randomUUID();
  const hash = await hashPassword(password, salt);
  await env.NAV_KV.put('user', JSON.stringify({ username, salt, hash }));

  const token = await signToken('user', env.AUTH_SECRET);
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token) });
}

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: '请求格式错误' }, 400);
  }
  const username = (body.username || '').trim();
  const password = body.password || '';

  const raw = await env.NAV_KV.get('user');
  if (!raw) return json({ error: '尚未注册，请先注册' }, 400);

  const user = JSON.parse(raw);
  if (username !== user.username) return json({ error: '用户名或密码错误' }, 401);
  const hash = await hashPassword(password, user.salt);
  if (hash !== user.hash) return json({ error: '用户名或密码错误' }, 401);

  const token = await signToken('user', env.AUTH_SECRET);
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token) });
}

async function listLinks(request, env) {
  if (!(await isAuthed(request, env))) return json({ error: '未授权' }, 401);
  const links = (await env.NAV_KV.get('links', 'json')) || [];
  return json(links);
}

async function addLink(request, env) {
  if (!(await isAuthed(request, env))) return json({ error: '未授权' }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: '请求格式错误' }, 400);
  }
  const name = (body.name || '').trim();
  let url = (body.url || '').trim();
  if (!name || !url) return json({ error: '名称和网址必填' }, 400);
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  const links = (await env.NAV_KV.get('links', 'json')) || [];
  const link = {
    id: crypto.randomUUID(),
    name,
    url,
    icon: (body.icon || '').trim(),
    description: (body.description || '').trim(),
    group: (body.group || '默认').trim(),
    createdAt: Date.now(),
  };
  links.push(link);
  await env.NAV_KV.put('links', JSON.stringify(links));
  return json(link, 201);
}

async function updateLink(request, env, id) {
  if (!(await isAuthed(request, env))) return json({ error: '未授权' }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: '请求格式错误' }, 400);
  }
  const links = (await env.NAV_KV.get('links', 'json')) || [];
  const idx = links.findIndex((l) => l.id === id);
  if (idx === -1) return json({ error: '未找到该网址' }, 404);

  const cur = links[idx];
  let url = body.url !== undefined ? (body.url || '').trim() : cur.url;
  if (url && !/^https?:\/\//i.test(url)) url = 'https://' + url;
  links[idx] = {
    ...cur,
    name: (body.name ?? cur.name).toString().trim() || cur.name,
    url,
    icon: body.icon !== undefined ? (body.icon || '').trim() : cur.icon,
    description:
      body.description !== undefined ? (body.description || '').trim() : cur.description,
    group: body.group !== undefined ? (body.group || '默认').trim() : cur.group,
  };
  await env.NAV_KV.put('links', JSON.stringify(links));
  return json(links[idx]);
}

async function deleteLink(request, env, id) {
  if (!(await isAuthed(request, env))) return json({ error: '未授权' }, 401);
  const links = (await env.NAV_KV.get('links', 'json')) || [];
  const next = links.filter((l) => l.id !== id);
  await env.NAV_KV.put('links', JSON.stringify(next));
  return json({ ok: true, removed: links.length - next.length });
}

// ---------- 路由分发 ----------

async function handleApi(request, env, url) {
  const path = url.pathname;
  const method = request.method;

  if (path === '/api/status' && method === 'GET') {
    return json({ registered: !!(await env.NAV_KV.get('user')) });
  }
  if (path === '/api/me' && method === 'GET') {
    return json({ authed: await isAuthed(request, env) });
  }
  if (path === '/api/register' && method === 'POST') return handleRegister(request, env);
  if (path === '/api/login' && method === 'POST') return handleLogin(request, env);
  if (path === '/api/logout' && method === 'POST') {
    return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
  }

  if (path === '/api/links') {
    if (method === 'GET') return listLinks(request, env);
    if (method === 'POST') return addLink(request, env);
  }

  const m = path.match(/^\/api\/links\/([^/]+)$/);
  if (m) {
    if (method === 'DELETE') return deleteLink(request, env, m[1]);
    if (method === 'PUT') return updateLink(request, env, m[1]);
  }

  return json({ error: '接口不存在' }, 404);
}

// ---------- Worker 入口 ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/api/')) {
      return handleApi(request, env, url);
    }

    // 受保护页面：/app.html 未登录跳回首页
    if (path === '/app' || path === '/app.html' || path.startsWith('/app/')) {
      const token = getCookie(request, 'session');
      if (!token || !(await verifyToken(token, env.AUTH_SECRET))) {
        return Response.redirect(url.origin + '/', 302);
      }
    }

    // 其余交给静态资产
    return env.ASSETS.fetch(request);
  },
};
