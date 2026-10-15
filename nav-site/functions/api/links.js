import { kv, json, isAuthed } from '../_utils.js';

// GET /api/links —— 列出所有网址（需登录）
export async function onRequestGet({ request, env }) {
  if (!(await isAuthed(request, env))) {
    return json({ error: '未授权' }, 401);
  }
  const links = (await kv(env).get('links', 'json')) || [];
  return json(links);
}

// POST /api/links —— 新增网址（需登录）
export async function onRequestPost({ request, env }) {
  if (!(await isAuthed(request, env))) {
    return json({ error: '未授权' }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: '请求格式错误' }, 400);
  }

  const name = (body.name || '').trim();
  let url = (body.url || '').trim();
  if (!name || !url) {
    return json({ error: '名称和网址必填' }, 400);
  }
  // 补全协议
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  const links = (await kv(env).get('links', 'json')) || [];
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
  await kv(env).put('links', JSON.stringify(links));
  return json(link, 201);
}
