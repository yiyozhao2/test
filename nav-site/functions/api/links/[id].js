import { kv, json, isAuthed } from '../_utils.js';

// DELETE /api/links/:id —— 删除网址（需登录）
export async function onRequestDelete({ request, env, params }) {
  if (!(await isAuthed(request, env))) {
    return json({ error: '未授权' }, 401);
  }
  const links = (await kv(env).get('links', 'json')) || [];
  const next = links.filter((l) => l.id !== params.id);
  await kv(env).put('links', JSON.stringify(next));
  return json({ ok: true, removed: links.length - next.length });
}

// PUT /api/links/:id —— 编辑网址（需登录）
export async function onRequestPut({ request, env, params }) {
  if (!(await isAuthed(request, env))) {
    return json({ error: '未授权' }, 401);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: '请求格式错误' }, 400);
  }

  const links = (await kv(env).get('links', 'json')) || [];
  const idx = links.findIndex((l) => l.id === params.id);
  if (idx === -1) {
    return json({ error: '未找到该网址' }, 404);
  }
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
  await kv(env).put('links', JSON.stringify(links));
  return json(links[idx]);
}
