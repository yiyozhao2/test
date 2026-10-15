import { kv, hashPassword, signToken, sessionCookie, json } from '../_utils.js';

// POST /api/register —— 仅当 KV 中还没有 user 时允许注册（首次注册后关闭）
export async function onRequestPost({ request, env }) {
  const existing = await kv(env).get('user');
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
  if (!username || !password) {
    return json({ error: '用户名和密码必填' }, 400);
  }
  if (password.length < 6) {
    return json({ error: '密码至少 6 位' }, 400);
  }

  const salt = crypto.randomUUID();
  const hash = await hashPassword(password, salt);
  await kv(env).put('user', JSON.stringify({ username, salt, hash }));

  const token = await signToken('user', env.AUTH_SECRET);
  return json({ ok: true }, 200, {
    'Set-Cookie': sessionCookie(token),
  });
}
