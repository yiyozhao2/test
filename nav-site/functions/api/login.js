import { kv, hashPassword, signToken, sessionCookie, json } from '../_utils.js';

// POST /api/login —— 校验账号密码，成功下发会话 Cookie
export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: '请求格式错误' }, 400);
  }

  const username = (body.username || '').trim();
  const password = body.password || '';

  const raw = await kv(env).get('user');
  if (!raw) {
    return json({ error: '尚未注册，请先注册' }, 400);
  }

  const user = JSON.parse(raw);
  if (username !== user.username) {
    return json({ error: '用户名或密码错误' }, 401);
  }

  const hash = await hashPassword(password, user.salt);
  if (hash !== user.hash) {
    return json({ error: '用户名或密码错误' }, 401);
  }

  const token = await signToken('user', env.AUTH_SECRET);
  return json({ ok: true }, 200, {
    'Set-Cookie': sessionCookie(token),
  });
}
