import { json, sessionCookie } from '../_utils.js';

// POST /api/logout —— 清除会话 Cookie
export async function onRequestPost() {
  return json({ ok: true }, 200, {
    'Set-Cookie': sessionCookie('', 0),
  });
}
