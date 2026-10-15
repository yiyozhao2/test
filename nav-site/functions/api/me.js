import { json, isAuthed } from '../_utils.js';

// GET /api/me —— 前端判断当前是否已登录
export async function onRequest({ request, env }) {
  const authed = await isAuthed(request, env);
  return json({ authed });
}
