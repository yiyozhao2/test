import { kv, json } from '../_utils.js';

// GET /api/status —— 前端用来判断「是否还能注册」
export async function onRequestGet({ env }) {
  const exists = !!(await kv(env).get('user'));
  return json({ registered: exists });
}
