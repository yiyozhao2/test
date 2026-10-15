import { getCookie, verifyToken } from './_utils.js';

// 全局中间件：API 放行；受保护页面 /app.html 必须登录，否则跳回首页
export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);

  // API 由各自处理器校验权限，这里直接放行
  if (url.pathname.startsWith('/api/')) {
    return next();
  }

  // 受保护区域：导航主页
  const isProtected =
    url.pathname === '/app' ||
    url.pathname === '/app.html' ||
    url.pathname.startsWith('/app/');

  if (isProtected) {
    const token = getCookie(request, 'session');
    if (!token || !(await verifyToken(token, env.AUTH_SECRET))) {
      return Response.redirect(url.origin + '/', 302);
    }
  }

  return next();
}
