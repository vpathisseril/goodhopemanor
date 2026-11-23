'use strict';
/**
 * Minimal route table. Each route is
 *   {methods: ['GET', ...], path: '/exact/path' | /^regex-with-(groups)$/, handler(req, res, params)}
 * where params are the regex capture groups. Routes are tried in order; the first match wins.
 */
function findRoute(routes, method, pathname) {
  for (const route of routes) {
    if (!route.methods.includes(method)) continue;
    if (typeof route.path === 'string') {
      if (route.path === pathname) return {route, params: []};
      continue;
    }
    const match = route.path.exec(pathname);
    if (match) return {route, params: match.slice(1)};
  }
  return null;
}

module.exports = {findRoute};
