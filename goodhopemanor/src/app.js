'use strict';
const http = require('node:http');
const {loadConfig} = require('./config');
const {openDatabase} = require('./database');
const {randomToken, sameOrigin} = require('./security');
const {UploadError} = require('./uploads');
const {json, serveStatic} = require('./responses');
const {ApiError, nowISOString} = require('./http');
const {createContext} = require('./context');
const {findRoute} = require('./router');

const ALLOWED_METHODS = ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE'];

function logRequest(config, req, res, startedAt) {
  if (!config.production && process.env.ACCESS_LOG !== '1') return;
  // Replace ids so logs group by route and never carry document or user identifiers.
  const route = String(req.url || '/')
    .split('?')[0]
    .replace(/[a-f0-9-]{36}/gi, ':id')
    .slice(0, 160);
  console.log(
    JSON.stringify({
      level: 'info',
      event: 'http.request',
      route,
      method: req.method,
      status: res.statusCode,
      durationMs: Date.now() - startedAt,
    }),
  );
}

function createServer(config, store) {
  const ctx = createContext(config, store);
  const routes = [
    {
      methods: ['GET'],
      path: '/api/health',
      handler: (req, res) => ctx.reply(res, 200, {status: 'ok'}),
    },
    ...require('./routes/auth')(ctx),
    ...require('./routes/documents')(ctx),
    ...require('./routes/users')(ctx),
    ...require('./routes/audit')(ctx),
  ];

  const server = http.createServer(async (req, res) => {
    const startedAt = Date.now();
    res.setHeader('X-Request-ID', randomToken(12));
    res.on('finish', () => logRequest(config, req, res, startedAt));
    try {
      const url = new URL(req.url, 'http://localhost');
      const {pathname} = url;
      if (!ALLOWED_METHODS.includes(req.method)) {
        return json(res, config, 405, {error: 'Method not allowed'});
      }
      if (!sameOrigin(req, config)) {
        return json(res, config, 403, {error: 'Request origin not allowed'});
      }
      const found = findRoute(routes, req.method, pathname);
      if (found) return await found.route.handler(req, res, found.params);
      if (pathname.startsWith('/api/'))
        return json(res, config, 404, {error: 'API route not found'});
      if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, config, url);
      return json(res, config, 405, {error: 'Method not allowed'});
    } catch (e) {
      const status = e instanceof ApiError || e instanceof UploadError ? e.status : 500;
      if (status === 500) {
        console.error(
          JSON.stringify({level: 'error', message: e.message, route: req.url, at: nowISOString()}),
        );
      }
      if (!res.headersSent) {
        return json(res, config, status, {
          error: status === 500 ? 'Internal server error' : e.message,
        });
      }
      res.destroy();
    }
  });
  return {server, db: store.db};
}

async function initialize(env = process.env) {
  const config = loadConfig(env);
  const store = openDatabase(config);
  await store.seedAdmin();
  return {...createServer(config, store), config};
}

module.exports = {initialize, createServer};
