import express from 'express';
import compression from 'compression';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import { fileURLToPath } from 'url';
import { keysRouter } from './routes/keys.js';
import { clientProfilesRouter } from './routes/client-profiles.js';
import { conversationsRouter } from './routes/conversations.js';
import { logsRouter } from './routes/logs.js';
import { modelsRouter } from './routes/models.js';
import { proxyRouter } from './routes/proxy.js';
import { responsesRouter } from './routes/responses.js';
import { anthropicRouter } from './routes/anthropic.js';
import { fallbackRouter } from './routes/fallback.js';
import { profilesRouter } from './routes/profiles.js';
import { embeddingsRouter } from './routes/embeddings.js';
import { mediaRouter } from './routes/media.js';
import { searchRouter } from './routes/search.js';
import { decisionsRouter } from './routes/decisions.js';
import { analyticsRouter } from './routes/analytics.js';
import { healthRouter } from './routes/health.js';
import { freeTierRouter } from './routes/free-tier.js';
import { settingsRouter } from './routes/settings.js';
import { premiumRouter } from './routes/premium.js';
import { backupsRouter } from './routes/backups.js';
import { cacheRouter } from './routes/cache.js';
import { compressionRouter } from './routes/compression.js';
import { authRouter } from './routes/auth.js';
import { docsRouter } from './routes/docs.js';
import { mcpRouter } from './routes/mcp.js';
import { statusRouter, providersRouter } from './routes/status.js';
import { geminiRouter } from './routes/gemini.js';
import { ollamaRouter } from './routes/ollama.js';
import { urlTokenRouter } from './routes/url-tokens.js';
import { updateRouter } from './routes/update.js';
import { moderationRouter } from './routes/moderation.js';
import { requireAuth } from './middleware/requireAuth.js';
import { createHostGuard } from './middleware/allowed-hosts.js';
import { createProxyRateLimiter, createAdminRateLimiter } from './middleware/rateLimit.js';

const EXPORT_RATE_LIMIT_RPM = 10;
import { errorHandler } from './middleware/errorHandler.js';
import { clientContextMiddleware } from './lib/client-context.js';
import type { Config } from './lib/config.js';
import { loadConfig } from './lib/config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DEFAULT_DASHBOARD_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://[::1]:5173',
];

export const INLINE_BOOTSTRAP_SHA = "'sha256-4Mz/yZAENQGlTAAeE1WqXruXCripvlvl0s+Q9S1VS4A='";

const HASHED_ASSET_RE = /-[A-Za-z0-9_-]{6,}\.[A-Za-z0-9]+$/;
function isImmutableAsset(filePath: string): boolean {
  return (
    filePath.includes(`${path.sep}assets${path.sep}`) ||
    HASHED_ASSET_RE.test(path.basename(filePath))
  );
}

const LOOPBACK_HOST_RE = /^(?:localhost|[^.]+(?:\.[^.]+)*\.localhost|127(?:\.\d{1,3}){3}|[?::1]?)$/i;

function isHttpsRequest(req: express.Request): boolean {
  const forwardedProto = req.headers['x-forwarded-proto'];
  const first = String(forwardedProto ?? '').split(',')[0]!.trim().toLowerCase();
  return first === 'https' || req.secure;
}

function isTrustworthyOrigin(req: express.Request): boolean {
  return isHttpsRequest(req) || LOOPBACK_HOST_RE.test(req.hostname ?? '');
}

export function createApp(config?: Config) {
  const cfg = config ?? loadConfig();
  const app = express();

  app.set('trust proxy', cfg.trustProxy);
  app.use(createHostGuard(cfg.allowedHosts));
  const allowedCorsOrigins = new Set([
    ...DEFAULT_DASHBOARD_ORIGINS,
    ...cfg.dashboardOrigins,
  ]);

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", INLINE_BOOTSTRAP_SHA],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        formAction: ["'self'"],
        baseUri: ["'self'"],
        upgradeInsecureRequests: null,
      },
    },
    hsts: false,
    crossOriginOpenerPolicy: false,
    originAgentCluster: false,
  }));

  app.use((req, res, next) => {
    const shouldEmit =
      cfg.cspUpgradeInsecureRequests === true ||
      (cfg.cspUpgradeInsecureRequests === undefined && isHttpsRequest(req));

    if (shouldEmit) {
      const csp = res.getHeader('content-security-policy');
      if (typeof csp === 'string' && !csp.includes('upgrade-insecure-requests')) {
        res.setHeader('content-security-policy', `${csp}; upgrade-insecure-requests`);
      }
    }

    if (isTrustworthyOrigin(req)) {
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      res.setHeader('Origin-Agent-Cluster', '?1');
    }

    next();
  });

  app.use(cors({
    origin(origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
      callback(null, !origin || allowedCorsOrigins.has(origin));
    },
  }));

  app.use(
    ['/v1', '/v1beta', '/mcp', '/api/chat', '/api/generate', '/api/embed', '/api/embeddings'],
    express.json({ limit: cfg.requestBodyLimitBytes }),
  );
  app.use(express.json({ limit: '10mb' }));

  app.use(clientContextMiddleware);

  app.use(
    ['/api/tags', '/api/version', '/api/show', '/api/chat', '/api/generate', '/api/embed', '/api/embeddings'],
    createProxyRateLimiter(cfg.proxyRateLimitRpm),
  );
  app.use(ollamaRouter);

  const adminRateLimiter = createAdminRateLimiter();
  app.use('/api', adminRateLimiter);

  app.use('/api/auth', authRouter);
  app.use('/api/keys/export', createAdminRateLimiter(EXPORT_RATE_LIMIT_RPM));
  app.use('/api/keys', requireAuth, keysRouter);
  app.use('/api/client-profiles', requireAuth, clientProfilesRouter);
  app.use('/api/conversations', requireAuth, conversationsRouter);
  app.use('/api/logs', requireAuth, logsRouter);
  app.use('/api/models', requireAuth, modelsRouter);
  app.use('/api/profiles', requireAuth, profilesRouter);
  app.use('/api/fallback', requireAuth, fallbackRouter);
  app.use('/api/embeddings', requireAuth, embeddingsRouter);
  app.use('/api/media', requireAuth, mediaRouter);
  app.use('/api/search', requireAuth, searchRouter);
  app.use('/api/decisions', requireAuth, decisionsRouter);
  app.use('/api/analytics', requireAuth, analyticsRouter);
  app.use('/api/health', requireAuth, healthRouter);
  app.use('/api/free-tier', requireAuth, freeTierRouter);
  app.use('/api/settings', requireAuth, settingsRouter);
  app.use('/api/premium', requireAuth, premiumRouter);
  app.use('/api/backups', requireAuth, backupsRouter);
  app.use('/api/cache', requireAuth, cacheRouter);
  app.use('/api/compression', requireAuth, compressionRouter);
  app.use('/api/update', requireAuth, updateRouter);

  app.get('/api/ping', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  app.use('/v1', docsRouter);
  app.use('/v1', providersRouter);
  app.use('/v1/t/:token', createProxyRateLimiter(cfg.proxyRateLimitRpm));
  app.use('/v1/t/:token', urlTokenRouter);
  app.use('/v1', createProxyRateLimiter(cfg.proxyRateLimitRpm));
  app.use('/v1', anthropicRouter);
  app.use('/v1', proxyRouter);
  app.use('/v1', moderationRouter);
  app.use('/v1', responsesRouter);

  app.use('/v1beta', createProxyRateLimiter(
