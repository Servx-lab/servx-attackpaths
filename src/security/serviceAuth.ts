import crypto from 'crypto';
import type { NextFunction, Request, Response } from 'express';

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const NONCE_TTL_MS = 10 * 60 * 1000;
const MAX_NONCES = 10_000;

const seenNonces = new Map<string, number>();

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function inboundServiceAuthConfigured(): boolean {
  return Boolean(
    process.env.SERVX_EXECUTOR_INBOUND_HMAC_SECRET?.trim() &&
    process.env.SERVX_EXECUTOR_INBOUND_KEY_ID?.trim()
  );
}

export function outboundServiceAuthConfigured(): boolean {
  return Boolean(
    process.env.SERVX_EXECUTOR_OUTBOUND_HMAC_SECRET?.trim() &&
    process.env.SERVX_EXECUTOR_OUTBOUND_KEY_ID?.trim()
  );
}

export function canonicalServiceRequest(params: {
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  contentSha256: string;
}): string {
  return [
    params.method.toUpperCase(),
    params.path,
    params.timestamp,
    params.nonce,
    params.contentSha256,
  ].join('\n');
}

export function sha256Hex(payload: string | Buffer = ''): string {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

export function signServiceRequest(params: {
  secret: string;
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  contentSha256: string;
}): string {
  return crypto
    .createHmac('sha256', params.secret)
    .update(canonicalServiceRequest(params))
    .digest('hex');
}

export function makeOutboundServiceHeaders(params: {
  method: string;
  path: string;
  body?: string;
}): Record<string, string> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const contentSha256 = sha256Hex(params.body || '');
  const secret = requiredEnv('SERVX_EXECUTOR_OUTBOUND_HMAC_SECRET');
  const signature = signServiceRequest({
    secret,
    method: params.method,
    path: params.path,
    timestamp,
    nonce,
    contentSha256,
  });

  return {
    Authorization: 'ServX-HMAC v1',
    'X-ServX-Key-Id': requiredEnv('SERVX_EXECUTOR_OUTBOUND_KEY_ID'),
    'X-ServX-Timestamp': timestamp,
    'X-ServX-Nonce': nonce,
    'X-ServX-Content-SHA256': contentSha256,
    'X-ServX-Signature': `v1=${signature}`,
  };
}

function pruneNonces(now: number): void {
  for (const [nonce, expiresAt] of seenNonces) {
    if (expiresAt <= now) seenNonces.delete(nonce);
  }

  while (seenNonces.size >= MAX_NONCES) {
    const oldest = seenNonces.keys().next().value;
    if (!oldest) break;
    seenNonces.delete(oldest);
  }
}

function headerValue(req: Request, name: string): string {
  const value = req.header(name);
  return value ? value.trim() : '';
}

function timingSafeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

/**
 * Verifies signed control-plane requests. The in-memory nonce cache is a
 * defense-in-depth fallback for this single executor; the ServX API uses its
 * durable Redis cache for callback replay protection.
 */
export function requireInboundServiceAuth(req: Request, res: Response, next: NextFunction): void {
  try {
    const secret = requiredEnv('SERVX_EXECUTOR_INBOUND_HMAC_SECRET');
    const timestamp = headerValue(req, 'X-ServX-Timestamp');
    const nonce = headerValue(req, 'X-ServX-Nonce');
    const contentSha256 = headerValue(req, 'X-ServX-Content-SHA256');
    const signatureHeader = headerValue(req, 'X-ServX-Signature');
    const authorization = headerValue(req, 'Authorization');
    const keyId = headerValue(req, 'X-ServX-Key-Id');

    if (
      authorization !== 'ServX-HMAC v1' ||
      keyId !== requiredEnv('SERVX_EXECUTOR_INBOUND_KEY_ID') ||
      !timestamp ||
      !nonce ||
      !contentSha256 ||
      !signatureHeader.startsWith('v1=')
    ) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const timestampMs = Number(timestamp) * 1000;
    const now = Date.now();
    if (!Number.isFinite(timestampMs) || Math.abs(now - timestampMs) > MAX_CLOCK_SKEW_MS) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const rawBody = (req as Request & { rawBody?: string }).rawBody || '';
    if (!timingSafeEqual(contentSha256, sha256Hex(rawBody))) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const expected = signServiceRequest({
      secret,
      method: req.method,
      path: req.originalUrl.split('?')[0],
      timestamp,
      nonce,
      contentSha256,
    });
    const supplied = signatureHeader.slice(3);
    if (!timingSafeEqual(supplied, expected)) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    pruneNonces(now);
    if (seenNonces.has(nonce)) {
      res.status(409).json({ error: 'ReplayRejected' });
      return;
    }
    seenNonces.set(nonce, now + NONCE_TTL_MS);
    next();
  } catch (error) {
    console.error('[serviceAuth] inbound request rejected:', error);
    res.status(503).json({ error: 'ServiceAuthUnavailable' });
  }
}
