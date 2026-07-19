import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

const CLOCK_SKEW_SECONDS = 5 * 60;
const NONCE_TTL_MS = 10 * 60 * 1_000;
const seenNonces = new Map<string, number>();

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonical(params: { method: string; path: string; timestamp: string; nonce: string; contentSha256: string }): string {
  return [params.method.toUpperCase(), params.path, params.timestamp, params.nonce, params.contentSha256].join('\n');
}

export function signServiceRequest(params: { secret: string; method: string; path: string; timestamp: string; nonce: string; contentSha256: string }): string {
  return crypto.createHmac('sha256', params.secret).update(canonical(params)).digest('hex');
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function readHeader(req: Request, name: string): string {
  return req.header(name)?.trim() || '';
}

function claimNonce(key: string): boolean {
  const now = Date.now();
  for (const [nonce, expiresAt] of seenNonces) {
    if (expiresAt <= now) seenNonces.delete(nonce);
  }
  if (seenNonces.has(key)) return false;
  seenNonces.set(key, now + NONCE_TTL_MS);
  return true;
}

/** Verifies requests sent by the ServX control plane to this isolated executor. */
export function requireInboundServiceAuth(req: Request, res: Response, next: NextFunction): void {
  try {
    const timestamp = readHeader(req, 'X-ServX-Timestamp');
    const nonce = readHeader(req, 'X-ServX-Nonce');
    const contentSha256 = readHeader(req, 'X-ServX-Content-SHA256');
    const signatureHeader = readHeader(req, 'X-ServX-Signature');
    const keyId = readHeader(req, 'X-ServX-Key-Id');
    const authorization = readHeader(req, 'Authorization');
    const rawBody = String((req as Request & { rawBody?: string }).rawBody || '');

    if (
      authorization !== 'ServX-HMAC v1' ||
      keyId !== requiredEnv('ATTACK_PATHS_EXECUTOR_INBOUND_KEY_ID') ||
      !timestamp || !nonce || !contentSha256 || !signatureHeader.startsWith('v1=')
    ) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const timestampSeconds = Number(timestamp);
    if (!Number.isFinite(timestampSeconds) || Math.abs(Math.floor(Date.now() / 1000) - timestampSeconds) > CLOCK_SKEW_SECONDS) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    if (!safeEqual(contentSha256, sha256(rawBody))) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const expected = signServiceRequest({
      secret: requiredEnv('ATTACK_PATHS_EXECUTOR_INBOUND_HMAC_SECRET'),
      method: req.method,
      path: req.originalUrl.split('?')[0],
      timestamp,
      nonce,
      contentSha256,
    });
    if (!safeEqual(signatureHeader.slice(3), expected) || !claimNonce(`${keyId}:${nonce}`)) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  } catch (error) {
    console.error('[serviceAuth] inbound request rejected:', error instanceof Error ? error.message : error);
    res.status(503).json({ error: 'ServiceAuthUnavailable' });
  }
}

export function executorReady(): { ready: boolean; missing: string[] } {
  const required = [
    'SERVX_CONTROL_PLANE_URL',
    'ATTACK_PATHS_EXECUTOR_INBOUND_HMAC_SECRET',
    'ATTACK_PATHS_EXECUTOR_INBOUND_KEY_ID',
    'ATTACK_PATHS_EXECUTOR_OUTBOUND_HMAC_SECRET',
    'ATTACK_PATHS_EXECUTOR_OUTBOUND_KEY_ID',
  ];
  const missing = required.filter((name) => !process.env[name]?.trim());
  return { ready: missing.length === 0, missing };
}
