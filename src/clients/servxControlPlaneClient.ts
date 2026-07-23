import crypto from 'node:crypto';
import { sha256, signServiceRequest } from '../security/serviceAuth.js';

export type RemoteScanInput = {
  jobId: string;
  repoId: string;
  repoFullName: string;
  targetUrl: string;
  scanTypes: string[];
  analysisDepth: number;
  profile: 'quick' | 'deep_repo' | 'verified_live';
  executionLeaseId: string;
  leaseExpiresAt: string;
  githubAccessToken: string;
};

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function baseUrl(): string {
  return requiredEnv('SERVX_CONTROL_PLANE_URL').replace(/\/+$/, '');
}

function headers(method: string, path: string, body = ''): Record<string, string> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const contentSha256 = sha256(body);
  const signature = signServiceRequest({
    secret: requiredEnv('ATTACK_PATHS_EXECUTOR_OUTBOUND_HMAC_SECRET'),
    method,
    path,
    timestamp,
    nonce,
    contentSha256,
  });
  return {
    Authorization: 'ServX-HMAC v1',
    'X-ServX-Key-Id': requiredEnv('ATTACK_PATHS_EXECUTOR_OUTBOUND_KEY_ID'),
    'X-ServX-Timestamp': timestamp,
    'X-ServX-Nonce': nonce,
    'X-ServX-Content-SHA256': contentSha256,
    'X-ServX-Signature': `v1=${signature}`,
    ...(body ? { 'Content-Type': 'application/json' } : {}),
  };
}

async function request(path: string, method: 'GET' | 'POST', body = ''): Promise<Response> {
  const response = await fetch(`${baseUrl()}${path}`, {
    method,
    headers: headers(method, path, body),
    body: body || undefined,
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`ServX control-plane request ${path} failed (${response.status})${detail ? `: ${detail.slice(0, 300)}` : ''}`);
  }
  return response;
}

export async function fetchRemoteScanInput(jobId: string, retries = 2): Promise<RemoteScanInput> {
  const path = `/api/internal/attack-paths/jobs/${encodeURIComponent(jobId)}/input`;
  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    try {
      const response = await request(path, 'GET');
      const payload = await response.json() as { input?: RemoteScanInput };
      if (!payload.input?.executionLeaseId || !payload.input.githubAccessToken) throw new Error('ServX returned incomplete scan input');
      return payload.input;
    } catch (err: any) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt <= retries) {
        console.warn(`[servxControlPlaneClient] fetchRemoteScanInput attempt ${attempt} failed for ${jobId}: ${lastError.message}. Retrying...`);
        await new Promise((r) => setTimeout(r, 2000 * attempt));
      }
    }
  }
  throw lastError || new Error('Failed to fetch scan input');
}

export async function reportRemoteProgress(jobId: string, executionLeaseId: string, update: { status: string; progressPct: number; phaseMessage: string }): Promise<void> {
  const path = `/api/internal/attack-paths/jobs/${encodeURIComponent(jobId)}/progress`;
  const body = JSON.stringify({ executionLeaseId, ...update });
  await request(path, 'POST', body);
}

export async function completeRemoteJob(jobId: string, executionLeaseId: string, payload: Record<string, unknown>): Promise<void> {
  const path = `/api/internal/attack-paths/jobs/${encodeURIComponent(jobId)}/complete`;
  const body = JSON.stringify({ executionLeaseId, status: 'completed', progressPct: 100, ...payload });
  await request(path, 'POST', body);
}

export async function failRemoteJob(jobId: string, executionLeaseId: string, lastError: string, progressPct = 0): Promise<void> {
  const path = `/api/internal/attack-paths/jobs/${encodeURIComponent(jobId)}/fail`;
  const body = JSON.stringify({ executionLeaseId, lastError: lastError.slice(0, 4_000), progressPct });
  await request(path, 'POST', body);
}
