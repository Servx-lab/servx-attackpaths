import { makeOutboundServiceHeaders } from '../security/serviceAuth.js';

export type RemoteScanInput = {
  jobId: string;
  repoId: string;
  repoFullName: string;
  targetUrl?: string;
  scanTypes: string[];
  analysisDepth: number;
  profile: 'quick' | 'deep_repo' | 'verified_live';
  executionLeaseId: string;
  leaseExpiresAt: string;
  githubAccessToken: string;
};

type ProgressUpdate = {
  status: string;
  progressPct: number;
  phaseMessage: string;
};

function controlPlaneBaseUrl(): string {
  const value = process.env.SERVX_CONTROL_PLANE_URL?.trim().replace(/\/+$/, '');
  if (!value) throw new Error('SERVX_CONTROL_PLANE_URL is required');
  return value;
}

async function signedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const body = typeof init.body === 'string' ? init.body : '';
  const headers = new Headers(init.headers);
  const signed = makeOutboundServiceHeaders({ method: init.method || 'GET', path, body });
  Object.entries(signed).forEach(([key, value]) => headers.set(key, value));
  if (body) headers.set('Content-Type', 'application/json');

  return fetch(`${controlPlaneBaseUrl()}${path}`, {
    ...init,
    headers,
    signal: AbortSignal.timeout(30_000),
  });
}

async function requireOk(response: Response, action: string): Promise<void> {
  if (response.ok) return;
  const detail = await response.text().catch(() => '');
  throw new Error(`${action} failed (${response.status})${detail ? `: ${detail.slice(0, 300)}` : ''}`);
}

export async function fetchRemoteScanInput(jobId: string): Promise<RemoteScanInput> {
  const path = `/api/internal/attack-paths/jobs/${encodeURIComponent(jobId)}/input`;
  const response = await signedFetch(path);
  await requireOk(response, 'Fetch scan input');
  const payload = await response.json() as { input?: RemoteScanInput };
  if (!payload.input?.jobId || !payload.input.githubAccessToken || !payload.input.executionLeaseId) {
    throw new Error('ServX returned incomplete scan input');
  }
  return payload.input;
}

export async function reportRemoteProgress(jobId: string, executionLeaseId: string, update: ProgressUpdate): Promise<void> {
  const path = `/api/internal/attack-paths/jobs/${encodeURIComponent(jobId)}/progress`;
  const body = JSON.stringify({ ...update, executionLeaseId });
  const response = await signedFetch(path, { method: 'POST', body });
  await requireOk(response, 'Report scan progress');
}

export async function reportRemoteCompletion(jobId: string, executionLeaseId: string, update: Record<string, unknown>): Promise<void> {
  const path = `/api/internal/attack-paths/jobs/${encodeURIComponent(jobId)}/complete`;
  const body = JSON.stringify({ ...update, executionLeaseId });
  const response = await signedFetch(path, { method: 'POST', body });
  await requireOk(response, 'Report scan completion');
}

export async function reportRemoteFailure(jobId: string, executionLeaseId: string, update: { lastError: string; progressPct?: number }): Promise<void> {
  const path = `/api/internal/attack-paths/jobs/${encodeURIComponent(jobId)}/fail`;
  const body = JSON.stringify({ ...update, executionLeaseId });
  const response = await signedFetch(path, { method: 'POST', body });
  await requireOk(response, 'Report scan failure');
}
