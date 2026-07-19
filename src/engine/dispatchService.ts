import {
  fetchRemoteScanInput,
  reportRemoteCompletion,
  reportRemoteFailure,
  reportRemoteProgress,
  type RemoteScanInput,
} from '../clients/servxControlPlaneClient.js';
import { runRemoteAttackPathsJob } from './attackPathsJobRunner.js';
import { inboundServiceAuthConfigured, outboundServiceAuthConfigured } from '../security/serviceAuth.js';

type QueuedJob = {
  completion: Promise<void>;
  resolve: () => void;
  abortController: AbortController;
  started: boolean;
};

const activeJobs = new Map<string, QueuedJob>();
const pendingJobIds: string[] = [];
let isDraining = false;

export function isDispatcherReady(): boolean {
  return Boolean(
    process.env.SERVX_CONTROL_PLANE_URL?.trim() &&
    inboundServiceAuthConfigured() &&
    outboundServiceAuthConfigured()
  );
}

export function activeDispatchCount(): number {
  return activeJobs.size;
}

/** Lets the HTTP server finish an in-flight repository scan during graceful shutdown. */
export async function waitForDispatchDrain(timeoutMs: number): Promise<void> {
  const drain = async (): Promise<void> => {
    while (activeJobs.size > 0) {
      await Promise.allSettled(Array.from(activeJobs.values(), (job) => job.completion));
    }
  };

  await Promise.race([
    drain(),
    new Promise<void>((resolve) => setTimeout(resolve, timeoutMs)),
  ]);
}

/**
 * Queues scans serially for the free-tier executor. A duplicate dispatch is
 * safe: it returns the same completion promise instead of rerunning the scan.
 */
export function dispatchRemoteJob(jobId: string): Promise<void> {
  const current = activeJobs.get(jobId);
  if (current) return current.completion;

  let resolve!: () => void;
  const completion = new Promise<void>((done) => {
    resolve = done;
  });
  activeJobs.set(jobId, { completion, resolve, abortController: new AbortController(), started: false });
  pendingJobIds.push(jobId);
  void drainQueue();
  return completion;
}

/** Stops a queued job immediately or terminates the active scanner process. */
export function cancelRemoteJob(jobId: string): boolean {
  const queued = activeJobs.get(jobId);
  if (!queued) return false;

  queued.abortController.abort();
  if (!queued.started) {
    const index = pendingJobIds.indexOf(jobId);
    if (index >= 0) pendingJobIds.splice(index, 1);
    activeJobs.delete(jobId);
    queued.resolve();
  }
  return true;
}

async function drainQueue(): Promise<void> {
  if (isDraining) return;
  isDraining = true;

  try {
    while (pendingJobIds.length > 0) {
      const jobId = pendingJobIds.shift();
      if (!jobId) continue;
      const queued = activeJobs.get(jobId);
      if (!queued) continue;
      queued.started = true;

      try {
        await fetchAndRunRemoteJob(jobId, queued.abortController.signal);
      } finally {
        activeJobs.delete(jobId);
        queued.resolve();
      }
    }
  } finally {
    isDraining = false;
  }
}

async function fetchAndRunRemoteJob(jobId: string, signal: AbortSignal): Promise<void> {
  let input: RemoteScanInput | undefined;
  try {
    input = await fetchRemoteScanInput(jobId);
    if (signal.aborted) return;
    const leasedInput = input;
    await runRemoteAttackPathsJob(leasedInput, {
      progress: (update) => reportRemoteProgress(jobId, leasedInput.executionLeaseId, update),
      complete: (update) => reportRemoteCompletion(jobId, leasedInput.executionLeaseId, sanitizeCompletion(update)),
      fail: (update) => reportRemoteFailure(jobId, leasedInput.executionLeaseId, update),
    }, signal);
  } catch (error: any) {
    if (signal.aborted) return;
    const lastError = error?.message || 'Executor dispatch failed';
    console.error(`[dispatchService] ${jobId} failed:`, lastError);
    if (!input) return;
    await reportRemoteFailure(jobId, input.executionLeaseId, { lastError }).catch((callbackError) => {
      console.error(`[dispatchService] failure callback for ${jobId} failed:`, callbackError);
    });
  }
}

function sanitizeCompletion(value: Record<string, unknown>): Record<string, unknown> {
  const toolStatuses = Array.isArray(value.toolStatuses)
    ? value.toolStatuses.map((tool) => {
      if (!tool || typeof tool !== 'object') return tool;
      const raw = tool as Record<string, unknown>;
      return {
        ...raw,
        artifacts: Array.isArray(raw.artifacts)
          ? raw.artifacts.map((artifact) => {
            if (!artifact || typeof artifact !== 'object') return artifact;
            const { path: _localPath, ...safeArtifact } = artifact as Record<string, unknown>;
            return safeArtifact;
          })
          : [],
      };
    })
    : [];

  return {
    ...value,
    scanArtifacts: [],
    toolStatuses,
  };
}
