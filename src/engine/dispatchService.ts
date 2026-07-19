import {
  completeRemoteJob,
  failRemoteJob,
  fetchRemoteScanInput,
  reportRemoteProgress,
} from '../clients/servxControlPlaneClient.js';
import { runRemoteAttackPathsJob } from './remoteJobRunner.js';

type QueuedJob = { jobId: string; controller: AbortController; started: boolean };

const queue: QueuedJob[] = [];
const jobs = new Map<string, QueuedJob>();
let draining = false;

export function activeDispatchCount(): number {
  return jobs.size;
}

export function isDispatcherReady(): boolean {
  return !draining || queue.length >= 0;
}

export function dispatchRemoteJob(jobId: string): 'queued' | 'duplicate' {
  if (jobs.has(jobId)) return 'duplicate';
  const job: QueuedJob = { jobId, controller: new AbortController(), started: false };
  jobs.set(jobId, job);
  queue.push(job);
  void drain();
  return 'queued';
}

export function cancelRemoteJob(jobId: string): 'cancelling' | 'not_active' {
  const job = jobs.get(jobId);
  if (!job) return 'not_active';
  job.controller.abort();
  if (!job.started) {
    const index = queue.indexOf(job);
    if (index >= 0) queue.splice(index, 1);
    jobs.delete(jobId);
  }
  return 'cancelling';
}

async function drain(): Promise<void> {
  if (draining) return;
  draining = true;
  try {
    while (queue.length > 0) {
      const job = queue.shift();
      if (!job || job.controller.signal.aborted) {
        if (job) jobs.delete(job.jobId);
        continue;
      }
      job.started = true;
      try {
        const input = await fetchRemoteScanInput(job.jobId);
        if (job.controller.signal.aborted) continue;
        await runRemoteAttackPathsJob(input, {
          progress: (update) => reportRemoteProgress(input.jobId, input.executionLeaseId, update),
          complete: (payload) => completeRemoteJob(input.jobId, input.executionLeaseId, payload),
          fail: (lastError, progressPct) => failRemoteJob(input.jobId, input.executionLeaseId, lastError, progressPct),
        }, job.controller.signal);
      } catch (error) {
        if (!job.controller.signal.aborted) console.error(`[dispatchService] ${job.jobId} failed before scan execution:`, error instanceof Error ? error.message : error);
      } finally {
        jobs.delete(job.jobId);
      }
    }
  } finally {
    draining = false;
  }
}
