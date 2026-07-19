import type { Request, Response } from 'express';
import { z } from 'zod';
import { activeDispatchCount, cancelRemoteJob, dispatchRemoteJob, isDispatcherReady } from '../engine/dispatchService.js';

const dispatchSchema = z.object({
  jobId: z.string().min(1).max(128).optional(),
});

export function readiness(_req: Request, res: Response): void {
  if (!isDispatcherReady()) {
    res.status(503).json({ status: 'not_ready', reason: 'executor configuration is incomplete' });
    return;
  }
  res.status(200).json({ status: 'ready', activeJobs: activeDispatchCount() });
}

export function wake(_req: Request, res: Response): void {
  if (!isDispatcherReady()) {
    res.status(503).json({ error: 'ExecutorNotReady' });
    return;
  }
  res.status(202).json({ status: 'ready', activeJobs: activeDispatchCount() });
}

export function dispatch(req: Request, res: Response): void {
  const parsed = dispatchSchema.safeParse(req.body || {});
  const pathJobId = String(req.params.jobId || '');
  if (!parsed.success || !pathJobId) {
    res.status(400).json({ error: 'BadRequest' });
    return;
  }
  if (parsed.data.jobId && parsed.data.jobId !== pathJobId) {
    res.status(400).json({ error: 'BadRequest' });
    return;
  }
  if (!isDispatcherReady()) {
    res.status(503).json({ error: 'ExecutorNotReady' });
    return;
  }

  void dispatchRemoteJob(pathJobId);
  res.status(202).json({ jobId: pathJobId, status: 'accepted' });
}

export function cancel(req: Request, res: Response): void {
  const parsed = dispatchSchema.safeParse(req.body || {});
  const pathJobId = String(req.params.jobId || '');
  if (!parsed.success || !pathJobId || (parsed.data.jobId && parsed.data.jobId !== pathJobId)) {
    res.status(400).json({ error: 'BadRequest' });
    return;
  }
  res.status(202).json({ jobId: pathJobId, status: cancelRemoteJob(pathJobId) ? 'cancelling' : 'not_active' });
}

export function heartbeat(_req: Request, res: Response): void {
  res.status(204).end();
}
