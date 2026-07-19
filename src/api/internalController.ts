import type { Request, Response } from 'express';
import { z } from 'zod';
import { activeDispatchCount, cancelRemoteJob, dispatchRemoteJob, isDispatcherReady } from '../engine/dispatchService.js';
import { executorReady } from '../security/serviceAuth.js';

const dispatchSchema = z.object({ jobId: z.string().min(1).max(128) });

export function readiness(_req: Request, res: Response): void {
  const configuration = executorReady();
  const status = configuration.ready && isDispatcherReady() ? 200 : 503;
  res.status(status).json({ ready: status === 200, activeDispatches: activeDispatchCount(), missing: configuration.missing });
}

export function wake(_req: Request, res: Response): void {
  const configuration = executorReady();
  if (!configuration.ready) {
    res.status(503).json({ error: 'ExecutorNotConfigured', missing: configuration.missing });
    return;
  }
  res.status(202).json({ status: 'awake', activeDispatches: activeDispatchCount() });
}

export function dispatch(req: Request, res: Response): void {
  const parsed = dispatchSchema.safeParse(req.body || {});
  const pathJobId = String(req.params.jobId || '').trim();
  if (!parsed.success || !pathJobId || parsed.data.jobId !== pathJobId) {
    res.status(400).json({ error: 'BadRequest' });
    return;
  }
  const configuration = executorReady();
  if (!configuration.ready) {
    res.status(503).json({ error: 'ExecutorNotConfigured', missing: configuration.missing });
    return;
  }
  const state = dispatchRemoteJob(pathJobId);
  res.status(202).json({ status: state, jobId: pathJobId, activeDispatches: activeDispatchCount() });
}

export function cancel(req: Request, res: Response): void {
  const parsed = dispatchSchema.safeParse(req.body || {});
  const pathJobId = String(req.params.jobId || '').trim();
  if (!parsed.success || !pathJobId || parsed.data.jobId !== pathJobId) {
    res.status(400).json({ error: 'BadRequest' });
    return;
  }
  res.status(202).json({ status: cancelRemoteJob(pathJobId), jobId: pathJobId });
}
