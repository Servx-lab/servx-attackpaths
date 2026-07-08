import { Request, Response } from 'express';
import { createAttackPathsJob, getAttackPathsJobById, updateAttackPathsJobProgress } from '../engine/jobService.js';
import { z } from 'zod';

const createJobSchema = z.object({
  requestedBy: z.string().min(1),
  repoId: z.string().min(1),
  repoFullName: z.string().min(1),
  targetUrl: z.string().optional().default(''),
  scanTypes: z.array(z.string()).default([]),
  analysisDepth: z.number().default(2),
  deviceId: z.string().optional().default(''),
  idempotencyKey: z.string().optional().default(''),
  githubAccessTokenEnc: z.string().optional().default(''),
  githubTokenIv: z.string().optional().default(''),
});

export async function createJob(req: Request, res: Response): Promise<void> {
  try {
    const validated = createJobSchema.parse(req.body);
    const job = await createAttackPathsJob(validated);
    res.status(201).json({
      jobId: job._id,
      status: job.status,
      message: 'Attack path scan job queued successfully.'
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Invalid request payload' });
  }
}

export async function getJob(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const job = await getAttackPathsJobById(id);
    if (!job) {
      res.status(404).json({ error: 'Job not found' });
      return;
    }
    res.status(200).json(job);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
}

export async function streamJob(req: Request, res: Response): Promise<void> {
  const { id } = req.params;
  try {
    const initialJob = await getAttackPathsJobById(id);
    if (!initialJob) {
      res.status(404).json({ error: 'Job not found' });
      return;
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const sendEvent = (event: string, data: any) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent('progress', {
      status: initialJob.status,
      phaseMessage: initialJob.phaseMessage,
      progressPct: initialJob.progressPct,
    });

    if (['completed', 'failed'].includes(initialJob.status)) {
      sendEvent(initialJob.status, initialJob);
      res.end();
      return;
    }

    const interval = setInterval(async () => {
      try {
        const job = await getAttackPathsJobById(id);
        if (!job) {
          clearInterval(interval);
          res.end();
          return;
        }

        sendEvent('progress', {
          status: job.status,
          phaseMessage: job.phaseMessage,
          progressPct: job.progressPct,
        });

        if (['completed', 'failed'].includes(job.status)) {
          sendEvent(job.status, job);
          clearInterval(interval);
          res.end();
        }
      } catch (err) {
        clearInterval(interval);
        res.end();
      }
    }, 2000);

    req.on('close', () => {
      clearInterval(interval);
    });
  } catch (err: any) {
    if (!res.headersSent) {
      res.status(500).json({ error: err.message || 'Internal server error' });
    }
  }
}

export async function cancelJob(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const job = await updateAttackPathsJobProgress(id, {
      status: 'failed',
      phaseMessage: 'Cancelled by user',
    });
    if (!job) {
      res.status(404).json({ error: 'Job not found' });
      return;
    }
    res.status(200).json({ message: 'Job cancelled successfully', jobId: id });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
}
