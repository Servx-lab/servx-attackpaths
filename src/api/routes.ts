import { Router } from 'express';
import { createJob, getJob, streamJob, cancelJob } from './controller.js';

const router = Router();

router.post('/jobs', createJob);
router.get('/jobs/:id', getJob);
router.get('/jobs/:id/stream', streamJob);
router.delete('/jobs/:id', cancelJob);

export default router;
