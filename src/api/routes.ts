import { Router } from 'express';
import { cancel, dispatch, heartbeat, readiness, wake } from './internalController.js';
import { requireInboundServiceAuth } from '../security/serviceAuth.js';

const router = Router();

router.get('/ready', requireInboundServiceAuth, readiness);
router.post('/internal/v1/wake', requireInboundServiceAuth, wake);
router.post('/internal/v1/jobs/:jobId/dispatch', requireInboundServiceAuth, dispatch);
router.post('/internal/v1/jobs/:jobId/cancel', requireInboundServiceAuth, cancel);
router.post('/internal/v1/jobs/:jobId/heartbeat', requireInboundServiceAuth, heartbeat);

export default router;
