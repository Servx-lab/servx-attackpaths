import express from 'express';
import dotenv from 'dotenv';
import routes from './api/routes.js';
import { activeDispatchCount, isDispatcherReady, waitForDispatchDrain } from './engine/dispatchService.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;

app.use(express.json({
  limit: '1mb',
  verify: (req, _res, buffer) => {
    (req as express.Request & { rawBody?: string }).rawBody = buffer.toString('utf8');
  },
}));

app.use(routes);

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'servx-attackpaths',
    version: '0.1.0',
    activeJobs: activeDispatchCount(),
  });
});

function startServer() {
  const server = app.listen(PORT, () => {
    console.log(`[servx-attackpaths] 🚀 Service running on port ${PORT}`);
    console.log(`[servx-attackpaths] Health check available at http://localhost:${PORT}/health`);
    console.log(`[servx-attackpaths] Executor ready: ${isDispatcherReady() ? 'yes' : 'no'}`);
  });

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[servx-attackpaths] Received ${signal}; stopping new requests and draining active scans.`);
    server.close();
    await waitForDispatchDrain(270_000);
    process.exit(0);
  };

  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));
}

startServer();
