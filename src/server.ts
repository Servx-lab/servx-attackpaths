import express from 'express';
import dotenv from 'dotenv';
import routes from './api/routes.js';
import { executorReady } from './security/serviceAuth.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb', verify: (req, _res, buffer) => { (req as express.Request & { rawBody?: string }).rawBody = buffer.toString('utf8'); } }));

app.use(routes);

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'servx-attackpaths', version: '0.1.0' });
});

async function startServer() {
  app.listen(PORT, () => {
    console.log(`[servx-attackpaths] 🚀 Service running on port ${PORT}`);
    console.log(`[servx-attackpaths] Health check available at http://localhost:${PORT}/health`);
    const configuration = executorReady();
    if (configuration.ready) console.log('[servx-attackpaths] Signed ServX executor bridge is ready.');
    else console.warn(`[servx-attackpaths] Waiting for executor configuration: ${configuration.missing.join(', ')}`);
  });
}

startServer();
