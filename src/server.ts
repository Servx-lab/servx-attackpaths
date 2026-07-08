import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import routes from './api/routes.js';
import { runAttackPathsJobV1 } from './engine/attackPathsJobRunner.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/servx-attackpaths';

app.use(cors());
app.use(express.json());

app.use('/api/v1', routes);

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'servx-attackpaths', version: '0.1.0' });
});

async function startServer() {
  app.listen(PORT, () => {
    console.log(`[servx-attackpaths] 🚀 Service running on port ${PORT}`);
    console.log(`[servx-attackpaths] Health check available at http://localhost:${PORT}/health`);
  });

  console.log(`[servx-attackpaths] Connecting to MongoDB at ${MONGODB_URI}...`);
  mongoose.connect(MONGODB_URI).then(() => {
    console.log(`[servx-attackpaths] ✅ Connected to MongoDB.`);
    // Start background scanning engine loop
    runAttackPathsJobV1().catch((err) => {
      console.error(`[servx-attackpaths] Fatal error in background job runner:`, err);
    });
  }).catch((err) => {
    console.error(`[servx-attackpaths] ⚠️ Failed to connect to MongoDB:`, err.message || err);
  });
}

startServer();
