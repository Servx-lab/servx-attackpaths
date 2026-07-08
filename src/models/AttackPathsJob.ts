import mongoose, { Document, Schema } from 'mongoose';

export interface AttackPathsJobDoc extends Document {
  _id: any;
  requestedBy: string;
  repoId: string;
  repoFullName: string;
  targetUrl?: string;
  scanTypes: string[];
  analysisDepth: number;
  deviceId?: string;
  idempotencyKey?: string;
  status: 'queued' | 'cpgraph_building' | 'cpgraph_analyzing' | 'harness_synthesizing' | 'sandbox_verifying' | 'rendering_report' | 'completed' | 'failed';
  phaseMessage: string;
  progressPct: number;
  githubAccessTokenEnc?: string;
  githubTokenIv?: string;
  githubTokenExpiry?: Date | null;
  results: any;
  scanArtifacts: any;
  toolStatuses: any[];
  graphArtifact: any;
  assuranceSummary: any;
  reportArtifactUrl?: string;
  lastError?: string;
  startedAt?: Date | null;
  completedAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

const attackPathsJobSchema = new Schema<AttackPathsJobDoc>(
  {
    requestedBy: { type: String, required: true, index: true },
    repoId: { type: String, required: true, index: true },
    repoFullName: { type: String, required: true },
    targetUrl: { type: String, default: '' },
    scanTypes: { type: [String], required: true, default: [] },
    analysisDepth: { type: Number, required: true },
    deviceId: { type: String, default: '' },
    idempotencyKey: { type: String, default: '', index: true },
    status: {
      type: String,
      enum: [
        'queued',
        'cpgraph_building',
        'cpgraph_analyzing',
        'harness_synthesizing',
        'sandbox_verifying',
        'rendering_report',
        'completed',
        'failed',
      ],
      default: 'queued',
      index: true,
    },
    phaseMessage: { type: String, default: '' },
    progressPct: { type: Number, default: 0 },
    githubAccessTokenEnc: { type: String, default: '' },
    githubTokenIv: { type: String, default: '' },
    githubTokenExpiry: { type: Date, default: null },
    results: { type: Schema.Types.Mixed, default: [] },
    scanArtifacts: { type: Schema.Types.Mixed, default: [] },
    toolStatuses: { type: Schema.Types.Mixed, default: [] },
    graphArtifact: { type: Schema.Types.Mixed, default: null },
    assuranceSummary: { type: Schema.Types.Mixed, default: {} },
    reportArtifactUrl: { type: String, default: '' },
    lastError: { type: String, default: '' },
    startedAt: { type: Date, default: null },
    completedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

export const AttackPathsJobModel =
  mongoose.models.AttackPathsJob ||
  mongoose.model<AttackPathsJobDoc>('AttackPathsJob', attackPathsJobSchema);

export default AttackPathsJobModel;
