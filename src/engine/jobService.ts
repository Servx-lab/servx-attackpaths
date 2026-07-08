import AttackPathsJobModel, { AttackPathsJobDoc } from '../models/AttackPathsJob.js';

export async function createAttackPathsJob(params: any): Promise<AttackPathsJobDoc> {
  const doc = await AttackPathsJobModel.create({
    ...params,
    status: 'queued',
    progressPct: 0,
    phaseMessage: 'Queued',
    startedAt: null,
    completedAt: null,
    results: [],
    scanArtifacts: [],
    toolStatuses: [],
    graphArtifact: null,
    reportArtifactUrl: '',
    lastError: '',
  });
  return doc as AttackPathsJobDoc;
}

export async function getAttackPathsJobById(jobId: string): Promise<AttackPathsJobDoc | null> {
  return AttackPathsJobModel.findById(jobId).exec();
}

export async function updateAttackPathsJobProgress(jobId: string, update: {
  status?: string;
  progressPct?: number;
  phaseMessage?: string;
}): Promise<AttackPathsJobDoc | null> {
  return AttackPathsJobModel.findByIdAndUpdate(
    jobId,
    {
      $set: {
        ...(update.status ? { status: update.status } : {}),
        ...(typeof update.progressPct === 'number' ? { progressPct: update.progressPct } : {}),
        ...(update.phaseMessage ? { phaseMessage: update.phaseMessage } : {}),
      }
    },
    { new: true }
  ).exec();
}

export async function setAttackPathsJobResult(jobId: string, update: {
  status: string;
  progressPct: number;
  phaseMessage: string;
  results: any;
  scanArtifacts?: any;
  toolStatuses?: any[];
  graphArtifact: any;
  reportArtifactUrl: string;
  failedScanners?: any[];
  lastError?: string;
  assuranceSummary?: any;
}): Promise<AttackPathsJobDoc | null> {
  return AttackPathsJobModel.findByIdAndUpdate(
    jobId,
    {
      $set: {
        status: update.status,
        progressPct: update.progressPct,
        phaseMessage: update.phaseMessage,
        results: update.results,
        scanArtifacts: update.scanArtifacts ?? [],
        toolStatuses: update.toolStatuses ?? [],
        graphArtifact: update.graphArtifact,
        reportArtifactUrl: update.reportArtifactUrl,
        assuranceSummary: update.assuranceSummary ?? {},
        lastError: update.lastError || '',
        completedAt: new Date(),
      }
    },
    { new: true }
  ).exec();
}
