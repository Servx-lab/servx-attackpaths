import assert from 'node:assert/strict';
import test from 'node:test';
import { buildStaticAttackPathCandidates } from '../src/engine/attackPathsJobRunner.js';
import { runRemoteAttackPathsJob } from '../src/engine/remoteJobRunner.js';

test('rejects a live target before any repository materialization or scanner execution', async () => {
  let failure = '';
  await runRemoteAttackPathsJob({
    jobId: 'remote-runner-test',
    repoId: 'repo-1',
    repoFullName: 'owner/repository',
    targetUrl: 'https://unverified.example',
    scanTypes: ['supply_chain'],
    analysisDepth: 2,
    profile: 'deep_repo',
    executionLeaseId: 'e6a24bf6-a94d-4a7d-857d-df86eb8bd3a4',
    leaseExpiresAt: '2030-01-01T00:00:00.000Z',
    githubAccessToken: 'not-used',
  }, {
    progress: async () => undefined,
    complete: async () => assert.fail('completion must not be called'),
    fail: async (message) => { failure = message; },
  });

  assert.match(failure, /Live deployment scanning is not enabled/);
});

test('returns only source-local route-to-sink candidates and labels them as partial', () => {
  const candidates = buildStaticAttackPathCandidates([
    { path: 'src/routes/admin.ts', content: "router.post('/admin/run', requireAuth, (req) => { eval(req.body.command); });" },
    { path: 'src/routes/other.ts', content: "router.get('/other', (_req, res) => res.send('ok'));" },
  ], [
    { id: 'admin-eval', severity: 'critical', title: 'Suspicious eval() usage', detail: 'Dynamic code.', file: 'src/routes/admin.ts:1', source: 'sast_scan' },
    { id: 'unrelated-eval', severity: 'critical', title: 'Suspicious eval() usage', detail: 'Dynamic code.', file: 'src/routes/unrelated.ts:1', source: 'sast_scan' },
  ]);

  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].route, '/admin/run');
  assert.equal(candidates[0].authBoundary, 'present');
  assert.equal(candidates[0].confidence, 'partial');
});
