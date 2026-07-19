import assert from 'node:assert/strict';
import test from 'node:test';
import { buildStaticAttackPathCandidates, runRemoteAttackPathsJob } from '../src/engine/attackPathsJobRunner.js';

test('rejects a live target before any repository or network scanner work begins', async () => {
  let completionCalled = false;
  let failure = '';

  await runRemoteAttackPathsJob({
    jobId: 'runner-test-01',
    repoId: 'repo-01',
    repoFullName: 'owner/repository',
    targetUrl: 'https://not-authorized.example',
    scanTypes: ['supply_chain'],
    analysisDepth: 2,
    profile: 'deep_repo',
    executionLeaseId: '0fbb4c95-fc7c-4af1-a67c-03e2ce2b89e7',
    leaseExpiresAt: '2030-01-01T00:00:00.000Z',
    githubAccessToken: 'test-token',
  }, {
    progress: async () => undefined,
    complete: async () => { completionCalled = true; },
    fail: async (update) => { failure = update.lastError; },
  });

  assert.equal(completionCalled, false);
  assert.match(failure, /Live deployment scanning is not enabled/);
});

test('reports only source-local route-to-sink candidates and labels them as partial evidence', () => {
  const candidates = buildStaticAttackPathCandidates([
    {
      path: 'src/routes/admin.ts',
      content: "router.post('/admin/run', requireAuth, (req, res) => { eval(req.body.command); });",
    },
    {
      path: 'src/routes/other.ts',
      content: "router.get('/other', (_req, res) => res.send('ok'));",
    },
  ], [
    {
      id: 'sast-admin-eval',
      severity: 'critical',
      title: 'Potential code injection',
      detail: 'Untrusted data reaches a dynamic evaluator.',
      file: 'src/routes/admin.ts:1',
      source: 'sast_scan',
    },
    {
      id: 'sast-other-eval',
      severity: 'critical',
      title: 'Potential code injection',
      detail: 'This must not be attached to the admin route.',
      file: 'src/routes/unrelated.ts:8',
      source: 'sast_scan',
    },
  ]);

  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].route, '/admin/run');
  assert.equal(candidates[0].authBoundary, 'present');
  assert.equal(candidates[0].confidence, 'partial');
  assert.match(candidates[0].note, /not verified/);
});
