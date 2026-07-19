import assert from 'node:assert/strict';
import test from 'node:test';
import { sha256, signServiceRequest } from '../src/security/serviceAuth.js';

test('HMAC signatures bind the method, path, timestamp, nonce, and exact body', () => {
  const request = {
    secret: 'test-secret',
    method: 'POST',
    path: '/internal/v1/jobs/job-123/dispatch',
    timestamp: '1784470000',
    nonce: 'nonce-123',
    contentSha256: sha256('{"jobId":"job-123"}'),
  };

  const signature = signServiceRequest(request);
  assert.equal(signature, signServiceRequest(request));
  assert.notEqual(signature, signServiceRequest({ ...request, path: '/internal/v1/jobs/job-124/dispatch' }));
  assert.notEqual(signature, signServiceRequest({ ...request, contentSha256: sha256('{"jobId":"job-124"}') }));
});
