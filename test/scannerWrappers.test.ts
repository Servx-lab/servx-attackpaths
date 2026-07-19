import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  parseGitleaksFindings,
  parseSemgrepFindings,
  parseSyftFindings,
  parseTrivyFindings,
} from '../src/scanners/scannerWrappers.js';
import type { ScannerRunResult } from '../src/scanners/scannerRunner.js';

const jobDir = await fs.mkdtemp(path.join(os.tmpdir(), 'servx-parser-fixture-'));
after(async () => fs.rm(jobDir, { recursive: true, force: true }));

async function report(name: string, payload: unknown): Promise<ScannerRunResult> {
  const filePath = path.join(jobDir, name);
  await fs.writeFile(filePath, JSON.stringify(payload), 'utf8');
  return { tool: name, status: 'ran', findingsCount: 0, artifacts: [{ tool: name, kind: 'report', path: filePath }] };
}

test('normalizes known-positive scanner reports without retaining a secret value', async () => {
  const gitleaks = await report('gitleaks.json', [
    { RuleID: 'generic-api-key', File: 'src/a.ts', StartLine: 4, Fingerprint: 'first', Description: 'Potential key' },
    { RuleID: 'generic-api-key', File: 'src/b.ts', StartLine: 8, Fingerprint: 'second', Description: 'Potential key' },
  ]);
  const semgrep = await report('semgrep.json', { results: [
    { check_id: 'javascript.eval', path: 'src/a.ts', start: { line: 4 }, end: { line: 4 }, extra: { severity: 'ERROR', message: 'Avoid eval' } },
    { check_id: 'javascript.eval', path: 'src/b.ts', start: { line: 8 }, end: { line: 8 }, extra: { severity: 'ERROR', message: 'Avoid eval' } },
  ] });
  const trivy = await report('trivy.json', { Results: [{ Target: 'Dockerfile', Vulnerabilities: [{ VulnerabilityID: 'CVE-2026-1', PkgName: 'demo', InstalledVersion: '1.0.0', Severity: 'HIGH' }], Misconfigurations: [{ RuleID: 'DS001', Title: 'Unsafe configuration', Severity: 'MEDIUM' }], Secrets: [{ RuleID: 'secret-rule', Title: 'Potential secret', Severity: 'HIGH', StartLine: 9 }] }] });
  const syft = await report('syft.json', { artifacts: [{ id: 'pkg-1', name: 'demo', version: '1.0.0', type: 'npm' }] });

  const [gitleaksFindings, semgrepFindings, trivyFindings, syftFindings] = await Promise.all([
    parseGitleaksFindings('repo', gitleaks),
    parseSemgrepFindings('repo', semgrep),
    parseTrivyFindings('repo', trivy),
    parseSyftFindings('repo', syft),
  ]);

  assert.equal(gitleaksFindings.length, 2);
  assert.notEqual(gitleaksFindings[0].id, gitleaksFindings[1].id);
  assert.equal(semgrepFindings.length, 2);
  assert.notEqual(semgrepFindings[0].id, semgrepFindings[1].id);
  assert.deepEqual(new Set(trivyFindings.map((finding) => finding.source)), new Set(['package_scan', 'iac_scan', 'secret_scan']));
  assert.equal(syftFindings[0].source, 'sbom_scan');
  assert.equal(JSON.stringify(trivyFindings).includes('matched-secret-value'), false);
});
