import fs from 'node:fs/promises';
import {
  buildGraphArtifact,
  buildOwaspWebAssuranceSummary,
  buildStaticAttackPathCandidates,
  extractSbomManifest,
  makeGitHubFindings,
  scanForCspmConfigs,
  scanForIacIssues,
  scanForSastPatterns,
  scanForSecrets,
  scanPackageDependencies,
} from './attackPathsJobRunner.js';
import { materializeRepoFromGitHub } from './repoMaterializer.js';
import { detectScannerTools, ensureJobWorkspace, type ScannerRunResult } from '../scanners/scannerRunner.js';
import { parseGitleaksFindings, parseSemgrepFindings, parseSyftFindings, parseTrivyFindings, runGitleaks, runSemgrep, runSyft, runTrivy } from '../scanners/scannerWrappers.js';
import { fetchRepoSecurityData } from '../scanners/githubGraphScanner.js';
import { transformVulnerabilityAlerts } from '../scanners/vulnerabilityTransform.js';
import type { RemoteScanInput } from '../clients/servxControlPlaneClient.js';

type Reporter = {
  progress: (update: { status: string; progressPct: number; phaseMessage: string }) => Promise<void>;
  complete: (payload: Record<string, unknown>) => Promise<void>;
  fail: (lastError: string, progressPct?: number) => Promise<void>;
};

function assertNotCancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error('Scan cancelled by the user.');
}

function skipped(tool: string, message: string): ScannerRunResult {
  return { tool, status: 'skipped', findingsCount: 0, artifacts: [], error: message };
}

function safeError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error || 'Repository scan failed')).replace(/(?:ghp|github_pat|gho|ghu|ghs|ghx)_[A-Za-z0-9_]+/g, '[REDACTED]').slice(0, 4_000);
}

/** Runs a ServX-dispatched repository scan. It never reads MongoDB or decrypts stored tokens. */
export async function runRemoteAttackPathsJob(input: RemoteScanInput, reporter: Reporter, signal?: AbortSignal): Promise<void> {
  const jobDir = await ensureJobWorkspace(input.jobId);
  try {
    assertNotCancelled(signal);
    if (input.targetUrl) throw new Error('Live deployment scanning is not enabled. It requires ownership verification and outbound-network isolation before release.');
    if (!input.repoFullName.includes('/')) throw new Error('Invalid repository name supplied by the control plane.');
    const [owner, repo] = input.repoFullName.split('/');
    const repoId = input.repoId || input.jobId;
    const failedScanners: Array<{ scanner: string; error: string }> = [];

    await reporter.progress({ status: 'cpgraph_building', progressPct: 8, phaseMessage: 'Preparing the authorized repository source.' });
    const materialized = await materializeRepoFromGitHub({
      jobId: input.jobId,
      repoFullName: input.repoFullName,
      accessToken: input.githubAccessToken,
      maxFilesToFetch: input.profile === 'deep_repo' ? 120 : 60,
    });
    assertNotCancelled(signal);
    const files = materialized.files.map((file) => ({ path: file.path, content: file.content }));
    if (files.length === 0) throw new Error('The authorized repository contained no supported source files to scan.');

    await reporter.progress({ status: 'cpgraph_analyzing', progressPct: 20, phaseMessage: 'Reading GitHub alerts and repository dependencies.' });
    const [githubFindings, packageFindings] = await Promise.all([
      fetchRepoSecurityData(owner, repo, input.githubAccessToken)
        .then((data) => makeGitHubFindings(repoId, transformVulnerabilityAlerts(data.nodes).alerts))
        .catch((error) => { failedScanners.push({ scanner: 'github_security_alerts', error: safeError(error) }); return []; }),
      scanPackageDependencies(input.githubAccessToken, owner, repo, repoId)
        .catch((error) => { failedScanners.push({ scanner: 'package_dependency_scan', error: safeError(error) }); return []; }),
    ]);

    const available = await detectScannerTools(['gitleaks', 'semgrep', 'trivy', 'syft']);
    const installed = new Set(available.filter((tool) => tool.installed).map((tool) => tool.name));
    const toolStatuses: ScannerRunResult[] = [];
    await reporter.progress({ status: 'cpgraph_analyzing', progressPct: 32, phaseMessage: 'Scanning source for exposed credentials.' });
    const gitleaks = installed.has('gitleaks') ? await runGitleaks({ repoDir: materialized.workDir, jobDir }) : skipped('gitleaks', 'Gitleaks is not installed on this executor.');
    toolStatuses.push(gitleaks);
    assertNotCancelled(signal);

    await reporter.progress({ status: 'harness_synthesizing', progressPct: 48, phaseMessage: 'Applying static source-security rules.' });
    const semgrep = installed.has('semgrep') ? await runSemgrep({ repoDir: materialized.workDir, jobDir }) : skipped('semgrep', 'Semgrep is not installed on this executor.');
    toolStatuses.push(semgrep);
    assertNotCancelled(signal);

    await reporter.progress({ status: 'sandbox_verifying', progressPct: 63, phaseMessage: 'Checking dependencies and infrastructure configuration.' });
    const trivy = installed.has('trivy') ? await runTrivy({ target: materialized.workDir, jobDir }) : skipped('trivy', 'Trivy is not installed on this executor.');
    toolStatuses.push(trivy);
    assertNotCancelled(signal);

    await reporter.progress({ status: 'sandbox_verifying', progressPct: 76, phaseMessage: 'Building the software inventory.' });
    const syft = installed.has('syft') ? await runSyft({ target: materialized.workDir, jobDir }) : skipped('syft', 'Syft is not installed on this executor.');
    toolStatuses.push(syft);
    assertNotCancelled(signal);

    const [builtinSecrets, builtinSast, builtinIac, builtinSbom, builtinCspm, gitleaksFindings, semgrepFindings, trivyFindings, syftFindings] = await Promise.all([
      scanForSecrets(repoId, files), scanForSastPatterns(repoId, files), scanForIacIssues(repoId, files), extractSbomManifest(repoId, files), scanForCspmConfigs(repoId, files),
      parseGitleaksFindings(repoId, gitleaks), parseSemgrepFindings(repoId, semgrep), parseTrivyFindings(repoId, trivy), parseSyftFindings(repoId, syft),
    ]);
    const secretFindings = [...builtinSecrets, ...gitleaksFindings];
    const sastFindings = [...builtinSast, ...semgrepFindings];
    const iacFindings = [...builtinIac, ...trivyFindings.filter((finding) => finding.source === 'iac_scan')];
    const packageScanFindings = [...packageFindings, ...trivyFindings.filter((finding) => finding.source === 'package_scan')];
    const sbomFindings = [...builtinSbom, ...syftFindings];
    const results = [...githubFindings, ...packageScanFindings, ...secretFindings, ...sastFindings, ...iacFindings, ...sbomFindings, ...builtinCspm];
    const assuranceSummary = buildOwaspWebAssuranceSummary(results, toolStatuses);
    const attackPathCandidates = buildStaticAttackPathCandidates(files, results);

    await reporter.progress({ status: 'rendering_report', progressPct: 92, phaseMessage: 'Normalizing evidence for review.' });
    await reporter.complete({
      phaseMessage: failedScanners.length ? 'Repository scan completed with partial coverage.' : 'Repository scan completed.',
      results,
      toolStatuses: toolStatuses.map((tool) => ({ tool: tool.tool, status: tool.status, findingsCount: tool.findingsCount, error: tool.error || null })),
      graphArtifact: buildGraphArtifact({ repoFullName: input.repoFullName, targetUrl: '', githubFindings, packageScanFindings, secretFindings, sastFindings, iacFindings, dastFindings: [], sbomFindings, cspmFindings: builtinCspm, liveFindings: [], failedScanners, toolStatuses, assuranceSummary, candidates: attackPathCandidates }),
      reportArtifactUrl: '',
      lastError: failedScanners.map((item) => `${item.scanner}: ${item.error}`).join('; '),
      assuranceSummary,
    });
  } catch (error) {
    if (!signal?.aborted) await reporter.fail(safeError(error));
  } finally {
    await fs.rm(jobDir, { recursive: true, force: true }).catch(() => undefined);
  }
}
