import fs from 'fs/promises';
import {
  fetchRepoSecurityData,
  type GitHubCodeScanningAlert,
  type GitHubSecretScanningAlert,
} from '../scanners/githubGraphScanner.js';
import {
  transformVulnerabilityAlerts,
  type VulnerabilityItem,
} from '../scanners/vulnerabilityTransform.js';
import { materializeRepoFromGitHub } from './repoMaterializer.js';
import {
  ensureJobWorkspace,
  type ScannerRunResult,
} from '../scanners/scannerRunner.js';
import { materializeDeepRepoFromGitHub } from './deepRepoMaterializer.js';
import {
  runGitleaks,
  runTrivy,
  runSemgrep,
  runSyft,
  parseGitleaksFindings,
  parseSemgrepFindings,
  parseTrivyFindings,
  parseSyftFindings,
} from '../scanners/scannerWrappers.js';

const OSV_QUERY_BATCH_API_URL = 'https://api.osv.dev/v1/querybatch';
const MAX_OSV_QUERIES_PER_SCAN = 500;

type AttackPathFinding = {
  id: string;
  severity: 'critical' | 'medium' | 'low';
  title: string;
  detail: string;
  file?: string;
  source:
    | 'github_security_alert'
    | 'github_code_scanning'
    | 'github_secret_scanning'
    | 'live_deployment_scan'
    | 'package_scan'
    | 'secret_scan'
    | 'sast_scan'
    | 'iac_scan'
    | 'dast_scan'
    | 'sbom_scan'
    | 'cspm_scan';
  metadata?: Record<string, any>;
};

type OwaspCategoryStatus = 'covered' | 'partial' | 'not_assessed';
type OwaspVerdict = 'pass' | 'partial' | 'fail' | 'not_assessed';

type OwaspCategorySummary = {
  id: string;
  name: string;
  status: OwaspCategoryStatus;
  findingsCount: number;
  criticalCount: number;
  evidenceSources: string[];
  notes?: string;
};

type OwaspAssuranceSummary = {
  framework: 'OWASP Web Top 10';
  version: '2025';
  verdict: OwaspVerdict;
  coveragePct: number;
  totalFindings: number;
  categories: OwaspCategorySummary[];
};

type StaticAttackPathCandidate = {
  id: string;
  route: string;
  routeFile: string;
  authBoundary: 'present' | 'not_detected';
  findingId: string;
  findingTitle: string;
  findingFile?: string;
  severity: 'critical' | 'medium' | 'low';
  confidence: 'partial';
  note: string;
};

function safeRepoFullName(repoFullName: string) {
  return String(repoFullName || '').trim();
}

type DependencyCoordinate = {
  name: string;
  ecosystem: 'npm' | 'PyPI' | 'Go' | 'crates.io' | 'Maven';
  version: string;
  file: string;
};

function isExactVersion(version: string): boolean {
  return /^(?:v)?\d+(?:\.\d+){1,3}(?:[-+._][0-9A-Za-z.-]+)?$/.test(version.trim());
}

function addDependency(
  dependencies: Map<string, DependencyCoordinate>,
  candidate: DependencyCoordinate
): void {
  const name = candidate.name.trim();
  const version = candidate.version.trim();
  if (!name || !isExactVersion(version)) return;
  const key = `${candidate.ecosystem}:${name}@${version}`;
  if (!dependencies.has(key)) dependencies.set(key, { ...candidate, name, version });
}

function npmNameFromPackageLockPath(lockPath: string): string {
  const marker = 'node_modules/';
  const index = lockPath.lastIndexOf(marker);
  return index >= 0 ? lockPath.slice(index + marker.length) : '';
}

function addNpmDependencyTree(
  dependencies: Map<string, DependencyCoordinate>,
  entries: Record<string, any>,
  file: string
): void {
  for (const [name, data] of Object.entries(entries || {})) {
    if (!data || typeof data !== 'object') continue;
    addDependency(dependencies, { name, version: String((data as any).version || ''), ecosystem: 'npm', file });
    addNpmDependencyTree(dependencies, (data as any).dependencies || {}, file);
  }
}

function addCargoLockDependencies(dependencies: Map<string, DependencyCoordinate>, content: string, file: string): void {
  let current: Record<string, string> = {};
  const flush = () => {
    addDependency(dependencies, {
      name: current.name || '',
      version: current.version || '',
      ecosystem: 'crates.io',
      file,
    });
    current = {};
  };

  for (const line of content.split(/\r?\n/)) {
    if (/^\[\[package\]\]\s*$/.test(line.trim())) {
      flush();
      continue;
    }
    const match = line.match(/^\s*(name|version)\s*=\s*"([^"]+)"\s*$/);
    if (match) current[match[1]] = match[2];
  }
  flush();
}

function addPoetryLockDependencies(dependencies: Map<string, DependencyCoordinate>, content: string, file: string): void {
  let current: Record<string, string> = {};
  const flush = () => {
    addDependency(dependencies, {
      name: current.name || '',
      version: current.version || '',
      ecosystem: 'PyPI',
      file,
    });
    current = {};
  };

  for (const line of content.split(/\r?\n/)) {
    if (/^\[\[package\]\]\s*$/.test(line.trim())) {
      flush();
      continue;
    }
    const match = line.match(/^\s*(name|version)\s*=\s*"([^"]+)"\s*$/);
    if (match) current[match[1]] = match[2];
  }
  flush();
}

function extractDependencyCoordinates(files: Array<{ path: string; content?: string }>): DependencyCoordinate[] {
  const dependencies = new Map<string, DependencyCoordinate>();

  for (const file of files) {
    const content = file.content || '';
    const baseName = file.path.split('/').pop()?.toLowerCase() || '';
    if (!content.trim()) continue;

    if (baseName === 'package-lock.json') {
      try {
        const lock = JSON.parse(content) as any;
        for (const [lockPath, packageData] of Object.entries(lock.packages || {})) {
          const name = npmNameFromPackageLockPath(lockPath);
          addDependency(dependencies, {
            name,
            version: String((packageData as any)?.version || ''),
            ecosystem: 'npm',
            file: file.path,
          });
        }
        addNpmDependencyTree(dependencies, lock.dependencies || {}, file.path);
      } catch {
        // A malformed lockfile is ignored here; the workflow scanner reports it separately.
      }
      continue;
    }

    if (baseName === 'package.json') {
      try {
        const manifest = JSON.parse(content) as any;
        for (const group of [manifest.dependencies, manifest.devDependencies, manifest.optionalDependencies]) {
          for (const [name, version] of Object.entries(group || {})) {
            addDependency(dependencies, { name, version: String(version || ''), ecosystem: 'npm', file: file.path });
          }
        }
      } catch {
        // Ignore malformed manifests; other scanners retain the parse failure as their own signal.
      }
      continue;
    }

    if (baseName === 'requirements.txt') {
      for (const line of content.split(/\r?\n/)) {
        const match = line.match(/^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)\s*(?:#.*)?$/);
        if (match) addDependency(dependencies, { name: match[1], version: match[2], ecosystem: 'PyPI', file: file.path });
      }
      continue;
    }

    if (baseName === 'pipfile.lock') {
      try {
        const lock = JSON.parse(content) as any;
        for (const group of [lock.default, lock.develop]) {
          for (const [name, packageData] of Object.entries(group || {})) {
            const version = String((packageData as any)?.version || '').replace(/^==/, '');
            addDependency(dependencies, { name, version, ecosystem: 'PyPI', file: file.path });
          }
        }
      } catch {
        // Ignore malformed Pipenv locks.
      }
      continue;
    }

    if (baseName === 'poetry.lock') {
      addPoetryLockDependencies(dependencies, content, file.path);
      continue;
    }

    if (baseName === 'go.mod') {
      let inRequireBlock = false;
      for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (line === 'require (') {
          inRequireBlock = true;
          continue;
        }
        if (inRequireBlock && line === ')') {
          inRequireBlock = false;
          continue;
        }
        const match = (inRequireBlock ? line : line.replace(/^require\s+/, '')).match(/^([^\s]+)\s+(v?\d+(?:\.\d+){1,3}(?:[-+._][0-9A-Za-z.-]+)?)/);
        if (match && (inRequireBlock || /^require\s+/.test(line))) {
          addDependency(dependencies, { name: match[1], version: match[2], ecosystem: 'Go', file: file.path });
        }
      }
      continue;
    }

    if (baseName === 'cargo.lock') {
      addCargoLockDependencies(dependencies, content, file.path);
      continue;
    }

    if (baseName === 'yarn.lock') {
      for (const stanza of content.split(/\r?\n\s*\r?\n/)) {
        const header = stanza.match(/^\s*([^\n:]+):\s*$/m)?.[1]?.split(',')[0]?.trim().replace(/^['"]|['"]$/g, '');
        const version = stanza.match(/^\s*version\s+["']([^"']+)["']\s*$/m)?.[1];
        const lastAt = header?.lastIndexOf('@') ?? -1;
        if (header && version && lastAt > 0) {
          addDependency(dependencies, { name: header.slice(0, lastAt), version, ecosystem: 'npm', file: file.path });
        }
      }
      continue;
    }

    if (baseName === 'pnpm-lock.yaml') {
      for (const line of content.split(/\r?\n/)) {
        const match = line.match(/^\s+['"]?((?:@[^/\s]+\/)?[^@'":\s]+)@(\d+(?:\.\d+){1,3}(?:[-+._][0-9A-Za-z.-]+)?)/);
        if (match) addDependency(dependencies, { name: match[1], version: match[2], ecosystem: 'npm', file: file.path });
      }
      continue;
    }

    if (baseName === 'pom.xml') {
      const dependencyPattern = /<dependency>([\s\S]*?)<\/dependency>/g;
      for (const match of content.matchAll(dependencyPattern)) {
        const groupId = match[1].match(/<groupId>\s*([^<\s]+)\s*<\/groupId>/)?.[1];
        const artifactId = match[1].match(/<artifactId>\s*([^<\s]+)\s*<\/artifactId>/)?.[1];
        const version = match[1].match(/<version>\s*([^<\s]+)\s*<\/version>/)?.[1];
        if (groupId && artifactId && version) {
          addDependency(dependencies, { name: `${groupId}:${artifactId}`, version, ecosystem: 'Maven', file: file.path });
        }
      }
      continue;
    }

    if (baseName === 'build.gradle' || baseName === 'build.gradle.kts') {
      const dependencyPattern = /(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*(?:\(|\s)\s*['"]([^:'"\s]+):([^:'"\s]+):([^'"\s)]+)['"]/g;
      for (const match of content.matchAll(dependencyPattern)) {
        addDependency(dependencies, {
          name: `${match[1]}:${match[2]}`,
          version: match[3],
          ecosystem: 'Maven',
          file: file.path,
        });
      }
    }
  }

  return Array.from(dependencies.values()).slice(0, MAX_OSV_QUERIES_PER_SCAN);
}

async function queryOsvForDependencies(
  dependencies: DependencyCoordinate[]
): Promise<Array<{ dependency: DependencyCoordinate; vulnerabilities: any[] }>> {
  const results: Array<{ dependency: DependencyCoordinate; vulnerabilities: any[] }> = [];
  const batchSize = 1000;

  for (let start = 0; start < dependencies.length; start += batchSize) {
    const batch = dependencies.slice(start, start + batchSize);
    const response = await fetch(OSV_QUERY_BATCH_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        queries: batch.map((dependency) => ({
          package: { name: dependency.name, ecosystem: dependency.ecosystem },
          version: dependency.version,
        })),
      }),
      cache: 'no-store',
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      throw new Error(`OSV query batch failed (${response.status})`);
    }

    const payload = (await response.json()) as any;
    const batchResults = Array.isArray(payload?.results) ? payload.results : [];
    for (let index = 0; index < batch.length; index += 1) {
      results.push({
        dependency: batch[index],
        vulnerabilities: Array.isArray(batchResults[index]?.vulns) ? batchResults[index].vulns : [],
      });
    }
  }

  return results;
}

function mapOsvSeverityToFindingSeverity(vulnerability: any): 'critical' | 'medium' | 'low' {
  const severity = vulnerability?.database_specific?.severity || vulnerability?.ecosystem_specific?.severity || vulnerability?.severity;
  const raw = typeof severity === 'string' ? severity.toLowerCase() : '';
  if (raw.includes('critical')) return 'critical';
  if (raw.includes('high')) return 'critical';
  if (raw.includes('moderate') || raw.includes('medium')) return 'medium';
  return 'low';
}

async function scanPackageDependencies(
  repoId: string,
  materializedFiles: Array<{ path: string; content?: string }>
): Promise<AttackPathFinding[]> {
  const findings: AttackPathFinding[] = [];
  const seen = new Set<string>();
  const dependencies = extractDependencyCoordinates(materializedFiles);
  const osvResults = await queryOsvForDependencies(dependencies);

  for (const { dependency, vulnerabilities } of osvResults) {
    for (const vuln of vulnerabilities) {
      const id = `${repoId}-osv-${dependency.ecosystem}-${dependency.name}-${dependency.version}-${String(vuln.id || 'unknown')}`;
      if (seen.has(id)) continue;
      seen.add(id);

      const summary = String(vuln.summary || vuln.details || `Known vulnerability in ${dependency.name}`).trim();
      const severity = mapOsvSeverityToFindingSeverity(vuln);

      findings.push({
        id,
        severity,
        title: `Dependency vulnerability: ${dependency.name}@${dependency.version}`,
        detail: summary,
        file: dependency.file,
        source: 'package_scan',
        metadata: {
          packageName: dependency.name,
          ecosystem: dependency.ecosystem,
          version: dependency.version,
          osvId: vuln.id,
          aliases: vuln.aliases || [],
          published: vuln.published || null,
          references: vuln.references || [],
          provenance: 'OSV query batch',
        },
      });
    }
  }

  return findings;
}

const AWS_ACCESS_KEY_RE = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/;
const GITHUB_TOKEN_RE = /\b(?:ghp|github_pat|gho|ghu|ghs|ghx)_[A-Za-z0-9_]{36,}\b/;
const GENERIC_API_KEY_RE = /(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['"][^'"]{12,}['"]/i;
const AWS_SECRET_RE = /(?:aws.{0,10}?(?:secret|password))\s*[:=]\s*['"][^'"]{12,}['"]/i;
const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\b/;
const BASIC_AUTH_RE = /authorization:\s*basic\s+[a-zA-Z0-9+/=]{20,}/i;

async function scanForSecrets(
  repoId: string,
  files: Array<{ path: string; content?: string }>
): Promise<AttackPathFinding[]> {
  const findings: AttackPathFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const content = file.content || '';
    if (!content.trim()) continue;

    const checks: Array<{ pattern: RegExp; title: string; detail: string; severity: 'critical' | 'medium' | 'low' }> = [
      {
        pattern: AWS_ACCESS_KEY_RE,
        title: 'AWS access key detected',
        detail: 'An AWS access key ID was detected in source. Rotate it immediately and move it to a secrets manager.',
        severity: 'critical',
      },
      {
        pattern: AWS_SECRET_RE,
        title: 'AWS secret reference detected',
        detail: 'A reference that looks like an AWS secret was detected. Rotate affected credentials and remove them from source.',
        severity: 'critical',
      },
      {
        pattern: GITHUB_TOKEN_RE,
        title: 'GitHub token detected',
        detail: 'A GitHub token or PAT was detected in source. Revoke it immediately and rotate to a stored secret.',
        severity: 'critical',
      },
      {
        pattern: JWT_RE,
        title: 'JWT-style token detected',
        detail: 'A bearer-style token was detected in source. Treat it as compromised and rotate it.',
        severity: 'critical',
      },
      {
        pattern: BASIC_AUTH_RE,
        title: 'Basic auth credential detected',
        detail: 'A base64-encoded basic auth credential was detected in source. Revoke and rotate it.',
        severity: 'critical',
      },
      {
        pattern: GENERIC_API_KEY_RE,
        title: 'Generic secret pattern detected',
        detail: 'A string assigned to a secret-like key was detected in source. Confirm it is not a production credential.',
        severity: 'medium',
      },
    ];

    for (const check of checks) {
      const match = content.match(check.pattern);
      if (!match) continue;

      const id = `${repoId}-secret-${file.path}-${check.title}`;
      if (seen.has(id)) continue;
      seen.add(id);

      findings.push({
        id,
        severity: check.severity,
        title: check.title,
        detail: check.detail,
        file: file.path,
        source: 'secret_scan',
        metadata: {
          pattern: check.title,
          matched: match[0] ? maskSecret(match[0]) : undefined,
        },
      });
    }
  }

  return findings;
}

function maskSecret(value: string): string {
  if (value.length <= 8) return '****';
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

async function scanForSastPatterns(
  repoId: string,
  files: Array<{ path: string; content?: string }>
): Promise<AttackPathFinding[]> {
  const findings: AttackPathFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const content = file.content || '';
    if (!content.trim()) continue;
    const lines = content.split(/\r?\n/);

    const patterns: Array<{ expression: RegExp; title: string; detail: string; severity: 'critical' | 'medium' | 'low' }> = [
      {
        expression: /\beval\s*\(/,
        title: 'Suspicious eval() usage',
        detail: 'eval() executes dynamic code and is a common source of injection attacks. Validate and remove it if possible.',
        severity: 'critical',
      },
      {
        expression: /new\s+Function\s*\(/,
        title: 'Suspicious Function constructor usage',
        detail: 'new Function() compiles dynamic code at runtime. Prefer static implementations.',
        severity: 'critical',
      },
      {
        expression: /innerHTML\s*=|document\.write\s*\(/,
        title: 'Potential DOM XSS sink',
        detail: 'Direct DOM manipulation with untrusted content can enable cross-site scripting. Use safe APIs.',
        severity: 'medium',
      },
      {
        expression: /(?:query|execute|exec)\s*\(\s*(?:`|\${)/,
        title: 'Potential SQL/command injection',
        detail: 'Dynamic query or command assembly was detected. Use parameterized queries or validated inputs.',
        severity: 'critical',
      },
      {
        expression: /\.exec\s*\(/,
        title: 'Potential command execution',
        detail: 'Child process execution was detected. Avoid shell execution with unsanitized input.',
        severity: 'medium',
      },
      {
        expression: /\$or\s*:\s*\[/,
        title: 'Potential NoSQL injection',
        detail: 'Mongo-style query operators are being constructed dynamically. Validate input types.',
        severity: 'medium',
      },
    ];

    for (const pattern of patterns) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = line.match(pattern.expression);
        if (!match) continue;

        const id = `${repoId}-sast-${file.path}-${i + 1}-${pattern.title}`;
        if (seen.has(id)) continue;
        seen.add(id);

        findings.push({
          id,
          severity: pattern.severity,
          title: pattern.title,
          detail: pattern.detail,
          file: `${file.path}:${i + 1}`,
          source: 'sast_scan',
          metadata: {
            line: i + 1,
            snippet: line.trim(),
          },
        });
      }
    }
  }

  return findings;
}

/**
 * Builds only evidence-backed, source-local path candidates. A route and a
 * dangerous sink must occur in the same source file; the result remains
 * `partial` until later control-flow and deployment verification exist.
 */
export function buildStaticAttackPathCandidates(
  files: Array<{ path: string; content?: string }>,
  findings: AttackPathFinding[]
): StaticAttackPathCandidate[] {
  const candidates: StaticAttackPathCandidate[] = [];
  const seen = new Set<string>();
  const sinkFindings = findings.filter((finding) => finding.source === 'sast_scan');

  for (const file of files) {
    const content = file.content || '';
    if (!content) continue;
    const routes = new Set<string>();
    for (const match of content.matchAll(/\b(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/g)) {
      routes.add(match[1]);
    }
    const nextRoute = file.path.match(/(?:^|\/)app\/api\/(.+)\/route\.(?:[cm]?[jt]sx?)$/i);
    if (nextRoute) routes.add(`/api/${nextRoute[1].replace(/\/\[\.\.\.([^\]]+)\]/g, ':$1*').replace(/\/\[([^\]]+)\]/g, ':$1')}`);
    if (routes.size === 0) continue;

    const authBoundary: StaticAttackPathCandidate['authBoundary'] =
      /\b(?:requireAuth|authenticate|authMiddleware|withAuth|isAuthenticated|authorize|permission)\b/i.test(content)
        ? 'present'
        : 'not_detected';
    const fileFindings = sinkFindings.filter((finding) => String(finding.file || '').replace(/:\d+(?::\d+)?$/, '') === file.path);
    for (const route of routes) {
      for (const finding of fileFindings) {
        const id = `candidate-${route}-${finding.id}`.replace(/[^a-zA-Z0-9-_]/g, '_').slice(0, 140);
        if (seen.has(id)) continue;
        seen.add(id);
        candidates.push({
          id,
          route,
          routeFile: file.path,
          authBoundary,
          findingId: finding.id,
          findingTitle: finding.title,
          findingFile: finding.file,
          severity: finding.severity,
          confidence: 'partial',
          note: 'Source-local route-to-sink candidate. Control flow, reachability, and deployment exposure are not verified.',
        });
      }
    }
  }

  return candidates.slice(0, 100);
}

async function scanForIacIssues(
  repoId: string,
  files: Array<{ path: string; content?: string }>
): Promise<AttackPathFinding[]> {
  const findings: AttackPathFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const content = file.content || '';
    const fileName = file.path.split('/').pop()?.toLowerCase() || '';

    if (fileName === 'dockerfile' || /dockerfile/i.test(file.path)) {
      if (/USER\s+root/i.test(content) && !/USER\s+(?!root\b)[a-zA-Z0-9_-]+/i.test(content)) {
        const id = `${repoId}-iac-root-${file.path}`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push({
            id,
            severity: 'medium',
            title: 'Container runs as root',
            detail: 'The Dockerfile does not downgrade to a non-root user. Run containers with the least privilege.',
            file: file.path,
            source: 'iac_scan',
          });
        }
      }

      if (!/HEALTHCHECK/i.test(content)) {
        const id = `${repoId}-iac-healthcheck-${file.path}`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push({
            id,
            severity: 'low',
            title: 'Missing docker HEALTHCHECK',
            detail: 'A HEALTHCHECK instruction helps orchestrators detect unhealthy containers earlier.',
            file: file.path,
            source: 'iac_scan',
          });
        }
      }
    }

    if (fileName === 'vercel.json' || /vercel/i.test(file.path)) {
      if (!/content-security-policy/i.test(content)) {
        const id = `${repoId}-iac-csp-${file.path}`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push({
            id,
            severity: 'medium',
            title: 'Missing CSP header in Vercel config',
            detail: 'Add a Content-Security-Policy header in vercel.json to mitigate XSS risk.',
            file: file.path,
            source: 'iac_scan',
          });
        }
      }

      if (/cors|access-control-allow-origin[\s\S]*?\*/i.test(content)) {
        const id = `${repoId}-iac-cors-${file.path}`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push({
            id,
            severity: 'medium',
            title: 'Overly permissive CORS configuration',
            detail: 'CORS is allowing all origins. Restrict access to trusted domains.',
            file: file.path,
            source: 'iac_scan',
          });
        }
      }
    }

    if (fileName.endsWith('.tf') || fileName === 'render.yaml' || fileName === 'render.yml') {
      const hasPublicBucket = /public\s*[:=]\s*true|acl\s*[:=]\s*['"]public['"]/i.test(content);
      if (hasPublicBucket) {
        const id = `${repoId}-iac-public-bucket-${file.path}`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push({
            id,
            severity: 'critical',
            title: 'Public bucket exposure detected in IaC',
            detail: 'Infrastructure as code allows public object access. Restrict bucket access to private or required principals.',
            file: file.path,
            source: 'iac_scan',
          });
        }
      }
    }
  }

  return findings;
}

async function scanForDastSignals(repoId: string, targetUrl: string): Promise<AttackPathFinding[]> {
  const findings: AttackPathFinding[] = [];

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'manual',
      cache: 'no-store',
    });

    const headers = response.headers;

    if (!headers.has('x-content-type-options')) {
      findings.push({
        id: `${repoId}-dast-mime-sniffing`,
        severity: 'low',
        title: 'Missing X-Content-Type-Options header',
        detail: 'Add the X-Content-Type-Options nosniff header to prevent MIME type confusion attacks.',
        file: targetUrl,
        source: 'dast_scan',
      });
    }

    if (!headers.has('strict-transport-security')) {
      findings.push({
        id: `${repoId}-dast-hsts`,
        severity: 'medium',
        title: 'Missing HSTS header',
        detail: 'Add Strict-Transport-Security to enforce HTTPS on future requests.',
        file: targetUrl,
        source: 'dast_scan',
      });
    }

    if (!headers.has('x-frame-options') && !/frame-ancestors/i.test(headers.get('content-security-policy') || '')) {
      findings.push({
        id: `${repoId}-dast-clickjack`,
        severity: 'medium',
        title: 'Missing clickjacking protection',
        detail: 'Add X-Frame-Options or a frame-ancestors CSP directive to prevent clickjacking.',
        file: targetUrl,
        source: 'dast_scan',
      });
    }

    if (headers.get('access-control-allow-origin') === '*') {
      findings.push({
        id: `${repoId}-dast-cors`,
        severity: 'medium',
        title: 'Wildcard CORS on live target',
        detail: 'Access-Control-Allow-Origin is *, which allows any origin to read authenticated responses.',
        file: targetUrl,
        source: 'dast_scan',
      });
    }

    const cookieHeader = headers.get('set-cookie') || '';
    if (cookieHeader.length > 0 && !/secure/i.test(cookieHeader)) {
      findings.push({
        id: `${repoId}-dast-cookie-secure`,
        severity: 'medium',
        title: 'Cookie missing Secure flag',
        detail: 'Session cookies should include the Secure flag to enforce HTTPS-only transmission.',
        file: targetUrl,
        source: 'dast_scan',
      });
    }
  } catch {
    // ignore live target probe failures
  }

  return findings;
}

async function extractSbomManifest(repoId: string, files: Array<{ path: string; content?: string }>): Promise<AttackPathFinding[]> {
  const findings: AttackPathFinding[] = [];
  const seen = new Set<string>();

  const manifestFiles = files.filter((file) => /(^|\/)package\.json$|(^|\/)package-lock\.json$|(^|\/)yarn\.lock$|(^|\/)pnpm-lock\.yaml$|(^|\/)bun\.lockb$|(^|\/)go\.mod$/i.test(file.path));

  if (manifestFiles.length === 0) {
    return findings;
  }

  for (const file of manifestFiles) {
    const id = `${repoId}-sbom-${file.path}`;
    if (seen.has(id)) continue;
    seen.add(id);

    const ext = file.path.split('.').pop()?.toLowerCase();
    findings.push({
      id,
      severity: 'low',
      title: 'Software inventory found',
      detail: `A ${ext ? ext.toUpperCase() : 'manifest'} file was detected at ${file.path}. Keep it updated to maintain an accurate supply-chain inventory.`,
      file: file.path,
      source: 'sbom_scan',
      metadata: {
        manifestType: ext || 'unknown',
      },
    });
  }

  return findings;
}

async function scanForCspmConfigs(repoId: string, files: Array<{ path: string; content?: string }>): Promise<AttackPathFinding[]> {
  const findings: AttackPathFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const content = file.content || '';
    if (!content.trim()) continue;

    if (/(^|\/)\.env(\.|$)/i.test(file.path)) {
      const id = `${repoId}-cspm-${file.path}-env`;
      if (!seen.has(id)) {
        seen.add(id);
        findings.push({
          id,
          severity: 'medium',
          title: 'Environment file detected',
          detail: 'An environment file was detected. Verify no production secrets are stored in it.',
          file: file.path,
          source: 'cspm_scan',
        });
      }
    }

    if (/(aws|gcp|azure|iam|bucket|storage|cloud)/i.test(file.path)) {
      const id = `${repoId}-cspm-${file.path}-cloud`;
      if (!seen.has(id)) {
        seen.add(id);
        findings.push({
          id,
          severity: 'medium',
          title: 'Cloud credentials or config reference detected',
          detail: 'Files reference cloud provider configurations. Ensure least-privilege IAM and audit external access.',
          file: file.path,
          source: 'cspm_scan',
        });
      }
    }
  }

  return findings;
}

function mapSeverity(value: string | undefined): 'critical' | 'medium' | 'low' {
  const upper = String(value || '').toUpperCase();
  if (upper === 'CRITICAL' || upper === 'HIGH') return 'critical';
  if (upper === 'MODERATE' || upper === 'MEDIUM') return 'medium';
  return 'low';
}

function makeGitHubFindings(repoId: string, alerts: VulnerabilityItem[]): AttackPathFinding[] {
  return alerts.map((alert, index) => ({
    id: `${repoId}-gh-${index + 1}`,
    severity: mapSeverity(alert.severity),
    title: `Dependency vulnerability: ${alert.packageName}`,
    detail: [
      alert.advisorySummary || 'Open GitHub security alert detected for this dependency.',
      alert.vulnerableVersionRange ? `Affected: ${alert.vulnerableVersionRange}.` : null,
      alert.firstPatchedVersion ? `Patch: ${alert.firstPatchedVersion}.` : null,
      typeof alert.cvssScore === 'number' ? `CVSS: ${alert.cvssScore}.` : null,
    ]
      .filter(Boolean)
      .join(' '),
    file: 'package manifest / dependency graph',
    source: 'github_security_alert',
    metadata: {
      packageName: alert.packageName,
      severity: alert.severity,
      cvssScore: alert.cvssScore,
      createdAt: alert.createdAt,
      provenance: 'GitHub Dependabot alert',
    },
  }));
}

function mapGitHubCodeSeverity(value: string | undefined): 'critical' | 'medium' | 'low' {
  const severity = String(value || '').toLowerCase();
  if (severity === 'critical' || severity === 'high' || severity === 'error') return 'critical';
  if (severity === 'medium' || severity === 'moderate' || severity === 'warning') return 'medium';
  return 'low';
}

function makeGitHubCodeScanningFindings(repoId: string, alerts: GitHubCodeScanningAlert[]): AttackPathFinding[] {
  return alerts.map((alert) => ({
    id: `${repoId}-gh-code-${alert.number}`,
    severity: mapGitHubCodeSeverity(alert.severity),
    title: `GitHub code scanning: ${alert.ruleId}`,
    detail: alert.description || 'Open GitHub code-scanning alert detected for this repository.',
    file: alert.path ? `${alert.path}${alert.startLine ? `:${alert.startLine}` : ''}` : 'repository source',
    source: 'github_code_scanning',
    metadata: {
      alertNumber: alert.number,
      ruleId: alert.ruleId,
      tags: alert.tags,
      toolName: alert.toolName || null,
      htmlUrl: alert.htmlUrl || null,
      createdAt: alert.createdAt || null,
      provenance: 'GitHub code scanning alert',
    },
  }));
}

function makeGitHubSecretScanningFindings(repoId: string, alerts: GitHubSecretScanningAlert[]): AttackPathFinding[] {
  return alerts.map((alert) => {
    const activeOrPublic = alert.validity === 'active' || alert.publiclyLeaked;
    const secretType = alert.secretTypeDisplayName || alert.secretType;
    return {
      id: `${repoId}-gh-secret-${alert.number}`,
      severity: activeOrPublic ? 'critical' : 'medium',
      title: `GitHub secret scanning: ${secretType}`,
      detail: activeOrPublic
        ? 'GitHub reports an active or publicly leaked secret. Revoke and rotate it immediately; the secret value is intentionally not displayed by ServX.'
        : 'GitHub reports a potential secret. Confirm exposure, then revoke and rotate it if valid; the secret value is intentionally not displayed by ServX.',
      file: 'GitHub secret scanning alert',
      source: 'github_secret_scanning',
      metadata: {
        alertNumber: alert.number,
        secretType: alert.secretType,
        validity: alert.validity || null,
        publiclyLeaked: Boolean(alert.publiclyLeaked),
        htmlUrl: alert.htmlUrl || null,
        createdAt: alert.createdAt || null,
        provenance: 'GitHub secret scanning alert',
      },
    };
  });
}

function makeLiveFindings(repoId: string, targetUrl: string, findings: Array<{ type: string; pattern: string; context: string; source: string }>): AttackPathFinding[] {
  return findings.map((finding, index) => ({
    id: `${repoId}-live-${index + 1}`,
    severity: finding.pattern === 'aws_key' || finding.pattern === 'stripe' || finding.pattern === 'github' ? 'critical' : 'medium',
    title: `Live exposure detected: ${finding.pattern}`,
    detail: `${finding.type} observed while scanning ${targetUrl}. ${finding.context}`,
    file: finding.source,
    source: 'live_deployment_scan',
    metadata: {
      pattern: finding.pattern,
      source: finding.source,
      targetUrl,
    },
  }));
}

function categoriesForFinding(finding: AttackPathFinding): string[] {
  const source = finding.source;
  const title = finding.title.toLowerCase();

  if (source === 'github_security_alert' || source === 'package_scan' || source === 'sbom_scan') {
    return ['A08'];
  }
  if (source === 'github_secret_scanning' || source === 'secret_scan' || title.includes('token') || title.includes('key')) {
    return ['A04', 'A02'];
  }
  if (source === 'iac_scan' || source === 'cspm_scan') {
    return ['A02'];
  }
  if (source === 'dast_scan' || source === 'live_deployment_scan') {
    if (title.includes('cors') || title.includes('access control') || title.includes('clickjacking')) return ['A01', 'A02'];
    if (title.includes('cookie') || title.includes('hsts') || title.includes('header')) return ['A02'];
    return ['A05', 'A02'];
  }
  if (source === 'github_code_scanning' || source === 'sast_scan') {
    if (title.includes('injection')) return ['A05'];
    if (title.includes('eval') || title.includes('function constructor')) return ['A06'];
    if (title.includes('xss')) return ['A03'];
    return ['A05'];
  }
  return [];
}

function buildOwaspWebAssuranceSummary(findings: AttackPathFinding[], toolStatuses: ScannerRunResult[]): OwaspAssuranceSummary {
  const categories: Array<{ id: string; name: string; assessable: boolean }> = [
    { id: 'A01', name: 'Broken Access Control', assessable: true },
    { id: 'A02', name: 'Security Misconfiguration', assessable: true },
    { id: 'A03', name: 'Cross-Site Scripting / Client-Side Injection', assessable: true },
    { id: 'A04', name: 'Cryptographic Failures', assessable: true },
    { id: 'A05', name: 'Injection', assessable: true },
    { id: 'A06', name: 'Insecure Design', assessable: false },
    { id: 'A08', name: 'Software and Data Integrity Failures', assessable: true },
    { id: 'A09', name: 'Security Logging and Monitoring Failures', assessable: false },
  ];

  const summaries: OwaspCategorySummary[] = categories.map((category) => {
    const relatedFindings = findings.filter((finding) => categoriesForFinding(finding).includes(category.id));
    const criticalCount = relatedFindings.filter((finding) => finding.severity === 'critical').length;
    const evidenceSources = Array.from(new Set(relatedFindings.map((finding) => finding.source)));

    let status: OwaspCategoryStatus = 'not_assessed';
    let notes = '';

    if (!category.assessable) {
      status = 'not_assessed';
      notes = 'Requires architectural review or non-automated assessment.';
    } else if (relatedFindings.length > 0) {
      status = 'covered';
      if (criticalCount > 0) {
        notes = `${criticalCount} critical findings require remediation.`;
      }
    } else {
      const hasRelevantTool =
        (category.id === 'A01' && findings.some((f) => f.source === 'dast_scan' || f.source === 'live_deployment_scan')) ||
        (category.id === 'A02' && findings.some((f) => f.source === 'iac_scan' || f.source === 'cspm_scan' || f.source === 'dast_scan')) ||
        (category.id === 'A03' && findings.some((f) => f.source === 'sast_scan' || f.source === 'github_code_scanning')) ||
        (category.id === 'A04' && findings.some((f) => f.source === 'secret_scan' || f.source === 'github_secret_scanning')) ||
        (category.id === 'A05' && findings.some((f) => f.source === 'sast_scan' || f.source === 'github_code_scanning' || f.source === 'dast_scan')) ||
        (category.id === 'A08' && findings.some((f) => f.source === 'package_scan' || f.source === 'github_security_alert' || f.source === 'sbom_scan'));

      status = hasRelevantTool ? 'partial' : 'not_assessed';
      notes = hasRelevantTool ? 'Coverage exists, but no direct finding was detected in this run.' : 'No scanner evidence for this category.';
    }

    return {
      id: category.id,
      name: category.name,
      status,
      findingsCount: relatedFindings.length,
      criticalCount,
      evidenceSources,
      notes,
    };
  });

  const assessable = summaries.filter((item) => item.status !== 'not_assessed' || categories.find((c) => c.id === item.id)?.assessable);
  const covered = summaries.filter((item) => item.status === 'covered').length;
  const partial = summaries.filter((item) => item.status === 'partial').length;
  const critical = findings.filter((finding) => finding.severity === 'critical').length;
  const coveragePct = Math.round((covered / Math.max(1, assessable.length)) * 100);

  let verdict: OwaspVerdict = 'not_assessed';
  if (findings.length === 0 && partial === 0 && covered === 0) {
    verdict = 'not_assessed';
  } else if (critical > 0) {
    verdict = 'fail';
  } else if (partial > 0 || summaries.some((item) => item.status === 'not_assessed' && categories.find((c) => c.id === item.id)?.assessable)) {
    verdict = 'partial';
  } else {
    verdict = 'pass';
  }

  return {
    framework: 'OWASP Web Top 10',
    version: '2025',
    verdict,
    coveragePct,
    totalFindings: findings.length,
    categories: summaries,
  };
}

function buildGraphArtifact(params: {
  repoFullName: string;
  targetUrl: string;
  githubFindings: AttackPathFinding[];
  packageScanFindings: AttackPathFinding[];
  secretFindings: AttackPathFinding[];
  sastFindings: AttackPathFinding[];
  iacFindings: AttackPathFinding[];
  dastFindings: AttackPathFinding[];
  sbomFindings: AttackPathFinding[];
  cspmFindings: AttackPathFinding[];
  liveFindings: AttackPathFinding[];
  failedScanners: Array<{ scanner: string; error: string }>;
  toolStatuses: ScannerRunResult[];
  assuranceSummary: OwaspAssuranceSummary;
  attackPathCandidates: StaticAttackPathCandidate[];
}) {
  const {
    repoFullName,
    targetUrl,
    githubFindings,
    packageScanFindings,
    secretFindings,
    sastFindings,
    iacFindings,
    dastFindings,
    sbomFindings,
    cspmFindings,
    liveFindings,
    failedScanners,
    toolStatuses,
    assuranceSummary,
    attackPathCandidates,
  } = params;

  const nodes: any[] = [
    { id: 'repo', type: 'repo', label: repoFullName },
    { id: 'deps', type: 'scan', label: 'GitHub Security Alerts' },
    { id: 'packages', type: 'scan', label: 'Package Dependency Scan (OSV)' },
  ];
  const edges: any[] = [
    { from: 'repo', to: 'deps', type: 'analyzes' },
    { from: 'repo', to: 'packages', type: 'analyzes' },
  ];

  if (secretFindings.length || toolStatuses.some((t) => t.tool === 'gitleaks')) {
    nodes.push({ id: 'secrets', type: 'scan', label: 'Secret Scan' });
    edges.push({ from: 'repo', to: 'secrets', type: 'analyzes' });
  }
  if (sastFindings.length || toolStatuses.some((t) => t.tool === 'semgrep')) {
    nodes.push({ id: 'sast', type: 'scan', label: 'SAST Scan' });
    edges.push({ from: 'repo', to: 'sast', type: 'analyzes' });
  }
  if (iacFindings.length || toolStatuses.some((t) => t.tool === 'trivy')) {
    nodes.push({ id: 'iac', type: 'scan', label: 'IaC Scan' });
    edges.push({ from: 'repo', to: 'iac', type: 'analyzes' });
  }
  if (dastFindings.length || toolStatuses.some((t) => t.tool === 'nuclei')) {
    nodes.push({ id: 'dast', type: 'scan', label: 'DAST Signals' });
    edges.push({ from: 'repo', to: 'dast', type: 'analyzes' });
  }

  if (targetUrl) {
    nodes.push({ id: 'live', type: 'scan', label: targetUrl });
    edges.push({ from: 'repo', to: 'live', type: 'analyzes' });
  }

  if (sbomFindings.length || toolStatuses.some((t) => t.tool === 'syft')) {
    nodes.push({ id: 'sbom', type: 'inventory', label: 'SBOM / Inventory' });
    edges.push({ from: 'repo', to: 'sbom', type: 'analyzes' });
  }
  if (cspmFindings.length || toolStatuses.some((t) => t.tool === 'cloudsploit')) {
    nodes.push({ id: 'cspm', type: 'scan', label: 'CSPM Configs' });
    edges.push({ from: 'repo', to: 'cspm', type: 'analyzes' });
  }

  for (const candidate of attackPathCandidates) {
    const routeNodeId = `route-${candidate.id}`;
    const sinkNodeId = `sink-${candidate.findingId}`;
    nodes.push({
      id: routeNodeId,
      type: 'route',
      label: candidate.route,
      metadata: { file: candidate.routeFile, authBoundary: candidate.authBoundary, confidence: candidate.confidence },
    });
    nodes.push({
      id: sinkNodeId,
      type: 'finding',
      label: candidate.findingTitle,
      metadata: { findingId: candidate.findingId, file: candidate.findingFile, severity: candidate.severity },
    });
    edges.push({ from: 'repo', to: routeNodeId, type: 'contains_route' });
    edges.push({ from: routeNodeId, to: sinkNodeId, type: 'potential_reachable_sink', confidence: 'partial' });
  }

  return {
    version: 'v5-owasp-web-assurance',
    summary: {
      repoFullName,
      targetUrl: targetUrl || null,
      githubFindings: githubFindings.length,
      githubSecuritySources: {
        dependabot: githubFindings.filter((finding) => finding.source === 'github_security_alert').length,
        codeScanning: githubFindings.filter((finding) => finding.source === 'github_code_scanning').length,
        secretScanning: githubFindings.filter((finding) => finding.source === 'github_secret_scanning').length,
      },
      packageScanFindings: packageScanFindings.length,
      secretFindings: secretFindings.length,
      sastFindings: sastFindings.length,
      iacFindings: iacFindings.length,
      dastFindings: dastFindings.length,
      sbomFindings: sbomFindings.length,
      cspmFindings: cspmFindings.length,
      liveFindings: liveFindings.length,
      totalFindings:
        githubFindings.length +
        packageScanFindings.length +
        secretFindings.length +
        sastFindings.length +
        iacFindings.length +
        dastFindings.length +
        sbomFindings.length +
        cspmFindings.length +
        liveFindings.length,
      assuranceSummary,
      toolStatuses: toolStatuses.map((tool) => ({
        tool: tool.tool,
        status: tool.status,
        findingsCount: tool.findingsCount,
        error: tool.error || null,
        artifacts: tool.artifacts.map((artifact) => ({
          kind: artifact.kind,
          sizeBytes: artifact.sizeBytes,
        })),
      })),
      failedScanners,
      attackPathCandidatesCount: attackPathCandidates.length,
    },
    nodes,
    edges,
    attackPathCandidates,
  };
}

export type RemoteAttackPathsJobInput = {
  jobId: string;
  repoId: string;
  repoFullName: string;
  targetUrl?: string;
  scanTypes: string[];
  analysisDepth: number;
  profile: 'quick' | 'deep_repo' | 'verified_live';
  executionLeaseId: string;
  leaseExpiresAt: string;
  githubAccessToken: string;
};

export type AttackPathsJobReporter = {
  progress: (update: { status: string; progressPct: number; phaseMessage: string }) => Promise<void>;
  complete: (update: Record<string, any>) => Promise<void>;
  fail: (update: { lastError: string; progressPct?: number }) => Promise<void>;
};

class ScanCancelledError extends Error {
  constructor() {
    super('Scan cancelled.');
    this.name = 'ScanCancelledError';
  }
}

function throwIfCancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ScanCancelledError();
}

async function processJob(job: any, reporter: AttackPathsJobReporter, signal?: AbortSignal): Promise<void> {
  const jobId = String(job._id);
  const repoId = String(job.repoId || jobId);
  const repoFullName = safeRepoFullName(job.repoFullName);
  const requestedTargetUrl = String(job.targetUrl || '').trim();
  const targetUrl = '';
  const isQuickProfile = job.profile === 'quick';
  const isDeepRepositoryProfile = job.profile === 'deep_repo';
  let jobDir = '';
  const githubAccessToken =
    typeof job.githubAccessToken === 'string' && job.githubAccessToken.trim()
      ? job.githubAccessToken.trim()
      : '';

  const reportProgress = async (update: { status: string; progressPct: number; phaseMessage: string }) => {
    await reporter.progress(update);
  };

  const reportCompletion = async (update: Record<string, any>) => {
    await reporter.complete(update);
  };

  try {
    throwIfCancelled(signal);
    if (!repoFullName.includes('/')) {
      throw new Error(`Invalid repoFullName for job: ${repoFullName}`);
    }
    if (!githubAccessToken) {
      throw new Error('ServX did not supply a GitHub token for this repository scan.');
    }
    if (job.profile === 'verified_live') {
      throw new Error('Live deployment scanning is not enabled yet. It requires ownership verification and outbound-network isolation before release.');
    }
    if (!isQuickProfile && !isDeepRepositoryProfile) {
      throw new Error('Unsupported scan profile.');
    }
    if (requestedTargetUrl) {
      throw new Error('Live deployment scanning is not enabled yet. It requires ownership verification and outbound-network isolation before release.');
    }

    const [owner, repo] = repoFullName.split('/');
    const failedScanners: Array<{ scanner: string; error: string }> = [];
    const toolStatuses: ScannerRunResult[] = [];

    jobDir = await ensureJobWorkspace(jobId);
    let repoScanDir = jobDir;

    await reportProgress({
      status: 'cpgraph_building',
      progressPct: 5,
      phaseMessage: 'Preparing repository scan inputs...',
    });

    let materializedFiles: Array<{ path: string; content?: string }> = [];
    try {
      throwIfCancelled(signal);
      const materializedRepo = await materializeRepoFromGitHub({
        jobId,
        repoFullName,
        accessToken: githubAccessToken,
        maxFilesToFetch: 200,
        signal,
      });
      materializedFiles = materializedRepo.files.map((file) => ({
        path: file.path,
        content: file.content,
      }));
      console.log(`[attackPathsJobRunner] Materialized ${materializedFiles.length} files for ${repoFullName}`);
    } catch (err: any) {
      failedScanners.push({
        scanner: 'repo_materializer',
        error: err?.message || 'Failed to materialize repository files',
      });
      console.warn(`[attackPathsJobRunner] Materialization failed for ${repoFullName}: ${err?.message || String(err)}`);
    }

    if (isDeepRepositoryProfile) {
      await reportProgress({
        status: 'cpgraph_building',
        progressPct: 10,
        phaseMessage: 'Preparing the authorized repository for deep scanning...',
      });
      try {
        throwIfCancelled(signal);
        const deepRepo = await materializeDeepRepoFromGitHub({
          jobDir,
          repoFullName,
          accessToken: githubAccessToken,
          signal,
        });
        repoScanDir = deepRepo.workDir;
        console.log(`[attackPathsJobRunner] Deep repository materialized at ${deepRepo.revision} (${deepRepo.sizeBytes} bytes).`);
      } catch (err: any) {
        failedScanners.push({
          scanner: 'deep_repo_materializer',
          error: err?.message || 'Failed to prepare repository for deep scanning',
        });
        console.warn(`[attackPathsJobRunner] Deep materialization failed for ${repoFullName}: ${err?.message || String(err)}`);
      }
    }

    await reportProgress({
      status: 'cpgraph_analyzing',
      progressPct: 18,
      phaseMessage: isQuickProfile
        ? 'Collecting GitHub alerts and bounded dependency evidence...'
        : 'Running queued deep repository scanners...',
    });

    const githubPromise = (async (): Promise<AttackPathFinding[]> => {
      console.log(`[attackPathsJobRunner] Fetching GitHub security alerts for ${repoFullName}...`);
      const raw = await fetchRepoSecurityData(owner, repo, githubAccessToken);
      const transformed = transformVulnerabilityAlerts(raw.nodes);
      for (const sourceFailure of raw.sourceErrors) {
        failedScanners.push({
          scanner: `github_${sourceFailure.source}`,
          error: sourceFailure.message,
        });
      }
      return [
        ...makeGitHubFindings(repoId, transformed.alerts),
        ...makeGitHubCodeScanningFindings(repoId, raw.codeScanningAlerts),
        ...makeGitHubSecretScanningFindings(repoId, raw.secretScanningAlerts),
      ];
    })();

    const packagePromise = (async (): Promise<AttackPathFinding[]> => {
      console.log(`[attackPathsJobRunner] Scanning package dependencies via OSV for ${repoFullName}...`);
      return scanPackageDependencies(repoId, materializedFiles);
    })();

    const builtinSecretPromise = scanForSecrets(repoId, materializedFiles);
    const builtinSastPromise = scanForSastPatterns(repoId, materializedFiles);
    const builtinIacPromise = scanForIacIssues(repoId, materializedFiles);
    const builtinSbomPromise = extractSbomManifest(repoId, materializedFiles);
    const builtinCspmPromise = scanForCspmConfigs(repoId, materializedFiles);
    const builtinDastPromise = Promise.resolve([] as AttackPathFinding[]);

    let gitleaksResult: ScannerRunResult = { tool: 'gitleaks', status: 'skipped', findingsCount: 0, artifacts: [], error: 'Deep profile was not requested.' };
    let semgrepResult: ScannerRunResult = { tool: 'semgrep', status: 'skipped', findingsCount: 0, artifacts: [], error: 'Deep profile was not requested.' };
    let trivyResult: ScannerRunResult = { tool: 'trivy', status: 'skipped', findingsCount: 0, artifacts: [], error: 'Deep profile was not requested.' };
    let syftResult: ScannerRunResult = { tool: 'syft', status: 'skipped', findingsCount: 0, artifacts: [], error: 'Deep profile was not requested.' };

    if (isDeepRepositoryProfile) {
      if (repoScanDir === jobDir) {
        const error = 'Deep repository workspace is unavailable.';
        gitleaksResult.error = error;
        semgrepResult.error = error;
        trivyResult.error = error;
        syftResult.error = error;
      } else {
        throwIfCancelled(signal);
        await reportProgress({
          status: 'cpgraph_analyzing',
          progressPct: 25,
          phaseMessage: 'Scanning repository history and source files for exposed secrets...',
        });
        gitleaksResult = await runGitleaks({ repoDir: repoScanDir, jobDir, signal });
        throwIfCancelled(signal);
        await reportProgress({
          status: 'cpgraph_analyzing',
          progressPct: 40,
          phaseMessage: 'Analyzing source code with Semgrep security rules...',
        });
        semgrepResult = await runSemgrep({ repoDir: repoScanDir, jobDir, signal });
        throwIfCancelled(signal);
        await reportProgress({
          status: 'cpgraph_analyzing',
          progressPct: 55,
          phaseMessage: 'Checking dependencies, secrets, and infrastructure configuration...',
        });
        trivyResult = await runTrivy({ target: repoScanDir, jobDir, signal });
        throwIfCancelled(signal);
        await reportProgress({
          status: 'sandbox_verifying',
          progressPct: 65,
          phaseMessage: 'Building the repository software inventory...',
        });
        syftResult = await runSyft({ target: repoScanDir, jobDir, signal });
        throwIfCancelled(signal);
      }
      toolStatuses.push(gitleaksResult, semgrepResult, trivyResult, syftResult);
      for (const tool of toolStatuses) {
        if (tool.status === 'failed') {
          failedScanners.push({
            scanner: tool.tool,
            error: tool.error || 'Scanner failed without an error message.',
          });
        }
      }
    }

    const [
      githubFindings,
      packageScanFindings,
      builtinSecretFindings,
      builtinSastFindings,
      builtinIacFindings,
      builtinSbomFindings,
      builtinCspmFindings,
      builtinDastFindings,
      gitleaksFindings,
      semgrepFindings,
      trivyFindings,
      syftFindings,
    ] = await Promise.all([
      githubPromise.catch((err: any) => {
        console.error(`[attackPathsJobRunner] GitHub security alerts fetch failed for ${repoFullName}: ${err?.message || String(err)}`);
        failedScanners.push({ scanner: 'github_security_alerts', error: err?.message || String(err) });
        return [] as AttackPathFinding[];
      }),
      packagePromise.catch((err: any) => {
        console.error(`[attackPathsJobRunner] Package dependency scan failed for ${repoFullName}: ${err?.message || String(err)}`);
        failedScanners.push({ scanner: 'package_dependency_scan', error: err?.message || String(err) });
        return [] as AttackPathFinding[];
      }),
      builtinSecretPromise.catch((err: any) => {
        console.error(`[attackPathsJobRunner] Secret scan failed for ${repoFullName}: ${err?.message || String(err)}`);
        failedScanners.push({ scanner: 'secret_scan', error: err?.message || String(err) });
        return [] as AttackPathFinding[];
      }),
      builtinSastPromise.catch((err: any) => {
        console.error(`[attackPathsJobRunner] SAST scan failed for ${repoFullName}: ${err?.message || String(err)}`);
        failedScanners.push({ scanner: 'sast_scan', error: err?.message || String(err) });
        return [] as AttackPathFinding[];
      }),
      builtinIacPromise.catch((err: any) => {
        console.error(`[attackPathsJobRunner] IaC scan failed for ${repoFullName}: ${err?.message || String(err)}`);
        failedScanners.push({ scanner: 'iac_scan', error: err?.message || String(err) });
        return [] as AttackPathFinding[];
      }),
      builtinSbomPromise.catch((err: any) => {
        console.error(`[attackPathsJobRunner] SBOM extraction failed for ${repoFullName}: ${err?.message || String(err)}`);
        failedScanners.push({ scanner: 'sbom_scan', error: err?.message || String(err) });
        return [] as AttackPathFinding[];
      }),
      builtinCspmPromise.catch((err: any) => {
        console.error(`[attackPathsJobRunner] CSPM config scan failed for ${repoFullName}: ${err?.message || String(err)}`);
        failedScanners.push({ scanner: 'cspm_scan', error: err?.message || String(err) });
        return [] as AttackPathFinding[];
      }),
      builtinDastPromise.catch((err: any) => {
        console.error(`[attackPathsJobRunner] DAST signal scan failed for ${repoFullName}: ${err?.message || String(err)}`);
        failedScanners.push({ scanner: 'dast_scan', error: err?.message || String(err) });
        return [] as AttackPathFinding[];
      }),
      parseGitleaksFindings(repoId, gitleaksResult),
      parseSemgrepFindings(repoId, semgrepResult),
      parseTrivyFindings(repoId, trivyResult),
      parseSyftFindings(repoId, syftResult),
    ]);

    await reportProgress({
      status: 'sandbox_verifying',
      progressPct: 70,
      phaseMessage: 'Finalizing bounded repository findings...',
    });

    const liveFindings: AttackPathFinding[] = [];

    await reportProgress({
      status: 'rendering_report',
      progressPct: 90,
      phaseMessage: 'Normalizing real findings for dashboard rendering...',
    });

    const secretFindings = [...builtinSecretFindings, ...gitleaksFindings];
    const sastFindings = [...builtinSastFindings, ...semgrepFindings];
    const iacFindings = [...builtinIacFindings, ...trivyFindings.filter((finding) => finding.source === 'iac_scan')];
    const packageScanFindingsMerged = [...packageScanFindings, ...trivyFindings.filter((finding) => finding.source === 'package_scan')];
    const sbomFindings = [...builtinSbomFindings, ...syftFindings];
    const cspmFindings = [...builtinCspmFindings];
    const dastFindings = [...builtinDastFindings];

    const repoFindings = [
      ...githubFindings,
      ...packageScanFindingsMerged,
      ...secretFindings,
      ...sastFindings,
      ...iacFindings,
      ...dastFindings,
    ];

    const summaryFindings = [...sbomFindings, ...cspmFindings];
    const results = [...repoFindings, ...liveFindings, ...summaryFindings];
    const attackPathCandidates = buildStaticAttackPathCandidates(materializedFiles, results);
    const scanArtifacts = toolStatuses.flatMap((tool) => tool.artifacts);
    const assuranceSummary = buildOwaspWebAssuranceSummary(results, toolStatuses);

    if (results.length === 0 && failedScanners.length > 0) {
      const errorMessages = failedScanners.map((item) => `${item.scanner}: ${item.error}`).join('; ');
      console.error(`[attackPathsJobRunner] All scanners failed for ${jobId}: ${errorMessages}`);
      throw new Error(errorMessages);
    }

    if (results.length === 0 && failedScanners.length === 0) {
      console.warn(`[attackPathsJobRunner] No findings for ${jobId}. Repo may have no detectable issues or GitHub token lacks permissions.`);
    }

    await reportCompletion({
      status: 'completed',
      progressPct: 100,
      phaseMessage:
        failedScanners.length > 0
          ? 'Repository evidence collection completed with partial coverage'
          : 'Repository evidence collection completed',
      results,
      scanArtifacts,
      toolStatuses: toolStatuses.map((tool) => ({
        tool: tool.tool,
        status: tool.status,
        findingsCount: tool.findingsCount,
        error: tool.error || null,
        rawExitCode: tool.rawExitCode ?? null,
        artifacts: tool.artifacts.map((artifact) => ({
          path: artifact.path,
          kind: artifact.kind,
          sizeBytes: artifact.sizeBytes,
        })),
      })),
      assuranceSummary,
      graphArtifact: buildGraphArtifact({
        repoFullName,
        targetUrl,
        githubFindings,
        packageScanFindings: packageScanFindingsMerged,
        secretFindings,
        sastFindings,
        iacFindings,
        dastFindings,
        sbomFindings,
        cspmFindings,
        liveFindings,
        failedScanners,
        toolStatuses,
        assuranceSummary,
        attackPathCandidates,
      }),
      reportArtifactUrl: '',
      lastError: failedScanners.length > 0 ? failedScanners.map((item) => `${item.scanner}: ${item.error}`).join('; ') : '',
    });

    console.log(`[attackPathsJobRunner] job completed successfully: ${jobId}`);
  } catch (err: any) {
    const lastError = err?.message || String(err);

    if (err instanceof ScanCancelledError || signal?.aborted) {
      console.log(`[attackPathsJobRunner] job cancelled: ${jobId}`);
      return;
    }

    await reporter.fail({ lastError, progressPct: job.progressPct || 0 });

    console.error(`[attackPathsJobRunner] job failed: ${jobId}`, err);
  } finally {
    if (jobDir) {
      await fs.rm(jobDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

/** Runs a ServX-dispatched job without connecting the executor to ServX MongoDB. */
export async function runRemoteAttackPathsJob(
  input: RemoteAttackPathsJobInput,
  reporter: AttackPathsJobReporter,
  signal?: AbortSignal
): Promise<void> {
  await processJob(
    {
      _id: input.jobId,
      repoId: input.repoId,
      repoFullName: input.repoFullName,
      targetUrl: input.targetUrl || '',
      profile: input.profile,
      scanTypes: input.scanTypes,
      analysisDepth: input.analysisDepth,
      githubAccessToken: input.githubAccessToken,
      progressPct: 0,
    },
    reporter,
    signal
  );
}
