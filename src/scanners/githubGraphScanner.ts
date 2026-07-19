import { ValidationError } from '../utils/errors.js';

const GITHUB_API_URL = 'https://api.github.com';
const ALERTS_PER_PAGE = 100;
const MAX_ALERT_PAGES = 10;
const REQUEST_TIMEOUT_MS = 15_000;

export type VulnerabilityAlertNode = {
  securityVulnerability?: {
    package?: { name?: string };
    severity?: string;
    vulnerableVersionRange?: string;
    firstPatchedVersion?: { identifier?: string } | null;
    advisory?: {
      summary?: string;
      cvss?: { score?: number } | null;
    } | null;
  } | null;
  createdAt?: string;
  htmlUrl?: string;
  manifestPath?: string;
  dependencyScope?: string;
};

export type GitHubCodeScanningAlert = {
  number: number;
  ruleId: string;
  severity?: string;
  description?: string;
  tags: string[];
  path?: string;
  startLine?: number;
  htmlUrl?: string;
  createdAt?: string;
  toolName?: string;
};

export type GitHubSecretScanningAlert = {
  number: number;
  secretType: string;
  secretTypeDisplayName?: string;
  validity?: string;
  publiclyLeaked?: boolean;
  htmlUrl?: string;
  createdAt?: string;
};

export type GitHubSecuritySourceError = {
  source: 'dependabot' | 'code_scanning' | 'secret_scanning';
  message: string;
};

export type RepoSecurityData = {
  totalCount: number;
  nodes: VulnerabilityAlertNode[];
  codeScanningAlerts: GitHubCodeScanningAlert[];
  secretScanningAlerts: GitHubSecretScanningAlert[];
  sourceErrors: GitHubSecuritySourceError[];
};

type PagedResponse = {
  rows: any[];
  truncated: boolean;
};

function repositoryPath(owner: string, repo: string, suffix: string): string {
  return `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}${suffix}`;
}

async function githubJson(token: string, path: string): Promise<unknown> {
  const response = await fetch(`${GITHUB_API_URL}${path}`, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': 'ServX-AttackPaths-Worker',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`GitHub API returned ${response.status}`);
  }
  return response.json();
}

async function listAlerts(token: string, path: string): Promise<PagedResponse> {
  const rows: any[] = [];
  const delimiter = path.includes('?') ? '&' : '?';

  for (let page = 1; page <= MAX_ALERT_PAGES; page += 1) {
    const payload = await githubJson(token, `${path}${delimiter}per_page=${ALERTS_PER_PAGE}&page=${page}`);
    if (!Array.isArray(payload)) {
      throw new Error('GitHub API returned an unexpected alert payload.');
    }
    rows.push(...payload);
    if (payload.length < ALERTS_PER_PAGE) return { rows, truncated: false };
  }

  return { rows, truncated: true };
}

function sourceError(source: GitHubSecuritySourceError['source'], error: unknown): GitHubSecuritySourceError {
  const message = error instanceof Error ? error.message : 'GitHub security source is unavailable.';
  return { source, message: message.slice(0, 240) };
}

function mapDependabotAlert(alert: any): VulnerabilityAlertNode {
  const vulnerability = alert?.security_vulnerability || {};
  const advisory = alert?.security_advisory || {};
  return {
    securityVulnerability: {
      package: { name: vulnerability?.package?.name },
      severity: vulnerability?.severity || advisory?.severity,
      vulnerableVersionRange: vulnerability?.vulnerable_version_range,
      firstPatchedVersion: vulnerability?.first_patched_version
        ? { identifier: vulnerability.first_patched_version.identifier }
        : null,
      advisory: {
        summary: advisory?.summary,
        cvss: typeof advisory?.cvss?.score === 'number' ? { score: advisory.cvss.score } : null,
      },
    },
    createdAt: alert?.created_at,
    htmlUrl: alert?.html_url,
    manifestPath: alert?.dependency?.manifest_path,
    dependencyScope: alert?.dependency?.scope,
  };
}

function mapCodeScanningAlert(alert: any): GitHubCodeScanningAlert {
  const instance = alert?.most_recent_instance || {};
  return {
    number: Number(alert?.number || 0),
    ruleId: String(alert?.rule?.id || 'github-code-scanning-rule'),
    severity: String(alert?.rule?.security_severity_level || alert?.rule?.severity || '').toLowerCase(),
    description: alert?.rule?.description || alert?.rule?.name,
    tags: Array.isArray(alert?.rule?.tags) ? alert.rule.tags.map(String) : [],
    path: instance?.location?.path,
    startLine: Number.isFinite(instance?.location?.start_line) ? instance.location.start_line : undefined,
    htmlUrl: alert?.html_url,
    createdAt: alert?.created_at,
    toolName: alert?.tool?.name,
  };
}

function mapSecretScanningAlert(alert: any): GitHubSecretScanningAlert {
  return {
    number: Number(alert?.number || 0),
    secretType: String(alert?.secret_type || 'unknown_secret'),
    secretTypeDisplayName: alert?.secret_type_display_name,
    validity: alert?.validity,
    publiclyLeaked: Boolean(alert?.publicly_leaked),
    htmlUrl: alert?.html_url,
    createdAt: alert?.created_at,
  };
}

/**
 * Collects authoritative GitHub alerts separately. A missing permission for one
 * source is reported as partial coverage; it must not hide successful data from
 * the other security products.
 */
export async function fetchRepoSecurityData(owner: string, repo: string, token: string): Promise<RepoSecurityData> {
  const safeOwner = owner?.trim();
  const safeRepo = repo?.trim();
  const safeToken = token?.trim();

  if (!safeOwner || !safeRepo) {
    throw new ValidationError('Repository owner and repo name are required.');
  }
  if (!safeToken) {
    throw new ValidationError('GitHub access token is missing.');
  }

  const [dependabot, codeScanning, secretScanning] = await Promise.allSettled([
    listAlerts(safeToken, repositoryPath(safeOwner, safeRepo, '/dependabot/alerts?state=open')),
    listAlerts(safeToken, repositoryPath(safeOwner, safeRepo, '/code-scanning/alerts?state=open')),
    listAlerts(safeToken, repositoryPath(safeOwner, safeRepo, '/secret-scanning/alerts?state=open')),
  ]);

  const sourceErrors: GitHubSecuritySourceError[] = [];
  const dependabotRows = dependabot.status === 'fulfilled' ? dependabot.value.rows : [];
  const codeScanningRows = codeScanning.status === 'fulfilled' ? codeScanning.value.rows : [];
  const secretScanningRows = secretScanning.status === 'fulfilled' ? secretScanning.value.rows : [];

  if (dependabot.status === 'rejected') sourceErrors.push(sourceError('dependabot', dependabot.reason));
  if (codeScanning.status === 'rejected') sourceErrors.push(sourceError('code_scanning', codeScanning.reason));
  if (secretScanning.status === 'rejected') sourceErrors.push(sourceError('secret_scanning', secretScanning.reason));
  if (dependabot.status === 'fulfilled' && dependabot.value.truncated) sourceErrors.push({ source: 'dependabot', message: 'Dependabot alert feed exceeded the 1,000-alert safety cap.' });
  if (codeScanning.status === 'fulfilled' && codeScanning.value.truncated) sourceErrors.push({ source: 'code_scanning', message: 'Code-scanning alert feed exceeded the 1,000-alert safety cap.' });
  if (secretScanning.status === 'fulfilled' && secretScanning.value.truncated) sourceErrors.push({ source: 'secret_scanning', message: 'Secret-scanning alert feed exceeded the 1,000-alert safety cap.' });

  return {
    totalCount: dependabotRows.length,
    nodes: dependabotRows.map(mapDependabotAlert),
    codeScanningAlerts: codeScanningRows.map(mapCodeScanningAlert).filter((alert) => alert.number > 0),
    secretScanningAlerts: secretScanningRows.map(mapSecretScanningAlert).filter((alert) => alert.number > 0),
    sourceErrors,
  };
}
