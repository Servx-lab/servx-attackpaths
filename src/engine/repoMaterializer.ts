import fs from 'fs/promises';
import path from 'path';
import os from 'os';

export interface MaterializedFile {
  path: string;
  sha: string;
  size: number;
  content?: string;
}

export interface MaterializedRepo {
  workDir: string;
  files: MaterializedFile[];
  defaultBranch: string;
}

const MAX_FILES_HARD_LIMIT = 200;
const MAX_FILE_BYTES = 512 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;

const SPECIAL_SECURITY_FILES = new Set([
  'dockerfile',
  'containerfile',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'go.mod',
  'go.sum',
  'requirements.txt',
  'poetry.lock',
  'pipfile.lock',
  'cargo.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'terraform.lock.hcl',
]);

function isSelectedSecurityFile(item: any): boolean {
  if (item.type !== 'blob' || typeof item.path !== 'string') return false;
  const filePath = item.path;
  const basename = path.posix.basename(filePath).toLowerCase();
  const size = Number(item.size || 0);

  if (!filePath || filePath.startsWith('/') || filePath.split('/').includes('..')) return false;
  if (Number.isFinite(size) && size > MAX_FILE_BYTES) return false;
  if (
    /(^|\/)(node_modules|dist|build|out|public|static|assets|media|vendor|coverage|\.git|\.next|\.nuxt|\.output)\//i.test(filePath) ||
    /(^|\/)(test|tests|__tests__|spec|fixtures|docs?|examples?)\//i.test(filePath)
  ) {
    return false;
  }
  if (/\.(png|jpe?g|gif|svg|ico|webp|mp4|mp3|woff2?|ttf|eot|pdf|zip|tar|gz|map|min\.js|min\.css)$/i.test(filePath)) {
    return false;
  }

  if (SPECIAL_SECURITY_FILES.has(basename)) return true;
  return /\.(ts|js|tsx|jsx|mjs|cjs|py|go|java|kt|kts|rb|php|cs|rs|sql|json|yaml|yml|env|ini|conf|tf|hcl)$/i.test(filePath);
}

/**
 * Fetches repository file tree and key blob contents from GitHub via REST API,
 * writing them to a temporary workspace for AST analysis and sandboxed execution.
 */
export async function materializeRepoFromGitHub(params: {
  jobId: string;
  repoFullName: string;
  accessToken: string;
  maxFilesToFetch?: number;
  maxTotalBytes?: number;
  signal?: AbortSignal;
}): Promise<MaterializedRepo> {
  const {
    jobId,
    repoFullName,
    accessToken,
    maxFilesToFetch = MAX_FILES_HARD_LIMIT,
    maxTotalBytes = DEFAULT_MAX_TOTAL_BYTES,
    signal,
  } = params;
  const [owner, repo] = repoFullName.split('/');
  const effectiveMaxTotalBytes = Math.min(
    Math.max(1, Number(maxTotalBytes) || DEFAULT_MAX_TOTAL_BYTES),
    DEFAULT_MAX_TOTAL_BYTES
  );

  if (!owner || !repo) {
    throw new Error(`Invalid repoFullName: ${repoFullName}`);
  }

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3+json',
    Authorization: `token ${accessToken}`,
    'User-Agent': 'ServX-AttackPaths-Worker',
  };
  const githubFetch = (url: string) => fetch(url, {
    headers,
    signal: signal ? AbortSignal.any([AbortSignal.timeout(REQUEST_TIMEOUT_MS), signal]) : AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  // 1. Get repository metadata to determine default branch
  const repoRes = await githubFetch(`https://api.github.com/repos/${owner}/${repo}`);
  if (!repoRes.ok) {
    throw new Error(`Failed to fetch repo info (${repoRes.status}): ${await repoRes.text()}`);
  }
  const repoData: any = await repoRes.json();
  const defaultBranch = repoData.default_branch || 'main';

  // 2. Fetch recursive git tree
  const treeRes = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`);
  if (!treeRes.ok) {
    throw new Error(`Failed to fetch git tree (${treeRes.status}): ${await treeRes.text()}`);
  }
  const treeData: any = await treeRes.json();
  if (treeData.truncated) {
    throw new Error('GitHub truncated the repository tree; refusing to report incomplete source coverage.');
  }
  const tree: any[] = treeData.tree || [];

  const codeFiles = tree.filter(isSelectedSecurityFile);

  // Sort: prioritize routes, controllers, middleware, services, models
  codeFiles.sort((a, b) => {
    const score = (p: string) => {
      let s = 0;
      if (SPECIAL_SECURITY_FILES.has(path.posix.basename(p).toLowerCase())) s += 100;
      if (/(route|router|controller|middleware|auth|guard|sink|db|sql|query|api)/i.test(p)) s += 10;
      if (p.endsWith('.ts') || p.endsWith('.js')) s += 5;
      return s;
    };
    return score(b.path) - score(a.path);
  });

  const selectedFiles = codeFiles.slice(0, Math.min(Math.max(1, maxFilesToFetch), MAX_FILES_HARD_LIMIT));
  const workDir = path.join(os.tmpdir(), 'servx-attack-paths', jobId, repoFullName.replace('/', '_'));
  await fs.mkdir(workDir, { recursive: true });

  const materializedFiles: MaterializedFile[] = [];
  let totalBytes = 0;

  // 3. Fetch blobs for selected files
  for (const fileItem of selectedFiles) {
    try {
      if (signal?.aborted) throw new Error('Scan cancelled.');
      const blobRes = await githubFetch(fileItem.url || `https://api.github.com/repos/${owner}/${repo}/git/blobs/${fileItem.sha}`);
      if (!blobRes.ok) continue;

      const blobData: any = await blobRes.json();
      let content = '';
      if (blobData.encoding === 'base64' && blobData.content) {
        const decoded = Buffer.from(blobData.content, 'base64');
        if (decoded.length > MAX_FILE_BYTES || totalBytes + decoded.length > effectiveMaxTotalBytes) continue;
        content = decoded.toString('utf8');
      }

      const filePath = path.resolve(workDir, fileItem.path);
      if (!filePath.startsWith(`${workDir}${path.sep}`)) continue;
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, content, 'utf8');
      totalBytes += Buffer.byteLength(content, 'utf8');

      materializedFiles.push({
        path: fileItem.path,
        sha: fileItem.sha,
        size: fileItem.size || content.length,
        content,
      });
    } catch (err) {
      if (signal?.aborted) throw err;
      console.warn(`[repoMaterializer] Failed to fetch blob for ${fileItem.path}:`, err);
    }
  }

  return {
    workDir,
    files: materializedFiles,
    defaultBranch,
  };
}
