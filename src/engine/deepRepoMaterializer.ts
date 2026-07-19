import { spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';

const GITHUB_API_URL = 'https://api.github.com';
const REQUEST_TIMEOUT_MS = 20_000;
const CLONE_TIMEOUT_MS = 15 * 60_000;
const MAX_CAPTURED_GIT_OUTPUT_BYTES = 128 * 1024;
const MAX_DEEP_REPO_SIZE_KB = Math.min(
  Math.max(1, Number(process.env.ATTACK_PATHS_MAX_DEEP_REPO_SIZE_KB || 100 * 1024)),
  250 * 1024
);
const MAX_DEEP_REPO_BYTES = MAX_DEEP_REPO_SIZE_KB * 1024;

export type DeepMaterializedRepo = {
  workDir: string;
  revision: string;
  sizeBytes: number;
};

function parseRepoFullName(repoFullName: string): { owner: string; repo: string } {
  const [owner, repo, ...extra] = repoFullName.trim().split('/');
  if (
    extra.length > 0 ||
    !owner ||
    !repo ||
    !/^[A-Za-z0-9_.-]+$/.test(owner) ||
    !/^[A-Za-z0-9_.-]+$/.test(repo)
  ) {
    throw new Error('Invalid repository name for deep scan.');
  }
  return { owner, repo };
}

async function run(
  command: string,
  args: string[],
  cwd: string,
  timeoutMs: number,
  environment: NodeJS.ProcessEnv = {},
  signal?: AbortSignal
): Promise<string> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('Scan cancelled.'));
      return;
    }
    const child = spawn(command, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: '0',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_ALLOW_PROTOCOL: 'https',
        ...environment,
      },
    });
    let stdout = '';
    let stderr = '';
    let timer: NodeJS.Timeout;
    const abort = () => {
      child.kill('SIGTERM');
      clearTimeout(timer);
      reject(new Error('Scan cancelled.'));
    };
    const removeAbortListener = () => signal?.removeEventListener('abort', abort);
    timer = setTimeout(() => {
      child.kill('SIGTERM');
      removeAbortListener();
      reject(new Error(`${command} timed out after ${Math.round(timeoutMs / 60_000)} minutes.`));
    }, timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });

    const append = (current: string, chunk: Buffer | string): string => {
      if (current.length >= MAX_CAPTURED_GIT_OUTPUT_BYTES) return current;
      return current + String(chunk).slice(0, MAX_CAPTURED_GIT_OUTPUT_BYTES - current.length);
    };
    child.stdout.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.on('error', (error) => {
      clearTimeout(timer);
      removeAbortListener();
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      removeAbortListener();
      if (code === 0) {
        resolve(stdout.trim());
        return;
      }
      reject(new Error(`${command} failed (${code ?? 'unknown'}): ${stderr.trim().slice(0, 500)}`));
    });
  });
}

async function scrubAndMeasureRepo(workDir: string, signal?: AbortSignal): Promise<number> {
  let totalBytes = 0;
  const pending = [workDir];

  while (pending.length > 0) {
    if (signal?.aborted) throw new Error('Scan cancelled.');
    const current = pending.pop();
    if (!current) continue;
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const entryPath = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        await fs.unlink(entryPath);
        continue;
      }
      if (entry.isDirectory()) {
        pending.push(entryPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const stat = await fs.stat(entryPath);
      totalBytes += stat.size;
      if (totalBytes > MAX_DEEP_REPO_BYTES) {
        throw new Error(`Repository source exceeds the ${MAX_DEEP_REPO_SIZE_KB} KB deep-scan limit.`);
      }
    }
  }

  return totalBytes;
}

/**
 * Shallow-clones an already authorized GitHub repository for a single deep
 * scan. Git metadata is removed before scanners run so the OAuth token cannot
 * persist in .git/config, and symlinks are removed to keep tools inside the
 * temporary workspace.
 */
export async function materializeDeepRepoFromGitHub(params: {
  jobDir: string;
  repoFullName: string;
  accessToken: string;
  signal?: AbortSignal;
}): Promise<DeepMaterializedRepo> {
  const { jobDir, repoFullName, accessToken, signal } = params;
  const { owner, repo } = parseRepoFullName(repoFullName);
  const token = accessToken.trim();
  if (!token) throw new Error('GitHub token is required for a deep repository scan.');

  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'User-Agent': 'ServX-AttackPaths-Worker',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  const metadataResponse = await fetch(`${GITHUB_API_URL}/repos/${owner}/${repo}`, {
    headers,
    signal: signal ? AbortSignal.any([AbortSignal.timeout(REQUEST_TIMEOUT_MS), signal]) : AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!metadataResponse.ok) {
    throw new Error(`Unable to authorize repository for deep scan (${metadataResponse.status}).`);
  }
  const metadata = await metadataResponse.json() as { size?: number };
  if (Number(metadata.size || 0) > MAX_DEEP_REPO_SIZE_KB) {
    throw new Error(`Repository exceeds the ${MAX_DEEP_REPO_SIZE_KB} KB deep-scan limit.`);
  }

  const workDir = path.join(jobDir, 'deep-repository');
  const remote = `https://github.com/${owner}/${repo}.git`;
  try {
    // Git reads this only for this child process. Unlike a credential embedded
    // in the remote URL, it is neither logged by this process nor persisted in
    // the cloned repository's config.
    await run(
      'git',
      [
        'clone',
        '--config', 'protocol.file.allow=never',
        '--depth=1',
        '--no-tags',
        '--single-branch',
        '--no-recurse-submodules',
        remote,
        workDir,
      ],
      jobDir,
      CLONE_TIMEOUT_MS,
      {
        GIT_CONFIG_COUNT: '1',
        GIT_CONFIG_KEY_0: 'http.extraHeader',
        GIT_CONFIG_VALUE_0: `Authorization: Bearer ${token}`,
      },
      signal
    );
    const revision = await run('git', ['rev-parse', 'HEAD'], workDir, 30_000, {}, signal);
    await fs.rm(path.join(workDir, '.git'), { recursive: true, force: true });
    const sizeBytes = await scrubAndMeasureRepo(workDir, signal);
    return { workDir, revision, sizeBytes };
  } catch (error) {
    await fs.rm(workDir, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}
