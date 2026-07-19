# ServX Attack Paths executor

This repository is the isolated repository-scan executor for ServX. It is not
a browser API and it does not own users, repositories, job state, MongoDB, or
long-lived GitHub credentials.

```text
ServX web -> ServX API (auth, repository authorization, quotas, job state, SSE)
          -> signed HTTPS -> Attack Paths executor
          <- signed HTTPS -- progress, findings, and completion
```

Only the ServX API can call the executor. Every non-health endpoint requires
an HMAC signature containing the request method, path, timestamp, nonce, and
body hash. The executor fetches a short-lived, lease-bound job input from
ServX, scans one job at a time, returns normalized evidence, and deletes its
temporary workspace.

## Endpoints

- `GET /health` — public liveness only.
- `GET /ready` — signed readiness/configuration check.
- `POST /internal/v1/wake` — signed warm-up request.
- `POST /internal/v1/jobs/:jobId/dispatch` — signed, idempotent queueing.
- `POST /internal/v1/jobs/:jobId/cancel` — signed cancellation request.

There is deliberately no public create-job, result, SSE, CORS, MongoDB, or
direct GitHub-token endpoint in this process.

## Scan policy

The interactive default is `deep_repo` for a connected repository that ServX
has authorized for the signed-in user. The executor gathers GitHub security
alerts, OSV dependency evidence, built-in source/config checks, and available
Gitleaks, Semgrep, Trivy, and Syft results. It returns scanner coverage so a
clean result is not confused with proof of security.

Active URL/DAST scanning is rejected. It must stay disabled until ServX has
verified deployment ownership and isolated outbound network access.

## Local development

```bash
npm install
cp .env.example .env
npm run dev
```

Configure both directions of the HMAC bridge. The executor uses
`SERVX_CONTROL_PLANE_URL` to call the ServX internal router; the ServX API uses
`ATTACK_PATHS_EXECUTOR_URL` to call this service. The two secret values must be
distinct and mirrored in the appropriate direction:

```text
# ServX API -> executor (set in both places)
ATTACK_PATHS_EXECUTOR_INBOUND_KEY_ID=servx-control-plane-local
ATTACK_PATHS_EXECUTOR_INBOUND_HMAC_SECRET=<long random secret A>

# executor -> ServX API (set in both places)
ATTACK_PATHS_EXECUTOR_OUTBOUND_KEY_ID=attackpaths-executor-local
ATTACK_PATHS_EXECUTOR_OUTBOUND_HMAC_SECRET=<different long random secret B>
```

For the local executor, set `SERVX_CONTROL_PLANE_URL=http://localhost:5000`.
For the local ServX API, set `ATTACK_PATHS_EXECUTOR_URL=http://localhost:5001`.

Do **not** set `MONGODB_URI`, `ENCRYPTION_KEY`, or `GITHUB_TOKEN` in the
executor environment. ServX retains those responsibilities.

## Free Render beta

The separate Render account is suitable for isolation, not for an always-on
worker. Let the web service sleep when unused; ServX's authenticated warm-up
and signed dispatch wake it as needed. The control plane persists the queue and
lease, so a cold start or executor restart does not lose a job. Do not use a
public cron keepalive to manufacture uptime.

Run one repository scan at a time and keep ServX's three-scans-per-24-hours
and bounded queue policy enabled. Move active scanning or materially higher
capacity to a dedicated worker after measuring real CPU, memory, duration, and
egress usage.
