# ServX Attack Paths executor

This repository is the isolated **scan executor** for ServX Attack Paths. It is
not a user-facing application and must be deployed separately from the ServX
control plane.

The browser stays inside the main ServX application:

```text
ServX web -> ServX API (auth, authorization, quota, job store, SSE)
          -> signed HTTPS -> this executor (queued repository scan)
          <- signed HTTPS -- progress and findings
```

The executor has no MongoDB connection, Supabase key, encryption key, or
persisted GitHub credential. ServX sends a signed job id, the executor fetches
one in-memory scan input over a second signed channel, and results flow back to
ServX. It exposes only:

- `GET /health` — unauthenticated process liveness.
- `GET /ready` — HMAC-protected configuration/readiness check.
- `POST /internal/v1/wake` — HMAC-protected cold-start warmup.
- `POST /internal/v1/jobs/:jobId/dispatch` — HMAC-protected, idempotent job
  queueing.

There is no browser CORS API and no public job-create/result endpoint.

## Scan profiles

Every job is created by the authenticated ServX API only after it confirms the
user can access the connected GitHub repository. This executor never accepts a
repository name, Git URL, target URL, or scanner arguments from a browser.

`quick` provides GitHub Dependabot/code/secret-scanning alerts, OSV dependency
checks, and bounded source/config evidence without cloning the full repository.

`deep_repo` is the default interactive scan. The executor shallow-clones the
already-authorized repository, rejects metadata larger than 100 MiB by default
(configurable, hard maximum 250 MiB), removes Git metadata and symlinks, and
runs one scanner at a time. The image contains pinned releases of Gitleaks,
Semgrep, Trivy, and Syft, plus a reviewed Semgrep rules commit. Its persisted progress stages are: prepare the
repository, scan secrets, analyze source, check dependencies/configuration,
build the SBOM, and normalize the report. Workspaces and raw reports are
deleted at the end of the job.

`verified_live` remains rejected. The product does not scan arbitrary URLs or
perform DAST in this service.

The Free Render executor intentionally runs one scan at a time; all additional
jobs wait in the ServX-controlled queue. Durable job state and the daily quota
remain in ServX MongoDB, not in Render memory.

## Local setup

```bash
npm ci
cp .env.example .env
npm run build
npm start
```

Set the variables described in [`.env.example`](.env.example). Use two distinct
HMAC secrets: one for ServX -> executor, and one for executor -> ServX.

## Render deployment

[`render.yaml`](render.yaml) declares a Free Docker web service with the
scanner toolchain baked into its image. Add its secret environment variables in
the separate Render account, then set the matching values in the main ServX API
environment:

```text
# ServX API
ATTACK_PATHS_EXECUTOR_URL=https://<executor>.onrender.com
ATTACK_PATHS_EXECUTOR_INBOUND_HMAC_SECRET=<same as executor inbound secret>
ATTACK_PATHS_EXECUTOR_INBOUND_KEY_ID=servx-control-plane-2026-01
ATTACK_PATHS_EXECUTOR_OUTBOUND_HMAC_SECRET=<same as executor outbound secret>
ATTACK_PATHS_EXECUTOR_OUTBOUND_KEY_ID=attackpaths-executor-2026-01
ATTACK_PATHS_MAX_QUEUED_JOBS=25
# Set to true only to pause new scan admissions and new executor dispatches.
ATTACK_PATHS_KILL_SWITCH=false
```

Do not put either HMAC secret in the frontend. Do not configure `MONGODB_URI`,
`ENCRYPTION_KEY`, or a reusable `GITHUB_TOKEN` on the executor.

The ServX API must also have a working `REDIS_URL`: executor callbacks fail
closed when replay protection is unavailable.

ServX persists each job, grants the executor a short-lived lease, rejects stale
callbacks, requeues expired leases after a restart, and supports user
cancellation. The executor still handles one job at a time; a bounded queue is
an intentional capacity control, not a background-process substitute.

Free Render web services sleep after idle time and can restart at any time, so
the control plane treats the executor as a wake-on-dispatch dependency rather
than a durable worker. The dashboard's authenticated warmup request makes the
cold start less visible; a signed dispatch then queues the job. Do not use a
public cron keepalive: it burns free-runtime hours without improving scan
correctness.

For the detailed integration, security boundaries, rollout policy, and
remaining hardening work, read [the integration plan](docs/servx-integration-plan.md).
For scheduled and pull-request scanning alongside the interactive executor,
read the [GitHub Actions deep-scan guide](docs/github-actions-deep-scan.md).
