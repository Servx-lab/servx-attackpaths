# ServX security scanner TODO

This is the implementation checklist for a free-by-default, evidence-backed
scanner. “Free” does not remove ownership checks, quotas, execution limits, or
the prohibition on arbitrary target scanning.

## Done in this pass

- [x] Separate the scanner executor from the browser and ServX credentials.
- [x] Keep manual live-target scanning disabled for the beta.
- [x] Enforce authenticated repository selection, idempotency, and an initial
  manual-scan quota in ServX.
- [x] Preserve CLI-created reports instead of overwriting them with stdout.
- [x] Build the dedicated Docker executor with pinned, checksum-verified
  Gitleaks, Trivy, and Syft releases plus a pinned Semgrep release. Deep jobs
  execute them serially in a temporary cloned repository.
- [x] Pin the reviewed Semgrep rule repository to commit
  `e5b5a42ec061854378c11e0d01f19250b52bc2e9` in the Docker image. The executor
  uses the curated language and configuration directories rather than a mutable
  Semgrep registry alias.
- [x] Bound repository materialization by path, file count, file size, total
  bytes, request timeout, and GitHub recursive-tree truncation.
- [x] Bound deep repository cloning by GitHub metadata size (100 MiB default,
  250 MiB maximum), shallow history, no submodules, no symlinks, a 15-minute
  clone timeout, and a post-clone byte check.
- [x] Ingest complete GitHub Dependabot, code-scanning, and secret-scanning
  alert feeds with pagination and per-source availability reporting.

## Next: trustworthy free scanning

- [x] Replace generic completion language with scanner provenance, a coverage
  list, skipped/failed-source reasons, queue state, and persisted run metrics.
- [x] Query bounded resolved dependency manifests and lockfiles with OSV batch
  queries for npm (npm/yarn/pnpm), Python (requirements/Pipenv/Poetry), Go,
  Maven/Gradle, and Rust.
- [ ] Parse CycloneDX/SPDX SBOM uploads and more package-manager lockfiles;
  record an explicit partial-coverage warning whenever a manifest is skipped.
- [ ] Normalize findings into stable fingerprints with source, rule/CVE/CWE,
  location, fix version, evidence URL, confidence, and remediation.
- [ ] Add fixtures with known-positive and known-negative samples for every
  parser and run them in CI. Initial positive fixtures cover Gitleaks,
  Semgrep, Trivy, Syft, and live-target rejection; negative fixture coverage
  and false-positive tracking remain to be added.
- [x] Add a user-installed, immutable-image GitHub Actions workflow for
  Gitleaks, Semgrep, and Trivy. It uploads SARIF with the repository's scoped
  `GITHUB_TOKEN`, never a browser token.
- [ ] Import SARIF/artifact results into ServX and deduplicate them with
  GitHub-native alerts.

## Later: verified attack paths and live testing

- [ ] Build attack paths only from verified routes, auth/authorization
  boundaries, reachable sinks, dependencies, and connected deployment assets.
  Do not label a scanner-to-repository diagram as an attack path.
- [ ] Add verified deployment ownership, DNS/IP checks on every redirect,
  port allowlists, egress isolation, and response/log redaction before
  enabling any live scan.
- [ ] Move long-running/active DAST to paid isolated workers. Never run
  Puppeteer with `--no-sandbox` against arbitrary targets.
- [x] Add durable leases, retry/recovery dispatch, cancellation, queue
  capacity, run metrics, and stale-callback rejection.
- [x] Add a deployment-wide scan kill switch (`ATTACK_PATHS_KILL_SWITCH=true`) before wider production use. It blocks new admissions and new executor dispatches while preserving evidence already recorded.

## Free-tier anti-abuse policy

- GitHub App/OAuth-authorized repositories only; no arbitrary URLs or Git
  clone URLs.
- One active manual job per user and repository, three manual deep scan
  requests per rolling 24 hours, bounded queue, and endpoint rate limits.
- Fixed signed workflow and fixed scanner arguments only; no custom commands,
  scanner templates, or user-provided rule URLs.
- Scan input, report, artifact, and callback payload size limits; reject stale
  OIDC/SARIF uploads and duplicate workflow runs.
- Free users receive the same core detection quality. A future paid tier buys
  queue capacity, larger repository limits, retention, scheduling,
  collaboration, and verified active testing rather than basic vulnerability
  visibility.
