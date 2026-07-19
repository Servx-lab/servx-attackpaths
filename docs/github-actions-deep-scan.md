# GitHub Actions deep-scan template

The ServX executor supports an interactive queued deep scan for a user's
authenticated, connected repository. This workflow is its complementary path
for scheduled and pull-request scanning inside the repository owner's GitHub
Actions runner. It uses GitHub-native security controls and makes results
available through the code-scanning API that ServX already reads.

## Install

1. Copy `templates/github-actions/servx-security-scan.yml` to
   `.github/workflows/servx-security-scan.yml` in the repository being scanned.
2. Copy `templates/github-actions/servx-semgrep.yml` to
   `.servx/servx-semgrep.yml` in that repository.
3. Resolve each scanner image to an immutable `sha256:` digest, review it, and
   set these GitHub repository variables: `SERVX_GITLEAKS_IMAGE_DIGEST`,
   `SERVX_SEMGREP_IMAGE_DIGEST`, and `SERVX_TRIVY_IMAGE_DIGEST`.
4. Enable Dependabot alerts, secret scanning where available, and GitHub CodeQL
   default setup. ServX then reads GitHub-native alerts plus the SARIF results
   from this workflow.

The workflow uses read-only source mounts and disables container networking for
all source scanners. Trivy receives a short, explicit network-enabled step only
to download its vulnerability database, then scans offline. It uses the
repository's `GITHUB_TOKEN` only to upload SARIF to GitHub; no ServX browser
token, callback secret, or arbitrary URL is exposed to the workflow.

## Operational rules

- Review and commit the Semgrep rules with the application code. Do not accept
  a user-supplied remote Semgrep config or custom command through ServX.
- Keep the `actions/checkout` commit and image digests immutable. Update them
  through a reviewed pull request and retain the prior digest in history.
- Treat a workflow run as a source of evidence, not proof that an application
  is secure. Results should include tool, rule, location, commit SHA, and the
  GitHub alert URL where GitHub provides one.
- ServX must deduplicate these results against GitHub CodeQL/Dependabot/secret
  alerts by tool/rule/location/fingerprint before displaying a count.
