# The free executor is deliberately a one-process queued scanner. Pinning tool
# versions makes scanner behavior reproducible; update them through a reviewed
# change and rebuild the image.
FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS tools

ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.70.0
ARG SYFT_VERSION=1.44.0
ARG SEMGREP_VERSION=1.168.0
ARG SEMGREP_RULES_COMMIT=e5b5a42ec061854378c11e0d01f19250b52bc2e9
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/semgrep/bin:$PATH \
    SEMGREP_SEND_METRICS=off \
    TRIVY_NO_PROGRESS=true

RUN apt-get update \
  && apt-get install --no-install-recommends -y ca-certificates curl git python3 python3-venv tar which \
  && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
  case "${TARGETARCH:-amd64}" in \
    amd64) gitleaks_arch=x64; trivy_arch=64bit; syft_arch=amd64 ;; \
    arm64) gitleaks_arch=arm64; trivy_arch=ARM64; syft_arch=arm64 ;; \
    *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  gitleaks_archive="gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz"; \
  curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gitleaks_archive}"; \
  curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
  grep " ${gitleaks_archive}$" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum --check --status; \
  tar -xzf "${gitleaks_archive}" -C /usr/local/bin gitleaks; \
  trivy_archive="trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"; \
  curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_archive}"; \
  curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
  grep " ${trivy_archive}$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum --check --status; \
  tar -xzf "${trivy_archive}" -C /usr/local/bin trivy; \
  syft_archive="syft_${SYFT_VERSION}_linux_${syft_arch}.tar.gz"; \
  curl -fsSLO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${syft_archive}"; \
  curl -fsSLO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt"; \
  grep " ${syft_archive}$" "syft_${SYFT_VERSION}_checksums.txt" | sha256sum --check --status; \
  tar -xzf "${syft_archive}" -C /usr/local/bin syft; \
  rm -f *.tar.gz *_checksums.txt; \
  python3 -m venv /opt/semgrep; \
  /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"; \
  mkdir -p /opt/servx/semgrep-rules; \
  git init /opt/servx/semgrep-rules; \
  git -C /opt/servx/semgrep-rules remote add origin https://github.com/semgrep/semgrep-rules.git; \
  git -C /opt/servx/semgrep-rules fetch --depth=1 origin "${SEMGREP_RULES_COMMIT}"; \
  git -C /opt/servx/semgrep-rules checkout --detach FETCH_HEAD; \
  test "$(git -C /opt/servx/semgrep-rules rev-parse HEAD)" = "${SEMGREP_RULES_COMMIT}"; \
  rm -rf /opt/servx/semgrep-rules/.git; \
  gitleaks version; trivy --version; syft version; semgrep --version

FROM tools AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM tools AS runtime

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
  && npm cache clean --force \
  && chown -R node:node /app
COPY --from=build --chown=node:node /app/dist ./dist

ENV NODE_ENV=production
USER node
EXPOSE 10000
CMD ["node", "dist/server.js"]
