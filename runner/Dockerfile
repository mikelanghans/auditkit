# Deep-audit runner image. Build from the repo root so the shared contract is
# available:   fly deploy --config runner/fly.toml --dockerfile runner/Dockerfile .
FROM node:22-bookworm-slim

# git: clone the client repo. iptables: egress lockdown. bubblewrap + util-linux
# (prlimit): the OS sandbox the skill requires before running any target code.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates iptables bubblewrap util-linux coreutils procps \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged users: the audit agent and the egress proxy.
RUN useradd --create-home --uid 10001 auditor \
 && useradd --no-create-home --uid 10002 --shell /usr/sbin/nologin egress

WORKDIR /app
COPY runner/package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Cloudflare security-audit skill (MIT), pinned. Bump deliberately.
ARG SKILL_REPO=https://github.com/cloudflare/security-audit-skill.git
ARG SKILL_COMMIT=c1c8a8c
RUN git clone --filter=blob:none "$SKILL_REPO" /opt/security-audit-skill \
 && git -C /opt/security-audit-skill checkout "$SKILL_COMMIT" \
 && mkdir -p /home/auditor/.claude/skills \
 && cp -r /opt/security-audit-skill/skills/security-audit /home/auditor/.claude/skills/security-audit \
 && chown -R auditor:auditor /home/auditor/.claude

COPY src/lib/code-audit-contract.ts ./contract.ts
COPY runner/run-job.mjs runner/egress-proxy.mjs runner/lockdown.sh runner/sbx ./
RUN chmod +x lockdown.sh sbx && ln -s /app/sbx /usr/local/bin/sbx \
 && git config --system --add safe.directory /work/repo

# The job runs as root only long enough to set up the firewall; the agent runs
# as `auditor`. See run-job.mjs.
CMD ["node", "--experimental-strip-types", "--no-warnings", "/app/run-job.mjs"]
