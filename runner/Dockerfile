# Deep-audit runner image. Build from the repo root so the shared contract is
# available:   fly deploy --config runner/fly.toml --dockerfile runner/Dockerfile .
FROM node:22-bookworm-slim

# git: clone the client repo. iproute2 + util-linux (unshare, setpriv): the
# agent's loopback-only network namespace. bubblewrap + util-linux (prlimit):
# the OS sandbox the skill requires before running any target code.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates iproute2 bubblewrap util-linux coreutils procps \
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
COPY runner/run-job.mjs runner/egress-proxy.mjs runner/uds-bridge.mjs runner/netns-agent.sh runner/sbx ./
RUN chmod +x netns-agent.sh sbx && ln -s /app/sbx /usr/local/bin/sbx \
 && git config --system --add safe.directory /work/repo

# The supervisor runs as root to clone and to create the agent's network
# namespace; the agent runs as `auditor` inside it. See run-job.mjs.
CMD ["node", "--experimental-strip-types", "--no-warnings", "/app/run-job.mjs"]
