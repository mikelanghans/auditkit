# Deep code audit runner

Runs Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT) against one client
repository per job, on a Fly.io machine that is created for the job and destroyed when it exits. AuditKit is the control
plane: it starts the machine, and the runner posts signed results back.

```
AuditKit (startCodeAudit)  ──Machines API──▶  Fly machine (this image)
  code_audit_runs row                          1. decrypt job (AES-GCM, key from CODE_AUDIT_WEBHOOK_SECRET)
                                               2. start allowlisting egress proxy (TCP + Unix socket)
                                               3. clone repo read-only; GitHub token used once, never on disk
                                               4. drop GitHub from the allowlist (model API + callback only)
                                               5. run the skill as uid `auditor` via the Claude Agent SDK,
                                                  strict agent budget from the profile; target code only in `sbx`
                                               6. run the skill's validators
/api/public/hooks/code-audit  ◀──HMAC──────    7. POST findings, ledger, REPORT.md; exit → machine destroyed
```

## Status

This is a skeleton. Each piece is written and the AuditKit side is tested, but the runner itself has **not yet been run
end to end on Fly**. Do the first runs on a sample repo you own and watch the machine logs (`fly logs -a <app>`).

Things to confirm on the first run:

- App secrets (`fly secrets set`) are available to machines created through the Machines API.
- `bwrap` works inside the Fly VM as the `auditor` user (unprivileged user namespaces). Test with
  `sbx /tmp/x sh -c 'id; getent hosts example.com || echo no-network'`.
- The Agent SDK loads the skill from `~/.claude/skills` with `settingSources: ["user"]`, and its subagents (Task tool)
  respect the budget. Check `agents_spent` in the posted `run-metadata.json` against the budget.
- Cost per profile. Record it and set prices before offering this to clients.

## One-time setup

```bash
# From the repo root.
fly apps create auditkit-code-audit-runner            # or change `app` in runner/fly.toml

# Secrets the runner needs. Use the same CODE_AUDIT_WEBHOOK_SECRET in AuditKit.
fly secrets set -a auditkit-code-audit-runner \
  ANTHROPIC_API_KEY=sk-ant-... \
  CODE_AUDIT_WEBHOOK_SECRET="$(openssl rand -hex 32)"

# Build and push the image without starting anything.
fly deploy --config runner/fly.toml --dockerfile runner/Dockerfile --build-only --push \
  --image-label v1 .
# → registry.fly.io/auditkit-code-audit-runner:v1

# A token that can only manage this one app.
fly tokens create deploy -a auditkit-code-audit-runner
```

Then set these on the AuditKit server (never with a `VITE_` prefix):

| Variable | Value |
|---|---|
| `FLY_API_TOKEN` | the deploy token above |
| `CODE_AUDIT_FLY_APP` | `auditkit-code-audit-runner` |
| `CODE_AUDIT_RUNNER_IMAGE` | `registry.fly.io/auditkit-code-audit-runner:v1` |
| `CODE_AUDIT_WEBHOOK_SECRET` | same value as the runner secret (32+ chars) |
| `PUBLIC_APP_URL` | AuditKit's public origin, e.g. `https://auditkit.syncopateddynamics.com` |

Optional runner secrets: `CODE_AUDIT_MODEL` (model id for the agent) and `CODE_AUDIT_MAX_HOURS` (default 3).

## Updating the skill

The skill is pinned by commit in the `Dockerfile` (`SKILL_COMMIT`). Bump it deliberately, rebuild with a new image
label, and update `CODE_AUDIT_RUNNER_IMAGE`.

## Safety properties

- **Client code is hostile input.** The agent runs as an unprivileged user in its own network namespace with loopback
  only (no iptables needed); its only outbound path is a bridge to a proxy that allows `api.anthropic.com` and the
  AuditKit callback host. The runner checks a direct connection fails before starting the agent. Target code runs only inside `sbx` (no network, empty
  environment, read-only filesystem except its scratch directory, resource and time limits), as the skill requires.
- **No AuditKit secrets on the runner.** It holds the Anthropic key and the shared webhook secret, nothing else. The
  client's GitHub token arrives encrypted, is used for one fetch, and is dropped.
- **Results are checked twice.** The runner runs the skill's validators; AuditKit rejects output that did not pass them,
  re-validates the record shape, and never re-imports a finished run.
- **Findings never auto-pass anything.** Only a confirmed finding, mapped by the auditor, can mark a checklist item as
  failing.
- **Consent.** Starting a run requires confirming the client agreed to their code being analysed with Anthropic's API.
  Put this in the engagement letter.
