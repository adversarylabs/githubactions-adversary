# Checks — what ci/github-actions detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence where applicable.

Runtime source of truth: [`src/spec.ts`](src/spec.ts).
Regression entry: [`test/`](test/).

**Scope:** `.github/workflows/*.yml` and `*.yaml`.

---

## Critical

### `gha.pull-request-target.pwn`

| | |
| --- | --- |
| **What** | pull_request_target checks out untrusted PR code |
| **Why** | Base-repo secrets + write token with attacker-controlled code |
| **Looks for** | pull_request_target + checkout of PR head ref/sha |
| **Stays quiet when** | Metadata-only jobs; use pull_request for untrusted code |
| **Remediation** | Never checkout PR head in pull_request_target |

### `gha.script-injection.context`

| | |
| --- | --- |
| **What** | Untrusted github.event interpolated into run: |
| **Why** | Issue titles/bodies/refs can break out of shell |
| **Looks for** | Inline ${{ github.event… }} in run scripts |
| **Stays quiet when** | Pass via env: and quote "$VAR" |
| **Remediation** | Never expand untrusted event fields into shell |

## High

### `gha.action.unpinned-tag`

| | |
| --- | --- |
| **What** | External action uses mutable ref |
| **Why** | Tags/branches can be retargeted |
| **Looks for** | uses: org/action@v1 / @main without 40-char SHA |
| **Stays quiet when** | Full commit SHA (optional version comment) |
| **Remediation** | Pin third-party actions to SHAs |

### `gha.permissions.write-all`

| | |
| --- | --- |
| **What** | Workflow grants write-all token permissions |
| **Why** | Amplifies any injection |
| **Looks for** | permissions: write-all |
| **Stays quiet when** | Default read; narrow write on release jobs |
| **Remediation** | Least-privilege GITHUB_TOKEN |

### `gha.permissions.contents-write-on-pr`

| | |
| --- | --- |
| **What** | contents: write on pull_request |
| **Why** | Fork PRs may push with elevated token in some setups |
| **Looks for** | contents write on PR-triggered jobs |
| **Stays quiet when** | Read-only on PR; write only on trusted events |
| **Remediation** | Split privileged jobs |

### `gha.self-hosted.untrusted`

| | |
| --- | --- |
| **What** | Untrusted code on self-hosted runner |
| **Why** | Persistent runners retain secrets/state |
| **Looks for** | self-hosted + untrusted PR code |
| **Stays quiet when** | Ephemeral runners or trusted events only |
| **Remediation** | Do not run fork PR code on persistent self-hosted |

### `gha.runs-on.expression`

| | |
| --- | --- |
| **What** | Dynamic runs-on expression |
| **Why** | Attacker may influence runner labels |
| **Looks for** | runs-on from untrusted expressions |
| **Stays quiet when** | Static labels |
| **Remediation** | Hard-code runner labels |

## Medium

### `gha.custom-runner.missing-timeout`

| | |
| --- | --- |
| **What** | Long-running build, packaging, release, or integration job has no job timeout on a custom runner |
| **Why** | A stuck job can occupy scarce runner capacity for GitHub's six-hour default |
| **Looks for** | Long-running signals such as ARM/cross-compilation, multi-arch, QEMU/buildx, packaging, publishing, or integration/e2e on self-hosted or custom runner labels without `timeout-minutes` |
| **Stays quiet when** | Any job timeout is set; the job is short; or the job uses a GitHub-hosted runner |
| **Remediation** | Set `timeout-minutes` from observed runtime plus reasonable headroom |
