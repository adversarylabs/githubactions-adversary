# ci/github-actions — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `ci/github-actions`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Prevent GitHub Actions compromise: pwn-requests, script injection, supply-chain action pins, and over-privileged tokens.

## LLM strategy (required for world-class)
**Enhance:** decide if a checkout is *executed* as code; connect permissions + trigger + checkout into one story.
**Discover:** novel expression injections and cache poisoning topologies.

### Division of labor
| Layer | Responsibility |
| --- | --- |
| **Static / structural** | Precise, deterministic signals with line-level evidence. |
| **LLM enhancement** | Impact, multi-file stories, ranking, FP suppression when context proves safe. |
| **LLM discovery** | Novel issues only with concrete file:line evidence; no invented vulns. |

### Trust / anti-FP rules
1. Evidence required: file + line + snippet (or explicit multi-file list).
2. LLM-only findings default medium/low confidence until backed by a static rule.
3. One finding per remediation story; skip vendor/generated noise.
4. When unsure, do not report.

## Review verdicts (staff pass)

- **P0 implement:** `pull-request-target.pwn`, `script-injection.context` (incl. head_ref), `action.unpinned-tag`, `permissions.write-all`, `self-hosted.untrusted`, `permissions.contents-write-on-pr`, `runs-on.expression`
- **P1:** `secrets.to-pr-fork`, `workflow-run.untrusted`, `cache.poison`, `oidc.missing-cloud-auth`, `concurrency.missing`, `artifact.secret-upload`, `matrix.secrets-leak`, `checkout.persist-credentials`, `actions.create-release.token`, `composite.unpinned-nested`, `if.weak-trust-gate`, `deploy.without-environment`, `timeout.missing`, `shell.errexit`, `artifact.download-execute`
- **LLM-only:** `third-party.unreviewed`, `environment.ungated`
- **Replaced:** `artifacts.retention` → `artifact.secret-upload` (retention alone is noise; secrets landing in artifacts is the real, exploited issue).
- **Renamed:** `if.contains-injection` → `if.weak-trust-gate` (if: expressions are not shell-injected; the real class is spoofable trust gates).

## Issue catalog

---
### 1. `gha.pull-request-target.pwn` — pull_request_target checks out untrusted code

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** Privileged trigger + checkout of PR head enables pwn-request secret theft.

**Static detection.** Detect on: pull_request_target combined with checkout ref to head.sha or PR repo.

**LLM role.** LLM: does subsequent step execute package managers/build scripts from checkout? Also cover issue_comment '/ok-to-test' style workflows that check out the PR head.

**False-positive guards.** Workflows that only comment via API without checkout of untrusted code.

**Public examples of the bad pattern:**
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
  - https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/
  - https://www.stepsecurity.io/blog/github-actions-pwn-request-vulnerability

---
### 2. `gha.script-injection.context` — Untrusted github.event.* interpolated into run:

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** Title/body/branch names injected into shell enable script injection.

**Static detection.** Detect untrusted contexts inside run:/script blocks: github.event.* (issue/PR/comment title, body, author), github.head_ref and github.event.pull_request.head.ref (branch names are attacker-controlled — the most-missed case in the wild), github.event.inputs.* / inputs.*, and commit messages.

**LLM role.** LLM: is the context used in env: (safer) vs inline shell?

**False-positive guards.** env: TITLE: ${{ }} then use "$TITLE" quoted — still warn but lower.

**Public examples of the bad pattern:**
  - https://securitylab.github.com/resources/github-actions-untrusted-input/
  - https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/
  - https://docs.github.com/en/actions/reference/security/secure-use

---
### 3. `gha.action.unpinned-tag` — Action pinned to mutable tag/branch

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** uses: org/action@v1 or @main can move under attacker control.

**Static detection.** Detect non-SHA refs on third-party actions.

**LLM role.** Allow actions/* with policy note; prioritize third-party.

**False-positive guards.** Local actions ./.github/actions/.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/reference/security/secure-use
  - https://github.com/mheap/pin-github-action
  - https://blog.rafaelgss.dev/why-you-should-pin-actions-by-commit-hash

---
### 4. `gha.permissions.write-all` — Missing or overly broad permissions

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Default write-all GITHUB_TOKEN or permissions: write-all.

**Static detection.** Parse permissions: keys at workflow/job level.

**LLM role.** Recommend least privilege map.

**False-positive guards.** Workflows that truly need contents: write for releases — require narrow scope.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
  - https://github.com/ossf/scorecard — Token-Permissions check

---
### 5. `gha.secrets.to-pr-fork` — Secrets available to fork PR workflows

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** pull_request with secrets on forks or environment misuse.

**Static detection.** Detect secrets usage under pull_request without environment protection.

**LLM role.** LLM: environment gate present?

**False-positive guards.** Internal repos without forks.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/managing-workflow-runs/approving-workflow-runs-from-public-forks
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
  - https://docs.github.com/en/actions/reference/security/secure-use

---
### 6. `gha.workflow-run.untrusted` — workflow_run executes untrusted artifacts

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** workflow_run downloads artifacts from untrusted workflow without validation.

**Static detection.** Detect workflow_run + actions/download-artifact patterns.

**LLM role.** Require artifact hash verification narrative.

**False-positive guards.** Trusted monorepo-only pipelines.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/reference/security/secure-use
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
  - https://github.com/actions/download-artifact

---
### 7. `gha.cache.poison` — Shared cache keys across privileged/untrusted jobs

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Poisoning needs a cache *write* from untrusted code that a privileged job later restores. GitHub scopes PR caches to the PR branch (they can read base caches but cannot write them), so branch-name keys alone are not exploitable. The real findings: untrusted code executing in privileged contexts (pull_request_target / workflow_run) that saves caches, and privileged jobs restoring via broad restore-keys prefixes that collide with attacker-influenced saves.

**Static detection.** Detect cache save steps in privileged-trigger workflows that also execute untrusted code; broad restore-keys prefixes in release/deploy workflows.

**LLM role.** LLM: privileged job restore vs untrusted save.

**False-positive guards.** Read-only caches.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows
  - https://adnan-riaz.com/posts/github-actions-cache-poisoning/
  - https://github.com/actions/cache

---
### 8. `gha.oidc.missing-cloud-auth` — Static cloud keys instead of OIDC

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** AWS_ACCESS_KEY_ID secrets instead of configure-aws-credentials OIDC.

**Static detection.** Detect long-lived cloud keys in env.

**LLM role.** Recommend OIDC.

**False-positive guards.** Non-cloud workflows.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
  - https://github.com/aws-actions/configure-aws-credentials
  - https://github.com/google-github-actions/auth

---
### 9. `gha.third-party.unreviewed` — Third-party action from low-trust publisher

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** uses: random-user/action@...

**Static detection.** Heuristic on publisher popularity / org verification.

**LLM role.** LLM: assess action source risk; never block solely on stars.

**False-positive guards.** Well-known orgs.

**Public examples of the bad pattern:**
  - https://github.com/ossf/scorecard
  - https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
  - https://github.com/step-security/harden-runner

---
### 10. `gha.concurrency.missing` — No concurrency group on deploy workflows

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Deploy jobs without concurrency cancel-in-progress risk races.

**Static detection.** Detect environment: production without concurrency.

**LLM role.** Suggest group keys.

**False-positive guards.** Stateless CI tests.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-jobs/using-concurrency
  - https://github.com/actions/starter-workflows
  - https://docs.github.com/en/actions/deployment/about-deployments/about-continuous-deployment

---
### 11. `gha.environment.ungated` — Production environment without protection rules

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** environment: production with secrets but no reviewers (repo settings unknown).

**Static detection.** Static can only note environment presence; LLM suggests verification.

**LLM role.** Do not claim settings state without API.

**False-positive guards.** Always soft finding.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment
  - https://docs.github.com/en/actions/reference/security/secure-use
  - https://github.com/actions/starter-workflows

---
### 12. `gha.shell.errexit` — bash without pipefail/errexit

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** The default Linux shell is `bash -e` (errexit is already on); the actual gap is pipefail. Flag multi-line run blocks that use pipes without `shell: bash` (which adds -o pipefail) or an explicit set -o pipefail.

**Static detection.** Detect `|` in run blocks lacking shell: bash / set -o pipefail.

**LLM role.** Suggest template.

**False-positive guards.** Explicit `bash -e` already set.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsshell
  - https://github.com/rhysd/actionlint
  - https://github.com/actions/starter-workflows

---
### 13. `gha.matrix.secrets-leak` — Matrix includes secrets in logs

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** strategy.matrix includes sensitive values printed in logs.

**Static detection.** Detect secrets-like keys in matrix.

**LLM role.** LLM: will values appear in logs?

**False-positive guards.** Non-secret matrices.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs
  - https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
  - https://github.com/actions/runner

---
### 14. `gha.self-hosted.untrusted` — Self-hosted runner on public PR

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** runs-on: self-hosted with pull_request from forks risks runner compromise.

**Static detection.** Detect self-hosted + pull_request without from-fork guards.

**LLM role.** Hard finding for public repos.

**False-positive guards.** Private repos.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security
  - https://securitylab.github.com/resources/github-actions-self-hosted-runners/
  - https://docs.github.com/en/actions/reference/security/secure-use

---
### 15. `gha.checkout.persist-credentials` — checkout persists credentials

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** persist-credentials: true (default) leaves token in .git for later steps.

**Static detection.** Detect checkout without persist-credentials: false when later untrusted steps exist.

**LLM role.** LLM: subsequent steps trust boundary.

**False-positive guards.** Simple workflows needing git push.

**Public examples of the bad pattern:**
  - https://github.com/actions/checkout — persist-credentials input
  - https://docs.github.com/en/actions/reference/security/secure-use
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/

---
### 16. `gha.actions.create-release.token` — Overbroad token for release

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** contents: write at workflow level for single release job.

**Static detection.** Scope analysis of permissions vs jobs.

**LLM role.** Recommend job-level permissions.

**False-positive guards.** Monolithic release workflows.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs
  - https://github.com/softprops/action-gh-release
  - https://docs.github.com/en/actions/security-guides/automatic-token-authentication

---
### 17. `gha.composite.unpinned-nested` — Composite action uses unpinned nested actions

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** action.yml runs nested uses: @v1.

**Static detection.** Parse composite actions.

**LLM role.** Same as unpinned.

**False-positive guards.** Local nested actions.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/creating-actions/creating-a-composite-action
  - https://github.com/mheap/pin-github-action
  - https://docs.github.com/en/actions/reference/security/secure-use

---
### 18. `gha.if.weak-trust-gate` — Privileged job gated by a spoofable if: condition

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Privileged jobs whose only guard is a condition the attacker can influence: actor-name checks (github.actor == 'dependabot[bot]' fires on others' events too), label gates on pull_request_target (code can change after labeling), or head_ref/branch-name matching.

**Static detection.** Detect privileged triggers (pull_request_target / workflow_run) whose jobs are gated solely by actor/label/branch-name conditions.

**LLM role.** LLM: expression sandbox limits.

**False-positive guards.** Trusted actor-only gates.

**Public examples of the bad pattern:**
  - https://securitylab.github.com/resources/github-actions-untrusted-input/
  - https://docs.github.com/en/actions/learn-github-actions/expressions
  - https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/

---
### 19. `gha.deploy.without-environment` — Deploy to cloud without environment

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** AWS/GCP deploy actions without environment: key.

**Static detection.** Detect deploy actions missing environment.

**LLM role.** Suggest environments for approval.

**False-positive guards.** Non-prod accounts.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment
  - https://github.com/aws-actions/configure-aws-credentials
  - https://github.com/actions/starter-workflows

---
### 20. `gha.timeout.missing` — No job timeout

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** Jobs without timeout-minutes can run forever (cost/DoS).

**Static detection.** Detect missing timeout-minutes.

**LLM role.** Suggest defaults.

**False-positive guards.** Workflow bots intentional long runs.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes
  - https://github.com/rhysd/actionlint
  - https://github.com/actions/starter-workflows

---
### 21. `gha.permissions.contents-write-on-pr` — contents:write on pull_request

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** PR workflows with write can be dangerous with injection.

**Static detection.** Detect permissions + pull_request combination.

**LLM role.** Combine with injection analysis.

**False-positive guards.** Trusted monorepo bots.

**Public examples of the bad pattern:**
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
  - https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs
  - https://github.com/ossf/scorecard

---
### 22. `gha.runs-on.expression` — runs-on from untrusted expression

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | medium |

**What it is.** runs-on: ${{ github.event.issue.title }} style label injection.

**Static detection.** Detect expressions in runs-on.

**LLM role.** Hard fail if untrusted context.

**False-positive guards.** Static label maps from trusted env.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-jobs/choosing-the-runner-for-a-job
  - https://securitylab.github.com/resources/github-actions-untrusted-input/
  - https://docs.github.com/en/actions/reference/security/secure-use

---
### 23. `gha.artifact.download-execute` — Downloaded artifact executed without verification

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** download-artifact then chmod +x ./tool && ./tool.

**Static detection.** Dataflow-ish patterns across steps.

**LLM role.** LLM: multi-step story.

**False-positive guards.** Artifacts built in same trusted job.

**Public examples of the bad pattern:**
  - https://github.com/actions/download-artifact
  - https://docs.github.com/en/actions/reference/security/secure-use
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/

---
### 24. `gha.artifact.secret-upload` — Artifacts capture secrets/credentials

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** upload-artifact of paths that commonly contain credentials: the whole workspace after auth steps, .git/config (checkout's persisted token), .env, .npmrc, docker config.json. On public repos, artifacts are downloadable — the ArtiPACKED class of leak.

**Static detection.** upload-artifact with path: . or broad globs; known credential paths; escalate when a prior step wrote credentials (docker/login-action, checkout with default persist-credentials).

**LLM role.** Trace what actually lands in the uploaded directory across steps.

**False-positive guards.** Build outputs from paths that cannot contain credentials; short retention on private repos lowers severity (do not suppress).

**Public examples of the bad pattern:**
  - https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/ — ArtiPACKED research
  - https://github.com/actions/upload-artifact
  - https://github.com/actions/checkout — persist-credentials default

---

## Implementation roadmap (after approval)
1. Ship P0 static rules with vulnerable+clean fixtures.
2. Feed static signals into LLM review for enhancement (not re-detection).
3. Add discovery prompts constrained to evidence.
4. Precision bake-off on popular public repos; FP budget is a release gate.

**P0 priorities:** pwn-request, script injection (incl. head_ref), unpinned third-party actions, self-hosted+PR, write permissions on PR, runs-on expressions.
