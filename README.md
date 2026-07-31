# ci/github-actions

**ci/github-actions** reviews GitHub Actions workflows for **security, supply-chain, and reliability** defects: unpinned actions, over-broad tokens, pwn-request patterns, script injection, and unsafe self-hosted runners.

It is a **CI security reviewer** for `.github/workflows`, not a general YAML linter. When it reports, a workflow can steal secrets or run untrusted code with privileged tokens.

## What it does

1. **Discovers** workflow files under `.github/workflows/`.
2. **Runs deterministic detectors** with stable rule ids and file:line evidence.
3. **Synthesizes a review** prioritizing critical privilege and injection issues.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Highlights:

| Area | Examples |
| --- | --- |
| Supply chain | Actions pinned to tags/branches instead of full SHAs |
| Permissions | `permissions: write-all`; contents write on PR |
| Pwn-request | `pull_request_target` checking out PR head |
| Injection | Untrusted `github.event` fields expanded in `run:` |
| Runners | Untrusted code on self-hosted; dynamic `runs-on` expressions |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| Depot-specific cache/runner concerns | [`ci/depot`](https://github.com/adversarylabs/depotci-adversary) |
| Committed secrets in any file | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |
| Dockerfile supply chain | [`container/dockerfile`](https://github.com/adversarylabs/dockerfile-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire where graded fixtures exist.
- Prefer missing a weak signal over a false positive on normal production code.
