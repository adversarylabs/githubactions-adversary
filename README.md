# GitHub Actions adversary

Reviews GitHub Actions workflows for security, supply-chain, and reliability defects.

## Checks

- **External action uses a mutable reference:** Pin external actions to full commit SHAs.
- **Workflow grants write-all token permissions:** Default to read-only and elevate only narrowly scoped release jobs.
- **Trusted pull_request_target workflow executes pull-request code:** Never execute pull-request-controlled code in pull_request_target.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the github-actions adversary when changes include `.github/workflows/*.yml` or `.github/workflows/*.yaml`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.

## Issue catalog

What this adversary targets (P0 / P1 / LLM-only priorities, detection notes, and public pattern references) is documented in [docs/issue-catalog.md](docs/issue-catalog.md).
