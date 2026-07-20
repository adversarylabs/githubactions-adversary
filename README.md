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
