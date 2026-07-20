# Initial checks

## github-actions.unpinned-action

- Severity: medium
- Category: supply-chain
- Recommendation: Pin external actions to full commit SHAs.

## github-actions.write-all

- Severity: high
- Category: permissions
- Recommendation: Default to read-only and elevate only narrowly scoped release jobs.

## github-actions.pull-request-target-head

- Severity: critical
- Category: security
- Recommendation: Never execute pull-request-controlled code in pull_request_target.

