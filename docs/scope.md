# ci/github-actions — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `githubactions`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** .github/workflows

## Mission

Review GitHub Actions workflows for security, supply-chain, and reliability defects.

## In scope (fair miss if humans raised it and we did not)

- Privileged jobs, self-hosted runner risks, --privileged
- Unpinned actions, supply-chain footguns
- Secret leakage in workflows
- Dangerous permissions / GITHUB_TOKEN misuse
- Unreliable or insecure workflow patterns
- Removed or renamed step ids still referenced through outputs in the same job

## Out of scope (not a miss for this adversary)

- Application Go/TS business logic
- Dockerfile content (unless only referenced)
- Non-workflow files as primary surface

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
