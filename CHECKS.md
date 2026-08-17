# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `gha.action.unpinned-tag` | High | External action uses mutable ref |
| `gha.custom-runner.missing-timeout` | Medium | Long-running build, packaging, release, or integration job has no job timeout on a custom runner |
| `gha.permissions.contents-write-on-pr` | High | contents: write on pull_request |
| `gha.permissions.write-all` | High | Workflow grants write-all token permissions |
| `gha.pull-request-target.pwn` | Critical | pull_request_target checks out untrusted PR code |
| `gha.runs-on.expression` | High | Dynamic runs-on expression |
| `gha.script-injection.context` | Critical | Untrusted github.event interpolated into run: |
| `gha.self-hosted.untrusted` | High | Untrusted code on self-hosted runner |
| `gha.step.stale-output-reference` | Medium | A changed workflow still references `steps.<id>.outputs.<key>` after that output disappeared |
