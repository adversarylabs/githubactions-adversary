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
| `gha.step.stale-output-reference` | High | A changed workflow job still references `steps.<id>.outputs.<key>` after that same job's step id was removed or renamed |

`gha.step.stale-output-reference` compares previous and current semantic YAML by job identity. It reports only when a step id previously present in that same job disappears while the same live downstream step expression, job output, or environment URL still references the old id. Step-level `if` conditions are parsed as implicit expressions even without `${{ }}`; braced expressions are scanned without treating `}}` inside quoted strings as the expression terminator. Anonymous step consumers must remain semantically identical; stable consumer step ids and output names provide stronger identity. Ambiguous anonymous consumers and invalid duplicate step ids fail closed. The previous and current relationship must have been executable: statically disabled jobs, earlier-step and self references, job pre-execution fields, steps disabled by literal GitHub-expression falsy values or mechanically proven constant comparisons, short-circuited expression branches, and expression string literals stay quiet. Constant equality follows GitHub's documented loose numeric coercion for null, booleans, numbers, empty strings, and legal JSON-number strings; nonnumeric conversions and dynamic conditions fail open as potentially executable. Output keys are deliberately opaque, so action-defined outputs, dynamic `GITHUB_OUTPUT` writes, and output-key-only edits stay quiet while the producer id survives. Comments, non-expression strings, cross-job lookalikes, job renames, and unrelated edits to legacy broken references also stay quiet.
