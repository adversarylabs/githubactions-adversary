import assert from "node:assert/strict";
import test from "node:test";
import { detectCiSecurityIssues, GHA_RULE_IDS } from "../src/ci-security-core.ts";

test("detectCiSecurityIssues finds P0 patterns on vulnerable snippets", () => {
  const src = `
on: pull_request_target
permissions: write-all
jobs:
  t:
    runs-on: \${{ github.event.issue.title }}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: echo "\${{ github.event.comment.body }}"
`;
  const hits = detectCiSecurityIssues(".github/workflows/x.yml", src);
  const keys = new Set(hits.map((h) => h.key));
  assert.ok(keys.has("unpinned-action"));
  assert.ok(keys.has("write-all"));
  assert.ok(keys.has("pull-request-target-pwn"));
  assert.ok(keys.has("script-injection"));
  assert.ok(keys.has("runs-on-expression"));
  for (const hit of hits) {
    const id = GHA_RULE_IDS[hit.key];
    if (id) assert.match(id, /^gha\./);
  }
});

test("clean pinned workflow is quiet for unpinned", () => {
  const src = `
on: push
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`;
  const hits = detectCiSecurityIssues("w.yml", src);
  assert.equal(hits.some((h) => h.key === "unpinned-action"), false);
});
