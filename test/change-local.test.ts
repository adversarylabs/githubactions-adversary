import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated workflow edit does not surface a legacy unpinned action", async () => {
  const repo = await repositoryWithLegacyWorkflow();
  const path = ".github/workflows/ci.yml";
  await writeFile(join(repo, path), workflow("new unrelated diagnostic"));

  const result = await changedReview(repo, [path]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "gha.action.unpinned-tag"),
    false,
  );
});

test("an added workflow remains fully eligible", async () => {
  const repo = await repositoryWithLegacyWorkflow();
  const path = ".github/workflows/added.yml";
  await writeFile(join(repo, path), workflow("added workflow"));

  const result = await changedReview(repo, [path]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "gha.action.unpinned-tag"),
    true,
  );
});

test("changed line findings still use unchanged workflow context", async () => {
  const repo = await repositoryWithLegacyWorkflow();
  const path = ".github/workflows/context.yml";
  await writeFile(join(repo, path), contextualWorkflow("ubuntu-latest"));
  await execute("git", ["add", path], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "context fixture"], { cwd: repo });
  await writeFile(join(repo, path), contextualWorkflow("self-hosted"));

  const result = await changedReview(repo, [path]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "gha.self-hosted.untrusted"),
    true,
  );
});

async function repositoryWithLegacyWorkflow(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "githubactions-change-local-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await mkdir(join(repo, ".github/workflows"), { recursive: true });
  await writeFile(join(repo, ".github/workflows/ci.yml"), workflow("old diagnostic"));
  await execute("git", ["add", ".github/workflows/ci.yml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

function workflow(diagnostic: string): string {
  return `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo test
      - name: Diagnostic
        run: echo ${JSON.stringify(diagnostic)}
`;
}

function contextualWorkflow(runner: string): string {
  return `name: Pull request
on: pull_request
jobs:
  test:
    runs-on: ${runner}
    steps:
      - run: echo test
`;
}

async function changedReview(repoPath: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}
