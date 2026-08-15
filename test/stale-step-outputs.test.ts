import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);
const ruleId = "gha.step.stale-output-reference";
const path = ".github/workflows/release.yml";

test("deleted step still referenced by later outputs expression", async () => {
  const repo = await gitRepo(workflow({ includeMeta: true, ref: "tags" }));
  await writeFile(join(repo, path), workflow({ includeMeta: false, ref: "tags" }));
  const result = await changedReview(repo);
  const hits = result.findings.filter((finding) => finding.ruleId === ruleId);
  assert.equal(hits.length, 1);
  assert.match(JSON.stringify(hits[0]), /steps\.meta\.outputs\.tags|stale-output/);
});

test("renamed output key with leftover old reference", async () => {
  const repo = await gitRepo(workflow({ includeMeta: true, ref: "tags", outputKey: "tags" }));
  await writeFile(join(repo, path), workflow({ includeMeta: true, ref: "tags", outputKey: "tag" }));
  const result = await changedReview(repo);
  assert.equal(result.findings.some((finding) => finding.ruleId === ruleId), true);
});

test("removed outputs stay quiet when no remaining reference", async () => {
  const repo = await gitRepo(workflow({ includeMeta: true, ref: "tags" }));
  await writeFile(join(repo, path), workflow({ includeMeta: false, ref: undefined }));
  const result = await changedReview(repo);
  assert.equal(result.findings.some((finding) => finding.ruleId === ruleId), false);
});

test("rename stays quiet when every reference is updated", async () => {
  const repo = await gitRepo(workflow({ includeMeta: true, ref: "tags", outputKey: "tags" }));
  await writeFile(join(repo, path), workflow({ includeMeta: true, ref: "tag", outputKey: "tag" }));
  const result = await changedReview(repo);
  assert.equal(result.findings.some((finding) => finding.ruleId === ruleId), false);
});

test("comment-only edit of a leftover expression stays quiet", async () => {
  const repo = await gitRepo(workflow({ includeMeta: true, ref: "tags", note: "old" }));
  await writeFile(join(repo, path), workflow({ includeMeta: true, ref: "tags", note: "new" }));
  const result = await changedReview(repo);
  assert.equal(result.findings.some((finding) => finding.ruleId === ruleId), false);
});

test("full-line comment is not a live reference", async () => {
  const previous = workflow({ includeMeta: true, ref: "tags" });
  const current = workflow({ includeMeta: false, ref: undefined }).replace(
    "      - run: echo unused\n",
    "      # - run: docker build --tag ${{ steps.meta.outputs.tags }}\n",
  );
  const repo = await gitRepo(previous);
  await writeFile(join(repo, path), current);
  const result = await changedReview(repo);
  assert.equal(result.findings.some((finding) => finding.ruleId === ruleId), false);
});

test("opaque GITHUB_OUTPUT step remains quiet while the step still exists", async () => {
  const previous = `name: Release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - id: meta
        run: echo "tags=v1" >> "$GITHUB_OUTPUT"
      - run: docker build --tag \${{ steps.meta.outputs.tags }} .
`;
  const repo = await gitRepo(previous);
  await writeFile(join(repo, path), previous.replace("echo \"tags=v1\"", "echo \"tags=v2\""));
  const result = await changedReview(repo);
  assert.equal(result.findings.some((finding) => finding.ruleId === ruleId), false);
});

function workflow(options: {
  includeMeta: boolean;
  ref?: string;
  outputKey?: string;
  note?: string;
}): string {
  const key = options.outputKey ?? "tags";
  const meta = options.includeMeta
    ? `      - id: meta
        run: echo meta
        outputs:
          ${key}: v1
`
    : "";
  const use = options.ref === undefined
    ? "      - run: echo unused\n"
    : `      - run: docker build --tag \${{ steps.meta.outputs.${options.ref} }} .\n`;
  const note = options.note === undefined ? "" : `    env:\n      NOTE: ${options.note}\n`;
  return `name: Release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
${note}    steps:
${meta}${use}`;
}

async function gitRepo(content: string): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "githubactions-stale-outputs-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await mkdir(join(repo, ".github/workflows"), { recursive: true });
  await writeFile(join(repo, path), content);
  await execute("git", ["add", path], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "baseline"], { cwd: repo });
  return repo;
}

async function changedReview(repo: string) {
  return createApp().run({
    input: {
      source: { path: repo },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: [path],
      },
    },
  });
}
