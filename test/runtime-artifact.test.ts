import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const execute = promisify(execFile);

test("the bundled runtime executes without node_modules", async () => {
  const artifact = await mkdtemp(join(tmpdir(), "github-actions-artifact-"));
  const target = await mkdtemp(join(tmpdir(), "github-actions-target-"));
  await mkdir(join(artifact, "dist"), { recursive: true });
  await cp(join(projectRoot, "dist", "index.js"), join(artifact, "dist", "index.js"));
  await cp(join(projectRoot, "schema"), join(artifact, "schema"), { recursive: true });
  await cp(join(projectRoot, "schemas"), join(artifact, "schemas"), { recursive: true });
  await cp(join(projectRoot, "THIRD_PARTY_NOTICES.md"), join(artifact, "THIRD_PARTY_NOTICES.md"));
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');

  const notices = await readFile(join(artifact, "THIRD_PARTY_NOTICES.md"), "utf8");
  assert.deepEqual([...notices.matchAll(/^## (.+?) \(/gm)].map((match) => match[1]), [
    "@adversarylabs/sdk", "ajv", "fast-deep-equal", "fast-uri", "json-schema-traverse", "yaml",
  ]);
  assert.match(notices, /Permission is hereby granted/);
  assert.match(notices, /Redistribution and use in source and binary forms/);

  const runtime = await import(pathToFileURL(join(artifact, "dist", "index.js")).href) as {
    createApp(): { run(options: { input: unknown }): Promise<{ adversary: { name: string; version?: string }; findings: unknown[] }> };
  };
  const result = await runtime.createApp().run({ input: { source: { path: target } } });
  assert.equal(result.adversary.name, "github-actions");
  assert.equal(result.adversary.version, "0.0.18");
  assert.deepEqual(result.findings, []);
});

test("packaging excludes linked-worktree metadata and shipped files contain no local paths", async () => {
  const ignored = (await readFile(join(projectRoot, ".adversaryignore"), "utf8"))
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  assert.ok(ignored.includes(".git"));
  assert.ok(ignored.includes("node_modules/"));
  const runtimeFiles = [
    "adversary.yaml",
    "dist/index.js",
    "THIRD_PARTY_NOTICES.md",
    "schema/adversary.manifest.v1.schema.json",
    "schemas/adversary.review.v1.schema.json",
    "package.json",
  ];
  const archiveRoot = await mkdtemp(join(tmpdir(), "github-actions-package-"));
  const archive = join(archiveRoot, "package.tar");
  for (const relative of runtimeFiles) {
    await execute("git", ["ls-files", "--error-unmatch", relative], { cwd: projectRoot });
  }
  await execute("git", ["archive", "--format=tar", `--output=${archive}`, "HEAD", ...runtimeFiles], {
    cwd: projectRoot,
  });
  const { stdout: listing } = await execute("tar", ["-tf", archive]);
  for (const relative of listing.split(/\r?\n/).filter(Boolean)) {
    assert.equal(relative.split("/").includes("node_modules"), false, `${relative} must not ship`);
    assert.equal(relative.split("/").includes(".git"), false, `${relative} must not ship`);
  }
  for (const relative of runtimeFiles) {
    const content = await readFile(join(projectRoot, relative), "utf8");
    assert.doesNotMatch(content, /(?:\/Users\/|\/private\/tmp\/|[A-Za-z]:\\\\Users\\\\)/);
  }
});
