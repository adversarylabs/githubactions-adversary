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

test("deleted same-job step id leaves a broken output reference", async () => {
  const hits = await findings(workflow(producer("meta"), "meta"), workflow("", "meta"));
  assert.equal(hits.length, 1);
  assert.match(JSON.stringify(hits[0]), /release.*steps\.meta\.outputs\.tags.*same-job-step-id-removed-or-renamed/);
});

test("renamed step id with a surviving old reference reports", async () => {
  const hits = await findings(workflow(producer("meta"), "meta"), workflow(producer("metadata"), "meta"));
  assert.equal(hits.length, 1);
});

test("renaming the step id and every reference stays quiet", async () => {
  const hits = await findings(workflow(producer("meta"), "meta"), workflow(producer("metadata"), "metadata"));
  assert.deepEqual(hits, []);
});

test("the exact Paralus-style implicit action output remains quiet when only action inputs disappear", async () => {
  const previous = workflow(`      - name: Docker metadata
        id: meta-init
        uses: docker/metadata-action@818d4b7b91585d195f67373fd9cb0332e31a7175
        with:
          images: ghcr.io/paralus/paralus-init
          tags: |
            type=ref,event=tag
`, "meta-init");
  const current = previous.replace("          tags: |\n            type=ref,event=tag\n", "");
  assert.deepEqual(await findings(previous, current), []);
});

test("renaming or removing a declared output key is outside the rule", async () => {
  const previous = workflow(scriptProducer("meta", "tags"), "meta", "tags");
  const current = workflow(scriptProducer("meta", "tag"), "meta", "tags");
  assert.deepEqual(await findings(previous, current), []);
});

test("a dynamic GITHUB_OUTPUT producer is quiet while its id survives", async () => {
  const dynamic = `      - id: meta
        run: printf '%s=%s\\n' "$OUTPUT_NAME" v1 >> "$GITHUB_OUTPUT"
`;
  const previous = workflow(dynamic, "meta");
  const current = previous.replace(" v1 >>", " v2 >>");
  assert.deepEqual(await findings(previous, current), []);
});

test("a deleted dynamic producer reports because its identity is proven", async () => {
  const dynamic = `      - id: meta
        run: printf '%s=%s\\n' "$OUTPUT_NAME" v1 >> "$GITHUB_OUTPUT"
`;
  assert.equal((await findings(workflow(dynamic, "meta"), workflow("", "meta"))).length, 1);
});

test("same-looking references and producers in different jobs do not cross-contaminate", async () => {
  const previous = twoJobs(producer("meta"), "", "meta");
  const current = twoJobs("", producer("meta"), "meta");
  const hits = await findings(previous, current);
  assert.equal(hits.length, 1);
  assert.match(JSON.stringify(hits[0]), /jobId.*build/);
});

test("a reference in a job that never owned the step id remains legacy noise", async () => {
  const previous = workflow("", "meta");
  const current = previous.replace("ubuntu-latest", "ubuntu-24.04");
  assert.deepEqual(await findings(previous, current), []);
});

test("comment-only edits and commented expressions stay quiet", async () => {
  const previous = workflow(producer("meta"), "meta") + "# old note ${{ steps.ghost.outputs.tags }}\n";
  const current = previous.replace("# old note", "# new note");
  assert.deepEqual(await findings(previous, current), []);
});

test("text outside a GitHub expression is not a semantic reference", async () => {
  const previous = workflow(producer("meta"), undefined);
  const current = workflow("", undefined).replace("echo unused", "echo steps.meta.outputs.tags");
  assert.deepEqual(await findings(previous, current), []);
});

test("multiline expressions are parsed from YAML scalar values", async () => {
  const previous = workflow(producer("meta"), undefined).replace(
    "      - run: echo unused\n",
    "      - name: consume\n        env:\n          TAGS: >-\n            ${{\n              steps.meta.outputs.tags\n            }}\n        run: echo ok\n",
  );
  const current = previous.replace(producer("meta"), "");
  const hits = await findings(previous, current);
  assert.equal(hits.length, 1);
  assert.match(JSON.stringify(hits[0]), /steps\.meta\.outputs\.tags/);
});

test("job renames are not guessed as same-job step changes", async () => {
  const previous = workflow(producer("meta"), "meta");
  const current = previous.replace("  release:", "  publish:").replace(producer("meta"), "");
  assert.deepEqual(await findings(previous, current), []);
});

test("duplicate step ids fail closed", async () => {
  const duplicated = workflow(producer("meta") + producer("meta"), "meta");
  assert.deepEqual(await findings(duplicated, workflow("", "meta")), []);
});

test("only a previously downstream step relationship is eligible", async () => {
  const earlier = `      - run: echo \${{ steps.meta.outputs.tags }}
${producer("meta")}`;
  const self = `      - id: meta
        env:
          OLD: \${{ steps.meta.outputs.tags }}
        run: echo ok
`;
  for (const previous of [workflow(earlier, undefined), workflow(self, undefined)]) {
    const current = previous.replace(/\s*- id: meta\n(?:\s+uses:.*\n)?/, "\n");
    assert.deepEqual(await findings(previous, current), []);
  }
});

test("job outputs and environment URLs are post-step consumers but runs-on is not", async () => {
  const baseline = workflow(producer("meta"), undefined);
  const variants = [
    {
      field: "    outputs:\n      tags: ${{ steps.meta.outputs.tags }}\n    runs-on:",
      expected: 1,
    },
    {
      field: "    environment:\n      name: production\n      url: ${{ steps.meta.outputs.url }}\n    runs-on:",
      expected: 1,
    },
    { field: "    runs-on: ${{ steps.meta.outputs.runner }}\n    # old-runs-on:", expected: 0 },
  ];
  for (const { field, expected } of variants) {
    const previous = baseline.replace("    runs-on:", field);
    const current = previous.replace(producer("meta"), "");
    assert.equal((await findings(previous, current)).length, expected);
  }
});

test("step metadata fields that cannot use the steps context stay quiet", async () => {
  const previous = workflow(
    producer("meta") + `      - name: \${{ steps.meta.outputs.name }}
        uses: ./\${{ steps.meta.outputs.action }}
`,
    undefined,
  );
  assert.deepEqual(await findings(previous, previous.replace(producer("meta"), "")), []);
});

test("step-looking expression string literals are ignored without hiding a live reference", async () => {
  const literalConsumers = [
    "      - run: echo ${{ 'steps.meta.outputs.tags' }}\n",
    "      - run: echo ${{ format('steps.meta.outputs.tags') }}\n",
    "      - run: echo ${{ format('not ''steps.meta.outputs.tags''') }}\n",
  ];
  for (const consumer of literalConsumers) {
    const previous = workflow(producer("meta") + consumer, undefined);
    assert.deepEqual(await findings(previous, previous.replace(producer("meta"), "")), []);
  }
  const live = "      - run: echo ${{ format('ignored steps.meta.outputs.other') || steps.meta.outputs.tags }}\n";
  const previous = workflow(producer("meta") + live, undefined);
  assert.equal((await findings(previous, previous.replace(producer("meta"), ""))).length, 1);
});

test("step if accepts implicit GitHub expressions without braces", async () => {
  for (const condition of [
    "steps.meta.outputs.enabled",
    "true && steps.meta.outputs.enabled",
    "(steps.meta.outputs.enabled)",
    '"steps.meta.outputs.enabled"',
  ]) {
    const consumer = `      - id: publish
        if: ${condition}
        run: echo publish
`;
    const previous = workflow(producer("meta") + consumer, undefined);
    assert.equal((await findings(previous, previous.replace(producer("meta"), ""))).length, 1);
  }

  const disabled = `      - id: publish
        if: false && steps.meta.outputs.enabled
        run: echo publish
`;
  const previous = workflow(producer("meta") + disabled, undefined);
  assert.deepEqual(await findings(previous, previous.replace(producer("meta"), "")), []);
});

test("quoted closing braces do not truncate a GitHub expression", async () => {
  const liveExpressions = [
    "'x}}y' && steps.meta.outputs.tags",
    "format('{{Hello {0}!}}', 'Mona') && steps.meta.outputs.tags",
    'format("x}}y") && steps.meta.outputs.tags',
  ];
  for (const expression of liveExpressions) {
    const consumer = `      - id: publish
        run: echo \${{ ${expression} }}
`;
    const previous = workflow(producer("meta") + consumer, undefined);
    assert.equal((await findings(previous, previous.replace(producer("meta"), ""))).length, 1);
  }

  const unreachable = `      - id: publish
        run: echo \${{ true || ('x}}y' && steps.meta.outputs.tags) }}
`;
  const previous = workflow(producer("meta") + unreachable, undefined);
  assert.deepEqual(await findings(previous, previous.replace(producer("meta"), "")), []);
});

test("expression scanning resumes after a quoted-brace expression", async () => {
  const consumer = `      - id: publish
        run: echo \${{ 'x}}y' }} \${{ steps.meta.outputs.tags }}
`;
  const previous = workflow(producer("meta") + consumer, undefined);
  assert.equal((await findings(previous, previous.replace(producer("meta"), ""))).length, 1);
});

test("statically disabled producers and consumers do not establish live relationships", async () => {
  for (const condition of [
    "false",
    "${{ 0 }}",
    "${{ null }}",
    "${{ '' }}",
    "${{ false == true }}",
    "${{ true != true }}",
    "${{ 'a' == 'b' }}",
    "${{ 'A' != 'a' }}",
    "${{ !true == true }}",
    "${{ 0 != false }}",
    "${{ null != false }}",
    "${{ '' != false }}",
    "${{ '0' != false }}",
    "${{ '1' != true }}",
  ]) {
    const disabledProducer = producer("meta").replace("        uses:", `        if: ${condition}\n        uses:`);
    const previousProducer = workflow(disabledProducer, "meta");
    assert.deepEqual(await findings(previousProducer, previousProducer.replace(disabledProducer, "")), []);

    const previousConsumer = workflow(producer("meta"), undefined).replace(
      "      - run: echo unused\n",
      `      - if: ${condition}\n        run: echo \${{ steps.meta.outputs.tags }}\n`,
    );
    assert.deepEqual(await findings(previousConsumer, previousConsumer.replace(producer("meta"), "")), []);
  }
});

test("references in statically short-circuited expression branches stay quiet", async () => {
  const quietExpressions = [
    "false && steps.meta.outputs.tags",
    "true || steps.meta.outputs.tags",
    "false && (github.ref == steps.meta.outputs.tags)",
    "true || (false && steps.meta.outputs.tags)",
    "0 && steps.meta.outputs.tags",
    "null && steps.meta.outputs.tags",
    "'' && steps.meta.outputs.tags",
    "'a' == 'b' && steps.meta.outputs.tags",
    "false || false && steps.meta.outputs.tags",
  ];
  for (const expression of quietExpressions) {
    const previous = workflow(producer("meta"), undefined).replace(
      "      - run: echo unused\n",
      `      - run: echo \${{ ${expression} }}\n`,
    );
    assert.deepEqual(await findings(previous, previous.replace(producer("meta"), "")), []);
  }
});

test("proven true and unprovable conditions remain eligible", async () => {
  for (const condition of [
    "${{ 'false' }}",
    "${{ 'A' == 'a' }}",
    "${{ 'a' != 'b' }}",
    "${{ '1' == true }}",
    "${{ 'not-a-number' == false }}",
    "${{ github.ref }}",
  ]) {
    const active = producer("meta").replace("        uses:", `        if: ${condition}\n        uses:`);
    const previous = workflow(active, "meta");
    assert.equal((await findings(previous, previous.replace(active, ""))).length, 1);
  }
});

test("dynamic conditions and post-step job outputs remain live", async () => {
  const dynamic = workflow(producer("meta"), undefined).replace(
    "      - run: echo unused\n",
    "      - if: ${{ github.ref == 'refs/heads/main' }}\n        run: echo ${{ steps.meta.outputs.tags }}\n",
  );
  assert.equal((await findings(dynamic, dynamic.replace(producer("meta"), ""))).length, 1);

  const output = workflow(producer("meta"), undefined).replace(
    "    runs-on:",
    "    outputs:\n      tags: ${{ steps.meta.outputs.tags }}\n    runs-on:",
  );
  assert.equal((await findings(output, output.replace(producer("meta"), ""))).length, 1);
});

test("statically disabled jobs do not establish or retain executable relationships", async () => {
  const active = workflow(producer("meta"), "meta");
  const disabledPrevious = active.replace("    runs-on:", "    if: false\n    runs-on:");
  const disabledCurrent = workflow("", "meta").replace(
    "    runs-on:",
    "    if: ${{ false }}\n    runs-on:",
  );
  assert.deepEqual(await findings(disabledPrevious, workflow("", "meta")), []);
  assert.deepEqual(await findings(active, disabledCurrent), []);

  const dynamic = active.replace("    runs-on:", "    if: ${{ github.ref }}\n    runs-on:");
  assert.equal((await findings(dynamic, dynamic.replace(producer("meta"), ""))).length, 1);
});

test("a surviving reference must be the same previous semantic consumer occurrence", async () => {
  const early = "      - run: echo ${{ steps.meta.outputs.tags }}\n";
  const late = "      - run: publish ${{ steps.meta.outputs.tags }}\n";
  assert.deepEqual(await findings(
    workflow(early + producer("meta") + late, undefined),
    workflow(early, undefined),
  ), []);

  const previous = workflow(producer("meta") + late, undefined);
  assert.equal((await findings(previous, workflow(late, undefined))).length, 1);
});

test("consumer scopes and job-output identities do not validate different references", async () => {
  const early = "      - run: echo ${{ steps.meta.outputs.tags }}\n";
  const previous = workflow(early + producer("meta"), undefined).replace(
    "    runs-on:",
    "    outputs:\n      image: ${{ steps.meta.outputs.tags }}\n    runs-on:",
  );
  assert.deepEqual(await findings(previous, workflow(early, undefined)), []);

  const previousOutput = workflow(producer("meta"), undefined).replace(
    "    runs-on:",
    "    outputs:\n      image: ${{ steps.meta.outputs.tags }}\n    runs-on:",
  );
  const currentOutput = workflow("", undefined).replace(
    "    runs-on:",
    "    outputs:\n      image: ${{ steps.meta.outputs.tags }}\n    runs-on:",
  );
  assert.equal((await findings(previousOutput, currentOutput)).length, 1);
});

test("duplicate ids invalidate the workflow even when a duplicate is disabled", async () => {
  const disabledDuplicate = producer("meta").replace(
    "        uses:",
    "        if: false\n        uses:",
  );
  const previous = workflow(producer("meta") + disabledDuplicate, "meta");
  assert.deepEqual(await findings(previous, workflow("", "meta")), []);

  const active = workflow(producer("meta"), "meta");
  const unrelatedDuplicates = producer("other") + producer("other").replace(
    "        uses:",
    "        if: false\n        uses:",
  );
  assert.deepEqual(await findings(active, workflow(unrelatedDuplicates, "meta")), []);
});

test("ambiguous anonymous consumers fail closed while stable consumer ids survive edits", async () => {
  const duplicateConsumers = "      - run: echo ${{ steps.meta.outputs.tags }}\n".repeat(2);
  assert.deepEqual(await findings(
    workflow(producer("meta") + duplicateConsumers, undefined),
    workflow(duplicateConsumers, undefined),
  ), []);

  const namedConsumer = `      - id: publish
        name: old label
        run: echo \${{ steps.meta.outputs.tags }}
`;
  const previous = workflow(producer("meta") + namedConsumer, undefined);
  const current = workflow(namedConsumer.replace("old label", "new label"), undefined);
  assert.equal((await findings(previous, current)).length, 1);
});

function producer(id: string): string {
  return `      - id: ${id}\n        uses: docker/metadata-action@v5\n`;
}

function scriptProducer(id: string, output: string): string {
  return `      - id: ${id}\n        run: echo "${output}=v1" >> "$GITHUB_OUTPUT"\n`;
}

function workflow(step: string, reference?: string, output = "tags"): string {
  const consumer = reference === undefined
    ? "      - run: echo unused\n"
    : `      - run: docker build --tag \${{ steps.${reference}.outputs.${output} }} .\n`;
  return `name: Release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
${step}${consumer}`;
}

function twoJobs(buildStep: string, publishStep: string, reference: string): string {
  return `name: Release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
${buildStep}      - run: echo \${{ steps.${reference}.outputs.tags }}
  publish:
    runs-on: ubuntu-latest
    steps:
${publishStep}      - run: echo \${{ steps.${reference}.outputs.tags }}
`;
}

async function findings(previous: string, current: string) {
  const repo = await gitRepo(previous);
  await writeFile(join(repo, path), current);
  const result = await changedReview(repo);
  return result.findings.filter((finding) => finding.ruleId === ruleId);
}

async function gitRepo(content: string): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "githubactions-step-identity-"));
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
