import assert from "node:assert/strict";
import test from "node:test";
import { ACTIONLINT_VERSION, runActionlint } from "../src/actionlint.js";

test("runs the vendored actionlint engine deterministically", async () => {
  assert.equal(ACTIONLINT_VERSION, "1.7.12");
  const errors = await runActionlint(".github/workflows/invalid.yml", `
on: unknown_event
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`);

  assert.equal(errors.length, 1);
  assert.equal(errors[0]?.kind, "events");
  assert.match(errors[0]?.message ?? "", /unknown Webhook event/);
  assert.equal(errors[0]?.line, 2);
});

test("returns no diagnostics for a valid workflow", async () => {
  const errors = await runActionlint(".github/workflows/valid.yml", `
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`);
  assert.deepEqual(errors, []);
});
