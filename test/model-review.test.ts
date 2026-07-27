import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ModelUnavailableError,
  type ModelReviewRequest,
  type ReviewModel,
} from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";
import { GITHUBACTIONS_MODEL_PROMPT, GITHUBACTIONS_MODEL_SCHEMA } from "../src/model-review.ts";

function unavailableModel(): ReviewModel {
  return {
    async review() { throw new ModelUnavailableError("no broker"); },
  };
}

function capturingModel(output: unknown): ReviewModel & { requests: ModelReviewRequest[] } {
  const requests: ModelReviewRequest[] = [];
  return {
    requests,
    async review<T>(request: ModelReviewRequest) {
      requests.push(request);
      const schema = request.schema as { required?: string[] };
      if (Array.isArray(schema.required) && schema.required.includes("concern")) {
        return { output: { concern: "material secret exposure" } as T, provider: "f", model: "c" };
      }
      return { output: output as T, provider: "f", model: "t" };
    },
  };
}

async function writeRoot(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "githubactions-model-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(root, rel);
    await mkdir(join(abs, ".."), { recursive: true });
    await writeFile(abs, content);
  }
  return root;
}

test("static path works when model unavailable", async () => {
  const root = await writeRoot({ "README.md": "hello\n" });
  const result = await createApp().run({ model: unavailableModel(), input: { source: { path: root } } });
  assert.ok(Array.isArray(result.findings));
});

test("injected model path receives prepared catalog", async () => {
  const root = await writeRoot({ "README.md": "hello\n" });
  const model = capturingModel({
    assessment: { risk: "none", summary: "No material secret exposure in prepared evidence." },
    ship: true,
    observations: [],
  });
  await createApp().run({ model, input: { source: { path: root } } });
  assert.ok(model.requests.length >= 1);
  const req = model.requests.find((r) => {
    const schema = r.schema as { required?: string[] };
    return !(Array.isArray(schema.required) && schema.required.includes("concern"));
  })!;
  assert.equal(req.prompt, GITHUBACTIONS_MODEL_PROMPT);
  assert.deepEqual(req.schema, GITHUBACTIONS_MODEL_SCHEMA);
  const input = req.input as { domain: string };
  assert.equal(input.domain, "githubactions");
});
