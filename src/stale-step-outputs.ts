import { parseAllDocuments } from "yaml";

export interface StaleStepOutputHit {
  file: string;
  line: number;
  snippet: string;
  label: string;
  data: Record<string, unknown>;
}

interface StepOutputs {
  declared: Set<string>;
  opaque: boolean;
}

const REFERENCE = /steps\.([A-Za-z_][\w-]*)\.outputs\.([A-Za-z_][\w-]*)/g;

/**
 * Changed-local detector: a step output definition disappeared while the
 * same workflow file still references steps.<id>.outputs.<key>.
 */
export function detectStaleStepOutputs(
  file: string,
  current: string,
  previous: string | undefined,
): StaleStepOutputHit[] {
  if (previous === undefined) return [];
  const previousSteps = collectStepOutputs(previous);
  if (previousSteps.size === 0) return [];
  const currentSteps = collectStepOutputs(current);
  const hits: StaleStepOutputHit[] = [];
  const seen = new Set<string>();

  for (const reference of collectReferences(current)) {
    if (!outputRemoved(previousSteps, currentSteps, reference.stepId, reference.key)) continue;
    const key = `${reference.line}:${reference.stepId}:${reference.key}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hits.push({
      file,
      line: reference.line,
      snippet: reference.snippet,
      label: `Workflow still references steps.${reference.stepId}.outputs.${reference.key} after that output disappeared`,
      data: { stepId: reference.stepId, outputKey: reference.key },
    });
  }
  return hits;
}

function outputRemoved(
  previousSteps: Map<string, StepOutputs>,
  currentSteps: Map<string, StepOutputs>,
  stepId: string,
  key: string,
): boolean {
  const previous = previousSteps.get(stepId);
  if (previous === undefined) return false;
  if (!emittedKey(previous, key)) return false;
  const current = currentSteps.get(stepId);
  if (current === undefined) return true;
  return !emittedKey(current, key);
}

function emittedKey(step: StepOutputs, key: string): boolean {
  return step.opaque || step.declared.has(key);
}

function collectStepOutputs(source: string): Map<string, StepOutputs> {
  const steps = new Map<string, StepOutputs>();
  let documents;
  try {
    documents = parseAllDocuments(source, { prettyErrors: false, uniqueKeys: true });
  } catch {
    return steps;
  }
  for (const document of documents) {
    if (document.errors.length > 0) continue;
    let manifest: Record<string, unknown> | undefined;
    try {
      manifest = asRecord(document.toJS({ maxAliasCount: 100 }));
    } catch {
      continue;
    }
    if (manifest === undefined) continue;
    const jobs = asRecord(manifest.jobs);
    if (jobs === undefined) continue;
    for (const job of Object.values(jobs)) {
      const list = asRecord(job)?.steps;
      if (!Array.isArray(list)) continue;
      for (const raw of list) {
        const step = asRecord(raw);
        if (step === undefined) continue;
        const id = step.id;
        if (typeof id !== "string" || id.length === 0) continue;
        const discovered = discoverStepOutputs(step);
        const existing = steps.get(id);
        if (existing === undefined) {
          steps.set(id, discovered);
          continue;
        }
        existing.opaque ||= discovered.opaque;
        for (const key of discovered.declared) existing.declared.add(key);
      }
    }
  }
  return steps;
}

function discoverStepOutputs(step: Record<string, unknown>): StepOutputs {
  // Reusable actions own their output contract outside the workflow. Treat
  // those producers as opaque so a version or input edit cannot look like an
  // output deletion without action metadata.
  if (typeof step.uses === "string") return { declared: new Set(), opaque: true };
  if (typeof step.run !== "string") return { declared: new Set(), opaque: false };

  const declared = new Set<string>();
  let opaque = false;
  for (const line of step.run.split(/\r?\n/)) {
    if (!/(?:\$GITHUB_OUTPUT|\$\{GITHUB_OUTPUT\})/.test(line)) continue;
    const match = /["']?([A-Za-z_][\w-]*)(?:=|<<)[^\n]*(?:\$GITHUB_OUTPUT|\$\{GITHUB_OUTPUT\})/.exec(line);
    if (match?.[1] === undefined) {
      opaque = true;
    } else {
      declared.add(match[1]);
    }
  }
  return { declared, opaque };
}

function collectReferences(source: string): Array<{ stepId: string; key: string; line: number; snippet: string }> {
  const references: Array<{ stepId: string; key: string; line: number; snippet: string }> = [];
  const lines = source.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (/^\s*#/.test(line)) continue;
    REFERENCE.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = REFERENCE.exec(line)) !== null) {
      references.push({
        stepId: match[1] ?? "",
        key: match[2] ?? "",
        line: index + 1,
        snippet: line.trim(),
      });
    }
  }
  return references;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}
