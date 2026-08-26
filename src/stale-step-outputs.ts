import { isMap, isScalar, isSeq, parseAllDocuments } from "yaml";

export interface StaleStepOutputHit {
  file: string;
  line: number;
  snippet: string;
  label: string;
  data: Record<string, unknown>;
}

interface StepIdentity {
  line: number;
  index: number;
}

interface StepReference {
  stepId: string;
  outputKey: string;
  line: number;
  snippet: string;
  scope: "job-output" | "step";
  stepIndex?: number;
  consumerKey: string;
}

interface JobContract {
  stepIds: Map<string, StepIdentity>;
  references: StepReference[];
  valid: boolean;
  executable: boolean;
}

const STEP_OUTPUT_REFERENCE = /\bsteps\s*\.\s*([A-Za-z_][\w-]*)\s*\.\s*outputs\s*\.\s*([A-Za-z_][\w-]*)/g;
const STEP_RUNTIME_FIELDS = [
  "continue-on-error",
  "env",
  "if",
  "run",
  "shell",
  "timeout-minutes",
  "with",
  "working-directory",
] as const;

/**
 * Changed-relationship detector: a step identity that existed in a job was
 * removed or renamed while that same current job still refers to one of its
 * outputs. Output keys are intentionally opaque: actions and scripts may
 * define them outside the workflow or dynamically through GITHUB_OUTPUT.
 */
export function detectStaleStepOutputs(
  file: string,
  current: string,
  previous: string | undefined,
): StaleStepOutputHit[] {
  if (previous === undefined) return [];
  const previousJobs = collectJobs(previous);
  const currentJobs = collectJobs(current);
  const hits: StaleStepOutputHit[] = [];
  const seen = new Set<string>();

  for (const [jobId, currentJob] of currentJobs) {
    const previousJob = previousJobs.get(jobId);
    if (previousJob === undefined || !previousJob.valid || !currentJob.valid ||
      !previousJob.executable || !currentJob.executable) continue;
    const removedStepIds = new Set(
      [...previousJob.stepIds.keys()].filter((stepId) => !currentJob.stepIds.has(stepId)),
    );
    if (removedStepIds.size === 0) continue;

    for (const reference of currentJob.references) {
      if (!removedStepIds.has(reference.stepId)) continue;
      const previousProducer = previousJob.stepIds.get(reference.stepId);
      if (previousProducer === undefined || !previousJob.references.some((candidate) =>
        candidate.stepId === reference.stepId && candidate.outputKey === reference.outputKey &&
        candidate.consumerKey === reference.consumerKey &&
        (candidate.scope === "job-output" ||
          (candidate.scope === "step" && candidate.stepIndex !== undefined &&
            candidate.stepIndex > previousProducer.index))
      )) continue;
      const key = `${jobId}:${reference.line}:${reference.stepId}:${reference.outputKey}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({
        file,
        line: reference.line,
        snippet: reference.snippet,
        label: `Job ${jobId} still references steps.${reference.stepId}.outputs.${reference.outputKey} after step ${reference.stepId} was removed or renamed`,
        data: {
          jobId,
          stepId: reference.stepId,
          outputKey: reference.outputKey,
          relationshipChange: "same-job-step-id-removed-or-renamed",
          previousStepLine: previousProducer.line,
        },
      });
    }
  }
  return hits;
}

function collectJobs(source: string): Map<string, JobContract> {
  const jobs = new Map<string, JobContract>();
  let documents;
  try {
    documents = parseAllDocuments(source, { prettyErrors: false, uniqueKeys: true });
  } catch {
    return jobs;
  }
  if (documents.length !== 1 || documents[0]?.errors.length !== 0) return jobs;
  const root = documents[0]?.contents;
  if (!isMap(root)) return jobs;
  const jobsNode = mapValue(root, "jobs");
  if (!isMap(jobsNode)) return jobs;

  for (const pair of jobsNode.items) {
    const jobId = scalarString(pair.key);
    const jobNode = pair.value;
    if (jobId === undefined || !isMap(jobNode)) continue;
    const contract: JobContract = {
      stepIds: new Map(),
      references: [],
      valid: true,
      executable: !conditionContainerIsStaticallyDisabled(jobNode),
    };
    const outputsNode = mapValue(jobNode, "outputs");
    if (isMap(outputsNode)) {
      for (const output of outputsNode.items) {
        const outputName = scalarString(output.key);
        if (outputName === undefined) continue;
        contract.references.push(...collectReferences(output.value, source).map((reference, ordinal) => ({
          ...reference,
          scope: "job-output" as const,
          consumerKey: `job-output:${outputName}:${ordinal}`,
        })));
      }
    }
    const environmentNode = mapValue(jobNode, "environment");
    if (isMap(environmentNode)) {
      const environmentUrl = mapValue(environmentNode, "url");
      if (environmentUrl !== undefined) {
        contract.references.push(...collectReferences(environmentUrl, source).map((reference, ordinal) => ({
          ...reference,
          scope: "job-output" as const,
          consumerKey: `environment-url:${ordinal}`,
        })));
      }
    }
    const stepsNode = mapValue(jobNode, "steps");
    if (isSeq(stepsNode)) {
      const stepMaps = stepsNode.items.filter(isMap);
      const semanticKeys = stepMaps.map((step) => semanticNodeKey(step));
      const semanticCounts = new Map<string, number>();
      for (const key of semanticKeys) semanticCounts.set(key, (semanticCounts.get(key) ?? 0) + 1);

      // Duplicate IDs make the workflow invalid even when one duplicate is
      // statically disabled; GitHub validates identities before execution.
      const allIds = new Set<string>();
      for (const rawStep of stepMaps) {
        const id = scalarString(mapValue(rawStep, "id"));
        if (id === undefined || id.length === 0) continue;
        if (allIds.has(id)) contract.valid = false;
        allIds.add(id);
      }

      for (const [index, rawStep] of stepsNode.items.entries()) {
        if (!isMap(rawStep)) continue;
        if (conditionContainerIsStaticallyDisabled(rawStep)) continue;
        const idNode = mapValue(rawStep, "id");
        const id = scalarString(idNode);
        const semanticKey = semanticNodeKey(rawStep);
        const stepConsumerKey = id !== undefined && id.length > 0
          ? `id:${id}`
          : semanticCounts.get(semanticKey) === 1 ? `semantic:${semanticKey}` : undefined;
        for (const field of STEP_RUNTIME_FIELDS) {
          const fieldNode = mapValue(rawStep, field);
          if (fieldNode === undefined || stepConsumerKey === undefined) continue;
          contract.references.push(...collectReferences(fieldNode, source, field === "if").map((reference, ordinal) => ({
            ...reference,
            scope: "step" as const,
            stepIndex: index,
            consumerKey: `step:${stepConsumerKey}:${field}:${ordinal}`,
          })));
        }
        if (id === undefined || id.length === 0) continue;
        contract.stepIds.set(id, { line: nodeLine(idNode, source), index });
      }
    }
    jobs.set(jobId, contract);
  }
  return jobs;
}

function collectReferences(
  node: unknown,
  source: string,
  implicitExpression = false,
): Array<Omit<StepReference, "scope" | "stepIndex" | "consumerKey">> {
  const references: Array<Omit<StepReference, "scope" | "stepIndex" | "consumerKey">> = [];
  const lines = source.split(/\r?\n/);
  function visit(value: unknown): void {
    if (isMap(value)) {
      for (const pair of value.items) visit(pair.value);
      return;
    }
    if (isSeq(value)) {
      for (const item of value.items) visit(item);
      return;
    }
    if (!isScalar(value) || value.range === undefined || value.range === null) return;
    const raw = source.slice(value.range[0], value.range[1]);
    const explicitRanges = bracedExpressionRanges(raw);
    const ranges = explicitRanges.length > 0
      ? explicitRanges
      : implicitExpression ? [implicitScalarExpressionRange(raw)] : [];
    for (const range of ranges) {
      if (range.end <= range.start) continue;
      const body = maskExpressionStrings(raw.slice(range.start, range.end));
      STEP_OUTPUT_REFERENCE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = STEP_OUTPUT_REFERENCE.exec(body.text)) !== null) {
        if (!expressionOffsetIsReachable(body.text, match.index ?? 0, body.stringValues)) continue;
        const offset = value.range[0] + range.start + (match.index ?? 0);
        const line = offsetLine(source, offset);
        references.push({
          stepId: match[1] ?? "",
          outputKey: match[2] ?? "",
          line,
          snippet: lines[line - 1]?.trim() ?? "",
        });
      }
    }
  }
  visit(node);
  return references;
}

function bracedExpressionRanges(raw: string): ExpressionRange[] {
  const ranges: ExpressionRange[] = [];
  let cursor = 0;
  while (cursor < raw.length - 2) {
    const opening = raw.indexOf("${{", cursor);
    if (opening < 0) break;
    const start = opening + 3;
    let quote: "'" | '"' | undefined;
    let closing = -1;
    for (let index = start; index < raw.length - 1; index += 1) {
      const character = raw[index];
      if (quote !== undefined) {
        if (quote === "'" && character === "'" && raw[index + 1] === "'") {
          index += 1;
          continue;
        }
        if (character !== quote) continue;
        if (quote === '"') {
          let backslashes = 0;
          for (let escaped = index - 1; escaped >= start && raw[escaped] === "\\"; escaped -= 1) {
            backslashes += 1;
          }
          if (backslashes % 2 === 1) continue;
        }
        quote = undefined;
        continue;
      }
      if (character === "'" || character === '"') {
        quote = character;
        continue;
      }
      if (character === "}" && raw[index + 1] === "}") {
        closing = index;
        break;
      }
    }
    if (closing < 0) break;
    ranges.push({ start, end: closing });
    cursor = closing + 2;
  }
  return ranges;
}

function implicitScalarExpressionRange(raw: string): ExpressionRange {
  const range = trimRange(raw, 0, raw.length);
  const first = raw[range.start];
  if ((first === "'" || first === '"') && raw[range.end - 1] === first) {
    return trimRange(raw, range.start + 1, range.end - 1);
  }
  return range;
}

function conditionContainerIsStaticallyDisabled(
  container: { items: Array<{ key: unknown; value: unknown }> },
): boolean {
  const condition = mapValue(container, "if");
  if (!isScalar(condition)) return false;
  if (condition.value === false || condition.value === null || Object.is(condition.value, 0) || Object.is(condition.value, -0)) {
    return true;
  }
  if (typeof condition.value !== "string") return false;
  const raw = condition.value.trim();
  if (raw.length === 0) return true;
  const expression = /^\$\{\{([\s\S]*)\}\}$/.exec(raw)?.[1] ?? raw;
  const masked = maskExpressionStrings(expression);
  return evaluateBoolean(masked.text, masked.stringValues) === false;
}

function expressionOffsetIsReachable(
  expression: string,
  offset: number,
  stringValues: ReadonlyMap<string, string>,
): boolean {
  const range = trimRange(expression, 0, expression.length);
  if (offset < range.start || offset >= range.end) return false;
  return offsetReachableInRange(expression, offset, range.start, range.end, stringValues);
}

function offsetReachableInRange(
  expression: string,
  offset: number,
  start: number,
  end: number,
  stringValues: ReadonlyMap<string, string>,
): boolean {
  const range = unwrapParenthesizedRange(expression, trimRange(expression, start, end));
  const orParts = splitLogical(expression, range.start, range.end, "||");
  if (orParts.length > 1) {
    const target = orParts.findIndex((part) => offset >= part.start && offset < part.end);
    if (target < 0) return false;
    for (let index = 0; index < target; index += 1) {
      if (evaluateBoolean(expression.slice(orParts[index]!.start, orParts[index]!.end), stringValues) === true) return false;
    }
    const part = orParts[target]!;
    return offsetReachableInRange(expression, offset, part.start, part.end, stringValues);
  }
  const andParts = splitLogical(expression, range.start, range.end, "&&");
  if (andParts.length > 1) {
    const target = andParts.findIndex((part) => offset >= part.start && offset < part.end);
    if (target < 0) return false;
    for (let index = 0; index < target; index += 1) {
      if (evaluateBoolean(expression.slice(andParts[index]!.start, andParts[index]!.end), stringValues) === false) return false;
    }
    const part = andParts[target]!;
    return offsetReachableInRange(expression, offset, part.start, part.end, stringValues);
  }

  const nested = innermostParenthesizedRange(expression, offset, range.start, range.end);
  return nested === undefined ||
    offsetReachableInRange(expression, offset, nested.start + 1, nested.end - 1, stringValues);
}

function evaluateBoolean(expression: string, stringValues: ReadonlyMap<string, string>): boolean | undefined {
  const range = unwrapParenthesizedRange(expression, trimRange(expression, 0, expression.length));
  const orParts = splitLogical(expression, range.start, range.end, "||");
  if (orParts.length > 1) {
    const values = orParts.map((part) => evaluateBoolean(expression.slice(part.start, part.end), stringValues));
    if (values.some((value) => value === true)) return true;
    return values.every((value) => value === false) ? false : undefined;
  }
  const andParts = splitLogical(expression, range.start, range.end, "&&");
  if (andParts.length > 1) {
    const values = andParts.map((part) => evaluateBoolean(expression.slice(part.start, part.end), stringValues));
    if (values.some((value) => value === false)) return false;
    return values.every((value) => value === true) ? true : undefined;
  }
  const text = expression.slice(range.start, range.end).trim();
  const comparison = splitComparison(text);
  if (comparison !== undefined) {
    const left = evaluateConstant(comparison.left, stringValues);
    const right = evaluateConstant(comparison.right, stringValues);
    if (left === undefined || right === undefined) return undefined;
    const equal = constantsEqual(left, right);
    if (equal === undefined) return undefined;
    return comparison.operator === "==" ? equal : !equal;
  }
  if (text.startsWith("!")) {
    const value = evaluateBoolean(text.slice(1), stringValues);
    return value === undefined ? undefined : !value;
  }
  const constant = parseConstant(text, stringValues);
  if (constant?.kind === "boolean") return constant.value as boolean;
  if (constant?.kind === "null") return false;
  if (constant?.kind === "number") return !Object.is(constant.value, 0) && !Object.is(constant.value, -0);
  if (constant?.kind === "string") return constant.value.length > 0;
  return undefined;
}

function evaluateConstant(expression: string, stringValues: ReadonlyMap<string, string>): Constant | undefined {
  const range = unwrapParenthesizedRange(expression, trimRange(expression, 0, expression.length));
  const text = expression.slice(range.start, range.end).trim();
  if (text.startsWith("!")) {
    const value = evaluateBoolean(text.slice(1), stringValues);
    return value === undefined ? undefined : { kind: "boolean", value: !value };
  }
  return parseConstant(text, stringValues);
}

type Constant =
  | { kind: "boolean"; value: boolean }
  | { kind: "null"; value: null }
  | { kind: "number"; value: number }
  | { kind: "string"; value: string };

function constantsEqual(left: Constant, right: Constant): boolean | undefined {
  if (left.kind === right.kind) return left.value === right.value;
  const leftNumber = coerceConstantNumber(left);
  const rightNumber = coerceConstantNumber(right);
  return leftNumber === undefined || rightNumber === undefined ? undefined : leftNumber === rightNumber;
}

function coerceConstantNumber(value: Constant): number | undefined {
  switch (value.kind) {
    case "null": return 0;
    case "boolean": return value.value ? 1 : 0;
    case "number": return Number.isFinite(value.value) ? value.value : undefined;
    case "string": {
      if (value.value.length === 0) return 0;
      try {
        const parsed: unknown = JSON.parse(value.value);
        return typeof parsed === "number" && Number.isFinite(parsed) ? parsed : undefined;
      } catch {
        return undefined;
      }
    }
  }
}

function parseConstant(text: string, stringValues: ReadonlyMap<string, string>): Constant | undefined {
  const value = text.trim();
  if (/^true$/i.test(value)) return { kind: "boolean", value: true };
  if (/^false$/i.test(value)) return { kind: "boolean", value: false };
  if (/^null$/i.test(value)) return { kind: "null", value: null };
  if (value.length === 1 && value.charCodeAt(0) >= 0xE000 && value.charCodeAt(0) <= 0xF8FF) {
    const stringValue = stringValues.get(value);
    return stringValue === undefined ? undefined : { kind: "string", value: stringValue };
  }
  if (/^-?0[xX][0-9a-fA-F]+$/.test(value)) {
    const negative = value.startsWith("-");
    const parsed = Number.parseInt(negative ? value.slice(3) : value.slice(2), 16);
    return { kind: "number", value: negative ? -parsed : parsed };
  }
  if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(value)) {
    return { kind: "number", value: Number(value) };
  }
  return undefined;
}

function splitComparison(
  expression: string,
): { left: string; operator: "==" | "!="; right: string } | undefined {
  let depth = 0;
  for (let index = 0; index < expression.length - 1; index += 1) {
    if (expression[index] === "(") depth += 1;
    else if (expression[index] === ")") depth = Math.max(0, depth - 1);
    else if (depth === 0) {
      const operator = expression.slice(index, index + 2);
      if (operator === "==" || operator === "!=") {
        const left = expression.slice(0, index).trim();
        const right = expression.slice(index + 2).trim();
        if (left.length === 0 || right.length === 0 || splitComparison(right) !== undefined) return undefined;
        return { left, operator, right };
      }
    }
  }
  return undefined;
}

interface ExpressionRange { start: number; end: number }

function splitLogical(
  expression: string,
  start: number,
  end: number,
  operator: "&&" | "||",
): ExpressionRange[] {
  const parts: ExpressionRange[] = [];
  let depth = 0;
  let partStart = start;
  for (let index = start; index < end - 1; index += 1) {
    const character = expression[index];
    if (character === "(") depth += 1;
    else if (character === ")") depth = Math.max(0, depth - 1);
    else if (depth === 0 && expression.slice(index, index + 2) === operator) {
      parts.push(trimRange(expression, partStart, index));
      partStart = index + 2;
      index += 1;
    }
  }
  if (parts.length === 0) return [{ start, end }];
  parts.push(trimRange(expression, partStart, end));
  return parts;
}

function unwrapParenthesizedRange(expression: string, initial: ExpressionRange): ExpressionRange {
  let range = initial;
  while (expression[range.start] === "(" && matchingParenthesis(expression, range.start) === range.end - 1) {
    range = trimRange(expression, range.start + 1, range.end - 1);
  }
  return range;
}

function innermostParenthesizedRange(
  expression: string,
  offset: number,
  start: number,
  end: number,
): ExpressionRange | undefined {
  const stack: number[] = [];
  let best: ExpressionRange | undefined;
  for (let index = start; index < end; index += 1) {
    if (expression[index] === "(") stack.push(index);
    else if (expression[index] === ")") {
      const open = stack.pop();
      if (open !== undefined && offset > open && offset < index) best = { start: open, end: index + 1 };
    }
  }
  return best;
}

function matchingParenthesis(expression: string, open: number): number | undefined {
  let depth = 0;
  for (let index = open; index < expression.length; index += 1) {
    if (expression[index] === "(") depth += 1;
    else if (expression[index] === ")" && --depth === 0) return index;
  }
  return undefined;
}

function trimRange(expression: string, start: number, end: number): ExpressionRange {
  while (start < end && /\s/.test(expression[start] ?? "")) start += 1;
  while (end > start && /\s/.test(expression[end - 1] ?? "")) end -= 1;
  return { start, end };
}

function maskExpressionStrings(
  expression: string,
): { text: string; stringValues: ReadonlyMap<string, string> } {
  // Split into UTF-16 code units so masked-expression offsets remain aligned
  // with RegExp indices and YAML source ranges even when an expression contains emoji.
  const characters = expression.split("");
  const stringTokens = new Map<string, string>([["", "\uE000"]]);
  const stringValues = new Map<string, string>([["\uE000", ""]]);
  let quote: "'" | '"' | undefined;
  let quoteStart = -1;
  let stringValue = "";
  for (let index = 0; index < characters.length; index += 1) {
    const character = characters[index];
    if (quote === undefined) {
      if (character === "'" || character === '"') {
        quote = character;
        quoteStart = index;
        stringValue = "";
        characters[index] = " ";
      }
      continue;
    }
    characters[index] = " ";
    if (character !== quote) {
      stringValue += character;
      continue;
    }
    if (quote === "'" && characters[index + 1] === "'") {
      stringValue += "'";
      characters[index + 1] = " ";
      index += 1;
      continue;
    }
    let backslashes = 0;
    for (let cursor = index - 1; cursor >= 0 && expression[cursor] === "\\"; cursor -= 1) backslashes += 1;
    if (quote === '"' && backslashes % 2 === 1) {
      stringValue += '"';
      continue;
    }
    const normalized = stringValue.toLocaleLowerCase("en-US");
    let token = stringTokens.get(normalized);
    if (token === undefined && stringTokens.size < 0x1900) {
      token = String.fromCharCode(0xE000 + stringTokens.size);
      stringTokens.set(normalized, token);
      stringValues.set(token, normalized);
    }
    characters[quoteStart] = token ?? " ";
    quote = undefined;
    quoteStart = -1;
    stringValue = "";
    continue;
  }
  if (quoteStart >= 0) characters[quoteStart] = " ";
  return { text: characters.join(""), stringValues };
}

function semanticNodeKey(node: unknown): string {
  return JSON.stringify(semanticNodeValue(node));
}

function semanticNodeValue(node: unknown): unknown {
  if (isScalar(node)) return ["scalar", typeof node.value, node.value];
  if (isSeq(node)) return ["sequence", node.items.map(semanticNodeValue)];
  if (isMap(node)) {
    const entries = node.items.map((pair) => [
      semanticNodeKey(pair.key),
      semanticNodeValue(pair.value),
    ] as const);
    entries.sort(([left], [right]) => left.localeCompare(right));
    return ["mapping", entries];
  }
  return ["unsupported"];
}

function mapValue(map: { items: Array<{ key: unknown; value: unknown }> }, key: string): unknown {
  return map.items.find((pair) => scalarString(pair.key) === key)?.value;
}

function scalarString(node: unknown): string | undefined {
  return isScalar(node) && typeof node.value === "string" ? node.value : undefined;
}

function nodeLine(node: unknown, source: string): number {
  return isScalar(node) && node.range !== undefined && node.range !== null
    ? offsetLine(source, node.range[0])
    : 1;
}

function offsetLine(source: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset; index += 1) {
    if (source.charCodeAt(index) === 10) line += 1;
  }
  return line;
}
