import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import { detectCiSecurityIssues, GHA_RULE_IDS } from "./ci-security-core.js";
import { detectMissingLongRunningJobTimeouts } from "./job-timeouts.js";
import { detectStaleStepOutputs } from "./stale-step-outputs.js";
import { observationFor } from "./rules.js";
import { runModelGithubActionsReview } from "./model-review.js";
import { spec, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  previousSource?: string;
  changedLines: Set<number>;
  status: "added" | "modified" | "repository";
}
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }

const byId = new Map<string, RuleSpec>(spec.rules.map((rule) => [rule.id, rule]));

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  const sources: SourceFile[] = [];
  for (const file of scoped) {
    if (wholeTarget || file.status === "repository") {
      sources.push({
        path: file.path,
        source: file.content,
        changedLines: new Set<number>(),
        status: "repository",
      });
      continue;
    }

    const change = await changedSource(ctx, file.path);
    sources.push({
      path: file.path,
      source: file.content,
      previousSource: change.previousSource,
      changedLines: change.changedLines,
      status: change.status,
    });
  }
  ctx.summary.files_scanned = sources.length;

  const detections: Detection[] = [];
  for (const file of sources) {
    for (const hit of detectCiSecurityIssues(file.path, file.source)) {
      if (!isEligibleLine(file, hit.line)) continue;
      const ruleId = GHA_RULE_IDS[hit.key];
      if (!ruleId) continue;
      const rule = byId.get(ruleId);
      if (!rule) continue;
      detections.push({
        rule,
        file: hit.file,
        line: hit.line,
        snippet: hit.snippet,
        label: hit.label,
        data: hit.data,
      });
    }
    const timeoutRule = byId.get("gha.custom-runner.missing-timeout");
    if (timeoutRule !== undefined) {
      for (const hit of detectMissingLongRunningJobTimeouts(file.path, file.source)) {
        if (!isEligibleLine(file, hit.line)) continue;
        detections.push({ rule: timeoutRule, ...hit });
      }
    }
    const staleOutputRule = byId.get("gha.step.stale-output-reference");
    if (staleOutputRule !== undefined && file.status === "modified") {
      for (const hit of detectStaleStepOutputs(file.path, file.source, file.previousSource)) {
        detections.push({ rule: staleOutputRule, ...hit });
      }
    }
  }

  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }

  const staticSeverities = detections.map((d) => String(d.rule.severity));
  const staticPrimaryConcern = detections[0]?.rule.title.toLowerCase();
  await runModelGithubActionsReview(
    ctx,
    detections.map((d) => ({
      ruleId: d.rule.id,
      file: d.file,
      line: d.line,
      snippet: d.snippet,
      message: d.label,
      severity: String(d.rule.severity),
    })),
    sources.map((s) => ({ path: s.path, content: s.source })),
    staticSeverities,
    staticPrimaryConcern,
  );
}

function isEligibleLine(file: SourceFile, line: number): boolean {
  return file.status === "repository" || file.status === "added" || file.changedLines.has(line);
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceFile, "changedLines" | "status" | "previousSource">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  let previousSource: string | undefined;
  try {
    previousSource = await gitOutput(ctx.repoPath, ["show", `${base}:${path}`]);
  } catch {
    previousSource = undefined;
  }
  return { changedLines: changedLineNumbers(patch), status: "modified", previousSource };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
