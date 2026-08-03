import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { type RuleContext } from "@adversarylabs/sdk";
import { detectCiSecurityIssues, GHA_RULE_IDS } from "./ci-security-core.js";
import { observationFor } from "./rules.js";
import { runModelGithubActionsReview } from "./model-review.js";
import { spec, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;

interface SourceFile { path: string; source: string }
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
  const sources: SourceFile[] = scoped.map((file) => ({ path: file.path, source: file.content }));
  ctx.summary.files_scanned = sources.length;

  const detections: Detection[] = [];
  for (const file of sources) {
    for (const hit of detectCiSecurityIssues(file.path, file.source)) {
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
