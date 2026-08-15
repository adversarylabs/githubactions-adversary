import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

const workflowFiles = [".github/workflows/*.yml", ".github/workflows/*.yaml"] as const;

export const spec = {
  id: "github-actions",
  displayName: "GitHub Actions",
  description: "Reviews GitHub Actions workflows for security, supply-chain, and reliability defects.",
  files: [...workflowFiles],
  rules: [
    {
      id: "gha.action.unpinned-tag",
      title: "External action uses a mutable reference",
      summary: "External action uses a mutable tag or branch",
      category: "supply-chain",
      severity: "high",
      confidence: "high",
      whyItMatters: "Mutable tags and branch refs can be retargeted, swapping trusted action code for attacker-controlled code.",
      impact: "Compromised actions can steal secrets, modify code, or push malicious releases.",
      recommendation: "Pin third-party actions to full 40-character commit SHAs (optionally with a version comment).",
      complexity: "small",
      tags: ["supply-chain", "unpinned-action"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: {
          pattern: "uses:\\s*[\\w.-]+\\/[\\w./-]+@(?![0-9a-fA-F]{40}(?:\\s|$|#))[^\\s#]+",
          flags: "i",
        },
        requires: [],
      },
    },
    {
      id: "gha.permissions.write-all",
      title: "Workflow grants write-all token permissions",
      summary: "Workflow grants write-all GITHUB_TOKEN permissions",
      category: "permissions",
      severity: "high",
      confidence: "high",
      whyItMatters: "write-all grants every token scope, amplifying any script injection or compromised step.",
      impact: "Attackers who reach a step can push code, create releases, or modify repository settings.",
      recommendation: "Default to contents: read (or omit for defaults) and grant write only on narrowly scoped release jobs.",
      complexity: "small",
      tags: ["permissions", "write-all"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: { pattern: "permissions:\\s*write-all", flags: "i" },
        requires: [],
      },
    },
    {
      id: "gha.pull-request-target.pwn",
      title: "pull_request_target checks out untrusted pull request code",
      summary: "Trusted pull_request_target workflow checks out PR head",
      category: "security",
      severity: "critical",
      confidence: "high",
      whyItMatters: "pull_request_target runs with base-repo secrets and write tokens; checking out PR head enables pwn-request attacks.",
      impact: "Fork PRs can exfiltrate secrets or push malicious commits using privileged workflow context.",
      recommendation: "Never checkout PR head in pull_request_target; use pull_request for untrusted code, or only run trusted metadata operations.",
      complexity: "small",
      tags: ["security", "pwn-request"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: {
          pattern: "github\\.event\\.pull_request\\.head\\.(?:sha|ref)",
          flags: "i",
        },
        requires: [{ pattern: "pull_request_target", flags: "i" }],
      },
    },
    {
      id: "gha.script-injection.context",
      title: "Untrusted github.event context interpolated into run:",
      summary: "Untrusted event fields expanded inline in shell steps",
      category: "security",
      severity: "critical",
      confidence: "high",
      whyItMatters: "Issue titles, comment bodies, and head refs can contain shell metacharacters that break out of unquoted expansions.",
      impact: "Attackers can inject shell commands into privileged workflows and steal secrets.",
      recommendation: "Pass untrusted values through env: and quote \"$VAR\" in shell, or avoid shell entirely.",
      complexity: "small",
      tags: ["security", "script-injection"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: {
          // Inline expansion of high-risk untrusted contexts inside run steps.
          pattern:
            "run:\\s*(?:\\|[-+]?\\s*)?(?:[^\\n]*\\n)*?[^\\n]*\\$\\{\\{\\s*github\\.event\\.(?:issue|comment|discussion|pull_request|review|review_comment|head_commit)\\.[^}]+\\}\\}",
          flags: "i",
        },
        requires: [],
      },
    },
    {
      id: "gha.self-hosted.untrusted",
      title: "Self-hosted runner on pull_request",
      summary: "Self-hosted runner executes untrusted pull_request jobs",
      category: "security",
      severity: "critical",
      confidence: "high",
      whyItMatters: "Public PR jobs on self-hosted runners expose the host and any credentials available to that machine.",
      impact: "Attackers can persist on the runner, steal secrets, or pivot to the network.",
      recommendation: "Use GitHub-hosted runners for untrusted PR code, or isolate self-hosted runners with ephemeral VMs and no secrets.",
      complexity: "small",
      tags: ["security", "self-hosted"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: { pattern: "runs-on:\\s*(?:\\[\\s*)?self-hosted", flags: "i" },
        requires: [{ pattern: "pull_request(?:_target)?\\b", flags: "i" }],
      },
    },
    {
      id: "gha.permissions.contents-write-on-pr",
      title: "contents: write granted on pull_request",
      summary: "PR workflow has contents: write",
      category: "permissions",
      severity: "high",
      confidence: "high",
      whyItMatters: "Write access on PR workflows combines badly with script injection and compromised actions.",
      impact: "A single injected step can push to the repository.",
      recommendation: "Use contents: read on pull_request; confine writes to protected, non-fork jobs.",
      complexity: "small",
      tags: ["permissions", "pull_request"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: { pattern: "contents:\\s*write", flags: "i" },
        requires: [{ pattern: "pull_request(?:_target)?\\b", flags: "i" }],
      },
    },
    {
      id: "gha.custom-runner.missing-timeout",
      title: "Long-running custom-runner job has no timeout",
      summary: "Long-running custom-runner job can run for GitHub's six-hour default",
      category: "reliability",
      severity: "medium",
      confidence: "high",
      whyItMatters: "A stuck build, packaging, or release job can occupy a scarce custom runner for GitHub's six-hour default.",
      impact: "Hung work wastes runner capacity and can block queued release or integration work.",
      recommendation: "Set a job-level timeout-minutes value based on observed runtime plus reasonable headroom.",
      complexity: "trivial",
      tags: ["reliability", "timeout", "custom-runner"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: { pattern: "runs-on\\s*:", flags: "i" },
        requires: [],
      },
    },
    {
      id: "gha.runs-on.expression",
      title: "runs-on takes an untrusted expression",
      summary: "Runner label derived from an expression",
      category: "security",
      severity: "critical",
      confidence: "high",
      whyItMatters: "Attacker-controlled runner labels can route jobs onto compromised self-hosted runners.",
      impact: "Job may execute on attacker infrastructure with repository tokens and secrets.",
      recommendation: "Hard-code runner labels or map from a trusted allowlist, never raw event fields.",
      complexity: "small",
      tags: ["security", "runs-on"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: {
          pattern: "runs-on:\\s*\\$\\{\\{[^}]+\\}\\}",
          flags: "i",
        },
        requires: [],
      },
    },
    {
      id: "gha.step.stale-output-reference",
      title: "Workflow references a removed step output",
      summary: "A later step still reads a step output that this change removed or renamed",
      category: "reliability",
      severity: "high",
      confidence: "high",
      whyItMatters: "Downstream steps receive an empty value, so tagging, signing, or artifact archival can silently fail.",
      impact: "Releases may ship untagged images or skip required artifacts.",
      recommendation: "Update or delete every steps.<id>.outputs.<key> reference when removing or renaming that output.",
      complexity: "small",
      tags: ["reliability", "step-outputs"],
      match: {
        kind: "content",
        files: [...workflowFiles],
        pattern: { pattern: "steps\\.[\\w-]+\\.outputs\\.[\\w-]+", flags: "i" },
        requires: [],
      },
    },
  ],
} as const satisfies AdversarySpec;
