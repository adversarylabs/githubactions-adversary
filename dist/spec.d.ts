import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "github-actions";
    readonly displayName: "GitHub Actions";
    readonly description: "Reviews GitHub Actions workflows for security, supply-chain, and reliability defects.";
    readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
    readonly rules: [{
        readonly id: "gha.action.unpinned-tag";
        readonly title: "External action uses a mutable reference";
        readonly summary: "External action uses a mutable tag or branch";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Mutable tags and branch refs can be retargeted, swapping trusted action code for attacker-controlled code.";
        readonly impact: "Compromised actions can steal secrets, modify code, or push malicious releases.";
        readonly recommendation: "Pin third-party actions to full 40-character commit SHAs (optionally with a version comment).";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "unpinned-action"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "uses:\\s*[\\w.-]+\\/[\\w./-]+@(?![0-9a-fA-F]{40}(?:\\s|$|#))[^\\s#]+";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gha.permissions.write-all";
        readonly title: "Workflow grants write-all token permissions";
        readonly summary: "Workflow grants write-all GITHUB_TOKEN permissions";
        readonly category: "permissions";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "write-all grants every token scope, amplifying any script injection or compromised step.";
        readonly impact: "Attackers who reach a step can push code, create releases, or modify repository settings.";
        readonly recommendation: "Default to contents: read (or omit for defaults) and grant write only on narrowly scoped release jobs.";
        readonly complexity: "small";
        readonly tags: ["permissions", "write-all"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "permissions:\\s*write-all";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gha.pull-request-target.pwn";
        readonly title: "pull_request_target checks out untrusted pull request code";
        readonly summary: "Trusted pull_request_target workflow checks out PR head";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "pull_request_target runs with base-repo secrets and write tokens; checking out PR head enables pwn-request attacks.";
        readonly impact: "Fork PRs can exfiltrate secrets or push malicious commits using privileged workflow context.";
        readonly recommendation: "Never checkout PR head in pull_request_target; use pull_request for untrusted code, or only run trusted metadata operations.";
        readonly complexity: "small";
        readonly tags: ["security", "pwn-request"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "github\\.event\\.pull_request\\.head\\.(?:sha|ref)";
                readonly flags: "i";
            };
            readonly requires: [{
                readonly pattern: "pull_request_target";
                readonly flags: "i";
            }];
        };
    }, {
        readonly id: "gha.script-injection.context";
        readonly title: "Untrusted github.event context interpolated into run:";
        readonly summary: "Untrusted event fields expanded inline in shell steps";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Issue titles, comment bodies, and head refs can contain shell metacharacters that break out of unquoted expansions.";
        readonly impact: "Attackers can inject shell commands into privileged workflows and steal secrets.";
        readonly recommendation: "Pass untrusted values through env: and quote \"$VAR\" in shell, or avoid shell entirely.";
        readonly complexity: "small";
        readonly tags: ["security", "script-injection"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "run:\\s*(?:\\|[-+]?\\s*)?(?:[^\\n]*\\n)*?[^\\n]*\\$\\{\\{\\s*github\\.event\\.(?:issue|comment|discussion|pull_request|review|review_comment|head_commit)\\.[^}]+\\}\\}";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "gha.self-hosted.untrusted";
        readonly title: "Self-hosted runner on pull_request";
        readonly summary: "Self-hosted runner executes untrusted pull_request jobs";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Public PR jobs on self-hosted runners expose the host and any credentials available to that machine.";
        readonly impact: "Attackers can persist on the runner, steal secrets, or pivot to the network.";
        readonly recommendation: "Use GitHub-hosted runners for untrusted PR code, or isolate self-hosted runners with ephemeral VMs and no secrets.";
        readonly complexity: "small";
        readonly tags: ["security", "self-hosted"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "runs-on:\\s*(?:\\[\\s*)?self-hosted";
                readonly flags: "i";
            };
            readonly requires: [{
                readonly pattern: "pull_request(?:_target)?\\b";
                readonly flags: "i";
            }];
        };
    }, {
        readonly id: "gha.permissions.contents-write-on-pr";
        readonly title: "contents: write granted on pull_request";
        readonly summary: "PR workflow has contents: write";
        readonly category: "permissions";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Write access on PR workflows combines badly with script injection and compromised actions.";
        readonly impact: "A single injected step can push to the repository.";
        readonly recommendation: "Use contents: read on pull_request; confine writes to protected, non-fork jobs.";
        readonly complexity: "small";
        readonly tags: ["permissions", "pull_request"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "contents:\\s*write";
                readonly flags: "i";
            };
            readonly requires: [{
                readonly pattern: "pull_request(?:_target)?\\b";
                readonly flags: "i";
            }];
        };
    }, {
        readonly id: "gha.runs-on.expression";
        readonly title: "runs-on takes an untrusted expression";
        readonly summary: "Runner label derived from an expression";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Attacker-controlled runner labels can route jobs onto compromised self-hosted runners.";
        readonly impact: "Job may execute on attacker infrastructure with repository tokens and secrets.";
        readonly recommendation: "Hard-code runner labels or map from a trusted allowlist, never raw event fields.";
        readonly complexity: "small";
        readonly tags: ["security", "runs-on"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "runs-on:\\s*\\$\\{\\{[^}]+\\}\\}";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
