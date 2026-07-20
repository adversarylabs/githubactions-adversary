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
        readonly id: "github-actions.unpinned-action";
        readonly title: "External action uses a mutable reference";
        readonly summary: "External action uses a mutable reference";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "External action uses a mutable reference weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pin external actions to full commit SHAs.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "unpinned-action"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "uses:\\s*[\\w.-]+\\/[\\w./-]+@(?![0-9a-f]{40}(?:\\s|$))[^\\s#]+";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "github-actions.write-all";
        readonly title: "Workflow grants write-all token permissions";
        readonly summary: "Workflow grants write-all token permissions";
        readonly category: "permissions";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Workflow grants write-all token permissions weakens an important permissions boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Default to read-only and elevate only narrowly scoped release jobs.";
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
        readonly id: "github-actions.pull-request-target-head";
        readonly title: "Trusted pull_request_target workflow executes pull-request code";
        readonly summary: "Trusted pull_request_target workflow executes pull-request code";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Trusted pull_request_target workflow executes pull-request code weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Never execute pull-request-controlled code in pull_request_target.";
        readonly complexity: "small";
        readonly tags: ["security", "pull-request-target-head"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".github/workflows/*.yml", ".github/workflows/*.yaml"];
            readonly pattern: {
                readonly pattern: "github\\.event\\.pull_request\\.head\\.sha";
                readonly flags: "i";
            };
            readonly requires: [{
                readonly pattern: "pull_request_target";
                readonly flags: "i";
            }];
        };
    }];
};
export {};
