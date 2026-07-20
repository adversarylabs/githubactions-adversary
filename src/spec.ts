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

export const spec = {
  "id": "github-actions",
  "displayName": "GitHub Actions",
  "description": "Reviews GitHub Actions workflows for security, supply-chain, and reliability defects.",
  "files": [
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml"
  ],
  "rules": [
    {
      "id": "github-actions.unpinned-action",
      "title": "External action uses a mutable reference",
      "summary": "External action uses a mutable reference",
      "category": "supply-chain",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "External action uses a mutable reference weakens an important supply-chain boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Pin external actions to full commit SHAs.",
      "complexity": "small",
      "tags": [
        "supply-chain",
        "unpinned-action"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".github/workflows/*.yml",
          ".github/workflows/*.yaml"
        ],
        "pattern": {
          "pattern": "uses:\\s*[\\w.-]+\\/[\\w./-]+@(?![0-9a-f]{40}(?:\\s|$))[^\\s#]+",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "github-actions.write-all",
      "title": "Workflow grants write-all token permissions",
      "summary": "Workflow grants write-all token permissions",
      "category": "permissions",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Workflow grants write-all token permissions weakens an important permissions boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Default to read-only and elevate only narrowly scoped release jobs.",
      "complexity": "small",
      "tags": [
        "permissions",
        "write-all"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".github/workflows/*.yml",
          ".github/workflows/*.yaml"
        ],
        "pattern": {
          "pattern": "permissions:\\s*write-all",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "github-actions.pull-request-target-head",
      "title": "Trusted pull_request_target workflow executes pull-request code",
      "summary": "Trusted pull_request_target workflow executes pull-request code",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Trusted pull_request_target workflow executes pull-request code weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Never execute pull-request-controlled code in pull_request_target.",
      "complexity": "small",
      "tags": [
        "security",
        "pull-request-target-head"
      ],
      "match": {
        "kind": "content",
        "files": [
          ".github/workflows/*.yml",
          ".github/workflows/*.yaml"
        ],
        "pattern": {
          "pattern": "github\\.event\\.pull_request\\.head\\.sha",
          "flags": "i"
        },
        "requires": [
          {
            "pattern": "pull_request_target",
            "flags": "i"
          }
        ]
      }
    }
  ]
} as const satisfies AdversarySpec;
