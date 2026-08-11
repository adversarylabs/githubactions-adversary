export interface JobTimeoutHit {
    file: string;
    line: number;
    snippet: string;
    label: string;
    data: Record<string, unknown>;
}
/**
 * Detect long-running build/release jobs which can occupy a scarce custom
 * runner for GitHub's default six-hour limit because they omit a job timeout.
 */
export declare function detectMissingLongRunningJobTimeouts(file: string, source: string): JobTimeoutHit[];
