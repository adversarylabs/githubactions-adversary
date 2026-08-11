const LONG_RUNNING_SIGNAL = /\b(?:aarch64|arm(?:v\d+)?|buildx|cross[-_ ]?(?:compile|compilation)|e2e|end[-_ ]?to[-_ ]?end|integration|multi[-_ ]?arch|package|packaging|publish|qemu|release)\b/i;
const GITHUB_HOSTED_RUNNER = /^(?:ubuntu|windows|macos)-[a-z0-9_.-]+$/i;
/**
 * Detect long-running build/release jobs which can occupy a scarce custom
 * runner for GitHub's default six-hour limit because they omit a job timeout.
 */
export function detectMissingLongRunningJobTimeouts(file, source) {
    const lines = source.split(/\r?\n/);
    const hits = [];
    for (const job of collectJobs(lines)) {
        const runner = readRunner(job.lines);
        if (runner === undefined || !isCustomRunner(runner.labels, runner.expression))
            continue;
        if (hasJobTimeout(job.lines))
            continue;
        const searchable = [job.id, ...job.lines.filter((line) => !/^\s*runs-on\s*:/.test(line.trimStart()))].join("\n");
        if (!LONG_RUNNING_SIGNAL.test(searchable))
            continue;
        hits.push({
            file,
            line: job.line,
            snippet: `${job.id}:`,
            label: `Long-running job ${job.id} has no timeout on custom runner ${runner.display}`,
            data: { job: job.id, runner: runner.display },
        });
    }
    return hits;
}
function collectJobs(lines) {
    const jobs = [];
    let inJobs = false;
    let current;
    const flush = () => {
        if (current !== undefined)
            jobs.push(current);
        current = undefined;
    };
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        if (!inJobs) {
            if (/^jobs:\s*(?:#.*)?$/.test(line))
                inJobs = true;
            continue;
        }
        if (/^[A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(line)) {
            flush();
            break;
        }
        const header = /^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$/.exec(line);
        if (header !== null) {
            flush();
            current = { id: header[1] ?? "", line: index + 1, lines: [] };
            continue;
        }
        if (current !== undefined)
            current.lines.push(line);
    }
    flush();
    return jobs;
}
function hasJobTimeout(lines) {
    return lines.some((line) => /^    timeout-minutes\s*:\s*\S+/.test(line));
}
function readRunner(lines) {
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        const match = /^    runs-on\s*:\s*(.*?)\s*(?:#.*)?$/.exec(line);
        if (match === null)
            continue;
        const value = (match[1] ?? "").trim();
        if (value.includes("${{"))
            return { labels: [], display: value, expression: true };
        if (value.startsWith("[") && value.endsWith("]")) {
            const labels = value.slice(1, -1).split(",").map(cleanLabel).filter(Boolean);
            return { labels, display: `[${labels.join(", ")}]`, expression: false };
        }
        if (value !== "") {
            const label = cleanLabel(value);
            return { labels: label === "" ? [] : [label], display: label, expression: false };
        }
        const labels = [];
        for (let next = index + 1; next < lines.length; next += 1) {
            const item = /^      -\s*(.*?)\s*(?:#.*)?$/.exec(lines[next] ?? "");
            if (item === null)
                break;
            const label = cleanLabel(item[1] ?? "");
            if (label !== "")
                labels.push(label);
        }
        return { labels, display: `[${labels.join(", ")}]`, expression: false };
    }
    return undefined;
}
function cleanLabel(value) {
    return value.trim().replace(/^['"]|['"]$/g, "");
}
function isCustomRunner(labels, expression) {
    if (expression || labels.length === 0)
        return false;
    if (labels.some((label) => label.toLowerCase() === "self-hosted"))
        return true;
    if (labels.length > 1)
        return true;
    return !GITHUB_HOSTED_RUNNER.test(labels[0] ?? "");
}
