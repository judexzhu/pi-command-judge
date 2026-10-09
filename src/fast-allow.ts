/**
 * Tier 0 Fast-Allow: Deterministic in-memory auto-allow for safe, read-only
 * commands and inspection tools. Bypasses the model and network roundtrip (<1ms).
 *
 * If any segment in a pipeline/chain is NOT explicitly known-safe, returns false.
 */

import { normalizeSegment, splitSegments } from "./hard-defer.ts";

/** Safe read-only executables with standard flags that inspect local workspace without mutation. */
const SAFE_READ_ONLY_PREFIXES: RegExp[] = [
  // Local filesystem and file reading
  /^(ls|pwd|whoami|id|uname|date|uptime|env|printenv|which|whereis|type)\b/,
  /^(cat|head|tail|less|more|wc|nl|stat|file)\b/,
  /^(grep|egrep|fgrep|rg|ag|ack)\b/,
  /^(jq|yq|cut|sort|uniq|tr|column|fold|fmt|tee)\b/,
  /^(echo|printf)\b/,

  // Git inspection and safe local tracking
  /^git\s+(status|diff|log|show|branch|rev-parse|describe|remote|config\s+--get|check-ignore|ls-files)\b/,

  // Package manager / compiler inspection and test runners
  /^(pnpm|npm|yarn|bun)\s+(test|run\s+(test|check|lint|typecheck)|list|why)\b/,
  /^(pytest|python3?\s+-m\s+(pytest|unittest))\b/,
  /^(go\s+test|cargo\s+check|cargo\s+test|tsc\s+--noEmit)\b/,

  // Read-only OpenShift / Kubernetes inspection
  /^(oc|kubectl)\s+(get|describe|logs|explain|top|events|version|api-resources|api-versions)\b/,

  // Read-only Red Hat / cloud inspection
  /^ocm\s+(get|describe|list)\b/,
  /^rosa\s+(describe|list)\b/,
  /^aws\s+(ec2|s3|iam|sts|lambda|cloudwatch)\s+(describe-|list-|get-caller-identity)\b/,
  /^az\s+[\w-]+\s+(show|list)\b/,
];

/** Check if an individual segment is definitely a safe read-only query. */
export function isSafeSegment(segment: string): boolean {
  const norm = normalizeSegment(segment);
  // Redirections that write files (> or >>) prevent fast-allow
  if (/[>|]/.test(segment) && /(?:^|[^12])>>?/.test(segment)) {
    return false;
  }
  return SAFE_READ_ONLY_PREFIXES.some((re) => re.test(norm));
}

/**
 * Returns true only if EVERY segment of the command is verified safe read-only,
 * and no segment contains file writing redirects or forbidden constructs.
 */
export function isFastAllowable(command: string): boolean {
  const segments = splitSegments(command);
  if (segments.length === 0) return false;
  return segments.every(isSafeSegment);
}
