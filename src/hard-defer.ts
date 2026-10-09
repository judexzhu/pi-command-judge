/**
 * Deterministic hard lines. Anything matched here is never sent to the model
 * and never auto-allowed: the ask always reaches you.
 *
 * Conservative by design. A false positive only costs one prompt; a false
 * negative could let a model approve a customer-environment mutation.
 */

export interface HardDeferHit {
  /** Rule name, for the audit log. */
  rule: string;
  /** The normalized command segment (or script line) that matched. */
  segment: string;
}

/** Whole-command constructs that hide what will actually run. */
const STRUCTURAL: ReadonlyArray<readonly [string, RegExp]> = [
  ["command-substitution", /\$\(|`/],
  ["process-substitution", /[<>]\(/],
  ["heredoc", /<<-?\s*['"]?\w/],
];

/** Per-segment rules, matched against a normalized segment. */
const SEGMENT_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  // Deletes and destructive local git
  ["delete", /^(rm|rmdir|unlink|shred|srm|trash|trash-put)\b/],
  ["find-delete-or-exec", /^find\b.*\s-(delete|exec|execdir|ok|okdir)\b/],
  [
    "git-destructive",
    /^git\b(.*\s)?['"]?(push|clean|rm|filter-branch|filter-repo|update-ref|reset\s+--hard|checkout\s+--(\s|$)|restore\b|reflog\s+expire|gc\s+--prune|branch\s+-D|stash\s+(drop|clear))/,
  ],

  // Privilege and indirection
  ["privilege", /^(sudo|doas|su|pkexec)\b/],
  ["shell-wrapper", /^(bash|sh|zsh|dash|ksh|fish)\s+-\w*c\b/],
  ["eval-or-source", /^(eval|source|\.)\s/],
  ["xargs", /^xargs\b/],
  ["parallel-runner", /^(parallel|watch)\b/],

  // OpenShift / Kubernetes mutations (verb may follow global flags)
  [
    "kube-mutation",
    /^(oc|kubectl)\b(.*\s)?['"]?(apply|create|delete|patch|edit|replace|scale|autoscale|rollout|set|label|annotate|taint|drain|cordon|uncordon|exec|debug|rsh|rsync|cp|attach|port-forward|run|expose|adm(?!\s+top\b)|process|new-app|new-project|new-build|start-build|cancel-build|import-image|tag|login|logout)\b/,
  ],
  [
    "kube-context-switch",
    /^(oc|kubectl)\s+config\s+(use-context|set|set-context|set-cluster|set-credentials|delete-\w+|rename-context)\b/,
  ],
  ["kube-secrets", /^(oc|kubectl)\b.*\b(secrets?|secret\/\S+|create\s+token|serviceaccounts?\s+get-token)\b/],
  ["kube-secrets", /^oc\s+(extract|whoami\s+(-t|--show-token))\b/],

  // Red Hat managed-service tooling
  [
    "ocm-mutation",
    /^ocm\s+(post|patch|delete|create|edit|upgrade|hibernate|resume|backplane|login|logout|account\s+(roles|users)\s+(add|remove))\b/,
  ],
  ["ops-tooling", /^(osdctl|backplane|ocm-backplane)\b/],
  [
    "rosa-mutation",
    /^rosa\s+(create|delete|edit|upgrade|grant|revoke|register|deregister|attach|detach|link|unlink|install|uninstall|init|login|logout|hibernate|resume)\b/,
  ],

  // Cloud CLIs (aws is handled separately below)
  [
    "az-mutation",
    /^az\b.*\s(create|delete|update|set|add|remove|start|stop|restart|deallocate|scale|upgrade|invoke|run-command|deploy|purge|import|reset|rotate|assign|login|logout|get-access-token)\b/,
  ],
  ["az-secrets", /^az\s+keyvault\s+(secret|key|certificate)\b/],
  [
    "gcloud-mutation",
    /^gcloud\b.*\s(create|delete|update|set|add-\S+|remove-\S+|start|stop|reset|deploy|ssh|scp|print-access-token|login|activate-service-account)\b/,
  ],

  // Remote forges
  [
    "gh-mutation",
    /^gh\b.*\s(create|delete|merge|close|reopen|edit|comment|review|release|api|secret|ssh-key|auth|lock|unlock|transfer|archive|rerun|cancel)\b/,
  ],
  ["gh-workflow-run", /^gh\s+workflow\s+run\b/],

  // Network and remote shells
  ["network", /^(curl|wget|http|https|ssh|scp|sftp|rsync|nc|ncat|netcat|socat|telnet|ftp|mosh)\b/],

  // Infra-as-code and deploy tools
  ["helm-mutation", /^helm\s+(install|upgrade|uninstall|delete|rollback|push|repo\s+add|plugin\s+install)\b/],
  [
    "terraform-mutation",
    /^(terraform|tofu)\s+(apply|destroy|import|state|taint|untaint|force-unlock|workspace\s+delete)\b/,
  ],
  ["deploy-tools", /^(ansible|ansible-playbook|pulumi|cdk|serverless|sls|argocd|flux|tkn)\b/],

  // Package installs (run third-party code)
  ["package-install", /^(npm|pnpm|yarn|bun)\s+(install|i|add|publish|exec|dlx|x|update|upgrade|remove|rm|uninstall)\b/],
  ["package-install", /^(npx|pnpx|bunx|pipx)\b/],
  [
    "package-install",
    /^(pip3?|uv\s+pip|gem|brew|apt|apt-get|dnf|yum|zypper|apk)\s+(install|add|upgrade|remove|uninstall|reinstall)\b/,
  ],
  ["package-install", /^(cargo|go)\s+install\b/],

  // System and container changes
  [
    "system",
    /^(systemctl|launchctl|kill|killall|pkill|reboot|shutdown|halt|crontab|mount|umount|dd|mkfs\S*|fdisk|parted|iptables|nft|ufw|chown|chgrp)\b/,
  ],
  ["system", /^chmod\s+(-\S*R|--recursive)\b/],
  [
    "container-mutation",
    /^(docker|podman)\s+(rm|rmi|push|login|logout|system\s+prune|image\s+prune|volume\s+(rm|prune)|network\s+(rm|prune)|run\s+.*--privileged|exec)\b/,
  ],
];

const AWS_SAFE_ACTION = /^(describe-|list-|get-)/;
const AWS_SENSITIVE_ACTION =
  /^(get-secret-value|get-parameters?|get-parameters-by-path|get-session-token|get-federation-token|get-login-password|get-authorization-token|get-password-data|get-access-key-info)$/;
const AWS_SAFE_REST = /^(s3\s+ls\b|sts\s+get-caller-identity\b|configure\s+list(-profiles)?\b)/;

/** Wrappers that change how a command runs but not what it is. Stripped repeatedly. */
const TRANSPARENT_PREFIX =
  /^(time|nohup|nice(\s+-n\s*-?\d+)?|ionice(\s+-\S+)*|stdbuf(\s+-\S+)*|command|builtin|exec|timeout(\s+-\S+)*\s+\S+|env(\s+-\S+)*)\s+/;
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S*)\s+/;

/**
 * Split a command line into segments at unquoted control operators:
 * ;, &&, ||, |, &, \n, (, ), {, }
 * Operators inside single ('...') or double ("...") quotes are preserved inside the argument.
 */
export function splitSegments(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let escape = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];

    if (escape) {
      current += ch;
      escape = false;
      continue;
    }

    if (ch === "\\" && !inSingle) {
      escape = true;
      current += ch;
      continue;
    }

    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
      continue;
    }

    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
      continue;
    }

    if (!inSingle && !inDouble) {
      // Check two-character delimiters: && or ||
      if ((ch === "&" && command[i + 1] === "&") || (ch === "|" && command[i + 1] === "|")) {
        const trimmed = current.trim();
        if (trimmed) segments.push(trimmed);
        current = "";
        i++; // skip next char
        continue;
      }

      // Check single-character delimiters: ;, |, &, \n, (, ), {, }
      if (ch === ";" || ch === "|" || ch === "&" || ch === "\n" || ch === "\r" || ch === "(" || ch === ")" || ch === "{" || ch === "}") {
        const trimmed = current.trim();
        if (trimmed) segments.push(trimmed);
        current = "";
        continue;
      }
    }

    current += ch;
  }

  const finalTrimmed = current.trim();
  if (finalTrimmed) segments.push(finalTrimmed);
  return segments;
}

/** Strip env assignments and transparent wrappers; drop a leading absolute path from the program name. */
export function normalizeSegment(segment: string): string {
  let s = segment.trim();
  for (let i = 0; i < 10; i++) {
    const before = s;
    s = s.replace(ENV_ASSIGNMENT, "").replace(TRANSPARENT_PREFIX, "").trim();
    if (s === before) break;
  }
  // \rm, "rm", 'rm' → rm (alias bypass and quoted program names)
  s = s.replace(/^\\/, "").replace(/^(['"])([^'"\s]+)\1/, "$2");
  // /usr/local/bin/oc → oc
  return s.replace(/^\/(?:[\w.-]+\/)+([\w.-]+)(?=\s|$)/, "$1");
}

function awsRule(segment: string): string | null {
  if (!/^aws\b/.test(segment)) return null;
  const rest = segment
    .replace(/^aws\s*/, "")
    .replace(
      /--(profile|region|output|endpoint-url|query|color|cli-read-timeout|cli-connect-timeout)(=\S+|\s+\S+)/g,
      "",
    )
    .replace(/--(no-paginate|no-cli-pager|debug|no-verify-ssl)\b/g, "")
    .trim();
  if (AWS_SAFE_REST.test(rest)) return null;
  const action = rest.split(/\s+/)[1];
  if (!action) return "aws-unknown";
  if (AWS_SENSITIVE_ACTION.test(action)) return "aws-secrets";
  if (AWS_SAFE_ACTION.test(action)) return null;
  return "aws-mutation";
}

/** Check one already-normalized segment. */
export function checkSegment(segment: string, extra: readonly RegExp[] = []): HardDeferHit | null {
  // Commit messages and search terms are text, not verbs: "git commit -m 'push fix'" is not a push.
  const subject = /^git\b/.test(segment)
    ? segment.replace(/\s(-m|--message|--grep|-S|-G|--author|-F)(=|\s+)('[^']*'|"[^"]*"|\S+)/g, " ")
    : segment;
  for (const [rule, re] of SEGMENT_RULES) {
    if (re.test(subject)) return { rule, segment };
  }
  const aws = awsRule(segment);
  if (aws) return { rule: aws, segment };
  for (const re of extra) {
    if (re.test(segment)) return { rule: `extra:${re.source}`, segment };
  }
  return null;
}

/**
 * Return the first hard line the command crosses, or null.
 * `extra` are operator-supplied regexes applied to each normalized segment.
 */
export function findHardDefer(command: string, extra: readonly RegExp[] = []): HardDeferHit | null {
  for (const [rule, re] of STRUCTURAL) {
    if (re.test(command)) return { rule, segment: command.trim() };
  }
  for (const raw of splitSegments(command)) {
    const hit = checkSegment(normalizeSegment(raw), extra);
    if (hit) return hit;
  }
  return null;
}

/** Compile operator regex strings, reporting the ones that fail. */
export function compileExtra(patterns: readonly string[]): { compiled: RegExp[]; invalid: string[] } {
  const compiled: RegExp[] = [];
  const invalid: string[] = [];
  for (const p of patterns) {
    try {
      compiled.push(new RegExp(p));
    } catch {
      invalid.push(p);
    }
  }
  return { compiled, invalid };
}
