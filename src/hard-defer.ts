/**
 * Deterministic hard lines. Anything matched here is never sent to the model
 * and never auto-allowed: the ask always reaches you.
 *
 * Conservative by design. A false positive only costs one prompt; a false
 * negative could let a model approve a customer-environment mutation.
 */

import type { HardDeferConfig } from "./config.ts";

export interface HardDeferHit {
  /** Rule name, for the audit log. */
  rule: string;
  /** The normalized command segment (or script line) that matched. */
  segment: string;
}

export type HardDeferCategory =
  | "deletion"
  | "gitRemote"
  | "privilege"
  | "substitutions"
  | "indirection"
  | "secrets"
  | "k8s"
  | "cloud"
  | "network"
  | "packages"
  | "database"
  | "system";

/** Whole-command constructs that hide what will actually run or cause local DoS. */
const STRUCTURAL: ReadonlyArray<readonly [string, RegExp, HardDeferCategory]> = [
  ["command-substitution", /\$\(|`/, "substitutions"],
  ["process-substitution", /[<>]\(/, "substitutions"],
  ["heredoc", /<<-?\s*['"]?\w/, "substitutions"],
  ["fork-bomb", /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "system"],
];

/** Per-segment rules, matched against a normalized segment. */
const SEGMENT_RULES: ReadonlyArray<readonly [string, RegExp, HardDeferCategory]> = [
  // Deletes and destructive local git
  ["delete", /^(rm|rmdir|unlink|shred|srm|trash|trash-put)\b/, "deletion"],
  ["find-delete-or-exec", /^find\b.*\s-(delete|exec|execdir|ok|okdir)\b/, "deletion"],
  [
    "git-destructive",
    /^git\b(.*\s)?['"]?(push|clean|rm|filter-branch|filter-repo|update-ref|reset\s+--hard|checkout\s+--(\s|$)|restore\b|reflog\s+expire|gc\s+--prune|branch\s+-D|stash\s+(drop|clear))/,
    "gitRemote",
  ],

  // Privilege and indirection
  ["privilege", /^(sudo|doas|su|pkexec)\b/, "privilege"],
  ["shell-wrapper", /^(bash|sh|zsh|dash|ksh|fish)\s+-\w*c\b/, "indirection"],
  ["eval-or-source", /^(eval|source|\.)\s/, "indirection"],
  ["xargs", /^xargs\b/, "indirection"],
  ["parallel-runner", /^(parallel|watch)\b/, "indirection"],

  // OpenShift / Kubernetes mutations (verb may follow global flags)
  [
    "kube-mutation",
    /^(oc|kubectl)\b(.*\s)?['"]?(apply|create|delete|patch|edit|replace|scale|autoscale|rollout|set|label|annotate|taint|drain|cordon|uncordon|exec|debug|rsh|rsync|cp|attach|port-forward|run|expose|adm(?!\s+top\b)|process|new-app|new-project|new-build|start-build|cancel-build|import-image|tag|login|logout)\b/,
    "k8s",
  ],
  [
    "kube-context-switch",
    /^(oc|kubectl)\s+config\s+(use-context|set|set-context|set-cluster|set-credentials|delete-\w+|rename-context)\b/,
    "k8s",
  ],
  ["kube-secrets", /^(oc|kubectl)\b.*\b(secrets?|secret\/\S+|create\s+token|serviceaccounts?\s+get-token)\b/, "secrets"],
  ["kube-secrets", /^oc\s+(extract|whoami\s+(-t|--show-token))\b/, "secrets"],

  // Red Hat managed-service tooling
  [
    "ocm-mutation",
    /^ocm\s+(post|patch|delete|create|edit|upgrade|hibernate|resume|backplane|login|logout|account\s+(roles|users)\s+(add|remove))\b/,
    "cloud",
  ],
  ["ops-tooling", /^(osdctl|backplane|ocm-backplane)\b/, "cloud"],
  [
    "rosa-mutation",
    /^rosa\s+(create|delete|edit|upgrade|grant|revoke|register|deregister|attach|detach|link|unlink|install|uninstall|init|login|logout|hibernate|resume)\b/,
    "cloud",
  ],

  // Cloud CLIs (aws is handled separately below)
  [
    "az-mutation",
    /^az\b.*\s(create|delete|update|set|add|remove|start|stop|restart|deallocate|scale|upgrade|invoke|run-command|deploy|purge|import|reset|rotate|assign|login|logout|get-access-token)\b/,
    "cloud",
  ],
  ["az-secrets", /^az\s+keyvault\s+(secret|key|certificate)\b/, "secrets"],
  [
    "gcloud-mutation",
    /^gcloud\b.*\s(create|delete|update|set|add-\S+|remove-\S+|start|stop|reset|deploy|ssh|scp|print-access-token|login|activate-service-account)\b/,
    "cloud",
  ],

  // Remote forges
  [
    "gh-mutation",
    /^gh\b.*\s(create|delete|merge|close|reopen|edit|comment|review|release|api|secret|ssh-key|auth|lock|unlock|transfer|archive|rerun|cancel)\b/,
    "gitRemote",
  ],
  ["gh-workflow-run", /^gh\s+workflow\s+run\b/, "gitRemote"],

  // Network and remote shells
  ["network", /^(curl|wget|http|https|ssh|scp|sftp|rsync|nc|ncat|netcat|socat|telnet|ftp|mosh)\b/, "network"],

  // Infra-as-code and deploy tools
  ["helm-mutation", /^helm\s+(install|upgrade|uninstall|delete|rollback|push|repo\s+add|plugin\s+install)\b/, "k8s"],
  [
    "terraform-mutation",
    /^(terraform|tofu)\s+(apply|destroy|import|state|taint|untaint|force-unlock|workspace\s+delete)\b/,
    "cloud",
  ],
  ["deploy-tools", /^(ansible|ansible-playbook|pulumi|cdk|serverless|sls|argocd|flux|tkn)\b/, "cloud"],

  // Package installs (run third-party code)
  ["package-install", /^(npm|pnpm|yarn|bun)\s+(install|i|add|publish|exec|dlx|x|update|upgrade|remove|rm|uninstall)\b/, "packages"],
  ["package-install", /^(npx|pnpx|bunx|pipx)\b/, "packages"],
  [
    "package-install",
    /^(pip3?|uv\s+pip|gem|brew|apt|apt-get|dnf|yum|zypper|apk)\s+(install|add|upgrade|remove|uninstall|reinstall)\b/,
    "packages",
  ],
  ["package-install", /^(cargo|go)\s+install\b/, "packages"],

  // System, disk, device, and container changes
  [
    "system",
    /^(systemctl|launchctl|kill|killall|pkill|reboot|shutdown|halt|crontab|mount|umount|dd|mkfs\S*|fdisk|sfdisk|parted|wipefs|iptables|nft|ufw|chown|chgrp)\b/,
    "system",
  ],
  ["raw-device-write", /(^|\s)(dd\s+.*of=\/dev\/|>+\s*\/dev\/(sd[a-z]|nvme\w+|hd[a-z]|disk\w+|null\b))/, "system"],
  ["system", /^chmod\s+(-\S*R|--recursive)\b/, "system"],
  ["system-permissions", /^chmod\s+([0-7]*777|a\+[rwx]+)\s+\//, "system"],
  [
    "container-mutation",
    /^(docker|podman)\s+(rm|rmi|push|login|logout|system\s+prune|image\s+prune|volume\s+(rm|prune)|network\s+(rm|prune)|run\s+.*--privileged|exec)\b/,
    "system",
  ],
  ["container-escape", /-(v|volume)\s+.*\/var\/run\/docker\.sock\b/, "system"],

  // Database mutations & drops (Postgres, MySQL, Mongo, Redis, SQLite)
  [
    "database-mutation",
    /^(psql|mysql|mariadb|mongosh|mongo|sqlite3|redis-cli)\b.*\b(drop\s+(database|schema|table|collection)|truncate\s+table|delete\s+from|flushall|flushdb)\b/i,
    "database",
  ],

  // Direct credential / secret dumps
  [
    "credential-exposure",
    /^(cat|less|more|head|tail|grep|rg|view|nano|vim|vi)\b.*(\.ssh\/(id_\w+|authorized_keys)|\.aws\/(credentials|config)|\.gnupg|\.env(\.\w+)?\b|\.netrc)/i,
    "secrets",
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

function isRuleActive(rule: string, cat: HardDeferCategory, config?: HardDeferConfig): boolean {
  if (!config) return true;
  if (config.enabled === false) return false;
  if (config.disabledRules && config.disabledRules.includes(rule)) return false;
  if (config.categories && config.categories[cat] === false) return false;
  return true;
}

/** Check one already-normalized segment. */
export function checkSegment(
  segment: string,
  extra: readonly RegExp[] = [],
  config?: HardDeferConfig,
): HardDeferHit | null {
  // Commit messages and search terms are text, not verbs: "git commit -m 'push fix'" is not a push.
  const subject = /^git\b/.test(segment)
    ? segment.replace(/\s(-m|--message|--grep|-S|-G|--author|-F)(=|\s+)('[^']*'|"[^"]*"|\S+)/g, " ")
    : segment;
  for (const [rule, re, cat] of SEGMENT_RULES) {
    if (isRuleActive(rule, cat, config) && re.test(subject)) return { rule, segment };
  }
  const aws = awsRule(segment);
  if (aws) {
    const cat = aws === "aws-secrets" ? "secrets" : "cloud";
    if (isRuleActive(aws, cat, config)) return { rule: aws, segment };
  }
  for (const re of extra) {
    if (re.test(segment)) return { rule: `extra:${re.source}`, segment };
  }
  return null;
}

/**
 * Return the first hard line the command crosses, or null.
 * `extra` are operator-supplied regexes applied to each normalized segment.
 */
export function findHardDefer(
  command: string,
  extra: readonly RegExp[] = [],
  config?: HardDeferConfig,
): HardDeferHit | null {
  if (config?.enabled === false) {
    for (const raw of splitSegments(command)) {
      const seg = normalizeSegment(raw);
      for (const re of extra) {
        if (re.test(seg)) return { rule: `extra:${re.source}`, segment: seg };
      }
    }
    return null;
  }
  for (const [rule, re, cat] of STRUCTURAL) {
    if (isRuleActive(rule, cat, config) && re.test(command)) {
      return { rule, segment: command.trim() };
    }
  }
  for (const raw of splitSegments(command)) {
    const hit = checkSegment(normalizeSegment(raw), extra, config);
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
