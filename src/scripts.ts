/**
 * Scripts: find which local file a command will execute, read it safely, and
 * pre-scan it for hard lines before any model sees it.
 */

import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

import type { HardDeferConfig } from "./config.ts";
import { checkSegment, type HardDeferHit, normalizeSegment, splitSegments } from "./hard-defer.ts";

export interface ScriptRef {
  /** Path as written in the command. */
  path: string;
  /** Interpreter, or "direct" for ./script. */
  interpreter: string;
}

const SCRIPT_EXT = "py|sh|bash|zsh|js|mjs|cjs|ts|mts|rb|pl|php";
const INTERPRETER =
  /^(python3?(?:\.\d+)?|bash|sh|zsh|node|deno\s+run|bun(?:\s+run)?|tsx|ts-node|ruby|perl|php|uv\s+run(?:\s+python3?)?|poetry\s+run\s+python3?)\s+/;
const INTERP_SCRIPT = new RegExp(`^(?:-{1,2}[\\w-]+(?:=\\S+)?\\s+)*([^\\s'"]+\\.(?:${SCRIPT_EXT}))(?=\\s|$)`);
const DIRECT_SCRIPT = /^(\.{1,2}\/[^\s'"]+|[\w.-]+\/[^\s'"]+\.(?:py|sh|bash|zsh|js|mjs|ts|rb|pl))(?=\s|$)/;

/** Find the first local script any segment of the command executes. */
export function detectScript(command: string): ScriptRef | null {
  for (const raw of splitSegments(command)) {
    const seg = normalizeSegment(raw);
    const interp = INTERPRETER.exec(seg);
    if (interp) {
      const m = INTERP_SCRIPT.exec(seg.slice(interp[0].length));
      if (m) return { path: m[1], interpreter: interp[1].replace(/\s+/g, " ") };
      continue;
    }
    const direct = DIRECT_SCRIPT.exec(seg);
    if (direct) return { path: direct[1], interpreter: "direct" };
  }
  return null;
}

export type ReadScriptResult =
  | { ok: true; path: string; content: string }
  | { ok: false; reason: "outside-cwd" | "not-found" | "too-large" | "not-a-file" | "binary" };

/** Read a script only if it resolves (after symlinks) inside cwd and is small text. */
export function readScriptSafely(ref: ScriptRef, cwd: string, maxBytes: number): ReadScriptResult {
  const abs = isAbsolute(ref.path) ? ref.path : resolve(cwd, ref.path);
  let real: string;
  let realCwd: string;
  try {
    real = realpathSync(abs);
    realCwd = realpathSync(cwd);
  } catch {
    return { ok: false, reason: "not-found" };
  }
  const rel = relative(realCwd, real);
  if (rel.startsWith("..") || isAbsolute(rel)) return { ok: false, reason: "outside-cwd" };
  const st = statSync(real);
  if (!st.isFile()) return { ok: false, reason: "not-a-file" };
  if (st.size > maxBytes) return { ok: false, reason: "too-large" };
  const content = readFileSync(real, "utf8");
  if (content.includes("\u0000")) return { ok: false, reason: "binary" };
  return { ok: true, path: rel, content };
}

/** Patterns that make a script's effects untraceable or dangerous, for any language. */
const SCRIPT_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  ["script-delete", /\b(shutil\.rmtree|os\.(remove|unlink|rmdir|removedirs)|\.unlink\(|\.rmdir\(|fs\.(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\b|fs\.promises\.(rm|unlink|rmdir)|FileUtils\.(rm|rm_r|rm_rf)|File\.delete|unlink\s*\()/],
  ["script-obfuscation", /\b(eval|exec)\s*\(|new\s+Function\s*\(|base64\.(b64decode|decodebytes)|\batob\s*\(|Buffer\.from\([^)]*['"]base64['"]|marshal\.loads|pickle\.loads|codecs\.decode/],
  ["script-network-write", /\b(requests|httpx|session)\.(post|put|patch|delete)\s*\(|method\s*[:=]\s*['"](POST|PUT|PATCH|DELETE)['"]|urllib\.request\.Request\([^)]*method=/i],
  ["script-kube-mutation", /\b(oc|kubectl)\b['",\s]{1,6}(?:[-\w=./'",\s]{0,60}?['",\s])?(apply|create|delete|patch|edit|replace|scale|rollout|set|label|annotate|taint|drain|cordon|exec|debug|rsh|cp|adm|login)\b/],
  ["script-ops-tooling", /\b(osdctl|backplane)\b|\bocm\b['",\s]{1,6}(post|patch|delete|create|edit|upgrade|backplane)\b/],
  ["script-cloud-mutation", /\baws\b['",\s]{1,6}\w[\w-]*['",\s]{1,6}(create|delete|put|update|modify|terminate|stop|start|reboot|run|attach|detach|associate|authorize|revoke|tag|untag|invoke|send|publish|copy|restore|import|cancel|reset|replace)-|\baz\b.{0,60}\s(create|delete|update|set|start|stop|restart|deallocate|deploy|purge)\b|get-secret-value|get-parameter/],
  ["script-shell-out", /\bshell\s*=\s*True\b|os\.system\s*\(|os\.popen\s*\(|child_process|execSync|spawnSync|\bsubprocess\.(call|run|Popen|check_call|check_output)\s*\(\s*f?['"]/],
  ["script-privilege", /\bsudo\b|\bsetuid\b|os\.set(e)?uid/],
];

/** Mutating SDK calls, only checked when the file imports a cloud or cluster SDK. */
const SDK_IMPORT = /\b(import|from|require\()\s*['"]?(boto3|botocore|kubernetes|openshift|azure\.|@azure\/|google\.cloud|@google-cloud\/|@kubernetes\/client-node|aws-sdk|@aws-sdk\/)/;
const SDK_MUTATION = /\b(create|delete|patch|replace|update|put|terminate|stop|start|modify|attach|detach|reboot|scale)_[a-z_]+\s*\(|\.(create|delete|patch|replace|update|terminate|stop|start|modify)[A-Z]\w*\s*\(|new\s+(Put|Delete|Create|Update|Terminate|Modify)\w*Command\s*\(/;

/** Statically scan script content. Shell scripts also get the per-line command rules. */
export function scanScript(
  ref: ScriptRef,
  content: string,
  extra: readonly RegExp[] = [],
  config?: HardDeferConfig,
): HardDeferHit | null {
  const isShell = /\.(sh|bash|zsh)$/.test(ref.path) || ["bash", "sh", "zsh"].includes(ref.interpreter);
  if (isShell) {
    for (const line of content.split(/\r?\n/)) {
      const code = line.replace(/(^|\s)#.*$/, "").trim();
      if (!code) continue;
      // In scripts, command substitutions $(...) and process substitutions are part of the
      // script text that the model inspects in full; only check static segment rules.
      for (const raw of splitSegments(code)) {
        const hit = checkSegment(normalizeSegment(raw), extra, config);
        if (hit) return { rule: `script:${hit.rule}`, segment: hit.segment };
      }
    }
  }
  for (const [rule, re] of SCRIPT_RULES) {
    if (config?.disabledRules?.includes(rule)) continue;
    const m = re.exec(content);
    if (m) return { rule, segment: lineAround(content, m.index) };
  }
  if (SDK_IMPORT.test(content)) {
    if (!config?.disabledRules?.includes("script-sdk-mutation") && config?.categories?.cloud !== false && config?.categories?.k8s !== false) {
      const m = SDK_MUTATION.exec(content);
      if (m) return { rule: "script-sdk-mutation", segment: lineAround(content, m.index) };
    }
  }
  return null;
}

function lineAround(content: string, index: number): string {
  const start = content.lastIndexOf("\n", index) + 1;
  const end = content.indexOf("\n", index);
  return content.slice(start, end === -1 ? undefined : end).trim().slice(0, 200);
}
