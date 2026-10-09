/**
 * Config: ~/.pi/agent/extensions/pi-command-judge/config.json
 * No file means the link is not registered (the operator declined it).
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

export interface HardDeferCategories {
  deletion?: boolean;
  gitRemote?: boolean;
  privilege?: boolean;
  substitutions?: boolean;
  indirection?: boolean;
  secrets?: boolean;
  k8s?: boolean;
  cloud?: boolean;
  network?: boolean;
  packages?: boolean;
  database?: boolean;
  system?: boolean;
}

export interface HardDeferConfig {
  enabled?: boolean;
  categories?: HardDeferCategories;
  disabledRules?: string[];
}

export interface CommandJudgeConfig {
  /** Pi model registry provider, e.g. "openai-compatible". */
  provider: string;
  /** Model id within that provider. */
  model: string;
  commandTimeoutMs: number;
  scriptTimeoutMs: number;
  /** Auto-allow only when P(allow) from logprobs is at least this. */
  minAllowProbability: number;
  /** When logprobs are unavailable: true → defer; false → trust the parsed verdict. */
  requireLogprobs: boolean;
  maxScriptBytes: number;
  maxTokensCommand: number;
  maxTokensScript: number;
  /** Merged into the request body (thinking off for Qwen3 by default). */
  extraBody: Record<string, unknown>;
  /** Extra hard-defer regexes, applied to each normalized command segment and shell-script line. */
  extraHardDefer: string[];
  /** Replace the default policy text (string or file path). */
  policy: string | null;
  /** Additional rules appended to the policy (string or file path). */
  extraPolicy: string | null;
  /** Custom user instructions injected into the prompt. */
  customPromptInstructions: string | null;
  /** Configurable hard-defer settings. */
  hardDefer: HardDeferConfig;
  /** Show a notification with the judge's reason when it defers a script or command. */
  notifyOnDefer: boolean;
  /** Log what it would allow, but always defer. */
  dryRun: boolean;
  /** Ask the server for schema-guided JSON (response_format). Off → plain JSON parsed defensively. */
  structuredOutput: boolean;
  /** Send throwaway calls at session start so the first real ask doesn't pay cold-start costs. */
  warmup: boolean;
  /** Call this URL instead of the one Pi resolves (e.g. to bypass a local proxy). Credentials still come from Pi. */
  baseUrl: string | null;
  /** Read the API key from this environment variable instead of Pi's credentials. */
  apiKeyEnv: string | null;
}

export const DEFAULT_CONFIG: CommandJudgeConfig = {
  provider: "openai-compatible",
  model: "Qwen/Qwen2.5-Coder-32B-Instruct",
  commandTimeoutMs: 4000,
  scriptTimeoutMs: 10000,
  minAllowProbability: 0.9,
  requireLogprobs: true,
  maxScriptBytes: 64 * 1024,
  maxTokensCommand: 150,
  maxTokensScript: 500,
  extraBody: { chat_template_kwargs: { enable_thinking: false } },
  extraHardDefer: [],
  policy: null,
  extraPolicy: null,
  customPromptInstructions: null,
  hardDefer: {
    enabled: true,
    categories: {},
    disabledRules: [],
  },
  notifyOnDefer: true,
  dryRun: true,
  structuredOutput: true,
  warmup: true,
  baseUrl: null,
  apiKeyEnv: null,
};

export interface LoadResult {
  config: CommandJudgeConfig | undefined;
  path: string;
  issues: string[];
}

export function configPath(agentDir: string): string {
  return join(agentDir, "extensions", "pi-command-judge", "config.json");
}

export function loadConfig(agentDir: string): LoadResult {
  const path = configPath(agentDir);
  if (!existsSync(path)) return { config: undefined, path, issues: [] };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    // A broken file disables the link (more prompts), never loosens anything.
    return { config: undefined, path, issues: [`unparseable JSON: ${(err as Error).message}`] };
  }
  return { ...parseConfig(raw), path };
}

export function parseConfig(raw: unknown): { config: CommandJudgeConfig | undefined; issues: string[] } {
  const issues: string[] = [];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { config: undefined, issues: ["config must be a JSON object"] };
  }
  const input = raw as Record<string, unknown>;
  const out: CommandJudgeConfig = { ...DEFAULT_CONFIG };

  const str = (k: "provider" | "model") => {
    if (input[k] === undefined) return;
    if (typeof input[k] === "string" && input[k]) out[k] = input[k] as string;
    else issues.push(`${k} must be a non-empty string`);
  };
  const num = (
    k:
      | "commandTimeoutMs"
      | "scriptTimeoutMs"
      | "minAllowProbability"
      | "maxScriptBytes"
      | "maxTokensCommand"
      | "maxTokensScript",
    min: number,
    max: number,
  ) => {
    if (input[k] === undefined) return;
    const v = input[k];
    if (typeof v === "number" && v >= min && v <= max) out[k] = v;
    else issues.push(`${k} must be a number in [${min}, ${max}]`);
  };
  const bool = (k: "requireLogprobs" | "notifyOnDefer" | "dryRun" | "structuredOutput" | "warmup") => {
    if (input[k] === undefined) return;
    if (typeof input[k] === "boolean") out[k] = input[k] as boolean;
    else issues.push(`${k} must be a boolean`);
  };

  str("provider");
  str("model");
  num("commandTimeoutMs", 500, 60000);
  num("scriptTimeoutMs", 500, 120000);
  num("minAllowProbability", 0.5, 1);
  num("maxScriptBytes", 1024, 1024 * 1024);
  num("maxTokensCommand", 20, 2000);
  num("maxTokensScript", 50, 4000);
  bool("requireLogprobs");
  bool("notifyOnDefer");
  bool("dryRun");
  bool("structuredOutput");
  bool("warmup");

  if (input.extraBody !== undefined) {
    if (typeof input.extraBody === "object" && input.extraBody !== null && !Array.isArray(input.extraBody)) {
      out.extraBody = input.extraBody as Record<string, unknown>;
    } else issues.push("extraBody must be an object");
  }
  if (input.extraHardDefer !== undefined) {
    if (Array.isArray(input.extraHardDefer) && input.extraHardDefer.every((p) => typeof p === "string")) {
      out.extraHardDefer = input.extraHardDefer as string[];
    } else issues.push("extraHardDefer must be an array of regex strings");
  }
  for (const k of ["baseUrl", "apiKeyEnv"] as const) {
    if (input[k] === undefined) continue;
    if (input[k] === null || (typeof input[k] === "string" && input[k])) out[k] = input[k] as string | null;
    else issues.push(`${k} must be a non-empty string or null`);
  }
  for (const k of ["policy", "extraPolicy", "customPromptInstructions"] as const) {
    if (input[k] !== undefined) {
      if (input[k] === null || typeof input[k] === "string") out[k] = input[k] as string | null;
      else issues.push(`${k} must be a string or null`);
    }
  }

  if (input.hardDefer !== undefined) {
    if (typeof input.hardDefer === "object" && input.hardDefer !== null && !Array.isArray(input.hardDefer)) {
      const hd = input.hardDefer as Record<string, unknown>;
      const conf: HardDeferConfig = { ...DEFAULT_CONFIG.hardDefer };
      if (hd.enabled !== undefined) {
        if (typeof hd.enabled === "boolean") conf.enabled = hd.enabled;
        else issues.push("hardDefer.enabled must be a boolean");
      }
      if (hd.disabledRules !== undefined) {
        if (Array.isArray(hd.disabledRules) && hd.disabledRules.every((r) => typeof r === "string")) {
          conf.disabledRules = hd.disabledRules as string[];
        } else issues.push("hardDefer.disabledRules must be an array of rule strings");
      }
      if (hd.categories !== undefined) {
        if (typeof hd.categories === "object" && hd.categories !== null && !Array.isArray(hd.categories)) {
          conf.categories = hd.categories as HardDeferCategories;
        } else issues.push("hardDefer.categories must be an object");
      }
      out.hardDefer = conf;
    } else issues.push("hardDefer must be an object");
  }

  return { config: out, issues };
}

/** Resolve string or file path into text content. */
export function resolveTextOrFile(textOrPath: string | null | undefined, baseDir = process.cwd()): string | null {
  if (!textOrPath) return null;
  const trimmed = textOrPath.trim();
  if (!trimmed.includes("\n") && (trimmed.endsWith(".md") || trimmed.endsWith(".txt") || trimmed.startsWith("./") || trimmed.startsWith("../") || trimmed.startsWith("/") || trimmed.startsWith("~/"))) {
    const expanded = trimmed.startsWith("~/") ? join(homedir(), trimmed.slice(2)) : trimmed;
    const abs = isAbsolute(expanded) ? expanded : resolve(baseDir, expanded);
    if (existsSync(abs)) {
      try {
        return readFileSync(abs, "utf8").trim();
      } catch {
        // Fall back to literal text
      }
    }
  }
  return trimmed;
}
