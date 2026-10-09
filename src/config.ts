/**
 * Config: ~/.pi/agent/extensions/pi-command-judge/config.json
 * No file means the link is not registered (the operator declined it).
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

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
  /** Replace the default policy text. */
  policy: string | null;
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
  if (input.policy !== undefined) {
    if (input.policy === null || typeof input.policy === "string") out.policy = input.policy as string | null;
    else issues.push("policy must be a string or null");
  }
  return { config: out, issues };
}
