/**
 * The decision pipeline, free of Pi so tests and evals run it directly.
 *
 *   1. hard-defer rules on the command          → defer, no model call
 *   2. script detection → safe read → pre-scan  → defer on any problem
 *   3. model verdict + logprob confidence       → allow only if all gates pass
 *   4. any error, timeout or doubt              → defer
 *
 * The pipeline never denies: the worst case is the normal prompt.
 */

import type { CommandJudgeConfig } from "./config.ts";
import { isFastAllowable } from "./fast-allow.ts";
import { findHardDefer } from "./hard-defer.ts";
import type { Effects, JudgeFn } from "./judge-client.ts";
import { DEFAULT_POLICY, renderUserPrompt, verdictSchema } from "./prompt.ts";
import { detectScript, type ReadScriptResult, type ScriptRef, scanScript } from "./scripts.ts";

export interface DecideInput {
  command: string;
  cwd: string;
}

export interface DecideDeps {
  config: CommandJudgeConfig;
  extraHardDefer: readonly RegExp[];
  judge: JudgeFn;
  readScript: (ref: ScriptRef, cwd: string, maxBytes: number) => ReadScriptResult;
}

export type Stage = "hard-defer" | "fast-allow" | "script" | "model";

export interface Decision {
  verdict: "allow" | "defer";
  stage: Stage;
  /** Short machine-readable reason. */
  reason: string;
  /** Human-readable detail for the log and the notification. */
  detail?: string;
  script?: string;
  effects?: Effects;
  pAllow?: number | null;
  modelDecision?: "allow" | "defer";
  latencyMs?: number;
  /** In dry run: what the judge would have done. */
  wouldAllow?: boolean;
}

export async function decide(input: DecideInput, deps: DecideDeps): Promise<Decision> {
  const { config } = deps;

  const hard = findHardDefer(input.command, deps.extraHardDefer);
  if (hard) {
    return { verdict: "defer", stage: "hard-defer", reason: `hard:${hard.rule}`, detail: hard.segment };
  }

  // Tier 0: Fast deterministic allow for clean, read-only inspection commands
  if (isFastAllowable(input.command)) {
    if (config.dryRun) {
      return { verdict: "defer", stage: "fast-allow", reason: "dry-run", detail: "fast-allowable", wouldAllow: true };
    }
    return { verdict: "allow", stage: "fast-allow", reason: "fast-allow", detail: "deterministic-safe" };
  }

  let script: { path: string; content: string } | undefined;
  const ref = detectScript(input.command);
  if (ref) {
    const read = deps.readScript(ref, input.cwd, config.maxScriptBytes);
    if (!read.ok) {
      return { verdict: "defer", stage: "script", reason: `script-unreadable:${read.reason}`, detail: ref.path };
    }
    const hit = scanScript(ref, read.content, deps.extraHardDefer);
    if (hit) {
      return {
        verdict: "defer",
        stage: "script",
        reason: `hard:${hit.rule}`,
        detail: hit.segment,
        script: read.path,
      };
    }
    script = { path: read.path, content: read.content };
  }

  const result = await deps.judge({
    system: config.policy ?? DEFAULT_POLICY,
    user: renderUserPrompt({ cwd: input.cwd, command: input.command, script }),
    schema: verdictSchema(script !== undefined),
    maxTokens: script ? config.maxTokensScript : config.maxTokensCommand,
    timeoutMs: script ? config.scriptTimeoutMs : config.commandTimeoutMs,
  });

  if (!result.ok) {
    return {
      verdict: "defer",
      stage: "model",
      reason: `model-${result.error}`,
      detail: result.detail,
      script: script?.path,
      latencyMs: result.latencyMs,
    };
  }

  const base = {
    stage: "model" as const,
    detail: result.reason,
    script: script?.path,
    effects: result.effects,
    pAllow: result.pAllow,
    modelDecision: result.decision,
    latencyMs: result.latencyMs,
  };

  if (result.decision !== "allow") return { ...base, verdict: "defer", reason: "model-defer" };

  if (script && !result.effects) return { ...base, verdict: "defer", reason: "missing-effects" };
  if (result.effects && effectsNeedHuman(result.effects)) {
    return { ...base, verdict: "defer", reason: "effects-need-human" };
  }

  if (result.pAllow === null) {
    if (config.requireLogprobs) return { ...base, verdict: "defer", reason: "no-logprobs" };
  } else if (result.pAllow < config.minAllowProbability) {
    return { ...base, verdict: "defer", reason: "low-confidence" };
  }

  if (config.dryRun) return { ...base, verdict: "defer", reason: "dry-run", wouldAllow: true };
  return { ...base, verdict: "allow", reason: "model-allow" };
}

/** Cross-check: a model "allow" contradicted by its own effects summary is not an allow. */
export function effectsNeedHuman(e: Effects): boolean {
  return e.deletes.length > 0 || e.network.length > 0 || e.runs_other_code || e.cluster_or_cloud.some(isMutation);
}

function isMutation(s: string): boolean {
  return /\b(apply|create|delete|patch|edit|replace|scale|rollout|restart|update|modify|terminate|write|put|post|remove|drain|cordon|label|annotate|exec)\b/i.test(
    s,
  );
}

/** One-paragraph summary for the notification shown next to the prompt. */
export function summarize(d: Decision): string {
  const lines = [`command-judge deferred (${d.reason})${d.script ? ` — ${d.script}` : ""}`];
  if (d.detail) lines.push(d.detail);
  if (d.effects) {
    const e = d.effects;
    const fmt = (label: string, xs: string[]) => (xs.length ? `${label}: ${xs.join(", ")}` : null);
    for (const line of [
      fmt("reads", e.reads),
      fmt("writes", e.writes),
      fmt("deletes", e.deletes),
      fmt("network", e.network),
      fmt("cluster/cloud", e.cluster_or_cloud),
      e.runs_other_code ? "runs other code" : null,
    ]) {
      if (line) lines.push(line);
    }
  }
  return lines.join("\n");
}
