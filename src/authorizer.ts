/**
 * Live-authority link for pi-permission-system: adjudicates bash commands and
 * scripts from both direct parent session asks and forwarded subagent asks.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import type {
  Authorizer,
  AuthorizerLog,
  AuthorizerVerdict,
  PermissionQuery,
  PromptPermissionDetails,
} from "@gotgenes/pi-permission-system";

import { type CommandJudgeConfig } from "./config.ts";
import { decide, summarize } from "./decide.ts";
import type { JudgeFn } from "./judge-client.ts";
import { readScriptSafely, type ReadScriptResult, type ScriptRef } from "./scripts.ts";

export const LINK_NAME = "command-judge";
export const DECISION_EVENT = "command_judge.decision";

export interface Notifier {
  notify(message: string, type?: "info" | "warning" | "error"): void;
}

export interface AuthorizerDeps {
  config?: CommandJudgeConfig;
  extraHardDefer?: readonly RegExp[];
  cwd?: string | (() => string | undefined);
  agentDir?: string;
  judge?: JudgeFn;
  resolveJudge?: (config: CommandJudgeConfig) => Promise<{ judge: JudgeFn; endpointHost?: string } | { error: string }>;
  endpointHost?: string | (() => string | undefined);
  ui?: Notifier;
  readScript?: (ref: ScriptRef, cwd: string, maxBytes: number) => ReadScriptResult;
}

export interface Provenance {
  agentName: string | null;
  requesterSessionId: string | null;
}

export function extractProvenance(details: PromptPermissionDetails): Provenance {
  return {
    agentName: details.agentName ?? details.forwarding?.requesterAgentName ?? null,
    requesterSessionId: details.forwarding?.requesterSessionId ?? null,
  };
}

export function resolveRequesterCwd(
  details: PromptPermissionDetails,
  fallbackCwd: string,
  agentDir?: string,
): string {
  const explicit =
    (details.accessIntent as { requesterCwd?: string } | undefined)?.requesterCwd ??
    (details as { requesterCwd?: string })?.requesterCwd ??
    (details.forwarding as { requesterCwd?: string } | undefined)?.requesterCwd;
  if (explicit && typeof explicit === "string") {
    return explicit;
  }

  if (details.requestId) {
    try {
      const baseDir = agentDir ?? process.env.PI_AGENT_DIR ?? join(homedir(), ".pi", "agent");
      const forwardingSessionsDir = join(baseDir, "sessions", "permission-forwarding", "sessions");
      if (existsSync(forwardingSessionsDir)) {
        for (const sessionDir of readdirSync(forwardingSessionsDir)) {
          const reqFile = join(forwardingSessionsDir, sessionDir, "requests", `${details.requestId}.json`);
          if (existsSync(reqFile)) {
            const raw = readFileSync(reqFile, "utf-8");
            const parsed = JSON.parse(raw);
            const foundCwd = parsed?.accessIntent?.requesterCwd;
            if (foundCwd && typeof foundCwd === "string") {
              return foundCwd;
            }
          }
        }
      }
    } catch {
      // Non-fatal, fallback to default cwd
    }
  }

  return fallbackCwd;
}

function logDecision(
  log: AuthorizerLog | undefined,
  details: PromptPermissionDetails,
  command: string,
  cwd: string,
  provenance: Provenance,
  payload: Record<string, unknown>,
): void {
  log?.review?.(DECISION_EVENT, {
    requestId: details.requestId,
    command,
    cwd,
    agentName: provenance.agentName,
    requesterSessionId: provenance.requesterSessionId,
    ...payload,
  });
}

/**
 * Creates the authorizer link callback adhering to Authorizer["authorize"].
 */
export function createAuthorizer(deps: AuthorizerDeps): Authorizer["authorize"] {
  let cachedJudge: JudgeFn | undefined = deps.judge;
  let cachedEndpointHost: string | undefined;

  return async (
    details: PromptPermissionDetails,
    _query: PermissionQuery,
    log: AuthorizerLog,
  ): Promise<AuthorizerVerdict> => {
    const cfg = deps.config;
    if (!cfg) return { kind: "defer" };

    const surface = details.accessIntent?.surface ?? details.surface ?? null;
    if (surface !== null && surface !== "bash") return { kind: "defer" };

    const command = details.command ?? (surface === "bash" && typeof details.value === "string" ? details.value : undefined);
    if (!command || !command.trim()) return { kind: "defer" };

    const extraHardDeferRules = deps.extraHardDefer ?? [];
    const fallbackCwd = (typeof deps.cwd === "function" ? deps.cwd() : deps.cwd) ?? process.cwd();
    const effectiveCwd = resolveRequesterCwd(details, fallbackCwd, deps.agentDir);
    const readScript = deps.readScript ?? readScriptSafely;
    const ui = deps.ui;
    const provenance = extractProvenance(details);

    let endpointHost =
      (typeof deps.endpointHost === "function" ? deps.endpointHost() : deps.endpointHost) ??
      cachedEndpointHost ??
      "unresolved";

    const lazyJudge: JudgeFn = async (req) => {
      if (!cachedJudge) {
        if (deps.resolveJudge) {
          const res = await deps.resolveJudge(cfg);
          if ("error" in res) {
            return { ok: false, error: "network", detail: res.error, latencyMs: 0 };
          }
          cachedJudge = res.judge;
          if (res.endpointHost) {
            cachedEndpointHost = res.endpointHost;
            endpointHost = res.endpointHost;
          }
        } else {
          return { ok: false, error: "network", detail: "model-unresolved", latencyMs: 0 };
        }
      }
      return cachedJudge(req);
    };

    let decision;
    try {
      decision = await decide(
        { command, cwd: effectiveCwd, projectCwd: fallbackCwd },
        { config: cfg, extraHardDefer: extraHardDeferRules, judge: lazyJudge, readScript },
      );
    } catch (err) {
      logDecision(log, details, command, effectiveCwd, provenance, {
        verdict: "defer",
        stage: "internal-error",
        reason: "internal-error",
        detail: String(err),
      });
      return { kind: "defer" };
    }

    logDecision(log, details, command, effectiveCwd, provenance, {
      model: `${cfg.provider}/${cfg.model}`,
      endpoint: endpointHost,
      dryRun: cfg.dryRun,
      ...decision,
    });

    if (decision.verdict === "allow") return { kind: "allow" };
    if (cfg.notifyOnDefer && decision.stage !== "hard-defer") {
      ui?.notify(summarize(decision), "info");
    }
    return { kind: "defer" };
  };
}
