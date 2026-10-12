/**
 * Live-authority link for pi-permission-system: adjudicates bash commands and
 * scripts from both direct parent session asks and forwarded subagent asks.
 */

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
  config?: CommandJudgeConfig | (() => CommandJudgeConfig | undefined);
  extraHardDefer?: readonly RegExp[] | (() => readonly RegExp[] | undefined);
  cwd?: string | (() => string | undefined);
  judge?: JudgeFn;
  getJudge?: () => Promise<{ judge: JudgeFn; endpointHost?: string } | { error: string }>;
  resolveJudge?: (config: CommandJudgeConfig) => Promise<{ judge: JudgeFn; endpointHost?: string } | { error: string }>;
  endpointHost?: string | (() => string | undefined);
  ui?: Notifier | (() => Notifier | undefined);
  readScript?: (ref: ScriptRef, cwd: string, maxBytes: number) => ReadScriptResult;
}

function resolveGetter<T>(val: T | (() => T | undefined) | undefined): T | undefined {
  if (typeof val === "function") {
    return (val as () => T | undefined)();
  }
  return val;
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
    const cfg = resolveGetter(deps.config);
    if (!cfg) return { kind: "defer" };

    const surface = details.accessIntent?.surface ?? details.surface ?? null;
    if (surface !== "bash") return { kind: "defer" };

    const command = details.command ?? (details.surface === "bash" && typeof details.value === "string" ? details.value : undefined);
    if (!command || !command.trim()) return { kind: "defer" };

    const extra = resolveGetter(deps.extraHardDefer) ?? [];
    const cwd = resolveGetter(deps.cwd) ?? process.cwd();
    const readScript = deps.readScript ?? readScriptSafely;
    const ui = resolveGetter(deps.ui);

    let endpointHost = resolveGetter(deps.endpointHost) ?? cachedEndpointHost ?? "unresolved";

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
        } else if (deps.getJudge) {
          const res = await deps.getJudge();
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
        { command, cwd },
        { config: cfg, extraHardDefer: extra, judge: lazyJudge, readScript },
      );
    } catch (err) {
      log?.review?.(DECISION_EVENT, {
        requestId: details.requestId,
        command,
        verdict: "defer",
        reason: "internal-error",
        detail: String(err),
      });
      return { kind: "defer" };
    }

    log?.review?.(DECISION_EVENT, {
      requestId: details.requestId,
      command,
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
