/**
 * Wiring, following @gotgenes/pi-permission-model-judge: load config at
 * session_start, register the "command-judge" link when permissions:ready fires
 * (it may fire more than once, so registration is idempotent), dispose on
 * shutdown.
 *
 * Add "command-judge" to authorizerChain in pi-permission-system's config to
 * activate it. The link only reviews asks on the "bash" surface; every other
 * ask (paths, outside-directory, MCP, skills) is deferred untouched.
 */

import { type ExtensionAPI, getAgentDir } from "@earendil-works/pi-coding-agent";
import type { PermissionsReadyEvent } from "@gotgenes/pi-permission-system";
import { getPermissionsService, PERMISSIONS_READY_CHANNEL } from "@gotgenes/pi-permission-system";

import { createAuthorizer, DECISION_EVENT, LINK_NAME, type Notifier } from "./authorizer.ts";
import { loadConfig, resolveTextOrFile, type CommandJudgeConfig } from "./config.ts";
import { compileExtra } from "./hard-defer.ts";
import { createJudge, type JudgeFn } from "./judge-client.ts";
import { composePolicy, renderUserPrompt, verdictSchema } from "./prompt.ts";
import { readScriptSafely } from "./scripts.ts";

export { DECISION_EVENT, LINK_NAME };
const TAG = "[pi-command-judge]";

interface RegistryLike {
  find(provider: string, modelId: string): { id: string; api: string; baseUrl: string } | undefined;
  getApiKeyAndHeaders(
    model: unknown,
  ): Promise<{ ok: true; apiKey?: string; headers?: Record<string, string>; baseUrl?: string } | { ok: false; error: string }>;
}

export default function commandJudgeExtension(pi: ExtensionAPI): void {
  let config: CommandJudgeConfig | undefined;
  let extra: RegExp[] = [];
  let cwd = process.cwd();
  let registry: RegistryLike | undefined;
  let ui: Notifier | undefined;
  let judge: JudgeFn | undefined;
  let endpointHost = "unresolved";
  let dispose: (() => void) | undefined;

  pi.on("session_start", (_event, ctx) => {
    const loaded = loadConfig(getAgentDir());
    for (const issue of loaded.issues) console.warn(`${TAG} ${loaded.path}: ${issue}`);
    config = loaded.config;
    cwd = ctx.cwd;
    registry = ctx.modelRegistry as unknown as RegistryLike;
    ui = (ctx as unknown as { ui?: Notifier }).ui;
    judge = undefined;
    if (config) {
      const { compiled, invalid } = compileExtra(config.extraHardDefer);
      extra = compiled;
      for (const p of invalid) console.warn(`${TAG} ignoring invalid extraHardDefer regex: ${p}`);
      if (config.warmup) void warm(config);
    }
  });

  pi.events.on(PERMISSIONS_READY_CHANNEL, (data) => {
    if (dispose || !config) return;
    const sessionId = (data as Partial<PermissionsReadyEvent> | undefined)?.sessionId;
    const service = typeof sessionId === "string" ? getPermissionsService(sessionId) : undefined;
    if (!service) {
      console.warn(`${TAG} no permission service for this session; is @gotgenes/pi-permission-system loaded?`);
      return;
    }
    const authorize = createAuthorizer({
      config,
      extraHardDefer: extra,
      cwd,
      endpointHost: () => endpointHost,
      ui,
      judge,
      resolveJudge,
      readScript: readScriptSafely,
    });
    dispose = service.registerAuthorizer(LINK_NAME, authorize);
  });

  pi.on("session_shutdown", () => {
    dispose?.();
    dispose = undefined;
    config = undefined;
    registry = undefined;
    ui = undefined;
    judge = undefined;
  });

  async function resolveJudge(cfg: CommandJudgeConfig): Promise<{ judge: JudgeFn; endpointHost?: string } | { error: string }> {
    if (judge) return { judge, endpointHost };
    const model = registry?.find(cfg.provider, cfg.model);
    if (!model) return { error: "model-unresolved" };
    if (model.api !== "openai-completions" && model.api !== "openai-responses") {
      return { error: `unsupported-api:${model.api}` };
    }
    const auth = await registry!.getApiKeyAndHeaders(model);
    if (!auth.ok) return { error: "auth-failed" };
    const baseUrl = cfg.baseUrl ?? auth.baseUrl ?? model.baseUrl;
    const apiKey = cfg.apiKeyEnv ? process.env[cfg.apiKeyEnv] : auth.apiKey;
    if (cfg.apiKeyEnv && !apiKey) return { error: `missing-env:${cfg.apiKeyEnv}` };
    try {
      endpointHost = new URL(baseUrl).host;
    } catch {
      endpointHost = baseUrl;
    }
    judge = createJudge({
      baseUrl,
      modelId: model.id,
      api: model.api,
      apiKey,
      headers: auth.headers,
      extraBody: cfg.extraBody,
      structuredOutput: cfg.structuredOutput,
    });
    return { judge, endpointHost };
  }

  /**
   * Fire throwaway calls with both schemas (command and script) so the server
   * compiles their grammars and the connection is open before the first real ask.
   * Results are ignored; failures are silent here and show up on real asks.
   */
  async function warm(cfg: CommandJudgeConfig): Promise<void> {
    const resolved = await resolveJudge(cfg).catch(() => ({ error: "warmup-failed" }));
    if ("error" in resolved) return;
    judge = resolved.judge;
    const basePolicy = resolveTextOrFile(cfg.policy, cwd);
    const extraPolicy = resolveTextOrFile(cfg.extraPolicy, cwd);
    const system = composePolicy(basePolicy, extraPolicy);
    const customInstructions = resolveTextOrFile(cfg.customPromptInstructions, cwd);
    const started = Date.now();
    await Promise.allSettled([
      resolved.judge({
        system,
        user: renderUserPrompt({ cwd, command: "ls", customInstructions }),
        schema: verdictSchema(false),
        maxTokens: cfg.maxTokensCommand,
        timeoutMs: 60000,
      }),
      resolved.judge({
        system,
        user: renderUserPrompt({ cwd, command: "python3 warm.py", script: { path: "warm.py", content: "print('ok')" }, customInstructions }),
        schema: verdictSchema(true),
        maxTokens: cfg.maxTokensScript,
        timeoutMs: 60000,
      }),
    ]);
    if (process.env.PI_COMMAND_JUDGE_DEBUG) console.warn(`${TAG} warm-up done in ${Date.now() - started}ms`);
  }
}
