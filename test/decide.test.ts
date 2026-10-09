import { describe, expect, it, vi } from "vitest";

import { DEFAULT_CONFIG, parseConfig, type CommandJudgeConfig } from "../src/config.ts";
import { decide, type DecideDeps } from "../src/decide.ts";
import { allowProbability, type JudgeFn, type JudgeResult, parseVerdict } from "../src/judge-client.ts";
import type { ReadScriptResult } from "../src/scripts.ts";

const LIVE: CommandJudgeConfig = { ...DEFAULT_CONFIG, dryRun: false };

const noEffects = { reads: [], writes: [], deletes: [], network: [], cluster_or_cloud: [], runs_other_code: false };

function judgeReturning(r: Partial<Extract<JudgeResult, { ok: true }>> | Extract<JudgeResult, { ok: false }>): JudgeFn {
  return vi.fn(async () =>
    "error" in r
      ? r
      : ({ ok: true, decision: "allow", reason: "ok", pAllow: 0.99, latencyMs: 5, raw: "{}", ...r } as JudgeResult),
  );
}

function deps(judge: JudgeFn, config = LIVE, script?: ReadScriptResult): DecideDeps {
  return {
    config,
    extraHardDefer: [],
    judge,
    readScript: () => script ?? { ok: false, reason: "not-found" },
  };
}

describe("decide", () => {
  it("never calls the model for hard lines", async () => {
    const judge = judgeReturning({});
    const d = await decide({ command: "oc delete pod x", cwd: "/w" }, deps(judge));
    expect(d).toMatchObject({ verdict: "defer", stage: "hard-defer" });
    expect(judge).not.toHaveBeenCalled();
  });

  it("allows a confident model allow", async () => {
    // A command not in fast-allow list (e.g. general script or complex tool) falls through to model
    const d = await decide({ command: "python3 -m some_tool", cwd: "/w" }, deps(judgeReturning({})));
    expect(d.verdict).toBe("allow");
  });

  it("fast-allows deterministic safe commands without calling model", async () => {
    const judge = judgeReturning({});
    const d = await decide({ command: "git status", cwd: "/w" }, deps(judge));
    expect(d).toMatchObject({ verdict: "allow", stage: "fast-allow", reason: "fast-allow" });
    expect(judge).not.toHaveBeenCalled();
  });

  it("fast-allows in dry-run by deferring with wouldAllow", async () => {
    const judge = judgeReturning({});
    const d = await decide({ command: "git status", cwd: "/w" }, deps(judge, { ...LIVE, dryRun: true }));
    expect(d).toMatchObject({ verdict: "defer", stage: "fast-allow", reason: "dry-run", wouldAllow: true });
    expect(judge).not.toHaveBeenCalled();
  });

  it("defers low confidence", async () => {
    const d = await decide({ command: "python3 -m some_tool", cwd: "/w" }, deps(judgeReturning({ pAllow: 0.6 })));
    expect(d).toMatchObject({ verdict: "defer", reason: "low-confidence" });
  });

  it("defers when logprobs are missing and required", async () => {
    const d = await decide({ command: "python3 -m some_tool", cwd: "/w" }, deps(judgeReturning({ pAllow: null })));
    expect(d).toMatchObject({ verdict: "defer", reason: "no-logprobs" });
  });

  it("defers on model defer, timeout and garbage", async () => {
    for (const j of [
      judgeReturning({ decision: "defer" }),
      judgeReturning({ ok: false, error: "timeout", detail: ">4000ms", latencyMs: 4000 }),
      judgeReturning({ ok: false, error: "unparseable", detail: "?", latencyMs: 9 }),
    ]) {
      expect((await decide({ command: "make lint", cwd: "/w" }, deps(j))).verdict).toBe("defer");
    }
  });

  it("dry run never allows but records wouldAllow", async () => {
    const d = await decide({ command: "python3 -m some_tool", cwd: "/w" }, deps(judgeReturning({}), { ...LIVE, dryRun: true }));
    expect(d).toMatchObject({ verdict: "defer", reason: "dry-run", wouldAllow: true });
  });

  it("defers unreadable scripts without calling the model", async () => {
    const judge = judgeReturning({});
    const d = await decide({ command: "python3 ../other/x.py", cwd: "/w" }, deps(judge, LIVE, { ok: false, reason: "outside-cwd" }));
    expect(d).toMatchObject({ verdict: "defer", reason: "script-unreadable:outside-cwd" });
    expect(judge).not.toHaveBeenCalled();
  });

  it("defers scripts that fail the static scan", async () => {
    const judge = judgeReturning({});
    const d = await decide(
      { command: "python3 x.py", cwd: "/w" },
      deps(judge, LIVE, { ok: true, path: "x.py", content: "import shutil\nshutil.rmtree('/')" }),
    );
    expect(d).toMatchObject({ verdict: "defer", stage: "script", reason: "hard:script-delete" });
    expect(judge).not.toHaveBeenCalled();
  });

  it("sends clean scripts to the model with a longer timeout", async () => {
    const judge = judgeReturning({ effects: noEffects });
    const d = await decide(
      { command: "python3 report.py", cwd: "/w" },
      deps(judge, LIVE, { ok: true, path: "report.py", content: "print('hi')" }),
    );
    expect(d.verdict).toBe("allow");
    const call = (judge as unknown as { mock: { calls: [{ timeoutMs: number; user: string }][] } }).mock.calls[0][0];
    expect(call.timeoutMs).toBe(LIVE.scriptTimeoutMs);
    expect(call.user).toContain("<script>");
  });

  it("overrides a model allow contradicted by its own effects", async () => {
    const judge = judgeReturning({ effects: { ...noEffects, cluster_or_cloud: ["oc delete pod stale"] } });
    const d = await decide(
      { command: "python3 report.py", cwd: "/w" },
      deps(judge, LIVE, { ok: true, path: "report.py", content: "print('hi')" }),
    );
    expect(d).toMatchObject({ verdict: "defer", reason: "effects-need-human" });
  });

  it("requires effects for scripts", async () => {
    const d = await decide(
      { command: "python3 report.py", cwd: "/w" },
      deps(judgeReturning({}), LIVE, { ok: true, path: "report.py", content: "print('hi')" }),
    );
    expect(d).toMatchObject({ verdict: "defer", reason: "missing-effects" });
  });
});

describe("parseVerdict / allowProbability", () => {
  it("rejects garbage", () => {
    expect(parseVerdict("sure, go ahead").ok).toBe(false);
    expect(parseVerdict('{"decision":"yes"}').ok).toBe(false);
  });

  it("reads P(allow) at the decision token", () => {
    const lp = (token: string, p: number, top?: Array<[string, number]>) => ({
      token,
      logprob: Math.log(p),
      top_logprobs: top?.map(([t, q]) => ({ token: t, logprob: Math.log(q) })),
    });
    const entries = [
      lp('{"', 1),
      lp("decision", 1),
      lp('":"', 1),
      lp("allow", 0.93, [["allow", 0.93], ["defer", 0.07]]),
      lp('","', 1),
    ];
    expect(allowProbability(entries)).toBeCloseTo(0.93, 5);
  });

  it("handles a token that carries the quote and the value", () => {
    const entries = [
      { token: '{"decision":', logprob: 0 },
      { token: ' "all', logprob: Math.log(0.8), top_logprobs: [{ token: ' "all', logprob: Math.log(0.8) }, { token: ' "def', logprob: Math.log(0.2) }] },
    ];
    expect(allowProbability(entries)).toBeCloseTo(0.8, 5);
  });

  it("returns null when the decision token is absent", () => {
    expect(allowProbability([{ token: "{}", logprob: 0 }])).toBeNull();
  });
});

describe("parseConfig", () => {
  it("defaults to dry run", () => {
    expect(parseConfig({}).config?.dryRun).toBe(true);
  });
  it("reports bad values and keeps defaults", () => {
    const r = parseConfig({ minAllowProbability: 2, extraHardDefer: "x" });
    expect(r.issues).toHaveLength(2);
    expect(r.config?.minAllowProbability).toBe(DEFAULT_CONFIG.minAllowProbability);
  });
});
