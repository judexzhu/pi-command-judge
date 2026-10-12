import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { PermissionQuery, PromptPermissionDetails } from "@gotgenes/pi-permission-system";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createAuthorizer, DECISION_EVENT, extractProvenance, LINK_NAME } from "../src/authorizer.ts";
import { DEFAULT_CONFIG, type CommandJudgeConfig } from "../src/config.ts";
import type { JudgeFn } from "../src/judge-client.ts";

const LIVE_CONFIG: CommandJudgeConfig = { ...DEFAULT_CONFIG, dryRun: false };

function createAsk(overrides: Partial<PromptPermissionDetails>): PromptPermissionDetails {
  return {
    requestId: "req-" + Math.random().toString(36).slice(2, 8),
    source: "tool_call",
    agentName: null,
    payload: {
      type: "tool-call",
      toolName: "bash",
      parameters: {},
    } as any,
    ...overrides,
  };
}

function createMockLog() {
  const reviews: Array<{ event: string; data: Record<string, unknown> }> = [];
  return {
    review: vi.fn((event: string, data: Record<string, unknown>) => {
      reviews.push({ event, data });
    }),
    reviews,
  };
}

const mockQuery = {} as PermissionQuery;

describe("authorizer seam and forwarded ask command extraction", () => {
  it("exports LINK_NAME as command-judge", () => {
    expect(LINK_NAME).toBe("command-judge");
  });

  describe("direct parent asks", () => {
    it("fast-allows direct parent bash asks with deterministic safe commands", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: "git status",
        surface: "bash",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          verdict: "allow",
          stage: "fast-allow",
        }),
      );
    });

    it("hard-defers direct parent bash asks with dangerous commands", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: "rm -rf /",
        surface: "bash",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "rm -rf /",
          verdict: "defer",
          stage: "hard-defer",
        }),
      );
    });

    it("allows direct parent bash asks when model judge approves", async () => {
      const log = createMockLog();
      const judge = vi.fn(async () => ({
        ok: true as const,
        decision: "allow" as const,
        reason: "safe direct command",
        pAllow: 0.98,
        latencyMs: 10,
        raw: "{}",
      }));
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        command: "cargo build",
        surface: "bash",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(judge).toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "cargo build",
          verdict: "allow",
          stage: "model",
        }),
      );
    });
  });

  describe("forwarded subagent asks", () => {
    it("fast-allows forwarded subagent asks with deterministic safe commands in details.value", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "git status",
        agentName: "worker-agent",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          verdict: "allow",
          stage: "fast-allow",
        }),
      );
    });

    it("fast-allows forwarded subagent asks where surface is carried in accessIntent", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "git diff",
        accessIntent: {
          surface: "bash",
          matchValues: ["git diff"],
          boundaryValue: null,
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git diff",
          verdict: "allow",
          stage: "fast-allow",
        }),
      );
    });

    it("extracts command from details.value when details.surface is undefined but accessIntent.surface is bash", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: undefined,
        surface: undefined,
        value: "git diff",
        accessIntent: {
          surface: "bash",
          matchValues: ["git diff"],
          boundaryValue: null,
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git diff",
          verdict: "allow",
          stage: "fast-allow",
        }),
      );
    });

    it("hard-defers forwarded dangerous asks (e.g. oc delete pod x) without calling model", async () => {
      const log = createMockLog();
      const judge = vi.fn();
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "oc delete pod x",
        agentName: "subagent-1",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "oc delete pod x",
          verdict: "defer",
          stage: "hard-defer",
        }),
      );
    });

    it("hard-defers forwarded dangerous asks with other cloud deletion tools", async () => {
      const log = createMockLog();
      const judge = vi.fn();
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "kubectl delete deployment nginx",
        agentName: "subagent-1",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "kubectl delete deployment nginx",
          verdict: "defer",
          stage: "hard-defer",
        }),
      );
    });
  });

  describe("non-bash asks", () => {
    it("immediately defers non-bash asks with surface = read without error or logging", async () => {
      const log = createMockLog();
      const judge = vi.fn();
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        surface: "read",
        value: "/path/to/file",
        command: "git status",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).not.toHaveBeenCalled();
    });

    it("immediately defers non-bash asks with surface = write without error or logging", async () => {
      const log = createMockLog();
      const judge = vi.fn();
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        surface: "write",
        value: "/path/to/dest",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).not.toHaveBeenCalled();
    });
  });

  describe("asks missing command and value", () => {
    it("defers asks missing both command and value", async () => {
      const log = createMockLog();
      const judge = vi.fn();
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        surface: "bash",
        command: undefined,
        value: undefined,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).not.toHaveBeenCalled();
    });

    it("defers asks where value is not a string", async () => {
      const log = createMockLog();
      const judge = vi.fn();
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        surface: "bash",
        command: undefined,
        value: null,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).not.toHaveBeenCalled();
    });

    it("defers asks where command is whitespace-only", async () => {
      const log = createMockLog();
      const judge = vi.fn();
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        surface: "bash",
        command: "   ",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).not.toHaveBeenCalled();
    });
  });

  describe("model judge integration for forwarded asks", () => {
    it("allows forwarded asks when model judge returns allow", async () => {
      const log = createMockLog();
      const judge = vi.fn(async () => ({
        ok: true as const,
        decision: "allow" as const,
        reason: "build is safe and clean",
        pAllow: 0.96,
        latencyMs: 12,
        raw: "{}",
      }));
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "cargo build",
        agentName: "worker-build",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(judge).toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "cargo build",
          verdict: "allow",
          stage: "model",
          modelDecision: "allow",
          pAllow: 0.96,
        }),
      );
    });

    it("defers forwarded asks when model judge returns defer", async () => {
      const log = createMockLog();
      const judge = vi.fn(async () => ({
        ok: true as const,
        decision: "defer" as const,
        reason: "mutation risks detected",
        pAllow: 0.25,
        latencyMs: 14,
        raw: "{}",
      }));
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "cargo build",
        agentName: "worker-build",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "cargo build",
          verdict: "defer",
          stage: "model",
          modelDecision: "defer",
          pAllow: 0.25,
        }),
      );
    });

    it("defers forwarded asks when model judge fails or times out", async () => {
      const log = createMockLog();
      const judge = vi.fn(async () => ({
        ok: false as const,
        error: "timeout" as const,
        detail: ">4000ms",
        latencyMs: 4001,
      }));
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "cargo build",
        agentName: "worker-build",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "cargo build",
          verdict: "defer",
          stage: "model",
          reason: "model-timeout",
        }),
      );
    });

    it("defers in dry-run mode and records wouldAllow", async () => {
      const log = createMockLog();
      const judge = vi.fn(async () => ({
        ok: true as const,
        decision: "allow" as const,
        reason: "ok",
        pAllow: 0.99,
        latencyMs: 10,
        raw: "{}",
      }));
      const authorize = createAuthorizer({
        config: { ...LIVE_CONFIG, dryRun: true },
        judge,
      });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "cargo build",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "cargo build",
          verdict: "defer",
          dryRun: true,
          wouldAllow: true,
        }),
      );
    });
  });

  describe("ui notification and error resilience", () => {
    it("notifies ui on defer if notifyOnDefer is true and not hard-defer", async () => {
      const log = createMockLog();
      const ui = { notify: vi.fn() };
      const judge = vi.fn(async () => ({
        ok: true as const,
        decision: "defer" as const,
        reason: "not safe",
        pAllow: 0.1,
        latencyMs: 5,
        raw: "{}",
      }));
      const authorize = createAuthorizer({
        config: { ...LIVE_CONFIG, notifyOnDefer: true },
        judge,
        ui,
      });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "cargo build",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(ui.notify).toHaveBeenCalledTimes(1);
    });

    it("does not notify ui on hard-defer even if notifyOnDefer is true", async () => {
      const log = createMockLog();
      const ui = { notify: vi.fn() };
      const authorize = createAuthorizer({
        config: { ...LIVE_CONFIG, notifyOnDefer: true },
        ui,
      });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "oc delete pod x",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(ui.notify).not.toHaveBeenCalled();
    });

    it("catches internal errors, logs error, and defers without throwing", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        readScript: () => {
          throw new Error("unexpected disk failure");
        },
      });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "python3 test.py",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "python3 test.py",
          verdict: "defer",
          reason: "internal-error",
        }),
      );
    });
  });

  describe("scoped subagent working directory resolution and script containment", () => {
    let tempRoot: string;
    let parentDir: string;
    let subagentDir: string;

    beforeEach(() => {
      tempRoot = mkdtempSync(join(tmpdir(), "pi-authorizer-test-"));
      parentDir = join(tempRoot, "parent");
      subagentDir = join(tempRoot, "subagent");
      mkdirSync(parentDir, { recursive: true });
      mkdirSync(subagentDir, { recursive: true });
    });

    afterEach(() => {
      rmSync(tempRoot, { recursive: true, force: true });
    });

    it("resolves effective cwd from accessIntent.requesterCwd and records cwd in review log", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
      });
      const ask = createAsk({
        surface: "bash",
        value: "git status",
        accessIntent: {
          surface: "bash",
          matchValues: ["git status"],
          boundaryValue: null,
          requesterCwd: subagentDir,
        } as any,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          cwd: subagentDir,
          verdict: "allow",
        }),
      );
    });

    it("falls back to deps.cwd when requesterCwd is absent in accessIntent", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
      });
      const ask = createAsk({
        surface: "bash",
        value: "git status",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          cwd: parentDir,
          verdict: "allow",
        }),
      );
    });

    it("falls back to getter deps.cwd() when requesterCwd is absent", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: () => parentDir,
      });
      const ask = createAsk({
        surface: "bash",
        value: "git status",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          cwd: parentDir,
          verdict: "allow",
        }),
      );
    });

    it("reads, scans, and submits to judge a script inside subagent cwd (accessIntent.requesterCwd)", async () => {
      const scriptPath = join(subagentDir, "build.sh");
      writeFileSync(scriptPath, "#!/bin/bash\necho 'building project'\n");

      const log = createMockLog();
      const judge = vi.fn<JudgeFn>(async () => ({
        ok: true as const,
        decision: "allow" as const,
        reason: "safe build script",
        effects: {
          reads: [],
          writes: ["project"],
          deletes: [],
          network: [],
          cluster_or_cloud: [],
          runs_other_code: false,
        },
        pAllow: 0.95,
        latencyMs: 15,
        raw: "{}",
      }));

      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
        judge,
      });

      const ask = createAsk({
        surface: "bash",
        value: "./build.sh",
        accessIntent: {
          surface: "bash",
          matchValues: ["./build.sh"],
          boundaryValue: null,
          requesterCwd: subagentDir,
        } as any,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(judge).toHaveBeenCalled();
      const judgeCall = judge.mock.calls[0]![0];
      expect(judgeCall.user).toContain("building project");
      expect(judgeCall.user).toContain(subagentDir);
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "./build.sh",
          cwd: subagentDir,
          verdict: "allow",
          stage: "model",
        }),
      );
    });

    it("defers when a script inside subagent cwd violates hard static rules", async () => {
      const scriptPath = join(subagentDir, "danger.py");
      writeFileSync(scriptPath, "import shutil\nshutil.rmtree('/important')\n");

      const log = createMockLog();
      const judge = vi.fn();

      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
        judge,
      });

      const ask = createAsk({
        surface: "bash",
        value: "python3 danger.py",
        accessIntent: {
          surface: "bash",
          matchValues: ["python3 danger.py"],
          boundaryValue: null,
          requesterCwd: subagentDir,
        } as any,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "python3 danger.py",
          cwd: subagentDir,
          verdict: "defer",
          stage: "script",
          reason: "hard:script-delete",
        }),
      );
    });

    it("defers when script escapes subagent cwd via parent relative path (outside-cwd)", async () => {
      const outsideScriptPath = join(tempRoot, "outside.py");
      writeFileSync(outsideScriptPath, "print('outside')\n");

      const log = createMockLog();
      const judge = vi.fn();

      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
        judge,
      });

      const ask = createAsk({
        surface: "bash",
        value: "python3 ../outside.py",
        accessIntent: {
          surface: "bash",
          matchValues: ["python3 ../outside.py"],
          boundaryValue: null,
          requesterCwd: subagentDir,
        } as any,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "python3 ../outside.py",
          cwd: subagentDir,
          verdict: "defer",
          stage: "script",
          reason: "script-unreadable:outside-cwd",
        }),
      );
    });

    it("defers when script escapes subagent cwd via absolute path outside subagent cwd", async () => {
      const outsideScriptPath = join(tempRoot, "outside.sh");
      writeFileSync(outsideScriptPath, "#!/bin/bash\necho hello\n");

      const log = createMockLog();
      const judge = vi.fn();

      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
        judge,
      });

      const ask = createAsk({
        surface: "bash",
        value: `bash ${outsideScriptPath}`,
        accessIntent: {
          surface: "bash",
          matchValues: [`bash ${outsideScriptPath}`],
          boundaryValue: null,
          requesterCwd: subagentDir,
        } as any,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: `bash ${outsideScriptPath}`,
          cwd: subagentDir,
          verdict: "defer",
          stage: "script",
          reason: "script-unreadable:outside-cwd",
        }),
      );
    });

    it("defers when script is a symlink inside subagent cwd resolving outside (outside-cwd)", async () => {
      const outsideScriptPath = join(tempRoot, "secret-outside.sh");
      writeFileSync(outsideScriptPath, "#!/bin/bash\necho leaked\n");
      const symlinkPath = join(subagentDir, "symlinked.sh");
      symlinkSync(outsideScriptPath, symlinkPath);

      const log = createMockLog();
      const judge = vi.fn();

      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
        judge,
      });

      const ask = createAsk({
        surface: "bash",
        value: "./symlinked.sh",
        accessIntent: {
          surface: "bash",
          matchValues: ["./symlinked.sh"],
          boundaryValue: null,
          requesterCwd: subagentDir,
        } as any,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "./symlinked.sh",
          cwd: subagentDir,
          verdict: "defer",
          stage: "script",
          reason: "script-unreadable:outside-cwd",
        }),
      );
    });

    it("defers when script is missing in subagent cwd (not-found)", async () => {
      const log = createMockLog();
      const judge = vi.fn();

      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
        judge,
      });

      const ask = createAsk({
        surface: "bash",
        value: "python3 nonexistent.py",
        accessIntent: {
          surface: "bash",
          matchValues: ["python3 nonexistent.py"],
          boundaryValue: null,
          requesterCwd: subagentDir,
        } as any,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "python3 nonexistent.py",
          cwd: subagentDir,
          verdict: "defer",
          stage: "script",
          reason: "script-unreadable:not-found",
        }),
      );
    });

    it("defers when script exists in parent cwd but not subagent cwd", async () => {
      const parentScript = join(parentDir, "only-in-parent.py");
      writeFileSync(parentScript, "print('in parent')\n");

      const log = createMockLog();
      const judge = vi.fn();

      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        cwd: parentDir,
        judge,
      });

      const ask = createAsk({
        surface: "bash",
        value: "python3 only-in-parent.py",
        accessIntent: {
          surface: "bash",
          matchValues: ["python3 only-in-parent.py"],
          boundaryValue: null,
          requesterCwd: subagentDir,
        } as any,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(judge).not.toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "python3 only-in-parent.py",
          cwd: subagentDir,
          verdict: "defer",
          stage: "script",
          reason: "script-unreadable:not-found",
        }),
      );
    });
  });

  describe("subagent provenance in decision audit logs", () => {
    it("records agentName from forwarding.requesterAgentName when details.agentName is missing", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "git status",
        agentName: null,
        forwarding: {
          requesterAgentName: "delegated-worker",
          requesterSessionId: "session-xyz",
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          verdict: "allow",
          stage: "fast-allow",
          agentName: "delegated-worker",
          requesterSessionId: "session-xyz",
        }),
      );
    });

    it("records agentName and requesterSessionId for forwarded asks on fast-allow", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "git status",
        agentName: "reviewer",
        forwarding: {
          requesterAgentName: "reviewer",
          requesterSessionId: "session-xyz",
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          verdict: "allow",
          stage: "fast-allow",
          agentName: "reviewer",
          requesterSessionId: "session-xyz",
        }),
      );
    });

    it("records agentName and requesterSessionId for forwarded asks on hard-defer", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "rm -rf /",
        agentName: "reviewer",
        forwarding: {
          requesterAgentName: "reviewer",
          requesterSessionId: "session-xyz",
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "rm -rf /",
          verdict: "defer",
          stage: "hard-defer",
          agentName: "reviewer",
          requesterSessionId: "session-xyz",
        }),
      );
    });

    it("records agentName and requesterSessionId for forwarded asks on model evaluation", async () => {
      const log = createMockLog();
      const judge = vi.fn(async () => ({
        ok: true as const,
        decision: "allow" as const,
        reason: "safe cargo build",
        pAllow: 0.95,
        latencyMs: 15,
        raw: "{}",
      }));
      const authorize = createAuthorizer({ config: LIVE_CONFIG, judge });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "cargo build",
        agentName: "reviewer",
        forwarding: {
          requesterAgentName: "reviewer",
          requesterSessionId: "session-xyz",
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "cargo build",
          verdict: "allow",
          stage: "model",
          agentName: "reviewer",
          requesterSessionId: "session-xyz",
        }),
      );
    });

    it("records null agentName and null requesterSessionId for direct parent asks", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: "git status",
        surface: "bash",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          verdict: "allow",
          agentName: null,
          requesterSessionId: null,
        }),
      );
    });

    it("records null for missing or undefined agentName on direct parent asks", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({ config: LIVE_CONFIG });
      const ask = createAsk({
        command: "git status",
        surface: "bash",
        agentName: undefined as any,
        forwarding: undefined,
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "allow" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "git status",
          verdict: "allow",
          agentName: null,
          requesterSessionId: null,
        }),
      );
    });

    it("records subagent provenance when resolveJudge returns an error", async () => {
      const log = createMockLog();
      const resolveJudge = vi.fn(async () => ({ error: "auth-failed" }));
      const authorize = createAuthorizer({ config: LIVE_CONFIG, resolveJudge });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "cargo build",
        agentName: "reviewer",
        forwarding: {
          requesterAgentName: "reviewer",
          requesterSessionId: "session-xyz",
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(resolveJudge).toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "cargo build",
          verdict: "defer",
          stage: "model",
          reason: "model-network",
          agentName: "reviewer",
          requesterSessionId: "session-xyz",
        }),
      );
    });

    it("records subagent provenance when resolveJudge throws an unhandled error", async () => {
      const log = createMockLog();
      const resolveJudge = vi.fn(async () => {
        throw new Error("judge resolution crashed");
      });
      const authorize = createAuthorizer({ config: LIVE_CONFIG, resolveJudge });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "cargo build",
        agentName: "reviewer",
        forwarding: {
          requesterAgentName: "reviewer",
          requesterSessionId: "session-xyz",
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(resolveJudge).toHaveBeenCalled();
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "cargo build",
          verdict: "defer",
          reason: "internal-error",
          agentName: "reviewer",
          requesterSessionId: "session-xyz",
        }),
      );
    });

    it("records subagent provenance when decide throws an internal error", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        readScript: () => {
          throw new Error("unexpected script reading failure");
        },
      });
      const ask = createAsk({
        command: undefined,
        surface: "bash",
        value: "python3 test.py",
        agentName: "reviewer",
        forwarding: {
          requesterAgentName: "reviewer",
          requesterSessionId: "session-xyz",
        },
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "python3 test.py",
          verdict: "defer",
          reason: "internal-error",
          agentName: "reviewer",
          requesterSessionId: "session-xyz",
        }),
      );
    });

    it("records null provenance when decide throws an internal error for direct parent ask", async () => {
      const log = createMockLog();
      const authorize = createAuthorizer({
        config: LIVE_CONFIG,
        readScript: () => {
          throw new Error("unexpected script reading failure");
        },
      });
      const ask = createAsk({
        command: "python3 test.py",
        surface: "bash",
      });

      const result = await authorize(ask, mockQuery, log as any);
      expect(result).toEqual({ kind: "defer" });
      expect(log.review).toHaveBeenCalledWith(
        DECISION_EVENT,
        expect.objectContaining({
          command: "python3 test.py",
          verdict: "defer",
          reason: "internal-error",
          agentName: null,
          requesterSessionId: null,
        }),
      );
    });
  });

  describe("extractProvenance helper", () => {
    it("prefers details.agentName when present", () => {
      const ask = createAsk({
        agentName: "primary-worker",
        forwarding: {
          requesterAgentName: "forwarded-worker",
          requesterSessionId: "sess-1",
        },
      });
      expect(extractProvenance(ask)).toEqual({
        agentName: "primary-worker",
        requesterSessionId: "sess-1",
      });
    });

    it("falls back to forwarding.requesterAgentName when agentName is missing or null", () => {
      const ask = createAsk({
        agentName: null,
        forwarding: {
          requesterAgentName: "forwarded-worker",
          requesterSessionId: "sess-1",
        },
      });
      expect(extractProvenance(ask)).toEqual({
        agentName: "forwarded-worker",
        requesterSessionId: "sess-1",
      });
    });

    it("falls back to forwarding.requesterAgentName when agentName is undefined", () => {
      const ask = createAsk({
        agentName: undefined as any,
        forwarding: {
          requesterAgentName: "forwarded-worker",
          requesterSessionId: "sess-1",
        },
      });
      expect(extractProvenance(ask)).toEqual({
        agentName: "forwarded-worker",
        requesterSessionId: "sess-1",
      });
    });

    it("returns null when neither agentName nor forwarding is provided", () => {
      const ask = createAsk({
        agentName: null,
      });
      expect(extractProvenance(ask)).toEqual({
        agentName: null,
        requesterSessionId: null,
      });
    });
  });
});
