import type { PermissionQuery, PromptPermissionDetails } from "@gotgenes/pi-permission-system";
import { describe, expect, it, vi } from "vitest";

import { createAuthorizer, DECISION_EVENT, LINK_NAME } from "../src/authorizer.ts";
import { DEFAULT_CONFIG, type CommandJudgeConfig } from "../src/config.ts";

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
});
