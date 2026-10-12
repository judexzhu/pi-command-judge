# 0004: Subagent Forwarded Ask Adjudication and Provenance

## Status
Accepted

## Context
When subagents run under `@gotgenes/pi-permission-system`, child sessions do not evaluate authorizer chain links locally (`adjudicatesLocally === false`). Instead, permission asks are forwarded upward to the serving parent session's inbox.

In `@gotgenes/pi-permission-system`, the parent session constructs `PromptPermissionDetails` for forwarded asks with `surface = "bash"` and `value = "<command>"`, but leaves `details.command` undefined. Because `pi-command-judge` strictly required `details.command`, all forwarded bash asks were immediately deferred to interactive human prompts, breaking automated subagent execution.

Furthermore, subagents may execute in git worktrees or custom subdirectories. Evaluating relative scripts against the parent session's `cwd` risks reading incorrect files or failing with false `not-found` defers.

## Decision
1. **Command Extraction & Surface Gating**:
   - Resolve surface from `details.accessIntent?.surface ?? details.surface ?? null`. If `surface !== "bash"`, defer immediately without evaluating.
   - Extract the command via `details.command ?? (typeof details.value === "string" ? details.value : undefined)`.
   - Allows the parent authorizer link to adjudicate forwarded subagent bash asks seamlessly.
   - On deferral, optionally trigger parent UI toast notification (`ui.notify`) when configured (`notifyOnDefer = true`).

2. **Scoped CWD Resolution for Scripts**:
   - Resolve the execution working directory for script evaluation via `resolveRequesterCwd`:
     1. In-memory `requesterCwd` from `details.accessIntent.requesterCwd`, `(details as any).requesterCwd`, or `details.forwarding.requesterCwd`.
     2. Runtime forwarded request inspection: if `details.requestId` is present, read the request record from `~/.pi/agent/sessions/permission-forwarding/sessions/*/requests/<requestId>.json` where the wire `ForwardedAccessIntent` retains `requesterCwd` before upstream's `toAccessFacts` strips it.
     3. Fallback to parent `ctx.cwd`.
   - Preserve the containment boundary in `readScriptSafely`: scripts must resolve strictly inside the effective working directory. Attempts to execute files outside this directory trigger `outside-cwd` and defer to human confirmation.

3. **Subagent Provenance in Review Logs**:
   - Extract provenance:
     - `agentName`: `details.agentName ?? details.forwarding?.requesterAgentName ?? null`.
     - `requesterSessionId`: `details.forwarding?.requesterSessionId ?? null`.
   - Include `agentName` and `requesterSessionId` in all `command_judge.decision` audit entries (both normal decisions and internal errors).
   - Upstream `@gotgenes/pi-permission-system` uses flat depth-1 forwarding (all child and nested subagents escalate directly to the root serving session). Therefore, single-hop forwarding provenance directly captures the executing subagent identity.

## Consequences
- Subagent bash commands gain full access to fast-allow, hard-defer screening, and model judging without requiring separate link registration in child sessions.
- In-tree subagent scripts are verified against the subagent's actual working directory rather than the parent's, both via in-memory metadata and filesystem request inspection.
- Containment invariants remain intact: reading external scripts still fails closed to manual confirmation.
- Audit trails clearly attribute verdicts to the requesting subagent.
