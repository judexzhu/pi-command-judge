# 0004: Subagent Forwarded Ask Adjudication and Provenance

## Status
Accepted

## Context
When subagents run under `@gotgenes/pi-permission-system`, child sessions do not evaluate authorizer chain links locally (`adjudicatesLocally === false`). Instead, permission asks are forwarded upward to the serving parent session's inbox.

In `@gotgenes/pi-permission-system`, the parent session constructs `PromptPermissionDetails` for forwarded asks with `surface = "bash"` and `value = "<command>"`, but leaves `details.command` undefined. Because `pi-command-judge` strictly required `details.command`, all forwarded bash asks were immediately deferred to interactive human prompts, breaking automated subagent execution.

Furthermore, subagents may execute in git worktrees or custom subdirectories. Evaluating relative scripts against the parent session's `cwd` risks reading incorrect files or failing with false `not-found` defers.

## Decision
1. **Command Extraction Fallback**:
   - Extract the command via `details.command ?? (surface === "bash" ? details.value : undefined)`.
   - Allows the parent authorizer link to adjudicate forwarded subagent bash asks seamlessly.

2. **Scoped CWD Resolution for Scripts**:
   - Resolve the execution working directory for script evaluation using the child's `requesterCwd` from request metadata when present, falling back to parent `ctx.cwd`.
   - Preserve the containment boundary in `readScriptSafely`: scripts must resolve strictly inside the effective working directory. Attempts to execute files outside this directory trigger `outside-cwd` and defer to human confirmation.

3. **Subagent Provenance in Review Logs**:
   - Include `agentName` (from `details.agentName`) and `requesterSessionId` (from `details.forwarding?.requesterSessionId`) in the `command_judge.decision` audit entry.
   - Distinguishes direct parent actions from delegated subagent actions in downstream security audits.

## Consequences
- Subagent bash commands gain full access to fast-allow, hard-defer screening, and model judging without requiring separate link registration in child sessions.
- In-tree subagent scripts are verified against the subagent's actual working directory rather than the parent's.
- Containment invariants remain intact: reading external scripts still fails closed to manual confirmation.
- Audit trails clearly attribute verdicts to the requesting subagent.
