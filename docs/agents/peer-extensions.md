# Peer Extensions

Documents peer extension integration points and runtime filesystem topology.

## `@gotgenes/pi-permission-system`

`pi-command-judge` intercepts and adjudicates asks forwarded by `@gotgenes/pi-permission-system`.

### Runtime Filesystem Topology

Permission forwarding persists active session artifacts in `~/.pi/agent/sessions/permission-forwarding/`:

```
~/.pi/agent/sessions/permission-forwarding/
└── sessions/
    └── <sessionId>/
        ├── requests/
        │   └── <requestId>.json
        ├── responses/
        └── heartbeat.json
```

### In-Memory vs. On-Disk Facts

- **Wire request record (`requests/<requestId>.json`)**:
  Contains raw `ForwardedAccessIntent` properties:
  - `agentName`: Subagent name.
  - `requesterSessionId`: Originating subagent session ID.
  - `requesterCwd`: Child worktree or working directory where the subagent executed.

- **In-memory `PromptPermissionDetails`**:
  Upstream's `toAccessFacts()` projects the wire request into prompt facts, omitting `requesterCwd`.
  `src/authorizer.ts` resolves working directory via:
  1. In-memory `details.accessIntent.requesterCwd` (if present).
  2. Fallback disk lookup in `~/.pi/agent/sessions/permission-forwarding/sessions/*/requests/<requestId>.json`.
  3. Parent agent context `ctx.cwd`.

### Test Fixture Guidelines

When writing integration tests with peer extension structures:

- Do not use `as any` to smuggle unprojected properties directly into `PromptPermissionDetails`.
- Test helpers must model both the in-memory projection and the on-disk request file to prevent mock contract drift.
