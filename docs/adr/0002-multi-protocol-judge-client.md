# 0002: Multi-Protocol Support for Judge Client (Completions vs Responses)

## Status
Accepted

## Context
`pi-command-judge` previously assumed an `openai-completions` API endpoint (`/v1/chat/completions`) primarily targeting self-hosted inference servers (e.g., vLLM). Pi core standardizes upstream OpenAI models (e.g. `gpt-4.1-mini`, `gpt-4o`) under the `openai-responses` API wire protocol (`/v1/responses`).

When users configured native OpenAI models as judges, the authorizer link aborted with `unsupported-api:openai-responses`, falling back to deferring every bash command.

## Decision
1. Support both `openai-completions` and `openai-responses` wire protocols in `createJudge`.
2. Keep strict safety invariants: fail-safe by default. If `requireLogprobs: true` (default) and an endpoint or model returns no logprobs, defer (`reason: "no-logprobs"`).
3. Extract wire protocol marshalling into dedicated strategy adapters (`chat-completions` vs `responses`) within `src/judge-client.ts` to isolate schema constraints (`response_format` vs `text.format`) and logprob extraction while preserving a single unified `JudgeFn` interface.
4. Auto-detect protocol via model registry `model.api` field during resolution.

## Consequences
- Native Pi OpenAI models and compatible gateways can serve directly as command judges without custom proxying.
- Logprob extraction continues to power the $P(\text{allow}) \ge 0.90$ confidence threshold.
- Fail-safe invariant is preserved across both protocols.
