# 0003: Customer-Configurable Hard-Defers and Policies

## Status
Accepted

## Context
Previously, `pi-command-judge` enforced static, hardcoded hard-defer rules (`src/hard-defer.ts`) covering all deletions, git operations, cloud CLIs, and Kubernetes mutations. Operators working in isolated sandboxes (e.g. local `kind` clusters, throwaway dev VMs) were forced to manually approve every routine mutation because the static rules prevented requests from ever reaching the model judge.

Furthermore, customizing the evaluation policy required replacing the entire monolithic prompt in `config.json`, which was brittle to maintain across upstream updates.

## Decision
1. **Configurable Hard-Defers**:
   - Introduce `hardDefer` configuration with category-level toggles (`k8s`, `cloud`, `git`, `packages`, `privilege`, `deletion`, etc.) and granular `disabledRules: string[]`.
   - Bypassing or disabling a hard-defer rule does *not* auto-allow the command; it shifts evaluation from static defer to the model judge ($P(\text{allow}) \ge 0.90$).
   - Retain the fail-safe default: all hard-defer categories remain enabled unless explicitly opted out by the operator.

2. **Policy Composition & External Files**:
   - Support `policy` (full override) and `extraPolicy` (additive rules appended to base policy).
   - Support file paths (e.g. `~/.pi/policy.md` or `./policy.txt`) in addition to raw strings.
   - Support `customPromptInstructions` to enrich the model's user context while locking the schema output instructions to guarantee decision-token logprob extraction.

## Consequences
- Operators can tailor the judge to their risk tolerance (e.g., enabling model judgment for local k8s mutations while keeping cloud deletions hard-deferred).
- Base safety rules remain updatable without breaking customer customizations.
- Invariants for guided JSON schema parsing and token probability validation remain strictly protected.
