# pi-command-judge

[![npm version](https://img.shields.io/npm/v/pi-command-judge.svg)](https://www.npmjs.com/package/pi-command-judge)
[![CI](https://github.com/judexzhu/pi-command-judge/actions/workflows/ci.yml/badge.svg)](https://github.com/judexzhu/pi-command-judge/actions)

An `authorizerChain` link for [`@gotgenes/pi-permission-system`](https://github.com/gotgenes/pi-packages/tree/main/packages/pi-permission-system).
It reviews the **bash asks your rules leave over** and either **allows** them or **defers** them to you. It never denies.

```
bash ask ──► 0. fast-allow: deterministic safe reads (git status/diff/log, ls, grep, read-only cluster queries)
                 └─ match → auto-allow in <1ms without calling model
         ──► 1. hard-defer rules (deletes, pushes, cluster/cloud mutations, secrets, network, installs, sudo, indirection)
                 └─ match → your prompt, no model call
         ──► 2. script? read it (inside cwd only, ≤64 KB, text) and statically scan it
                 └─ unreadable or risky → your prompt (+ notification saying why)
         ──► 3. internal model (e.g. Qwen on vLLM, thinking off, guided JSON, logprobs)
                 allow only if: verdict=allow AND P(allow) ≥ 0.9 AND (scripts) effects show no deletes/network/mutations
         ──► anything else, any error or timeout → your prompt
```

Other surfaces (paths, outside-directory, MCP, skills) are untouched: the link defers them immediately.

## Install

Install via npm into your Pi environment:

```bash
npm install -g pi-command-judge
# or install in Pi:
pi install npm:pi-command-judge
```

Or clone and build locally:

```bash
git clone https://github.com/judexzhu/pi-command-judge.git
cd pi-command-judge && npm install
npm test            # 171 deterministic tests, no model needed
npm run try -- --no-model "oc delete pod x"
REPEAT=5 TIMEOUT_MS=30000 STRUCTURED=0 npm run try -- "make test"   # latency A/B
pi install ./       # or add to "packages" in ~/.pi/agent/settings.json
```

## Configure

1. **This extension**: copy `config/config.example.json` to
   `~/.pi/agent/extensions/pi-command-judge/config.json`. No file means the link is not registered.
2. **pi-permission-system**: add the link to `~/.pi/agent/extensions/pi-permission-system/config.json`:
   ```json
   { "authorizerChain": ["command-judge"] }
   ```
   Keep your tiered `permission` rules. The judge only sees what they `ask`.
3. **Protect the configs** from the agent, in the same file:
   ```json
   "path_write": { "*/.pi/agent/extensions/*": "ask", "*/.pi/extensions/*": "ask" }
   ```

## Roll out

| Week | Setting | Do |
|---|---|---|
| 1 | `"dryRun": true` (default) | Work normally. Every would-be allow is logged as `reason: "dry-run", wouldAllow: true`. |
| 1 | — | `npm run eval` with your endpoint. **FALSE ALLOWS must be 0.** Add your own cases to `evals/cases.jsonl`. |
| 2 | `"dryRun": false` | Only after a week of agreeing with every `wouldAllow` and a clean eval. |

```bash
BASE_URL=https://… API_KEY=… npm run eval -- --verbose
```

## Audit

Every decision is written to the shared review log as `command_judge.decision`:

```bash
jq -c 'select(.event=="command_judge.decision") | {command, verdict, stage, reason, pAllow, latencyMs}' \
  ~/.pi/agent/extensions/pi-permission-system/logs/pi-permission-system-permission-review.jsonl
```

Check the exact field layout with `head -1` on that file; the core may nest details differently.

## Config reference

| Key | Default | Notes |
|---|---|---|
| `provider` / `model` | `openai-compatible` / `Qwen/Qwen2.5-Coder-32B-Instruct` | Resolved through Pi's model registry; must be an `openai-completions` model (e.g. vLLM). |
| `dryRun` | `true` | Never allows; logs what it would have allowed. |
| `minAllowProbability` | `0.9` | From logprobs at the decision token. |
| `requireLogprobs` | `true` | If the endpoint returns none, defer. |
| `commandTimeoutMs` / `scriptTimeoutMs` | `4000` / `10000` | Timeout → defer. |
| `maxScriptBytes` | `65536` | Bigger scripts → defer. |
| `extraBody` | thinking off | Merged into the request body. |
| `extraHardDefer` | `[]` | Your own regexes, matched per normalized command segment and per shell-script line. |
| `notifyOnDefer` | `true` | Shows the judge's reason or effects summary when it defers a model or script decision. |
| `structuredOutput` | `true` | Schema-guided JSON via `response_format`. Set `false` if your server is slow with it; replies are then parsed defensively (anything malformed defers). |
| `warmup` | `true` | Two throwaway calls at session start, so the first real ask doesn't pay grammar-compile or connection costs. |
| `baseUrl` | `null` | Override the endpoint Pi resolves, e.g. to bypass a local proxy. Every decision logs the `endpoint` host it used. |
| `apiKeyEnv` | `null` | Take the API key from this env var instead of Pi's credentials. |
| `policy` | built-in | Replace the policy text the model sees (string or file path). |
| `extraPolicy` | `null` | Additional rules appended to the base policy (string or file path). |
| `customPromptInstructions` | `null` | Custom instructions injected into user prompt context (string or file path). |
| `hardDefer` | enabled | Fine-grained hard-defer control: `categories` toggles (`deletion`, `k8s`, `cloud`, `gitRemote`, `packages`, `privilege`, `network`, `database`, `system`, etc.) and `disabledRules` array. See [docs/hard-defer-rules.md](docs/hard-defer-rules.md) for full descriptions. |


## Known limits

- Control operators (`;`, `&&`, `||`, `|`, `&`, `\n`) are parsed with quote-awareness: pipes and semicolons inside quoted strings (e.g. `grep -E "a|b"`, `git log --grep="x; y"`) are safely preserved. Unquoted operators split into discrete segments for independent validation.
- Commands with `$( )`, backticks, `<( )` and heredocs trigger hard defers by design.
- Static script scans catch common patterns (deletes, obfuscation, shelling out with strings, network writes,
  cluster/cloud mutations, SDK mutations). A script that builds commands from variables goes to the model, which is
  told to defer when it can't trace effects. The eval set contains such cases; add your own.
- Scripts that call other local scripts or modules: only the entry file is read.
- The model sees the command and script. That data stays on your designated endpoint; don't point this at an external
  model for sensitive work without approval.
