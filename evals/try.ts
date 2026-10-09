/**
 * Try one command through the full pipeline, without Pi.
 *
 *   npm run try -- "oc get pods -n openshift-monitoring"
 *   npm run try -- --cwd ~/repo "python3 scripts/report.py"     # reads the real script from --cwd
 *   npm run try -- --no-model "rm -rf build"                     # hard rules and script scan only
 *
 * Model calls need BASE_URL and API_KEY (and optionally MODEL). Always runs live (dryRun off),
 * so you see what it would actually decide.
 *
 * Latency testing:
 *   REPEAT=5 TIMEOUT_MS=30000 npm run try -- "make test"                 # structured output (default)
 *   REPEAT=5 TIMEOUT_MS=30000 STRUCTURED=0 npm run try -- "make test"    # plain JSON
 */

import { resolve } from "node:path";

import { DEFAULT_CONFIG } from "../src/config.ts";
import { decide } from "../src/decide.ts";
import { createJudge, type JudgeFn } from "../src/judge-client.ts";
import { readScriptSafely } from "../src/scripts.ts";

const args = process.argv.slice(2);
let cwd = process.cwd();
let useModel = true;
const rest: string[] = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--cwd") cwd = resolve(args[++i] ?? ".");
  else if (args[i] === "--no-model") useModel = false;
  else rest.push(args[i]);
}
const command = rest.join(" ");
if (!command) {
  console.error('usage: npm run try -- [--cwd DIR] [--no-model] "<command>"');
  process.exit(2);
}

const baseUrl = process.env.BASE_URL;
if (useModel && !baseUrl) {
  console.error("BASE_URL not set: running hard rules and script scan only (or pass --no-model).");
  useModel = false;
}

const timeoutMs = Number(process.env.TIMEOUT_MS ?? DEFAULT_CONFIG.commandTimeoutMs);
const structuredOutput = process.env.STRUCTURED !== "0";
const repeat = Math.max(1, Number(process.env.REPEAT ?? 1));
const config = {
  ...DEFAULT_CONFIG,
  dryRun: false,
  structuredOutput,
  commandTimeoutMs: timeoutMs,
  scriptTimeoutMs: Math.max(timeoutMs, DEFAULT_CONFIG.scriptTimeoutMs),
};

const noModel: JudgeFn = async () => ({ ok: false, error: "network", detail: "model disabled (--no-model)", latencyMs: 0 });
const judge = useModel
  ? createJudge({
      baseUrl: baseUrl!,
      modelId: process.env.MODEL ?? DEFAULT_CONFIG.model,
      apiKey: process.env.API_KEY,
      extraBody: DEFAULT_CONFIG.extraBody,
      structuredOutput,
    })
  : noModel;

let last;
for (let i = 1; i <= repeat; i++) {
  last = await decide(
    { command, cwd },
    { config, extraHardDefer: [], judge, readScript: readScriptSafely },
  );
  if (repeat > 1) {
    const p = last.pAllow == null ? "-" : last.pAllow.toFixed(3);
    console.log(`#${i}  ${String(last.latencyMs ?? 0).padStart(6)}ms  ${last.verdict.padEnd(5)} ${last.reason.padEnd(20)} p=${p}`);
  }
}
console.log(JSON.stringify(last, null, 2));
console.error(`structuredOutput=${structuredOutput} timeoutMs=${timeoutMs}`);
