/**
 * Calls an OpenAI-compatible /chat/completions endpoint (e.g. vLLM)
 * with guided JSON decoding and logprobs, so confidence comes from the model's
 * token probabilities rather than its own say-so.
 */

export interface Effects {
  reads: string[];
  writes: string[];
  deletes: string[];
  network: string[];
  cluster_or_cloud: string[];
  runs_other_code: boolean;
}

export interface JudgeCall {
  system: string;
  user: string;
  schema: Record<string, unknown>;
  maxTokens: number;
  timeoutMs: number;
}

export type JudgeResult =
  | {
      ok: true;
      decision: "allow" | "defer";
      reason: string;
      effects?: Effects;
      /** Probability mass on "allow" at the decision token, or null if logprobs were unavailable. */
      pAllow: number | null;
      latencyMs: number;
      raw: string;
    }
  | { ok: false; error: "timeout" | "http" | "unparseable" | "network"; detail: string; latencyMs: number };

export type JudgeFn = (call: JudgeCall) => Promise<JudgeResult>;

export interface EndpointConfig {
  baseUrl: string;
  modelId: string;
  apiKey?: string;
  headers?: Record<string, string>;
  extraBody: Record<string, unknown>;
  /** Send response_format json_schema (default true). */
  structuredOutput?: boolean;
}

interface LogprobEntry {
  token: string;
  logprob: number;
  top_logprobs?: Array<{ token: string; logprob: number }>;
}

export function createJudge(endpoint: EndpointConfig): JudgeFn {
  const url = `${endpoint.baseUrl.replace(/\/+$/, "")}/chat/completions`;
  return async (call) => {
    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), call.timeoutMs);
    try {
      const res = await fetch(url, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          ...(endpoint.apiKey ? { Authorization: `Bearer ${endpoint.apiKey}` } : {}),
          ...(endpoint.headers ?? {}),
        },
        body: JSON.stringify({
          model: endpoint.modelId,
          temperature: 0,
          max_tokens: call.maxTokens,
          logprobs: true,
          top_logprobs: 5,
          ...(endpoint.structuredOutput === false
            ? {}
            : {
                response_format: {
                  type: "json_schema",
                  json_schema: { name: "verdict", schema: call.schema, strict: true },
                },
              }),
          messages: [
            { role: "system", content: call.system },
            { role: "user", content: call.user },
          ],
          ...endpoint.extraBody,
        }),
      });
      const latencyMs = Date.now() - started;
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        return { ok: false, error: "http", detail: `${res.status} ${text.slice(0, 300)}`, latencyMs };
      }
      const body = (await res.json()) as {
        choices?: Array<{ message?: { content?: string }; logprobs?: { content?: LogprobEntry[] } }>;
      };
      const choice = body.choices?.[0];
      const raw = choice?.message?.content ?? "";
      return { ...parseVerdict(raw, choice?.logprobs?.content), latencyMs, raw } as JudgeResult;
    } catch (err) {
      const latencyMs = Date.now() - started;
      if (controller.signal.aborted) return { ok: false, error: "timeout", detail: `>${call.timeoutMs}ms`, latencyMs };
      return { ok: false, error: "network", detail: String(err).slice(0, 300), latencyMs };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** Parse the JSON verdict and compute P(allow). Anything malformed is an error, never an allow. */
export function parseVerdict(
  raw: string,
  logprobs?: LogprobEntry[],
):
  | { ok: true; decision: "allow" | "defer"; reason: string; effects?: Effects; pAllow: number | null }
  | { ok: false; error: "unparseable"; detail: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/g, ""));
  } catch {
    return { ok: false, error: "unparseable", detail: raw.slice(0, 300) };
  }
  const v = parsed as { decision?: unknown; reason?: unknown; effects?: unknown };
  if (v.decision !== "allow" && v.decision !== "defer") {
    return { ok: false, error: "unparseable", detail: `bad decision: ${String(v.decision)}` };
  }
  return {
    ok: true,
    decision: v.decision,
    reason: typeof v.reason === "string" ? v.reason : "",
    effects: isEffects(v.effects) ? v.effects : undefined,
    pAllow: logprobs ? allowProbability(logprobs) : null,
  };
}

/**
 * Locate the first token of the "decision" value and sum the probability of
 * alternatives that begin spelling "allow". Returns null if the token can't be found.
 */
export function allowProbability(entries: LogprobEntry[]): number | null {
  let text = "";
  for (const entry of entries) {
    if (/"decision"\s*:\s*"$/.test(text)) {
      const alts = entry.top_logprobs?.length ? entry.top_logprobs : [{ token: entry.token, logprob: entry.logprob }];
      let mass = 0;
      for (const alt of alts) {
        const t = alt.token.replace(/^\s*"?/, "");
        if (t.length > 0 && "allow".startsWith(t)) mass += Math.exp(alt.logprob);
      }
      return Math.min(1, mass);
    }
    text += entry.token;
    // Handle a token that carries both the opening quote and the value start, e.g. ` "allow`.
    const m = /"decision"\s*:\s*"([a-z]+)$/.exec(text);
    if (m) {
      const alts = entry.top_logprobs?.length ? entry.top_logprobs : [{ token: entry.token, logprob: entry.logprob }];
      let mass = 0;
      for (const alt of alts) {
        const value = /"?([a-z]+)$/.exec(alt.token)?.[1] ?? "";
        if (value.length > 0 && "allow".startsWith(value)) mass += Math.exp(alt.logprob);
      }
      return Math.min(1, mass);
    }
  }
  return null;
}

function isEffects(x: unknown): x is Effects {
  if (typeof x !== "object" || x === null) return false;
  const e = x as Record<string, unknown>;
  const arr = (k: string) => Array.isArray(e[k]) && (e[k] as unknown[]).every((s) => typeof s === "string");
  return (
    arr("reads") &&
    arr("writes") &&
    arr("deletes") &&
    arr("network") &&
    arr("cluster_or_cloud") &&
    typeof e.runs_other_code === "boolean"
  );
}
