import axios from "axios";

type TransportErrorKind =
  | "timeout"
  | "connection_refused"
  | "dns"
  | "tls"
  | "network"
  | "aborted"
  | "unknown";

export type HttpResult = {
  ok: boolean;
  status?: number;
  data?: unknown;
  headers?: Record<string, string>;
  durationMs?: number;
  size?: number;
  error?: string;
  errorKind?: TransportErrorKind;
  transient?: boolean;
  attempts?: number;
};

type RequestBudgetConfig = {
  maxRps?: number;
  adaptiveBackoff?: boolean;
  penaltyMs?: number;
};

type EffectiveRequestBudget = {
  maxRps?: number;
  adaptiveBackoff: boolean;
  penaltyMs: number;
};

type HostBudgetState = {
  nextAt: number;
  queue: Promise<void>;
};

const activeBudgets = new Map<number, RequestBudgetConfig>();
const hostBudgets = new Map<string, HostBudgetState>();
let budgetTokenSeq = 0;
let effectiveBudget: EffectiveRequestBudget = {
  maxRps: undefined,
  adaptiveBackoff: false,
  penaltyMs: 750
};

export function acquireRequestBudget(config?: RequestBudgetConfig) {
  const token = ++budgetTokenSeq;
  activeBudgets.set(token, {
    maxRps:
      typeof config?.maxRps === "number" && Number.isFinite(config.maxRps) && config.maxRps > 0
        ? config.maxRps
        : undefined,
    adaptiveBackoff: config?.adaptiveBackoff === true,
    penaltyMs:
      typeof config?.penaltyMs === "number" && Number.isFinite(config.penaltyMs)
        ? Math.max(50, Math.round(config.penaltyMs))
        : 750
  });
  recomputeEffectiveBudget();
  return () => {
    activeBudgets.delete(token);
    recomputeEffectiveBudget();
  };
}

export async function httpRequest(opts: {
  baseUrl: string;
  method: string;
  path: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: any;
  timeoutMs?: number;
  maxRetries?: number;
  retryDelayMs?: number;
  retryBackoffFactor?: number;
  retryStatusCodes?: number[];
  retryUnsafeMethods?: boolean;
}): Promise<HttpResult> {
  const maxRetries =
    typeof opts.maxRetries === "number" && Number.isFinite(opts.maxRetries)
      ? Math.max(0, Math.floor(opts.maxRetries))
      : 2;
  const retryDelayMs =
    typeof opts.retryDelayMs === "number" && Number.isFinite(opts.retryDelayMs)
      ? Math.max(10, Math.floor(opts.retryDelayMs))
      : 200;
  const retryBackoffFactor =
    typeof opts.retryBackoffFactor === "number" && Number.isFinite(opts.retryBackoffFactor)
      ? Math.max(1, opts.retryBackoffFactor)
      : 2;
  const retryStatusCodes = new Set(
    Array.isArray(opts.retryStatusCodes) && opts.retryStatusCodes.length
      ? opts.retryStatusCodes
      : [408, 425, 429, 502, 503, 504]
  );
  const method = String(opts.method ?? "GET").toUpperCase();
  const isSafeMethod = method === "GET" || method === "HEAD" || method === "OPTIONS";
  const canRetryStatus = opts.retryUnsafeMethods === true ? true : isSafeMethod;

  let lastError: any = undefined;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      await waitForBudgetSlot(opts.baseUrl);
      const started = Date.now();
      const res = await axios.request({
        baseURL: opts.baseUrl,
        url: opts.path,
        method: opts.method as any,
        params: opts.query,
        data: opts.body,
        headers: opts.headers,
        timeout: opts.timeoutMs ?? 7000,
        maxRedirects: 0,
        validateStatus: () => true
      });
      const durationMs = Date.now() - started;
      const dataStr = typeof res.data === "string" ? res.data : JSON.stringify(res.data ?? {});
      const status = res.status;
      const retriableStatus =
        canRetryStatus && retryStatusCodes.has(status) && attempt <= maxRetries;
      maybeApplyAdaptiveBackoff(opts.baseUrl, status, res.headers);
      if (retriableStatus) {
        const retryAfterMs = parseRetryAfterMs(res.headers?.["retry-after"]);
        const waitMs =
          typeof retryAfterMs === "number"
            ? retryAfterMs
            : Math.round(retryDelayMs * Math.pow(retryBackoffFactor, attempt - 1));
        await sleep(waitMs);
        continue;
      }
      return {
        ok: true,
        status,
        data: res.data,
        headers: res.headers as Record<string, string>,
        durationMs,
        size: dataStr.length,
        attempts: attempt
      };
    } catch (e: any) {
      lastError = e;
      const c = classifyTransportError(e);
      const canRetry = c.transient && attempt <= maxRetries;
      if (!canRetry) {
        return {
          ok: false,
          error: formatTransportError(c.kind, e),
          errorKind: c.kind,
          transient: c.transient,
          attempts: attempt
        };
      }
      const waitMs = Math.round(retryDelayMs * Math.pow(retryBackoffFactor, attempt - 1));
      await sleep(waitMs);
    }
  }

  const c = classifyTransportError(lastError);
  return {
    ok: false,
    error: formatTransportError(c.kind, lastError),
    errorKind: c.kind,
    transient: c.transient,
    attempts: maxRetries + 1
  };
}

function sleep(ms: number) {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function waitForBudgetSlot(baseUrl: string) {
  const maxRps = effectiveBudget.maxRps;
  if (!maxRps || maxRps <= 0) return;
  const host = hostKeyFromBaseUrl(baseUrl);
  const intervalMs = Math.max(1, Math.ceil(1000 / maxRps));
  let state = hostBudgets.get(host);
  if (!state) {
    state = { nextAt: 0, queue: Promise.resolve() };
    hostBudgets.set(host, state);
  }
  state.queue = state.queue.then(async () => {
    const now = Date.now();
    const waitMs = Math.max(0, state!.nextAt - now);
    if (waitMs > 0) await sleep(waitMs);
    const at = Math.max(Date.now(), state!.nextAt);
    state!.nextAt = at + intervalMs;
  });
  await state.queue;
}

function maybeApplyAdaptiveBackoff(baseUrl: string, status: number, headers?: Record<string, any>) {
  if (!effectiveBudget.adaptiveBackoff) return;
  if (status !== 429 && status !== 503) return;
  const retryAfter = parseRetryAfterMs(headers?.["retry-after"]);
  const penalty = typeof retryAfter === "number" ? retryAfter : effectiveBudget.penaltyMs;
  applyHostPenalty(baseUrl, penalty);
}

function applyHostPenalty(baseUrl: string, ms: number) {
  const host = hostKeyFromBaseUrl(baseUrl);
  let state = hostBudgets.get(host);
  if (!state) {
    state = { nextAt: 0, queue: Promise.resolve() };
    hostBudgets.set(host, state);
  }
  state.nextAt = Math.max(state.nextAt, Date.now() + Math.max(0, Math.round(ms)));
}

function hostKeyFromBaseUrl(baseUrl: string) {
  try {
    const u = new URL(baseUrl);
    return `${u.protocol}//${u.host}`.toLowerCase();
  } catch {
    return String(baseUrl ?? "").toLowerCase();
  }
}

function recomputeEffectiveBudget() {
  let maxRps: number | undefined = undefined;
  let adaptiveBackoff = false;
  let penaltyMs = 750;
  for (const cfg of activeBudgets.values()) {
    if (typeof cfg.maxRps === "number" && cfg.maxRps > 0) {
      maxRps = typeof maxRps === "number" ? Math.min(maxRps, cfg.maxRps) : cfg.maxRps;
    }
    if (cfg.adaptiveBackoff) adaptiveBackoff = true;
    if (typeof cfg.penaltyMs === "number" && cfg.penaltyMs > penaltyMs) penaltyMs = cfg.penaltyMs;
  }
  effectiveBudget = { maxRps, adaptiveBackoff, penaltyMs };
}

function parseRetryAfterMs(value: unknown): number | undefined {
  const str = Array.isArray(value) ? String(value[0] ?? "") : String(value ?? "");
  if (!str.trim()) return undefined;
  const sec = Number(str);
  if (Number.isFinite(sec) && sec >= 0) return Math.round(sec * 1000);
  const timestamp = Date.parse(str);
  if (!Number.isFinite(timestamp)) return undefined;
  const delta = timestamp - Date.now();
  return delta > 0 ? delta : 0;
}

function formatTransportError(kind: TransportErrorKind, err: any) {
  const msg = String(err?.message ?? err ?? "unknown transport error").trim();
  return `[${kind}] ${msg}`;
}

function classifyTransportError(err: any): { kind: TransportErrorKind; transient: boolean } {
  const code = String(err?.code ?? "").toUpperCase();
  const msg = String(err?.message ?? "").toLowerCase();

  if (code === "ECONNABORTED" || code === "ETIMEDOUT" || msg.includes("timeout")) {
    return { kind: "timeout", transient: true };
  }
  if (code === "ECONNREFUSED") {
    return { kind: "connection_refused", transient: true };
  }
  if (code === "ENOTFOUND") {
    return { kind: "dns", transient: false };
  }
  if (code === "EAI_AGAIN") {
    return { kind: "dns", transient: true };
  }
  if (code === "ERR_TLS_CERT_ALTNAME_INVALID" || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE") {
    return { kind: "tls", transient: false };
  }
  if (code === "ERR_CANCELED") {
    return { kind: "aborted", transient: false };
  }
  if (
    code === "ECONNRESET" ||
    code === "EPIPE" ||
    code === "ENETUNREACH" ||
    code === "EHOSTUNREACH"
  ) {
    return { kind: "network", transient: true };
  }
  return { kind: "unknown", transient: false };
}
