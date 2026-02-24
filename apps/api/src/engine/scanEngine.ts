import YAML from "yaml";
import FormData from "form-data";
import { AsyncLocalStorage } from "node:async_hooks";
import { createHmac, createPrivateKey, createSign } from "node:crypto";
import { parseOpenApiDetailed, parseOpenApiDetailedNoValidate, type EndpointDetail } from "../openapi";
import { acquireRequestBudget, httpRequest as transportHttpRequest } from "./runner";
import { generateSqlInjectionTests, type SqlTest } from "./generators/sqlInjection";
import { generateXssTests, type XssTest } from "./generators/xss";
import { generateOpenRedirectTests, type OpenRedirectTest } from "./generators/openRedirect";
import { generateHeaderInjectionTests, type HeaderInjectionTest } from "./generators/headerInjection";
import { generateSsrfTests, type SsrfTest } from "./generators/ssrf";
import { generateTemplateInjectionTests, type TemplateInjectionTest } from "./generators/templateInjection";
import { generatePathTraversalTests, type PathTraversalTest } from "./generators/pathTraversal";

type SeedFile = { id: string; buffer: Buffer; filename?: string; mimetype?: string };
const seedFiles = new Map<string, SeedFile>();
const SCANNER_HTTP_TRACE_ENABLED = process.env.DAST_HTTP_TRACE === "1";
const SCANNER_HTTP_DEBUG_CAPTURE_ENABLED = process.env.DAST_HTTP_DEBUG_CAPTURE !== "0";

export function registerSeedFile(file: SeedFile) {
  seedFiles.set(file.id, file);
}

export type AuthConfig = {
  bearerToken?: string;
  apiKey?: { headerName?: string; value?: string };
  customHeaders?: { key: string; value: string }[];
  basic?: { username?: string; password?: string };
  jwt?: {
    mode?: "existing" | "generate";
    existingToken?: string;
    algorithm?: "HS256" | "HS384" | "HS512" | "RS256";
    secretOrPrivateKey?: string;
    secretBase64?: boolean;
    header?: Record<string, unknown>;
    payload?: Record<string, unknown>;
    tokenLocation?: "authorization" | "custom_header" | "query";
    customHeaderName?: string;
    queryParamName?: string;
    tokenPrefix?: string;
  };
};

type AuthRuntime = {
  apply: (headers?: Record<string, string>, query?: Record<string, string>) => { headers?: Record<string, string>; query?: Record<string, string> };
};

const authRuntimeStore = new AsyncLocalStorage<AuthRuntime | undefined>();
type HttpDebugSnapshot = {
  requestUrl?: string;
  requestHeaders?: Record<string, string>;
  requestBody?: string;
  requestBodyTruncated?: boolean;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  responseBodyTruncated?: boolean;
};
const httpDebugStore = new AsyncLocalStorage<{ lastHttpDebug?: HttpDebugSnapshot }>();

async function httpRequest(opts: {
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
  skipAuth?: boolean;
}) {
  const { skipAuth, ...transportOpts } = opts;
  const startedAt = Date.now();

  if (skipAuth) {
    const result = await transportHttpRequest(transportOpts);
    storeLastHttpDebug(transportOpts, result);
    logScannerHttpTrace({ opts: transportOpts, result, startedAt, skipAuth: true });
    return result;
  }
  const runtime = authRuntimeStore.getStore();
  if (!runtime) {
    const result = await transportHttpRequest(transportOpts);
    storeLastHttpDebug(transportOpts, result);
    logScannerHttpTrace({ opts: transportOpts, result, startedAt, skipAuth: false });
    return result;
  }
  const applied = runtime.apply(transportOpts.headers, transportOpts.query);
  const finalOpts = {
    ...transportOpts,
    headers: applied.headers,
    query: applied.query
  };
  const result = await transportHttpRequest(finalOpts);
  storeLastHttpDebug(finalOpts, result);
  logScannerHttpTrace({ opts: finalOpts, result, startedAt, skipAuth: false });
  return result;
}

function storeLastHttpDebug(
  opts: {
    baseUrl: string;
    method: string;
    path: string;
    headers?: Record<string, string>;
    query?: Record<string, string>;
    body?: unknown;
  },
  result: Awaited<ReturnType<typeof transportHttpRequest>>
) {
  if (!SCANNER_HTTP_DEBUG_CAPTURE_ENABLED) return;
  const store = httpDebugStore.getStore();
  if (!store) return;

  const requestHeaders = maskSensitiveHeaders(opts.headers);
  const requestBodyPreview = previewDebugBody(opts.body);
  const responseHeaders = maskSensitiveHeaders(result.headers);
  const responseBodyPreview = previewDebugBody(result.data);

  store.lastHttpDebug = {
    requestUrl: buildRequestUrl(opts.baseUrl, opts.path, opts.query),
    requestHeaders: requestHeaders && Object.keys(requestHeaders).length ? requestHeaders : undefined,
    requestBody: requestBodyPreview.text,
    requestBodyTruncated: requestBodyPreview.truncated || undefined,
    responseHeaders: responseHeaders && Object.keys(responseHeaders).length ? responseHeaders : undefined,
    responseBody: responseBodyPreview.text,
    responseBodyTruncated: responseBodyPreview.truncated || undefined
  };
}

function logScannerHttpTrace(args: {
  opts: {
    baseUrl: string;
    method: string;
    path: string;
    query?: Record<string, string>;
  };
  result: Awaited<ReturnType<typeof transportHttpRequest>>;
  startedAt: number;
  skipAuth: boolean;
}) {
  if (!SCANNER_HTTP_TRACE_ENABLED) return;
  const { opts, result, startedAt, skipAuth } = args;
  const method = String(opts.method ?? "GET").toUpperCase();
  const url = buildTraceUrl(opts.baseUrl, opts.path);
  const queryKeys = Object.keys(opts.query ?? {}).filter(Boolean);
  const elapsed = Date.now() - startedAt;
  const queryMeta = queryKeys.length ? ` queryKeys=${queryKeys.join(",")}` : "";
  const authMeta = skipAuth ? " auth=skipped" : "";

  if (result.ok) {
    console.info(
      `[scanner:http] ${method} ${url} -> ${result.status ?? "?"} ${elapsed}ms${queryMeta}${authMeta}`
    );
    return;
  }

  console.warn(
    `[scanner:http] ${method} ${url} -> ERROR ${elapsed}ms kind=${result.errorKind ?? "unknown"}${queryMeta}${authMeta} msg=${String(result.error ?? "").slice(0, 180)}`
  );
}

function buildTraceUrl(baseUrl: string, path: string) {
  try {
    const u = new URL(String(path ?? ""), String(baseUrl ?? ""));
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    const b = String(baseUrl ?? "").replace(/\/+$/, "");
    const p = String(path ?? "");
    return p ? `${b}/${p.replace(/^\/+/, "")}` : b;
  }
}

function maskSensitiveHeaders(headers?: Record<string, string>) {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = String(k);
    const lower = key.toLowerCase();
    if (
      lower === "authorization" ||
      lower === "cookie" ||
      lower === "set-cookie" ||
      lower.includes("token") ||
      lower.includes("secret") ||
      lower.includes("api-key") ||
      lower.includes("apikey")
    ) {
      out[key] = "***";
    } else {
      out[key] = String(v);
    }
  }
  return out;
}

function previewDebugBody(body: unknown): { text?: string; truncated: boolean } {
  if (body == null) return { text: undefined, truncated: false };

  let text = "";
  try {
    if (typeof body === "string") {
      text = maskSecretsInStringBody(body);
    } else if (Buffer.isBuffer(body)) {
      text = `<Buffer ${body.length} bytes>`;
    } else if (typeof body === "object") {
      text = JSON.stringify(maskSecretsInObject(body));
    } else {
      text = String(body);
    }
  } catch {
    text = "<nie udało się zserializować treści>";
  }

  return { text, truncated: false };
}

function maskSecretsInStringBody(input: string) {
  const trimmed = input.trim();
  if (!trimmed) return input;
  try {
    const parsed = JSON.parse(trimmed);
    return JSON.stringify(maskSecretsInObject(parsed));
  } catch {
    // ignore non-json body
  }
  return input.replace(
    /\b(password|passwd|secret|token|access_token|refresh_token|api[_-]?key)\b\s*([=:])\s*([^&\s]+)/gi,
    (_m, key, sep) => `${key}${sep}***`
  );
}

function maskSecretsInObject(value: any): any {
  if (Array.isArray(value)) return value.map(maskSecretsInObject);
  if (!value || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    const lower = k.toLowerCase();
    if (
      lower.includes("password") ||
      lower.includes("secret") ||
      lower.includes("token") ||
      lower === "authorization" ||
      lower.includes("api_key") ||
      lower.includes("apikey")
    ) {
      out[k] = "***";
    } else {
      out[k] = maskSecretsInObject(v);
    }
  }
  return out;
}

export type ThrottleConfig = {
  mode?: "none" | "rps" | "delay";
  value?: number;
};

export type SmartTestConfig = {
  testVolume?: "low" | "medium" | "high";
  requestConcurrency?: number;
  maxTotalTests?: number;
  globalMaxRps?: number;
  adaptiveRequestBackoff?: boolean;
  requestBackoffPenaltyMs?: number;
  baselineIncludeUnsafeMethods?: boolean;
  fuzzDepth?: number;
  bodyFieldLimit?: number;
  anomalySensitivity?: "low" | "medium" | "high";
  riskScoring?: boolean;
  riskWeights?: {
    AUTH?: number;
    SQLi?: number;
    XSS?: number;
    PATH_TRAVERSAL?: number;
    TEMPLATE_INJECTION?: number;
    SSRF?: number;
    HEADER_INJECTION?: number;
    OPEN_REDIRECT?: number;
    RATE_LIMIT?: number;
    FUZZ?: number;
  };
  inconclusiveMultiplier?: number;
  responseValidation?: "off" | "warn" | "strict";
  enabledTests?: {
    SQLi?: boolean;
    XSS?: boolean;
    PATH_TRAVERSAL?: boolean;
    TEMPLATE_INJECTION?: boolean;
    SSRF?: boolean;
    HEADER_INJECTION?: boolean;
    OPEN_REDIRECT?: boolean;
    FUZZ?: boolean;
    AUTH?: boolean;
    RATE_LIMIT?: boolean;
  };
};

export type SeedConfig = {
  enabled?: boolean;
  createEndpoints?: Array<{
    method: string;
    path: string;
    inputMode?: "none" | "json" | "form" | "multipart" | "binary";
    contentType?: string;
    accept?: string;
    headers?: string[];
    security?: string[];
    idExtractor?: string | null;
    resourceKey?: string;
    enabled?: boolean;
    payload?: any;
    files?: Record<string, { fileId: string }>;
    query?: Record<string, string>;
    headers?: Record<string, string>;
  }>;
};

type BaselineResult = {
  ok: boolean;
  status?: number;
  size?: number;
  timeMs?: number;
  contentType?: string;
  jsonSignature?: string;
  sampleCount?: number;
  successCount?: number;
  unstable?: boolean;
  statusVariance?: number;
  sizeVarianceRatio?: number;
  timeVarianceRatio?: number;
};

type FuzzTest = {
  method: string;
  path: string;
  payload: string;
  location: "body" | "query" | "path" | "header" | "cookie";
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: any;
  contentType?: string;
  originalPath?: string;
  expectedResponseSchema?: any;
};

export type ScanStatus = "queued" | "running" | "finished";

export type ScanEvent =
  | { type: "connected"; scanId: string; status: ScanStatus }
  | { type: "scan_started" }
  | { type: "step"; message: string }
  | { type: "scan_finished" }
  | {
      type: "test_result";
      testType:
        | "SQLi"
        | "XSS"
        | "PATH_TRAVERSAL"
        | "TEMPLATE_INJECTION"
        | "SSRF"
        | "HEADER_INJECTION"
        | "OPEN_REDIRECT"
        | "AUTH"
        | "FUZZ"
        | "RATE_LIMIT";
      method: string;
      path: string;
      payload: string;
      location?: "body" | "query" | "path" | "header" | "cookie";
      ok: boolean;
      verdict?: "ok" | "suspicious" | "inconclusive" | "error";
      baselineStatus?: number;
      baselineSize?: number;
      status?: number;
      responseTimeMs?: number;
      responseSize?: number;
      responseHeaders?: Record<string, string>;
      requestUrl?: string;
      debugRequestHeaders?: Record<string, string>;
      debugRequestBody?: string;
      debugRequestBodyTruncated?: boolean;
      debugResponseHeaders?: Record<string, string>;
      debugResponseBody?: string;
      debugResponseBodyTruncated?: boolean;
      suspicious?: boolean;
      evidence?: string;
      schemaIssues?: string[];
      error?: string;
    };

export async function runScan(args: {
  scanId: string;
  openApi?: unknown;
  openApiText?: string;
  baseUrl?: string;
  auth?: AuthConfig;
  throttle?: ThrottleConfig;
  seed?: SeedConfig | boolean;
  smart?: SmartTestConfig;
  emit: (ev: ScanEvent) => void;
  setEndpoints: (endpoints: Endpoint[]) => void;
  setReport: (r: { totalTests: number; totalErrors: number; totalSuspicious: number }) => void;
  setSeedResults: (seeds: { method: string; path: string; resourceKey: string; id?: string; status: "ok" | "error" | "no_id"; message?: string }[]) => void;
}) {
  const {
    openApi,
    openApiText,
    baseUrl,
    auth,
    throttle,
    seed,
    smart,
    emit: rawEmit,
    setEndpoints,
    setReport,
    setSeedResults
  } = args;

  const releaseRequestBudget = acquireRequestBudget({
    maxRps: smart?.globalMaxRps,
    adaptiveBackoff: smart?.adaptiveRequestBackoff === true,
    penaltyMs: smart?.requestBackoffPenaltyMs
  });
  const authRuntime = createAuthRuntime(auth);
  const emit = (ev: ScanEvent) => {
    if (ev.type !== "test_result" || !SCANNER_HTTP_DEBUG_CAPTURE_ENABLED) {
      rawEmit(ev);
      return;
    }
    const store = httpDebugStore.getStore();
    const debug = store?.lastHttpDebug;
    if (!debug) {
      rawEmit(ev);
      return;
    }
    store!.lastHttpDebug = undefined;
    rawEmit({
      ...ev,
      debugRequestHeaders: debug.requestHeaders,
      debugRequestBody: debug.requestBody,
      debugRequestBodyTruncated: debug.requestBodyTruncated,
      debugResponseHeaders: debug.responseHeaders,
      debugResponseBody: debug.responseBody,
      debugResponseBodyTruncated: debug.responseBodyTruncated
    });
  };

  try {
    await httpDebugStore.run({}, async () => authRuntimeStore.run(authRuntime, async () => {
    emit({ type: "scan_started" });

  // 1) Build spec object + unwrap wrappers
  let specObj: any = openApi;
  if (!specObj && typeof openApiText === "string" && openApiText.trim()) {
    try {
      specObj = JSON.parse(openApiText);
    } catch {
      specObj = YAML.parse(openApiText);
    }
  }

  if (specObj && typeof specObj === "object" && (specObj as any).openApi) {
    specObj = (specObj as any).openApi;
  }
  if (specObj && typeof specObj === "object" && (specObj as any).spec) {
    specObj = (specObj as any).spec;
  }

  if (!specObj) {
    emit({ type: "step", message: "Brak specyfikacji OpenAPI." });
    setReport({ totalTests: 0, totalErrors: 0, totalSuspicious: 0 });
    emit({ type: "scan_finished" });
    return;
  }

  if (specObj && typeof specObj === "object" && typeof specObj.openapi === "string") {
    if (specObj.openapi.startsWith("3.2")) {
      emit({
        type: "step",
        message:
          "Uwaga: OpenAPI 3.2.x nie jest obsługiwane przez parser. Próbuję zfallbackować do 3.1.0."
      });
      specObj = { ...specObj, openapi: "3.1.0" };
    }
  }

  // 2) Parse endpoints
  let endpoints: EndpointDetail[] = [];
  try {
    endpoints = await parseOpenApiDetailed(specObj);
    setEndpoints(endpoints.map((e) => ({ method: e.method, path: e.path })));

    emit({ type: "step", message: `Parsed ${endpoints.length} endpoints from OpenAPI` });
    for (const ep of endpoints.slice(0, 10)) {
      emit({ type: "step", message: `${ep.method} ${ep.path}` });
    }

    const multipart = endpoints.filter((e) =>
      (e.requestBodyContentTypes ?? []).some((t) => t.includes("multipart/form-data"))
    );
    if (multipart.length) {
      emit({
        type: "step",
        message: `Wykryto uploady (multipart): ${multipart.length} endpointów — testy bez plików mogą być ograniczone.`
      });
    }
  } catch (e: any) {
    const msg =
      typeof e?.message === "string" ? e.message : typeof e === "string" ? e : JSON.stringify(e);

    if (msg.includes("Missing $ref pointer")) {
      emit({
        type: "step",
        message:
          "Uwaga: spec ma brakujące $ref. Kontynuuję bez pełnej walidacji (mogą być ograniczone body)."
      });
      try {
        endpoints = parseOpenApiDetailedNoValidate(specObj);
        setEndpoints(endpoints.map((e) => ({ method: e.method, path: e.path })));
      } catch (fallbackErr: any) {
        const fb =
          typeof fallbackErr?.message === "string"
            ? fallbackErr.message
            : typeof fallbackErr === "string"
            ? fallbackErr
            : JSON.stringify(fallbackErr);
        emit({ type: "step", message: `Failed to parse OpenAPI specification: ${fb}` });
        setReport({ totalTests: 0, totalErrors: 0, totalSuspicious: 0 });
        emit({ type: "scan_finished" });
        return;
      }
    } else {
      emit({ type: "step", message: `Failed to parse OpenAPI specification: ${msg}` });
      setReport({ totalTests: 0, totalErrors: 0, totalSuspicious: 0 });
      emit({ type: "scan_finished" });
      return;
    }
  }

  const smartCfg = resolveSmartConfig(smart);
  const volumeLimits = resolveVolumeLimits(smartCfg.testVolume);
  const anomalySensitivity = smartCfg.anomalySensitivity ?? "medium";
  const responseValidation = smartCfg.responseValidation ?? "warn";
  const baselineSamples = resolveBaselineSampleCount(smartCfg.testVolume);
  const requestConcurrency = smartCfg.requestConcurrency ?? 1;
  const maxTotalTests = smartCfg.maxTotalTests;
  const baselineIncludeUnsafeMethods = smartCfg.baselineIncludeUnsafeMethods === true;
  const enabled = smartCfg.enabledTests ?? {
    SQLi: true,
    XSS: true,
    PATH_TRAVERSAL: true,
    TEMPLATE_INJECTION: true,
    SSRF: true,
    HEADER_INJECTION: true,
    OPEN_REDIRECT: true,
    FUZZ: true,
    AUTH: true,
    RATE_LIMIT: true
  };

  // 3) Generate SQLi tests
  emit({ type: "step", message: "Generowanie testów SQL Injection..." });
  const sqlTests = enabled.SQLi
    ? dedupeGeneratedTests(generateSqlInjectionTests(endpoints, volumeLimits))
    : [];
  emit({ type: "step", message: `Wygenerowano ${sqlTests.length} testów SQL Injection.` });

  // 4) Generate XSS tests
  emit({ type: "step", message: "Generowanie testów XSS..." });
  const xssTests = enabled.XSS ? dedupeGeneratedTests(generateXssTests(endpoints, volumeLimits)) : [];
  emit({ type: "step", message: `Wygenerowano ${xssTests.length} testów XSS.` });

  // 4.015625) Generate Path Traversal tests
  emit({ type: "step", message: "Generowanie testów Path Traversal..." });
  const pathTraversalTests = enabled.PATH_TRAVERSAL
    ? dedupeGeneratedTests(generatePathTraversalTests(endpoints, volumeLimits))
    : [];
  emit({ type: "step", message: `Wygenerowano ${pathTraversalTests.length} testów Path Traversal.` });

  // 4.03125) Generate Template Injection tests
  emit({ type: "step", message: "Generowanie testów Template Injection..." });
  const templateTests = enabled.TEMPLATE_INJECTION
    ? dedupeGeneratedTests(generateTemplateInjectionTests(endpoints, volumeLimits))
    : [];
  emit({ type: "step", message: `Wygenerowano ${templateTests.length} testów Template Injection.` });

  // 4.0625) Generate SSRF tests
  emit({ type: "step", message: "Generowanie testów SSRF..." });
  const ssrfTests = enabled.SSRF ? dedupeGeneratedTests(generateSsrfTests(endpoints, volumeLimits)) : [];
  emit({ type: "step", message: `Wygenerowano ${ssrfTests.length} testów SSRF.` });

  // 4.125) Generate Header Injection tests
  emit({ type: "step", message: "Generowanie testów Header Injection..." });
  const headerInjectionTests = enabled.HEADER_INJECTION
    ? dedupeGeneratedTests(generateHeaderInjectionTests(endpoints, volumeLimits))
    : [];
  emit({ type: "step", message: `Wygenerowano ${headerInjectionTests.length} testów Header Injection.` });

  // 4.25) Generate Open Redirect tests
  emit({ type: "step", message: "Generowanie testów Open Redirect..." });
  const openRedirectTests = enabled.OPEN_REDIRECT
    ? dedupeGeneratedTests(generateOpenRedirectTests(endpoints, volumeLimits))
    : [];
  emit({ type: "step", message: `Wygenerowano ${openRedirectTests.length} testów Open Redirect.` });

  // 4.5) Generate FUZZ tests (validation / type)
  emit({ type: "step", message: "Generowanie testów walidacji parametrów..." });
  const fuzzTests = enabled.FUZZ
    ? dedupeGeneratedTests(
        generateFuzzTests(endpoints, {
          maxParamPayloads: volumeLimits.maxParamPayloads,
          maxBodyFields: smartCfg.bodyFieldLimit ?? volumeLimits.maxBodyFields,
          fuzzDepth: smartCfg.fuzzDepth ?? 3
        })
      )
    : [];
  emit({ type: "step", message: `Wygenerowano ${fuzzTests.length} testów walidacji.` });

  const limited = applyGlobalTestLimit(
    {
      sql: sqlTests,
      xss: xssTests,
      pathTraversal: pathTraversalTests,
      template: templateTests,
      ssrf: ssrfTests,
      headerInjection: headerInjectionTests,
      openRedirect: openRedirectTests,
      fuzz: fuzzTests
    },
    maxTotalTests
  );
  const sqlTestsLimited = limited.sql;
  const xssTestsLimited = limited.xss;
  const pathTraversalTestsLimited = limited.pathTraversal;
  const templateTestsLimited = limited.template;
  const ssrfTestsLimited = limited.ssrf;
  const headerInjectionTestsLimited = limited.headerInjection;
  const openRedirectTestsLimited = limited.openRedirect;
  const fuzzTestsLimited = limited.fuzz;
  if (limited.trimmed > 0) {
    emit({
      type: "step",
      message: `Ograniczono liczbę testów do ${limited.kept} (ucięto ${limited.trimmed}, maxTotalTests=${maxTotalTests}).`
    });
  }

  // 5) Run (axios) if baseUrl exists
  const target = resolveTargetBaseUrl(baseUrl, specObj);
  if (!target) {
    emit({ type: "step", message: "Brak baseUrl — pomijam wykonywanie testów HTTP." });
    setReport({ totalTests: 0, totalErrors: 0, totalSuspicious: 0 });
    emit({ type: "scan_finished" });
    return;
  }

  emit({ type: "step", message: `Target API: ${target}` });

  const headers = buildAuthHeaders(auth);
  const throttleMs = resolveThrottleMs(throttle);

  const seedData = await runSeedMode({
    endpoints,
    target,
    headers,
    throttleMs,
    seed,
    emit
  });
  setSeedResults(seedData.results);
  const seedMap = seedData.map;

  const baselineEndpoints = selectBaselineEndpoints({
    endpoints,
    enabled,
    sqlTests: sqlTestsLimited,
    xssTests: xssTestsLimited,
    pathTraversalTests: pathTraversalTestsLimited,
    templateTests: templateTestsLimited,
    ssrfTests: ssrfTestsLimited,
    headerInjectionTests: headerInjectionTestsLimited,
    openRedirectTests: openRedirectTestsLimited,
    fuzzTests: fuzzTestsLimited
  });

  const zeroStats = { totalTests: 0, totalErrors: 0, totalSuspicious: 0 };
  let baseline = new Map<string, BaselineResult>();
  if (baselineEndpoints.length > 0) {
    baseline = await runBaselineRequests({
      endpoints: baselineEndpoints,
      target,
      headers,
      throttleMs,
      seedMap,
      samples: baselineSamples,
      requestConcurrency,
      includeUnsafeMethods: baselineIncludeUnsafeMethods,
      emit
    });
  } else {
    emit({ type: "step", message: "Brak aktywnych testów wymagających baseline — pomijam baseline." });
  }

  const authStats = enabled.AUTH
    ? await runAuthNegativeTests({ endpoints, target, baseline, emit, throttleMs, requestConcurrency })
    : zeroStats;
  const rateLimitStats = enabled.RATE_LIMIT
    ? await runRateLimitTests({
        endpoints,
        target,
        headers,
        throttleMs,
        baseline,
        seedMap,
        requestConcurrency,
        emit
      })
    : zeroStats;

  // 6) Run SQLi
  emit({ type: "step", message: "Wykonywanie testów SQL Injection..." });
  const sqlStats = enabled.SQLi
    ? await runSqlInjectionTests({
        target,
        tests: sqlTestsLimited,
        headers,
        throttleMs,
        baseline,
        seedMap,
        emit,
        anomalySensitivity,
        responseValidation,
        requestConcurrency
      })
    : zeroStats;

  // 7) Run XSS
  emit({ type: "step", message: "Wykonywanie testów XSS..." });
  const xssStats = enabled.XSS
    ? await runXssTests({
        target,
        tests: xssTestsLimited,
        headers,
        throttleMs,
        baseline,
        seedMap,
        emit,
        anomalySensitivity,
        responseValidation,
        requestConcurrency
      })
    : zeroStats;

  // 7.015625) Run Path Traversal
  emit({ type: "step", message: "Wykonywanie testów Path Traversal..." });
  const pathTraversalStats = enabled.PATH_TRAVERSAL
    ? await runPathTraversalTests({
        target,
        tests: pathTraversalTestsLimited,
        headers,
        throttleMs,
        baseline,
        seedMap,
        emit,
        anomalySensitivity,
        responseValidation,
        requestConcurrency
      })
    : zeroStats;

  // 7.03125) Run Template Injection
  emit({ type: "step", message: "Wykonywanie testów Template Injection..." });
  const templateStats = enabled.TEMPLATE_INJECTION
    ? await runTemplateInjectionTests({
        target,
        tests: templateTestsLimited,
        headers,
        throttleMs,
        baseline,
        seedMap,
        emit,
        anomalySensitivity,
        responseValidation,
        requestConcurrency
      })
    : zeroStats;

  // 7.0625) Run SSRF
  emit({ type: "step", message: "Wykonywanie testów SSRF..." });
  const ssrfStats = enabled.SSRF
    ? await runSsrfTests({
        target,
        tests: ssrfTestsLimited,
        headers,
        throttleMs,
        baseline,
        seedMap,
        emit,
        anomalySensitivity,
        responseValidation,
        requestConcurrency
      })
    : zeroStats;

  // 7.125) Run Header Injection
  emit({ type: "step", message: "Wykonywanie testów Header Injection..." });
  const headerInjectionStats = enabled.HEADER_INJECTION
    ? await runHeaderInjectionTests({
        target,
        tests: headerInjectionTestsLimited,
        headers,
        throttleMs,
        baseline,
        seedMap,
        emit,
        anomalySensitivity,
        responseValidation,
        requestConcurrency
      })
    : zeroStats;

  // 7.25) Run Open Redirect
  emit({ type: "step", message: "Wykonywanie testów Open Redirect..." });
  const openRedirectStats = enabled.OPEN_REDIRECT
    ? await runOpenRedirectTests({
        target,
        tests: openRedirectTestsLimited,
        headers,
        throttleMs,
        baseline,
        seedMap,
        emit,
        anomalySensitivity,
        responseValidation,
        requestConcurrency
      })
    : zeroStats;

  // 7.5) Run FUZZ
  emit({ type: "step", message: "Wykonywanie testów walidacji parametrów..." });
  const fuzzStats = enabled.FUZZ
    ? await runFuzzTests({
        target,
        tests: fuzzTestsLimited,
        headers,
        throttleMs,
        baseline,
        seedMap,
        emit,
        anomalySensitivity,
        responseValidation,
        requestConcurrency
      })
    : zeroStats;

  // 8) Report = suma
  const stats = {
    totalTests:
      sqlStats.totalTests +
      xssStats.totalTests +
      pathTraversalStats.totalTests +
      templateStats.totalTests +
      ssrfStats.totalTests +
      headerInjectionStats.totalTests +
      openRedirectStats.totalTests +
      fuzzStats.totalTests +
      authStats.totalTests +
      rateLimitStats.totalTests,
    totalErrors:
      sqlStats.totalErrors +
      xssStats.totalErrors +
      pathTraversalStats.totalErrors +
      templateStats.totalErrors +
      ssrfStats.totalErrors +
      headerInjectionStats.totalErrors +
      openRedirectStats.totalErrors +
      fuzzStats.totalErrors +
      authStats.totalErrors +
      rateLimitStats.totalErrors,
    totalSuspicious:
      sqlStats.totalSuspicious +
      xssStats.totalSuspicious +
      pathTraversalStats.totalSuspicious +
      templateStats.totalSuspicious +
      ssrfStats.totalSuspicious +
      headerInjectionStats.totalSuspicious +
      openRedirectStats.totalSuspicious +
      fuzzStats.totalSuspicious +
      authStats.totalSuspicious +
      rateLimitStats.totalSuspicious
  };

  setReport(stats);

  emit({
    type: "step",
    message: `Podsumowanie: testy=${stats.totalTests}, błędy=${stats.totalErrors}, podejrzane=${stats.totalSuspicious}`
  });

  emit({ type: "scan_finished" });
    }));
  } finally {
    releaseRequestBudget();
  }
}

async function runSqlInjectionTests(args: {
  target: string;
  tests: SqlTest[];
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  emit: (ev: ScanEvent) => void;
  anomalySensitivity?: "low" | "medium" | "high";
  responseValidation?: "off" | "warn" | "strict";
  requestConcurrency?: number;
}): Promise<{
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
}> {
  const { target, tests, headers, throttleMs, baseline, seedMap, emit, anomalySensitivity, responseValidation, requestConcurrency } = args;

  let totalErrors = 0;
  let totalSuspicious = 0;
  const totalTests = tests.length;

  await forEachWithConcurrency(tests, requestConcurrency ?? 1, async (t, idx) => {
    const i = idx + 1;

    const effectivePath =
      t.location === "path" ? t.path : applySeedToTemplate(t.originalPath ?? t.path, seedMap);
    const prepared = prepareBody(t.body ?? { input: t.payload }, t.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: t.method,
      path: effectivePath,
      headers: mergeHeaders(headers, t.headers, t.contentType, prepared.headers),
      body: prepared.body,
      query: t.query,
      timeoutMs: 7000
    });

    if (!r.ok) {
      totalErrors++;

      emit({
        type: "test_result",
        testType: "SQLi",
        method: t.method,
        path: t.path,
        payload: t.payload,
        ok: false,
        error: String(r.error ?? "Unknown error")
      });

      emit({
        type: "step",
        message: `[${i}/${tests.length}] SQLi ${t.method} ${t.path} → error: ${r.error}`
      });

      return;
    }

    const dataStr = typeof r.data === "string" ? r.data : JSON.stringify(r.data ?? {});
    const sqlPattern = /sql|syntax|sqlite|postgres|mysql|mariadb|odbc|pdo|query failed|ORA-\d+/i;
    const baselineEntry = baseline.get(keyFor(t.method, t.originalPath ?? t.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineBad = baselineStatus == null ? true : baselineStatus >= 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const anomaly = baselineEntry ? isResponseAnomalous(baselineEntry, r, anomalySensitivity) : false;
    const blindTimeSignal = isBlindTimeSignal(t, baselineEntry, r);
    const blindBoolean = await runBlindBooleanCompanion({
      target,
      t,
      headers,
      contentType: t.contentType,
      primaryEffectivePath: effectivePath,
      primary: r
    });
    if (blindBoolean.error) {
      totalErrors++;
    }
    const schemaIssues = responseValidation === "off" ? [] : validateResponseSchema(t.expectedResponseSchema, r);
    const schemaFlag = schemaIssues.length && (r.status ?? 0) < 400;
    const suspicious =
      !baselineBad &&
      !baselineUnstable &&
      ((r.status ?? 0) >= 500 ||
        sqlPattern.test(dataStr) ||
        anomaly ||
        blindTimeSignal ||
        blindBoolean.suspicious);
    const verdict = suspicious
      ? "suspicious"
      : responseValidation === "strict" && schemaFlag
      ? "suspicious"
      : baselineBad || baselineUnstable || (r.status ?? 0) >= 500 || (schemaFlag && responseValidation === "warn")
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    const verdictLabel = suspicious ? "⚠️ podejrzane" : "OK";
    const evidence = suspicious ? dataStr.slice(0, 400) : undefined;
    const blindEvidence = blindBoolean.suspicious
      ? `Blind boolean: true(status=${r.status ?? "-"}, size=${r.size ?? "-"}), false(status=${blindBoolean.status ?? "-"}, size=${blindBoolean.size ?? "-"})`
      : undefined;
    const blindTimeEvidence = blindTimeSignal
      ? `Blind time: czas=${r.durationMs ?? "-"}ms, baseline=${baselineEntry?.timeMs ?? "-"}ms`
      : undefined;

    emit({
      type: "test_result",
      testType: "SQLi",
      method: t.method,
      path: t.originalPath ?? t.path,
      payload: t.payload,
      ok: true,
      verdict,
      baselineStatus,
      baselineSize,
      location: t.location,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, effectivePath, t.query),
      suspicious,
      evidence: joinEvidence(
        evidence,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined,
        anomaly ? "Anomalia odpowiedzi względem baseline." : undefined,
        blindTimeEvidence,
        blindEvidence,
        blindBoolean.error ? `Blind boolean błąd: ${blindBoolean.error}` : undefined,
        schemaIssues.length ? `Niezgodne z kontraktem: ${schemaIssues.join("; ")}` : undefined
      ),
      schemaIssues: schemaIssues.length ? schemaIssues : undefined
    });

    emit({
      type: "step",
      message: `[${i}/${tests.length}] SQLi ${t.method} ${t.originalPath ?? t.path} → ${r.status} (${verdictLabel})`
    });

    if (suspicious) {
      emit({
        type: "step",
        message: `Dowód (fragment): ${dataStr.slice(0, 160)}`
      });
    }

    if (throttleMs && throttleMs > 0) {
      await sleep(throttleMs);
    }
  });

  return { totalTests, totalErrors, totalSuspicious };
}

async function runXssTests(args: {
  target: string;
  tests: XssTest[];
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  emit: (ev: ScanEvent) => void;
  anomalySensitivity?: "low" | "medium" | "high";
  responseValidation?: "off" | "warn" | "strict";
  requestConcurrency?: number;
}): Promise<{
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
}> {
  const { target, tests, headers, throttleMs, baseline, seedMap, emit, anomalySensitivity, responseValidation, requestConcurrency } = args;

  let totalErrors = 0;
  let totalSuspicious = 0;
  const totalTests = tests.length;

  await forEachWithConcurrency(tests, requestConcurrency ?? 1, async (t, idx) => {
    const i = idx + 1;

    const effectivePath =
      t.location === "path" ? t.path : applySeedToTemplate(t.originalPath ?? t.path, seedMap);
    const prepared = prepareBody(t.body ?? { input: t.payload }, t.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: t.method,
      path: effectivePath,
      headers: mergeHeaders(headers, t.headers, t.contentType, prepared.headers),
      body: prepared.body,
      query: t.query,
      timeoutMs: 7000
    });

    if (!r.ok) {
      totalErrors++;

      emit({
        type: "test_result",
        testType: "XSS",
        method: t.method,
        path: t.path,
        payload: t.payload,
        ok: false,
        error: String(r.error ?? "Unknown error")
      });

      emit({
        type: "step",
        message: `[${i}/${tests.length}] XSS ${t.method} ${t.path} → error: ${r.error}`
      });

      return;
    }

    const dataStr = typeof r.data === "string" ? r.data : JSON.stringify(r.data ?? {});
    const reflection = dataStr.includes(t.payload);
    const baselineEntry = baseline.get(keyFor(t.method, t.originalPath ?? t.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineBad = baselineStatus == null ? true : baselineStatus >= 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const htmlLike = isHtmlResponse(r, baselineEntry, t.expectedResponseContentTypes);
    const xss = assessXssSignal(dataStr, t.payload, htmlLike);
    const anomaly = baselineEntry ? isResponseAnomalous(baselineEntry, r, anomalySensitivity) : false;
    const schemaIssues = responseValidation === "off" ? [] : validateResponseSchema(t.expectedResponseSchema, r);
    const schemaFlag = schemaIssues.length && (r.status ?? 0) < 400;
    const suspicious = !baselineBad && !baselineUnstable && xss.exploitableLikely;
    const verdict = suspicious
      ? "suspicious"
      : responseValidation === "strict" && schemaFlag
      ? "suspicious"
      : baselineBad ||
        baselineUnstable ||
        (r.status ?? 0) >= 500 ||
        (xss.reflection && !htmlLike) ||
        (xss.reflection && htmlLike && !xss.exploitableLikely) ||
        (schemaFlag && responseValidation === "warn")
      ? "inconclusive"
      : anomaly
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    const verdictLabel = suspicious ? "⚠️ podejrzane" : "OK";
    const evidence = suspicious
      ? dataStr.slice(0, 400)
      : xss.reflection && !htmlLike
      ? "Payload odbity, ale odpowiedź nie wygląda na HTML."
      : xss.reflection && htmlLike && !xss.exploitableLikely
      ? `Payload odbity, ale kontekst wygląda na mniej wykonywalny (${xss.reason}).`
      : anomaly
      ? "Anomalia odpowiedzi względem baseline."
      : undefined;

    emit({
      type: "test_result",
      testType: "XSS",
      method: t.method,
      path: t.originalPath ?? t.path,
      payload: t.payload,
      ok: true,
      verdict,
      baselineStatus,
      baselineSize,
      location: t.location,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, effectivePath, t.query),
      suspicious,
      evidence: joinEvidence(
        evidence,
        xss.reason && suspicious ? `Kontekst XSS: ${xss.reason}` : undefined,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined,
        schemaIssues.length ? `Niezgodne z kontraktem: ${schemaIssues.join("; ")}` : undefined
      ),
      schemaIssues: schemaIssues.length ? schemaIssues : undefined
    });

    emit({
      type: "step",
      message: `[${i}/${tests.length}] XSS ${t.method} ${t.originalPath ?? t.path} → ${r.status} (${verdictLabel})`
    });

    if (suspicious) {
      emit({
        type: "step",
        message: `Dowód (fragment): ${dataStr.slice(0, 160)}`
      });
    }

    if (throttleMs && throttleMs > 0) {
      await sleep(throttleMs);
    }
  });

  return { totalTests, totalErrors, totalSuspicious };
}

function isBlindTimeSignal(
  t: SqlTest,
  baseline: BaselineResult | undefined,
  r: { durationMs?: number; status?: number }
) {
  if (t.strategy !== "blind_time") return false;
  if (!baseline || !baseline.ok || baseline.unstable) return false;
  const baseMs = baseline.timeMs ?? 0;
  const curMs = r.durationMs ?? 0;
  if (baseMs <= 0 || curMs <= 0) return false;
  const ratio = curMs / Math.max(1, baseMs);
  const delta = curMs - baseMs;
  const status = r.status ?? 0;
  if (status >= 500) return false;
  return ratio >= 2.2 && delta >= 800;
}

async function runBlindBooleanCompanion(args: {
  target: string;
  t: SqlTest;
  headers?: Record<string, string>;
  contentType?: string;
  primaryEffectivePath: string;
  primary: { status?: number; size?: number; data?: unknown; headers?: Record<string, string> };
}) {
  const { target, t, headers, contentType, primaryEffectivePath, primary } = args;
  if (t.strategy !== "blind_boolean") return { suspicious: false as const };
  if (!t.secondaryPath && !t.secondaryQuery && !t.secondaryHeaders && !t.secondaryBody) {
    return { suspicious: false as const };
  }

  const prepared = prepareBody(t.secondaryBody ?? t.body ?? { input: t.payload }, contentType);
  const r2 = await httpRequest({
    baseUrl: target,
    method: t.method,
    path: t.secondaryPath ?? primaryEffectivePath,
    headers: mergeHeaders(headers, t.secondaryHeaders ?? t.headers, contentType, prepared.headers),
    body: prepared.body,
    query: t.secondaryQuery ?? t.query,
    timeoutMs: 7000
  });
  if (!r2.ok) {
    return {
      suspicious: false as const,
      error: String(r2.error ?? "Unknown error")
    };
  }
  const status = r2.status ?? 0;
  const size = r2.size ?? 0;
  const sig = buildJsonSignature(r2.data);
  const primaryStatus = primary.status ?? 0;
  const primarySize = primary.size ?? 0;
  const primarySig = buildJsonSignature(primary.data);
  const primaryCt = normalizeContentType(primary.headers);
  const secondaryCt = normalizeContentType(r2.headers);
  const sizeDiff = Math.abs(size - primarySize);
  const sizeThreshold = Math.max(30, Math.round(Math.max(1, primarySize) * 0.35));
  const statusDiff = primaryStatus !== status;
  const sigDiff = Boolean(primarySig && sig && primarySig !== sig);
  const ctDiff = Boolean(primaryCt && secondaryCt && primaryCt !== secondaryCt);
  const bothServerErrors = primaryStatus >= 500 && status >= 500;
  const suspicious = !bothServerErrors && (statusDiff || sigDiff || ctDiff || sizeDiff > sizeThreshold);
  return {
    suspicious,
    status,
    size,
    sig
  };
}

async function runFuzzTests(args: {
  target: string;
  tests: FuzzTest[];
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  emit: (ev: ScanEvent) => void;
  anomalySensitivity?: "low" | "medium" | "high";
  responseValidation?: "off" | "warn" | "strict";
  requestConcurrency?: number;
}): Promise<{
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
}> {
  const { target, tests, headers, throttleMs, baseline, seedMap, emit, anomalySensitivity, responseValidation, requestConcurrency } = args;
  let totalErrors = 0;
  let totalSuspicious = 0;
  const totalTests = tests.length;

  await forEachWithConcurrency(tests, requestConcurrency ?? 1, async (t, idx) => {
    const i = idx + 1;
    const effectivePath =
      t.location === "path" ? t.path : applySeedToTemplate(t.originalPath ?? t.path, seedMap);
    const prepared = prepareBody(t.body, t.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: t.method,
      path: effectivePath,
      headers: mergeHeaders(headers, t.headers, t.contentType, prepared.headers),
      body: prepared.body,
      query: t.query,
      timeoutMs: 7000
    });

    if (!r.ok) {
      totalErrors++;
      emit({
        type: "test_result",
        testType: "FUZZ",
        method: t.method,
        path: t.originalPath ?? t.path,
        payload: t.payload,
        location: t.location,
        ok: false,
        verdict: "error",
        error: String(r.error ?? "Unknown error")
      });
      emit({
        type: "step",
        message: `[${i}/${tests.length}] FUZZ ${t.method} ${t.originalPath ?? t.path} → error: ${r.error}`
      });
      return;
    }

    const baselineEntry = baseline.get(keyFor(t.method, t.originalPath ?? t.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineBad = baselineStatus == null ? true : baselineStatus >= 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const anomaly = baselineEntry ? isResponseAnomalous(baselineEntry, r, anomalySensitivity) : false;
    const schemaIssues = responseValidation === "off" ? [] : validateResponseSchema(t.expectedResponseSchema, r);
    const schemaFlag = schemaIssues.length && (r.status ?? 0) < 400;
    const suspicious = !baselineBad && !baselineUnstable && ((r.status ?? 0) >= 500 || anomaly);
    const verdict = suspicious
      ? "suspicious"
      : responseValidation === "strict" && schemaFlag
      ? "suspicious"
      : baselineBad || baselineUnstable || (r.status ?? 0) >= 500 || (schemaFlag && responseValidation === "warn")
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    emit({
      type: "test_result",
      testType: "FUZZ",
      method: t.method,
      path: t.originalPath ?? t.path,
      payload: t.payload,
      location: t.location,
      ok: true,
      verdict,
      baselineStatus,
      baselineSize,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, effectivePath, t.query),
      suspicious,
      evidence: joinEvidence(
        typeof r.data === "string" ? r.data.slice(0, 400) : undefined,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined,
        anomaly ? "Anomalia odpowiedzi względem baseline." : undefined,
        schemaIssues.length ? `Niezgodne z kontraktem: ${schemaIssues.join("; ")}` : undefined
      ),
      schemaIssues: schemaIssues.length ? schemaIssues : undefined
    });

    emit({
      type: "step",
      message: `[${i}/${tests.length}] FUZZ ${t.method} ${t.originalPath ?? t.path} → ${r.status} (${verdict})`
    });

    if (throttleMs && throttleMs > 0) {
      await sleep(throttleMs);
    }
  });

  return { totalTests, totalErrors, totalSuspicious };
}

async function runOpenRedirectTests(args: {
  target: string;
  tests: OpenRedirectTest[];
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  emit: (ev: ScanEvent) => void;
  anomalySensitivity?: "low" | "medium" | "high";
  responseValidation?: "off" | "warn" | "strict";
  requestConcurrency?: number;
}): Promise<{
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
}> {
  const { target, tests, headers, throttleMs, baseline, seedMap, emit, anomalySensitivity, responseValidation, requestConcurrency } = args;
  let totalErrors = 0;
  let totalSuspicious = 0;
  const totalTests = tests.length;

  await forEachWithConcurrency(tests, requestConcurrency ?? 1, async (t, idx) => {
    const i = idx + 1;
    const effectivePath =
      t.location === "path" ? t.path : applySeedToTemplate(t.originalPath ?? t.path, seedMap);
    const prepared = prepareBody(t.body, t.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: t.method,
      path: effectivePath,
      headers: mergeHeaders(headers, t.headers, t.contentType, prepared.headers),
      body: prepared.body,
      query: t.query,
      timeoutMs: 7000
    });

    if (!r.ok) {
      totalErrors++;
      emit({
        type: "test_result",
        testType: "OPEN_REDIRECT",
        method: t.method,
        path: t.originalPath ?? t.path,
        payload: t.payload,
        location: t.location,
        ok: false,
        verdict: "error",
        error: String(r.error ?? "Unknown error")
      });
      emit({
        type: "step",
        message: `[${i}/${tests.length}] OPEN_REDIRECT ${t.method} ${t.originalPath ?? t.path} → error: ${r.error}`
      });
      return;
    }

    const baselineEntry = baseline.get(keyFor(t.method, t.originalPath ?? t.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineBad = baselineStatus == null ? true : baselineStatus >= 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const anomaly = baselineEntry ? isResponseAnomalous(baselineEntry, r, anomalySensitivity) : false;
    const schemaIssues = responseValidation === "off" ? [] : validateResponseSchema(t.expectedResponseSchema, r);
    const schemaFlag = schemaIssues.length && (r.status ?? 0) < 400;

    const redirect = detectOpenRedirectSignal(target, t.payload, r.status ?? 0, r.headers);
    const suspicious = !baselineBad && !baselineUnstable && redirect.suspicious;
    const verdict = suspicious
      ? "suspicious"
      : responseValidation === "strict" && schemaFlag
      ? "suspicious"
      : baselineBad || baselineUnstable || (r.status ?? 0) >= 500 || (schemaFlag && responseValidation === "warn")
      ? "inconclusive"
      : anomaly
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    emit({
      type: "test_result",
      testType: "OPEN_REDIRECT",
      method: t.method,
      path: t.originalPath ?? t.path,
      payload: t.payload,
      location: t.location,
      ok: true,
      verdict,
      baselineStatus,
      baselineSize,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, effectivePath, t.query),
      suspicious,
      evidence: joinEvidence(
        redirect.reason,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined,
        anomaly ? "Anomalia odpowiedzi względem baseline." : undefined,
        schemaIssues.length ? `Niezgodne z kontraktem: ${schemaIssues.join("; ")}` : undefined
      ),
      schemaIssues: schemaIssues.length ? schemaIssues : undefined
    });

    emit({
      type: "step",
      message: `[${i}/${tests.length}] OPEN_REDIRECT ${t.method} ${t.originalPath ?? t.path} → ${r.status} (${verdict})`
    });

    if (throttleMs && throttleMs > 0) await sleep(throttleMs);
  });

  return { totalTests, totalErrors, totalSuspicious };
}

async function runHeaderInjectionTests(args: {
  target: string;
  tests: HeaderInjectionTest[];
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  emit: (ev: ScanEvent) => void;
  anomalySensitivity?: "low" | "medium" | "high";
  responseValidation?: "off" | "warn" | "strict";
  requestConcurrency?: number;
}): Promise<{
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
}> {
  const { target, tests, headers, throttleMs, baseline, seedMap, emit, anomalySensitivity, responseValidation, requestConcurrency } = args;
  let totalErrors = 0;
  let totalSuspicious = 0;
  const totalTests = tests.length;

  await forEachWithConcurrency(tests, requestConcurrency ?? 1, async (t, idx) => {
    const i = idx + 1;
    const effectivePath =
      t.location === "path" ? t.path : applySeedToTemplate(t.originalPath ?? t.path, seedMap);
    const prepared = prepareBody(t.body, t.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: t.method,
      path: effectivePath,
      headers: mergeHeaders(headers, t.headers, t.contentType, prepared.headers),
      body: prepared.body,
      query: t.query,
      timeoutMs: 7000
    });

    if (!r.ok) {
      totalErrors++;
      emit({
        type: "test_result",
        testType: "HEADER_INJECTION",
        method: t.method,
        path: t.originalPath ?? t.path,
        payload: t.payload,
        location: t.location,
        ok: false,
        verdict: "error",
        error: String(r.error ?? "Unknown error")
      });
      return;
    }

    const baselineEntry = baseline.get(keyFor(t.method, t.originalPath ?? t.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineBad = baselineStatus == null ? true : baselineStatus >= 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const anomaly = baselineEntry ? isResponseAnomalous(baselineEntry, r, anomalySensitivity) : false;
    const schemaIssues = responseValidation === "off" ? [] : validateResponseSchema(t.expectedResponseSchema, r);
    const schemaFlag = schemaIssues.length && (r.status ?? 0) < 400;

    const signal = detectHeaderInjectionSignal(r.headers, t.payload);
    const suspicious = !baselineBad && !baselineUnstable && signal.suspicious;
    const verdict = suspicious
      ? "suspicious"
      : responseValidation === "strict" && schemaFlag
      ? "suspicious"
      : baselineBad || baselineUnstable || (r.status ?? 0) >= 500 || (schemaFlag && responseValidation === "warn")
      ? "inconclusive"
      : anomaly
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    emit({
      type: "test_result",
      testType: "HEADER_INJECTION",
      method: t.method,
      path: t.originalPath ?? t.path,
      payload: t.payload,
      location: t.location,
      ok: true,
      verdict,
      baselineStatus,
      baselineSize,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, effectivePath, t.query),
      suspicious,
      evidence: joinEvidence(
        signal.reason,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined,
        anomaly ? "Anomalia odpowiedzi względem baseline." : undefined,
        schemaIssues.length ? `Niezgodne z kontraktem: ${schemaIssues.join("; ")}` : undefined
      ),
      schemaIssues: schemaIssues.length ? schemaIssues : undefined
    });

    emit({
      type: "step",
      message: `[${i}/${tests.length}] HEADER_INJECTION ${t.method} ${t.originalPath ?? t.path} → ${r.status} (${verdict})`
    });

    if (throttleMs && throttleMs > 0) await sleep(throttleMs);
  });

  return { totalTests, totalErrors, totalSuspicious };
}

async function runSsrfTests(args: {
  target: string;
  tests: SsrfTest[];
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  emit: (ev: ScanEvent) => void;
  anomalySensitivity?: "low" | "medium" | "high";
  responseValidation?: "off" | "warn" | "strict";
  requestConcurrency?: number;
}): Promise<{
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
}> {
  const { target, tests, headers, throttleMs, baseline, seedMap, emit, anomalySensitivity, responseValidation, requestConcurrency } = args;
  let totalErrors = 0;
  let totalSuspicious = 0;
  const totalTests = tests.length;

  await forEachWithConcurrency(tests, requestConcurrency ?? 1, async (t, idx) => {
    const i = idx + 1;
    const effectivePath =
      t.location === "path" ? t.path : applySeedToTemplate(t.originalPath ?? t.path, seedMap);
    const prepared = prepareBody(t.body, t.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: t.method,
      path: effectivePath,
      headers: mergeHeaders(headers, t.headers, t.contentType, prepared.headers),
      body: prepared.body,
      query: t.query,
      timeoutMs: 7000
    });

    if (!r.ok) {
      totalErrors++;
      emit({
        type: "test_result",
        testType: "SSRF",
        method: t.method,
        path: t.originalPath ?? t.path,
        payload: t.payload,
        location: t.location,
        ok: false,
        verdict: "error",
        error: String(r.error ?? "Unknown error")
      });
      return;
    }

    const baselineEntry = baseline.get(keyFor(t.method, t.originalPath ?? t.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineBad = baselineStatus == null ? true : baselineStatus >= 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const anomaly = baselineEntry ? isResponseAnomalous(baselineEntry, r, anomalySensitivity) : false;
    const schemaIssues = responseValidation === "off" ? [] : validateResponseSchema(t.expectedResponseSchema, r);
    const schemaFlag = schemaIssues.length && (r.status ?? 0) < 400;

    const ssrfSignal = detectSsrfSignal(t.payload, r.data);
    const suspicious = !baselineBad && !baselineUnstable && ssrfSignal.suspicious;
    const verdict = suspicious
      ? "suspicious"
      : responseValidation === "strict" && schemaFlag
      ? "suspicious"
      : baselineBad || baselineUnstable || (r.status ?? 0) >= 500 || (schemaFlag && responseValidation === "warn")
      ? "inconclusive"
      : anomaly
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    emit({
      type: "test_result",
      testType: "SSRF",
      method: t.method,
      path: t.originalPath ?? t.path,
      payload: t.payload,
      location: t.location,
      ok: true,
      verdict,
      baselineStatus,
      baselineSize,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, effectivePath, t.query),
      suspicious,
      evidence: joinEvidence(
        ssrfSignal.reason,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined,
        anomaly ? "Anomalia odpowiedzi względem baseline." : undefined,
        schemaIssues.length ? `Niezgodne z kontraktem: ${schemaIssues.join("; ")}` : undefined
      ),
      schemaIssues: schemaIssues.length ? schemaIssues : undefined
    });

    emit({
      type: "step",
      message: `[${i}/${tests.length}] SSRF ${t.method} ${t.originalPath ?? t.path} → ${r.status} (${verdict})`
    });

    if (throttleMs && throttleMs > 0) await sleep(throttleMs);
  });

  return { totalTests, totalErrors, totalSuspicious };
}

async function runTemplateInjectionTests(args: {
  target: string;
  tests: TemplateInjectionTest[];
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  emit: (ev: ScanEvent) => void;
  anomalySensitivity?: "low" | "medium" | "high";
  responseValidation?: "off" | "warn" | "strict";
  requestConcurrency?: number;
}): Promise<{
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
}> {
  const { target, tests, headers, throttleMs, baseline, seedMap, emit, anomalySensitivity, responseValidation, requestConcurrency } = args;
  let totalErrors = 0;
  let totalSuspicious = 0;
  const totalTests = tests.length;

  await forEachWithConcurrency(tests, requestConcurrency ?? 1, async (t, idx) => {
    const i = idx + 1;
    const effectivePath =
      t.location === "path" ? t.path : applySeedToTemplate(t.originalPath ?? t.path, seedMap);
    const prepared = prepareBody(t.body, t.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: t.method,
      path: effectivePath,
      headers: mergeHeaders(headers, t.headers, t.contentType, prepared.headers),
      body: prepared.body,
      query: t.query,
      timeoutMs: 7000
    });

    if (!r.ok) {
      totalErrors++;
      emit({
        type: "test_result",
        testType: "TEMPLATE_INJECTION",
        method: t.method,
        path: t.originalPath ?? t.path,
        payload: t.payload,
        location: t.location,
        ok: false,
        verdict: "error",
        error: String(r.error ?? "Unknown error")
      });
      return;
    }

    const baselineEntry = baseline.get(keyFor(t.method, t.originalPath ?? t.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineBad = baselineStatus == null ? true : baselineStatus >= 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const anomaly = baselineEntry ? isResponseAnomalous(baselineEntry, r, anomalySensitivity) : false;
    const schemaIssues = responseValidation === "off" ? [] : validateResponseSchema(t.expectedResponseSchema, r);
    const schemaFlag = schemaIssues.length && (r.status ?? 0) < 400;

    const ssti = detectTemplateInjectionSignal(t.payload, r.data);
    const suspicious = !baselineBad && !baselineUnstable && ssti.suspicious;
    const verdict = suspicious
      ? "suspicious"
      : responseValidation === "strict" && schemaFlag
      ? "suspicious"
      : baselineBad || baselineUnstable || (r.status ?? 0) >= 500 || (schemaFlag && responseValidation === "warn")
      ? "inconclusive"
      : anomaly
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    emit({
      type: "test_result",
      testType: "TEMPLATE_INJECTION",
      method: t.method,
      path: t.originalPath ?? t.path,
      payload: t.payload,
      location: t.location,
      ok: true,
      verdict,
      baselineStatus,
      baselineSize,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, effectivePath, t.query),
      suspicious,
      evidence: joinEvidence(
        ssti.reason,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined,
        anomaly ? "Anomalia odpowiedzi względem baseline." : undefined,
        schemaIssues.length ? `Niezgodne z kontraktem: ${schemaIssues.join("; ")}` : undefined
      ),
      schemaIssues: schemaIssues.length ? schemaIssues : undefined
    });

    emit({
      type: "step",
      message: `[${i}/${tests.length}] TEMPLATE_INJECTION ${t.method} ${t.originalPath ?? t.path} → ${r.status} (${verdict})`
    });

    if (throttleMs && throttleMs > 0) await sleep(throttleMs);
  });

  return { totalTests, totalErrors, totalSuspicious };
}

async function runPathTraversalTests(args: {
  target: string;
  tests: PathTraversalTest[];
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  emit: (ev: ScanEvent) => void;
  anomalySensitivity?: "low" | "medium" | "high";
  responseValidation?: "off" | "warn" | "strict";
  requestConcurrency?: number;
}): Promise<{
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
}> {
  const { target, tests, headers, throttleMs, baseline, seedMap, emit, anomalySensitivity, responseValidation, requestConcurrency } = args;
  let totalErrors = 0;
  let totalSuspicious = 0;
  const totalTests = tests.length;

  await forEachWithConcurrency(tests, requestConcurrency ?? 1, async (t, idx) => {
    const i = idx + 1;
    const effectivePath =
      t.location === "path" ? t.path : applySeedToTemplate(t.originalPath ?? t.path, seedMap);
    const prepared = prepareBody(t.body, t.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: t.method,
      path: effectivePath,
      headers: mergeHeaders(headers, t.headers, t.contentType, prepared.headers),
      body: prepared.body,
      query: t.query,
      timeoutMs: 7000
    });

    if (!r.ok) {
      totalErrors++;
      emit({
        type: "test_result",
        testType: "PATH_TRAVERSAL",
        method: t.method,
        path: t.originalPath ?? t.path,
        payload: t.payload,
        location: t.location,
        ok: false,
        verdict: "error",
        error: String(r.error ?? "Unknown error")
      });
      return;
    }

    const baselineEntry = baseline.get(keyFor(t.method, t.originalPath ?? t.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineBad = baselineStatus == null ? true : baselineStatus >= 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const anomaly = baselineEntry ? isResponseAnomalous(baselineEntry, r, anomalySensitivity) : false;
    const schemaIssues = responseValidation === "off" ? [] : validateResponseSchema(t.expectedResponseSchema, r);
    const schemaFlag = schemaIssues.length && (r.status ?? 0) < 400;

    const traversal = detectPathTraversalSignal(r.data, t.payload);
    const suspicious = !baselineBad && !baselineUnstable && traversal.suspicious;
    const verdict = suspicious
      ? "suspicious"
      : responseValidation === "strict" && schemaFlag
      ? "suspicious"
      : baselineBad || baselineUnstable || (r.status ?? 0) >= 500 || (schemaFlag && responseValidation === "warn")
      ? "inconclusive"
      : anomaly
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    emit({
      type: "test_result",
      testType: "PATH_TRAVERSAL",
      method: t.method,
      path: t.originalPath ?? t.path,
      payload: t.payload,
      location: t.location,
      ok: true,
      verdict,
      baselineStatus,
      baselineSize,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, effectivePath, t.query),
      suspicious,
      evidence: joinEvidence(
        traversal.reason,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined,
        anomaly ? "Anomalia odpowiedzi względem baseline." : undefined,
        schemaIssues.length ? `Niezgodne z kontraktem: ${schemaIssues.join("; ")}` : undefined
      ),
      schemaIssues: schemaIssues.length ? schemaIssues : undefined
    });

    emit({
      type: "step",
      message: `[${i}/${tests.length}] PATH_TRAVERSAL ${t.method} ${t.originalPath ?? t.path} → ${r.status} (${verdict})`
    });

    if (throttleMs && throttleMs > 0) await sleep(throttleMs);
  });

  return { totalTests, totalErrors, totalSuspicious };
}

function generateFuzzTests(
  endpoints: EndpointDetail[],
  opts?: { maxParamPayloads?: number; maxBodyFields?: number; fuzzDepth?: number }
): FuzzTest[] {
  const tests: FuzzTest[] = [];
  const stringPayloads = ["A".repeat(512), "A".repeat(2048), "../..", "%00", "invalid_enum_value"];
  const numberPayloads = ["-1", "0", "9999999999", "1.5", "abc"];
  const maxParamPayloads = opts?.maxParamPayloads ?? 6;
  const maxBodyFields = opts?.maxBodyFields ?? 6;
  const fuzzDepth = opts?.fuzzDepth ?? 3;

  for (const ep of endpoints) {
    const base = buildBaseRequest(ep);
    const allowBody = ["POST", "PUT", "PATCH"].includes(ep.method);

    for (const p of ep.parameters ?? []) {
      const payloads = deriveFuzzPayloads(p.schema, p.name);
      const fallbackPayloads =
        p.schema?.type === "integer" || p.schema?.type === "number" ? numberPayloads : stringPayloads;
      const finalPayloads = (payloads.length ? payloads : fallbackPayloads).slice(0, maxParamPayloads);

      if (p.in === "query") {
        for (const payload of finalPayloads) {
          tests.push({
            method: ep.method,
            path: base.resolvedPath,
            originalPath: ep.path,
            payload,
            location: "query",
            query: { ...base.query, [p.name]: payload },
            headers: base.headers,
            contentType: base.contentType,
            body: base.body,
            expectedResponseSchema: ep.responseBodySchema
          });
        }
      }

      if (p.in === "path") {
        for (const payload of finalPayloads) {
          const resolved = resolvePathParam(ep.path, p.name, payload);
          tests.push({
            method: ep.method,
            path: resolved,
            originalPath: ep.path,
            payload,
            location: "path",
            query: base.query,
            headers: base.headers,
            contentType: base.contentType,
            body: base.body,
            expectedResponseSchema: ep.responseBodySchema
          });
        }
      }

      if (p.in === "header") {
        for (const payload of finalPayloads) {
          tests.push({
            method: ep.method,
            path: base.resolvedPath,
            originalPath: ep.path,
            payload,
            location: "header",
            query: base.query,
            headers: { ...base.headers, [p.name]: payload },
            contentType: base.contentType,
            body: base.body,
            expectedResponseSchema: ep.responseBodySchema
          });
        }
      }

      if (p.in === "cookie") {
        for (const payload of finalPayloads) {
          tests.push({
            method: ep.method,
            path: base.resolvedPath,
            originalPath: ep.path,
            payload,
            location: "cookie",
            query: base.query,
            headers: mergeCookieHeader(base.headers, p.name, payload),
            contentType: base.contentType,
            body: base.body,
            expectedResponseSchema: ep.responseBodySchema
          });
        }
      }
    }

    if (allowBody && ep.requestBodySchema && base.body) {
      const schemaPaths = collectSchemaPaths(ep.requestBodySchema, "", 0, fuzzDepth).slice(0, maxBodyFields);
      for (const sp of schemaPaths) {
        const payloads = deriveFuzzValuesForSchema(sp.schema);
        for (const payloadValue of payloads) {
          const body = cloneJson(base.body);
          setValueAtPath(body, sp.path, payloadValue);
          tests.push({
            method: ep.method,
            path: base.resolvedPath,
            originalPath: ep.path,
            payload: String(payloadValue),
            location: "body",
            query: base.query,
            headers: base.headers,
            contentType: base.contentType,
            body,
            expectedResponseSchema: ep.responseBodySchema
          });
        }
      }
    }
  }

  return tests;
}

function buildAuthHeaders(auth?: AuthConfig): Record<string, string> | undefined {
  if (!auth) return undefined;
  const headers: Record<string, string> = {};

  const token = auth.bearerToken?.trim();
  if (token) headers.Authorization = `Bearer ${token}`;

  const apiKeyValue = auth.apiKey?.value?.trim();
  if (apiKeyValue) {
    const headerName = auth.apiKey?.headerName?.trim() || "X-API-Key";
    headers[headerName] = apiKeyValue;
  }

  const basicUser = auth.basic?.username?.trim();
  const basicPass = auth.basic?.password ?? "";
  if (basicUser) {
    const token = Buffer.from(`${basicUser}:${basicPass}`, "utf-8").toString("base64");
    headers.Authorization = `Basic ${token}`;
  }

  if (Array.isArray(auth.customHeaders)) {
    for (const h of auth.customHeaders) {
      const key = h.key?.trim();
      const value = h.value?.trim();
      if (!key || !value) continue;
      headers[key] = value;
    }
  }

  return Object.keys(headers).length ? headers : undefined;
}

function createAuthRuntime(auth?: AuthConfig): AuthRuntime {
  const jwtCfg = auth?.jwt;
  let cachedToken: string | undefined;
  let cachedExpMs: number | undefined;

  function resolveJwtToken(): string | undefined {
    if (!jwtCfg) return undefined;
    const mode = jwtCfg.mode ?? "existing";

    if (mode === "existing") {
      const token = String(jwtCfg.existingToken ?? "").trim();
      if (!token || !isJwtShape(token)) {
        throw new Error("Nieprawidłowy JWT: token musi zawierać 3 segmenty oddzielone kropkami.");
      }
      return token;
    }

    const now = Date.now();
    if (cachedToken && cachedExpMs && now < cachedExpMs) return cachedToken;
    if (cachedToken && !cachedExpMs) return cachedToken;

    const generated = generateJwtToken(jwtCfg);
    cachedToken = generated.token;
    cachedExpMs = generated.expMs;
    return cachedToken;
  }

  return {
    apply(headers, query) {
      const token = resolveJwtToken();
      if (!token) return { headers, query };

      const location = jwtCfg?.tokenLocation ?? "authorization";
      const prefix = (jwtCfg?.tokenPrefix ?? "Bearer").trim() || "Bearer";

      if (location === "authorization") {
        const nextHeaders = { ...(headers ?? {}) };
        nextHeaders.Authorization = `${prefix} ${token}`;
        return { headers: nextHeaders, query };
      }

      if (location === "custom_header") {
        const headerName = (jwtCfg?.customHeaderName ?? "X-JWT-Token").trim() || "X-JWT-Token";
        const nextHeaders = { ...(headers ?? {}) };
        nextHeaders[headerName] = `${prefix} ${token}`;
        return { headers: nextHeaders, query };
      }

      const paramName = (jwtCfg?.queryParamName ?? "token").trim() || "token";
      const nextQuery = { ...(query ?? {}) };
      nextQuery[paramName] = `${prefix} ${token}`;
      return { headers, query: nextQuery };
    }
  };
}

function generateJwtToken(jwtCfg: NonNullable<AuthConfig["jwt"]>): { token: string; expMs?: number } {
  const algorithm = jwtCfg.algorithm ?? "HS256";
  const headerObj: Record<string, unknown> = {
    typ: "JWT",
    alg: algorithm,
    ...(jwtCfg.header ?? {})
  };
  const payloadObj: Record<string, unknown> = {
    ...(jwtCfg.payload ?? {})
  };

  const iat = typeof payloadObj.iat === "number" ? payloadObj.iat : undefined;
  const exp = typeof payloadObj.exp === "number" ? payloadObj.exp : undefined;
  if (iat != null && exp != null && exp <= iat) {
    throw new Error("Nieprawidłowy JWT: exp musi być większe niż iat.");
  }

  const encodedHeader = base64UrlEncode(Buffer.from(JSON.stringify(headerObj), "utf-8"));
  const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payloadObj), "utf-8"));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  let signature = "";
  const secretRaw = String(jwtCfg.secretOrPrivateKey ?? "");

  if (algorithm === "HS256" || algorithm === "HS384" || algorithm === "HS512") {
    const key = jwtCfg.secretBase64 ? Buffer.from(secretRaw, "base64") : Buffer.from(secretRaw, "utf-8");
    const hashAlg = algorithm === "HS256" ? "sha256" : algorithm === "HS384" ? "sha384" : "sha512";
    signature = createHmac(hashAlg, key).update(signingInput).digest("base64url");
  } else if (algorithm === "RS256") {
    const privateKey = createPrivateKey(secretRaw);
    signature = createSign("RSA-SHA256").update(signingInput).end().sign(privateKey, "base64url");
  } else {
    throw new Error(`Nieobsługiwany algorytm JWT: ${algorithm}`);
  }

  const token = `${signingInput}.${signature}`;
  const expMs =
    typeof exp === "number"
      ? exp > 1_000_000_000_000
        ? exp
        : exp * 1000
      : undefined;
  return { token, expMs };
}

function isJwtShape(value: string) {
  return /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/.test(value);
}

function base64UrlEncode(buf: Buffer) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function resolveThrottleMs(throttle?: ThrottleConfig) {
  if (!throttle || throttle.mode === "none") return 0;
  const value = typeof throttle.value === "number" ? throttle.value : 0;
  if (value <= 0) return 0;
  if (throttle.mode === "delay") return Math.ceil(value);
  if (throttle.mode === "rps") return Math.ceil(1000 / value);
  return 0;
}

export function resolveSmartConfig(smart?: SmartTestConfig): SmartTestConfig {
  const fuzzDepth =
    typeof smart?.fuzzDepth === "number" && Number.isFinite(smart.fuzzDepth) ? smart.fuzzDepth : 3;
  const requestConcurrency =
    typeof smart?.requestConcurrency === "number" && Number.isFinite(smart.requestConcurrency)
      ? smart.requestConcurrency
      : 1;
  const maxTotalTests =
    typeof smart?.maxTotalTests === "number" && Number.isFinite(smart.maxTotalTests)
      ? smart.maxTotalTests
      : 0;
  const globalMaxRps =
    typeof smart?.globalMaxRps === "number" && Number.isFinite(smart.globalMaxRps)
      ? smart.globalMaxRps
      : 0;
  const requestBackoffPenaltyMs =
    typeof smart?.requestBackoffPenaltyMs === "number" && Number.isFinite(smart.requestBackoffPenaltyMs)
      ? smart.requestBackoffPenaltyMs
      : 750;
  const bodyFieldLimit =
    typeof smart?.bodyFieldLimit === "number" && Number.isFinite(smart.bodyFieldLimit)
      ? smart.bodyFieldLimit
      : 6;
  const inconclusiveMultiplier =
    typeof smart?.inconclusiveMultiplier === "number" && Number.isFinite(smart.inconclusiveMultiplier)
      ? smart.inconclusiveMultiplier
      : 0.4;
  return {
    testVolume: smart?.testVolume ?? "medium",
    requestConcurrency: Math.max(1, Math.min(16, Math.round(requestConcurrency))),
    maxTotalTests: Math.max(0, Math.min(50000, Math.round(maxTotalTests))),
    globalMaxRps: Math.max(0, Math.min(1000, Math.round(globalMaxRps))),
    adaptiveRequestBackoff: smart?.adaptiveRequestBackoff === true,
    requestBackoffPenaltyMs: Math.max(50, Math.min(30000, Math.round(requestBackoffPenaltyMs))),
    baselineIncludeUnsafeMethods: smart?.baselineIncludeUnsafeMethods === true,
    fuzzDepth: Math.max(1, Math.min(5, Math.round(fuzzDepth))),
    bodyFieldLimit: Math.max(1, Math.min(12, Math.round(bodyFieldLimit))),
    anomalySensitivity: smart?.anomalySensitivity ?? "medium",
    riskScoring: smart?.riskScoring ?? true,
    riskWeights: smart?.riskWeights,
    inconclusiveMultiplier: Math.max(0, Math.min(1, inconclusiveMultiplier)),
    responseValidation: smart?.responseValidation ?? "warn",
    enabledTests: {
      SQLi: smart?.enabledTests?.SQLi !== false,
      XSS: smart?.enabledTests?.XSS !== false,
      PATH_TRAVERSAL: smart?.enabledTests?.PATH_TRAVERSAL !== false,
      TEMPLATE_INJECTION: smart?.enabledTests?.TEMPLATE_INJECTION !== false,
      SSRF: smart?.enabledTests?.SSRF !== false,
      HEADER_INJECTION: smart?.enabledTests?.HEADER_INJECTION !== false,
      OPEN_REDIRECT: smart?.enabledTests?.OPEN_REDIRECT !== false,
      FUZZ: smart?.enabledTests?.FUZZ !== false,
      AUTH: smart?.enabledTests?.AUTH !== false,
      RATE_LIMIT: smart?.enabledTests?.RATE_LIMIT !== false
    }
  };
}

export function resolveVolumeLimits(volume?: "low" | "medium" | "high") {
  if (volume === "low") return { maxPayloads: 2, maxBodyFields: 3, maxParamPayloads: 2 };
  if (volume === "high") return { maxPayloads: 6, maxBodyFields: 10, maxParamPayloads: 6 };
  return { maxPayloads: 4, maxBodyFields: 6, maxParamPayloads: 4 };
}

function resolveBaselineSampleCount(volume?: "low" | "medium" | "high") {
  if (volume === "low") return 2;
  if (volume === "high") return 4;
  return 3;
}

export function estimateTestCounts(endpoints: EndpointDetail[], smart?: SmartTestConfig) {
  const cfg = resolveSmartConfig(smart);
  const limits = resolveVolumeLimits(cfg.testVolume);
  const enabled = cfg.enabledTests ?? {
    SQLi: true,
    XSS: true,
    PATH_TRAVERSAL: true,
    TEMPLATE_INJECTION: true,
    SSRF: true,
    HEADER_INJECTION: true,
    OPEN_REDIRECT: true,
    FUZZ: true,
    AUTH: true,
    RATE_LIMIT: true
  };
  const sql = enabled.SQLi ? generateSqlInjectionTests(endpoints, limits).length : 0;
  const xss = enabled.XSS ? generateXssTests(endpoints, limits).length : 0;
  const pathTraversal = enabled.PATH_TRAVERSAL ? generatePathTraversalTests(endpoints, limits).length : 0;
  const templateInjection = enabled.TEMPLATE_INJECTION
    ? generateTemplateInjectionTests(endpoints, limits).length
    : 0;
  const ssrf = enabled.SSRF ? generateSsrfTests(endpoints, limits).length : 0;
  const headerInjection = enabled.HEADER_INJECTION ? generateHeaderInjectionTests(endpoints, limits).length : 0;
  const openRedirect = enabled.OPEN_REDIRECT ? generateOpenRedirectTests(endpoints, limits).length : 0;
  const fuzz = enabled.FUZZ
    ? generateFuzzTests(endpoints, {
        maxParamPayloads: limits.maxParamPayloads,
        maxBodyFields: cfg.bodyFieldLimit ?? limits.maxBodyFields,
        fuzzDepth: cfg.fuzzDepth ?? 3
      }).length
    : 0;
  const auth = enabled.AUTH ? endpoints.filter((e) => hasSecurity(e)).length : 0;
  const rateLimit = enabled.RATE_LIMIT ? Math.min(4, getRateLimitCandidates(endpoints).length) : 0;
  const limited = applyGlobalTestLimit(
    {
      sql: new Array(sql),
      xss: new Array(xss),
      pathTraversal: new Array(pathTraversal),
      template: new Array(templateInjection),
      ssrf: new Array(ssrf),
      headerInjection: new Array(headerInjection),
      openRedirect: new Array(openRedirect),
      fuzz: new Array(fuzz)
    },
    cfg.maxTotalTests
  );
  const sqlLimited = limited.sql.length;
  const xssLimited = limited.xss.length;
  const pathTraversalLimited = limited.pathTraversal.length;
  const templateLimited = limited.template.length;
  const ssrfLimited = limited.ssrf.length;
  const headerInjectionLimited = limited.headerInjection.length;
  const openRedirectLimited = limited.openRedirect.length;
  const fuzzLimited = limited.fuzz.length;
  return {
    endpoints: endpoints.length,
    sql: sqlLimited,
    xss: xssLimited,
    pathTraversal: pathTraversalLimited,
    templateInjection: templateLimited,
    ssrf: ssrfLimited,
    headerInjection: headerInjectionLimited,
    openRedirect: openRedirectLimited,
    fuzz: fuzzLimited,
    auth,
    rateLimit,
    total:
      sqlLimited +
      xssLimited +
      pathTraversalLimited +
      templateLimited +
      ssrfLimited +
      headerInjectionLimited +
      openRedirectLimited +
      fuzzLimited +
      auth +
      rateLimit
  };
}

function selectBaselineEndpoints(args: {
  endpoints: EndpointDetail[];
  enabled: NonNullable<SmartTestConfig["enabledTests"]>;
  sqlTests: Array<{ method: string; path: string; originalPath?: string }>;
  xssTests: Array<{ method: string; path: string; originalPath?: string }>;
  pathTraversalTests: Array<{ method: string; path: string; originalPath?: string }>;
  templateTests: Array<{ method: string; path: string; originalPath?: string }>;
  ssrfTests: Array<{ method: string; path: string; originalPath?: string }>;
  headerInjectionTests: Array<{ method: string; path: string; originalPath?: string }>;
  openRedirectTests: Array<{ method: string; path: string; originalPath?: string }>;
  fuzzTests: Array<{ method: string; path: string; originalPath?: string }>;
}) {
  const {
    endpoints,
    enabled,
    sqlTests,
    xssTests,
    pathTraversalTests,
    templateTests,
    ssrfTests,
    headerInjectionTests,
    openRedirectTests,
    fuzzTests
  } = args;
  const endpointByKey = new Map(endpoints.map((ep) => [keyFor(ep.method, ep.path), ep] as const));
  const neededKeys = new Set<string>();

  const collect = (tests: Array<{ method: string; path: string; originalPath?: string }>) => {
    for (const t of tests) neededKeys.add(keyFor(t.method, t.originalPath ?? t.path));
  };

  if (enabled.SQLi) collect(sqlTests);
  if (enabled.XSS) collect(xssTests);
  if (enabled.PATH_TRAVERSAL) collect(pathTraversalTests);
  if (enabled.TEMPLATE_INJECTION) collect(templateTests);
  if (enabled.SSRF) collect(ssrfTests);
  if (enabled.HEADER_INJECTION) collect(headerInjectionTests);
  if (enabled.OPEN_REDIRECT) collect(openRedirectTests);
  if (enabled.FUZZ) collect(fuzzTests);
  if (enabled.AUTH) {
    for (const ep of endpoints) {
      if (hasSecurity(ep)) neededKeys.add(keyFor(ep.method, ep.path));
    }
  }
  if (enabled.RATE_LIMIT) {
    for (const ep of getRateLimitCandidates(endpoints)) {
      neededKeys.add(keyFor(ep.method, ep.path));
    }
  }

  const out: EndpointDetail[] = [];
  for (const k of neededKeys) {
    const ep = endpointByKey.get(k);
    if (ep) out.push(ep);
  }
  return out;
}

function resolveTargetBaseUrl(baseUrl: string | undefined, specObj: any) {
  const user = typeof baseUrl === "string" ? baseUrl.trim() : "";
  const serverUrl = getServerUrl(specObj);

  if (user) {
    try {
      const u = new URL(user);
      if (serverUrl && serverUrl.startsWith("/")) {
        const userHasPath = u.pathname && u.pathname !== "/" && u.pathname !== "";
        if (!userHasPath) return `${u.origin}${serverUrl}`;
      }
      return user;
    } catch {
      return user;
    }
  }

  if (serverUrl && /^https?:\/\//i.test(serverUrl)) return serverUrl;
  return "";
}

function getServerUrl(specObj: any) {
  if (!specObj || typeof specObj !== "object") return "";
  if (Array.isArray(specObj.servers) && specObj.servers.length) {
    const url = specObj.servers[0]?.url;
    return typeof url === "string" ? url : "";
  }

  const host = specObj.host;
  const basePath = typeof specObj.basePath === "string" ? specObj.basePath : "";
  const schemes = Array.isArray(specObj.schemes) ? specObj.schemes : [];
  const scheme = schemes[0] ?? "http";
  if (host) return `${scheme}://${host}${basePath}`;
  return "";
}

async function runBaselineRequests(args: {
  endpoints: EndpointDetail[];
  target: string;
  headers?: Record<string, string>;
  throttleMs?: number;
  seedMap: Map<string, string>;
  samples: number;
  requestConcurrency?: number;
  includeUnsafeMethods?: boolean;
  emit: (ev: ScanEvent) => void;
}) {
  const {
    endpoints,
    target,
    headers,
    throttleMs,
    seedMap,
    emit,
    samples,
    requestConcurrency,
    includeUnsafeMethods
  } = args;
  const map = new Map<string, BaselineResult>();
  const allowedMethods = includeUnsafeMethods
    ? new Set(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"])
    : new Set(["GET", "HEAD", "OPTIONS"]);
  emit({
    type: "step",
    message: `Baseline: sprawdzam poprawne żądania (próbek na endpoint: ${samples}, tryb=${includeUnsafeMethods ? "unsafe+" : "safe-only"})...`
  });

  const uniqueEndpoints = dedupeEndpointsForBaseline(endpoints).filter((ep) => allowedMethods.has(ep.method));
  await forEachWithConcurrency(uniqueEndpoints, requestConcurrency ?? 1, async (ep) => {
    const base = buildBaseRequest(ep, seedMap);
    const key = keyFor(ep.method, ep.path);

    const statuses: number[] = [];
    const sizes: number[] = [];
    const times: number[] = [];
    const cts: string[] = [];
    const sigs: string[] = [];
    let successCount = 0;

    for (let i = 0; i < samples; i++) {
      const prepared = prepareBody(base.body, base.contentType);
      const r = await httpRequest({
        baseUrl: target,
        method: ep.method,
        path: base.resolvedPath,
        headers: mergeHeaders(headers, base.headers, base.contentType, prepared.headers),
        body: prepared.body,
        query: base.query,
        timeoutMs: 7000
      });

      if (r.ok) {
        successCount++;
        if (typeof r.status === "number") statuses.push(r.status);
        if (typeof r.size === "number") sizes.push(r.size);
        if (typeof r.durationMs === "number") times.push(r.durationMs);
        const ct = normalizeContentType(r.headers);
        if (ct) cts.push(ct);
        const sig = buildJsonSignature(r.data);
        if (sig) sigs.push(sig);
      }

      if (throttleMs && throttleMs > 0) {
        await sleep(throttleMs);
      }
    }

    const statusVariance = uniqueCount(statuses);
    const sizeVarianceRatio = varianceRatio(sizes);
    const timeVarianceRatio = varianceRatio(times);
    const contentTypeVariance = uniqueCount(cts);
    const sigVariance = uniqueCount(sigs);
    const unstable =
      statusVariance > 1 ||
      contentTypeVariance > 1 ||
      sigVariance > 1 ||
      sizeVarianceRatio > 0.4 ||
      timeVarianceRatio > 4;

    const baselineEntry: BaselineResult = {
      ok: successCount > 0,
      status: medianNumber(statuses),
      size: medianNumber(sizes),
      timeMs: medianNumber(times),
      contentType: mostCommon(cts),
      jsonSignature: mostCommon(sigs),
      sampleCount: samples,
      successCount,
      unstable,
      statusVariance,
      sizeVarianceRatio,
      timeVarianceRatio
    };
    map.set(key, baselineEntry);

    emit({
      type: "step",
      message: `Baseline ${ep.method} ${ep.path} → status=${baselineEntry.status ?? "-"}, ok=${successCount}/${samples}, unstable=${unstable ? "TAK" : "NIE"}`
    });
  });

  return map;
}

function dedupeEndpointsForBaseline(endpoints: EndpointDetail[]) {
  const seen = new Set<string>();
  const out: EndpointDetail[] = [];
  for (const ep of endpoints) {
    const key = keyFor(ep.method, ep.path);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(ep);
  }
  return out;
}

async function runAuthNegativeTests(args: {
  endpoints: EndpointDetail[];
  target: string;
  baseline: Map<string, BaselineResult>;
  throttleMs?: number;
  requestConcurrency?: number;
  emit: (ev: ScanEvent) => void;
}): Promise<{ totalTests: number; totalErrors: number; totalSuspicious: number }> {
  const { endpoints, target, baseline, throttleMs, requestConcurrency, emit } = args;
  let totalErrors = 0;
  let totalSuspicious = 0;
  const authEndpoints = endpoints.filter((ep) => hasSecurity(ep));
  const totalTests = authEndpoints.length;

  emit({ type: "step", message: "Testy auth: sprawdzam brak autoryzacji..." });

  await forEachWithConcurrency(authEndpoints, requestConcurrency ?? 1, async (ep) => {
    const base = buildBaseRequest(ep, new Map());

    const prepared = prepareBody(base.body, base.contentType);
    const r = await httpRequest({
      baseUrl: target,
      method: ep.method,
      path: base.resolvedPath,
      skipAuth: true,
      headers: mergeHeaders(undefined, stripAuthHeaders(base.headers), base.contentType, prepared.headers),
      body: prepared.body,
      query: base.query,
      timeoutMs: 7000
    });

    if (!r.ok) totalErrors++;

    const baselineEntry = baseline.get(keyFor(ep.method, ep.path));
    const baselineStatus = baselineEntry?.status;
    const baselineSize = baselineEntry?.size;
    const baselineOk = baselineStatus != null && baselineStatus < 400;
    const baselineUnstable = baselineEntry?.unstable === true;
    const status = r.status ?? 0;
    const suspicious = baselineOk && !baselineUnstable && status < 400;
    const verdict = suspicious
      ? "suspicious"
      : !baselineOk || baselineUnstable || status >= 500
      ? "inconclusive"
      : "ok";

    if (suspicious) totalSuspicious++;

    emit({
      type: "test_result",
      testType: "AUTH",
      method: ep.method,
      path: ep.path,
      payload: "no_auth",
      location: "header",
      ok: r.ok,
      verdict,
      baselineStatus,
      baselineSize,
      status: r.status ?? 0,
      responseTimeMs: r.durationMs,
      responseSize: r.size,
      responseHeaders: pickSecurityHeaders(r.headers),
      requestUrl: buildRequestUrl(target, base.resolvedPath, base.query),
      suspicious,
      evidence: joinEvidence(
        typeof r.data === "string" ? r.data.slice(0, 400) : undefined,
        baselineUnstable ? "Baseline niestabilny (wynik ostrożny)." : undefined
      ),
      error: r.ok ? undefined : String(r.error ?? "Unknown error")
    });

    emit({
      type: "step",
      message: `AUTH ${ep.method} ${ep.path} → ${r.ok ? r.status : "error"} (${verdict})`
    });

    if (throttleMs && throttleMs > 0) {
      await sleep(throttleMs);
    }
  });

  return { totalTests, totalErrors, totalSuspicious };
}

async function runRateLimitTests(args: {
  endpoints: EndpointDetail[];
  target: string;
  headers?: Record<string, string>;
  throttleMs?: number;
  baseline: Map<string, BaselineResult>;
  seedMap: Map<string, string>;
  requestConcurrency?: number;
  emit: (ev: ScanEvent) => void;
}): Promise<{ totalTests: number; totalErrors: number; totalSuspicious: number }> {
  const { endpoints, target, headers, throttleMs, baseline, seedMap, requestConcurrency, emit } = args;
  const candidates = getRateLimitCandidates(endpoints);

  if (!candidates.length) return { totalTests: 0, totalErrors: 0, totalSuspicious: 0 };

  emit({ type: "step", message: "Testy rate limit: sprawdzam ograniczenia na wrażliwych endpointach..." });

  const rateLimitEndpoints = candidates.slice(0, 4);
  const totalTests = rateLimitEndpoints.length;
  let totalErrors = 0;
  let totalSuspicious = 0;

  await forEachWithConcurrency(rateLimitEndpoints, requestConcurrency ?? 1, async (ep) => {
    const base = buildBaseRequest(ep, seedMap);
    const baselineEntry = baseline.get(keyFor(ep.method, ep.path));
    const baselineStatus = baselineEntry?.status;
    const baselineOk = baselineStatus != null && baselineStatus < 400;
    const baselineUnstable = baselineEntry?.unstable === true;

    const burstCount = 10;
    const burstDelayMs = 50;
    const statuses: number[] = [];
    const times: number[] = [];
    let errors = 0;
    let lastHeaders: Record<string, string> | undefined;

    for (let i = 0; i < burstCount; i++) {
      const prepared = prepareBody(base.body, base.contentType);
      const r = await httpRequest({
        baseUrl: target,
        method: ep.method,
        path: base.resolvedPath,
        headers: mergeHeaders(headers, base.headers, base.contentType, prepared.headers),
        body: prepared.body,
        query: base.query,
        timeoutMs: 7000
      });

      if (!r.ok) {
        errors++;
      } else {
        statuses.push(r.status ?? 0);
        times.push(r.durationMs ?? 0);
        lastHeaders = r.headers;
      }

      if (burstDelayMs) await sleep(burstDelayMs);
    }

    const any429 = statuses.includes(429);
    const avgMs = times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : 0;
    const maxMs = times.length ? Math.max(...times) : 0;
    const baselineMs = baselineEntry?.timeMs ?? 0;
    const slowed = baselineMs > 0 && avgMs > baselineMs * 2;

    const ok = errors === 0 && statuses.length > 0;
    const suspicious = baselineOk && !baselineUnstable && !any429 && !slowed;
    const verdict = !ok
      ? "error"
      : !baselineOk || baselineUnstable
      ? "inconclusive"
      : suspicious
      ? "suspicious"
      : "ok";

    if (!ok) totalErrors++;
    if (suspicious) totalSuspicious++;

    const evidence = `burst=${burstCount}, delay=${burstDelayMs}ms, statusy=${summarizeStatusCounts(
      statuses
    )}, avg=${avgMs}ms, max=${maxMs}ms, baseline=${baselineMs || "-"}ms`;

    emit({
      type: "test_result",
      testType: "RATE_LIMIT",
      method: ep.method,
      path: ep.path,
      payload: `burst_${burstCount}`,
      location: "header",
      ok,
      verdict,
      baselineStatus,
      baselineSize: baselineEntry?.size,
      status: statuses[statuses.length - 1],
      responseTimeMs: avgMs,
      responseSize: undefined,
      responseHeaders: pickSecurityHeaders(lastHeaders),
      requestUrl: buildRequestUrl(target, base.resolvedPath, base.query),
      suspicious,
      evidence,
      error: ok ? undefined : "Błąd w części żądań burst"
    });

    emit({
      type: "step",
      message: `RATE_LIMIT ${ep.method} ${ep.path} → ${verdict} (${evidence})`
    });

    if (throttleMs && throttleMs > 0) await sleep(throttleMs);
  });

  return { totalTests, totalErrors, totalSuspicious };
}

function hasSecurity(ep: EndpointDetail) {
  if (!ep.security) return false;
  if (Array.isArray(ep.security) && ep.security.length === 0) return false;
  return true;
}

function getRateLimitCandidates(endpoints: EndpointDetail[]) {
  const keywords = [
    "login",
    "auth",
    "token",
    "password",
    "reset",
    "otp",
    "verify",
    "code",
    "register",
    "signup",
    "sign-up",
    "sms",
    "email"
  ];

  return endpoints.filter((ep) => {
    if (!["POST", "GET"].includes(ep.method)) return false;
    const path = ep.path.toLowerCase();
    return keywords.some((k) => path.includes(k));
  });
}

function stripAuthHeaders(headers?: Record<string, string>) {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (key === "authorization") continue;
    if (key.includes("api-key") || key.includes("api_key") || key.includes("apikey")) continue;
    out[k] = v;
  }
  return Object.keys(out).length ? out : undefined;
}

type BaseRequest = {
  body?: any;
  query: Record<string, string>;
  resolvedPath: string;
  contentType?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
};

function buildBaseRequest(ep: EndpointDetail, seedMap: Map<string, string> = new Map()): BaseRequest {
  let body = ep.requestBodySchema ? buildExampleFromSchema(ep.requestBodySchema, 0) : undefined;
  const contentType = pickContentType(ep.requestBodyContentTypes);
  const query: Record<string, string> = {};
  const headers: Record<string, string> = {};
  const cookies: Record<string, string> = {};

  for (const p of ep.parameters ?? []) {
    if (p.in === "query") {
      query[p.name] = exampleValue(p) ?? "test";
    }
    if (p.in === "header") {
      headers[p.name] = exampleValue(p) ?? "test";
    }
    if (p.in === "cookie") {
      cookies[p.name] = exampleValue(p) ?? "test";
    }
    if (p.in === "formData") {
      if (!body || typeof body !== "object") {
        // form fields in Swagger 2.0 are modeled as parameters
        body = {};
      }
      if (body && typeof body === "object") {
        (body as any)[p.name] = exampleValue(p) ?? "test";
      }
    }
  }

  const resolvedPath = resolvePath(ep.path, ep.parameters);
  const seededPath = applySeedToPath(resolvedPath, ep.parameters, seedMap);
  const cookieHeader = buildCookieHeader(cookies);
  if (cookieHeader) headers.Cookie = cookieHeader;
  return { body, query, resolvedPath: seededPath, contentType, headers, cookies };
}

function resolvePath(path: string, params?: EndpointDetail["parameters"]) {
  if (!params || !params.length) return path;
  let out = path;
  for (const p of params) {
    if (p.in !== "path") continue;
    const value = encodeURIComponent(exampleValue(p) ?? "1");
    out = out.replace(`{${p.name}}`, value);
  }
  return out;
}

function resolvePathParam(path: string, param: string, payload: string) {
  const value = encodeURIComponent(payload);
  return path.replace(`{${param}}`, value);
}

function applySeedToPath(
  path: string,
  params: EndpointDetail["parameters"] | undefined,
  seedMap: Map<string, string> | undefined
) {
  if (!params || !params.length) return path;
  if (!seedMap || seedMap.size === 0) return path;
  let out = path;
  for (const p of params) {
    if (p.in !== "path") continue;
    const seed = pickSeedForParam(path, p.name, seedMap);
    if (!seed) continue;
    out = out.replace(`{${p.name}}`, encodeURIComponent(seed));
  }
  return out;
}

function pickSeedForParam(path: string, paramName: string, seedMap: Map<string, string> | undefined) {
  if (!seedMap) return undefined;
  const key = resourceKeyFromPath(path);
  if (paramName.toLowerCase().includes("id") && seedMap.has(key)) {
    return seedMap.get(key);
  }
  if (seedMap.has(paramName)) return seedMap.get(paramName);
  if (seedMap.has(key)) return seedMap.get(key);
  return undefined;
}

function resourceKeyFromPath(path: string) {
  const parts = path.split("/").filter(Boolean);
  return parts[0] ?? path;
}

function applySeedToTemplate(path: string, seedMap: Map<string, string>) {
  if (!path.includes("{")) return path;
  const key = resourceKeyFromPath(path);
  const seed = seedMap.get(key);
  if (!seed) return path;
  return path.replace(/\{[^}]+\}/g, encodeURIComponent(seed));
}

async function runSeedMode(args: {
  endpoints: EndpointDetail[];
  target: string;
  headers?: Record<string, string>;
  throttleMs?: number;
  seed?: SeedConfig | boolean;
  emit: (ev: ScanEvent) => void;
}) {
  const { endpoints, target, headers, throttleMs, seed, emit } = args;
  const enabled = typeof seed === "boolean" ? seed : seed?.enabled;
  const seedMap = new Map<string, string>();
  const results: { method: string; path: string; resourceKey: string; id?: string; status: "ok" | "error" | "no_id"; message?: string }[] = [];
  if (!enabled) return { map: seedMap, results };

  const defaultCreates = inferSeedCreates(endpoints);
  const createEndpoints = (typeof seed === "object" && Array.isArray(seed.createEndpoints))
    ? seed.createEndpoints.filter((c) => c.enabled !== false)
    : defaultCreates;

  if (!createEndpoints.length) return { map: seedMap, results };

  emit({ type: "step", message: "Seed mode: tworzę dane testowe..." });

  for (const ce of createEndpoints) {
    const ep = endpoints.find(
      (e) => e.method === ce.method.toUpperCase() && e.path === ce.path
    );
    if (!ep) continue;
    const base = buildBaseRequest(ep, seedMap);
    const query = { ...base.query, ...(ce.query ?? {}) };
    const headersFromSeed = ce.headers ?? {};
    const inputMode = ce.inputMode ?? "json";
    const contentType = ce.contentType ?? (inputMode === "binary" ? "application/octet-stream" : base.contentType);
    const accept = ce.accept;

    let bodyForSeed =
      inputMode === "none"
        ? undefined
        : ce.payload ?? base.body ?? (inputMode === "json" ? {} : {});

    if (inputMode === "multipart" && bodyForSeed && ce.files) {
      const merged = typeof bodyForSeed === "object" ? { ...bodyForSeed } : {};
      for (const [key, ref] of Object.entries(ce.files)) {
        const file = seedFiles.get(ref.fileId);
        if (file?.buffer) merged[key] = file.buffer;
      }
      bodyForSeed = merged;
    }
    const prepared = prepareBody(bodyForSeed, contentType);
    const acceptHeader = accept ? { Accept: accept } : undefined;
    const extraHeaders = { ...(acceptHeader ?? {}), ...(prepared.headers ?? {}) };
    let r = await httpRequest({
      baseUrl: target,
      method: ep.method,
      path: base.resolvedPath,
      headers: mergeHeaders(headers, { ...base.headers, ...headersFromSeed }, contentType, extraHeaders),
      body: prepared.body,
      query,
      timeoutMs: 7000
    });

    if ((r.status === 409 || r.status === 422) && bodyForSeed) {
      const tweaked = tweakStringFields(bodyForSeed);
      const tweakedPrepared = prepareBody(tweaked, contentType);
      const tweakedExtra = { ...(acceptHeader ?? {}), ...(tweakedPrepared.headers ?? {}) };
      r = await httpRequest({
        baseUrl: target,
        method: ep.method,
        path: base.resolvedPath,
        headers: mergeHeaders(headers, { ...base.headers, ...headersFromSeed }, contentType, tweakedExtra),
        body: tweakedPrepared.body,
        query,
        timeoutMs: 7000
      });
    }

    const id = r.ok ? extractIdFromResponse(r.data, r.headers, ce.idExtractor) : undefined;
    const fallbackId = id ?? (r.ok ? extractId(r.data) : undefined);
    const finalId = fallbackId;
    if (!r.ok) {
      results.push({ method: ep.method, path: ep.path, resourceKey: ce.resourceKey ?? resourceKeyFromPath(ep.path), status: "error", message: String(r.error ?? r.status ?? "error") });
      emit({ type: "step", message: `Seed: ${ep.method} ${ep.path} → błąd` });
    } else if (finalId) {
      const key = ce.resourceKey ?? resourceKeyFromPath(ep.path);
      seedMap.set(key, String(finalId));
      results.push({ method: ep.method, path: ep.path, resourceKey: key, id: String(finalId), status: "ok" });
      emit({ type: "step", message: `Seed: ${ep.method} ${ep.path} → id=${finalId}` });
    } else {
      const key = ce.resourceKey ?? resourceKeyFromPath(ep.path);
      results.push({ method: ep.method, path: ep.path, resourceKey: key, status: "no_id" });
      emit({ type: "step", message: `Seed: ${ep.method} ${ep.path} → brak id` });
    }

    if (throttleMs && throttleMs > 0) await sleep(throttleMs);
  }

  return { map: seedMap, results };
}

function inferSeedCreates(endpoints: EndpointDetail[]) {
  const candidates = [
    { method: "POST", path: "/pets" },
    { method: "POST", path: "/orders" },
    { method: "POST", path: "/users" }
  ];
  return candidates.filter((c) =>
    endpoints.some((e) => e.method === c.method && e.path === c.path)
  );
}

function tweakStringFields(body: any) {
  if (body == null || typeof body !== "object") return body;
  const clone = JSON.parse(JSON.stringify(body));
  const now = Date.now();
  const walk = (obj: any) => {
    if (Array.isArray(obj)) {
      obj.forEach(walk);
      return;
    }
    if (obj && typeof obj === "object") {
      for (const key of Object.keys(obj)) {
        const v = obj[key];
        if (typeof v === "string") {
          obj[key] = `${v}-${now}`;
        } else {
          walk(v);
        }
      }
    }
  };
  walk(clone);
  return clone;
}
function extractId(data: any) {
  if (!data) return undefined;
  if (typeof data === "object") {
    for (const key of ["id", "petId", "orderId", "userId"]) {
      if ((data as any)[key] != null) return (data as any)[key];
    }
    if (Array.isArray(data) && data.length && (data[0] as any)?.id != null) return (data[0] as any).id;
  }
  return undefined;
}

function getPath(obj: any, path: string) {
  const parts = path.replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  let cur = obj;
  for (const p of parts) {
    if (cur == null) return undefined;
    cur = cur[p];
  }
  return cur;
}

function extractIdFromResponse(data: any, headers: Record<string, string> | undefined, idExtractor?: string | null) {
  if (!idExtractor) return undefined;
  if (idExtractor.startsWith("header.")) {
    const key = idExtractor.slice("header.".length).toLowerCase();
    const map = new Map(Object.entries(headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const val = map.get(key);
    if (val) return val;
    return undefined;
  }
  if (idExtractor.startsWith("body.")) {
    return getPath(data, idExtractor);
  }
  return undefined;
}

function exampleValue(p: any) {
  if (p?.example != null) return String(p.example);
  if (p?.default != null) return String(p.default);
  const schema = p?.schema;
  if (schema?.example != null) return String(schema.example);
  if (schema?.default != null) return String(schema.default);
  if (schema?.enum && schema.enum.length) return String(schema.enum[0]);
  return undefined;
}

function buildExampleFromSchema(schema: any, depth: number): any {
  if (!schema || depth > 3) return undefined;
  if (schema.$ref) return undefined;
  if (Array.isArray(schema.oneOf) || Array.isArray(schema.anyOf) || Array.isArray(schema.allOf)) {
    const next = schema.oneOf?.[0] ?? schema.anyOf?.[0] ?? schema.allOf?.[0];
    return buildExampleFromSchema(next, depth + 1);
  }
  if (schema.example != null) return schema.example;
  if (schema.default != null) return schema.default;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];

  const type = schema.type;
  if (type === "string") return schema.format === "date" ? "2018-01-01" : "test";
  if (type === "integer") return 1;
  if (type === "number") return 1.1;
  if (type === "boolean") return true;
  if (type === "array") {
    const item = buildExampleFromSchema(schema.items, depth + 1);
    return item === undefined ? [] : [item];
  }
  if (type === "object" || schema.properties) {
    const obj: Record<string, any> = {};
    const props = schema.properties ?? {};
    const required: string[] = Array.isArray(schema.required) ? schema.required : [];
    for (const key of required) {
      if (props[key] == null) continue;
      obj[key] = buildExampleFromSchema(props[key], depth + 1);
    }
    return obj;
  }
  return undefined;
}

function keyFor(method: string, path: string) {
  return `${method.toUpperCase()} ${path}`;
}

function sleep(ms: number) {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

function dedupeGeneratedTests<T>(tests: T[]) {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const t of tests) {
    const key = buildGeneratedTestKey(t as any);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(t);
  }
  return out;
}

function buildGeneratedTestKey(test: any) {
  return [
    String(test?.method ?? "").toUpperCase(),
    String(test?.originalPath ?? test?.path ?? ""),
    String(test?.path ?? ""),
    String(test?.location ?? ""),
    String(test?.payload ?? ""),
    String(test?.contentType ?? ""),
    stableSerialize(test?.query),
    stableSerialize(test?.headers),
    stableSerialize(test?.body)
  ].join("|");
}

function stableSerialize(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableSerialize(v)).join(",")}]`;
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${k}:${stableSerialize(obj[k])}`).join(",")}}`;
  }
  return String(value);
}

function applyGlobalTestLimit<T extends Record<string, any[]>>(
  groups: T,
  maxTotalTests?: number
): T & { kept: number; trimmed: number } {
  const cap =
    typeof maxTotalTests === "number" && Number.isFinite(maxTotalTests)
      ? Math.max(0, Math.floor(maxTotalTests))
      : 0;
  if (cap <= 0) {
    const kept = Object.values(groups).reduce((acc, arr) => acc + arr.length, 0);
    return { ...groups, kept, trimmed: 0 };
  }

  const out = {} as Record<string, any[]>;
  let original = 0;
  const entries = Object.entries(groups);
  for (const [, arr] of entries) {
    original += arr.length;
  }

  for (const [k] of entries) out[k] = [];

  let kept = 0;
  let cursor = 0;
  while (kept < cap) {
    let progressed = false;
    for (let i = 0; i < entries.length && kept < cap; i++) {
      const [k, arr] = entries[i];
      if (cursor >= arr.length) continue;
      out[k].push(arr[cursor]);
      kept++;
      progressed = true;
    }
    if (!progressed) break;
    cursor++;
  }

  return { ...(out as T), kept, trimmed: Math.max(0, original - kept) };
}

async function forEachWithConcurrency<T>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<void>
) {
  if (!items.length) return;
  const limit = Math.max(1, Math.floor(concurrency));
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const current = index++;
      if (current >= items.length) return;
      await fn(items[current], current);
    }
  });
  await Promise.all(workers);
}
function pickContentType(types?: string[]) {
  if (!types || !types.length) return "application/json";
  if (types.includes("application/json")) return "application/json";
  if (types.includes("application/x-www-form-urlencoded")) return "application/x-www-form-urlencoded";
  return types[0];
}

function mergeHeaders(
  base: Record<string, string> | undefined,
  extra: Record<string, string> | undefined,
  contentType?: string,
  extra2?: Record<string, string>
) {
  const headers: Record<string, string> = { ...(base ?? {}) };
  if (extra) {
    for (const [k, v] of Object.entries(extra)) headers[k] = v;
  }
  if (extra2) {
    for (const [k, v] of Object.entries(extra2)) headers[k] = v;
  }
  if (contentType && !contentType.includes("multipart/form-data")) {
    const hasContentType = Object.keys(headers).some((k) => k.toLowerCase() === "content-type");
    if (!hasContentType) headers["Content-Type"] = contentType;
  }
  return Object.keys(headers).length ? headers : undefined;
}

type PreparedBody = { body: any; headers?: Record<string, string> };

function prepareBody(body: any, contentType?: string): PreparedBody {
  if (!body) return { body };
  if (contentType && contentType.includes("multipart/form-data")) {
    const form = new FormData();
    const flat = flattenObject(body);
    for (const [k, v] of Object.entries(flat)) {
      if (Buffer.isBuffer(v)) {
        form.append(k, v, { filename: "seed-file" });
      } else {
        form.append(k, v as any);
      }
    }
    return { body: form, headers: form.getHeaders() };
  }
  if (contentType === "application/x-www-form-urlencoded") {
    const flat = flattenObject(body);
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(flat)) params.set(k, String(v));
    return { body: params };
  }
  return { body };
}

function flattenObject(obj: any, prefix = "", out: Record<string, string> = {}) {
  if (obj == null) return out;
  if (typeof obj !== "object") {
    out[prefix] = String(obj);
    return out;
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => flattenObject(v, `${prefix}[${i}]`, out));
    return out;
  }
  for (const key of Object.keys(obj)) {
    const next = prefix ? `${prefix}.${key}` : key;
    flattenObject(obj[key], next, out);
  }
  return out;
}

function buildCookieHeader(cookies: Record<string, string>) {
  const entries = Object.entries(cookies);
  if (!entries.length) return "";
  return entries.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("; ");
}

function parseCookieHeader(header?: string) {
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (!k) continue;
    out[k] = decodeURIComponent(rest.join("=") || "");
  }
  return out;
}

function mergeCookieHeader(headers: Record<string, string> | undefined, key: string, value: string) {
  const base = parseCookieHeader(headers?.Cookie);
  base[key] = value;
  const merged = buildCookieHeader(base);
  return { ...(headers ?? {}), Cookie: merged };
}

function cloneJson<T>(v: T): T {
  return v == null ? v : JSON.parse(JSON.stringify(v));
}

function setValueAtPath(obj: any, path: string, value: any) {
  if (!path) return;
  const parts = path.replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (cur[key] == null) cur[key] = {};
    cur = cur[key];
  }
  cur[parts[parts.length - 1]] = value;
}

function collectSchemaPaths(
  schema: any,
  prefix = "",
  depth = 0,
  maxDepth = 3
): { path: string; schema: any }[] {
  if (!schema || depth > maxDepth) return [];
  if (schema.$ref) return [];
  if (Array.isArray(schema.oneOf) || Array.isArray(schema.anyOf) || Array.isArray(schema.allOf)) {
    const next = schema.oneOf?.[0] ?? schema.anyOf?.[0] ?? schema.allOf?.[0];
    return collectSchemaPaths(next, prefix, depth + 1, maxDepth);
  }

  if (schema.type === "object" || schema.properties) {
    const props = schema.properties ?? {};
    const out: { path: string; schema: any }[] = [];
    for (const key of Object.keys(props)) {
      const next = prefix ? `${prefix}.${key}` : key;
      out.push(...collectSchemaPaths(props[key], next, depth + 1, maxDepth));
    }
    return out;
  }

  if (schema.type === "array" && schema.items) {
    const next = `${prefix}[0]`;
    return collectSchemaPaths(schema.items, next, depth + 1, maxDepth);
  }

  if (prefix) return [{ path: prefix, schema }];
  return [];
}

function deriveFuzzPayloads(schema: any, name?: string): string[] {
  const payloads: string[] = [];
  if (!schema) return payloads;
  const type = schema.type;
  if (schema.enum && schema.enum.length) {
    payloads.push("invalid_enum_value");
  }

  if (type === "string" || !type) {
    const format = schema.format;
    const pattern = schema.pattern;
    if (format === "email") payloads.push("not-an-email");
    if (format === "uuid") payloads.push("not-a-uuid");
    if (format === "date") payloads.push("2024-13-40");
    if (format === "date-time") payloads.push("2024-13-40T25:61:61Z");
    if (format === "uri" || format === "url") payloads.push("://bad-url");
    if (format === "ipv4") payloads.push("999.999.999.999");
    if (format === "ipv6") payloads.push("gggg::ffff");
    if (pattern) payloads.push("invalid_pattern");
    if (typeof schema.minLength === "number" && schema.minLength > 0) payloads.push("");
    if (typeof schema.maxLength === "number") {
      const len = Math.min(schema.maxLength + 10, 4096);
      payloads.push("A".repeat(len));
    }
    if (name && name.toLowerCase().includes("id")) payloads.push("0");
  }

  if (type === "integer" || type === "number") {
    if (typeof schema.minimum === "number") payloads.push(String(schema.minimum - 1));
    if (typeof schema.maximum === "number") payloads.push(String(schema.maximum + 1));
    payloads.push("1.5", "abc");
  }

  if (type === "boolean") payloads.push("not_bool");

  return Array.from(new Set(payloads)).slice(0, 6);
}

function deriveFuzzValuesForSchema(schema: any): any[] {
  const payloads = deriveFuzzPayloads(schema);
  return payloads.length ? payloads : ["invalid_value"];
}

function normalizeContentType(headers?: Record<string, string>) {
  if (!headers) return "";
  const key = Object.keys(headers).find((k) => k.toLowerCase() === "content-type");
  const raw = key ? String(headers[key]) : "";
  return raw.split(";")[0].trim().toLowerCase();
}

function isJsonContentType(ct?: string) {
  if (!ct) return false;
  return ct.includes("application/json") || ct.includes("+json");
}

function isHtmlContentType(ct?: string) {
  if (!ct) return false;
  return ct.includes("text/html") || ct.includes("application/xhtml");
}

function buildJsonSignature(data: unknown) {
  if (data == null) return undefined;
  const type = Array.isArray(data) ? "array" : typeof data;
  if (type !== "object" && type !== "array") return String(type);
  return signatureForValue(data, 2);
}

function signatureForValue(value: any, depth: number): string {
  if (value == null) return "null";
  if (Array.isArray(value)) {
    if (depth <= 0) return "array";
    const first = value[0];
    return `array:${signatureForValue(first, depth - 1)}`;
  }
  if (typeof value === "object") {
    if (depth <= 0) return "object";
    const keys = Object.keys(value).sort();
    const inner = keys.slice(0, 12).map((k) => `${k}:${signatureForValue(value[k], depth - 1)}`);
    return `{${inner.join(",")}}`;
  }
  return typeof value;
}

function isResponseAnomalous(
  baseline: BaselineResult,
  r: { headers?: Record<string, string>; data?: unknown; size?: number; status?: number },
  sensitivity: "low" | "medium" | "high" = "medium"
) {
  if (!baseline || !baseline.ok) return false;
  if (baseline.unstable) return false;
  const baseCt = baseline.contentType;
  const curCt = normalizeContentType(r.headers);
  const baseIsJson = isJsonContentType(baseCt);
  const curIsJson = isJsonContentType(curCt);
  const baseIsHtml = isHtmlContentType(baseCt);
  const curIsHtml = isHtmlContentType(curCt);

  const contentTypeMismatch =
    (baseIsJson && !curIsJson) || (baseIsHtml && !curIsHtml) || (!!baseCt && !!curCt && baseCt !== curCt);

  const curSig = buildJsonSignature(r.data);
  const sigMismatch = baseline.jsonSignature && curSig && baseline.jsonSignature !== curSig;

  const size = typeof r.size === "number" ? r.size : 0;
  const baseSize = typeof baseline.size === "number" ? baseline.size : 0;
  const varianceBoost = 1 + (baseline.sizeVarianceRatio ?? 0) * 2;
  const sizeMultiplierBase = sensitivity === "high" ? 1.2 : sensitivity === "low" ? 2.5 : 1.5;
  const sizeMultiplier = sizeMultiplierBase * varianceBoost;
  const sizeJump = baseSize > 0 && size > baseSize * sizeMultiplier;

  return contentTypeMismatch || (sigMismatch && sizeJump);
}

function isHtmlResponse(
  r: { headers?: Record<string, string>; data?: unknown },
  baseline?: BaselineResult,
  expected?: string[]
) {
  const responseCt = normalizeContentType(r.headers);
  if (isHtmlContentType(responseCt)) return true;
  if (isJsonContentType(responseCt)) return false;

  const expectedTypes = Array.isArray(expected)
    ? expected.map((t) => t.split(";")[0].trim().toLowerCase())
    : [];
  const expectedHtml = expectedTypes.some((t) => isHtmlContentType(t));
  const expectedJson = expectedTypes.some((t) => isJsonContentType(t));
  if (expectedHtml) return true;
  if (expectedJson) return false;

  const ct = baseline?.contentType || "";
  if (isHtmlContentType(ct)) return true;
  if (isJsonContentType(ct)) return false;

  const dataStr = typeof r.data === "string" ? r.data : "";
  return /<html|<body|<script|<svg/i.test(dataStr);
}

function assessXssSignal(dataStr: string, payload: string, htmlLike: boolean) {
  const reflection = dataStr.includes(payload);
  const payloadDangerous = /<script\b|on\w+\s*=|javascript:|<img\b|<svg\b|alert\s*\(/i.test(payload);
  const responseDangerous = /<script\b|on\w+\s*=|javascript:|<img\b|<svg\b/i.test(dataStr);
  const payloadHtmlTag = /<\s*\/?\s*[a-z]/i.test(payload);
  const benignFormattingOnly = /^<\s*(b|i|u|em|strong)\b[^>]*>.*<\s*\/\s*(b|i|u|em|strong)\s*>$/i.test(
    payload
  );

  if (!htmlLike) {
    return {
      reflection,
      exploitableLikely: false,
      reason: reflection ? "odbicie poza HTML" : undefined
    };
  }

  if (!reflection) {
    return {
      reflection,
      exploitableLikely: false,
      reason: undefined
    };
  }

  if (payloadDangerous && responseDangerous) {
    return {
      reflection,
      exploitableLikely: true,
      reason: "odbicie niebezpiecznego payloadu HTML/JS"
    };
  }

  if (payloadHtmlTag && !benignFormattingOnly) {
    return {
      reflection,
      exploitableLikely: true,
      reason: "odbicie surowego HTML (potencjalna injekcja)"
    };
  }

  return {
    reflection,
    exploitableLikely: false,
    reason: benignFormattingOnly ? "odbicie tylko tagów formatowania" : "odbicie o niskiej pewności"
  };
}

function validateResponseSchema(schema: any, r: { headers?: Record<string, string>; data?: unknown }) {
  if (!schema) return [];
  const issues: string[] = [];
  const ct = normalizeContentType(r.headers);
  const isJson = isJsonContentType(ct) || (r.data != null && typeof r.data === "object");
  if (!isJson) {
    issues.push("Odpowiedź nie jest JSON");
    return issues;
  }
  validateValueAgainstSchema(schema, r.data, "response", 0, issues);
  return issues.slice(0, 3);
}

function validateValueAgainstSchema(
  schema: any,
  value: any,
  path: string,
  depth: number,
  issues: string[]
) {
  if (!schema || depth > 3 || issues.length >= 3) return;
  if (schema.$ref) return;
  if (Array.isArray(schema.oneOf) || Array.isArray(schema.anyOf) || Array.isArray(schema.allOf)) {
    const next = schema.oneOf?.[0] ?? schema.anyOf?.[0] ?? schema.allOf?.[0];
    return validateValueAgainstSchema(next, value, path, depth + 1, issues);
  }

  const type = schema.type;
  if (type === "object" || schema.properties) {
    if (value == null || typeof value !== "object" || Array.isArray(value)) {
      issues.push(`${path} powinien być obiektem`);
      return;
    }
    const required: string[] = Array.isArray(schema.required) ? schema.required : [];
    for (const key of required) {
      if (value[key] == null) issues.push(`${path}.${key} jest wymagane`);
    }
    const props = schema.properties ?? {};
    for (const key of Object.keys(props)) {
      if (value[key] != null) {
        validateValueAgainstSchema(props[key], value[key], `${path}.${key}`, depth + 1, issues);
      }
    }
    return;
  }

  if (type === "array") {
    if (!Array.isArray(value)) {
      issues.push(`${path} powinien być tablicą`);
      return;
    }
    const item = value.length ? value[0] : undefined;
    if (schema.items && item !== undefined) {
      validateValueAgainstSchema(schema.items, item, `${path}[0]`, depth + 1, issues);
    }
    return;
  }

  if (type === "string") {
    if (typeof value !== "string") issues.push(`${path} powinien być stringiem`);
    return;
  }
  if (type === "integer") {
    if (typeof value !== "number" || !Number.isInteger(value)) issues.push(`${path} powinien być int`);
    return;
  }
  if (type === "number") {
    if (typeof value !== "number") issues.push(`${path} powinien być liczbą`);
    return;
  }
  if (type === "boolean") {
    if (typeof value !== "boolean") issues.push(`${path} powinien być boolean`);
    return;
  }
}

function uniqueCount(values: Array<string | number>) {
  return new Set(values).size;
}

function medianNumber(values: number[]) {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[mid];
  return Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

function varianceRatio(values: number[]) {
  if (values.length < 2) return 0;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const med = medianNumber(values) ?? 0;
  if (med <= 0) return 0;
  return (max - min) / med;
}

function mostCommon(values: string[]) {
  if (!values.length) return undefined;
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
}

function joinEvidence(...parts: Array<string | undefined>) {
  return parts.filter((p) => typeof p === "string" && p.trim()).join(" | ");
}

function buildRequestUrl(baseUrl: string, path: string, query?: Record<string, string>) {
  try {
    const u = new URL(path, baseUrl);
    if (query) {
      for (const [k, v] of Object.entries(query)) u.searchParams.set(k, String(v));
    }
    return u.toString();
  } catch {
    return `${baseUrl}${path}`;
  }
}

function pickSecurityHeaders(headers?: Record<string, string>) {
  if (!headers) return undefined;
  const lower = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)]));
  const wanted = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security"
  ];
  const out: Record<string, string> = {};
  for (const key of wanted) {
    const val = lower.get(key);
    if (val) out[key] = val;
  }
  return Object.keys(out).length ? out : undefined;
}

function summarizeStatusCounts(statuses: number[]) {
  if (!statuses.length) return "-";
  const counts: Record<string, number> = {};
  for (const s of statuses) counts[s] = (counts[s] ?? 0) + 1;
  return Object.entries(counts)
    .map(([k, v]) => `${k}:${v}`)
    .join("|");
}

function detectOpenRedirectSignal(
  targetBaseUrl: string,
  payload: string,
  status: number,
  headers?: Record<string, string>
) {
  if (status < 300 || status >= 400) {
    return { suspicious: false, reason: undefined as string | undefined };
  }
  const location = readHeader(headers, "location");
  if (!location) return { suspicious: false, reason: "Brak nagłówka Location przy 3xx." };

  const locationLower = location.toLowerCase();
  const payloadLower = payload.toLowerCase();
  const payloadHost = hostFromUrl(payloadLower);
  const targetHost = hostFromUrl(targetBaseUrl.toLowerCase());
  const locationHost = hostFromUrl(locationLower);

  const payloadEcho =
    locationLower.includes(payloadLower) ||
    (payloadHost && locationLower.includes(payloadHost)) ||
    (payloadLower.startsWith("//") && locationLower.includes(payloadLower.slice(2)));
  const externalHost = Boolean(locationHost && targetHost && locationHost !== targetHost);
  const suspicious = payloadEcho && externalHost;
  return {
    suspicious,
    reason: suspicious
      ? `Przekierowanie na zewnętrzny host po payloadzie (${location}).`
      : `3xx bez dowodu zewnętrznego przekierowania (${location}).`
  };
}

function hostFromUrl(input: string) {
  try {
    if (input.startsWith("//")) {
      return new URL(`http:${input}`).host.toLowerCase();
    }
    return new URL(input).host.toLowerCase();
  } catch {
    return "";
  }
}

function readHeader(headers: Record<string, string> | undefined, name: string) {
  if (!headers) return "";
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return String(v);
  }
  return "";
}

function detectHeaderInjectionSignal(headers: Record<string, string> | undefined, payload: string) {
  if (!headers) return { suspicious: false, reason: undefined as string | undefined };
  const headerNames = Object.keys(headers).map((k) => k.toLowerCase());
  const values = Object.values(headers).map((v) => String(v).toLowerCase());
  const payloadMarker = payload.toLowerCase().replace(/%20/g, " ").replace(/%0d|%0a/g, "").trim();

  const markerHeader = headerNames.includes("x-tomsec-injection");
  const payloadEcho = payloadMarker.length > 2 && values.some((v) => v.includes(payloadMarker));
  const suspicious = markerHeader || payloadEcho;
  return {
    suspicious,
    reason: suspicious
      ? `Nagłówki odpowiedzi wskazują możliwą injekcję (${headerNames.join(",")}).`
      : undefined
  };
}

function detectSsrfSignal(payload: string, data: unknown) {
  const body = typeof data === "string" ? data : JSON.stringify(data ?? {});
  const lower = body.toLowerCase();
  const payloadLower = payload.toLowerCase();
  const payloadHost = hostFromUrl(payloadLower);
  const internalPayload =
    payloadLower.includes("127.0.0.1") ||
    payloadLower.includes("169.254.169.254") ||
    payloadLower.includes("localhost");

  const internalIndicators = [
    "internal_resource_accessed",
    "metadata",
    "instance-id",
    "iam/security-credentials",
    "loopback"
  ];
  const hit = internalIndicators.some((k) => lower.includes(k));
  const payloadHostMentioned = Boolean(payloadHost && lower.includes(payloadHost));
  const localAddressMentioned =
    lower.includes("127.0.0.1") || lower.includes("169.254.169.254") || lower.includes("localhost");
  const structured = readSsrfStructuredEvidence(data, payloadHost);
  const strongEvidence = structured || (hit && payloadHostMentioned && localAddressMentioned);
  const suspicious = internalPayload && strongEvidence;
  return {
    suspicious,
    reason: suspicious
      ? "Odpowiedź sugeruje dostęp do zasobu wewnętrznego powiązanego z payloadem URL."
      : undefined
  };
}

function readSsrfStructuredEvidence(data: unknown, payloadHost: string) {
  if (!data || typeof data !== "object" || !payloadHost) return false;
  const obj = data as Record<string, unknown>;
  const source = String(obj.source ?? "").toLowerCase();
  const fetched = String(obj.fetched ?? "").toLowerCase();
  const requestedUrl = String(obj.requestedUrl ?? "").toLowerCase();
  const requestedHost = hostFromUrl(requestedUrl);
  const sourceInternal = source.includes("metadata") || source.includes("loopback") || source.includes("internal");
  const fetchedInternal =
    fetched.includes("internal") || fetched.includes("metadata") || fetched.includes("loopback");
  const payloadLinked =
    requestedHost === payloadHost ||
    requestedUrl.includes(payloadHost) ||
    requestedUrl.includes("127.0.0.1") ||
    requestedUrl.includes("169.254.169.254") ||
    requestedUrl.includes("localhost");
  return payloadLinked && (sourceInternal || fetchedInternal);
}

function detectTemplateInjectionSignal(payload: string, data: unknown) {
  const body = typeof data === "string" ? data : JSON.stringify(data ?? {});
  const lower = body.toLowerCase();
  const has49 = /\b49\b/.test(lower);
  const payloadReflected = body.includes(payload);
  const sstiPayload = payload.includes("7*7");
  const structuredEval = readTemplateStructuredEvidence(data);
  const textEval = has49 && /(render|template|output|result)/i.test(body);
  const suspicious = sstiPayload && !payloadReflected && (structuredEval || textEval);
  return {
    suspicious,
    reason: suspicious
      ? "Wykryto możliwą ewaluację payloadu szablonu (wynik 49 bez surowego payloadu)."
      : undefined
  };
}

function readTemplateStructuredEvidence(data: unknown) {
  if (!data || typeof data !== "object") return false;
  const obj = data as Record<string, unknown>;
  const candidates = [obj.rendered, obj.output, obj.result];
  return candidates.some((v) => String(v ?? "").trim() === "49");
}

function detectPathTraversalSignal(data: unknown, payload: string) {
  const body = typeof data === "string" ? data : JSON.stringify(data ?? {});
  const lower = body.toLowerCase();
  const payloadLower = payload.toLowerCase();
  const traversalPayload =
    payloadLower.includes("../") ||
    payloadLower.includes("..\\") ||
    payloadLower.includes("%2e%2e") ||
    payloadLower.includes("etc/passwd") ||
    payloadLower.includes("win.ini");
  const unixLeak =
    lower.includes("root:x:0:0:") || lower.includes("daemon:x:") || lower.includes("/bin/bash");
  const windowsLeak = lower.includes("[fonts]") || lower.includes("for 16-bit app support");
  const structuredLeak = readPathTraversalStructuredEvidence(data);
  const payloadEcho = lower.includes(payloadLower);
  const suspicious = traversalPayload && !payloadEcho && (unixLeak || windowsLeak || structuredLeak);
  return {
    suspicious,
    reason: suspicious ? "Odpowiedź zawiera sygnały odczytu pliku systemowego po payloadzie traversal." : undefined
  };
}

function readPathTraversalStructuredEvidence(data: unknown) {
  if (!data || typeof data !== "object") return false;
  const obj = data as Record<string, unknown>;
  const content = String(obj.content ?? "").toLowerCase();
  if (!content) return false;
  const unixLeak =
    content.includes("root:x:0:0:") ||
    content.includes("daemon:x:") ||
    content.includes("/bin/bash");
  const windowsLeak = content.includes("[fonts]") || content.includes("for 16-bit app support");
  return unixLeak || windowsLeak;
}
