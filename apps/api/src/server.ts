import "dotenv/config";
import {
  runScan,
  estimateTestCounts,
  type AuthConfig,
  type ThrottleConfig,
  type SeedConfig,
  type SmartTestConfig
} from "./engine/scanEngine";
import { db, loadScans, scheduleFlush, upsertScan, type StoredScan } from "./db";
import { generateSeedCandidates, parseSpecFromText } from "./seedCandidates";
import { parseOpenApiDetailed, parseOpenApiDetailedNoValidate } from "./openapi";
import { nanoid } from "nanoid";
import express from "express";
import cors from "cors";
import multer from "multer";
import { registerSeedFile } from "./engine/scanEngine";

const app = express();
app.use(cors());
app.use(express.json());
const upload = multer({ storage: multer.memoryStorage() });
const seedUpload = multer({ storage: multer.memoryStorage() });

/* ============================
   Types & storage
============================ */
type ScanStatus = "queued" | "running" | "finished";

type Scan = {
  id: string;
  createdAt: string;
  status: ScanStatus;
  endpoints?: { method: string; path: string }[];
  totalTests?: number;
  totalErrors?: number;
  totalSuspicious?: number;
  testResults: TestResult[];
  activityLog?: string[];
  seedResults?: SeedResult[];
  config?: ScanConfig;
};

type ScanEvent =
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

type TestResult = Extract<ScanEvent, { type: "test_result" }>;

type ScanConfig = {
  baseUrl?: string;
  auth?: AuthConfig;
  throttle?: ThrottleConfig;
  seed?: SeedConfig | boolean;
  smart?: SmartTestConfig;
};

type ScanPublic = Omit<Scan, "config" | "testResults">;
type SeedResult = { method: string; path: string; resourceKey: string; id?: string; status: "ok" | "error" | "no_id"; message?: string };

const scans = new Map<string, Scan>();

// SSE subscribers per scan
const subscribers = new Map<string, Set<express.Response>>();

// Event buffer per scan (so you can connect later and still see what happened)
const eventsBuffer = new Map<string, ScanEvent[]>();
const MAX_BUFFER = 200;

function formatActivityLogLine(ev: ScanEvent): string | null {
  if (ev.type === "step") return ev.message;
  if (ev.type === "scan_started") return "Rozpoczęto skanowanie";
  if (ev.type === "scan_finished") return "Zakończono skanowanie";
  if (ev.type !== "test_result") return null;

  const code =
    ev.testType === "SQLi"
      ? "SQLi"
      : ev.testType === "PATH_TRAVERSAL"
      ? "LFI/PT"
      : ev.testType === "TEMPLATE_INJECTION"
      ? "SSTI"
      : ev.testType === "HEADER_INJECTION"
      ? "CRLF Injection"
      : ev.testType === "OPEN_REDIRECT"
      ? "OR"
      : ev.testType === "RATE_LIMIT"
      ? "RLB"
      : ev.testType === "FUZZ"
      ? "IV"
      : ev.testType === "AUTH"
      ? "BAC"
      : ev.testType;

  const verdict =
    ev.verdict === "suspicious"
      ? "podejrzane"
      : ev.verdict === "inconclusive"
      ? "niejednoznaczne"
      : ev.verdict === "error" || !ev.ok
      ? "błąd"
      : "ok";
  const status = ev.ok ? ` ${ev.status ?? "-"}` : "";
  return `[${code}] ${ev.method} ${ev.path} -> ${verdict}${status}`;
}

function pushEvent(scanId: string, ev: ScanEvent) {
  const buf = eventsBuffer.get(scanId) ?? [];
  buf.push(ev);
  if (buf.length > MAX_BUFFER) buf.shift();
  eventsBuffer.set(scanId, buf);
}

function sendEvent(res: express.Response, ev: ScanEvent) {
  res.write(`data: ${JSON.stringify(ev)}\n\n`);
}

function broadcast(scanId: string, ev: ScanEvent) {
  pushEvent(scanId, ev);

  const subs = subscribers.get(scanId);
  if (!subs) return;
  for (const res of subs) sendEvent(res, ev);
}

/* ============================
   Routes
============================ */
app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.get("/api/scans", (_req, res) => {
  res.json(Array.from(scans.values()).map(toPublicScan));
});

app.delete("/api/scans", (_req, res) => {
  scans.clear();
  eventsBuffer.clear();
  for (const subs of subscribers.values()) {
    for (const r of subs) {
      try {
        r.end();
      } catch {}
    }
  }
  subscribers.clear();
  db.data!.scans = [];
  scheduleFlush();
  res.json({ ok: true });
});

app.post("/api/scans", async (req, res) => {
  const { openApi, openApiText, baseUrl, auth, throttle, seed, smart } = req.body ?? {};

  const id = `scan-${new Date().toISOString().replace(/[-:.TZ]/g, "")}`;
  const scan: Scan = {
    id,
    createdAt: new Date().toISOString(),
    status: "queued",
    testResults: [],
    activityLog: [],
    config: {
      baseUrl,
      auth,
      throttle,
      seed,
      smart
    }
  };

  scans.set(id, scan);
  eventsBuffer.set(id, []);
  upsertScan(scan as StoredScan);

  res.status(201).json(scan);

  setTimeout(async () => {
    scan.status = "running";

    const emitAndStore = (ev: ScanEvent) => {
      const line = formatActivityLogLine(ev);
      if (line) {
        scan.activityLog = scan.activityLog ?? [];
        scan.activityLog.push(line);
      }
      if (ev.type === "test_result") {
        scan.testResults.push(ev);
        scheduleFlush();
      } else if (line) {
        scheduleFlush();
      }
      broadcast(id, ev);
    };

    await runScan({
      scanId: id,
      openApi,
      openApiText,
      baseUrl,
      auth,
      throttle,
      seed,
      smart,
      emit: emitAndStore,
      setEndpoints: (endpoints) => {
        scan.endpoints = endpoints;
        upsertScan(scan as StoredScan);
      },
      setReport: (report) => {
        scan.totalTests = report.totalTests;
        scan.totalErrors = report.totalErrors;
        scan.totalSuspicious = report.totalSuspicious;
        upsertScan(scan as StoredScan);
      },
      setSeedResults: (seeds) => {
        scan.seedResults = seeds;
        upsertScan(scan as StoredScan);
      }
    });

    scan.status = "finished";
    upsertScan(scan as StoredScan);
  }, 300);
});

// SSE
app.get("/api/scans/:id/events", (req, res) => {
  const { id } = req.params;

  const scan = scans.get(id);
  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  // IMPORTANT: send something immediately
  sendEvent(res, { type: "connected", scanId: id, status: scan.status });

  // send buffered events so far
  const buf = eventsBuffer.get(id) ?? [];
  for (const ev of buf) sendEvent(res, ev);

  // register subscriber
  const set = subscribers.get(id) ?? new Set();
  set.add(res);
  subscribers.set(id, set);

  // keep-alive ping (comments)
  const ping = setInterval(() => {
    res.write(`: ping\n\n`);
  }, 10000);

  req.on("close", () => {
    clearInterval(ping);
    set.delete(res);
    if (set.size === 0) subscribers.delete(id);
  });
});

app.post(
  "/api/specs/upload",
  (upload.single("file") as any),
  (req: any, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    try {
      const text = req.file.buffer.toString("utf-8");
      res.status(201).json({
        openApiText: text,
        filename: req.file.originalname
      });
    } catch (e: any) {
      res.status(500).json({ error: e?.message ?? "Nie udało się odczytać pliku." });
    }
  }
);

app.post("/api/specs/seed-candidates", (req, res) => {
  const { openApiText, openApi } = req.body ?? {};
  let specObj: any = openApi;
  if (!specObj && typeof openApiText === "string") {
    specObj = parseSpecFromText(openApiText);
  }
  if (specObj && typeof specObj === "object" && (specObj as any).openApi) {
    specObj = (specObj as any).openApi;
  }
  if (specObj && typeof specObj === "object" && (specObj as any).spec) {
    specObj = (specObj as any).spec;
  }
  if (!specObj) return res.status(400).json({ error: "Brak specyfikacji OpenAPI" });

  const candidates = generateSeedCandidates(specObj);
  res.json({ candidates });
});

app.post("/api/scans/preview", async (req, res) => {
  const { openApi, openApiText, smart } = req.body ?? {};
  let specObj: any = openApi;
  if (!specObj && typeof openApiText === "string") {
    specObj = parseSpecFromText(openApiText);
  }
  if (specObj && typeof specObj === "object" && (specObj as any).openApi) {
    specObj = (specObj as any).openApi;
  }
  if (specObj && typeof specObj === "object" && (specObj as any).spec) {
    specObj = (specObj as any).spec;
  }
  if (!specObj) return res.status(400).json({ error: "Brak specyfikacji OpenAPI" });

  try {
    let endpoints;
    try {
      endpoints = await parseOpenApiDetailed(specObj);
    } catch (e: any) {
      const msg = typeof e?.message === "string" ? e.message : String(e);
      if (msg.includes("Missing $ref pointer")) {
        endpoints = parseOpenApiDetailedNoValidate(specObj);
      } else {
        throw e;
      }
    }
    const counts = estimateTestCounts(endpoints, smart);
    res.json({ counts });
  } catch (e: any) {
    res.status(400).json({ error: e?.message ?? String(e) });
  }
});

app.post("/api/scans/preview.csv", async (req, res) => {
  const { openApi, openApiText, smart } = req.body ?? {};
  let specObj: any = openApi;
  if (!specObj && typeof openApiText === "string") {
    specObj = parseSpecFromText(openApiText);
  }
  if (specObj && typeof specObj === "object" && (specObj as any).openApi) {
    specObj = (specObj as any).openApi;
  }
  if (specObj && typeof specObj === "object" && (specObj as any).spec) {
    specObj = (specObj as any).spec;
  }
  if (!specObj) return res.status(400).json({ error: "Brak specyfikacji OpenAPI" });

  try {
    let endpoints;
    try {
      endpoints = await parseOpenApiDetailed(specObj);
    } catch (e: any) {
      const msg = typeof e?.message === "string" ? e.message : String(e);
      if (msg.includes("Missing $ref pointer")) {
        endpoints = parseOpenApiDetailedNoValidate(specObj);
      } else {
        throw e;
      }
    }
    const counts = estimateTestCounts(endpoints, smart);
    const header = ["endpoints", "sql", "xss", "pathTraversal", "templateInjection", "ssrf", "headerInjection", "openRedirect", "fuzz", "auth", "rateLimit", "total"];
    const line = header.map((k) => `"${String((counts as any)[k] ?? "")}"`).join(",");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="scan-preview.csv"`);
    res.send(`${header.map((h) => `"${h}"`).join(",")}\n${line}`);
  } catch (e: any) {
    res.status(400).json({ error: e?.message ?? String(e) });
  }
});

app.post("/api/seeds/upload", (seedUpload.single("file") as any), (req: any, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const id = nanoid();
  registerSeedFile({
    id,
    buffer: req.file.buffer,
    filename: req.file.originalname,
    mimetype: req.file.mimetype
  });
  res.status(201).json({ fileId: id, filename: req.file.originalname });
});

// Upload error handler (multer)
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err?.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({ error: "Plik jest zbyt duży." });
  }
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Błąd uploadu: ${err.message}` });
  }
  if (err) {
    return res.status(500).json({ error: "Błąd serwera podczas uploadu." });
  }
  return res.status(500).json({ error: "Nieznany błąd serwera." });
});

app.get("/api/scans/:id/report", (req, res) => {
  const { id } = req.params;

  const scan = scans.get(id);
  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  const risk = computeRiskScore(
    scan.testResults ?? [],
    scan.config?.smart?.riskScoring !== false,
    scan.config?.smart?.riskWeights,
    scan.config?.smart?.inconclusiveMultiplier
  );

  res.json({
    id: scan.id,
    createdAt: scan.createdAt,
    status: scan.status,
    endpointsCount: scan.endpoints?.length ?? 0,
    totalTests: scan.totalTests ?? 0,
    totalErrors: scan.totalErrors ?? 0,
    totalSuspicious: scan.totalSuspicious ?? 0,
    seeds: scan.seedResults ?? [],
    riskScore: risk.score,
    riskLevel: risk.level
  });
});

app.get("/api/scans/:id/export", (req, res) => {
  const { id } = req.params;

  const scan = scans.get(id);
  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  const summary = buildSummary(scan);
  const payload = {
    scan: toPublicScan(scan),
    endpoints: scan.endpoints ?? [],
    report: {
      endpointsCount: scan.endpoints?.length ?? 0,
      totalTests: scan.totalTests ?? 0,
      totalErrors: scan.totalErrors ?? 0,
      totalSuspicious: scan.totalSuspicious ?? 0,
      riskScore: summary.riskScore,
      riskLevel: summary.riskLevel
    },
    seeds: scan.seedResults ?? [],
    activityLog: scan.activityLog ?? [],
    summary,
    testResults: scan.testResults
  };

  const pretty = String(req.query.pretty ?? "") === "1";
  if (pretty) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.send(`${JSON.stringify(payload, null, 2)}\n`);
    return;
  }
  res.json(payload);
});

app.get("/api/scans/:id/export.csv", (req, res) => {
  const { id } = req.params;

  const scan = scans.get(id);
  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  const pretty = String(req.query.pretty ?? "") === "1";
  const csv = testResultsToCsv(scan.testResults, { pretty });
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="scan-${id}-results.csv"`);
  res.send(csv);
});

function toPublicScan(scan: Scan): ScanPublic {
  const { config: _config, testResults: _testResults, ...rest } = scan;
  return rest;
}

function csvEscape(value: string) {
  const v = value.replace(/"/g, '""');
  return `"${v}"`;
}

function testResultsToCsv(results: TestResult[], opts?: { pretty?: boolean }) {
  const pretty = opts?.pretty === true;
  const header = [
    "testType",
    "method",
    "path",
    "payload",
    "location",
    "verdict",
    "severity",
    "baselineStatus",
    "baselineSize",
    "ok",
    "status",
    "suspicious",
    "responseTimeMs",
    "responseSize",
    "requestUrl",
    "responseHeaders",
    "debugRequestHeaders",
    "debugRequestBody",
    "debugRequestBodyTruncated",
    "debugResponseHeaders",
    "debugResponseBody",
    "debugResponseBodyTruncated",
    "error",
    "evidence"
  ];

  const lines = [header.map(csvEscape).join(",")];

  for (const r of results) {
    lines.push(
      [
        r.testType,
        r.method,
        r.path,
        r.payload,
        r.location ?? "",
        r.verdict ?? "",
        severityForCsv(r),
        r.baselineStatus != null ? String(r.baselineStatus) : "",
        r.baselineSize != null ? String(r.baselineSize) : "",
        String(r.ok),
        r.status != null ? String(r.status) : "",
        r.suspicious != null ? String(r.suspicious) : "",
        r.responseTimeMs != null ? String(r.responseTimeMs) : "",
        r.responseSize != null ? String(r.responseSize) : "",
        r.requestUrl ?? "",
        r.responseHeaders ? JSON.stringify(r.responseHeaders) : "",
        r.debugRequestHeaders ? JSON.stringify(r.debugRequestHeaders) : "",
        r.debugRequestBody ?? "",
        r.debugRequestBodyTruncated != null ? String(r.debugRequestBodyTruncated) : "",
        r.debugResponseHeaders ? JSON.stringify(r.debugResponseHeaders) : "",
        r.debugResponseBody ?? "",
        r.debugResponseBodyTruncated != null ? String(r.debugResponseBodyTruncated) : "",
        r.error ?? "",
        r.evidence ?? ""
      ].map(csvEscape).join(",")
    );
  }

  const newline = pretty ? "\r\n" : "\n";
  const body = lines.join(newline);
  return pretty ? `\uFEFF${body}${newline}` : body;
}

function severityForCsv(r: TestResult) {
  if (r.testType === "AUTH" || r.testType === "SQLi") return "High";
  if (r.testType === "PATH_TRAVERSAL") return "High";
  if (r.testType === "TEMPLATE_INJECTION") return "High";
  if (r.testType === "SSRF") return "High";
  if (r.testType === "HEADER_INJECTION") return "Medium";
  if (r.testType === "OPEN_REDIRECT") return "Medium";
  if (r.testType === "XSS") return "Medium";
  if (r.testType === "FUZZ") return "Low";
  if (r.testType === "RATE_LIMIT") return "Medium";
  return "";
}

function buildSummary(scan: Scan) {
  const results = scan.testResults ?? [];
  const suspicious = results.filter((r) => r.verdict === "suspicious");
  const authFindings = suspicious.filter((r) => r.testType === "AUTH");
  const counts: Record<string, number> = {};
  for (const r of suspicious) {
    counts[r.testType] = (counts[r.testType] ?? 0) + 1;
  }
  const risk = computeRiskScore(
    results,
    scan.config?.smart?.riskScoring !== false,
    scan.config?.smart?.riskWeights,
    scan.config?.smart?.inconclusiveMultiplier
  );
  return {
    suspiciousCount: suspicious.length,
    authFindingsCount: authFindings.length,
    byType: counts,
    riskScore: risk.score,
    riskLevel: risk.level
  };
}

function computeRiskScore(
  results: TestResult[],
  enabled = true,
  weights?: {
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
  },
  inconclusiveMultiplier?: number
) {
  if (!enabled) return { score: undefined, level: undefined };
  const w = {
    AUTH: 25,
    SQLi: 25,
    XSS: 15,
    PATH_TRAVERSAL: 18,
    TEMPLATE_INJECTION: 18,
    SSRF: 20,
    HEADER_INJECTION: 12,
    OPEN_REDIRECT: 12,
    RATE_LIMIT: 10,
    FUZZ: 8,
    ...(weights ?? {})
  };
  const mult =
    typeof inconclusiveMultiplier === "number" && Number.isFinite(inconclusiveMultiplier)
      ? Math.max(0, Math.min(1, inconclusiveMultiplier))
      : 0.4;
  let score = 0;
  for (const r of results) {
    const isSuspicious = r.verdict === "suspicious" || r.suspicious;
    const isInconclusive = r.verdict === "inconclusive";
    if (!isSuspicious && !isInconclusive) continue;
    const base =
      r.testType === "AUTH"
        ? w.AUTH
        : r.testType === "SQLi"
        ? w.SQLi
        : r.testType === "XSS"
        ? w.XSS
        : r.testType === "PATH_TRAVERSAL"
        ? w.PATH_TRAVERSAL
        : r.testType === "TEMPLATE_INJECTION"
        ? w.TEMPLATE_INJECTION
        : r.testType === "SSRF"
        ? w.SSRF
        : r.testType === "HEADER_INJECTION"
        ? w.HEADER_INJECTION
        : r.testType === "OPEN_REDIRECT"
        ? w.OPEN_REDIRECT
        : r.testType === "RATE_LIMIT"
        ? w.RATE_LIMIT
        : r.testType === "FUZZ"
        ? w.FUZZ
        : 5;
    score += isSuspicious ? base : Math.round(base * mult);
  }
  if (score > 100) score = 100;
  const level = score >= 61 ? "critical" : score >= 31 ? "high" : score >= 11 ? "medium" : "low";
  return { score, level };
}

/* ============================
   Server
============================ */
const PORT = Number(process.env.PORT || 4000);
async function boot() {
  await loadScans();
  for (const scan of db.data!.scans) {
    scans.set(scan.id, scan as Scan);
    eventsBuffer.set(scan.id, []);
  }
  app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
}

boot();
