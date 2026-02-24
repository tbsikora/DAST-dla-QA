import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Typography
} from "@mui/material";
import { RiskSummarySection } from "../components/RiskSummarySection";

const API = import.meta.env.VITE_API_URL ?? "";
const RUNNING_VIEW_CACHE_PREFIX = "dastqa:running-cache:";
const ACTIVE_RUNNING_SCAN_ID_KEY = "dastqa:active-running-scan-id";
const RUNNING_SELECTED_RESULT_PREFIX = "dastqa:running-selected-result:";
const TEST_TYPE_OPTIONS = [
  "ALL",
  "AUTH",
  "SQLi",
  "XSS",
  "SSRF",
  "HEADER_INJECTION",
  "OPEN_REDIRECT",
  "PATH_TRAVERSAL",
  "TEMPLATE_INJECTION",
  "FUZZ",
  "RATE_LIMIT"
] as const;
type ResultTestType = Exclude<(typeof TEST_TYPE_OPTIONS)[number], "ALL">;
type FilterTestType = (typeof TEST_TYPE_OPTIONS)[number];

type ScanEvent =
  | { type: "connected"; scanId: string; status: "queued" | "running" | "finished" }
  | { type: "scan_started" }
  | { type: "step"; message: string }
  | { type: "scan_finished" }
  | {
      type: "test_result";
      testType: ResultTestType;
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

type Report = {
  id: string;
  createdAt: string;
  status: "queued" | "running" | "finished";
  endpointsCount: number;
  totalTests: number;
  totalErrors: number;
  totalSuspicious: number;
  seeds?: { method: string; path: string; resourceKey: string; id?: string; status: "ok" | "error" | "no_id"; message?: string }[];
  riskScore?: number;
  riskLevel?: "low" | "medium" | "high" | "critical";
};

type TestResult = Extract<ScanEvent, { type: "test_result" }>;

type RunningViewCache = {
  scanId: string;
  events: ScanEvent[];
  activityLog?: string[];
  results: TestResult[];
  report: Report | null;
  liveCounts: { total: number; errors: number; suspicious: number; inconclusive: number };
  finished: boolean;
  cachedAt: number;
};

function runningCacheKey(scanId: string) {
  return `${RUNNING_VIEW_CACHE_PREFIX}${scanId}`;
}

function runningSelectedResultKey(scanId: string) {
  return `${RUNNING_SELECTED_RESULT_PREFIX}${scanId}`;
}

function loadRunningCache(scanId: string): RunningViewCache | null {
  if (typeof window === "undefined" || !scanId) return null;
  try {
    const raw = window.sessionStorage.getItem(runningCacheKey(scanId));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    if (parsed.scanId !== scanId) return null;
    return parsed as RunningViewCache;
  } catch {
    return null;
  }
}

function saveRunningCache(scanId: string, data: Omit<RunningViewCache, "scanId" | "cachedAt">) {
  if (typeof window === "undefined" || !scanId) return;
  try {
    window.sessionStorage.setItem(
      runningCacheKey(scanId),
      JSON.stringify({
        scanId,
        cachedAt: Date.now(),
        ...data
      } satisfies RunningViewCache)
    );
  } catch {
    // ignore storage errors
  }
}

function clearRunningCache(scanId: string) {
  if (typeof window === "undefined" || !scanId) return;
  try {
    window.sessionStorage.removeItem(runningCacheKey(scanId));
  } catch {
    // ignore storage errors
  }
}

function loadStoredSelectedResult(scanId: string): TestResult | null {
  if (typeof window === "undefined" || !scanId) return null;
  try {
    const raw = window.sessionStorage.getItem(runningSelectedResultKey(scanId));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as TestResult;
  } catch {
    return null;
  }
}

function saveStoredSelectedResult(scanId: string, result: TestResult) {
  if (typeof window === "undefined" || !scanId) return;
  try {
    window.sessionStorage.setItem(runningSelectedResultKey(scanId), JSON.stringify(result));
  } catch {
    // ignore storage errors
  }
}

function clearStoredSelectedResult(scanId: string) {
  if (typeof window === "undefined" || !scanId) return;
  try {
    window.sessionStorage.removeItem(runningSelectedResultKey(scanId));
  } catch {
    // ignore storage errors
  }
}

function getStoredActiveRunningScanId() {
  if (typeof window === "undefined") return "";
  try {
    return window.sessionStorage.getItem(ACTIVE_RUNNING_SCAN_ID_KEY) ?? "";
  } catch {
    return "";
  }
}

function setStoredActiveRunningScanId(scanId: string) {
  if (typeof window === "undefined" || !scanId) return;
  try {
    window.sessionStorage.setItem(ACTIVE_RUNNING_SCAN_ID_KEY, scanId);
  } catch {
    // ignore storage errors
  }
}

function clearStoredActiveRunningScanId(expectedScanId?: string) {
  if (typeof window === "undefined") return;
  try {
    if (expectedScanId) {
      const current = window.sessionStorage.getItem(ACTIVE_RUNNING_SCAN_ID_KEY);
      if (current && current !== expectedScanId) return;
    }
    window.sessionStorage.removeItem(ACTIVE_RUNNING_SCAN_ID_KEY);
  } catch {
    // ignore storage errors
  }
}

function statusPill(result: TestResult) {
  if (result.verdict === "error" || !result.ok) {
    return { text: "Błąd", color: "error" as const };
  }
  if (result.verdict === "inconclusive") {
    return { text: "Niejednoznaczne", color: "default" as const };
  }
  if (result.verdict === "suspicious" || result.suspicious) {
    return { text: "Podejrzane", color: "warning" as const };
  }
  return { text: "OK", color: "success" as const };
}

function trimStr(s: string, n: number) {
  if (s.length <= n) return s;
  return s.slice(0, n) + "…";
}

function formatBodyForDisplay(value?: string) {
  if (!value) return value ?? "";
  const trimmed = value.trim();
  if (!trimmed) return value;
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return value;
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed === "object") {
      return JSON.stringify(parsed, null, 2);
    }
  } catch {
    // keep original text when body is not valid JSON
  }
  return value;
}

function pad2(n: number) {
  return n.toString().padStart(2, "0");
}

function formatDateTime(iso: string) {
  try {
    const d = new Date(iso);
    const dd = pad2(d.getDate());
    const mm = pad2(d.getMonth() + 1);
    const yyyy = d.getFullYear();
    const hh = pad2(d.getHours());
    const mi = pad2(d.getMinutes());
    const ss = pad2(d.getSeconds());
    return `${dd}.${mm}.${yyyy}, ${hh}:${mi}:${ss}`;
  } catch {
    return iso;
  }
}

function buildRiskList(results: TestResult[]) {
  const counts = new Map<string, number>();
  for (const r of results) {
    if (r.verdict !== "suspicious") continue;
    let label = "Potencjalny problem";
    if (r.testType === "AUTH") label = "Brak wymuszenia autoryzacji";
    else if (r.testType === "SQLi") label = "Możliwe SQL Injection";
    else if (r.testType === "XSS") label = "Możliwe XSS";
    else if (r.testType === "SSRF") label = "Możliwe SSRF";
    else if (r.testType === "PATH_TRAVERSAL") label = "Możliwy Path Traversal";
    else if (r.testType === "TEMPLATE_INJECTION") label = "Możliwe Template Injection";
    else if (r.testType === "HEADER_INJECTION") label = "Możliwa injekcja nagłówków";
    else if (r.testType === "OPEN_REDIRECT") label = "Możliwy Open Redirect";
    else if (r.testType === "RATE_LIMIT") label = "Brak skutecznego rate limiting";
    else if (r.testType === "FUZZ") label = "Błąd walidacji wejścia";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return Array.from(counts.entries()).map(([label, count]) => ({ label, count }));
}

function computeRiskScore(results: TestResult[]): { score: number; level: "low" | "medium" | "high" | "critical" } {
  let score = 0;
  for (const r of results) {
    const isSuspicious = r.verdict === "suspicious" || r.suspicious;
    const isInconclusive = r.verdict === "inconclusive";
    if (!isSuspicious && !isInconclusive) continue;
    const base =
      r.testType === "AUTH"
        ? 25
        : r.testType === "SQLi"
        ? 25
        : r.testType === "XSS"
        ? 15
        : r.testType === "RATE_LIMIT"
        ? 10
        : r.testType === "FUZZ"
        ? 8
        : 5;
    score += isSuspicious ? base : Math.round(base * 0.4);
  }
  if (score > 100) score = 100;
  const level = score >= 61 ? "critical" : score >= 31 ? "high" : score >= 11 ? "medium" : "low";
  return { score, level };
}

function resultKey(r: TestResult) {
  return [
    r.testType,
    r.method,
    r.path,
    r.payload,
    r.location ?? "",
    r.status ?? "",
    r.verdict ?? "",
    r.baselineStatus ?? ""
  ].join("|");
}

function mergeUniqueResults(existing: TestResult[], incoming: TestResult[]) {
  const seen = new Set<string>();
  const out: TestResult[] = [];
  for (const r of existing) {
    const key = resultKey(r);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  for (const r of incoming) {
    const key = resultKey(r);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

function formatTestTypeLabel(testType: ResultTestType) {
  if (testType === "XSS") return "Cross-Site Scripting";
  if (testType === "SSRF") return "Server-Side Request Forgery";
  if (testType === "PATH_TRAVERSAL") return "Path Traversal";
  if (testType === "TEMPLATE_INJECTION") return "Server-Side Template Injection";
  if (testType === "HEADER_INJECTION") return "CRLF Injection";
  if (testType === "OPEN_REDIRECT") return "Open Redirect";
  if (testType === "RATE_LIMIT") return "Rate Limit Bypass";
  if (testType === "AUTH") return "Broken Access Control";
  if (testType === "FUZZ") return "Input Validation";
  if (testType === "SQLi") return "SQL Injection";
  return testType;
}

function formatTestTypeBadgeLabel(testType: ResultTestType) {
  if (testType === "SQLi") return "SQLi";
  if (testType === "XSS") return "XSS";
  if (testType === "SSRF") return "SSRF";
  if (testType === "PATH_TRAVERSAL") return "LFI/PT";
  if (testType === "TEMPLATE_INJECTION") return "SSTI";
  if (testType === "HEADER_INJECTION") return "CRLF Injection";
  if (testType === "OPEN_REDIRECT") return "OR";
  if (testType === "RATE_LIMIT") return "RLB";
  if (testType === "FUZZ") return "IV";
  if (testType === "AUTH") return "BAC";
  return testType;
}

function formatTestTypeFilterLabel(testType: FilterTestType) {
  if (testType === "ALL") return "Wszystkie";
  return formatTestTypeLabel(testType as ResultTestType);
}

function formatTestResultLogLine(result: TestResult) {
  const verdict =
    result.verdict === "suspicious"
      ? "podejrzane"
      : result.verdict === "inconclusive"
      ? "niejednoznaczne"
      : result.verdict === "error" || !result.ok
      ? "błąd"
      : "ok";
  const status = result.ok ? ` ${result.status ?? "-"}` : "";
  return `[${formatTestTypeBadgeLabel(result.testType)}] ${result.method} ${result.path} -> ${verdict}${status}`;
}

function formatScanEventLogLine(event: Exclude<ScanEvent, { type: "test_result" }>) {
  if (event.type === "step") return event.message;
  if (event.type === "connected") return `Połączono ze strumieniem zdarzeń (status skanu: ${event.status})`;
  if (event.type === "scan_started") return "Rozpoczęto skanowanie";
  if (event.type === "scan_finished") return "Zakończono skanowanie";
  return "";
}

export default function Running() {
  const [params] = useSearchParams();
  const scanId = params.get("scanId") ?? getStoredActiveRunningScanId();

  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [activityLog, setActivityLog] = useState<string[]>([]);
  const [results, setResults] = useState<TestResult[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [err, setErr] = useState("");
  const [liveCounts, setLiveCounts] = useState({ total: 0, errors: 0, suspicious: 0, inconclusive: 0 });

  const [q, setQ] = useState("");
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [onlyErrors, setOnlyErrors] = useState(false);
  const [testType, setTestType] = useState<FilterTestType>(() => {
    const fromUrl = params.get("testType");
    return TEST_TYPE_OPTIONS.includes(fromUrl as FilterTestType) ? (fromUrl as FilterTestType) : "ALL";
  });
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(20);

  const [selected, setSelected] = useState<TestResult | null>(null);

  const esRef = useRef<EventSource | null>(null);
  const finishedRef = useRef(false);
  const snapshotRef = useRef(false);
  const logRef = useRef<HTMLDivElement | null>(null);
  const resultsSeenRef = useRef<Set<string>>(new Set());
  const pendingResultsRef = useRef<TestResult[]>([]);
  const flushTimerRef = useRef<number | null>(null);

  const activityLogLines = useMemo(() => {
    if (activityLog.length) return activityLog;
    return events
      .map((e) => (e.type === "test_result" ? "" : formatScanEventLogLine(e)))
      .filter((line): line is string => !!line);
  }, [events, activityLog]);

  const statsLive = liveCounts;

  const filteredResults = useMemo(() => {
    const query = q.trim().toLowerCase();

    return results
      .filter((r) => (testType === "ALL" ? true : r.testType === testType))
      .filter((r) => (onlyErrors ? !r.ok : true))
      .filter((r) => (onlySuspicious ? !!r.suspicious : true))
      .filter((r) => {
        if (!query) return true;
        const pill = statusPill(r);
        const hay = [
          r.testType,
          formatTestTypeLabel(r.testType),
          formatTestTypeBadgeLabel(r.testType),
          r.method,
          r.path,
          r.status ?? "",
          r.verdict ?? "",
          pill.text,
          r.location ?? "",
          r.payload ?? "",
          r.error ?? "",
          r.evidence ?? ""
        ]
          .join(" ")
          .toLowerCase();
        return hay.includes(query);
      })
      .slice()
      .reverse();
  }, [results, q, onlyErrors, onlySuspicious, testType]);

  const pagedResults = useMemo(() => {
    const start = page * rowsPerPage;
    return filteredResults.slice(start, start + rowsPerPage);
  }, [filteredResults, page, rowsPerPage]);

  const riskLive = useMemo(() => computeRiskScore(results), [results]);
  const riskEnabled = report ? typeof report.riskScore === "number" : true;

  const scanTitle = report?.createdAt ? `Skan ${formatDateTime(report.createdAt)}` : `Skan ${scanId}`;

  useEffect(() => {
    if (!scanId) return;
    setStoredActiveRunningScanId(scanId);
  }, [scanId]);

  async function fetchReport() {
    try {
      const res = await fetch(`${API}/api/scans/${encodeURIComponent(scanId)}/report`);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Nie udało się pobrać raportu");
      setReport(data);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }

  async function fetchSnapshot() {
    try {
      const res = await fetch(`${API}/api/scans/${encodeURIComponent(scanId)}/export`);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Nie udało się pobrać danych skanu");

      if (Array.isArray(data?.testResults)) {
        const snapshotResults = data.testResults as TestResult[];
        setResults((prev) => {
          const merged = mergeUniqueResults(prev, snapshotResults);
          const set = new Set<string>();
          for (const r of merged) set.add(resultKey(r));
          resultsSeenRef.current = set;
          const total = merged.length;
          const errors = merged.filter((r) => r.verdict === "error" || !r.ok).length;
          const suspicious = merged.filter((r) => r.verdict === "suspicious" || r.suspicious).length;
          const inconclusive = merged.filter((r) => r.verdict === "inconclusive").length;
          setLiveCounts({ total, errors, suspicious, inconclusive });
          return merged;
        });
        snapshotRef.current = true;
      }

      if (Array.isArray(data?.activityLog)) {
        setActivityLog(data.activityLog.filter((x: unknown): x is string => typeof x === "string"));
      }

      if (data?.report && data?.scan) {
        setReport({
          id: data.scan.id,
          createdAt: data.scan.createdAt,
          status: data.scan.status,
          endpointsCount: data.report.endpointsCount ?? 0,
          totalTests: data.report.totalTests ?? 0,
          totalErrors: data.report.totalErrors ?? 0,
          totalSuspicious: data.report.totalSuspicious ?? 0,
          seeds: data.seeds ?? [],
          riskScore: data.report.riskScore,
          riskLevel: data.report.riskLevel
        });
        if (data.scan.status === "finished") {
          finishedRef.current = true;
          clearRunningCache(scanId);
          clearStoredSelectedResult(scanId);
          clearStoredActiveRunningScanId(scanId);
        }
      }
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }

  async function download(path: string, filename: string) {
    try {
      const res = await fetch(`${API}${path}`);
      if (!res.ok) {
        let msg = "Nie udało się pobrać pliku";
        try {
          const data = await res.json();
          msg = data?.error ?? msg;
        } catch {}
        throw new Error(msg);
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }

  function downloadJson() {
    if (!scanId) return;
    download(`/api/scans/${encodeURIComponent(scanId)}/export?pretty=1`, `scan-${scanId}.json`);
  }

  function downloadCsv() {
    if (!scanId) return;
    download(`/api/scans/${encodeURIComponent(scanId)}/export.csv?pretty=1`, `scan-${scanId}-results.csv`);
  }

  useEffect(() => {
    setEvents([]);
    setActivityLog([]);
    setResults([]);
    setReport(null);
    setErr("");
    setLiveCounts({ total: 0, errors: 0, suspicious: 0, inconclusive: 0 });
    finishedRef.current = false;
    snapshotRef.current = false;
    resultsSeenRef.current = new Set();
    pendingResultsRef.current = [];
    if (flushTimerRef.current) {
      window.clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }

    if (!scanId) {
      setSelected(null);
      setErr("Brak scanId w URL.");
      return;
    }

    const cached = loadRunningCache(scanId);
    if (cached) {
      setEvents(Array.isArray(cached.events) ? cached.events : []);
      setActivityLog(Array.isArray(cached.activityLog) ? cached.activityLog.filter((x): x is string => typeof x === "string") : []);
      setResults(Array.isArray(cached.results) ? cached.results : []);
      setReport(cached.report ?? null);
      setLiveCounts(cached.liveCounts ?? { total: 0, errors: 0, suspicious: 0, inconclusive: 0 });
      finishedRef.current = cached.finished === true;
      const seen = new Set<string>();
      for (const r of Array.isArray(cached.results) ? cached.results : []) {
        seen.add(resultKey(r));
      }
      resultsSeenRef.current = seen;
    }

    const cachedSelected = loadStoredSelectedResult(scanId);
    if (cachedSelected) {
      setSelected(cachedSelected);
    }

    fetchSnapshot();

    const es = new EventSource(`${API}/api/scans/${encodeURIComponent(scanId)}/events`);
    esRef.current = es;

    es.onmessage = (msg) => {
      try {
        const ev: ScanEvent = JSON.parse(msg.data);

        if (ev.type === "test_result") {
          const key = resultKey(ev);
          if (!resultsSeenRef.current.has(key)) {
            resultsSeenRef.current.add(key);
            setEvents((prev) => [...prev, { type: "step", message: formatTestResultLogLine(ev) }]);
            setActivityLog((prev) => [...prev, formatTestResultLogLine(ev)]);
            setLiveCounts((c) => ({
              total: c.total + 1,
              errors: c.errors + (ev.verdict === "error" || !ev.ok ? 1 : 0),
              suspicious: c.suspicious + (ev.verdict === "suspicious" || ev.suspicious ? 1 : 0),
              inconclusive: c.inconclusive + (ev.verdict === "inconclusive" ? 1 : 0)
            }));
            pendingResultsRef.current.push(ev);
            if (!flushTimerRef.current) {
              flushTimerRef.current = window.setTimeout(() => {
                flushTimerRef.current = null;
                const batch = pendingResultsRef.current.splice(0, pendingResultsRef.current.length);
                if (batch.length) {
                  setResults((prev) => [...prev, ...batch]);
                }
              }, 60);
            }
          }
          return;
        }

        setEvents((prev) => [...prev, ev]);
        const activityLine = formatScanEventLogLine(ev);
        if (activityLine) {
          setActivityLog((prev) => [...prev, activityLine]);
        }

        if (ev.type === "scan_finished" && !finishedRef.current) {
          finishedRef.current = true;
          clearRunningCache(scanId);
          clearStoredSelectedResult(scanId);
          clearStoredActiveRunningScanId(scanId);
          fetchReport();
          es.close();
        }
      } catch {
        // ignore malformed events
      }
    };

    es.onerror = () => {
      if (!finishedRef.current) setErr("Utracono połączenie ze strumieniem zdarzeń (SSE)." );
      es.close();
    };

    return () => es.close();
  }, [scanId]);

  useEffect(() => {
    setPage(0);
  }, [q, onlyErrors, onlySuspicious, testType]);

  useEffect(() => {
    if (!scanId) return;
    const finished = finishedRef.current || report?.status === "finished";
    if (finished) {
      clearRunningCache(scanId);
      clearStoredSelectedResult(scanId);
      return;
    }
    if (!events.length && !results.length && !report && liveCounts.total === 0) return;
    saveRunningCache(scanId, {
      events,
      activityLog,
      results,
      report,
      liveCounts,
      finished: false
    });
  }, [scanId, events, activityLog, results, report, liveCounts]);

  useEffect(() => {
    if (!scanId) return;
    if (!selected) {
      clearStoredSelectedResult(scanId);
      return;
    }
    saveStoredSelectedResult(scanId, selected);
  }, [scanId, selected]);

  useEffect(() => {
    if (!selected || !results.length) return;
    const selectedKey = resultKey(selected);
    const nextSelected = results.find((r) => resultKey(r) === selectedKey);
    if (nextSelected && nextSelected !== selected) {
      setSelected(nextSelected);
    }
  }, [results, selected]);

  useEffect(() => {
    const el = logRef.current;
    if (!el) return;
    if (report?.status === "finished") return;
    el.scrollTop = el.scrollHeight;
  }, [activityLogLines, report?.status]);

  if (!scanId) {
    return (
      <Box>
        <Box sx={{ mb: 3 }}>
          <Typography variant="h2">Brak uruchomionego skanu</Typography>
          <Typography sx={{ mt: 0.5, color: "text.secondary" }}>
            Wejdź w historię i wybierz skan albo uruchom nowy.
          </Typography>
          <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
            <Button variant="outlined" href="/history">Historia</Button>
            <Button variant="contained" href="/">Nowy skan</Button>
          </Stack>
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "center" }} spacing={2}>
          <Box>
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="h2">{scanTitle}</Typography>
              <Chip
                size="small"
                label={report?.status === "finished" ? "Zakończony" : "W toku"}
                color={report?.status === "finished" ? "success" : "warning"}
                variant="outlined"
              />
            </Stack>
          </Box>
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" onClick={downloadJson} disabled={!scanId}>Pobierz JSON</Button>
            <Button variant="outlined" onClick={downloadCsv} disabled={!scanId}>Pobierz CSV</Button>
          </Stack>
        </Stack>

        <Box sx={{ mt: 2 }}>
          <RiskSummarySection
            scan={{
              endpoints: report?.endpointsCount ?? 0,
              tests: statsLive.total,
              errors: statsLive.errors,
              suspicious: statsLive.suspicious,
              risks: buildRiskList(results),
              status: report?.status ?? "running",
              riskScore: riskEnabled ? report?.riskScore ?? riskLive.score : undefined,
              riskLevel: riskEnabled ? report?.riskLevel ?? riskLive.level : undefined
            }}
          />
        </Box>

        {report?.seeds?.length ? (
          <Paper variant="outlined" sx={{ mt: 2, p: 2, bgcolor: "#F9FAFD" }}>
            <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
              Seedowanie — status
            </Typography>
            <Stack spacing={0.5} sx={{ mt: 1 }}>
              {report.seeds.map((s, idx) => (
                <Typography key={idx} sx={{ fontFamily: "monospace", fontSize: 12 }}>
                  {s.method} {s.path} →{" "}
                  {s.status === "ok"
                    ? `id=${s.id}`
                    : s.status === "no_id"
                    ? "brak id"
                    : "błąd"}{" "}
                  ({s.resourceKey})
                </Typography>
              ))}
            </Stack>
          </Paper>
        ) : null}
      </Paper>

      {err ? <Alert sx={{ mt: 2 }} severity="error">{err}</Alert> : null}

      <Paper sx={{ mt: 3, p: 3 }}>
        <Typography sx={{ fontWeight: 600 }}>Przebieg skanu</Typography>
        <Paper
          variant="outlined"
          sx={{ mt: 2, p: 2, maxHeight: 320, overflow: "auto", bgcolor: "#F9FAFD" }}
          ref={logRef}
        >
          {activityLogLines.length ? (
            <Stack spacing={1}>
              {activityLogLines.map((line, idx) => (
                <Typography key={idx} sx={{ fontSize: 13 }}>{line}</Typography>
              ))}
            </Stack>
          ) : (
            <Typography sx={{ fontSize: 13, color: "text.secondary" }}>Czekam na zdarzenia…</Typography>
          )}
        </Paper>
      </Paper>

      <Paper sx={{ mt: 3, p: 3 }}>
        <Typography sx={{ fontWeight: 600 }}>Wyniki testów</Typography>
        <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }} sx={{ mt: 2 }}>
          <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel id="test-type">Typ</InputLabel>
              <Select labelId="test-type" label="Typ" value={testType} onChange={(e) => setTestType(e.target.value as FilterTestType)}>
                {TEST_TYPE_OPTIONS.map((t) => (
                  <MenuItem key={t} value={t}>
                    {formatTestTypeFilterLabel(t)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <FormControlLabel control={<Checkbox checked={onlySuspicious} onChange={(e) => setOnlySuspicious(e.target.checked)} />} label="Tylko podejrzane" />
            <FormControlLabel control={<Checkbox checked={onlyErrors} onChange={(e) => setOnlyErrors(e.target.checked)} />} label="Tylko błędy" />
          </Stack>
          <TextField
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Szukaj"
            size="small"
            fullWidth
            sx={{ minWidth: { xs: 0, md: 320 }, flex: 1 }}
          />
        </Stack>

        <TableContainer component={Paper} variant="outlined" sx={{ mt: 2 }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Typ</TableCell>
                <TableCell>Żądanie</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Werdykt</TableCell>
                <TableCell>Źródło</TableCell>
                <TableCell>Ładunek</TableCell>
                <TableCell>Błąd</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {pagedResults.length ? (
                pagedResults.map((r, idx) => {
                  const pill = statusPill(r);
                  return (
                    <TableRow key={idx} hover sx={{ cursor: "pointer" }} onClick={() => setSelected(r)}>
                      <TableCell>
                        <Chip
                          size="small"
                          label={formatTestTypeLabel(r.testType)}
                          color={
                            r.testType === "AUTH"
                              ? "error"
                              : r.testType === "SQLi"
                              ? "warning"
                              : r.testType === "XSS"
                              ? "info"
                              : r.testType === "SSRF"
                              ? "warning"
                              : r.testType === "PATH_TRAVERSAL"
                              ? "warning"
                              : r.testType === "TEMPLATE_INJECTION"
                              ? "warning"
                              : r.testType === "RATE_LIMIT"
                              ? "secondary"
                              : "default"
                          }
                          icon={
                            <span>
                              {r.testType === "AUTH"
                                ? "🔒"
                                : r.testType === "SQLi"
                                ? "💉"
                                : r.testType === "XSS"
                                ? "🧪"
                                : r.testType === "SSRF"
                                ? "🌐"
                                : r.testType === "PATH_TRAVERSAL"
                                ? "📁"
                                : r.testType === "TEMPLATE_INJECTION"
                                ? "🧩"
                                : r.testType === "HEADER_INJECTION"
                                ? "📬"
                                : r.testType === "OPEN_REDIRECT"
                                ? "↪️"
                                : r.testType === "RATE_LIMIT"
                                ? "⏱️"
                                : "🧰"}
                            </span>
                          }
                          sx={{ maxWidth: 320, "& .MuiChip-label": { whiteSpace: "nowrap" } }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>
                        {r.method} {r.path}
                      </TableCell>
                      <TableCell>{r.ok ? r.status ?? "-" : "-"}</TableCell>
                      <TableCell>
                        <Chip size="small" label={pill.text} color={pill.color} variant="outlined" />
                      </TableCell>
                      <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>{r.location ?? "-"}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{trimStr(r.payload, 60)}</TableCell>
                      <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>
                        {r.ok ? (r.evidence ? trimStr(r.evidence, 80) : "-") : trimStr(r.error ?? "-", 80)}
                      </TableCell>
                    </TableRow>
                  );
                })
              ) : (
                <TableRow>
                  <TableCell colSpan={7} sx={{ textAlign: "center", color: "text.secondary", py: 4 }}>
                    Brak wyników dla wybranych filtrów.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          component="div"
          count={filteredResults.length}
          page={page}
          onPageChange={(_e, next) => setPage(next)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[20, 30, 50]}
          labelRowsPerPage="Wyników na stronę"
        />
        <Typography sx={{ mt: 1, fontSize: 12, color: "text.secondary" }}>
          Wskazówka: kliknij w wiersz, żeby zobaczyć pełny ładunek i błąd.
        </Typography>
      </Paper>

      <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="md" fullWidth>
        <DialogTitle>Szczegóły testu</DialogTitle>
        <DialogContent dividers>
          {selected ? (
            <Stack spacing={2}>
              <Typography sx={{ fontFamily: "monospace", fontSize: 12 }}>
                {formatTestTypeLabel(selected.testType)} · {selected.method} {selected.path}
              </Typography>
              <Grid container spacing={2}>
                <Grid size={6}><Info label="Typ" value={formatTestTypeLabel(selected.testType)} /></Grid>
                <Grid size={6}><Info label="Werdykt" value={selected.verdict ?? (selected.ok ? "ok" : "error")} /></Grid>
                <Grid size={6}><Info label="Status HTTP" value={selected.ok ? String(selected.status ?? "-") : "-"} /></Grid>
                <Grid size={6}><Info label="Podejrzane" value={selected.suspicious ? "TAK" : "NIE"} /></Grid>
                <Grid size={6}><Info label="Źródło" value={selected.location ?? "-"} /></Grid>
                <Grid size={6}><Info label="HTTP bazowy" value={selected.baselineStatus != null ? String(selected.baselineStatus) : "-"} /></Grid>
                <Grid size={6}><Info label="Transport OK" value={selected.ok ? "TAK" : "NIE"} /></Grid>
                <Grid size={6}><Info label="Rozmiar bazowy" value={selected.baselineSize != null ? `${selected.baselineSize} B` : "-"} /></Grid>
                <Grid size={6}><Info label="Czas odpowiedzi" value={selected.responseTimeMs != null ? `${selected.responseTimeMs} ms` : "-"} /></Grid>
                <Grid size={6}><Info label="Rozmiar odpowiedzi" value={selected.responseSize != null ? `${selected.responseSize} B` : "-"} /></Grid>
              </Grid>

              {selected.requestUrl ? (
                <Section title="URL">
                  <Box component="pre" sx={{ bgcolor: "#F9FAFD", p: 2, borderRadius: 2, border: "1px solid #E6E8F0", fontSize: 12, whiteSpace: "pre-wrap" }}>
                    {selected.requestUrl}
                  </Box>
                </Section>
              ) : null}

              {selected.debugRequestHeaders && Object.keys(selected.debugRequestHeaders).length ? (
                <Section title="Nagłówki żądania">
                  <Box component="pre" sx={{ bgcolor: "#F7FAFF", p: 2, borderRadius: 2, border: "1px solid #DCE6F8", fontSize: 12, whiteSpace: "pre-wrap" }}>
                    {Object.entries(selected.debugRequestHeaders)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                  </Box>
                </Section>
              ) : null}

              <Section title="Payload">
                <Box component="pre" sx={{ bgcolor: "#F9FAFD", p: 2, borderRadius: 2, border: "1px solid #E6E8F0", fontSize: 12, whiteSpace: "pre-wrap" }}>
                  {formatBodyForDisplay(selected.payload)}
                </Box>
              </Section>

              {selected.debugRequestBody ? (
                <Section title="Ciało żądania">
                  <Box component="pre" sx={{ bgcolor: "#F9FAFD", p: 2, borderRadius: 2, border: "1px solid #E6E8F0", fontSize: 12, whiteSpace: "pre-wrap" }}>
                    {formatBodyForDisplay(selected.debugRequestBody)}
                    {selected.debugRequestBodyTruncated ? "\n\n[obcięto podgląd]" : ""}
                  </Box>
                </Section>
              ) : null}

              {!selected.ok ? (
                <Section title="Błąd transportowy">
                  <Box component="pre" sx={{ bgcolor: "#FFF1F1", p: 2, borderRadius: 2, border: "1px solid #FFD7D7", fontSize: 12, whiteSpace: "pre-wrap", color: "#C03434" }}>
                    {selected.error ?? "Nieznany błąd"}
                  </Box>
                </Section>
              ) : null}

              {selected.ok && selected.evidence ? (
                <Section title="Szczegóły wyniku">
                  <Box component="pre" sx={{ bgcolor: "#FFF7E6", p: 2, borderRadius: 2, border: "1px solid #FFE2B7", fontSize: 12, whiteSpace: "pre-wrap" }}>
                    {selected.evidence}
                  </Box>
                </Section>
              ) : null}

              {selected.debugResponseHeaders && Object.keys(selected.debugResponseHeaders).length ? (
                <Section title="Nagłówki odpowiedzi">
                  <Box component="pre" sx={{ bgcolor: "#F4F7FF", p: 2, borderRadius: 2, border: "1px solid #DDE4FF", fontSize: 12, whiteSpace: "pre-wrap" }}>
                    {Object.entries(selected.debugResponseHeaders)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                  </Box>
                </Section>
              ) : null}

              {selected.debugResponseBody ? (
                <Section title="Ciało odpowiedzi">
                  <Box component="pre" sx={{ bgcolor: "#F7F7FF", p: 2, borderRadius: 2, border: "1px solid #E2E2FF", fontSize: 12, whiteSpace: "pre-wrap" }}>
                    {formatBodyForDisplay(selected.debugResponseBody)}
                    {selected.debugResponseBodyTruncated ? "\n\n[obcięto podgląd]" : ""}
                  </Box>
                </Section>
              ) : null}

              {selected.ok && selected.responseHeaders ? (
                <Section title="Nagłówki bezpieczeństwa">
                  <Box component="pre" sx={{ bgcolor: "#F4F7FF", p: 2, borderRadius: 2, border: "1px solid #DDE4FF", fontSize: 12, whiteSpace: "pre-wrap" }}>
                    {Object.entries(selected.responseHeaders)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                  </Box>
                </Section>
              ) : null}
            </Stack>
          ) : null}
        </DialogContent>
        <DialogActions>
          {selected ? (
            <Button
              component="a"
              href={`/test-catalog?from=running-preview#${encodeURIComponent(selected.testType)}`}
              variant="outlined"
            >
              Otwórz w katalogu testów
            </Button>
          ) : null}
          <Button onClick={() => setSelected(null)}>Zamknij</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Typography sx={{ fontSize: 11, color: "text.secondary" }}>{label}</Typography>
      <Typography sx={{ mt: 0.5, fontWeight: 600 }}>{value}</Typography>
    </Paper>
  );
}

function Section({ title, children }: { title: string; children: any }) {
  return (
    <Box>
      <Typography sx={{ fontWeight: 600 }}>{title}</Typography>
      <Box sx={{ mt: 1 }}>{children}</Box>
    </Box>
  );
}
