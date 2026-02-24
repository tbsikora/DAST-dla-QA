import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Chip,
  Grid,
  Paper,
  TablePagination,
  Stack,
  Typography
} from "@mui/material";

const API = import.meta.env.VITE_API_URL ?? "";

type Scan = {
  id: string;
  createdAt: string;
  status: "queued" | "running" | "finished";
  endpoints?: { method: string; path: string }[];

  totalTests?: number;
  totalErrors?: number;
  totalSuspicious?: number;
};

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

function formatScanLabel(_id: string, createdAt: string) {
  return `Skan ${formatDateTime(createdAt)}`;
}

async function readJsonSafe(res: Response) {
  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return null;
  const text = await res.text();
  if (!text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function readTextSafe(res: Response) {
  try {
    const text = await res.text();
    return text.trim() ? text : null;
  } catch {
    return null;
  }
}

export default function History() {
  const nav = useNavigate();

  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(20);

  const sorted = useMemo(() => {
    return [...scans].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  }, [scans]);

  const paged = useMemo(() => {
    const start = page * rowsPerPage;
    return sorted.slice(start, start + rowsPerPage);
  }, [sorted, page, rowsPerPage]);

  async function load() {
    setErr("");
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/scans`);
      const data = await readJsonSafe(res);
      if (!res.ok) throw new Error((data as any)?.error ?? "Nie udało się pobrać historii skanów");
      setScans(Array.isArray(data) ? data : []);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }

  async function download(path: string, filename: string) {
    try {
      const res = await fetch(`${API}${path}`);
      if (!res.ok) {
        let msg = "Nie udało się pobrać pliku";
        try {
          const data = await readJsonSafe(res);
          msg = (data as any)?.error ?? msg;
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

  function downloadJson(id: string) {
    download(`/api/scans/${encodeURIComponent(id)}/export`, `scan-${id}.json`);
  }

  function downloadCsv(id: string) {
    download(`/api/scans/${encodeURIComponent(id)}/export.csv`, `scan-${id}-results.csv`);
  }

  async function clearHistory() {
    if (!confirm("Czy na pewno chcesz usunąć całą historię skanów?")) return;
    setErr("");
    try {
      const res = await fetch(`${API}/api/scans`, { method: "DELETE" });
      const data = await readJsonSafe(res);
      if (!res.ok) {
        const text = await readTextSafe(res);
        const details = (data as any)?.error ?? text ?? `HTTP ${res.status}`;
        throw new Error(`Nie udało się usunąć historii: ${details}`);
      }
      setScans([]);
      setPage(0);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <Box>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
        <Box>
          <Typography variant="h2">Historia skanów</Typography>
          <Typography sx={{ color: "text.secondary", mt: 0.5 }}>
            Kliknij skan, aby zobaczyć szczegóły testów i raport bezpieczeństwa.
          </Typography>
          <Button variant="outlined" color="error" onClick={clearHistory} sx={{ mt: 1.25 }}>
            Wyczyść historię
          </Button>
        </Box>
      </Stack>

      {err ? <Alert sx={{ mt: 2 }} severity="error">{err}</Alert> : null}

      <Paper sx={{ mt: 3, p: 3 }}>
        {loading ? (
          <Typography sx={{ color: "text.secondary" }}>Wczytywanie…</Typography>
        ) : sorted.length ? (
          <Stack spacing={2}>
            {paged.map((s) => {
              const endpointsCount = s.endpoints?.length ?? 0;

              const statusLabel =
                s.status === "finished"
                  ? "Zakończony"
                  : s.status === "running"
                  ? "W toku"
                  : "W kolejce";

              return (
                <Paper
                  key={s.id}
                  variant="outlined"
                  sx={{ p: 2, cursor: "pointer", "&:hover": { bgcolor: "#F9FAFD" } }}
                  onClick={() => nav(`/running?scanId=${encodeURIComponent(s.id)}`)}
                >
                  <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
                    <Box>
                      <Typography sx={{ fontWeight: 600 }}>{formatScanLabel(s.id, s.createdAt)}</Typography>
                      <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                        <Chip size="small" label={statusLabel} />
                        <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
                          {formatDateTime(s.createdAt)}
                        </Typography>
                      </Stack>
                    </Box>
                    <Stack direction="row" spacing={1} sx={{ ml: "auto" }}>
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          downloadJson(s.id);
                        }}
                      >
                        JSON
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          downloadCsv(s.id);
                        }}
                      >
                        CSV
                      </Button>
                    </Stack>
                  </Stack>

                  <Grid container spacing={2} sx={{ mt: 1 }}>
                    <Grid size={{ xs: 6, sm: 3 }}>
                      <Stat label="Endpointy" value={endpointsCount} />
                    </Grid>
                    <Grid size={{ xs: 6, sm: 3 }}>
                      <Stat label="Testy" value={s.totalTests ?? 0} />
                    </Grid>
                    <Grid size={{ xs: 6, sm: 3 }}>
                      <Stat label="Błędy" value={s.totalErrors ?? 0} />
                    </Grid>
                    <Grid size={{ xs: 6, sm: 3 }}>
                      <Stat label="Podejrzane" value={s.totalSuspicious ?? 0} />
                    </Grid>
                  </Grid>
                </Paper>
              );
            })}
            <TablePagination
              component="div"
              count={sorted.length}
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
          </Stack>
        ) : (
          <Typography sx={{ color: "text.secondary" }}>Brak wykonanych skanów.</Typography>
        )}
      </Paper>
    </Box>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Typography sx={{ fontSize: 12, color: "text.secondary" }}>{label}</Typography>
      <Typography sx={{ fontWeight: 600 }}>{value}</Typography>
    </Paper>
  );
}
