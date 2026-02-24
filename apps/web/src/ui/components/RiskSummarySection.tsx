import { Box, Card, CardContent, Chip, Grid, Stack, Typography } from "@mui/material";

export type RiskItem = { label: string; count?: number };

export type ScanSummary = {
  endpoints: number;
  tests: number;
  errors: number;
  suspicious: number;
  risks?: RiskItem[];
  status?: "queued" | "running" | "finished";
  riskScore?: number;
  riskLevel?: "low" | "medium" | "high" | "critical";
};

function hasAnyRisk(scan: ScanSummary) {
  const hasRiskItems = Array.isArray(scan.risks) && scan.risks.length > 0;
  return scan.suspicious > 0 || scan.errors > 0 || hasRiskItems;
}

function MetricCard({ label, value }: { label: string; value: number }) {
  return (
    <Card variant="outlined" sx={{ borderRadius: 2 }}>
      <CardContent sx={{ p: 2 }}>
        <Typography variant="caption" color="text.secondary">
          {label}
        </Typography>
        <Typography variant="h6" sx={{ mt: 0.5, fontWeight: 700 }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  );
}

export function RiskSummarySection({ scan }: { scan: ScanSummary }) {
  const riskDetected = hasAnyRisk(scan);
  const riskLevel = scan.riskLevel;
  const badgeText =
    riskLevel === "critical"
      ? "Krytyczne ryzyko"
      : riskLevel === "high"
      ? "Wysokie ryzyko"
      : riskLevel === "medium"
      ? "Umiarkowane ryzyko"
      : riskLevel === "low"
      ? "Niskie ryzyko"
      : riskDetected
      ? "Wysokie ryzyko"
      : "Brak ryzyka";
  const isRunning = scan.status === "running" || scan.status === "queued";

  return (
    <Box component="section" aria-label="Podsumowanie ryzyka">
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h6" component="h2">
          Podsumowanie
        </Typography>
        <Chip
          size="small"
          label={badgeText}
          color={riskDetected ? "error" : "success"}
          variant="outlined"
        />
      </Stack>

      {isRunning ? (
        <Typography variant="body2" color="text.secondary">
          W toku
        </Typography>
      ) : (
        <Grid container spacing={2}>
          <Grid size={{ xs: 6, sm: 3 }}>
            <MetricCard label="Endpointy" value={scan.endpoints} />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <MetricCard label="Testy" value={scan.tests} />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <MetricCard label="Błędy" value={scan.errors} />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <MetricCard label="Podejrzane" value={scan.suspicious} />
          </Grid>
          {typeof scan.riskScore === "number" ? (
            <Grid size={{ xs: 6, sm: 3 }}>
              <MetricCard label="Ryzyko (0-100)" value={scan.riskScore} />
            </Grid>
          ) : null}
        </Grid>
      )}
    </Box>
  );
}
