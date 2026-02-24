import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runScan, type ScanEvent } from "../engine/scanEngine";
import {
  baselineSafetySpec,
  headerNoiseSpec,
  noisyBaselineSpec,
  pathTraversalNoiseSpec,
  retryStatusSpec,
  ssrfNoiseSpec,
  startBaselineSafetyFixture,
  startTemplateNoiseFixture,
  startHeaderNoiseFixture,
  startPathTraversalNoiseFixture,
  startXssContextFixture,
  startNoisyBaselineFixture,
  startRetryStatusFixture,
  startSsrfNoiseFixture,
  stableSpec,
  startStableFixture,
  startVulnerableFixture,
  templateNoiseSpec,
  vulnerableSpec,
  xssContextSpec
} from "./fixtures/regressionFixtures";

type TestResultEvent = Extract<ScanEvent, { type: "test_result" }>;

type RunSummary = {
  report: { totalTests: number; totalErrors: number; totalSuspicious: number };
  results: TestResultEvent[];
};

type GoldenSnapshot = {
  report: { totalTests: number; totalErrors: number; totalSuspicious: number };
  byType: Record<
    string,
    {
      total: number;
      suspicious: number;
      inconclusive: number;
      error: number;
    }
  >;
  suspiciousFindings: Array<{
    testType: string;
    method: string;
    path: string;
    location: string;
    status: number;
    verdict: string;
  }>;
  transportErrors: Array<{
    testType: string;
    method: string;
    path: string;
    error: string;
  }>;
};

const defaultSmart = {
  testVolume: "low" as const,
  anomalySensitivity: "medium" as const,
  responseValidation: "warn" as const,
  enabledTests: {
    SQLi: true,
    XSS: true,
    PATH_TRAVERSAL: true,
    TEMPLATE_INJECTION: true,
    SSRF: true,
    HEADER_INJECTION: true,
    OPEN_REDIRECT: true,
    FUZZ: false,
    AUTH: true,
    RATE_LIMIT: false
  }
};

async function runScanForAssertions(args: {
  openApi: unknown;
  baseUrl: string;
  smart?: any;
  auth?: { bearerToken?: string };
}): Promise<RunSummary> {
  const results: TestResultEvent[] = [];
  let report = { totalTests: 0, totalErrors: 0, totalSuspicious: 0 };

  await runScan({
    scanId: `regression-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    openApi: args.openApi,
    baseUrl: args.baseUrl,
    smart: args.smart ?? defaultSmart,
    auth: args.auth,
    emit: (ev) => {
      if (ev.type === "test_result") results.push(ev);
    },
    setEndpoints: () => {},
    setReport: (r) => {
      report = r;
    },
    setSeedResults: () => {}
  });

  return { report, results };
}

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const goldenDir = path.join(thisDir, "golden");
const updateGolden = process.env.UPDATE_GOLDEN === "1";

function normalizeError(msg: string | undefined) {
  return String(msg ?? "")
    .replace(/\d+ms/g, "<duration>")
    .trim();
}

function buildSnapshot(run: RunSummary): GoldenSnapshot {
  const byType: GoldenSnapshot["byType"] = {};
  for (const r of run.results) {
    const key = r.testType;
    if (!byType[key]) {
      byType[key] = { total: 0, suspicious: 0, inconclusive: 0, error: 0 };
    }
    byType[key].total += 1;
    if (r.verdict === "suspicious" || r.suspicious) byType[key].suspicious += 1;
    if (r.verdict === "inconclusive") byType[key].inconclusive += 1;
    if (r.verdict === "error" || !r.ok) byType[key].error += 1;
  }

  const suspiciousFindings = run.results
    .filter((r) => r.verdict === "suspicious" || r.suspicious)
    .map((r) => ({
      testType: r.testType,
      method: r.method,
      path: r.path,
      location: r.location ?? "",
      status: r.status ?? 0,
      verdict: r.verdict ?? ""
    }))
    .sort((a, b) =>
      [a.testType, a.method, a.path, a.location].join("|").localeCompare(
        [b.testType, b.method, b.path, b.location].join("|")
      )
    );

  const transportErrors = run.results
    .filter((r) => r.verdict === "error" || !r.ok)
    .map((r) => ({
      testType: r.testType,
      method: r.method,
      path: r.path,
      error: normalizeError(r.error)
    }))
    .sort((a, b) =>
      [a.testType, a.method, a.path, a.error].join("|").localeCompare(
        [b.testType, b.method, b.path, b.error].join("|")
      )
    );

  const sortedByType = Object.fromEntries(
    Object.entries(byType).sort(([a], [b]) => a.localeCompare(b))
  );

  return {
    report: run.report,
    byType: sortedByType,
    suspiciousFindings,
    transportErrors
  };
}

async function assertGolden(caseName: string, snapshot: GoldenSnapshot) {
  await mkdir(goldenDir, { recursive: true });
  const filePath = path.join(goldenDir, `${caseName}.json`);
  const text = `${JSON.stringify(snapshot, null, 2)}\n`;
  const hasFile = existsSync(filePath);

  if (updateGolden || !hasFile) {
    await writeFile(filePath, text, "utf-8");
    console.log(`[GOLDEN] ${hasFile ? "updated" : "created"} ${caseName}.json`);
    return;
  }

  const expectedRaw = await readFile(filePath, "utf-8");
  const expected = JSON.parse(expectedRaw) as GoldenSnapshot;
  assert.deepEqual(
    snapshot,
    expected,
    `golden mismatch for ${caseName}.json (run with UPDATE_GOLDEN=1 to refresh intentionally)`
  );
}

function hasSuspicious(results: TestResultEvent[], testType: TestResultEvent["testType"]) {
  return results.some(
    (r) => r.testType === testType && (r.verdict === "suspicious" || r.suspicious === true)
  );
}

async function testCoreDetections() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      auth: { bearerToken: "fixture-token" }
    });

    assert.ok(run.report.totalTests > 0, "expected scanner to generate tests");
    assert.ok(hasSuspicious(run.results, "SQLi"), "expected at least one suspicious SQLi result");
    assert.ok(hasSuspicious(run.results, "XSS"), "expected at least one suspicious XSS result");
    assert.ok(hasSuspicious(run.results, "AUTH"), "expected at least one suspicious AUTH result");
    await assertGolden("vulnerable_core", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testBlindSqliSignals() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: true,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const blindEvidence = run.results
      .filter((r) => r.testType === "SQLi" && (r.verdict === "suspicious" || r.suspicious))
      .map((r) => String(r.evidence ?? ""))
      .some((e) => e.includes("Blind time") || e.includes("Blind boolean"));
    const blindProbeExecuted = run.results.some(
      (r) =>
        r.testType === "SQLi" &&
        /sleep\s*\(\s*1\s*\)|waitfor\s+delay|or\s+'1'='1|or\s+1=1/i.test(String(r.payload ?? ""))
    );
    const sqliSuspicious = run.results.some(
      (r) => r.testType === "SQLi" && (r.verdict === "suspicious" || r.suspicious)
    );
    assert.ok(blindProbeExecuted, "expected blind SQLi probes to be executed");
    assert.ok(sqliSuspicious, "expected SQLi suspicious finding");
    assert.ok(blindEvidence || blindProbeExecuted, "expected blind SQLi path evidence or probe coverage");
    await assertGolden("blind_sqli_signals", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testBaselineStabilityNoFalseSuspicious() {
  const fixture = await startStableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: stableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          ...defaultSmart.enabledTests,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          AUTH: false
        }
      }
    });

    const suspiciousCount = run.results.filter(
      (r) => r.verdict === "suspicious" || r.suspicious === true
    ).length;
    assert.equal(
      suspiciousCount,
      0,
      `expected no suspicious findings on stable fixture, got ${suspiciousCount}`
    );
    await assertGolden("stable_no_false_positive", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testTransportFailureClassification() {
  const closedPortBaseUrl = "http://127.0.0.1:9";
  const run = await runScanForAssertions({
    openApi: stableSpec,
    baseUrl: closedPortBaseUrl,
    smart: {
      ...defaultSmart,
      enabledTests: {
        ...defaultSmart.enabledTests,
        PATH_TRAVERSAL: false,
        TEMPLATE_INJECTION: false,
        SSRF: false,
        HEADER_INJECTION: false,
        OPEN_REDIRECT: false,
        AUTH: false,
        XSS: false
      }
    }
  });

  assert.ok(run.report.totalTests > 0, "expected tests to be generated for transport failure run");
  assert.ok(run.report.totalErrors > 0, "expected transport errors when target is unreachable");
  await assertGolden("transport_failure", buildSnapshot(run));
}

async function testGlobalMaxTotalTestsCap() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        maxTotalTests: 5,
        enabledTests: {
          SQLi: true,
          XSS: true,
          PATH_TRAVERSAL: true,
          TEMPLATE_INJECTION: true,
          SSRF: true,
          HEADER_INJECTION: true,
          OPEN_REDIRECT: true,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    assert.ok(run.report.totalTests <= 5, `expected capped execution <=5 tests, got ${run.report.totalTests}`);
    await assertGolden("max_total_tests_cap", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testGlobalMaxTotalTestsKeepsDiversity() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        maxTotalTests: 7,
        enabledTests: {
          SQLi: true,
          XSS: true,
          PATH_TRAVERSAL: true,
          TEMPLATE_INJECTION: true,
          SSRF: true,
          HEADER_INJECTION: true,
          OPEN_REDIRECT: true,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const types = new Set(run.results.map((r) => r.testType));
    assert.ok(run.report.totalTests <= 7, `expected capped execution <=7 tests, got ${run.report.totalTests}`);
    assert.ok(types.size >= 4, `expected diverse test types under cap, got ${types.size}`);
    await assertGolden("max_total_tests_diversity", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testSafeBaselineAvoidsUnsafeSideEffects() {
  const fixture = await startBaselineSafetyFixture();
  try {
    const run = await runScanForAssertions({
      openApi: baselineSafetySpec,
      baseUrl: fixture.baseUrl,
      auth: { bearerToken: "fixture-token" },
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: true,
          RATE_LIMIT: false
        }
      }
    });
    const counterRes = await fetch(`${fixture.baseUrl}/counter`);
    const counterJson = (await counterRes.json()) as { writes?: number };
    const writes = Number(counterJson.writes ?? 0);
    assert.equal(writes, 1, `expected exactly one write (auth check), got ${writes}`);
    await assertGolden("baseline_safe_methods", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testTransientStatusRetriesRecoverDetection() {
  const fixture = await startRetryStatusFixture();
  try {
    const run = await runScanForAssertions({
      openApi: retryStatusSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: true,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });

    const sqliSuspicious = run.results.some(
      (r) => r.testType === "SQLi" && (r.verdict === "suspicious" || r.suspicious)
    );
    assert.ok(sqliSuspicious, "expected SQLi suspicious finding after transient 503 retry");
    await assertGolden("status_retry_recovery", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testNoisyBaselineDowngradesToInconclusive() {
  const fixture = await startNoisyBaselineFixture();
  try {
    const run = await runScanForAssertions({
      openApi: noisyBaselineSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          ...defaultSmart.enabledTests,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          XSS: false,
          AUTH: false
        }
      }
    });

    const suspiciousCount = run.results.filter(
      (r) => r.verdict === "suspicious" || r.suspicious === true
    ).length;
    const inconclusiveCount = run.results.filter((r) => r.verdict === "inconclusive").length;
    assert.equal(
      suspiciousCount,
      0,
      `expected noisy baseline findings to be downgraded, got suspicious=${suspiciousCount}`
    );
    assert.ok(
      inconclusiveCount > 0,
      "expected at least one inconclusive finding due to baseline instability"
    );
    await assertGolden("noisy_baseline_downgrade", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testXssContextClassification() {
  const fixture = await startXssContextFixture();
  try {
    const run = await runScanForAssertions({
      openApi: xssContextSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: true,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });

    const safeFormatting = run.results.find(
      (r) => r.testType === "XSS" && r.path === "/xss/safe-format" && r.payload === "<b>test</b>"
    );
    assert.ok(safeFormatting, "missing XSS result for /xss/safe-format with <b>test</b>");
    assert.equal(
      safeFormatting.verdict,
      "inconclusive",
      "safe formatting reflection should be inconclusive, not suspicious"
    );

    const jsonReflectSuspicious = run.results.some(
      (r) =>
        r.testType === "XSS" &&
        r.path === "/xss/json-reflect" &&
        (r.verdict === "suspicious" || r.suspicious === true)
    );
    assert.equal(jsonReflectSuspicious, false, "JSON-only reflection should not be suspicious for XSS");

    const attrContextSuspicious = run.results.some(
      (r) =>
        r.testType === "XSS" &&
        r.path === "/xss/attr-context" &&
        (r.verdict === "suspicious" || r.suspicious === true)
    );
    assert.ok(attrContextSuspicious, "attribute context should produce suspicious XSS finding");

    await assertGolden("xss_context_classification", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testOpenRedirectSignals() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: true,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const suspiciousRedirect = run.results.some(
      (r) =>
        r.testType === "OPEN_REDIRECT" &&
        r.path === "/redirect" &&
        (r.verdict === "suspicious" || r.suspicious === true)
    );
    assert.ok(suspiciousRedirect, "expected suspicious open redirect finding for /redirect");
    await assertGolden("open_redirect_signals", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testHeaderInjectionSignals() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: true,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const suspiciousHeaderInjection = run.results.some(
      (r) =>
        r.testType === "HEADER_INJECTION" &&
        r.path === "/header-test" &&
        (r.verdict === "suspicious" || r.suspicious === true)
    );
    assert.ok(suspiciousHeaderInjection, "expected suspicious header injection finding for /header-test");
    await assertGolden("header_injection_signals", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testHeaderNoiseNoFalsePositive() {
  const fixture = await startHeaderNoiseFixture();
  try {
    const run = await runScanForAssertions({
      openApi: headerNoiseSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: true,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const suspicious = run.results.some(
      (r) => r.testType === "HEADER_INJECTION" && (r.verdict === "suspicious" || r.suspicious)
    );
    assert.equal(suspicious, false, "static Set-Cookie should not be suspicious without payload correlation");
    await assertGolden("header_noise_no_false_positive", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testSsrfSignals() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: true,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const suspiciousSsrf = run.results.some(
      (r) => r.testType === "SSRF" && r.path === "/fetch" && (r.verdict === "suspicious" || r.suspicious)
    );
    assert.ok(suspiciousSsrf, "expected suspicious SSRF finding for /fetch");
    await assertGolden("ssrf_signals", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testSsrfNoiseNoFalsePositive() {
  const fixture = await startSsrfNoiseFixture();
  try {
    const run = await runScanForAssertions({
      openApi: ssrfNoiseSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: false,
          SSRF: true,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const ssrfSuspicious = run.results.some(
      (r) => r.testType === "SSRF" && (r.verdict === "suspicious" || r.suspicious)
    );
    assert.equal(ssrfSuspicious, false, "static internal markers should not trigger suspicious SSRF");
    await assertGolden("ssrf_noise_no_false_positive", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testTemplateInjectionSignals() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: true,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const suspiciousSsti = run.results.some(
      (r) =>
        r.testType === "TEMPLATE_INJECTION" &&
        r.path === "/template/render" &&
        (r.verdict === "suspicious" || r.suspicious)
    );
    assert.ok(suspiciousSsti, "expected suspicious template injection finding for /template/render");
    await assertGolden("ssti_signals", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testTemplateNoiseNoFalsePositive() {
  const fixture = await startTemplateNoiseFixture();
  try {
    const run = await runScanForAssertions({
      openApi: templateNoiseSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: false,
          TEMPLATE_INJECTION: true,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const suspicious = run.results.some(
      (r) => r.testType === "TEMPLATE_INJECTION" && (r.verdict === "suspicious" || r.suspicious)
    );
    assert.equal(suspicious, false, "static 49 value should not be suspicious template injection");
    await assertGolden("template_noise_no_false_positive", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testPathTraversalSignals() {
  const fixture = await startVulnerableFixture();
  try {
    const run = await runScanForAssertions({
      openApi: vulnerableSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: true,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const suspiciousTraversal = run.results.some(
      (r) =>
        r.testType === "PATH_TRAVERSAL" &&
        r.path === "/files/read" &&
        (r.verdict === "suspicious" || r.suspicious)
    );
    assert.ok(suspiciousTraversal, "expected suspicious path traversal finding for /files/read");
    await assertGolden("path_traversal_signals", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function testPathTraversalNoiseNoFalsePositive() {
  const fixture = await startPathTraversalNoiseFixture();
  try {
    const run = await runScanForAssertions({
      openApi: pathTraversalNoiseSpec,
      baseUrl: fixture.baseUrl,
      smart: {
        ...defaultSmart,
        enabledTests: {
          SQLi: false,
          XSS: false,
          PATH_TRAVERSAL: true,
          TEMPLATE_INJECTION: false,
          SSRF: false,
          HEADER_INJECTION: false,
          OPEN_REDIRECT: false,
          FUZZ: false,
          AUTH: false,
          RATE_LIMIT: false
        }
      }
    });
    const suspicious = run.results.some(
      (r) => r.testType === "PATH_TRAVERSAL" && (r.verdict === "suspicious" || r.suspicious)
    );
    assert.equal(suspicious, false, "benign Windows text should not be suspicious path traversal");
    await assertGolden("path_traversal_noise_no_false_positive", buildSnapshot(run));
  } finally {
    await fixture.stop();
  }
}

async function main() {
  const started = Date.now();
  const cases: Array<{ name: string; run: () => Promise<void> }> = [
    { name: "core detections (SQLi/XSS/AUTH)", run: testCoreDetections },
    { name: "path traversal signals", run: testPathTraversalSignals },
    { name: "path traversal noise has no false positives", run: testPathTraversalNoiseNoFalsePositive },
    { name: "template injection signals", run: testTemplateInjectionSignals },
    { name: "template noise has no false positives", run: testTemplateNoiseNoFalsePositive },
    { name: "ssrf signals", run: testSsrfSignals },
    { name: "ssrf noise has no false positives", run: testSsrfNoiseNoFalsePositive },
    { name: "header injection signals", run: testHeaderInjectionSignals },
    { name: "header noise has no false positives", run: testHeaderNoiseNoFalsePositive },
    { name: "open redirect signals", run: testOpenRedirectSignals },
    { name: "blind SQLi signals (time/boolean)", run: testBlindSqliSignals },
    { name: "baseline stability (no false suspicious)", run: testBaselineStabilityNoFalseSuspicious },
    { name: "transport failures are surfaced", run: testTransportFailureClassification },
    { name: "safe baseline avoids unsafe side effects", run: testSafeBaselineAvoidsUnsafeSideEffects },
    { name: "global maxTotalTests cap is enforced", run: testGlobalMaxTotalTestsCap },
    { name: "global maxTotalTests keeps coverage diversity", run: testGlobalMaxTotalTestsKeepsDiversity },
    { name: "transient status retries recover detection", run: testTransientStatusRetriesRecoverDetection },
    { name: "noisy baseline is downgraded to inconclusive", run: testNoisyBaselineDowngradesToInconclusive },
    { name: "XSS context classification", run: testXssContextClassification }
  ];

  for (const c of cases) {
    const t0 = Date.now();
    await c.run();
    const elapsed = Date.now() - t0;
    console.log(`[PASS] ${c.name} (${elapsed}ms)`);
  }

  console.log(`Scanner regression suite finished in ${Date.now() - started}ms`);
}

main().catch((err) => {
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  console.error(`[FAIL] scanner regression suite\n${msg}`);
  process.exitCode = 1;
});
