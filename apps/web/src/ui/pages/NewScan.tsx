import { useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  FormControlLabel,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import InfoOutlined from "@mui/icons-material/InfoOutlined";
import CloseIcon from "@mui/icons-material/Close";
import WizardLayout from "../components/WizardLayout";

const API = import.meta.env.VITE_API_URL ?? "";
const NEW_SCAN_DRAFT_STORAGE_KEY = "dastqa:new-scan-wizard-draft:v1";

type AuthType = "none" | "bearer" | "jwt" | "apiKey" | "basic";
type ProfileType = "quick" | "custom" | "deep";
type JwtMode = "existing" | "generate";
type JwtAlgorithm = "HS256" | "HS384" | "HS512" | "RS256";
type JwtLocation = "authorization" | "custom_header" | "query";

type PreviewCounts = {
  endpoints: number;
  sql: number;
  xss: number;
  pathTraversal?: number;
  templateInjection?: number;
  ssrf?: number;
  headerInjection?: number;
  openRedirect?: number;
  fuzz: number;
  auth: number;
  rateLimit: number;
  total: number;
};

type OpenApiSummary = {
  endpoints: number;
  methods: number;
  params: number;
};

type SeedCandidate = {
  id: string;
  enabled: boolean;
  method: string;
  path: string;
  inputMode: "none" | "json" | "form" | "multipart" | "binary";
  contentType?: string;
  accept?: string;
  security?: string[];
  idExtractor?: string | null;
  resourceKey: string;
  confidence: number;
  reason: string;
  payloadText?: string;
  paramsText?: string;
  headerPairs?: { key: string; value: string }[];
};

type StepErrors = Record<string, string>;

type NewScanDraft = {
  step: number;
  baseUrl: string;
  uploadedFileName: string;
  openApiText: string;
  authType: AuthType;
  bearerToken: string;
  jwtMode: JwtMode;
  jwtExistingToken: string;
  jwtAlgorithm: JwtAlgorithm;
  jwtSecretOrPrivateKey: string;
  jwtSecretBase64: boolean;
  jwtHeaderJson: string;
  jwtPayloadJson: string;
  jwtTokenLocation: JwtLocation;
  jwtCustomHeaderName: string;
  jwtQueryParamName: string;
  jwtTokenPrefix: string;
  apiKeyHeader: string;
  apiKeyValue: string;
  basicUser: string;
  basicPass: string;
  profile: ProfileType;
  advancedOpen: boolean;
  testVolume: "low" | "medium" | "high";
  throttleMode: "none" | "rps" | "delay";
  throttleValue: string;
  validationMode: "off" | "warn" | "strict";
  enableSql: boolean;
  enableXss: boolean;
  enablePathTraversal: boolean;
  enableTemplateInjection: boolean;
  enableSsrf: boolean;
  enableHeaderInjection: boolean;
  enableOpenRedirect: boolean;
  enableFuzz: boolean;
  enableAuth: boolean;
  enableRateLimit: boolean;
  fuzzDepth: string;
  bodyFieldLimit: string;
  seedMode: boolean;
  seedConfig: SeedCandidate[];
  authorizedScanConsent: boolean;
};

function loadNewScanDraft(): Partial<NewScanDraft> | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.sessionStorage.getItem(NEW_SCAN_DRAFT_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as Partial<NewScanDraft>;
  } catch {
    return null;
  }
}

function saveNewScanDraft(draft: NewScanDraft) {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(NEW_SCAN_DRAFT_STORAGE_KEY, JSON.stringify(draft));
  } catch {
    // Ignore quota/storage errors to avoid breaking the wizard flow.
  }
}

function clearNewScanDraft() {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.removeItem(NEW_SCAN_DRAFT_STORAGE_KEY);
  } catch {
    // Ignore storage errors.
  }
}

export default function NewScan() {
  const nav = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const skipNextProfileDefaultsRef = useRef(false);
  const steps = ["API do skanowania", "Uwierzytelnianie", "Profil testów bezpieczeństwa", "Seedowanie", "Przegląd i uruchomienie"];

  const [step, setStep] = useState(0);
  const [stepErrors, setStepErrors] = useState<Record<number, StepErrors>>({});
  const [err, setErr] = useState("");
  const [baseUrl, setBaseUrl] = useState("");

  const [file, setFile] = useState<File | null>(null);
  const [uploadedFileName, setUploadedFileName] = useState("");
  const [openApiText, setOpenApiText] = useState("");
  const [loadingSpec, setLoadingSpec] = useState(false);

  const [authType, setAuthType] = useState<AuthType>("none");
  const [bearerToken, setBearerToken] = useState("");
  const [jwtMode, setJwtMode] = useState<JwtMode>("existing");
  const [jwtExistingToken, setJwtExistingToken] = useState("");
  const [jwtAlgorithm, setJwtAlgorithm] = useState<JwtAlgorithm>("HS256");
  const [jwtSecretOrPrivateKey, setJwtSecretOrPrivateKey] = useState("");
  const [jwtSecretBase64, setJwtSecretBase64] = useState(false);
  const [jwtHeaderJson, setJwtHeaderJson] = useState('{\n  "typ": "JWT",\n  "alg": "HS256"\n}');
  const [jwtPayloadJson, setJwtPayloadJson] = useState(() => {
    const now = Math.floor(Date.now() / 1000);
    return `{\n  "sub": "scanner",\n  "iss": "dast-scanner",\n  "iat": ${now},\n  "exp": ${now + 3600}\n}`;
  });
  const [jwtTokenLocation, setJwtTokenLocation] = useState<JwtLocation>("authorization");
  const [jwtCustomHeaderName, setJwtCustomHeaderName] = useState("X-JWT-Token");
  const [jwtQueryParamName, setJwtQueryParamName] = useState("token");
  const [jwtTokenPrefix, setJwtTokenPrefix] = useState("Bearer");
  const [apiKeyHeader, setApiKeyHeader] = useState("X-API-Key");
  const [apiKeyValue, setApiKeyValue] = useState("");
  const [basicUser, setBasicUser] = useState("");
  const [basicPass, setBasicPass] = useState("");

  const [profile, setProfile] = useState<ProfileType>("quick");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [testVolume, setTestVolume] = useState<"low" | "medium" | "high">("medium");
  const [throttleMode, setThrottleMode] = useState<"none" | "rps" | "delay">("none");
  const [throttleValue, setThrottleValue] = useState("");
  const [validationMode, setValidationMode] = useState<"off" | "warn" | "strict">("warn");
  const [enableSql, setEnableSql] = useState(true);
  const [enableXss, setEnableXss] = useState(true);
  const [enablePathTraversal, setEnablePathTraversal] = useState(true);
  const [enableTemplateInjection, setEnableTemplateInjection] = useState(true);
  const [enableSsrf, setEnableSsrf] = useState(true);
  const [enableHeaderInjection, setEnableHeaderInjection] = useState(true);
  const [enableOpenRedirect, setEnableOpenRedirect] = useState(true);
  const [enableFuzz, setEnableFuzz] = useState(true);
  const [enableAuth, setEnableAuth] = useState(true);
  const [enableRateLimit, setEnableRateLimit] = useState(true);
  const [fuzzDepth, setFuzzDepth] = useState("3");
  const [bodyFieldLimit, setBodyFieldLimit] = useState("6");
  const [seedMode, setSeedMode] = useState(false);
  const [seedConfig, setSeedConfig] = useState<SeedCandidate[]>([]);
  const [loadingSeeds, setLoadingSeeds] = useState(false);

  const [previewing, setPreviewing] = useState(false);
  const [preview, setPreview] = useState<PreviewCounts | null>(null);
  const [starting, setStarting] = useState(false);
  const [authorizedScanConsent, setAuthorizedScanConsent] = useState(false);
  const [confirmRunOpen, setConfirmRunOpen] = useState(false);
  const [draftHydrated, setDraftHydrated] = useState(false);

  useEffect(() => {
    if (skipNextProfileDefaultsRef.current) {
      skipNextProfileDefaultsRef.current = false;
      return;
    }
    applyProfileDefaults(profile);
  }, [profile]);

  useEffect(() => {
    if (profile === "custom") {
      setAdvancedOpen(true);
    }
  }, [profile]);

  useEffect(() => {
    const draft = loadNewScanDraft();
    if (!draft) {
      setDraftHydrated(true);
      return;
    }

    if (typeof draft.step === "number" && Number.isFinite(draft.step)) {
      setStep(Math.max(0, Math.min(steps.length - 1, Math.trunc(draft.step))));
    }
    if (typeof draft.baseUrl === "string") setBaseUrl(draft.baseUrl);
    if (typeof draft.uploadedFileName === "string") setUploadedFileName(draft.uploadedFileName);
    if (typeof draft.openApiText === "string") setOpenApiText(draft.openApiText);
    if (typeof draft.authType === "string") setAuthType(draft.authType as AuthType);
    if (typeof draft.bearerToken === "string") setBearerToken(draft.bearerToken);
    if (typeof draft.jwtMode === "string") setJwtMode(draft.jwtMode as JwtMode);
    if (typeof draft.jwtExistingToken === "string") setJwtExistingToken(draft.jwtExistingToken);
    if (typeof draft.jwtAlgorithm === "string") setJwtAlgorithm(draft.jwtAlgorithm as JwtAlgorithm);
    if (typeof draft.jwtSecretOrPrivateKey === "string") setJwtSecretOrPrivateKey(draft.jwtSecretOrPrivateKey);
    if (typeof draft.jwtSecretBase64 === "boolean") setJwtSecretBase64(draft.jwtSecretBase64);
    if (typeof draft.jwtHeaderJson === "string") setJwtHeaderJson(draft.jwtHeaderJson);
    if (typeof draft.jwtPayloadJson === "string") setJwtPayloadJson(draft.jwtPayloadJson);
    if (typeof draft.jwtTokenLocation === "string") setJwtTokenLocation(draft.jwtTokenLocation as JwtLocation);
    if (typeof draft.jwtCustomHeaderName === "string") setJwtCustomHeaderName(draft.jwtCustomHeaderName);
    if (typeof draft.jwtQueryParamName === "string") setJwtQueryParamName(draft.jwtQueryParamName);
    if (typeof draft.jwtTokenPrefix === "string") setJwtTokenPrefix(draft.jwtTokenPrefix);
    if (typeof draft.apiKeyHeader === "string") setApiKeyHeader(draft.apiKeyHeader);
    if (typeof draft.apiKeyValue === "string") setApiKeyValue(draft.apiKeyValue);
    if (typeof draft.basicUser === "string") setBasicUser(draft.basicUser);
    if (typeof draft.basicPass === "string") setBasicPass(draft.basicPass);
    if (typeof draft.profile === "string") {
      skipNextProfileDefaultsRef.current = true;
      setProfile(draft.profile as ProfileType);
    }
    if (typeof draft.advancedOpen === "boolean") {
      setAdvancedOpen(draft.profile === "custom" ? true : draft.advancedOpen);
    }
    if (typeof draft.testVolume === "string") setTestVolume(draft.testVolume as "low" | "medium" | "high");
    if (typeof draft.throttleMode === "string") setThrottleMode(draft.throttleMode as "none" | "rps" | "delay");
    if (typeof draft.throttleValue === "string") setThrottleValue(draft.throttleValue);
    if (typeof draft.validationMode === "string") setValidationMode(draft.validationMode as "off" | "warn" | "strict");
    if (typeof draft.enableSql === "boolean") setEnableSql(draft.enableSql);
    if (typeof draft.enableXss === "boolean") setEnableXss(draft.enableXss);
    if (typeof draft.enablePathTraversal === "boolean") setEnablePathTraversal(draft.enablePathTraversal);
    if (typeof draft.enableTemplateInjection === "boolean") setEnableTemplateInjection(draft.enableTemplateInjection);
    if (typeof draft.enableSsrf === "boolean") setEnableSsrf(draft.enableSsrf);
    if (typeof draft.enableHeaderInjection === "boolean") setEnableHeaderInjection(draft.enableHeaderInjection);
    if (typeof draft.enableOpenRedirect === "boolean") setEnableOpenRedirect(draft.enableOpenRedirect);
    if (typeof draft.enableFuzz === "boolean") setEnableFuzz(draft.enableFuzz);
    if (typeof draft.enableAuth === "boolean") setEnableAuth(draft.enableAuth);
    if (typeof draft.enableRateLimit === "boolean") setEnableRateLimit(draft.enableRateLimit);
    if (typeof draft.fuzzDepth === "string") setFuzzDepth(draft.fuzzDepth);
    if (typeof draft.bodyFieldLimit === "string") setBodyFieldLimit(draft.bodyFieldLimit);
    if (typeof draft.seedMode === "boolean") setSeedMode(draft.seedMode);
    if (Array.isArray(draft.seedConfig)) setSeedConfig(draft.seedConfig as SeedCandidate[]);
    if (typeof draft.authorizedScanConsent === "boolean") setAuthorizedScanConsent(draft.authorizedScanConsent);

    setDraftHydrated(true);
  }, []);

  useEffect(() => {
    if (!draftHydrated) return;
    saveNewScanDraft({
      step,
      baseUrl,
      uploadedFileName,
      openApiText,
      authType,
      bearerToken,
      jwtMode,
      jwtExistingToken,
      jwtAlgorithm,
      jwtSecretOrPrivateKey,
      jwtSecretBase64,
      jwtHeaderJson,
      jwtPayloadJson,
      jwtTokenLocation,
      jwtCustomHeaderName,
      jwtQueryParamName,
      jwtTokenPrefix,
      apiKeyHeader,
      apiKeyValue,
      basicUser,
      basicPass,
      profile,
      advancedOpen,
      testVolume,
      throttleMode,
      throttleValue,
      validationMode,
      enableSql,
      enableXss,
      enablePathTraversal,
      enableTemplateInjection,
      enableSsrf,
      enableHeaderInjection,
      enableOpenRedirect,
      enableFuzz,
      enableAuth,
      enableRateLimit,
      fuzzDepth,
      bodyFieldLimit,
      seedMode,
      seedConfig,
      authorizedScanConsent
    });
  }, [
    draftHydrated,
    step,
    baseUrl,
    uploadedFileName,
    openApiText,
    authType,
    bearerToken,
    jwtMode,
    jwtExistingToken,
    jwtAlgorithm,
    jwtSecretOrPrivateKey,
    jwtSecretBase64,
    jwtHeaderJson,
    jwtPayloadJson,
    jwtTokenLocation,
    jwtCustomHeaderName,
    jwtQueryParamName,
    jwtTokenPrefix,
    apiKeyHeader,
    apiKeyValue,
    basicUser,
    basicPass,
    profile,
    advancedOpen,
    testVolume,
    throttleMode,
    throttleValue,
    validationMode,
    enableSql,
    enableXss,
    enablePathTraversal,
    enableTemplateInjection,
    enableSsrf,
    enableHeaderInjection,
    enableOpenRedirect,
    enableFuzz,
    enableAuth,
    enableRateLimit,
    fuzzDepth,
    bodyFieldLimit,
    seedMode,
    seedConfig,
    authorizedScanConsent
  ]);

  const summary = useMemo(() => parseOpenApiSummary(openApiText), [openApiText]);
  const fileHint = useMemo(
    () => file?.name || uploadedFileName || "Wybierz plik (.json/.yaml/.yml)",
    [file, uploadedFileName]
  );

  function applyProfileDefaults(value: ProfileType) {
    if (value === "custom") {
      setAdvancedOpen(true);
      setTestVolume("low");
      setValidationMode("off");
      setEnableSql(false);
      setEnableXss(false);
      setEnablePathTraversal(false);
      setEnableTemplateInjection(false);
      setEnableSsrf(false);
      setEnableHeaderInjection(false);
      setEnableOpenRedirect(false);
      setEnableFuzz(false);
      setEnableAuth(false);
      setEnableRateLimit(false);
      setFuzzDepth("0");
      setBodyFieldLimit("0");
      setThrottleMode("none");
      setThrottleValue("0");
      return;
    }

    if (value === "quick") {
      setTestVolume("low");
      setValidationMode("warn");
      setFuzzDepth("3");
      setBodyFieldLimit("6");
      setThrottleMode("none");
      setThrottleValue("");
      setEnableSql(true);
      setEnableXss(true);
      setEnablePathTraversal(true);
      setEnableTemplateInjection(true);
      setEnableSsrf(true);
      setEnableHeaderInjection(true);
      setEnableOpenRedirect(true);
      setEnableFuzz(false);
      setEnableAuth(true);
      setEnableRateLimit(false);
      return;
    }
    setTestVolume("high");
    setValidationMode("strict");
    setFuzzDepth("5");
    setBodyFieldLimit("12");
    setThrottleMode("none");
    setThrottleValue("");
    setEnableSql(true);
    setEnableXss(true);
    setEnablePathTraversal(true);
    setEnableTemplateInjection(true);
    setEnableSsrf(true);
    setEnableHeaderInjection(true);
    setEnableOpenRedirect(true);
    setEnableFuzz(true);
    setEnableAuth(true);
    setEnableRateLimit(true);
  }

  async function onPickFile(f: File | null) {
    setErr("");
    setFile(f);
    setUploadedFileName(f?.name ?? "");
    setOpenApiText("");
    setPreview(null);
    if (!f) return;

    setLoadingSpec(true);
    try {
      const fd = new FormData();
      fd.append("file", f);
      const res = await fetch(`${API}/api/specs/upload`, { method: "POST", body: fd });
      const data = await safeJson(res);
      if (!res.ok) {
        throw new Error(
          data?.error ?? `Nie udało się wczytać pliku OpenAPI (HTTP ${res.status}).`
        );
      }
      const text = String(data?.openApiText ?? "");
      if (!text.trim()) {
        throw new Error(data?.error ?? "Plik OpenAPI został wczytany, ale odpowiedź jest pusta.");
      }
      setOpenApiText(text);
      await loadSeedCandidates(text);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setLoadingSpec(false);
    }
  }

  function clearUploadedFile() {
    setFile(null);
    setUploadedFileName("");
    setOpenApiText("");
    setPreview(null);
    setErr("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }

  function toNum(value: string, def: number, min: number, max: number) {
    const num = Number(value);
    if (!Number.isFinite(num)) return def;
    return Math.max(min, Math.min(max, num));
  }

  function withIds(candidates: any[], defaultEnabled = false): SeedCandidate[] {
    return candidates.map((c) => ({
      id: c.id ?? Math.random().toString(36).slice(2),
      enabled: defaultEnabled ? c.enabled !== false : false,
      method: c.method ?? "POST",
      path: c.path ?? "",
      inputMode: "none",
      contentType: c.contentType,
      accept: c.accept,
      security: c.security,
      idExtractor: c.idExtractor ?? null,
      resourceKey: c.resourceKey ?? "",
      confidence: typeof c.confidence === "number" ? c.confidence : 0,
      reason: c.reason ?? "Automatyczna propozycja",
      payloadText: "",
      paramsText: "",
      headerPairs: []
    }));
  }

  async function loadSeedCandidates(text: string) {
    if (!text.trim()) return;
    setLoadingSeeds(true);
    try {
      const res = await fetch(`${API}/api/specs/seed-candidates`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ openApiText: text })
      });
      const data = await safeJson(res);
      if (!res.ok) throw new Error(data?.error ?? "Nie udało się wygenerować endpointów seedowania.");
      const candidates = Array.isArray(data?.candidates) ? data.candidates : [];
      setSeedConfig(withIds(candidates, false));
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setLoadingSeeds(false);
    }
  }

  function parseKeyValueLines(text: string) {
    if (!text.trim()) return undefined;
    const out: Record<string, string> = {};
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [k, ...rest] = trimmed.split("=");
      if (!k) continue;
      out[k.trim()] = rest.join("=").trim();
    }
    return Object.keys(out).length ? out : undefined;
  }

  function headerPairsToObject(pairs?: { key: string; value: string }[]) {
    if (!Array.isArray(pairs) || !pairs.length) return undefined;
    const out: Record<string, string> = {};
    for (const p of pairs) {
      const key = String(p?.key ?? "").trim();
      const value = String(p?.value ?? "").trim();
      if (!key || !value) continue;
      out[key] = value;
    }
    return Object.keys(out).length ? out : undefined;
  }

  function parsePayload(text: string, inputMode: SeedCandidate["inputMode"]) {
    if (!text.trim()) return undefined;
    if (inputMode === "json") {
      try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
      } catch {
        return undefined;
      }
      return undefined;
    }
    if (inputMode === "form" || inputMode === "multipart") return parseKeyValueLines(text);
    if (inputMode === "binary") return text;
    return undefined;
  }

  function parseJsonObject(text: string): Record<string, unknown> | undefined {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
      return undefined;
    } catch {
      return undefined;
    }
  }

  function isLikelyPem(value: string) {
    const v = value.trim();
    return v.includes("-----BEGIN") && v.includes("PRIVATE KEY-----");
  }

  function buildSmartConfig() {
    return {
      testVolume,
      fuzzDepth: toNum(fuzzDepth, 3, 1, 5),
      bodyFieldLimit: toNum(bodyFieldLimit, 6, 1, 12),
      responseValidation: validationMode,
      enabledTests: {
        SQLi: enableSql,
        XSS: enableXss,
        PATH_TRAVERSAL: enablePathTraversal,
        TEMPLATE_INJECTION: enableTemplateInjection,
        SSRF: enableSsrf,
        HEADER_INJECTION: enableHeaderInjection,
        OPEN_REDIRECT: enableOpenRedirect,
        FUZZ: enableFuzz,
        AUTH: enableAuth,
        RATE_LIMIT: enableRateLimit
      }
    };
  }

  function buildAuthPayload() {
    if (authType === "none") return undefined;
    if (authType === "bearer") {
      return bearerToken.trim() ? { bearerToken: bearerToken.trim() } : undefined;
    }
    if (authType === "jwt") {
      if (jwtMode === "existing") {
        return {
          jwt: {
            mode: "existing",
            existingToken: jwtExistingToken.trim()
          }
        };
      }
      const header = parseJsonObject(jwtHeaderJson);
      const payload = parseJsonObject(jwtPayloadJson);
      if (!header || !payload) return undefined;
      return {
        jwt: {
          mode: "generate",
          algorithm: jwtAlgorithm,
          secretOrPrivateKey: jwtSecretOrPrivateKey,
          secretBase64: jwtSecretBase64,
          header,
          payload,
          tokenLocation: jwtTokenLocation,
          customHeaderName: jwtTokenLocation === "custom_header" ? jwtCustomHeaderName.trim() : undefined,
          queryParamName: jwtTokenLocation === "query" ? jwtQueryParamName.trim() : undefined,
          tokenPrefix: jwtTokenPrefix.trim() || "Bearer"
        }
      };
    }
    if (authType === "apiKey") {
      const value = apiKeyValue.trim();
      if (!value) return undefined;
      return {
        apiKey: {
          headerName: apiKeyHeader.trim() || "X-API-Key",
          value
        }
      };
    }
    if (authType === "basic") {
      const username = basicUser.trim();
      if (!username) return undefined;
      return {
        basic: {
          username,
          password: basicPass
        }
      };
    }
    return undefined;
  }

  function validateStep1(): StepErrors {
    const errors: StepErrors = {};
    const target = baseUrl.trim();
    if (!target) errors.baseUrl = "Podaj adres API (baseUrl).";
    else if (!/^https?:\/\/.+/i.test(target)) errors.baseUrl = 'Adres API musi zaczynać się od "http://" lub "https://".';
    if (!openApiText.trim()) errors.source = "Wgraj plik OpenAPI, aby przejść dalej.";
    return errors;
  }

  function validateStep2(): StepErrors {
    const errors: StepErrors = {};
    if (authType === "bearer" && !bearerToken.trim()) errors.bearerToken = "Podaj Bearer Token.";
    if (authType === "jwt") {
      if (jwtMode === "existing") {
        const token = jwtExistingToken.trim();
        if (!token) errors.jwtExistingToken = "Podaj token JWT.";
        else if (!/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/.test(token)) {
          errors.jwtExistingToken = "Token JWT ma nieprawidłowy format.";
        }
      } else {
        if (!jwtSecretOrPrivateKey.trim()) {
          errors.jwtSecretOrPrivateKey = jwtAlgorithm === "RS256" ? "Podaj klucz prywatny (PEM)." : "Podaj sekret.";
        }
        if (jwtAlgorithm === "RS256" && !isLikelyPem(jwtSecretOrPrivateKey)) {
          errors.jwtSecretOrPrivateKey = "Klucz prywatny musi być w formacie PEM.";
        }
        const header = parseJsonObject(jwtHeaderJson);
        const payload = parseJsonObject(jwtPayloadJson);
        if (!header) errors.jwtHeaderJson = "Nieprawidłowy JSON nagłówka JWT.";
        if (!payload) errors.jwtPayloadJson = "Nieprawidłowy JSON payload/claims.";
        const iat = payload && typeof payload.iat === "number" ? payload.iat : undefined;
        const exp = payload && typeof payload.exp === "number" ? payload.exp : undefined;
        if (iat != null && exp != null && exp <= iat) {
          errors.jwtClaims = "Pole exp musi być większe od iat.";
        }
        if (jwtTokenLocation === "custom_header" && !jwtCustomHeaderName.trim()) {
          errors.jwtCustomHeaderName = "Podaj nazwę nagłówka.";
        }
        if (jwtTokenLocation === "query" && !jwtQueryParamName.trim()) {
          errors.jwtQueryParamName = "Podaj nazwę parametru.";
        }
        if (!jwtTokenPrefix.trim()) {
          errors.jwtTokenPrefix = "Podaj prefiks tokena.";
        }
      }
    }
    if (authType === "apiKey") {
      if (!apiKeyHeader.trim()) errors.apiKeyHeader = "Podaj nazwę nagłówka klucza API.";
      if (!apiKeyValue.trim()) errors.apiKeyValue = "Podaj wartość klucza API.";
    }
    if (authType === "basic" && !basicUser.trim()) errors.basicUser = "Podaj użytkownika Basic Auth.";
    return errors;
  }

  function validateStep3(): StepErrors {
    const errors: StepErrors = {};
    if (
      !enableSql &&
      !enableXss &&
      !enablePathTraversal &&
      !enableTemplateInjection &&
      !enableSsrf &&
      !enableHeaderInjection &&
      !enableOpenRedirect &&
      !enableFuzz &&
      !enableAuth &&
      !enableRateLimit
    ) {
      errors.enabledTests = "Wybierz przynajmniej jeden typ testu.";
    }
    if (throttleMode !== "none") {
      const value = Number(throttleValue);
      if (!Number.isFinite(value) || value <= 0) {
        errors.throttleValue = "Podaj dodatnią wartość limitu zapytań.";
      }
    }
    return errors;
  }

  function validateStep4(): StepErrors {
    const errors: StepErrors = {};
    if (seedMode && seedConfig.filter((s) => s.enabled).length === 0) {
      errors.seed = "Włącz przynajmniej jedno seedowanie albo wyłącz seedowanie.";
    }
    return errors;
  }

  function getStepErrors(stepIndex: number): StepErrors {
    if (stepIndex === 0) return validateStep1();
    if (stepIndex === 1) return validateStep2();
    if (stepIndex === 2) return validateStep3();
    if (stepIndex === 3) return validateStep4();
    return {};
  }

  const currentErrors = useMemo(() => {
    const saved = stepErrors[step] ?? {};
    if (Object.keys(saved).length === 0) return {};
    const live = getStepErrors(step);
    const visible: StepErrors = {};
    for (const key of Object.keys(saved)) {
      if (live[key]) visible[key] = live[key];
    }
    return visible;
  }, [
    step,
    stepErrors,
    baseUrl,
    openApiText,
    authType,
    bearerToken,
    jwtMode,
    jwtExistingToken,
    jwtAlgorithm,
    jwtSecretOrPrivateKey,
    jwtSecretBase64,
    jwtHeaderJson,
    jwtPayloadJson,
    jwtTokenLocation,
    jwtCustomHeaderName,
    jwtQueryParamName,
    jwtTokenPrefix,
    apiKeyHeader,
    apiKeyValue,
    basicUser,
    enableSql,
    enableXss,
    enablePathTraversal,
    enableTemplateInjection,
    enableSsrf,
    enableHeaderInjection,
    enableOpenRedirect,
    enableFuzz,
    enableAuth,
    enableRateLimit,
    throttleMode,
    throttleValue,
    seedMode,
    seedConfig
  ]);

  async function fetchPreview() {
    if (!openApiText.trim()) return;
    setPreviewing(true);
    try {
      const res = await fetch(`${API}/api/scans/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ openApiText, smart: buildSmartConfig() })
      });
      const data = await safeJson(res);
      if (!res.ok) throw new Error(data?.error ?? "Nie udało się przygotować podglądu testów.");
      setPreview(data?.counts ?? null);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setPreviewing(false);
    }
  }

  useEffect(() => {
    if (step !== 4) return;
    if (!openApiText.trim()) return;
    const timer = setTimeout(() => {
      void fetchPreview();
    }, 250);
    return () => clearTimeout(timer);
  }, [
    step,
    openApiText,
    testVolume,
    fuzzDepth,
    bodyFieldLimit,
    validationMode,
    enableSql,
    enableXss,
    enablePathTraversal,
    enableTemplateInjection,
    enableSsrf,
    enableHeaderInjection,
    enableOpenRedirect,
    enableFuzz,
    enableAuth,
    enableRateLimit
  ]);

  async function startScan() {
    setErr("");
    setStarting(true);
    try {
      if (!openApiText.trim()) throw new Error("Brak wczytanej specyfikacji OpenAPI.");
      const target = baseUrl.trim();
      if (!target) throw new Error("Podaj adres API (baseUrl).");

      let throttle: { mode: "rps" | "delay"; value: number } | undefined;
      if (throttleMode !== "none") {
        const val = Number(throttleValue);
        if (!Number.isFinite(val) || val <= 0) throw new Error("Podaj dodatnią wartość limitu zapytań.");
        throttle = { mode: throttleMode, value: val };
      }

      const auth = buildAuthPayload();
      const smart = buildSmartConfig();

      const res = await fetch(`${API}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          openApiText,
          baseUrl: target,
          auth,
          throttle,
          smart,
          seed: seedMode
            ? {
                enabled: true,
                createEndpoints: seedConfig
                  .filter((s) => s.enabled)
                  .map((s) => ({
                    method: s.method,
                    path: s.path,
                    inputMode: s.inputMode,
                    contentType: s.contentType,
                    accept: s.accept,
                    security: s.security,
                    idExtractor: s.idExtractor ?? undefined,
                    resourceKey: s.resourceKey || undefined,
                    enabled: s.enabled,
                    payload: parsePayload(s.payloadText ?? "", s.inputMode),
                    query: parseKeyValueLines(s.paramsText ?? ""),
                    headers: headerPairsToObject(s.headerPairs)
                  }))
              }
            : false
        })
      });
      const scan = await safeJson(res);
      if (!res.ok) throw new Error(scan?.error ?? "Nie udało się uruchomić skanowania.");
      clearNewScanDraft();
      nav(`/running?scanId=${encodeURIComponent(scan.id)}`);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setStarting(false);
    }
  }

  async function handleNext() {
    const errors = getStepErrors(step);
    setStepErrors((prev) => ({ ...prev, [step]: errors }));
    if (Object.keys(errors).length) return;
    if (step === steps.length - 1) {
      setConfirmRunOpen(true);
      return;
    }
    setStep((s) => s + 1);
  }

  function handleBack() {
    setStep((s) => Math.max(0, s - 1));
  }

  const isStep1Ready = /^https?:\/\/.+/i.test(baseUrl.trim()) && !!openApiText.trim() && !err;
  const hasLoadedSpec = !!file || !!uploadedFileName || !!openApiText.trim();
  const nextLabel = step === steps.length - 1 ? (starting ? "Uruchamianie..." : "Uruchom skanowanie") : "Dalej";
  const nextDisabled =
    loadingSpec ||
    starting ||
    (step === 0 && !isStep1Ready) ||
    (step === steps.length - 1 && !authorizedScanConsent);

  return (
    <Box>
      <Typography variant="h2">Konfiguracja skanowania</Typography>
      <Typography sx={{ color: "text.secondary", mt: 0.5 }}>
        Skonfiguruj cel, uwierzytelnianie i profil testów bezpieczeństwa w pięciu krokach.
      </Typography>

      <WizardLayout
        steps={steps}
        activeStep={step}
        completedSteps={confirmRunOpen && step === steps.length - 1 ? [step] : undefined}
        onBack={handleBack}
        onNext={handleNext}
        backDisabled={step === 0 || loadingSpec || starting}
        nextDisabled={nextDisabled}
        nextLabel={nextLabel}
      >
        <Stack spacing={2}>
          {step === 0 ? (
            <StepTarget
              baseUrl={baseUrl}
              setBaseUrl={setBaseUrl}
              fileInputRef={fileInputRef}
              fileHint={fileHint}
              onPickFile={onPickFile}
              onClearFile={clearUploadedFile}
              hasFile={hasLoadedSpec}
              loaded={!!openApiText.trim()}
              loadingSpec={loadingSpec}
              errMessage={err}
              errors={currentErrors}
            />
          ) : null}

          {step === 1 ? (
            <StepAuth
              authType={authType}
              setAuthType={setAuthType}
              bearerToken={bearerToken}
              setBearerToken={setBearerToken}
              jwtMode={jwtMode}
              setJwtMode={setJwtMode}
              jwtExistingToken={jwtExistingToken}
              setJwtExistingToken={setJwtExistingToken}
              jwtAlgorithm={jwtAlgorithm}
              setJwtAlgorithm={setJwtAlgorithm}
              jwtSecretOrPrivateKey={jwtSecretOrPrivateKey}
              setJwtSecretOrPrivateKey={setJwtSecretOrPrivateKey}
              jwtSecretBase64={jwtSecretBase64}
              setJwtSecretBase64={setJwtSecretBase64}
              jwtHeaderJson={jwtHeaderJson}
              setJwtHeaderJson={setJwtHeaderJson}
              jwtPayloadJson={jwtPayloadJson}
              setJwtPayloadJson={setJwtPayloadJson}
              jwtTokenLocation={jwtTokenLocation}
              setJwtTokenLocation={setJwtTokenLocation}
              jwtCustomHeaderName={jwtCustomHeaderName}
              setJwtCustomHeaderName={setJwtCustomHeaderName}
              jwtQueryParamName={jwtQueryParamName}
              setJwtQueryParamName={setJwtQueryParamName}
              jwtTokenPrefix={jwtTokenPrefix}
              setJwtTokenPrefix={setJwtTokenPrefix}
              apiKeyHeader={apiKeyHeader}
              setApiKeyHeader={setApiKeyHeader}
              apiKeyValue={apiKeyValue}
              setApiKeyValue={setApiKeyValue}
              basicUser={basicUser}
              setBasicUser={setBasicUser}
              basicPass={basicPass}
              setBasicPass={setBasicPass}
              errors={currentErrors}
            />
          ) : null}

          {step === 2 ? (
            <StepProfile
              profile={profile}
              setProfile={setProfile}
              advancedOpen={advancedOpen}
              setAdvancedOpen={setAdvancedOpen}
              testVolume={testVolume}
              setTestVolume={setTestVolume}
              throttleMode={throttleMode}
              setThrottleMode={setThrottleMode}
              throttleValue={throttleValue}
              setThrottleValue={setThrottleValue}
              validationMode={validationMode}
              setValidationMode={setValidationMode}
              enableSql={enableSql}
              setEnableSql={setEnableSql}
              enableXss={enableXss}
              setEnableXss={setEnableXss}
              enablePathTraversal={enablePathTraversal}
              setEnablePathTraversal={setEnablePathTraversal}
              enableTemplateInjection={enableTemplateInjection}
              setEnableTemplateInjection={setEnableTemplateInjection}
              enableSsrf={enableSsrf}
              setEnableSsrf={setEnableSsrf}
              enableHeaderInjection={enableHeaderInjection}
              setEnableHeaderInjection={setEnableHeaderInjection}
              enableOpenRedirect={enableOpenRedirect}
              setEnableOpenRedirect={setEnableOpenRedirect}
              enableFuzz={enableFuzz}
              setEnableFuzz={setEnableFuzz}
              enableAuth={enableAuth}
              setEnableAuth={setEnableAuth}
              enableRateLimit={enableRateLimit}
              setEnableRateLimit={setEnableRateLimit}
              fuzzDepth={fuzzDepth}
              setFuzzDepth={setFuzzDepth}
              bodyFieldLimit={bodyFieldLimit}
              setBodyFieldLimit={setBodyFieldLimit}
              errors={currentErrors}
            />
          ) : null}

          {step === 3 ? (
            <StepSeeding
              baseUrl={baseUrl}
              setBaseUrl={setBaseUrl}
              seedMode={seedMode}
              setSeedMode={setSeedMode}
              seedConfig={seedConfig}
              setSeedConfig={setSeedConfig}
              loadingSeeds={loadingSeeds}
              onReloadSeeds={() => loadSeedCandidates(openApiText)}
              errors={currentErrors}
            />
          ) : null}

          {step === 4 ? (
            <StepReview
              baseUrl={baseUrl}
              authType={authType}
              profile={profile}
              seedMode={seedMode}
              enabledSeeds={seedConfig.filter((s) => s.enabled).length}
              summary={summary}
              preview={preview}
              previewing={previewing}
              enableSql={enableSql}
              enableXss={enableXss}
              enablePathTraversal={enablePathTraversal}
              enableTemplateInjection={enableTemplateInjection}
              enableSsrf={enableSsrf}
              enableHeaderInjection={enableHeaderInjection}
              enableOpenRedirect={enableOpenRedirect}
              enableFuzz={enableFuzz}
              enableAuth={enableAuth}
              enableRateLimit={enableRateLimit}
              authorizedScanConsent={authorizedScanConsent}
              setAuthorizedScanConsent={setAuthorizedScanConsent}
            />
          ) : null}

          {err ? (
            <Paper sx={{ p: 1.5, borderRadius: 2, border: "1px solid #FFD7D7", bgcolor: "#FFF5F5" }}>
              <Typography sx={{ color: "#C03434", fontSize: 13 }}>{err}</Typography>
            </Paper>
          ) : null}
        </Stack>
      </WizardLayout>

      <Dialog
        open={confirmRunOpen}
        onClose={() => (!starting ? setConfirmRunOpen(false) : undefined)}
        maxWidth="sm"
        fullWidth
        PaperProps={{
          sx: {
            bgcolor: "#192033",
            color: "#DDE3F0",
            borderRadius: 2,
            minHeight: 240
          }
        }}
      >
        <DialogTitle sx={{ color: "#FFFFFF", textAlign: "center", pt: 3 }}>
          Potwierdź uruchomienie skanowania
        </DialogTitle>
        <DialogContent sx={{ display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center" }}>
          <Typography sx={{ fontSize: 14, color: "#B7C0D8", maxWidth: 440 }}>
            Czy na pewno chcesz uruchomić skanowanie dla wskazanego API z bieżącą konfiguracją?
          </Typography>
        </DialogContent>
        <DialogActions sx={{ justifyContent: "center", pb: 2.5, px: 3 }}>
          <Button
            onClick={() => setConfirmRunOpen(false)}
            disabled={starting}
            variant="outlined"
            sx={{ color: "#DDE3F0", borderColor: "rgba(221,227,240,0.35)" }}
          >
            Anuluj
          </Button>
          <Button
            variant="outlined"
            disabled={starting}
            onClick={async () => {
              await startScan();
              setConfirmRunOpen(false);
            }}
            sx={{ color: "#DDE3F0", borderColor: "rgba(221,227,240,0.35)" }}
          >
            {starting ? "Uruchamianie..." : "Tak"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function TitleWithTooltip({ title, tooltip }: { title: string; tooltip: string }) {
  return (
    <Stack direction="row" spacing={1} alignItems="center">
      <Typography sx={{ fontWeight: 600 }}>{title}</Typography>
      <Tooltip title={tooltip} placement="right" arrow>
        <IconButton size="small" aria-label={`${title} informacje`}>
          <InfoOutlined fontSize="inherit" />
        </IconButton>
      </Tooltip>
    </Stack>
  );
}

function formatAuthType(authType: AuthType): string {
  if (authType === "none") return "Brak";
  if (authType === "bearer") return "Bearer Token";
  if (authType === "jwt") return "JWT Bearer";
  if (authType === "apiKey") return "Klucz API";
  if (authType === "basic") return "Basic Auth";
  return "Brak";
}

function formatProfile(profile: ProfileType): string {
  if (profile === "quick") return "Szybki";
  if (profile === "custom") return "Ustawienia własne użytkownika";
  return "Pogłębiony";
}

function getScanRunRiskAssessment(baseUrl: string, profile: ProfileType) {
  let hostname = "Nieznany host";
  let isPublicDomain = true;

  try {
    const parsed = new URL(baseUrl.trim());
    hostname = parsed.hostname || hostname;
    const h = hostname.toLowerCase();
    const isPrivateLike =
      h === "localhost" ||
      h === "127.0.0.1" ||
      h.startsWith("10.") ||
      h.startsWith("192.168.");
    isPublicDomain = !isPrivateLike;
  } catch {
    isPublicDomain = true;
  }

  if (!isPublicDomain) {
    return {
      level: "low" as const,
      label: "Niskie ryzyko",
      color: "success" as const,
      hostname,
      description:
        "Docelowy host wygląda na środowisko lokalne lub sieć prywatną (localhost / adres prywatny), co zwykle zmniejsza ryzyko wpływu na system produkcyjny podczas testów aktywnych."
    };
  }

  if (profile === "deep") {
    return {
      level: "high" as const,
      label: "Wysokie ryzyko",
      color: "error" as const,
      hostname,
      description:
        "Wybrano profil pogłębiony dla domeny publicznej. Taki skan wykonuje więcej testów i może częściej generować błędy aplikacyjne, dane testowe lub aktywować mechanizmy ochronne."
    };
  }

  return {
    level: "moderate" as const,
    label: "Umiarkowane ryzyko",
    color: "warning" as const,
    hostname,
    description:
      "Docelowy host wygląda na domenę publiczną. Nawet przy standardowym profilu skanowanie będzie wysyłać zmodyfikowane żądania testowe, które mogą wpłynąć na logi, limity i stan danych."
  };
}

type StepTargetProps = {
  baseUrl: string;
  setBaseUrl: (value: string) => void;
  fileInputRef: RefObject<HTMLInputElement>;
  fileHint: string;
  onPickFile: (file: File | null) => Promise<void>;
  onClearFile: () => void;
  hasFile: boolean;
  loaded: boolean;
  loadingSpec: boolean;
  errMessage: string;
  errors: StepErrors;
};

function StepTarget(props: StepTargetProps) {
  const {
    baseUrl,
    setBaseUrl,
    fileInputRef,
    fileHint,
    onPickFile,
    onClearFile,
    hasFile,
    loaded,
    loadingSpec,
    errMessage,
    errors
  } = props;

  return (
    <Stack spacing={2}>
      <TitleWithTooltip title="Krok 1: API do skanowania" tooltip="Ustaw adres API i wgraj plik OpenAPI." />
      <TextField
        label="Adres API (baseUrl)"
        value={baseUrl}
        onChange={(e) => setBaseUrl(e.target.value)}
        placeholder="https://api.example.com"
        error={!!errors.baseUrl}
        helperText={errors.baseUrl}
        fullWidth
      />

      <Stack spacing={1}>
        <input
          id="openapi-file"
          ref={fileInputRef}
          type="file"
          accept=".json,.yaml,.yml,application/json"
          onChange={(e) => onPickFile(e.target.files?.[0] ?? null)}
          style={{ display: "none" }}
        />
        <Stack direction="row" spacing={1.5} alignItems="center">
          <Button variant="outlined" component="label" htmlFor="openapi-file" disabled={loadingSpec || hasFile}>
            Wgraj plik
          </Button>
          <Typography sx={{ fontSize: 15, color: "text.secondary" }}>{fileHint}</Typography>
          {hasFile ? (
            <Tooltip title="Usuń wgrany plik" arrow>
              <IconButton
                size="small"
                aria-label="Usuń wgrany plik"
                onClick={onClearFile}
                disabled={loadingSpec}
              >
                <CloseIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          ) : null}
        </Stack>
      </Stack>

      {errors.source ? <Typography sx={{ fontSize: 12, color: "#C03434" }}>{errors.source}</Typography> : null}
      {!errMessage ? (
        <Typography
          sx={{
            fontSize: 12,
            color: loaded ? "#1E7A34" : "text.secondary"
          }}
        >
          {loadingSpec ? "Wczytywanie OpenAPI..." : loaded ? "Specyfikacja OpenAPI została wczytana." : "Brak wczytanej specyfikacji OpenAPI."}
        </Typography>
      ) : null}
    </Stack>
  );
}

type StepAuthProps = {
  authType: AuthType;
  setAuthType: (value: AuthType) => void;
  bearerToken: string;
  setBearerToken: (value: string) => void;
  jwtMode: JwtMode;
  setJwtMode: (value: JwtMode) => void;
  jwtExistingToken: string;
  setJwtExistingToken: (value: string) => void;
  jwtAlgorithm: JwtAlgorithm;
  setJwtAlgorithm: (value: JwtAlgorithm) => void;
  jwtSecretOrPrivateKey: string;
  setJwtSecretOrPrivateKey: (value: string) => void;
  jwtSecretBase64: boolean;
  setJwtSecretBase64: (value: boolean) => void;
  jwtHeaderJson: string;
  setJwtHeaderJson: (value: string) => void;
  jwtPayloadJson: string;
  setJwtPayloadJson: (value: string) => void;
  jwtTokenLocation: JwtLocation;
  setJwtTokenLocation: (value: JwtLocation) => void;
  jwtCustomHeaderName: string;
  setJwtCustomHeaderName: (value: string) => void;
  jwtQueryParamName: string;
  setJwtQueryParamName: (value: string) => void;
  jwtTokenPrefix: string;
  setJwtTokenPrefix: (value: string) => void;
  apiKeyHeader: string;
  setApiKeyHeader: (value: string) => void;
  apiKeyValue: string;
  setApiKeyValue: (value: string) => void;
  basicUser: string;
  setBasicUser: (value: string) => void;
  basicPass: string;
  setBasicPass: (value: string) => void;
  errors: StepErrors;
};

function StepAuth(props: StepAuthProps) {
  const {
    authType,
    setAuthType,
    bearerToken,
    setBearerToken,
    jwtMode,
    setJwtMode,
    jwtExistingToken,
    setJwtExistingToken,
    jwtAlgorithm,
    setJwtAlgorithm,
    jwtSecretOrPrivateKey,
    setJwtSecretOrPrivateKey,
    jwtSecretBase64,
    setJwtSecretBase64,
    jwtHeaderJson,
    setJwtHeaderJson,
    jwtPayloadJson,
    setJwtPayloadJson,
    jwtTokenLocation,
    setJwtTokenLocation,
    jwtCustomHeaderName,
    setJwtCustomHeaderName,
    jwtQueryParamName,
    setJwtQueryParamName,
    jwtTokenPrefix,
    setJwtTokenPrefix,
    apiKeyHeader,
    setApiKeyHeader,
    apiKeyValue,
    setApiKeyValue,
    basicUser,
    setBasicUser,
    basicPass,
    setBasicPass,
    errors
  } = props;

  return (
    <Stack spacing={2}>
      <TitleWithTooltip title="Krok 2: Uwierzytelnianie" tooltip="Wybierz typ uwierzytelniania i uzupełnij wymagane pola." />

      <FormControl fullWidth>
        <InputLabel id="auth-type-label">Typ uwierzytelniania</InputLabel>
        <Select
          labelId="auth-type-label"
          label="Typ uwierzytelniania"
          value={authType}
          onChange={(e) => setAuthType(e.target.value as AuthType)}
        >
          <MenuItem value="none">Brak</MenuItem>
          <MenuItem value="bearer">Bearer Token</MenuItem>
          <MenuItem value="jwt">JWT Bearer</MenuItem>
          <MenuItem value="apiKey">Klucz API</MenuItem>
          <MenuItem value="basic">Basic Auth</MenuItem>
        </Select>
      </FormControl>

      {authType === "bearer" ? (
        <TextField
          label="Bearer Token"
          value={bearerToken}
          onChange={(e) => setBearerToken(e.target.value)}
          error={!!errors.bearerToken}
          helperText={errors.bearerToken}
          fullWidth
        />
      ) : null}

      {authType === "apiKey" ? (
        <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
          <TextField
            label="Nagłówek klucza API"
            value={apiKeyHeader}
            onChange={(e) => setApiKeyHeader(e.target.value)}
            error={!!errors.apiKeyHeader}
            helperText={errors.apiKeyHeader}
            fullWidth
          />
          <TextField
            label="Wartość klucza API"
            value={apiKeyValue}
            onChange={(e) => setApiKeyValue(e.target.value)}
            error={!!errors.apiKeyValue}
            helperText={errors.apiKeyValue}
            fullWidth
          />
        </Stack>
      ) : null}

      {authType === "jwt" ? (
        <Stack spacing={2}>
          <Paper variant="outlined" sx={{ p: 1.5 }}>
            <RadioGroup
              row
              value={jwtMode}
              onChange={(e) => setJwtMode(e.target.value as JwtMode)}
            >
              <FormControlLabel value="existing" control={<Radio />} label="Użyj istniejącego tokena" />
              <FormControlLabel value="generate" control={<Radio />} label="Generuj token JWT" />
            </RadioGroup>
          </Paper>

          {jwtMode === "existing" ? (
            <TextField
              label="Token JWT"
              value={jwtExistingToken}
              onChange={(e) => setJwtExistingToken(e.target.value)}
              error={!!errors.jwtExistingToken}
              helperText={errors.jwtExistingToken ?? "Token zostanie wysłany w nagłówku Authorization: Bearer <token>"}
              multiline
              minRows={3}
              fullWidth
              sx={{ "& textarea": { WebkitTextSecurity: "disc" } }}
            />
          ) : (
            <Stack spacing={1.5}>
              <Typography sx={{ fontWeight: 600 }}>Generowanie tokena JWT</Typography>
              <FormControl fullWidth>
                <InputLabel id="jwt-alg-label">Algorytm</InputLabel>
                <Select
                  labelId="jwt-alg-label"
                  label="Algorytm"
                  value={jwtAlgorithm}
                  onChange={(e) => setJwtAlgorithm(e.target.value as JwtAlgorithm)}
                >
                  <MenuItem value="HS256">HS256</MenuItem>
                  <MenuItem value="HS384">HS384</MenuItem>
                  <MenuItem value="HS512">HS512</MenuItem>
                  <MenuItem value="RS256">RS256</MenuItem>
                </Select>
              </FormControl>

              <TextField
                label={jwtAlgorithm === "RS256" ? "Klucz prywatny (PEM)" : "Sekret"}
                value={jwtSecretOrPrivateKey}
                onChange={(e) => setJwtSecretOrPrivateKey(e.target.value)}
                error={!!errors.jwtSecretOrPrivateKey}
                helperText={errors.jwtSecretOrPrivateKey}
                multiline={jwtAlgorithm === "RS256"}
                minRows={jwtAlgorithm === "RS256" ? 4 : undefined}
                fullWidth
                sx={{ "& textarea": { WebkitTextSecurity: "disc" } }}
              />

              <FormControlLabel
                control={<Switch checked={jwtSecretBase64} onChange={(e) => setJwtSecretBase64(e.target.checked)} />}
                label="Sekret zakodowany jako Base64"
              />

              <TextField
                label="Nagłówek (JSON)"
                value={jwtHeaderJson}
                onChange={(e) => setJwtHeaderJson(e.target.value)}
                error={!!errors.jwtHeaderJson}
                helperText={errors.jwtHeaderJson}
                multiline
                minRows={4}
                fullWidth
              />

              <TextField
                label="Payload / Claims (JSON)"
                value={jwtPayloadJson}
                onChange={(e) => setJwtPayloadJson(e.target.value)}
                error={!!errors.jwtPayloadJson || !!errors.jwtClaims}
                helperText={errors.jwtPayloadJson ?? errors.jwtClaims}
                multiline
                minRows={6}
                fullWidth
              />

              <FormControl fullWidth>
                <InputLabel id="jwt-location-label">Lokalizacja tokena</InputLabel>
                <Select
                  labelId="jwt-location-label"
                  label="Lokalizacja tokena"
                  value={jwtTokenLocation}
                  onChange={(e) => setJwtTokenLocation(e.target.value as JwtLocation)}
                >
                  <MenuItem value="authorization">Nagłówek Authorization</MenuItem>
                  <MenuItem value="custom_header">Własny nagłówek</MenuItem>
                  <MenuItem value="query">Parametr query</MenuItem>
                </Select>
              </FormControl>

              {jwtTokenLocation === "custom_header" ? (
                <TextField
                  label="Nazwa nagłówka"
                  value={jwtCustomHeaderName}
                  onChange={(e) => setJwtCustomHeaderName(e.target.value)}
                  error={!!errors.jwtCustomHeaderName}
                  helperText={errors.jwtCustomHeaderName}
                  fullWidth
                />
              ) : null}

              {jwtTokenLocation === "query" ? (
                <TextField
                  label="Nazwa parametru"
                  value={jwtQueryParamName}
                  onChange={(e) => setJwtQueryParamName(e.target.value)}
                  error={!!errors.jwtQueryParamName}
                  helperText={errors.jwtQueryParamName}
                  fullWidth
                />
              ) : null}

              <TextField
                label="Prefiks tokena"
                value={jwtTokenPrefix}
                onChange={(e) => setJwtTokenPrefix(e.target.value)}
                error={!!errors.jwtTokenPrefix}
                helperText={errors.jwtTokenPrefix}
                fullWidth
              />
            </Stack>
          )}
        </Stack>
      ) : null}

      {authType === "basic" ? (
        <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
          <TextField
            label="Nazwa użytkownika"
            value={basicUser}
            onChange={(e) => setBasicUser(e.target.value)}
            error={!!errors.basicUser}
            helperText={errors.basicUser}
            fullWidth
          />
          <TextField
            label="Hasło"
            type="password"
            value={basicPass}
            onChange={(e) => setBasicPass(e.target.value)}
            fullWidth
          />
        </Stack>
      ) : null}

    </Stack>
  );
}

type StepProfileProps = {
  profile: ProfileType;
  setProfile: (value: ProfileType) => void;
  advancedOpen: boolean;
  setAdvancedOpen: (value: boolean) => void;
  testVolume: "low" | "medium" | "high";
  setTestVolume: (value: "low" | "medium" | "high") => void;
  throttleMode: "none" | "rps" | "delay";
  setThrottleMode: (value: "none" | "rps" | "delay") => void;
  throttleValue: string;
  setThrottleValue: (value: string) => void;
  validationMode: "off" | "warn" | "strict";
  setValidationMode: (value: "off" | "warn" | "strict") => void;
  enableSql: boolean;
  setEnableSql: (value: boolean) => void;
  enableXss: boolean;
  setEnableXss: (value: boolean) => void;
  enablePathTraversal: boolean;
  setEnablePathTraversal: (value: boolean) => void;
  enableTemplateInjection: boolean;
  setEnableTemplateInjection: (value: boolean) => void;
  enableSsrf: boolean;
  setEnableSsrf: (value: boolean) => void;
  enableHeaderInjection: boolean;
  setEnableHeaderInjection: (value: boolean) => void;
  enableOpenRedirect: boolean;
  setEnableOpenRedirect: (value: boolean) => void;
  enableFuzz: boolean;
  setEnableFuzz: (value: boolean) => void;
  enableAuth: boolean;
  setEnableAuth: (value: boolean) => void;
  enableRateLimit: boolean;
  setEnableRateLimit: (value: boolean) => void;
  fuzzDepth: string;
  setFuzzDepth: (value: string) => void;
  bodyFieldLimit: string;
  setBodyFieldLimit: (value: string) => void;
  errors: StepErrors;
};

function StepProfile(props: StepProfileProps) {
  const {
    profile,
    setProfile,
    advancedOpen,
    setAdvancedOpen,
    testVolume,
    setTestVolume,
    throttleMode,
    setThrottleMode,
    throttleValue,
    setThrottleValue,
    validationMode,
    setValidationMode,
    enableSql,
    setEnableSql,
    enableXss,
    setEnableXss,
    enablePathTraversal,
    setEnablePathTraversal,
    enableTemplateInjection,
    setEnableTemplateInjection,
    enableSsrf,
    setEnableSsrf,
    enableHeaderInjection,
    setEnableHeaderInjection,
    enableOpenRedirect,
    setEnableOpenRedirect,
    enableFuzz,
    setEnableFuzz,
    enableAuth,
    setEnableAuth,
    enableRateLimit,
    setEnableRateLimit,
    fuzzDepth,
    setFuzzDepth,
    bodyFieldLimit,
    setBodyFieldLimit,
    errors
  } = props;

  return (
    <Stack spacing={2}>
      <TitleWithTooltip
        title="Krok 3: Profil testów bezpieczeństwa"
        tooltip="Wybierz profil i opcjonalnie skonfiguruj ustawienia zaawansowane."
      />

      <FormControl fullWidth>
        <InputLabel id="profile-label">Profil testów bezpieczeństwa</InputLabel>
        <Select
          labelId="profile-label"
          label="Profil testów bezpieczeństwa"
          value={profile}
          onChange={(e) => setProfile(e.target.value as ProfileType)}
        >
          <MenuItem value="quick">Szybki</MenuItem>
          <MenuItem value="deep">Pogłębiony</MenuItem>
          <MenuItem value="custom">Ustawienia własne użytkownika</MenuItem>
        </Select>
      </FormControl>

      {profile === "custom" ? (
        <Paper variant="outlined" sx={{ p: 1.25, bgcolor: "#F7FAFF" }}>
          <Typography sx={{ fontSize: 13, color: "text.secondary" }}>
            Wybrano tryb ręczny. Skonfiguruj testy bezpieczeństwa samodzielnie w ustawieniach zaawansowanych.
          </Typography>
        </Paper>
      ) : null}

      <Accordion expanded={advancedOpen} onChange={(_, expanded) => setAdvancedOpen(expanded)}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography>Ustawienia zaawansowane</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Stack spacing={2}>
            <Alert severity="info" variant="outlined">
              Te przełączniki kontrolują wszystkie typy testów uruchamiane przez silnik skanera i raportowane w wynikach skanu.
            </Alert>

            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" },
                gap: 1.5
              }}
            >
              <Paper variant="outlined" sx={{ p: 1.25 }}>
                <Typography sx={{ fontSize: 12, fontWeight: 700, mb: 0.5 }}>Testy bezpieczeństwa</Typography>
                <Stack spacing={0.25}>
                  <FormControlLabel control={<Switch checked={enableSql} onChange={(e) => setEnableSql(e.target.checked)} />} label="SQLi" />
                  <FormControlLabel control={<Switch checked={enableXss} onChange={(e) => setEnableXss(e.target.checked)} />} label="XSS" />
                  <FormControlLabel control={<Switch checked={enableSsrf} onChange={(e) => setEnableSsrf(e.target.checked)} />} label="SSRF" />
                  <FormControlLabel
                    control={<Switch checked={enablePathTraversal} onChange={(e) => setEnablePathTraversal(e.target.checked)} />}
                    label="Path Traversal"
                  />
                  <FormControlLabel
                    control={<Switch checked={enableTemplateInjection} onChange={(e) => setEnableTemplateInjection(e.target.checked)} />}
                    label="Template Injection"
                  />
                  <FormControlLabel
                    control={<Switch checked={enableHeaderInjection} onChange={(e) => setEnableHeaderInjection(e.target.checked)} />}
                    label="Header Injection"
                  />
                  <FormControlLabel
                    control={<Switch checked={enableOpenRedirect} onChange={(e) => setEnableOpenRedirect(e.target.checked)} />}
                    label="Open Redirect"
                  />
                </Stack>
              </Paper>

              <Stack spacing={1.5}>
                <Paper variant="outlined" sx={{ p: 1.25 }}>
                  <Typography sx={{ fontSize: 12, fontWeight: 700, mb: 0.5 }}>Kontrola dostępu i operacyjne</Typography>
                  <Stack spacing={0.25}>
                    <FormControlLabel control={<Switch checked={enableAuth} onChange={(e) => setEnableAuth(e.target.checked)} />} label="AUTH" />
                    <FormControlLabel
                      control={<Switch checked={enableRateLimit} onChange={(e) => setEnableRateLimit(e.target.checked)} />}
                      label="Limit zapytań"
                    />
                  </Stack>
                </Paper>

                <Paper variant="outlined" sx={{ p: 1.25 }}>
                  <Typography sx={{ fontSize: 12, fontWeight: 700, mb: 0.5 }}>Testy jakości i odporności</Typography>
                  <Stack spacing={0.25}>
                    <FormControlLabel control={<Switch checked={enableFuzz} onChange={(e) => setEnableFuzz(e.target.checked)} />} label="FUZZ" />
                  </Stack>
                </Paper>
              </Stack>
            </Box>
            {errors.enabledTests ? <Typography sx={{ fontSize: 12, color: "#C03434" }}>{errors.enabledTests}</Typography> : null}

            <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
              <FormControl fullWidth>
                <InputLabel id="volume-label">Intensywność</InputLabel>
                <Select
                  labelId="volume-label"
                  label="Intensywność"
                  value={testVolume}
                  onChange={(e) => setTestVolume(e.target.value as "low" | "medium" | "high")}
                >
                  <MenuItem value="low">Niska</MenuItem>
                  <MenuItem value="medium">Średnia</MenuItem>
                  <MenuItem value="high">Wysoka</MenuItem>
                </Select>
              </FormControl>

              <FormControl fullWidth>
                <InputLabel id="validation-label">Walidacja odpowiedzi</InputLabel>
                <Select
                  labelId="validation-label"
                  label="Walidacja odpowiedzi"
                  value={validationMode}
                  onChange={(e) => setValidationMode(e.target.value as "off" | "warn" | "strict")}
                >
                  <MenuItem value="off">Wyłączona</MenuItem>
                  <MenuItem value="warn">Ostrzeżenia</MenuItem>
                  <MenuItem value="strict">Ścisła</MenuItem>
                </Select>
              </FormControl>
            </Stack>

            <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
              <TextField label="Głębokość fuzzingu (1-5)" value={fuzzDepth} onChange={(e) => setFuzzDepth(e.target.value)} fullWidth />
              <TextField label="Limit pól body (1-12)" value={bodyFieldLimit} onChange={(e) => setBodyFieldLimit(e.target.value)} fullWidth />
            </Stack>

            <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
              <FormControl fullWidth>
                <InputLabel id="throttle-mode-label">Limit zapytań</InputLabel>
                <Select
                  labelId="throttle-mode-label"
                  label="Limit zapytań"
                  value={throttleMode}
                  onChange={(e) => setThrottleMode(e.target.value as "none" | "rps" | "delay")}
                >
                  <MenuItem value="none">Brak</MenuItem>
                  <MenuItem value="rps">Limit RPS</MenuItem>
                  <MenuItem value="delay">Opóźnienie (ms)</MenuItem>
                </Select>
              </FormControl>
              <TextField
                label={throttleMode === "rps" ? "Żądania / sekunda" : "Opóźnienie (ms)"}
                value={throttleValue}
                onChange={(e) => setThrottleValue(e.target.value)}
                disabled={throttleMode === "none"}
                error={!!errors.throttleValue}
                helperText={errors.throttleValue}
                fullWidth
              />
            </Stack>
          </Stack>
        </AccordionDetails>
      </Accordion>

    </Stack>
  );
}

type StepReviewProps = {
  baseUrl: string;
  authType: AuthType;
  profile: ProfileType;
  seedMode: boolean;
  enabledSeeds: number;
  summary: OpenApiSummary;
  preview: PreviewCounts | null;
  previewing: boolean;
  enableSql: boolean;
  enableXss: boolean;
  enablePathTraversal: boolean;
  enableTemplateInjection: boolean;
  enableSsrf: boolean;
  enableHeaderInjection: boolean;
  enableOpenRedirect: boolean;
  enableFuzz: boolean;
  enableAuth: boolean;
  enableRateLimit: boolean;
  authorizedScanConsent: boolean;
  setAuthorizedScanConsent: (value: boolean) => void;
};

function StepReview(props: StepReviewProps) {
  const {
    baseUrl,
    authType,
    profile,
    seedMode,
    enabledSeeds,
    summary,
    preview,
    previewing,
    enableSql,
    enableXss,
    enablePathTraversal,
    enableTemplateInjection,
    enableSsrf,
    enableHeaderInjection,
    enableOpenRedirect,
    enableFuzz,
    enableAuth,
    enableRateLimit,
    authorizedScanConsent,
    setAuthorizedScanConsent
  } = props;
  const risk = getScanRunRiskAssessment(baseUrl, profile);

  return (
    <Stack spacing={2}>
      <TitleWithTooltip title="Krok 5: Przegląd i uruchomienie" tooltip="Sprawdź podsumowanie i uruchom skanowanie." />

      <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
        <Stack spacing={1.5}>
          <Typography sx={{ fontWeight: 600 }}>Ocena bezpieczeństwa uruchomienia skanu</Typography>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ xs: "flex-start", sm: "center" }}>
            <Chip
              label={risk.label}
              color={risk.color}
              sx={{
                fontWeight: 700,
                fontSize: 14,
                height: 32,
                "& .MuiChip-label": { px: 1.5 }
              }}
            />
            <Typography sx={{ fontSize: 14 }}>
              Host: <strong>{risk.hostname}</strong>
            </Typography>
            <Typography sx={{ fontSize: 14 }}>
              Profil: <strong>{formatProfile(profile)}</strong>
            </Typography>
          </Stack>
          <Typography sx={{ fontSize: 13, color: "text.secondary" }}>{risk.description}</Typography>
          <Alert severity="info" variant="outlined" sx={{ py: 0.5 }}>
            Zalecane jest użycie loklnego środowiska testowego.
          </Alert>
        </Stack>
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography sx={{ fontWeight: 600 }}>Możliwy wpływ skanowania</Typography>
        <Divider sx={{ my: 1 }} />
        <Box component="ul" sx={{ m: 0, pl: 2.25 }}>
          <Typography component="li" sx={{ fontSize: 13, mb: 0.5 }}>
            błędy 4xx/5xx
          </Typography>
          <Typography component="li" sx={{ fontSize: 13, mb: 0.5 }}>
            tworzenie danych
          </Typography>
          <Typography component="li" sx={{ fontSize: 13 }}>
            blokady rate limit / WAF
          </Typography>
        </Box>
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography sx={{ fontWeight: 600 }}>Podsumowanie konfiguracji</Typography>
        <Divider sx={{ my: 1 }} />
        <Stack spacing={0.75}>
          <Typography sx={{ fontSize: 13 }}>API: {baseUrl}</Typography>
          <Typography sx={{ fontSize: 13 }}>Źródło OpenAPI: wgrany plik</Typography>
          <Typography sx={{ fontSize: 13 }}>Uwierzytelnianie: {formatAuthType(authType)}</Typography>
          <Typography sx={{ fontSize: 13 }}>Profil testów bezpieczeństwa: {formatProfile(profile)}</Typography>
          <Typography sx={{ fontSize: 13 }}>
            Seedowanie: {seedMode ? `włączone (${enabledSeeds})` : "wyłączone"}
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            {enableSql ? <Chip size="small" label="SQLi" /> : null}
            {enableXss ? <Chip size="small" label="XSS" /> : null}
            {enablePathTraversal ? <Chip size="small" label="LFI/PT" /> : null}
            {enableTemplateInjection ? <Chip size="small" label="SSTI" /> : null}
            {enableSsrf ? <Chip size="small" label="SSRF" /> : null}
            {enableHeaderInjection ? <Chip size="small" label="CRLF Injection" /> : null}
            {enableOpenRedirect ? <Chip size="small" label="OR" /> : null}
            {enableFuzz ? <Chip size="small" label="IV" /> : null}
            {enableAuth ? <Chip size="small" label="BAC" /> : null}
            {enableRateLimit ? <Chip size="small" label="RLB" /> : null}
          </Stack>
        </Stack>
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography sx={{ fontWeight: 600 }}>Podsumowanie specyfikacji i testów</Typography>
        <Divider sx={{ my: 1 }} />
        <Stack spacing={0.5}>
          <Typography sx={{ fontSize: 13 }}>Endpointy (OpenAPI): {summary.endpoints}</Typography>
          <Typography sx={{ fontSize: 13 }}>Metody (OpenAPI): {summary.methods}</Typography>
          <Typography sx={{ fontSize: 13 }}>Parametry (OpenAPI): {summary.params}</Typography>
        </Stack>

        <Divider sx={{ my: 1.25 }} />

        {preview ? (
          <Stack spacing={0.5}>
            <Typography sx={{ fontSize: 13 }}>
              Estymacja: {preview.endpoints} | SQLi: {preview.sql} | XSS: {preview.xss} | SSRF: {preview.ssrf ?? 0} |
              {" "}LFI/PT: {preview.pathTraversal ?? 0} | CRLF Injection: {preview.headerInjection ?? 0}
            </Typography>
            <Typography sx={{ fontSize: 13 }}>
              SSTI: {preview.templateInjection ?? 0} | OR: {preview.openRedirect ?? 0} | IV: {preview.fuzz} | BAC:{" "}
              {preview.auth} | RLB: {preview.rateLimit} | Liczba żądań: {preview.total}
            </Typography>
          </Stack>
        ) : (
          <Typography sx={{ fontSize: 13, color: "text.secondary" }}>
            {previewing
              ? "Aktualizowanie podsumowania testów..."
              : "Podsumowanie testów pojawi się po wyliczeniu estymacji na podstawie bieżącej konfiguracji."}
          </Typography>
        )}
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Stack spacing={1.25}>
          <Alert severity="warning" variant="outlined">
            Skaner będzie aktywnie wysyłać zmodyfikowane oraz złośliwe żądania testowe do docelowego API w celu wykrycia podatności. Uruchamiaj skanowanie wyłącznie wobec systemów, do których testowania masz uprawnienia.
          </Alert>

          <FormControlLabel
            sx={{
              m: 0,
              width: "100%",
              alignItems: "center",
              gap: 0.5,
              "& .MuiFormControlLabel-label": {
                fontSize: 13,
                lineHeight: 1.35
              }
            }}
            control={
              <Checkbox
                checked={authorizedScanConsent}
                onChange={(e) => setAuthorizedScanConsent(e.target.checked)}
                inputProps={{
                  "aria-label": "Potwierdzam zgodę na przeprowadzanie testów bezpieczeństwa"
                }}
              />
            }
            label="Potwierdzam, że mam zgodę na przeprowadzanie testów bezpieczeństwa na tym systemie."
          />
        </Stack>
      </Paper>
    </Stack>
  );
}

type StepSeedingProps = {
  baseUrl: string;
  setBaseUrl: (value: string) => void;
  seedMode: boolean;
  setSeedMode: (value: boolean) => void;
  seedConfig: SeedCandidate[];
  setSeedConfig: (value: SeedCandidate[]) => void;
  loadingSeeds: boolean;
  onReloadSeeds: () => Promise<void>;
  errors: StepErrors;
};

function StepSeeding(props: StepSeedingProps) {
  const { baseUrl, setBaseUrl, seedMode, setSeedMode, seedConfig, setSeedConfig, loadingSeeds, onReloadSeeds, errors } = props;
  const enabledCount = seedConfig.filter((s) => s.enabled).length;
  const [activeTabById, setActiveTabById] = useState<Record<string, number>>({});
  const [jsonStateById, setJsonStateById] = useState<Record<string, { kind: "ok" | "error"; message: string }>>({});

  function updateSeed(id: string, updater: (seed: SeedCandidate) => SeedCandidate) {
    setSeedConfig(seedConfig.map((item) => (item.id === id ? updater(item) : item)));
  }

  function parseParamPairs(text: string) {
    if (!text.trim()) return [] as { key: string; value: string }[];
    const out: { key: string; value: string }[] = [];
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [key, ...rest] = trimmed.split("=");
      out.push({ key: key?.trim() ?? "", value: rest.join("=").trim() });
    }
    return out;
  }

  function toParamText(pairs: { key: string; value: string }[]) {
    return pairs
      .map((pair) => `${pair.key.trim()}=${pair.value}`)
      .join("\n");
  }

  function hasContentTypeHeader(seed: SeedCandidate) {
    return (seed.headerPairs ?? []).some((h) => h.key.trim().toLowerCase() === "content-type");
  }

  function buildCombinedUrl(seedPath: string) {
    const b = baseUrl.trim();
    const p = seedPath.trim();
    if (!b) return p;
    if (!p) return b;
    if (/^https?:\/\//i.test(p)) return p;
    return `${b.replace(/\/+$/, "")}/${p.replace(/^\/+/, "")}`;
  }

  function applyCombinedUrl(seed: SeedCandidate, value: string) {
    const raw = value.trim();
    if (!raw) {
      updateSeed(seed.id, (item) => ({ ...item, path: "" }));
      return;
    }

    if (baseUrl.trim() && raw.startsWith(baseUrl.trim())) {
      const rest = raw.slice(baseUrl.trim().length).trim();
      updateSeed(seed.id, (item) => ({ ...item, path: rest || "/" }));
      return;
    }

    if (/^https?:\/\//i.test(raw)) {
      try {
        const u = new URL(raw);
        setBaseUrl(`${u.protocol}//${u.host}`);
        updateSeed(seed.id, (item) => ({ ...item, path: `${u.pathname}${u.search}` || "/" }));
        return;
      } catch {
        updateSeed(seed.id, (item) => ({ ...item, path: raw }));
        return;
      }
    }

    updateSeed(seed.id, (item) => ({ ...item, path: raw }));
  }

  function suggestedContentType(seed: SeedCandidate) {
    if (seed.inputMode === "json") return "application/json";
    if (seed.inputMode === "form") return "application/x-www-form-urlencoded";
    if (seed.inputMode === "multipart") return "multipart/form-data";
    if (seed.inputMode === "binary") return "application/octet-stream";
    return "";
  }

  function formatJsonForSeed(seed: SeedCandidate) {
    try {
      const parsed = JSON.parse(seed.payloadText ?? "");
      const formatted = JSON.stringify(parsed, null, 2);
      updateSeed(seed.id, (s) => ({ ...s, payloadText: formatted }));
      setJsonStateById((prev) => ({ ...prev, [seed.id]: { kind: "ok", message: "JSON został sformatowany." } }));
    } catch {
      setJsonStateById((prev) => ({ ...prev, [seed.id]: { kind: "error", message: "Nieprawidłowy JSON." } }));
    }
  }

  function validateJsonForSeed(seed: SeedCandidate) {
    try {
      JSON.parse(seed.payloadText ?? "");
      setJsonStateById((prev) => ({ ...prev, [seed.id]: { kind: "ok", message: "JSON jest poprawny." } }));
    } catch {
      setJsonStateById((prev) => ({ ...prev, [seed.id]: { kind: "error", message: "Nieprawidłowy JSON." } }));
    }
  }

  return (
    <Stack spacing={2}>
      <TitleWithTooltip
        title="Krok 4: Seedowanie"
        tooltip="Utwórz dane testowe przed skanowaniem."
      />

      <FormControlLabel
        control={<Switch checked={seedMode} onChange={(e) => setSeedMode(e.target.checked)} />}
        label="Włącz seedowanie"
      />

      {seedMode ? (
        <Stack spacing={1.5}>
          <Stack direction="row" spacing={1.5} alignItems="center">
            <Button variant="outlined" onClick={onReloadSeeds} disabled={loadingSeeds}>
              {loadingSeeds ? "Wczytywanie..." : "Resetuj ustawienia"}
            </Button>
            <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
              Włączone: {enabledCount} / {seedConfig.length}
            </Typography>
          </Stack>

          {seedConfig.length === 0 ? (
            <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
              Brak endpointów seedowania. Najpierw wgraj plik OpenAPI lub odśwież listę.
            </Typography>
          ) : null}

          {seedConfig.map((s) => {
            const paramsPairs = parseParamPairs(s.paramsText ?? "");
            const nonEmptyParamsCount = paramsPairs.filter((pair) => pair.key.trim() || pair.value.trim()).length;
            const nonEmptyHeadersCount = (s.headerPairs ?? []).filter((h) => h.key.trim() || h.value.trim()).length;

            return (
              <Paper key={s.id} variant="outlined" sx={{ p: 1.25 }}>
                <Stack spacing={1}>
                  <FormControlLabel
                    sx={{ m: 0 }}
                    control={
                      <Switch
                        checked={s.enabled}
                        onChange={(e) => updateSeed(s.id, (item) => ({ ...item, enabled: e.target.checked }))}
                        inputProps={{ "aria-label": "Aktywne" }}
                      />
                    }
                    label="Aktywne"
                  />

                  <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "center" }}>
                    <FormControl size="small" sx={{ minWidth: 110 }}>
                      <InputLabel id={`seed-method-${s.id}`}>Metoda</InputLabel>
                      <Select
                        labelId={`seed-method-${s.id}`}
                        label="Metoda"
                        value={s.method.toUpperCase()}
                        onChange={(e) => updateSeed(s.id, (item) => ({ ...item, method: String(e.target.value).toUpperCase() }))}
                      >
                        <MenuItem value="GET">GET</MenuItem>
                        <MenuItem value="POST">POST</MenuItem>
                        <MenuItem value="PUT">PUT</MenuItem>
                        <MenuItem value="PATCH">PATCH</MenuItem>
                        <MenuItem value="DELETE">DELETE</MenuItem>
                      </Select>
                    </FormControl>
                    <TextField
                      placeholder="https://api.example.com/resource/path"
                      value={buildCombinedUrl(s.path)}
                      onChange={(e) => applyCombinedUrl(s, e.target.value)}
                      fullWidth
                      size="small"
                    />
                  </Stack>

                  <Tabs
                    value={activeTabById[s.id] ?? 0}
                    onChange={(_, value) => setActiveTabById((prev) => ({ ...prev, [s.id]: value }))}
                    variant="scrollable"
                    scrollButtons="auto"
                  >
                    <Tab label={`Parametry (${nonEmptyParamsCount})`} />
                    <Tab label={`Nagłówki (${nonEmptyHeadersCount})`} />
                    <Tab label="Body" />
                  </Tabs>

                  {(activeTabById[s.id] ?? 0) === 0 ? (
                    <Stack spacing={1}>
                      {paramsPairs.map((pair, idx) => (
                        <Stack key={`${s.id}-param-${idx}`} direction={{ xs: "column", sm: "row" }} spacing={1}>
                          <TextField
                            label="Parametr"
                            value={pair.key}
                            onChange={(e) =>
                              updateSeed(s.id, (item) => {
                                const next = parseParamPairs(item.paramsText ?? "");
                                next[idx] = { ...next[idx], key: e.target.value };
                                return { ...item, paramsText: toParamText(next) };
                              })
                            }
                            fullWidth
                            size="small"
                          />
                          <TextField
                            label="Wartość"
                            value={pair.value}
                            onChange={(e) =>
                              updateSeed(s.id, (item) => {
                                const next = parseParamPairs(item.paramsText ?? "");
                                next[idx] = { ...next[idx], value: e.target.value };
                                return { ...item, paramsText: toParamText(next) };
                              })
                            }
                            fullWidth
                            size="small"
                          />
                          <Button
                            variant="outlined"
                            size="small"
                            onClick={() =>
                              updateSeed(s.id, (item) => {
                                const next = parseParamPairs(item.paramsText ?? "").filter((_, i) => i !== idx);
                                return { ...item, paramsText: toParamText(next) };
                              })
                            }
                          >
                            Usuń
                          </Button>
                        </Stack>
                      ))}
                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() =>
                          updateSeed(s.id, (item) => {
                            const next = [...parseParamPairs(item.paramsText ?? ""), { key: "", value: "" }];
                            return { ...item, paramsText: toParamText(next) };
                          })
                        }
                        sx={{ alignSelf: "flex-start", textTransform: "none" }}
                      >
                        + Dodaj
                      </Button>
                    </Stack>
                  ) : null}

                  {(activeTabById[s.id] ?? 0) === 1 ? (
                    <Stack spacing={1}>
                      {(s.headerPairs ?? []).map((h, idx) => (
                        <Stack key={`${s.id}-header-${idx}`} direction={{ xs: "column", sm: "row" }} spacing={1}>
                          <TextField
                            label="Nagłówek"
                            value={h.key}
                            onChange={(e) =>
                              updateSeed(s.id, (item) => ({
                                ...item,
                                headerPairs: (item.headerPairs ?? []).map((entry, i) =>
                                  i === idx ? { ...entry, key: e.target.value } : entry
                                )
                              }))
                            }
                            fullWidth
                            size="small"
                          />
                          <TextField
                            label="Wartość"
                            value={h.value}
                            onChange={(e) =>
                              updateSeed(s.id, (item) => ({
                                ...item,
                                headerPairs: (item.headerPairs ?? []).map((entry, i) =>
                                  i === idx ? { ...entry, value: e.target.value } : entry
                                )
                              }))
                            }
                            fullWidth
                            size="small"
                          />
                          <Button
                            variant="outlined"
                            size="small"
                            onClick={() =>
                              updateSeed(s.id, (item) => ({
                                ...item,
                                headerPairs: (item.headerPairs ?? []).filter((_, i) => i !== idx)
                              }))
                            }
                          >
                            Usuń
                          </Button>
                        </Stack>
                      ))}

                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() =>
                          updateSeed(s.id, (item) => ({
                            ...item,
                            headerPairs: [...(item.headerPairs ?? []), { key: "", value: "" }]
                          }))
                        }
                        sx={{
                          alignSelf: "flex-start",
                          px: 1.25,
                          py: 0.25,
                          minHeight: 28,
                          fontSize: 12,
                          textTransform: "none"
                        }}
                      >
                        + Dodaj
                      </Button>
                    </Stack>
                  ) : null}

                  {(activeTabById[s.id] ?? 0) === 2 ? (
                  <Stack spacing={1}>
                    <FormControl size="small" sx={{ maxWidth: 260 }}>
                      <InputLabel id={`seed-body-mode-${s.id}`}>Typ body</InputLabel>
                      <Select
                        labelId={`seed-body-mode-${s.id}`}
                        label="Typ body"
                        value={s.inputMode}
                        onChange={(e) => updateSeed(s.id, (item) => ({ ...item, inputMode: e.target.value as SeedCandidate["inputMode"] }))}
                      >
                        <MenuItem value="none">Brak</MenuItem>
                        <MenuItem value="json">JSON</MenuItem>
                        <MenuItem value="multipart">Form-data</MenuItem>
                        <MenuItem value="form">x-www-form-urlencoded</MenuItem>
                      </Select>
                    </FormControl>

                    {s.inputMode === "json" ? (
                      <Stack direction="row" spacing={1}>
                        <Button size="small" variant="outlined" onClick={() => formatJsonForSeed(s)}>
                          Sformatuj
                        </Button>
                        <Button size="small" variant="outlined" onClick={() => validateJsonForSeed(s)}>
                          Waliduj JSON
                        </Button>
                      </Stack>
                    ) : null}

                    <TextField
                      label="Ciało żądania (body)"
                      value={s.payloadText ?? ""}
                      onChange={(e) => updateSeed(s.id, (item) => ({ ...item, payloadText: e.target.value }))}
                      placeholder={
                        s.inputMode === "json"
                          ? '{\n  "name": "test"\n}'
                          : s.inputMode === "binary"
                          ? "wklej surową treść"
                          : s.inputMode === "none"
                          ? ""
                          : "key=value"
                      }
                      disabled={s.inputMode === "none"}
                      multiline
                      minRows={4}
                      fullWidth
                      sx={{ "& .MuiInputBase-inputMultiline": { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" } }}
                    />

                    {jsonStateById[s.id] ? (
                      <Typography
                        sx={{
                          fontSize: 12,
                          color: jsonStateById[s.id].kind === "ok" ? "success.main" : "error.main"
                        }}
                      >
                        {jsonStateById[s.id].message}
                      </Typography>
                    ) : null}

                    {s.inputMode !== "none" && !hasContentTypeHeader(s) ? (
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
                          Sugestia: dodaj `Content-Type: {suggestedContentType(s)}`.
                        </Typography>
                        <Button
                          size="small"
                          variant="text"
                          onClick={() =>
                            updateSeed(s.id, (item) => ({
                              ...item,
                              headerPairs: [...(item.headerPairs ?? []), { key: "Content-Type", value: suggestedContentType(item) }]
                            }))
                          }
                        >
                          Dodaj
                        </Button>
                      </Stack>
                    ) : null}
                  </Stack>
                ) : null}

              </Stack>
            </Paper>
            );
          })}

          {errors.seed ? <Typography sx={{ fontSize: 12, color: "#C03434" }}>{errors.seed}</Typography> : null}
        </Stack>
      ) : (
        <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
          Seedowanie wyłączone. Skaner uruchomi skanowanie bez przygotowania danych testowych.
        </Typography>
      )}
    </Stack>
  );
}

function parseOpenApiSummary(openApiText: string): OpenApiSummary {
  const fallback = parseOpenApiSummaryByText(openApiText);
  if (!openApiText.trim()) return fallback;

  try {
    const spec = JSON.parse(openApiText);
    const paths = spec?.paths && typeof spec.paths === "object" ? spec.paths : {};
    const pathEntries = Object.entries(paths);
    const endpointCount = pathEntries.length;
    const methodSet = new Set<string>();
    let params = 0;
    const knownMethods = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);

    for (const [, pathDef] of pathEntries) {
      if (!pathDef || typeof pathDef !== "object") continue;
      const pathObj = pathDef as Record<string, any>;
      if (Array.isArray(pathObj.parameters)) params += pathObj.parameters.length;
      for (const [k, v] of Object.entries(pathObj)) {
        if (!knownMethods.has(k.toLowerCase())) continue;
        methodSet.add(k.toUpperCase());
        if (v && typeof v === "object" && Array.isArray((v as any).parameters)) {
          params += (v as any).parameters.length;
        }
      }
    }
    return { endpoints: endpointCount, methods: methodSet.size, params };
  } catch {
    return fallback;
  }
}

function parseOpenApiSummaryByText(openApiText: string): OpenApiSummary {
  if (!openApiText.trim()) return { endpoints: 0, methods: 0, params: 0 };
  const endpointSet = new Set<string>();
  const methodSet = new Set<string>();
  let params = 0;
  const lines = openApiText.split("\n");

  for (const line of lines) {
    const endpointMatch = line.match(/^\s*\/[^:\s]+.*:\s*$/);
    if (endpointMatch) endpointSet.add(endpointMatch[0].trim());
    const methodMatch = line.match(/^\s*(get|post|put|patch|delete|head|options):\s*$/i);
    if (methodMatch) methodSet.add(methodMatch[1].toUpperCase());
    if (/\bin:\s*(query|path|header|cookie)\b/i.test(line)) params += 1;
  }
  return {
    endpoints: endpointSet.size,
    methods: methodSet.size,
    params
  };
}

async function safeJson(res: Response) {
  const contentType = res.headers.get("content-type") ?? "";
  const text = await res.text();
  if (!text.trim()) return {};
  if (!contentType.includes("application/json")) {
    return { error: `Nieprawidłowa odpowiedź z API (status ${res.status}).` };
  }
  try {
    return JSON.parse(text);
  } catch {
    if (res.status === 413) {
      return { error: "Niepoprawny plik OpenAPI." };
    }
    return { error: `Nieprawidłowa odpowiedź z API (status ${res.status}).` };
  }
}
