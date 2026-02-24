import YAML from "yaml";

type InputMode = "none" | "json" | "form" | "multipart";

export type SeedCandidate = {
  enabled: boolean;
  method: string;
  path: string;
  inputMode: InputMode;
  contentType?: string;
  accept?: string;
  security?: string[];
  headers?: string[];
  idExtractor?: string | null;
  resourceKey: string;
  confidence: number;
  reason: string;
  requiresFile?: boolean;
  payload?: any;
};

const HTTP_METHODS = new Set([
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "head",
  "options",
  "trace"
]);

const EXCLUDE_KEYWORDS = ["login", "logout", "token", "auth", "health", "metrics", "upload", "download"];
const RESOURCE_PREFIXES = new Set(["api", "v1", "v2", "v3", "v4"]);

export function parseSpecFromText(openApiText: string) {
  if (!openApiText || !openApiText.trim()) return null;
  try {
    return JSON.parse(openApiText);
  } catch {
    return YAML.parse(openApiText);
  }
}

export function generateSeedCandidates(specObj: any): SeedCandidate[] {
  if (!specObj || typeof specObj !== "object") return [];
  const paths = specObj.paths;
  if (!paths || typeof paths !== "object") return [];

  const candidates: SeedCandidate[] = [];

  for (const path of Object.keys(paths)) {
    const pathItem = paths[path];
    if (!pathItem || typeof pathItem !== "object") continue;

    for (const key of Object.keys(pathItem)) {
      const method = key.toLowerCase();
      if (!HTTP_METHODS.has(method)) continue;
      const operation = pathItem[key] ?? {};

      const lowerPath = path.toLowerCase();
      const hasPathParam = path.includes("{");

      let score = 0;
      const reasons: string[] = [];

      if (method === "post") {
        score += 35;
        reasons.push("POST");
        if (!hasPathParam) {
          score += 10;
          reasons.push("kolekcja bez {id}");
        } else {
          score -= 5;
        }
      }
      if (method === "put") {
        score += 25;
        reasons.push("PUT");
        if (hasPathParam) {
          score += 10;
          reasons.push("ścieżka z {id}");
        }
      }
      if (method === "patch") {
        score += 15;
        reasons.push("PATCH");
        if (hasPathParam) score += 5;
      }
      if (method === "get") {
        score -= 25;
        reasons.push("GET");
      }

      if (EXCLUDE_KEYWORDS.some((k) => lowerPath.includes(k))) {
        score -= 40;
        reasons.push("ścieżka utility/auth");
      }

      const { inputMode, contentType, requiresFile } = detectInputMode(specObj, operation);
      if (inputMode === "json") score += 10;
      if (inputMode === "none") score += 5;
      if (inputMode === "multipart" && requiresFile) score -= 5;

      const accept = detectAccept(specObj, operation);
      const idInfo = detectIdExtractor(specObj, operation);
      if (idInfo?.idExtractor) {
        score += 30;
        reasons.push(idInfo.reason);
      } else {
        score -= 20;
        reasons.push("brak pewnego ID");
      }

      const responses = operation.responses ?? {};
      if (responses["201"] || responses["200"] || responses["202"]) {
        score += 10;
        reasons.push("odpowiedź 2xx");
      }

      const confidence = clamp(score, 0, 100);
      const resourceKey = inferResourceKey(path);
      const { security, headers } = detectSecurity(specObj, operation);

      candidates.push({
        enabled: true,
        method: method.toUpperCase(),
        path,
        inputMode,
        contentType,
        accept,
        security,
        headers,
        idExtractor: idInfo?.idExtractor ?? null,
        resourceKey,
        confidence,
        reason: reasons.join(", "),
        requiresFile
      });
    }
  }

  return candidates.sort((a, b) => b.confidence - a.confidence);
}

function detectInputMode(specObj: any, operation: any) {
  const isOas3 = typeof specObj?.openapi === "string";
  const isSwagger2 = typeof specObj?.swagger === "string";

  if (isOas3) {
    const content = operation?.requestBody?.content;
    if (!content || typeof content !== "object") return { inputMode: "none" as const };
    const types = Object.keys(content);
    if (types.includes("multipart/form-data")) {
      return {
        inputMode: "multipart" as const,
        contentType: "multipart/form-data",
        requiresFile: hasBinary(content)
      };
    }
    if (types.includes("application/x-www-form-urlencoded")) {
      return {
        inputMode: "form" as const,
        contentType: "application/x-www-form-urlencoded"
      };
    }
    if (types.includes("application/json") || types.includes("application/*+json")) {
      return {
        inputMode: "json" as const,
        contentType: "application/json"
      };
    }
    return { inputMode: "json" as const, contentType: types[0] };
  }

  if (isSwagger2) {
    const consumes = Array.isArray(operation?.consumes)
      ? operation.consumes
      : Array.isArray(specObj?.consumes)
      ? specObj.consumes
      : [];
    const params = Array.isArray(operation?.parameters) ? operation.parameters : [];
    const hasForm = params.some((p: any) => p?.in === "formData");
    const hasBody = params.some((p: any) => p?.in === "body");
    if (consumes.includes("multipart/form-data") || (hasForm && consumes.includes("multipart/form-data"))) {
      return {
        inputMode: "multipart" as const,
        contentType: "multipart/form-data",
        requiresFile: hasFileParam(params)
      };
    }
    if (consumes.includes("application/x-www-form-urlencoded") || hasForm) {
      return {
        inputMode: "form" as const,
        contentType: "application/x-www-form-urlencoded"
      };
    }
    if (hasBody) {
      return { inputMode: "json" as const, contentType: "application/json" };
    }
    return { inputMode: "none" as const };
  }

  return { inputMode: "none" as const };
}

function detectAccept(specObj: any, operation: any) {
  const isOas3 = typeof specObj?.openapi === "string";
  const isSwagger2 = typeof specObj?.swagger === "string";
  if (isOas3) {
    const responses = operation?.responses ?? {};
    const codes = Object.keys(responses);
    for (const code of ["201", "200", "202", ...codes]) {
      const content = responses?.[code]?.content;
      if (content && typeof content === "object") {
        const types = Object.keys(content);
        if (types.includes("application/json")) return "application/json";
        return types[0];
      }
    }
  }
  if (isSwagger2) {
    const produces = Array.isArray(operation?.produces)
      ? operation.produces
      : Array.isArray(specObj?.produces)
      ? specObj.produces
      : [];
    if (produces.includes("application/json")) return "application/json";
    return produces[0];
  }
  return undefined;
}

function detectIdExtractor(specObj: any, operation: any) {
  const responses = operation?.responses ?? {};
  const codes = ["201", "200", "202", ...Object.keys(responses)];
  for (const code of codes) {
    const resp = responses[code];
    if (!resp) continue;
    const headers = resp.headers ?? {};
    if (headers.Location || headers.location) {
      return { idExtractor: "header.location", reason: "Location header" };
    }
  }

  const schema = extractResponseSchema(specObj, operation);
  if (schema) {
    const field = findIdField(schema);
    if (field) return { idExtractor: field, reason: "ID w body" };
  }

  return { idExtractor: null, reason: "brak ID" };
}

function extractResponseSchema(specObj: any, operation: any) {
  const isOas3 = typeof specObj?.openapi === "string";
  const isSwagger2 = typeof specObj?.swagger === "string";
  const responses = operation?.responses ?? {};
  const codes = ["201", "200", "202", ...Object.keys(responses)];

  if (isOas3) {
    for (const code of codes) {
      const content = responses?.[code]?.content;
      if (!content || typeof content !== "object") continue;
      const preferred =
        content["application/json"] || content["application/*+json"] || Object.values(content)[0];
      const schema = (preferred as any)?.schema;
      if (schema) return schema;
    }
  }

  if (isSwagger2) {
    for (const code of codes) {
      const schema = responses?.[code]?.schema;
      if (schema) return schema;
    }
  }

  return undefined;
}

function findIdField(schema: any): string | null {
  if (!schema || typeof schema !== "object") return null;
  if (schema.type === "array" && schema.items) {
    const inner = findIdField(schema.items);
    return inner ? `body[0].${inner.replace(/^body\./, "")}` : null;
  }
  const props = schema.properties ?? {};
  const candidates = Object.keys(props).filter((k) => /(^id$|id$|uuid$)/i.test(k));
  if (candidates.length) return `body.${candidates[0]}`;
  return null;
}


function detectSecurity(specObj: any, operation: any) {
  const requirements = Array.isArray(operation?.security)
    ? operation.security
    : Array.isArray(specObj?.security)
    ? specObj.security
    : [];

  const schemes = specObj?.components?.securitySchemes || specObj?.securityDefinitions || {};
  const security: string[] = [];
  const headers: string[] = [];

  for (const req of requirements) {
    if (!req || typeof req !== "object") continue;
    for (const name of Object.keys(req)) {
      const scheme = schemes[name];
      security.push(name);
      if (!scheme) continue;
      if (scheme.type === "apiKey" && scheme.in === "header") {
        headers.push(scheme.name);
      }
      if (scheme.type === "http" && scheme.scheme === "bearer") {
        headers.push("Authorization");
      }
      if (scheme.type === "oauth2") {
        headers.push("Authorization");
      }
    }
  }

  return {
    security: security.length ? security : undefined,
    headers: headers.length ? Array.from(new Set(headers)) : undefined
  };
}

function inferResourceKey(path: string) {
  const parts = path.split("/").filter(Boolean).filter((p) => !p.startsWith("{"));
  const first = parts.find((p) => !RESOURCE_PREFIXES.has(p.toLowerCase()));
  return first ?? parts[0] ?? path.replace(/[\/{}]/g, "");
}

function hasBinary(content: any) {
  for (const key of Object.keys(content)) {
    const schema = content?.[key]?.schema;
    if (schema && schema.type === "string" && schema.format === "binary") return true;
  }
  return false;
}

function hasFileParam(params: any[]) {
  return params.some((p) => p?.type === "file" || p?.format === "binary");
}

function clamp(v: number, min: number, max: number) {
  return Math.max(min, Math.min(max, v));
}
