import type { EndpointDetail } from "../../openapi";

export type TemplateInjectionTest = {
  method: string;
  path: string;
  payload: string;
  location: "body" | "query" | "path" | "header" | "cookie";
  body?: any;
  query?: Record<string, string>;
  originalPath?: string;
  headers?: Record<string, string>;
  contentType?: string;
  expectedResponseSchema?: any;
};

const SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"];
const TEMPLATE_LIKE_PARAM = /(template|tpl|view|render|name|message|input|text|body|content)/i;

export function generateTemplateInjectionTests(
  endpoints: EndpointDetail[],
  opts?: { maxPayloads?: number; maxBodyFields?: number; maxParamPayloads?: number }
): TemplateInjectionTest[] {
  const tests: TemplateInjectionTest[] = [];
  const maxPayloads = opts?.maxPayloads ?? 3;
  const maxBodyFields = opts?.maxBodyFields ?? 6;
  const maxParamPayloads = opts?.maxParamPayloads ?? 3;
  const payloads = SSTI_PAYLOADS.slice(0, maxPayloads);

  for (const ep of endpoints) {
    if (!["GET", "POST", "PUT", "PATCH"].includes(ep.method)) continue;
    const base = buildBaseRequest(ep);
    const allowBody = ["POST", "PUT", "PATCH"].includes(ep.method);

    const bodyPaths = findStringPaths(base.body)
      .filter((p) => TEMPLATE_LIKE_PARAM.test(p))
      .slice(0, maxBodyFields);
    if (allowBody && base.body && bodyPaths.length) {
      for (const path of bodyPaths) {
        for (const payload of payloads) {
          const body = cloneJson(base.body);
          setValueAtPath(body, path, payload);
          tests.push({
            method: ep.method,
            path: base.resolvedPath,
            originalPath: ep.path,
            payload,
            location: "body",
            body,
            query: base.query,
            headers: base.headers,
            contentType: base.contentType,
            expectedResponseSchema: ep.responseBodySchema
          });
        }
      }
    }

    for (const param of base.queryParams.filter((p) => TEMPLATE_LIKE_PARAM.test(p))) {
      for (const payload of payloads.slice(0, maxParamPayloads)) {
        tests.push({
          method: ep.method,
          path: base.resolvedPath,
          originalPath: ep.path,
          payload,
          location: "query",
          body: allowBody ? base.body : undefined,
          query: { ...base.query, [param]: payload },
          headers: base.headers,
          contentType: base.contentType,
          expectedResponseSchema: ep.responseBodySchema
        });
      }
    }

    for (const param of base.pathParams.filter((p) => TEMPLATE_LIKE_PARAM.test(p))) {
      for (const payload of payloads.slice(0, maxParamPayloads)) {
        tests.push({
          method: ep.method,
          path: resolvePathParam(ep.path, param, payload),
          originalPath: ep.path,
          payload,
          location: "path",
          body: allowBody ? base.body : undefined,
          query: base.query,
          headers: base.headers,
          contentType: base.contentType,
          expectedResponseSchema: ep.responseBodySchema
        });
      }
    }

    for (const param of base.headerParams.filter((p) => TEMPLATE_LIKE_PARAM.test(p))) {
      for (const payload of payloads.slice(0, maxParamPayloads)) {
        tests.push({
          method: ep.method,
          path: base.resolvedPath,
          originalPath: ep.path,
          payload,
          location: "header",
          body: allowBody ? base.body : undefined,
          query: base.query,
          headers: { ...base.headers, [param]: payload },
          contentType: base.contentType,
          expectedResponseSchema: ep.responseBodySchema
        });
      }
    }

    for (const param of base.cookieParams.filter((p) => TEMPLATE_LIKE_PARAM.test(p))) {
      for (const payload of payloads.slice(0, maxParamPayloads)) {
        tests.push({
          method: ep.method,
          path: base.resolvedPath,
          originalPath: ep.path,
          payload,
          location: "cookie",
          body: allowBody ? base.body : undefined,
          query: base.query,
          headers: mergeCookieHeader(base.headers, param, payload),
          contentType: base.contentType,
          expectedResponseSchema: ep.responseBodySchema
        });
      }
    }
  }

  return tests;
}

type BaseRequest = {
  body?: any;
  query: Record<string, string>;
  queryParams: string[];
  pathParams: string[];
  headerParams: string[];
  cookieParams: string[];
  resolvedPath: string;
  headers?: Record<string, string>;
  contentType?: string;
};

function buildBaseRequest(ep: EndpointDetail): BaseRequest {
  const body = ep.requestBodySchema ? buildExampleFromSchema(ep.requestBodySchema, 0) : undefined;
  const contentType = pickContentType(ep.requestBodyContentTypes);
  const query: Record<string, string> = {};
  const queryParams: string[] = [];
  const pathParams: string[] = [];
  const headerParams: string[] = [];
  const cookieParams: string[] = [];
  const headers: Record<string, string> = {};
  const cookies: Record<string, string> = {};

  for (const p of ep.parameters ?? []) {
    if (p.in === "query") {
      queryParams.push(p.name);
      query[p.name] = exampleValue(p) ?? "test";
    }
    if (p.in === "path") pathParams.push(p.name);
    if (p.in === "header") {
      headerParams.push(p.name);
      headers[p.name] = exampleValue(p) ?? "test";
    }
    if (p.in === "cookie") {
      cookieParams.push(p.name);
      cookies[p.name] = exampleValue(p) ?? "test";
    }
  }

  const resolvedPath = resolvePath(ep.path, ep.parameters);
  const cookieHeader = buildCookieHeader(cookies);
  if (cookieHeader) headers.Cookie = cookieHeader;
  return { body, query, queryParams, pathParams, headerParams, cookieParams, resolvedPath, headers, contentType };
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
  return path.replace(`{${param}}`, encodeURIComponent(payload));
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

function pickContentType(types?: string[]) {
  if (!types || !types.length) return "application/json";
  if (types.includes("application/json")) return "application/json";
  if (types.includes("application/x-www-form-urlencoded")) return "application/x-www-form-urlencoded";
  return types[0];
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
  if (type === "string") return "test";
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

function findStringPaths(obj: any, prefix = ""): string[] {
  if (obj == null) return [];
  if (typeof obj === "string") return [prefix];
  if (Array.isArray(obj)) {
    const out: string[] = [];
    for (let i = 0; i < obj.length; i++) out.push(...findStringPaths(obj[i], `${prefix}[${i}]`));
    return out;
  }
  if (typeof obj === "object") {
    const out: string[] = [];
    for (const key of Object.keys(obj)) {
      const next = prefix ? `${prefix}.${key}` : key;
      out.push(...findStringPaths(obj[key], next));
    }
    return out;
  }
  return [];
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

function cloneJson<T>(v: T): T {
  return v == null ? v : JSON.parse(JSON.stringify(v));
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

