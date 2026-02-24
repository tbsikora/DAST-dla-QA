import type { EndpointDetail } from "../../openapi";

export type XssTest = {
  method: string;
  path: string;
  payload: string;
  location: "body" | "query" | "path" | "header" | "cookie";
  body?: any;
  query?: Record<string, string>;
  originalPath?: string;
  headers?: Record<string, string>;
  contentType?: string;
  expectedResponseContentTypes?: string[];
  expectedResponseSchema?: any;
};

const XSS_PAYLOADS = [
  `<b>test</b>`,
  `<script>alert(1)</script>`,
  `"><script>alert(1)</script>`,
  `<img src=x onerror=alert(1)>`,
  `'><svg/onload=alert(1)>`,
  `" onmouseover="alert(1)" x="`
];

export function generateXssTests(
  endpoints: EndpointDetail[],
  opts?: { maxPayloads?: number; maxBodyFields?: number; maxParamPayloads?: number }
): XssTest[] {
  const tests: XssTest[] = [];
  const maxPayloads = opts?.maxPayloads ?? XSS_PAYLOADS.length;
  const payloads = XSS_PAYLOADS.slice(0, maxPayloads);
  const maxBodyFields = opts?.maxBodyFields ?? 6;
  const maxParamPayloads = opts?.maxParamPayloads ?? payloads.length;
  const paramPayloads = payloads.slice(0, maxParamPayloads);

  for (const ep of endpoints) {
    if (!["POST", "PUT", "PATCH", "GET", "DELETE"].includes(ep.method)) continue;
    const base = buildBaseRequest(ep);
    const paramTypes = new Map<string, string>();
    for (const p of ep.parameters ?? []) {
      if (p?.name && p?.schema?.type) paramTypes.set(p.name, String(p.schema.type));
    }
    const allowBody = ["POST", "PUT", "PATCH"].includes(ep.method);
    const bodyPaths = findStringPaths(base.body).slice(0, maxBodyFields);

    if (bodyPaths.length && base.body && allowBody) {
      for (const payload of payloads) {
        for (const path of bodyPaths) {
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
            expectedResponseContentTypes: ep.responseContentTypes,
            expectedResponseSchema: ep.responseBodySchema
          });
        }
      }
    }

    for (const param of base.queryParams) {
      const type = paramTypes.get(param);
      if (type && type !== "string") continue;
      for (const paramPayload of paramPayloads) {
        tests.push({
          method: ep.method,
          path: base.resolvedPath,
          originalPath: ep.path,
          payload: paramPayload,
          location: "query",
          body: allowBody ? base.body : undefined,
          query: { ...base.query, [param]: paramPayload },
          headers: base.headers,
          contentType: base.contentType,
          expectedResponseContentTypes: ep.responseContentTypes,
          expectedResponseSchema: ep.responseBodySchema
        });
      }
    }

    for (const param of base.pathParams) {
      const type = paramTypes.get(param);
      if (type && type !== "string") continue;
      for (const paramPayload of paramPayloads) {
        const resolved = resolvePathParam(ep.path, param, paramPayload);
        tests.push({
          method: ep.method,
          path: resolved,
          originalPath: ep.path,
          payload: paramPayload,
          location: "path",
          body: allowBody ? base.body : undefined,
          query: base.query,
          headers: base.headers,
          contentType: base.contentType,
          expectedResponseContentTypes: ep.responseContentTypes,
          expectedResponseSchema: ep.responseBodySchema
        });
      }
    }

    for (const param of base.headerParams) {
      const type = paramTypes.get(param);
      if (type && type !== "string") continue;
      for (const paramPayload of paramPayloads) {
        tests.push({
          method: ep.method,
          path: base.resolvedPath,
          originalPath: ep.path,
          payload: paramPayload,
          location: "header",
          body: allowBody ? base.body : undefined,
          query: base.query,
          headers: { ...base.headers, [param]: paramPayload },
          contentType: base.contentType,
          expectedResponseContentTypes: ep.responseContentTypes,
          expectedResponseSchema: ep.responseBodySchema
        });
      }
    }

    for (const param of base.cookieParams) {
      const type = paramTypes.get(param);
      if (type && type !== "string") continue;
      for (const paramPayload of paramPayloads) {
        tests.push({
          method: ep.method,
          path: base.resolvedPath,
          originalPath: ep.path,
          payload: paramPayload,
          location: "cookie",
          body: allowBody ? base.body : undefined,
          query: base.query,
          headers: mergeCookieHeader(base.headers, param, paramPayload),
          contentType: base.contentType,
          expectedResponseContentTypes: ep.responseContentTypes,
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
    if (p.in === "path") {
      pathParams.push(p.name);
    }
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
  return {
    body,
    query,
    queryParams,
    pathParams,
    headerParams,
    cookieParams,
    resolvedPath,
    headers,
    contentType
  };
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

function findStringPaths(obj: any, prefix = ""): string[] {
  if (obj == null) return [];
  if (typeof obj === "string") return [prefix];
  if (Array.isArray(obj)) {
    const paths: string[] = [];
    for (let i = 0; i < obj.length; i++) {
      const p = findStringPaths(obj[i], `${prefix}[${i}]`);
      paths.push(...p);
    }
    return paths;
  }
  if (typeof obj === "object") {
    const paths: string[] = [];
    for (const key of Object.keys(obj)) {
      const next = prefix ? `${prefix}.${key}` : key;
      paths.push(...findStringPaths(obj[key], next));
    }
    return paths;
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
