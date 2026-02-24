// apps/api/src/openapi.ts
import SwaggerParser from "@apidevtools/swagger-parser";

export type Endpoint = { method: string; path: string };

export type ApiParameter = {
  name: string;
  in: "query" | "path" | "header" | "cookie" | "formData";
  required?: boolean;
  schema?: any;
  example?: any;
  default?: any;
};

export type EndpointDetail = {
  method: string;
  path: string;
  requestBodySchema?: any;
  requestBodyContentTypes?: string[];
  responseContentTypes?: string[];
  responseBodySchema?: any;
  parameters?: ApiParameter[];
  security?: any[] | null;
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

function normalizeValidationError(err: any): string {
  if (!err) return "Unknown error";

  // najczęstszy przypadek: normalny Error z message
  if (typeof err.message === "string" && err.message.trim()) return err.message;

  // czasem swagger-parser zwraca obiekt z errors/ details
  if (Array.isArray(err?.details) && err.details.length) {
    return err.details.map((d: any) => d?.message ?? JSON.stringify(d)).join("\n");
  }

  if (Array.isArray(err?.errors) && err.errors.length) {
    return err.errors.map((e: any) => e?.message ?? JSON.stringify(e)).join("\n");
  }

  // fallback
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

/**
 * Validates OpenAPI/Swagger and extracts endpoints.
 * Accepts:
 * - OpenAPI 3.x object (has `openapi`)
 * - Swagger 2.0 object (has `swagger`)
 */
export async function parseOpenApi(specObj: any): Promise<Endpoint[]> {
  const detailed = await parseOpenApiDetailed(specObj);
  return detailed.map((e) => ({ method: e.method, path: e.path }));
}

export async function parseOpenApiDetailed(specObj: any): Promise<EndpointDetail[]> {
  if (!specObj || typeof specObj !== "object") {
    throw new Error("Spec is empty or not an object.");
  }

  const isOas3 = typeof specObj.openapi === "string";
  const isSwagger2 = typeof specObj.swagger === "string";

  if (!isOas3 && !isSwagger2) {
    const keys = Object.keys(specObj).slice(0, 25).join(", ");
    throw new Error(
      `Spec is not a valid OpenAPI/Swagger document (missing "openapi" or "swagger"). Keys: ${keys}`
    );
  }

  // validate + resolve $refs
  let validated: any;
  try {
    validated = await SwaggerParser.validate(specObj);
  } catch (err: any) {
    const msg = normalizeValidationError(err);
    throw new Error(msg);
  }

  return buildEndpointsFromSpec(validated);
}

export function parseOpenApiDetailedNoValidate(specObj: any): EndpointDetail[] {
  if (!specObj || typeof specObj !== "object") {
    throw new Error("Spec is empty or not an object.");
  }
  return buildEndpointsFromSpec(specObj);
}

function buildEndpointsFromSpec(validated: any): EndpointDetail[] {
  const paths = validated?.paths;
  if (!paths || typeof paths !== "object") {
    throw new Error("OpenAPI/Swagger document has no 'paths' object.");
  }

  const endpoints: EndpointDetail[] = [];

  for (const path of Object.keys(paths)) {
    const pathItem = paths[path];
    if (!pathItem || typeof pathItem !== "object") continue;

    for (const key of Object.keys(pathItem)) {
      const method = key.toLowerCase();

      // np. swagger/openapi dopuszcza też "parameters" na poziomie ścieżki
      if (!HTTP_METHODS.has(method)) continue;

      const operation = pathItem[key] ?? {};

      const parameters = collectParameters(pathItem, operation);
      const { schema: requestBodySchema, contentTypes } = extractRequestBodySchema(validated, operation);
      const responseContentTypes = extractResponseContentTypes(validated, operation);
      const responseBodySchema = extractPrimaryResponseSchema(validated, operation, responseContentTypes);
      const security = Array.isArray(operation?.security)
        ? operation.security
        : Array.isArray(validated?.security)
        ? validated.security
        : null;

      endpoints.push({
        method: method.toUpperCase(),
        path,
        requestBodySchema,
        requestBodyContentTypes: contentTypes,
        responseContentTypes,
        responseBodySchema,
        parameters,
        security
      });
    }
  }

  // stabilna kolejność
  endpoints.sort((a, b) => {
    if (a.path === b.path) return a.method.localeCompare(b.method);
    return a.path.localeCompare(b.path);
  });

  return endpoints;
}

function collectParameters(pathItem: any, operation: any): ApiParameter[] {
  const params: any[] = [];
  if (Array.isArray(pathItem?.parameters)) params.push(...pathItem.parameters);
  if (Array.isArray(operation?.parameters)) params.push(...operation.parameters);

  const out: ApiParameter[] = [];
  for (const p of params) {
    if (!p || typeof p !== "object") continue;
    const loc = p.in;
    if (loc !== "query" && loc !== "path" && loc !== "header" && loc !== "cookie" && loc !== "formData") continue;

    out.push({
      name: p.name,
      in: loc,
      required: p.required,
      schema: p.schema,
      example: p.example,
      default: p.default
    });
  }
  return out;
}

function extractRequestBodySchema(validated: any, operation: any) {
  const isOas3 = typeof validated?.openapi === "string";
  const isSwagger2 = typeof validated?.swagger === "string";

  if (isOas3) {
    const content = operation?.requestBody?.content;
    if (!content || typeof content !== "object") return { schema: undefined, contentTypes: [] as string[] };
    const contentTypes = Object.keys(content);
    const json =
      content["application/json"] ||
      content["application/*+json"] ||
      Object.values(content)[0];
    return { schema: (json as any)?.schema, contentTypes };
  }

  if (isSwagger2) {
    const params = Array.isArray(operation?.parameters) ? operation.parameters : [];
    const bodyParam = params.find((p: any) => p?.in === "body");
    return { schema: bodyParam?.schema, contentTypes: ["application/json"] };
  }

  return { schema: undefined, contentTypes: [] as string[] };
}

function extractResponseContentTypes(validated: any, operation: any): string[] {
  const isOas3 = typeof validated?.openapi === "string";
  const isSwagger2 = typeof validated?.swagger === "string";

  if (isOas3) {
    const responses = operation?.responses;
    if (!responses || typeof responses !== "object") return [];
    const entries = Object.entries(responses);
    const twoxx = entries.filter(([code]) => /^2\d\d$/.test(code));
    const preferred = twoxx.length
      ? twoxx
      : responses.default
      ? [["default", (responses as any).default]]
      : entries;
    const types: string[] = [];
    for (const [, resp] of preferred) {
      const content = (resp as any)?.content;
      if (!content || typeof content !== "object") continue;
      types.push(...Object.keys(content));
    }
    return Array.from(new Set(types));
  }

  if (isSwagger2) {
    const produces = operation?.produces ?? validated?.produces;
    if (Array.isArray(produces)) return produces;
    return [];
  }

  return [];
}

function extractPrimaryResponseSchema(validated: any, operation: any, responseContentTypes: string[]) {
  const isOas3 = typeof validated?.openapi === "string";
  const isSwagger2 = typeof validated?.swagger === "string";

  if (isOas3) {
    const responses = operation?.responses;
    if (!responses || typeof responses !== "object") return undefined;
    const entries = Object.entries(responses);
    const twoxx = entries.filter(([code]) => /^2\d\d$/.test(code));
    const preferred = twoxx.length
      ? twoxx
      : responses.default
      ? [["default", (responses as any).default]]
      : entries;
    for (const [, resp] of preferred) {
      const content = (resp as any)?.content;
      if (!content || typeof content !== "object") continue;
      const json =
        content["application/json"] ||
        content["application/*+json"] ||
        (responseContentTypes?.length ? content[responseContentTypes[0]] : undefined) ||
        Object.values(content)[0];
      const schema = (json as any)?.schema;
      if (schema) return schema;
    }
  }

  if (isSwagger2) {
    const responses = operation?.responses;
    if (!responses || typeof responses !== "object") return undefined;
    const twoxx = Object.keys(responses).filter((code) => /^2\d\d$/.test(code));
    const preferred = twoxx.length ? twoxx : responses.default ? ["default"] : Object.keys(responses);
    for (const code of preferred) {
      const schema = (responses as any)[code]?.schema;
      if (schema) return schema;
    }
  }

  return undefined;
}
