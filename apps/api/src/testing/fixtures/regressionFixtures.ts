import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

export type OpenApiDoc = Record<string, unknown>;

export type RunningFixture = {
  baseUrl: string;
  stop: () => Promise<void>;
};

function listen(app: ReturnType<typeof express>) {
  return new Promise<Server>((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function toBaseUrl(server: Server) {
  const addr = server.address() as AddressInfo;
  return `http://127.0.0.1:${addr.port}`;
}

async function closeServer(server: Server) {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

export async function startVulnerableFixture(): Promise<RunningFixture> {
  const app = express();
  app.use(express.json());

  app.get("/search", (req, res) => {
    const q = String(req.query.q ?? "");
    if (/sleep\s*\(\s*1\s*\)|waitfor\s+delay/i.test(q)) {
      return setTimeout(() => {
        res.status(200).json({ items: [{ id: 99, name: "delayed-hit" }], delayed: true });
      }, 1100);
    }
    if (/1\s*=\s*2/.test(q)) {
      return res.status(200).json({ items: [] });
    }
    if (/1\s*=\s*1/.test(q)) {
      return res.status(200).json({ items: [{ id: 1, name: "predicate-true" }, { id: 2, name: "predicate-true-2" }] });
    }
    if (q.includes("'") || /or\s+1=1/i.test(q) || /--/.test(q)) {
      return res
        .status(500)
        .json({ error: "SQL syntax error near input", query: q });
    }
    return res.json({ items: [{ id: 1, name: "demo" }] });
  });

  app.get("/render", (req, res) => {
    const input = String(req.query.input ?? "");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.status(200).send(`<html><body>${input}</body></html>`);
  });

  // Intentionally vulnerable: security-required endpoint returns 200 without auth.
  app.get("/private/data", (_req, res) => {
    res.json({ ok: true, secret: "fixture-secret" });
  });

  app.get("/redirect", (req, res) => {
    const next = String(req.query.next ?? "");
    if (next) {
      res.setHeader("Location", next);
      return res.status(302).send("redirecting");
    }
    return res.status(200).json({ ok: true, message: "no redirect" });
  });

  app.get("/header-test", (req, res) => {
    const input = String(req.query.input ?? "");
    if (/%0d|%0a|\r|\n/i.test(input)) {
      res.setHeader("X-TomSec-Injection", "1");
      res.setHeader("Set-Cookie", "tomsec=1; Path=/");
    }
    res.status(200).json({ ok: true, input });
  });

  app.get("/fetch", (req, res) => {
    const url = String(req.query.url ?? "");
    const lowered = url.toLowerCase();
    const internal =
      lowered.includes("127.0.0.1") ||
      lowered.includes("169.254.169.254") ||
      lowered.includes("localhost");
    if (internal) {
      return res.status(200).json({
        ok: true,
        fetched: "internal_resource_accessed",
        source: lowered.includes("169.254.169.254") ? "metadata" : "loopback",
        requestedUrl: url
      });
    }
    return res.status(200).json({
      ok: true,
      fetched: "external_resource_accessed",
      source: "external",
      requestedUrl: url
    });
  });

  app.get("/template/render", (req, res) => {
    const input = String(req.query.input ?? "");
    const trimmed = input.trim();
    if (trimmed === "{{7*7}}" || trimmed === "${7*7}" || trimmed === "<%= 7*7 %>") {
      return res.status(200).json({
        ok: true,
        rendered: "49"
      });
    }
    return res.status(200).json({
      ok: true,
      rendered: input
    });
  });

  app.get("/files/read", (req, res) => {
    const name = String(req.query.name ?? "");
    const lowered = decodeURIComponent(name).toLowerCase();
    if (lowered.includes("../") || lowered.includes("..\\") || lowered.includes("etc/passwd")) {
      return res.status(200).json({
        ok: true,
        content: "root:x:0:0:root:/root:/bin/bash"
      });
    }
    if (lowered.includes("win.ini")) {
      return res.status(200).json({
        ok: true,
        content: "[fonts]\nfor 16-bit app support"
      });
    }
    return res.status(200).json({
      ok: true,
      content: "file-not-found"
    });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export async function startStableFixture(): Promise<RunningFixture> {
  const app = express();

  app.get("/products", (_req, res) => {
    res.json({ items: [{ id: 1, sku: "A-1" }] });
  });

  app.get("/status", (_req, res) => {
    res.json({ ok: true });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export async function startNoisyBaselineFixture(): Promise<RunningFixture> {
  const app = express();
  let counter = 0;

  app.get("/flaky", (req, res) => {
    const q = String(req.query.q ?? "");
    counter = (counter + 1) % 3;

    // Deterministic oscillation: 200, 500, 200, ...
    if (counter === 2) {
      return res.status(500).json({
        ok: false,
        reason: "temporary backend jitter",
        hint: q.length
      });
    }

    return res.status(200).json({
      ok: true,
      items: [{ id: 1, name: "stable-item" }],
      requestEcho: q.slice(0, 8)
    });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export async function startRetryStatusFixture(): Promise<RunningFixture> {
  const app = express();
  const attempts = new Map<string, number>();

  app.get("/search-retry", (req, res) => {
    const q = String(req.query.q ?? "");
    const key = q.trim().toLowerCase();
    const seen = attempts.get(key) ?? 0;
    attempts.set(key, seen + 1);

    if (seen === 0) {
      res.setHeader("Retry-After", "0");
      return res.status(503).json({ ok: false, reason: "transient upstream failure" });
    }

    if (q.includes("'") || /or\s+1=1/i.test(q) || /--/.test(q)) {
      return res.status(500).json({ error: "SQL syntax error near input", query: q });
    }
    return res.status(200).json({ items: [{ id: 1, name: "demo" }] });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

function escapeHtml(input: string) {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export async function startXssContextFixture(): Promise<RunningFixture> {
  const app = express();

  app.get("/xss/safe-format", (req, res) => {
    const input = String(req.query.input ?? "");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<html><body><p>${input}</p></body></html>`);
  });

  app.get("/xss/escaped", (req, res) => {
    const input = String(req.query.input ?? "");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<html><body>${escapeHtml(input)}</body></html>`);
  });

  app.get("/xss/attr-context", (req, res) => {
    const input = String(req.query.input ?? "");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<html><body><div data-q="${input}">row</div></body></html>`);
  });

  app.get("/xss/json-reflect", (req, res) => {
    const input = String(req.query.input ?? "");
    res.json({ ok: true, echoed: input });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export async function startSsrfNoiseFixture(): Promise<RunningFixture> {
  const app = express();

  app.get("/fetch-static", (_req, res) => {
    // Static diagnostic response that contains internal-ish words but does not depend on input URL.
    res.status(200).json({
      ok: true,
      source: "loopback",
      diagnostic: "internal_resource_accessed"
    });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export async function startHeaderNoiseFixture(): Promise<RunningFixture> {
  const app = express();

  app.get("/header-static", (_req, res) => {
    // Static cookie/header value unrelated to request payload.
    res.setHeader("Set-Cookie", "tomsec=1; Path=/");
    res.status(200).json({ ok: true });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export async function startPathTraversalNoiseFixture(): Promise<RunningFixture> {
  const app = express();

  app.get("/files/info", (_req, res) => {
    // Contains the word "Windows", but is not a leaked system file.
    res.status(200).json({
      ok: true,
      content: "Windows release notes and product documentation"
    });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export async function startTemplateNoiseFixture(): Promise<RunningFixture> {
  const app = express();

  app.get("/template/static49", (_req, res) => {
    // Static value "49" that is not a template evaluation result of user input.
    res.status(200).json({
      ok: true,
      answer: "49"
    });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export async function startBaselineSafetyFixture(): Promise<RunningFixture> {
  const app = express();
  app.use(express.json());
  let writes = 0;

  app.post("/mutate-auth", (_req, res) => {
    writes++;
    res.status(200).json({ ok: true, writes });
  });

  app.get("/counter", (_req, res) => {
    res.status(200).json({ writes });
  });

  const server = await listen(app);
  return {
    baseUrl: toBaseUrl(server),
    stop: () => closeServer(server)
  };
}

export const vulnerableSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression Vulnerable Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer"
      }
    }
  },
  paths: {
    "/search": {
      get: {
        parameters: [
          {
            name: "q",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "demo"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    items: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          id: { type: "integer" },
                          name: { type: "string" }
                        },
                        required: ["id", "name"]
                      }
                    }
                  },
                  required: ["items"]
                }
              }
            }
          }
        }
      }
    },
    "/render": {
      get: {
        parameters: [
          {
            name: "input",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "hello"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "text/html": {
                schema: { type: "string" }
              }
            }
          }
        }
      }
    },
    "/private/data": {
      get: {
        security: [{ bearerAuth: [] }],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    secret: { type: "string" }
                  },
                  required: ["ok", "secret"]
                }
              }
            }
          }
        }
      }
    },
    "/redirect": {
      get: {
        parameters: [
          {
            name: "next",
            in: "query",
            required: false,
            schema: { type: "string", format: "uri" },
            example: "https://example.com"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    message: { type: "string" }
                  },
                  required: ["ok", "message"]
                }
              }
            }
          },
          "302": {
            description: "redirect",
            headers: {
              Location: {
                schema: { type: "string" }
              }
            }
          }
        }
      }
    },
    "/header-test": {
      get: {
        parameters: [
          {
            name: "input",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "hello"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    input: { type: "string" }
                  },
                  required: ["ok", "input"]
                }
              }
            }
          }
        }
      }
    },
    "/fetch": {
      get: {
        parameters: [
          {
            name: "url",
            in: "query",
            required: false,
            schema: { type: "string", format: "uri" },
            example: "https://example.com"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    fetched: { type: "string" },
                    source: { type: "string" },
                    requestedUrl: { type: "string" }
                  },
                  required: ["ok", "fetched", "source", "requestedUrl"]
                }
              }
            }
          }
        }
      }
    },
    "/template/render": {
      get: {
        parameters: [
          {
            name: "input",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "hello"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    rendered: { type: "string" }
                  },
                  required: ["ok", "rendered"]
                }
              }
            }
          }
        }
      }
    },
    "/files/read": {
      get: {
        parameters: [
          {
            name: "name",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "readme.txt"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    content: { type: "string" }
                  },
                  required: ["ok", "content"]
                }
              }
            }
          }
        }
      }
    }
  }
};

export const stableSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression Stable Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  paths: {
    "/products": {
      get: {
        parameters: [
          {
            name: "q",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "shirt"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    items: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          id: { type: "integer" },
                          sku: { type: "string" }
                        },
                        required: ["id", "sku"]
                      }
                    }
                  },
                  required: ["items"]
                }
              }
            }
          }
        }
      }
    },
    "/status": {
      get: {
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" }
                  },
                  required: ["ok"]
                }
              }
            }
          }
        }
      }
    }
  }
};

export const noisyBaselineSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression Noisy Baseline Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  paths: {
    "/flaky": {
      get: {
        parameters: [
          {
            name: "q",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "abc"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    items: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          id: { type: "integer" },
                          name: { type: "string" }
                        },
                        required: ["id", "name"]
                      }
                    },
                    requestEcho: { type: "string" }
                  },
                  required: ["ok"]
                }
              }
            }
          },
          "500": {
            description: "error",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    reason: { type: "string" },
                    hint: { type: "integer" }
                  },
                  required: ["ok", "reason"]
                }
              }
            }
          }
        }
      }
    }
  }
};

export const xssContextSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression XSS Context Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  paths: {
    "/xss/safe-format": {
      get: {
        parameters: [{ name: "input", in: "query", schema: { type: "string" }, example: "hello" }],
        responses: {
          "200": { description: "ok", content: { "text/html": { schema: { type: "string" } } } }
        }
      }
    },
    "/xss/escaped": {
      get: {
        parameters: [{ name: "input", in: "query", schema: { type: "string" }, example: "hello" }],
        responses: {
          "200": { description: "ok", content: { "text/html": { schema: { type: "string" } } } }
        }
      }
    },
    "/xss/attr-context": {
      get: {
        parameters: [{ name: "input", in: "query", schema: { type: "string" }, example: "hello" }],
        responses: {
          "200": { description: "ok", content: { "text/html": { schema: { type: "string" } } } }
        }
      }
    },
    "/xss/json-reflect": {
      get: {
        parameters: [{ name: "input", in: "query", schema: { type: "string" }, example: "hello" }],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    echoed: { type: "string" }
                  },
                  required: ["ok", "echoed"]
                }
              }
            }
          }
        }
      }
    }
  }
};

export const retryStatusSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression Retry Status Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  paths: {
    "/search-retry": {
      get: {
        parameters: [
          {
            name: "q",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "abc"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    items: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          id: { type: "integer" },
                          name: { type: "string" }
                        },
                        required: ["id", "name"]
                      }
                    }
                  },
                  required: ["items"]
                }
              }
            }
          },
          "500": {
            description: "vulnerable sql error",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    error: { type: "string" },
                    query: { type: "string" }
                  },
                  required: ["error"]
                }
              }
            }
          },
          "503": {
            description: "transient"
          }
        }
      }
    }
  }
};

export const ssrfNoiseSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression SSRF Noise Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  paths: {
    "/fetch-static": {
      get: {
        parameters: [
          {
            name: "url",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "http://example.com"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    source: { type: "string" },
                    diagnostic: { type: "string" }
                  },
                  required: ["ok", "source", "diagnostic"]
                }
              }
            }
          }
        }
      }
    }
  }
};

export const headerNoiseSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression Header Noise Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  paths: {
    "/header-static": {
      get: {
        parameters: [
          {
            name: "input",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "hello"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" }
                  },
                  required: ["ok"]
                }
              }
            }
          }
        }
      }
    }
  }
};

export const pathTraversalNoiseSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression Path Traversal Noise Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  paths: {
    "/files/info": {
      get: {
        parameters: [
          {
            name: "name",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "readme.txt"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    content: { type: "string" }
                  },
                  required: ["ok", "content"]
                }
              }
            }
          }
        }
      }
    }
  }
};

export const templateNoiseSpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression Template Noise Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  paths: {
    "/template/static49": {
      get: {
        parameters: [
          {
            name: "input",
            in: "query",
            required: false,
            schema: { type: "string" },
            example: "hello"
          }
        ],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    answer: { type: "string" }
                  },
                  required: ["ok", "answer"]
                }
              }
            }
          }
        }
      }
    }
  }
};

export const baselineSafetySpec: OpenApiDoc = {
  openapi: "3.0.3",
  info: { title: "Scanner Regression Baseline Safety Fixture", version: "1.0.0" },
  servers: [{ url: "http://127.0.0.1" }],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer"
      }
    }
  },
  paths: {
    "/mutate-auth": {
      post: {
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: false,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  input: { type: "string" }
                }
              }
            }
          }
        },
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    writes: { type: "integer" }
                  },
                  required: ["ok", "writes"]
                }
              }
            }
          }
        }
      }
    },
    "/counter": {
      get: {
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    writes: { type: "integer" }
                  },
                  required: ["writes"]
                }
              }
            }
          }
        }
      }
    }
  }
};
