/**
 * HTTP-backed shared MCP tool-schema pin registry.
 *
 * For ephemeral / containerized / multi-replica agents that can't rely on a
 * local file-backed registry. Each request goes to a registry server the
 * operator runs (could be an Express/Fastify endpoint, an S3 bucket behind
 * a tiny shim, a Kubernetes ConfigMap controller, etc. — agent-iam
 * deliberately doesn't ship a server, since pin storage is a database
 * concern and operators have strong opinions about it).
 *
 * Documented HTTP contract (see `docs/mcp-policy.md`):
 *
 *   GET    /pins                         → 200 [{server,tool,hash,pinnedAt}, ...]
 *   GET    /pins?server=NAME             → 200 [{server,tool,hash,pinnedAt}, ...]
 *   GET    /pins/:server/:tool           → 200 {hash, pinnedAt} | 404
 *   PUT    /pins/:server/:tool           → 200 (body {hash}) | 409 if conflicting
 *   DELETE /pins/:server/:tool           → 200 | 404
 *
 * Server names and tool names are URL-encoded by the client; the server
 * receives them as path components and is responsible for decoding.
 *
 * Authentication: caller-supplied bearer token sent as `Authorization`.
 *
 * Failures: network errors and non-2xx responses (other than 404 on `get`)
 * propagate as thrown exceptions. The TOFU model assumes registry
 * availability — falling back to "no pin known" would defeat rug-pull
 * detection for ephemeral agents, which is exactly the case this client
 * exists to serve.
 */

import type { PinnedTool, SchemaPinRegistry } from "./schema-pin.js";

/** Options for constructing an HttpSchemaPinRegistry. */
export interface HttpSchemaPinRegistryOptions {
  /** Base URL of the registry server (no trailing slash needed). */
  baseURL: string;
  /** Optional bearer token sent in `Authorization: Bearer <token>`. */
  authToken?: string;
  /** Override the global fetch (useful for tests). */
  fetchImpl?: typeof fetch;
  /** Per-request timeout in ms (default: 10_000). */
  timeoutMs?: number;
}

/** Server-side wire shape; lines up with PinnedTool. */
interface PinResponse {
  hash: string;
  pinnedAt: string;
}

/** List endpoint wire shape. */
interface ListItemResponse {
  server: string;
  tool: string;
  hash: string;
  pinnedAt: string;
}

export class HttpSchemaPinRegistry implements SchemaPinRegistry {
  private readonly baseURL: string;
  private readonly authToken?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(options: HttpSchemaPinRegistryOptions) {
    if (!options.baseURL) {
      throw new Error("HttpSchemaPinRegistry: baseURL is required");
    }
    this.baseURL = options.baseURL.replace(/\/$/, "");
    this.authToken = options.authToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  async get(server: string, tool: string): Promise<PinnedTool | undefined> {
    const url = `${this.baseURL}/pins/${encodeURIComponent(server)}/${encodeURIComponent(tool)}`;
    const res = await this.request(url, { method: "GET" });
    if (res.status === 404) return undefined;
    await this.requireOk(res, "get");
    const body = (await res.json()) as PinResponse;
    return { hash: body.hash, pinnedAt: body.pinnedAt };
  }

  async set(server: string, tool: string, hash: string): Promise<void> {
    const url = `${this.baseURL}/pins/${encodeURIComponent(server)}/${encodeURIComponent(tool)}`;
    const res = await this.request(url, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash }),
    });
    await this.requireOk(res, "set");
  }

  async delete(server: string, tool: string): Promise<void> {
    const url = `${this.baseURL}/pins/${encodeURIComponent(server)}/${encodeURIComponent(tool)}`;
    const res = await this.request(url, { method: "DELETE" });
    if (res.status === 404) return; // idempotent
    await this.requireOk(res, "delete");
  }

  async list(
    server?: string
  ): Promise<Array<{ server: string; tool: string; pin: PinnedTool }>> {
    const url = server
      ? `${this.baseURL}/pins?server=${encodeURIComponent(server)}`
      : `${this.baseURL}/pins`;
    const res = await this.request(url, { method: "GET" });
    await this.requireOk(res, "list");
    const body = (await res.json()) as ListItemResponse[];
    return body.map((e) => ({
      server: e.server,
      tool: e.tool,
      pin: { hash: e.hash, pinnedAt: e.pinnedAt },
    }));
  }

  private async request(url: string, init: RequestInit): Promise<Response> {
    const headers: Record<string, string> = {
      ...(init.headers as Record<string, string> | undefined),
    };
    if (this.authToken) {
      headers["Authorization"] = `Bearer ${this.authToken}`;
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, headers, signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  private async requireOk(res: Response, op: string): Promise<void> {
    if (res.status >= 200 && res.status < 300) return;
    let detail = "";
    try {
      detail = await res.text();
    } catch {
      // ignore
    }
    throw new Error(
      `HttpSchemaPinRegistry.${op}: HTTP ${res.status} ${res.statusText}${detail ? ` — ${detail.slice(0, 200)}` : ""}`
    );
  }
}
