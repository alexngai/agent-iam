/**
 * Tests for HttpSchemaPinRegistry.
 *
 * Uses an in-process fake fetch implementation so we exercise the wire
 * contract without spinning up a real HTTP server. The fake mirrors the
 * documented contract; if real servers diverge, that's their bug to fix.
 */

import { test, describe, beforeEach } from "node:test";
import * as assert from "node:assert";
import { HttpSchemaPinRegistry, PinConflictError } from "./http-pin-registry.js";

/** Construct a fake fetch that backs onto an in-memory store. */
function fakeFetch() {
  const store = new Map<string, { hash: string; pinnedAt: string }>();
  const calls: Array<{ url: string; method: string; headers: Record<string, string>; body?: string }> = [];

  const impl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = (init?.headers as Record<string, string>) ?? {};
    const body = init?.body as string | undefined;
    calls.push({ url, method, headers, body });

    const u = new URL(url);
    const path = u.pathname;
    // GET /pins[?server=NAME] or /pins/:server/:tool
    if (path === "/pins" && method === "GET") {
      const server = u.searchParams.get("server");
      const items = [...store.entries()]
        .map(([k, v]) => {
          const idx = k.indexOf(":");
          return { server: k.slice(0, idx), tool: k.slice(idx + 1), ...v };
        })
        .filter((e) => server === null || e.server === server);
      return new Response(JSON.stringify(items), { status: 200 });
    }

    const m = path.match(/^\/pins\/([^/]+)\/([^/]+)$/);
    if (!m) return new Response("not found", { status: 404 });
    const server = decodeURIComponent(m[1]);
    const tool = decodeURIComponent(m[2]);
    const key = `${server}:${tool}`;

    if (method === "GET") {
      const v = store.get(key);
      if (!v) return new Response("not found", { status: 404 });
      return new Response(JSON.stringify(v), { status: 200 });
    }
    if (method === "PUT") {
      const parsed = JSON.parse(body ?? "{}") as { hash: string };
      store.set(key, { hash: parsed.hash, pinnedAt: new Date().toISOString() });
      return new Response("", { status: 200 });
    }
    if (method === "DELETE") {
      const had = store.delete(key);
      return new Response("", { status: had ? 200 : 404 });
    }
    return new Response("method not allowed", { status: 405 });
  };

  return { impl, store, calls };
}

describe("HttpSchemaPinRegistry", () => {
  let registry: HttpSchemaPinRegistry;
  let fake: ReturnType<typeof fakeFetch>;

  beforeEach(() => {
    fake = fakeFetch();
    registry = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      authToken: "secret-token",
      fetchImpl: fake.impl,
    });
  });

  test("rejects construction without baseURL", () => {
    assert.throws(
      () => new HttpSchemaPinRegistry({ baseURL: "" }),
      /baseURL is required/
    );
  });

  test("strips trailing slash from baseURL", async () => {
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com/",
      fetchImpl: fake.impl,
    });
    await r.get("fs", "read");
    assert.strictEqual(fake.calls[0].url, "https://pins.example.com/pins/fs/read");
  });

  test("get returns undefined on 404", async () => {
    const r = await registry.get("fs", "missing");
    assert.strictEqual(r, undefined);
  });

  test("set then get round-trips", async () => {
    await registry.set("fs", "read", "deadbeef");
    const pin = await registry.get("fs", "read");
    assert.ok(pin);
    assert.strictEqual(pin.hash, "deadbeef");
    assert.ok(pin.pinnedAt);
  });

  test("delete removes the pin", async () => {
    await registry.set("fs", "read", "h");
    await registry.delete("fs", "read");
    const pin = await registry.get("fs", "read");
    assert.strictEqual(pin, undefined);
  });

  test("delete is idempotent (404 swallowed)", async () => {
    await registry.delete("fs", "never-existed");
    // No throw; pass.
  });

  test("list with no filter returns all pins", async () => {
    await registry.set("fs", "read", "h1");
    await registry.set("net", "fetch", "h2");
    const all = await registry.list();
    assert.strictEqual(all.length, 2);
  });

  test("list with server filter returns only matching pins", async () => {
    await registry.set("fs", "read", "h1");
    await registry.set("fs", "write", "h2");
    await registry.set("net", "fetch", "h3");
    const fs = await registry.list("fs");
    assert.strictEqual(fs.length, 2);
    assert.ok(fs.every((e) => e.server === "fs"));
  });

  test("URL-encodes server and tool names with special chars", async () => {
    const weird = "io.github.org/server@1.0";
    await registry.set(weird, "tool", "h");
    const seen = fake.calls[fake.calls.length - 1].url;
    assert.match(seen, /\/pins\/io\.github\.org%2Fserver%401\.0\/tool$/);
  });

  test("attaches Authorization header when authToken is set", async () => {
    await registry.get("fs", "read");
    assert.strictEqual(fake.calls[0].headers["Authorization"], "Bearer secret-token");
  });

  test("omits Authorization header when no token configured", async () => {
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: fake.impl,
    });
    await r.get("fs", "read");
    const auth = fake.calls[fake.calls.length - 1].headers["Authorization"];
    assert.strictEqual(auth, undefined);
  });

  test("throws on non-2xx response (other than get-404)", async () => {
    const broken: typeof fetch = async () =>
      new Response("server down", { status: 500, statusText: "Internal Error" });
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: broken,
    });
    await assert.rejects(() => r.set("fs", "read", "h"), /HTTP 500/);
  });

  test("error message includes operation name and status", async () => {
    // 5xx goes through the generic error path; 409 is now PinConflictError
    // (covered by its own test below).
    const broken: typeof fetch = async () =>
      new Response("server down", { status: 503, statusText: "Service Unavailable" });
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: broken,
    });
    try {
      await r.set("fs", "read", "h");
      assert.fail("expected throw");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      assert.match(msg, /set/);
      assert.match(msg, /503/);
    }
  });

  test("respects timeoutMs (slow request aborts)", async () => {
    const slow: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        const signal = init?.signal as AbortSignal | undefined;
        signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: slow,
      timeoutMs: 50,
    });
    await assert.rejects(() => r.get("fs", "read"), /aborted/);
  });

  test("timeout also covers body parsing (drip-feed defense, review)", async () => {
    // Pre-fix: clearTimeout fired when fetch resolved with headers, leaving
    // body reads unbounded. A server can stream-feed a JSON body for hours.
    // We model that with a Response whose .json() rejects on signal abort.
    const dripFeed: typeof fetch = (_input, init) => {
      const signal = init?.signal as AbortSignal;
      const fakeBody = new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new Error("body aborted")));
      });
      const res = new Response(JSON.stringify({ hash: "x", pinnedAt: "y" }));
      // Override .json() to honor the abort signal; default Response.json
      // resolves immediately so we couldn't observe the bug.
      (res as any).json = () => fakeBody;
      return Promise.resolve(res);
    };
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: dripFeed,
      timeoutMs: 50,
    });
    await assert.rejects(() => r.get("fs", "read"), /body aborted/);
  });

  test("set throws PinConflictError on 409 (typed for callers)", async () => {
    const conflict: typeof fetch = async () =>
      new Response("hash already pinned", { status: 409, statusText: "Conflict" });
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: conflict,
    });
    try {
      await r.set("fs", "read", "h");
      assert.fail("expected throw");
    } catch (err) {
      assert.ok(err instanceof PinConflictError);
      assert.strictEqual((err as PinConflictError).server, "fs");
      assert.strictEqual((err as PinConflictError).tool, "read");
      assert.match((err as PinConflictError).response, /already pinned/);
    }
  });

  test("get throws on malformed body (missing hash)", async () => {
    const malformed: typeof fetch = async () =>
      new Response(JSON.stringify({ pinnedAt: "t" }), { status: 200 });
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: malformed,
    });
    await assert.rejects(() => r.get("fs", "read"), /malformed response body/);
  });

  test("list throws when body is not an array", async () => {
    const malformed: typeof fetch = async () =>
      new Response(JSON.stringify({ oops: "object" }), { status: 200 });
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: malformed,
    });
    await assert.rejects(() => r.list(), /not an array/);
  });

  test("list throws when items are missing fields", async () => {
    const malformed: typeof fetch = async () =>
      new Response(JSON.stringify([{ server: "fs", tool: "read" }]), { status: 200 });
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: malformed,
    });
    await assert.rejects(() => r.list(), /malformed response item/);
  });

  test("sets redirect: error on every request (no implicit redirect-follow)", async () => {
    let observedRedirect: RequestRedirect | undefined;
    const captureFetch: typeof fetch = async (_input, init) => {
      observedRedirect = init?.redirect;
      return new Response(JSON.stringify({ hash: "h", pinnedAt: "t" }), { status: 200 });
    };
    const r = new HttpSchemaPinRegistry({
      baseURL: "https://pins.example.com",
      fetchImpl: captureFetch,
    });
    await r.get("fs", "read");
    assert.strictEqual(observedRedirect, "error");
  });
});
