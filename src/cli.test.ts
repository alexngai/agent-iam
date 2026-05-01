/**
 * CLI exit-code tests.
 *
 * Spawns the compiled `dist/cli.js` as a subprocess and asserts on exit
 * code, stdout, and stderr. Avoids spurious failures from a developer
 * forgetting to rebuild: the suite runs after `npm run build` (per
 * package.json `test` script), so dist/cli.js is current.
 *
 * AGENT_IAM_HOME is pointed at a per-test temp dir so we don't
 * contaminate the developer's real config.
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { spawnSync } from "child_process";

const CLI = path.resolve(__dirname, "cli.js");

function run(
  args: string[],
  env: Record<string, string>
): { status: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
  return {
    status: r.status ?? -1,
    stdout: r.stdout,
    stderr: r.stderr,
  };
}

function setup(): { home: string; cleanup: () => void } {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-cli-test-"));
  return {
    home,
    cleanup: () => fs.rmSync(home, { recursive: true, force: true }),
  };
}

function mintToken(home: string, scopes: string[]): string {
  const r = run(
    ["token", "create-root", "--agent-id", "demo", "--scopes", ...scopes],
    { AGENT_IAM_HOME: home }
  );
  if (r.status !== 0) throw new Error(`token mint failed: ${r.stderr}`);
  return r.stdout.trim();
}

describe("agent-iam mcp test exit codes", () => {
  let env: { home: string; cleanup: () => void };
  beforeEach(() => {
    env = setup();
  });
  afterEach(() => {
    env.cleanup();
  });

  test("exit 0 on allow", () => {
    const token = mintToken(env.home, ["mcp:filesystem:read_file"]);
    const r = run(
      ["mcp", "test", "--token", token, "filesystem", "read_file"],
      { AGENT_IAM_HOME: env.home }
    );
    assert.strictEqual(r.status, 0);
    assert.match(r.stdout, /^allow/);
  });

  test("exit 1 on deny (no matching scope)", () => {
    const token = mintToken(env.home, ["github:repo:read"]);
    const r = run(
      ["mcp", "test", "--token", token, "filesystem", "read_file"],
      { AGENT_IAM_HOME: env.home }
    );
    assert.strictEqual(r.status, 1);
    assert.match(r.stdout, /^deny/);
  });

  test("exit 1 on deny via broker policy", () => {
    const token = mintToken(env.home, ["mcp:*"]);
    run(["mcp", "deny", "add", "mcp:shell:*"], { AGENT_IAM_HOME: env.home });
    const r = run(["mcp", "test", "--token", token, "shell", "exec"], {
      AGENT_IAM_HOME: env.home,
    });
    assert.strictEqual(r.status, 1);
    assert.match(r.stdout, /Broker policy/);
  });
});

describe("agent-iam mcp deny exit codes", () => {
  let env: { home: string; cleanup: () => void };
  beforeEach(() => {
    env = setup();
  });
  afterEach(() => {
    env.cleanup();
  });

  test("list with no patterns prints '(no patterns)' and exits 0", () => {
    const r = run(["mcp", "deny", "list"], { AGENT_IAM_HOME: env.home });
    assert.strictEqual(r.status, 0);
    assert.match(r.stdout, /\(no patterns\)/);
  });

  test("add then list shows the pattern", () => {
    run(["mcp", "deny", "add", "mcp:shell:*"], { AGENT_IAM_HOME: env.home });
    const r = run(["mcp", "deny", "list"], { AGENT_IAM_HOME: env.home });
    assert.strictEqual(r.status, 0);
    assert.match(r.stdout, /^mcp:shell:\*$/m);
  });

  test("add rejects bad pattern with exit 1", () => {
    const r = run(["mcp", "deny", "add", "github:repo:read"], {
      AGENT_IAM_HOME: env.home,
    });
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /must be '\*' or start with 'mcp:'/);
  });

  test("remove of absent pattern exits 1", () => {
    const r = run(["mcp", "deny", "remove", "mcp:never-added:*"], {
      AGENT_IAM_HOME: env.home,
    });
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /not found/);
  });
});

describe("agent-iam mcp jwks", () => {
  let env: { home: string; cleanup: () => void };
  beforeEach(() => {
    env = setup();
  });
  afterEach(() => {
    env.cleanup();
  });

  test("prints valid JWKS JSON with one EdDSA key", () => {
    const r = run(["mcp", "jwks"], { AGENT_IAM_HOME: env.home });
    assert.strictEqual(r.status, 0);
    const parsed = JSON.parse(r.stdout);
    assert.ok(Array.isArray(parsed.keys));
    assert.strictEqual(parsed.keys.length, 1);
    assert.strictEqual(parsed.keys[0].alg, "EdDSA");
    assert.strictEqual(parsed.keys[0].use, "sig");
    assert.ok(parsed.keys[0].kid);
  });
});

describe("agent-iam mcp issue-cred", () => {
  let env: { home: string; cleanup: () => void };
  beforeEach(() => {
    env = setup();
  });
  afterEach(() => {
    env.cleanup();
  });

  test("mints a JWT and writes audit event", () => {
    const token = mintToken(env.home, ["mcp:fs:read"]);
    const r = run(
      [
        "mcp",
        "issue-cred",
        "https://fs.example.com",
        "--token",
        token,
        "--scopes",
        "mcp:fs:read",
      ],
      { AGENT_IAM_HOME: env.home }
    );
    assert.strictEqual(r.status, 0);
    // JWT shape
    assert.match(r.stdout.trim(), /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    // Audit log captured the mint.
    const log = fs.readFileSync(
      path.join(env.home, "mcp-audit.jsonl"),
      "utf8"
    );
    const event = JSON.parse(log.trim());
    assert.strictEqual(event.kind, "mcp.credential.issued");
    assert.strictEqual(event.audience, "https://fs.example.com");
  });

  test("exits 1 on scope not granted by token", () => {
    const token = mintToken(env.home, ["mcp:fs:read"]);
    const r = run(
      [
        "mcp",
        "issue-cred",
        "https://fs.example.com",
        "--token",
        token,
        "--scopes",
        "mcp:fs:write_dangerous",
      ],
      { AGENT_IAM_HOME: env.home }
    );
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /not granted by the agent token/);
  });
});
