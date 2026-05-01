# Reference MCP Harness

A minimal, runnable reference for integrating agent-iam's MCP access
control into an agent harness. The harness is the trusted code around an
LLM that dispatches tool calls — **it owns enforcement**, agent-iam
distributes signed policy.

## Files

- `harness.ts` — the dispatch wrapper that integrates all four checks
  (TOFU schema pin, scope policy, annotation primitives, server identity).
- `demo.ts` — runs the harness against a fake server and prints decisions.

## Run the demo

The examples import from the compiled `dist/` so they mirror what
real package consumers see. Run `npm run build` first, then any TS
runner works:

```bash
npm install
npm run build
npx tsx examples/mcp-harness/demo.ts   # or ts-node, bun, etc.
```

If you'd rather not add a TS runner, the example is short enough to
read directly — it's intended as integration reference, not a
production CLI.

You'll see five scenarios, each followed by the structured audit events
the harness recorded (in addition to the human-readable log lines):

1. **Allow** — token grants the tool, no annotations escalate it. Audit
   events: `mcp.schema.pin` (first contact), `mcp.tool.decision` (allow).
2. **Deny by default** — token has no MCP scopes; default-deny fires.
3. **Broker deny override** — broker policy blocks shell tools regardless
   of token allow.
4. **Annotation escalation** — `destructiveHint` turns allow into ask.
5. **Rug-pull detection** — server changes a tool's description silently;
   TOFU pin reports drift. Audit chain: `pin → decision → drift → repin →
   decision`. The full sequence is what an incident responder would search
   for after the fact.

## Reading order

Start with `harness.ts` — the `dispatchToolCall` function is ~80 lines and
shows the full integration: schema TOFU, scope policy, annotation
escalation, audit emission. Then read `demo.ts` to see how each scenario
exercises a different check.

## Adapting to your stack

Replace the `invokeTool` stub with your actual MCP client call. Replace
the `promptHuman` stub with however your harness handles human-in-the-loop
(CLI prompt, web UI, Slack approval, etc.). Pass real `AgentToken`s minted
by your broker instance.

The harness accepts an optional `auditSink: MCPAuditSink` (defaults to
`NullAuditSink`). Wire `FileAuditSink` for production, `ConsoleAuditSink`
for stdout JSONL, or your own sink that ships events to OTel / SIEM.
`CompositeAuditSink` multiplexes to several at once.

For testing, swap `FileSchemaPinRegistry` for `MemorySchemaPinRegistry` so
each test starts with no pins. For ephemeral / containerized deployments,
swap to `HttpSchemaPinRegistry` against a registry server you operate
(see `docs/mcp-policy.md` for the HTTP contract).

Strict-mode TOFU (reject unrecognized tools entirely) is exposed via
`HarnessConfig.tofu = false` — useful when the tool set is curated and
unexpected tools should never autopin.
