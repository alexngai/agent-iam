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

You'll see five scenarios:

1. **Allow** — token grants the tool, no annotations escalate it.
2. **Deny by default** — token has no MCP scopes; default-deny fires.
3. **Broker deny override** — broker policy blocks shell tools regardless
   of token allow.
4. **Annotation escalation** — `destructiveHint` turns allow into ask.
5. **Rug-pull detection** — server changes a tool's description silently;
   TOFU pin reports drift.

## Reading order

Start with `harness.ts` — the `dispatchToolCall` function is ~40 lines and
shows the full integration. Then read `demo.ts` to see how each scenario
exercises a different check.

## Adapting to your stack

Replace the `invokeTool` stub with your actual MCP client call. Replace
the `promptHuman` stub with however your harness handles human-in-the-loop
(CLI prompt, web UI, Slack approval, etc.). Pass real `AgentToken`s minted
by your broker instance.

For testing, swap `FileSchemaPinRegistry` for `MemorySchemaPinRegistry` so
each test starts with no pins.
