# Agent Instructions

Agent IAM is a capability-based credential broker for AI agents: HMAC-signed
tokens define scopes/constraints with hierarchical delegation (attenuation
only — delegation can narrow but never widen permissions), plus a pluggable
persistent identity system (Ed25519 keypair, platform, SPIFFE, or DID) kept
separate from capability. Includes MCP tool-access control (schema-pin TOFU,
allow/deny scopes, RFC 8707 audience-bound credentials) and a leader/follower
distributed mode.

## Build & Test

```bash
npm install
npm run build   # compile TypeScript (tsc) — required before npm test
npm test        # node:test against compiled dist/*.test.js
npm run cli -- ...
```

## Top Conventions

- Main entry point for most operations is `Broker` (`src/broker.ts`).
- Identity ("who you are") and scopes ("what you can do") are separate but
  composable fields on `AgentToken` — don't conflate them.
- Config/keys live under `~/.agent-credentials/` (override with
  `AGENT_IAM_HOME`); private keys use mode `0o600`, dirs `0o700`.
- Tokens pass between processes via the `AGENT_TOKEN` env var.

See `CLAUDE.md` for the full guide.
