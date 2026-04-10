/**
 * Tests for TrustStore, TrustScorer, and attestation helpers
 */

import { test, describe } from "node:test";
import * as assert from "node:assert";
import {
  InMemoryTrustStore,
  TrustScorer,
  createAttestation,
  signAttestation,
  verifyAttestation,
  DEFAULT_SCORING_CONFIG,
} from "./trust-store.js";
import type { TrustAttestation } from "./types.js";

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

const SECRET = "test-secret-key-for-trust-attestations";
const AGENT_A = "did:key:z6MkAgent_A";
const AGENT_B = "did:key:z6MkAgent_B";
const SYSTEM = "map-system-1";

function makeAttestation(overrides: Partial<{
  subjectId: string;
  claimType: TrustAttestation["claim"]["type"];
  claimValue: number | boolean;
  claimContext: string;
  attesterId: string;
  issuedAt: string;
  expiresAt: string;
}> = {}): TrustAttestation {
  return createAttestation({
    subjectId: overrides.subjectId ?? AGENT_A,
    claimType: overrides.claimType ?? "task-completion",
    claimValue: overrides.claimValue ?? 0.9,
    claimContext: overrides.claimContext,
    attesterId: overrides.attesterId ?? SYSTEM,
    secret: SECRET,
    ...("issuedAt" in overrides || "expiresAt" in overrides
      ? {}
      : { expiresInDays: 90 }),
  });
}

/** Create an attestation with a specific issuedAt date (for decay tests). */
function makeAgedAttestation(daysAgo: number, value: number = 0.8): TrustAttestation {
  const issuedAt = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
  const a = makeAttestation({ claimValue: value });
  a.issuedAt = issuedAt.toISOString();
  // Re-sign after modifying issuedAt
  a.signature = signAttestation(a, SECRET);
  return a;
}

// ─────────────────────────────────────────────────────────────────
// ATTESTATION HELPERS
// ─────────────────────────────────────────────────────────────────

describe("createAttestation", () => {
  test("creates a well-formed attestation", () => {
    const a = createAttestation({
      subjectId: AGENT_A,
      claimType: "task-completion",
      claimValue: 0.95,
      claimContext: "task:code-review",
      attesterId: SYSTEM,
      secret: SECRET,
      expiresInDays: 30,
    });

    assert.ok(a.attestationId, "has attestationId");
    assert.strictEqual(a.subjectId, AGENT_A);
    assert.strictEqual(a.claim.type, "task-completion");
    assert.strictEqual(a.claim.value, 0.95);
    assert.strictEqual(a.claim.context, "task:code-review");
    assert.strictEqual(a.attesterId, SYSTEM);
    assert.ok(a.issuedAt);
    assert.ok(a.expiresAt);
    assert.ok(a.signature);
  });

  test("signature is verifiable", () => {
    const a = createAttestation({
      subjectId: AGENT_A,
      claimType: "security-clean",
      claimValue: true,
      attesterId: SYSTEM,
      secret: SECRET,
    });

    assert.strictEqual(verifyAttestation(a, SECRET), true);
    assert.strictEqual(verifyAttestation(a, "wrong-secret"), false);
  });

  test("tampered attestation fails verification", () => {
    const a = createAttestation({
      subjectId: AGENT_A,
      claimType: "quality-score",
      claimValue: 0.5,
      attesterId: SYSTEM,
      secret: SECRET,
    });

    // Tamper with the claim value
    (a.claim as { value: unknown }).value = 1.0;
    assert.strictEqual(verifyAttestation(a, SECRET), false);
  });

  test("omits expiresAt when expiresInDays not provided", () => {
    const a = createAttestation({
      subjectId: AGENT_A,
      claimType: "task-completion",
      claimValue: 0.8,
      attesterId: SYSTEM,
      secret: SECRET,
    });

    assert.strictEqual(a.expiresAt, undefined);
  });
});

// ─────────────────────────────────────────────────────────────────
// TRUST SCORER
// ─────────────────────────────────────────────────────────────────

describe("TrustScorer", () => {
  test("returns unknown for zero attestations", () => {
    const scorer = new TrustScorer();
    const score = scorer.computeScore(AGENT_A, []);

    assert.strictEqual(score.level, "unknown");
    assert.strictEqual(score.numericScore, 0);
    assert.strictEqual(score.attestationCount, 0);
    assert.strictEqual(score.attesterCount, 0);
  });

  test("computes score from single claim type", () => {
    const scorer = new TrustScorer();
    const attestations = [
      makeAttestation({ claimType: "task-completion", claimValue: 0.8 }),
      makeAttestation({ claimType: "task-completion", claimValue: 0.9 }),
    ];

    const score = scorer.computeScore(AGENT_A, attestations);

    assert.strictEqual(score.attestationCount, 2);
    assert.ok(score.numericScore > 0, "should have a positive score");
    assert.ok(score.breakdown["task-completion"], "should have task-completion breakdown");
    assert.strictEqual(score.breakdown["task-completion"].count, 2);
  });

  test("computes weighted average across claim types", () => {
    const scorer = new TrustScorer({
      weights: {
        "task-completion": 0.5,
        "permission-compliance": 0.5,
      },
    });

    const attestations = [
      makeAttestation({ claimType: "task-completion", claimValue: 1.0 }),
      makeAttestation({ claimType: "permission-compliance", claimValue: 0.0 }),
    ];

    const score = scorer.computeScore(AGENT_A, attestations);

    // With equal weights and values 1.0 and 0.0, score ≈ 0.5
    assert.ok(score.numericScore >= 0.45 && score.numericScore <= 0.55,
      `Expected ~0.5, got ${score.numericScore}`);
  });

  test("applies diversity bonus for multiple attesters", () => {
    const scorer = new TrustScorer({
      diversityBonusPerAttester: 0.1,
      maxDiversityBonus: 0.3,
    });

    // Same values, different attesters
    const singleAttester = [
      makeAttestation({ claimType: "task-completion", claimValue: 0.5, attesterId: "attester-1" }),
      makeAttestation({ claimType: "task-completion", claimValue: 0.5, attesterId: "attester-1" }),
    ];
    const multiAttester = [
      makeAttestation({ claimType: "task-completion", claimValue: 0.5, attesterId: "attester-1" }),
      makeAttestation({ claimType: "task-completion", claimValue: 0.5, attesterId: "attester-2" }),
      makeAttestation({ claimType: "task-completion", claimValue: 0.5, attesterId: "attester-3" }),
    ];

    const singleScore = scorer.computeScore(AGENT_A, singleAttester);
    const multiScore = scorer.computeScore(AGENT_A, multiAttester);

    assert.ok(multiScore.numericScore > singleScore.numericScore,
      `Diversity bonus: ${multiScore.numericScore} should be > ${singleScore.numericScore}`);
    assert.strictEqual(multiScore.attesterCount, 3);
    assert.strictEqual(singleScore.attesterCount, 1);
  });

  test("caps new agents at medium trust", () => {
    const scorer = new TrustScorer({
      minAttestationsForHigh: 5,
    });

    // Only 3 attestations, all perfect
    const few = Array.from({ length: 3 }, () =>
      makeAttestation({ claimType: "task-completion", claimValue: 1.0 }),
    );

    const score = scorer.computeScore(AGENT_A, few);

    // High numeric score, but capped at "medium" due to few attestations
    assert.ok(score.numericScore >= 0.6, `Expected high numeric score, got ${score.numericScore}`);
    assert.strictEqual(score.level, "medium",
      "Should be capped at medium with < minAttestationsForHigh");
  });

  test("allows high trust with enough attestations", () => {
    const scorer = new TrustScorer({
      minAttestationsForHigh: 5,
    });

    // 6 perfect attestations
    const enough = Array.from({ length: 6 }, () =>
      makeAttestation({ claimType: "task-completion", claimValue: 1.0 }),
    );

    const score = scorer.computeScore(AGENT_A, enough);
    assert.strictEqual(score.level, "high");
  });

  test("time decay reduces weight of old attestations", () => {
    const scorer = new TrustScorer({ decayHalfLifeDays: 30 });

    // Recent high score
    const recent = [makeAgedAttestation(1, 0.9)];
    const recentScore = scorer.computeScore(AGENT_A, recent);

    // Old high score (90 days = 3 half-lives → weight ≈ 0.125)
    const old = [makeAgedAttestation(90, 0.9)];
    const oldScore = scorer.computeScore(AGENT_A, old);

    // Both should still get the same average (single value),
    // but when mixed, recent should dominate
    const mixed = [makeAgedAttestation(1, 0.9), makeAgedAttestation(90, 0.1)];
    const mixedScore = scorer.computeScore(AGENT_A, mixed);

    // Mixed score should be closer to the recent value (0.9) than the old (0.1)
    assert.ok(mixedScore.numericScore > 0.6,
      `Expected recent to dominate: got ${mixedScore.numericScore}`);
  });

  test("boolean values are coerced correctly", () => {
    const scorer = new TrustScorer();
    const attestations = [
      makeAttestation({ claimType: "security-clean", claimValue: true }),
      makeAttestation({ claimType: "security-clean", claimValue: true }),
    ];

    const score = scorer.computeScore(AGENT_A, attestations);
    assert.ok(score.breakdown["security-clean"]);
    // true → 1.0, so average should be 1.0
    assert.strictEqual(score.breakdown["security-clean"].avgScore, 1);
  });

  test("maps score to correct levels", () => {
    const scorer = new TrustScorer({
      thresholds: { low: 0.3, high: 0.7 },
      minAttestationsForHigh: 1,
    });

    const lowScore = scorer.computeScore(AGENT_A, [
      makeAttestation({ claimValue: 0.1 }),
    ]);
    assert.strictEqual(lowScore.level, "low");

    const mediumScore = scorer.computeScore(AGENT_A, [
      makeAttestation({ claimValue: 0.5 }),
    ]);
    assert.strictEqual(mediumScore.level, "medium");

    const highScore = scorer.computeScore(AGENT_A, [
      makeAttestation({ claimValue: 0.9 }),
    ]);
    assert.strictEqual(highScore.level, "high");
  });

  test("values are clamped to [0, 1]", () => {
    const scorer = new TrustScorer({ minAttestationsForHigh: 1 });
    // Value > 1 should be clamped
    const attestations = [makeAttestation({ claimValue: 5.0 as unknown as number })];
    const score = scorer.computeScore(AGENT_A, attestations);
    assert.ok(score.numericScore <= 1, `Score should be <= 1, got ${score.numericScore}`);
  });

  test("numericScore capped at 1 even with diversity bonus", () => {
    const scorer = new TrustScorer({
      diversityBonusPerAttester: 0.5,
      maxDiversityBonus: 0.5,
      minAttestationsForHigh: 1,
    });
    const attestations = [
      makeAttestation({ claimValue: 0.9, attesterId: "a" }),
      makeAttestation({ claimValue: 0.9, attesterId: "b" }),
      makeAttestation({ claimValue: 0.9, attesterId: "c" }),
    ];
    const score = scorer.computeScore(AGENT_A, attestations);
    assert.ok(score.numericScore <= 1, `Score should be <= 1, got ${score.numericScore}`);
  });
});

// ─────────────────────────────────────────────────────────────────
// IN-MEMORY TRUST STORE
// ─────────────────────────────────────────────────────────────────

describe("InMemoryTrustStore", () => {
  test("stores and retrieves attestations", async () => {
    const store = new InMemoryTrustStore();
    const a1 = makeAttestation({ claimType: "task-completion", claimValue: 0.9 });
    const a2 = makeAttestation({ claimType: "permission-compliance", claimValue: 0.8 });

    await store.attest(a1);
    await store.attest(a2);

    const attestations = await store.getAttestations(AGENT_A);
    assert.strictEqual(attestations.length, 2);
  });

  test("returns empty for unknown agent", async () => {
    const store = new InMemoryTrustStore();
    const attestations = await store.getAttestations("unknown-agent");
    assert.strictEqual(attestations.length, 0);
  });

  test("filters out expired attestations on read", async () => {
    const store = new InMemoryTrustStore();

    // Active attestation
    const active = makeAttestation({ claimValue: 0.9 });

    // Expired attestation
    const expired = makeAttestation({ claimValue: 0.5 });
    expired.expiresAt = new Date(Date.now() - 1000).toISOString(); // expired 1s ago

    await store.attest(active);
    await store.attest(expired);

    const attestations = await store.getAttestations(AGENT_A);
    assert.strictEqual(attestations.length, 1);
    assert.strictEqual(attestations[0].attestationId, active.attestationId);
  });

  test("computes trust score", async () => {
    const store = new InMemoryTrustStore();

    for (let i = 0; i < 6; i++) {
      await store.attest(makeAttestation({
        claimType: "task-completion",
        claimValue: 0.85,
      }));
    }

    const score = await store.getTrustScore(AGENT_A);
    assert.strictEqual(score.persistentId, AGENT_A);
    assert.strictEqual(score.attestationCount, 6);
    assert.ok(score.numericScore > 0);
    assert.ok(["medium", "high"].includes(score.level));
  });

  test("returns unknown for agent with no attestations", async () => {
    const store = new InMemoryTrustStore();
    const score = await store.getTrustScore(AGENT_A);
    assert.strictEqual(score.level, "unknown");
    assert.strictEqual(score.numericScore, 0);
  });

  test("prunes expired attestations", async () => {
    const store = new InMemoryTrustStore();

    // Active
    await store.attest(makeAttestation({ claimValue: 0.9 }));

    // Expired
    const expired = makeAttestation({ claimValue: 0.5 });
    expired.expiresAt = new Date(Date.now() - 1000).toISOString();
    await store.attest(expired);

    const pruned = await store.pruneExpired();
    assert.strictEqual(pruned, 1);

    // Only the active one remains
    const attestations = await store.getAttestations(AGENT_A);
    assert.strictEqual(attestations.length, 1);
  });

  test("prunes removes empty agent entries", async () => {
    const store = new InMemoryTrustStore();

    const expired = makeAttestation({ claimValue: 0.5 });
    expired.expiresAt = new Date(Date.now() - 1000).toISOString();
    await store.attest(expired);

    assert.strictEqual(store.agentCount, 1);
    await store.pruneExpired();
    assert.strictEqual(store.agentCount, 0);
  });

  test("isolates attestations between agents", async () => {
    const store = new InMemoryTrustStore();

    await store.attest(makeAttestation({ subjectId: AGENT_A, claimValue: 0.9 }));
    await store.attest(makeAttestation({ subjectId: AGENT_B, claimValue: 0.3 }));

    const scoreA = await store.getTrustScore(AGENT_A);
    const scoreB = await store.getTrustScore(AGENT_B);

    assert.ok(scoreA.numericScore > scoreB.numericScore,
      `Agent A (${scoreA.numericScore}) should outscore Agent B (${scoreB.numericScore})`);
  });

  test("accepts custom scoring config", async () => {
    const store = new InMemoryTrustStore({
      scoring: {
        thresholds: { low: 0.1, high: 0.2 },
        minAttestationsForHigh: 1,
      },
    });

    await store.attest(makeAttestation({ claimValue: 0.5 }));

    const score = await store.getTrustScore(AGENT_A);
    assert.strictEqual(score.level, "high",
      `With low threshold, 0.5 should be high, got ${score.level}`);
  });

  test("multi-dimensional scoring with mixed claim types", async () => {
    const store = new InMemoryTrustStore({
      scoring: { minAttestationsForHigh: 1 },
    });

    // Good at tasks, bad at permissions
    await store.attest(makeAttestation({ claimType: "task-completion", claimValue: 0.95 }));
    await store.attest(makeAttestation({ claimType: "permission-compliance", claimValue: 0.1 }));
    await store.attest(makeAttestation({ claimType: "security-clean", claimValue: true }));

    const score = await store.getTrustScore(AGENT_A);

    // Should have breakdown for all three types
    assert.ok(score.breakdown["task-completion"]);
    assert.ok(score.breakdown["permission-compliance"]);
    assert.ok(score.breakdown["security-clean"]);

    // Score should reflect the mix (not just one dimension)
    assert.ok(score.numericScore > 0.3 && score.numericScore < 0.9,
      `Mixed score should be moderate, got ${score.numericScore}`);
  });
});
