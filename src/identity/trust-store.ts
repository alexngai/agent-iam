/**
 * Trust Store Implementation
 *
 * Stores behavioral attestations about agents (linked by persistentId)
 * and computes aggregate trust scores.
 *
 * Design principles (borrowing from AIR registry patterns):
 * - Multi-dimensional: separate scores per claim type, combined with weights
 * - Time-decaying: recent attestations matter more (exponential half-life)
 * - Diversity-aware: attestations from many different attesters score higher
 * - Graduated: new agents with few attestations are capped (like AIR's 30-day rule)
 * - Standalone: no external dependencies, works in-process
 *
 * Integration points:
 * - MAP event bus → createAttestation() → store.attest()
 * - Broker / IdentityVerifier → store.getTrustScore() → gate decisions
 * - CLI → store.getAttestations() → human review
 */

import * as crypto from "crypto";
import type {
  TrustAttestation,
  TrustScore,
  TrustStore,
  TrustClaimType,
} from "./types.js";

// ============================================================================
// Scoring Configuration
// ============================================================================

/**
 * Configuration for trust score computation.
 * All fields have sensible defaults — override only what you need.
 */
export interface TrustScoringConfig {
  /** Weight for each claim type (0–1). Need not sum to 1 — they are normalized. */
  weights: Partial<Record<TrustClaimType, number>>;

  /**
   * Thresholds for mapping numericScore → level.
   *   score < low        → "low"
   *   low ≤ score < high → "medium"
   *   score ≥ high       → "high"
   * Agents with zero attestations always get "unknown".
   */
  thresholds: { low: number; high: number };

  /** Half-life for exponential time decay, in days. Default: 30 */
  decayHalfLifeDays: number;

  /** Minimum non-expired attestations required before "high" is possible. Default: 5 */
  minAttestationsForHigh: number;

  /** Bonus per unique attester (added to base score). Default: 0.05 */
  diversityBonusPerAttester: number;

  /** Maximum total diversity bonus. Default: 0.15 */
  maxDiversityBonus: number;
}

export const DEFAULT_SCORING_CONFIG: TrustScoringConfig = {
  weights: {
    "task-completion": 0.30,
    "permission-compliance": 0.30,
    "security-clean": 0.20,
    "quality-score": 0.15,
    "custom": 0.05,
  },
  thresholds: { low: 0.3, high: 0.6 },
  decayHalfLifeDays: 30,
  minAttestationsForHigh: 5,
  diversityBonusPerAttester: 0.05,
  maxDiversityBonus: 0.15,
};

// ============================================================================
// Trust Scorer — pure scoring logic, no state
// ============================================================================

export class TrustScorer {
  private config: TrustScoringConfig;

  constructor(config?: Partial<TrustScoringConfig>) {
    this.config = { ...DEFAULT_SCORING_CONFIG, ...config };
    if (config?.weights) {
      this.config.weights = { ...DEFAULT_SCORING_CONFIG.weights, ...config.weights };
    }
    if (config?.thresholds) {
      this.config.thresholds = { ...DEFAULT_SCORING_CONFIG.thresholds, ...config.thresholds };
    }
  }

  /**
   * Compute a trust score from a set of attestations.
   * Attestations should already be filtered to non-expired.
   */
  computeScore(persistentId: string, attestations: TrustAttestation[]): TrustScore {
    const now = new Date();

    if (attestations.length === 0) {
      return {
        persistentId,
        level: "unknown",
        numericScore: 0,
        attestationCount: 0,
        attesterCount: 0,
        breakdown: {},
        computedAt: now.toISOString(),
      };
    }

    // Group by claim type
    const groups = new Map<string, TrustAttestation[]>();
    for (const a of attestations) {
      const key = a.claim.type;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(a);
    }

    // Score each claim type with time-weighted average
    const breakdown: TrustScore["breakdown"] = {};
    const claimScores: { type: string; score: number; weight: number }[] = [];

    for (const [type, group] of groups) {
      const { avg, count } = this.weightedAverage(group, now);
      breakdown[type] = { count, avgScore: avg };

      const weight = this.config.weights[type as TrustClaimType] ?? this.config.weights.custom ?? 0.05;
      claimScores.push({ type, score: avg, weight });
    }

    // Weighted combination of claim scores
    const totalWeight = claimScores.reduce((sum, c) => sum + c.weight, 0);
    const baseScore = totalWeight > 0
      ? claimScores.reduce((sum, c) => sum + c.score * c.weight, 0) / totalWeight
      : 0;

    // Diversity bonus: more unique attesters → higher trust
    const uniqueAttesters = new Set(attestations.map((a) => a.attesterId));
    const diversityBonus = Math.min(
      this.config.maxDiversityBonus,
      (uniqueAttesters.size - 1) * this.config.diversityBonusPerAttester,
    );

    const numericScore = Math.min(1, Math.max(0, baseScore + diversityBonus));

    // Map to level, with attestation-count cap
    const level = this.scoreToLevel(numericScore, attestations.length);

    return {
      persistentId,
      level,
      numericScore: Math.round(numericScore * 1000) / 1000, // 3 decimal places
      attestationCount: attestations.length,
      attesterCount: uniqueAttesters.size,
      breakdown,
      computedAt: now.toISOString(),
    };
  }

  /**
   * Compute time-decay weighted average of attestation values.
   * Values are coerced: number → clamp to [0,1], boolean → 0/1, else skipped.
   */
  private weightedAverage(
    attestations: TrustAttestation[],
    now: Date,
  ): { avg: number; count: number } {
    let weightedSum = 0;
    let weightSum = 0;
    let count = 0;

    for (const a of attestations) {
      const numericValue = this.coerceValue(a.claim.value);
      if (numericValue === null) continue;

      const issuedAt = new Date(a.issuedAt);
      const daysSince = (now.getTime() - issuedAt.getTime()) / (1000 * 60 * 60 * 24);
      const decayWeight = Math.pow(2, -(daysSince / this.config.decayHalfLifeDays));

      weightedSum += numericValue * decayWeight;
      weightSum += decayWeight;
      count++;
    }

    return {
      avg: weightSum > 0 ? weightedSum / weightSum : 0,
      count,
    };
  }

  /** Coerce an attestation value to a number in [0, 1], or null if not numeric. */
  private coerceValue(value: unknown): number | null {
    if (typeof value === "number") {
      return Math.max(0, Math.min(1, value));
    }
    if (typeof value === "boolean") {
      return value ? 1 : 0;
    }
    return null;
  }

  /** Map numeric score to trust level, applying the attestation-count cap. */
  private scoreToLevel(
    score: number,
    attestationCount: number,
  ): TrustScore["level"] {
    if (attestationCount === 0) return "unknown";

    // New agents (few attestations) are capped at "medium"
    // This prevents gaming by submitting a few perfect attestations
    if (attestationCount < this.config.minAttestationsForHigh && score >= this.config.thresholds.high) {
      return "medium";
    }

    if (score >= this.config.thresholds.high) return "high";
    if (score >= this.config.thresholds.low) return "medium";
    return "low";
  }
}

// ============================================================================
// In-Memory Trust Store
// ============================================================================

export interface InMemoryTrustStoreOptions {
  /** Scoring configuration */
  scoring?: Partial<TrustScoringConfig>;
}

/**
 * In-memory implementation of TrustStore.
 *
 * Suitable for single-process deployments or as a base for persistent stores.
 * For distributed deployments, the attestation data would need to be synced
 * (similar to how agent-iam's distributed module syncs revocation lists).
 */
export class InMemoryTrustStore implements TrustStore {
  private attestations = new Map<string, TrustAttestation[]>();
  private scorer: TrustScorer;

  constructor(options?: InMemoryTrustStoreOptions) {
    this.scorer = new TrustScorer(options?.scoring);
  }

  async attest(attestation: TrustAttestation): Promise<void> {
    const { subjectId } = attestation;
    if (!this.attestations.has(subjectId)) {
      this.attestations.set(subjectId, []);
    }
    this.attestations.get(subjectId)!.push(attestation);
  }

  async getAttestations(persistentId: string): Promise<TrustAttestation[]> {
    const all = this.attestations.get(persistentId) ?? [];
    const now = new Date();
    return all.filter((a) => !a.expiresAt || new Date(a.expiresAt) > now);
  }

  async getTrustScore(persistentId: string): Promise<TrustScore> {
    const active = await this.getAttestations(persistentId);
    return this.scorer.computeScore(persistentId, active);
  }

  async pruneExpired(): Promise<number> {
    let pruned = 0;
    const now = new Date();

    for (const [id, list] of this.attestations) {
      const before = list.length;
      const active = list.filter((a) => !a.expiresAt || new Date(a.expiresAt) > now);
      pruned += before - active.length;

      if (active.length === 0) {
        this.attestations.delete(id);
      } else {
        this.attestations.set(id, active);
      }
    }

    return pruned;
  }

  /** Return the number of agents tracked (for diagnostics). */
  get agentCount(): number {
    return this.attestations.size;
  }
}

// ============================================================================
// Attestation Helpers
// ============================================================================

/**
 * Create a signed TrustAttestation.
 *
 * The signature is an HMAC-SHA256 over the canonical attestation fields,
 * consistent with agent-iam's token signing approach.
 */
export function createAttestation(params: {
  subjectId: string;
  claimType: TrustClaimType;
  claimValue: number | boolean;
  claimContext?: string;
  attesterId: string;
  secret: string;
  expiresInDays?: number;
}): TrustAttestation {
  const now = new Date();
  const attestationId = crypto.randomUUID();

  const attestation: TrustAttestation = {
    attestationId,
    subjectId: params.subjectId,
    claim: {
      type: params.claimType,
      value: params.claimValue,
      ...(params.claimContext && { context: params.claimContext }),
    },
    attesterId: params.attesterId,
    issuedAt: now.toISOString(),
    ...(params.expiresInDays && {
      expiresAt: new Date(
        now.getTime() + params.expiresInDays * 24 * 60 * 60 * 1000,
      ).toISOString(),
    }),
    signature: "", // placeholder — computed below
  };

  attestation.signature = signAttestation(attestation, params.secret);
  return attestation;
}

/**
 * HMAC-SHA256 signature over canonical attestation fields.
 * Covers: subjectId, claim, attesterId, issuedAt, expiresAt.
 */
export function signAttestation(
  attestation: TrustAttestation,
  secret: string,
): string {
  const payload = JSON.stringify({
    attestationId: attestation.attestationId,
    subjectId: attestation.subjectId,
    claim: attestation.claim,
    attesterId: attestation.attesterId,
    issuedAt: attestation.issuedAt,
    expiresAt: attestation.expiresAt ?? null,
  });
  return crypto.createHmac("sha256", secret).update(payload).digest("base64url");
}

/**
 * Verify an attestation's HMAC signature.
 */
export function verifyAttestation(
  attestation: TrustAttestation,
  secret: string,
): boolean {
  const expected = signAttestation(attestation, secret);
  return crypto.timingSafeEqual(
    Buffer.from(attestation.signature),
    Buffer.from(expected),
  );
}
