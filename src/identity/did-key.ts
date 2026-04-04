/**
 * DID:key encoding/decoding for Ed25519 keys
 *
 * Implements the W3C DID:key method (did:key:z6Mk...) for Ed25519 public keys.
 * Uses multicodec prefix 0xed01 (Ed25519 public key) and base58btc multibase encoding.
 *
 * Format: did:key:z{base58btc(0xed01 + raw-32-byte-pubkey)}
 *
 * References:
 * - https://w3c-ccg.github.io/did-method-key/
 * - https://github.com/multiformats/multicodec
 */

import * as crypto from "crypto";

// Multicodec prefix for Ed25519 public key (varint-encoded 0xed)
const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);

// Base58btc alphabet (Bitcoin variant)
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode bytes to base58btc (Bitcoin alphabet).
 */
export function base58btcEncode(bytes: Buffer): string {
  // Count leading zeros
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }

  // Convert to BigInt for base conversion
  let num = BigInt("0x" + (bytes.length > 0 ? bytes.toString("hex") : "0"));
  const chars: string[] = [];

  while (num > 0n) {
    const remainder = Number(num % 58n);
    chars.unshift(BASE58_ALPHABET[remainder]);
    num = num / 58n;
  }

  // Preserve leading zeros as '1's
  return "1".repeat(leadingZeros) + chars.join("");
}

/**
 * Decode base58btc string to bytes.
 */
export function base58btcDecode(str: string): Buffer {
  // Count leading '1's (zero bytes)
  let leadingOnes = 0;
  for (const c of str) {
    if (c !== "1") break;
    leadingOnes++;
  }

  let num = 0n;
  for (const c of str) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx === -1) {
      throw new Error(`Invalid base58btc character: '${c}'`);
    }
    num = num * 58n + BigInt(idx);
  }

  // Convert BigInt to bytes
  const hex = num === 0n ? "" : num.toString(16);
  // Ensure even-length hex
  const paddedHex = hex.length % 2 === 0 ? hex : "0" + hex;
  const decoded = Buffer.from(paddedHex, "hex");

  // Prepend leading zero bytes
  return Buffer.concat([Buffer.alloc(leadingOnes), decoded]);
}

/**
 * Encode an Ed25519 public key (PEM or raw 32 bytes) as a DID:key identifier.
 *
 * @param publicKey - Ed25519 public key in PEM format or raw 32 bytes
 * @returns DID:key string (e.g., "did:key:z6Mk...")
 */
export function publicKeyToDidKey(publicKey: string | Buffer): string {
  const rawKey = extractRawPublicKey(publicKey);

  if (rawKey.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${rawKey.length} bytes`);
  }

  const multicodecKey = Buffer.concat([ED25519_MULTICODEC_PREFIX, rawKey]);
  return `did:key:z${base58btcEncode(multicodecKey)}`;
}

/**
 * Decode a DID:key identifier to extract the raw Ed25519 public key.
 *
 * @param didKey - DID:key string (e.g., "did:key:z6Mk...")
 * @returns Raw 32-byte Ed25519 public key
 */
export function didKeyToRawPublicKey(didKey: string): Buffer {
  if (!didKey.startsWith("did:key:z")) {
    throw new Error(`Invalid DID:key format: must start with "did:key:z", got "${didKey}"`);
  }

  const multibaseEncoded = didKey.slice("did:key:z".length);
  const decoded = base58btcDecode(multibaseEncoded);

  // Verify multicodec prefix
  if (decoded.length < 2 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error(
      `Invalid multicodec prefix: expected 0xed01 (Ed25519), got 0x${decoded.slice(0, 2).toString("hex")}`
    );
  }

  const rawKey = decoded.slice(2);
  if (rawKey.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key after prefix, got ${rawKey.length} bytes`);
  }

  return rawKey;
}

/**
 * Convert a raw Ed25519 public key to PEM format.
 */
export function rawPublicKeyToPem(rawKey: Buffer): string {
  const keyObj = crypto.createPublicKey({
    key: Buffer.concat([
      // Ed25519 SPKI header (12 bytes) + 32-byte key
      Buffer.from("302a300506032b6570032100", "hex"),
      rawKey,
    ]),
    format: "der",
    type: "spki",
  });
  return keyObj.export({ type: "spki", format: "pem" }) as string;
}

/**
 * Convert an Ed25519 public key (PEM) to JWK format.
 *
 * Returns: { kty: "OKP", crv: "Ed25519", x: "<base64url-raw-key>" }
 */
export function publicKeyToJwk(publicKey: string | Buffer): JsonWebKey {
  const rawKey = extractRawPublicKey(publicKey);
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: rawKey.toString("base64url"),
  };
}

/**
 * Convert a JWK to PEM format.
 */
export function jwkToPem(jwk: JsonWebKey): string {
  const keyObj = crypto.createPublicKey({ key: jwk as any, format: "jwk" });
  return keyObj.export({ type: "spki", format: "pem" }) as string;
}

/**
 * Check if a persistent ID is a DID:key format.
 */
export function isDidKey(persistentId: string): boolean {
  return persistentId.startsWith("did:key:");
}

/**
 * Check if a persistent ID is the legacy key: format.
 */
export function isLegacyKeyId(persistentId: string): boolean {
  return persistentId.startsWith("key:");
}

/**
 * Compute the legacy key: fingerprint from a PEM public key.
 * Used for backward compatibility and migration.
 */
export function computeLegacyFingerprint(publicKeyPem: string): string {
  return crypto
    .createHash("sha256")
    .update(publicKeyPem)
    .digest("hex")
    .slice(0, 32);
}

/**
 * Extract raw 32-byte Ed25519 public key from PEM or raw buffer.
 */
function extractRawPublicKey(publicKey: string | Buffer): Buffer {
  if (Buffer.isBuffer(publicKey) && publicKey.length === 32) {
    return publicKey;
  }

  const keyObj = typeof publicKey === "string"
    ? crypto.createPublicKey(publicKey)
    : crypto.createPublicKey({ key: publicKey, format: "der", type: "spki" });

  // Export as DER and strip the 12-byte SPKI header for Ed25519
  const der = keyObj.export({ type: "spki", format: "der" }) as Buffer;
  // Ed25519 SPKI is always 44 bytes: 12-byte header + 32-byte key
  return Buffer.from(der.subarray(12));
}
