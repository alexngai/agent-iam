/**
 * Broker MCP Signing Key Management
 *
 * Ed25519 keypair the broker uses to sign RFC 8707 audience-bound
 * credentials (issueMCPCredential). The key is generated lazily on first
 * use and stored beside the existing token-signing secret.
 *
 * Storage layout (matches src/identity/keypair-provider.ts conventions):
 *   {configDir}/mcp-signing.key   PEM PKCS8 private key, mode 0o600
 *   {configDir}/mcp-signing.pub   PEM SPKI public key
 *
 * The public key is also exportable as a JWK (RFC 7517) for distribution
 * via JWKS endpoints to MCP servers that need to verify our credentials.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { exportJWK, importSPKI } from "jose";

const PRIVATE_KEY_FILE = "mcp-signing.key";
const PUBLIC_KEY_FILE = "mcp-signing.pub";

/** A broker MCP signing keypair on disk. */
export interface MCPSigningKey {
  /** PEM PKCS8 private key (sign with this). */
  privateKey: string;
  /** PEM SPKI public key (publish via JWKS). */
  publicKey: string;
}

/**
 * Load the broker's MCP signing keypair from disk, generating one on
 * first call. The private key is written with mode 0o600.
 */
export function getOrCreateMCPSigningKey(configDir: string): MCPSigningKey {
  const privPath = path.join(configDir, PRIVATE_KEY_FILE);
  const pubPath = path.join(configDir, PUBLIC_KEY_FILE);

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    return {
      privateKey: fs.readFileSync(privPath, "utf8"),
      publicKey: fs.readFileSync(pubPath, "utf8"),
    };
  }

  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  // Unlink any pre-existing files first: `fs.writeFileSync(..., { mode })`
  // only applies the mode at *creation* time. Writing into a pre-existing
  // file with mode 0o644 leaves the previous mode intact, which would let
  // a hostile pre-creation force a 0o600 keypair to land at 0o644.
  if (fs.existsSync(privPath)) fs.unlinkSync(privPath);
  if (fs.existsSync(pubPath)) fs.unlinkSync(pubPath);

  fs.writeFileSync(privPath, privateKey as string, { mode: 0o600 });
  // Belt-and-braces: explicit chmod in case the FS umask altered the mode.
  fs.chmodSync(privPath, 0o600);
  fs.writeFileSync(pubPath, publicKey as string);

  return {
    privateKey: privateKey as string,
    publicKey: publicKey as string,
  };
}

/**
 * Convert a PEM-encoded SPKI public key to a JWK (RFC 7517).
 * Adds `use: "sig"`, `alg: "EdDSA"`, and a deterministic `kid` derived
 * from the SHA-256 of the canonical key bytes.
 */
export async function publicKeyToJwk(publicKeyPem: string): Promise<{
  kty: string;
  alg: string;
  use: string;
  kid: string;
  crv?: string;
  x?: string;
}> {
  const key = await importSPKI(publicKeyPem, "EdDSA", { extractable: true });
  const jwk = (await exportJWK(key)) as { kty: string; crv?: string; x?: string };
  // Deterministic kid: hash of the public key bytes (lowercase hex, first 16).
  const kid = crypto
    .createHash("sha256")
    .update(publicKeyPem)
    .digest("hex")
    .slice(0, 16);
  return {
    ...jwk,
    alg: "EdDSA",
    use: "sig",
    kid,
  };
}

/**
 * Build a JWKS document (RFC 7517) containing the broker's MCP public key.
 * The MCP server fetches this (e.g. from a `/.well-known/jwks.json` URL)
 * to verify credentials we issue with `issueMCPCredential`.
 */
export async function publicKeyToJwks(publicKeyPem: string): Promise<{
  keys: Array<{ kty: string; alg: string; use: string; kid: string }>;
}> {
  const jwk = await publicKeyToJwk(publicKeyPem);
  return { keys: [jwk] };
}
