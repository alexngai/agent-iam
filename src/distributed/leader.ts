/**
 * Leader broker that accepts follower syncs
 *
 * Extends base functionality with:
 * - HTTP server for sync endpoints
 * - WebSocket for push notifications
 * - Follower tracking
 * - Key rotation
 */

import * as http from "http";
import * as https from "https";
import * as fs from "fs";
import type { Broker } from "../broker.js";
import type { AgentToken } from "../types.js";
import { SigningKeyManager } from "./signing-keys.js";
import { RevocationList } from "./revocation.js";
import {
  BrokerMode,
  PushMessageType,
  type LeaderConfig,
  type SyncRequest,
  type SyncResponse,
  type FollowerInfo,
  type DistributedStatus,
  type PushMessage,
} from "./types.js";

/** Default configuration values */
const DEFAULT_PORT = 8443;
const DEFAULT_HOST = "0.0.0.0";
const DEFAULT_SYNC_INTERVAL = 60; // seconds

/** Connected WebSocket clients for push notifications */
interface WebSocketClient {
  followerId: string;
  send: (data: string) => void;
  close: () => void;
}

export class LeaderServer {
  private broker: Broker;
  private config: LeaderConfig;
  private configDir: string;
  private server: http.Server | https.Server | null = null;
  private signingKeyManager: SigningKeyManager;
  private revocationList: RevocationList;
  private providerConfigsVersion: number = 1;
  private followers: Map<string, FollowerInfo> = new Map();
  private wsClients: Map<string, WebSocketClient> = new Map();

  constructor(broker: Broker, configDir: string, config: LeaderConfig) {
    this.broker = broker;
    this.config = config;
    this.configDir = configDir;
    this.signingKeyManager = new SigningKeyManager(configDir);
    this.revocationList = new RevocationList(configDir);
  }

  /**
   * Start the leader HTTP server
   */
  async start(): Promise<void> {
    const port = this.config.port ?? DEFAULT_PORT;
    const host = this.config.host ?? DEFAULT_HOST;

    // Ensure signing key is initialized
    this.signingKeyManager.getCurrentKey();

    // Create request handler
    const handler = this.createRequestHandler();

    // Create server (HTTPS if certs provided, HTTP otherwise)
    if (this.config.tlsCertPath && this.config.tlsKeyPath) {
      const cert = fs.readFileSync(this.config.tlsCertPath);
      const key = fs.readFileSync(this.config.tlsKeyPath);
      this.server = https.createServer({ cert, key }, handler);
    } else {
      this.server = http.createServer(handler);
    }

    // Start listening
    return new Promise((resolve, reject) => {
      this.server!.on("error", reject);
      this.server!.listen(port, host, () => {
        console.log(`Leader server listening on ${host}:${port}`);
        resolve();
      });
    });
  }

  /**
   * Stop the leader server
   */
  async stop(): Promise<void> {
    if (!this.server) return;

    // Close all WebSocket connections
    for (const client of this.wsClients.values()) {
      client.close();
    }
    this.wsClients.clear();

    return new Promise((resolve) => {
      this.server!.close(() => {
        this.server = null;
        resolve();
      });
    });
  }

  /**
   * Revoke a token and push to followers
   */
  async revokeToken(
    token: AgentToken,
    reason?: string
  ): Promise<void> {
    this.revocationList.revoke({
      tokenId: token.agentId,
      agentId: token.agentId,
      reason,
    });

    // Push to all connected followers
    this.pushToFollowers({
      type: PushMessageType.REVOCATION,
      timestamp: new Date().toISOString(),
      data: {
        tokenId: token.agentId,
        reason,
        revokedAt: new Date().toISOString(),
      },
    });
  }

  /**
   * Rotate the signing key and push to followers
   */
  async rotateSigningKey(): Promise<{ version: number }> {
    const { key, version } = this.signingKeyManager.rotate();

    // Push to all connected followers
    this.pushToFollowers({
      type: PushMessageType.KEY_ROTATION,
      timestamp: new Date().toISOString(),
      data: {
        newKeyVersion: version,
        newKey: key.toString("base64"),
      },
    });

    return { version };
  }

  /**
   * Check if a token is revoked
   */
  isRevoked(tokenId: string): boolean {
    return this.revocationList.isRevoked(tokenId);
  }

  /**
   * Get the signing key manager
   */
  getSigningKeyManager(): SigningKeyManager {
    return this.signingKeyManager;
  }

  /**
   * Get the revocation list
   */
  getRevocationList(): RevocationList {
    return this.revocationList;
  }

  /**
   * Get leader status
   */
  getStatus(): DistributedStatus {
    return {
      mode: BrokerMode.LEADER,
      signingKeyVersion: this.signingKeyManager.getCurrentVersion(),
      providerConfigsVersion: this.providerConfigsVersion,
      revocationCount: this.revocationList.count(),
      followerCount: this.followers.size,
      followers: Array.from(this.followers.keys()),
    };
  }

  /**
   * Create the HTTP request handler
   */
  private createRequestHandler(): http.RequestListener {
    return async (req, res) => {
      // Set CORS headers
      res.setHeader("Content-Type", "application/json");

      try {
        // Authenticate request
        const authHeader = req.headers.authorization;
        if (!this.authenticateRequest(authHeader)) {
          res.statusCode = 401;
          res.end(JSON.stringify({ error: "Unauthorized" }));
          return;
        }

        // Route request
        const url = new URL(req.url ?? "/", `http://${req.headers.host}`);

        if (req.method === "POST" && url.pathname === "/sync") {
          await this.handleSync(req, res);
        } else if (req.method === "GET" && url.pathname === "/status") {
          this.handleStatus(res);
        } else if (req.method === "POST" && url.pathname === "/rotate-key") {
          await this.handleRotateKey(res);
        } else if (req.method === "POST" && url.pathname.startsWith("/revoke/")) {
          await this.handleRevoke(req, res, url.pathname);
        } else {
          res.statusCode = 404;
          res.end(JSON.stringify({ error: "Not found" }));
        }
      } catch (error) {
        res.statusCode = 500;
        res.end(
          JSON.stringify({
            error: error instanceof Error ? error.message : "Internal error",
          })
        );
      }
    };
  }

  /**
   * Authenticate a request using bearer token
   */
  private authenticateRequest(authHeader: string | undefined): boolean {
    if (!authHeader) return false;

    const [scheme, token] = authHeader.split(" ");
    if (scheme?.toLowerCase() !== "bearer") return false;

    return token === this.config.followerAuthToken;
  }

  /**
   * Handle sync request from follower
   */
  private async handleSync(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    const body = await this.readBody(req);
    const syncRequest = JSON.parse(body) as SyncRequest;

    // Update follower tracking
    this.followers.set(syncRequest.followerId, {
      followerId: syncRequest.followerId,
      lastSyncAt: new Date().toISOString(),
      signingKeyVersion: syncRequest.signingKeyVersion,
      providerConfigsVersion: syncRequest.providerConfigsVersion,
      revocationListVersion: syncRequest.revocationListVersion,
      ipAddress: req.socket.remoteAddress,
    });

    // Build sync response
    const response: SyncResponse = {
      signingKeyVersion: this.signingKeyManager.getCurrentVersion(),
      providerConfigsVersion: this.providerConfigsVersion,
      revocationListDelta: this.revocationList.getRevocationsSince(
        syncRequest.revocationListVersion
      ),
      revocationListVersion: this.revocationList.getVersion(),
      nextSyncSeconds: DEFAULT_SYNC_INTERVAL,
      leaderTimestamp: new Date().toISOString(),
    };

    // Include signing key if follower needs it
    if (syncRequest.signingKeyVersion < this.signingKeyManager.getCurrentVersion()) {
      response.signingKey = this.signingKeyManager.exportCurrentKey();
    }

    // Include provider configs if changed
    if (syncRequest.providerConfigsVersion < this.providerConfigsVersion) {
      response.providerConfigs = this.broker.showConfig().providers as Record<string, unknown>;
    }

    res.statusCode = 200;
    res.end(JSON.stringify(response));
  }

  /**
   * Handle status request
   */
  private handleStatus(res: http.ServerResponse): void {
    res.statusCode = 200;
    res.end(JSON.stringify(this.getStatus()));
  }

  /**
   * Handle key rotation request
   */
  private async handleRotateKey(res: http.ServerResponse): Promise<void> {
    const { version } = await this.rotateSigningKey();
    res.statusCode = 200;
    res.end(JSON.stringify({ version }));
  }

  /**
   * Handle token revocation request
   */
  private async handleRevoke(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    pathname: string
  ): Promise<void> {
    const tokenId = pathname.replace("/revoke/", "");
    const body = await this.readBody(req);
    const { reason } = JSON.parse(body || "{}") as { reason?: string };

    this.revocationList.revoke({
      tokenId,
      agentId: tokenId,
      reason,
    });

    // Push to followers
    this.pushToFollowers({
      type: PushMessageType.REVOCATION,
      timestamp: new Date().toISOString(),
      data: {
        tokenId,
        reason,
        revokedAt: new Date().toISOString(),
      },
    });

    res.statusCode = 200;
    res.end(JSON.stringify({ revoked: true }));
  }

  /**
   * Read request body
   */
  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => resolve(Buffer.concat(chunks).toString()));
      req.on("error", reject);
    });
  }

  /**
   * Push a message to all connected followers
   */
  private pushToFollowers(message: PushMessage): void {
    const data = JSON.stringify(message);
    for (const client of this.wsClients.values()) {
      try {
        client.send(data);
      } catch {
        // Client disconnected, will be cleaned up
      }
    }
  }

  /**
   * Increment provider configs version (call after config changes)
   */
  incrementConfigVersion(): void {
    this.providerConfigsVersion++;
  }
}
