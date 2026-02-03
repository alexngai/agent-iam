/**
 * AWS STS provider adapter
 *
 * Uses AWS credentials to assume IAM roles and issue temporary credentials.
 * Supports both direct credential configuration and profile-based auth.
 */

import type { CredentialResult } from "../types.js";

/** AWS permission policy mapping from our scopes */
const SCOPE_TO_POLICY: Record<string, object> = {
  "aws:s3:read": {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
        Resource: "*",
      },
    ],
  },
  "aws:s3:write": {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
        Resource: "*",
      },
    ],
  },
  "aws:dynamodb:read": {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:DescribeTable"],
        Resource: "*",
      },
    ],
  },
  "aws:dynamodb:write": {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
        ],
        Resource: "*",
      },
    ],
  },
  "aws:lambda:invoke": {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["lambda:InvokeFunction"],
        Resource: "*",
      },
    ],
  },
  "aws:sqs:read": {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["sqs:ReceiveMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"],
        Resource: "*",
      },
    ],
  },
  "aws:sqs:write": {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["sqs:SendMessage", "sqs:DeleteMessage", "sqs:ReceiveMessage"],
        Resource: "*",
      },
    ],
  },
  "aws:sns:publish": {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["sns:Publish"],
        Resource: "*",
      },
    ],
  },
};

/** AWS provider configuration */
export interface AWSProviderConfig {
  /** AWS region */
  region: string;
  /** IAM Role ARN to assume */
  roleArn: string;
  /** External ID for role assumption (optional) */
  externalId?: string;
  /** Session duration in seconds (default: 3600) */
  sessionDuration?: number;
  /** AWS access key ID (optional, uses default credential chain if not provided) */
  accessKeyId?: string;
  /** AWS secret access key (optional) */
  secretAccessKey?: string;
}

/** AWS STS AssumeRole response */
interface AssumeRoleResponse {
  AssumeRoleResponse: {
    AssumeRoleResult: {
      Credentials: {
        AccessKeyId: string;
        SecretAccessKey: string;
        SessionToken: string;
        Expiration: string;
      };
      AssumedRoleUser: {
        Arn: string;
        AssumedRoleId: string;
      };
    };
  };
}

/** AWS credentials from environment or config */
interface AWSCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export class AWSProvider {
  private config: AWSProviderConfig;

  constructor(config: AWSProviderConfig) {
    this.config = config;
  }

  /**
   * Issue AWS temporary credentials by assuming a role
   *
   * @param scope - The scope requested (e.g., "aws:s3:read")
   * @param resource - Resource pattern (e.g., "my-bucket/*")
   */
  async issueCredential(scope: string, resource: string): Promise<CredentialResult> {
    const policy = this.scopeToPolicy(scope, resource);
    const sessionDuration = this.config.sessionDuration ?? 3600;

    const credentials = await this.assumeRole(
      `agent-iam-${Date.now()}`,
      policy,
      sessionDuration
    );

    return {
      credentialType: "aws_credentials",
      credential: {
        accessKeyId: credentials.accessKeyId,
        secretAccessKey: credentials.secretAccessKey,
        sessionToken: credentials.sessionToken,
        region: this.config.region,
      },
      expiresAt: credentials.expiration,
    };
  }

  /**
   * Assume an IAM role using STS
   */
  private async assumeRole(
    sessionName: string,
    policy: object | null,
    durationSeconds: number
  ): Promise<{
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken: string;
    expiration: string;
  }> {
    const baseCreds = this.getBaseCredentials();

    const params = new URLSearchParams({
      Action: "AssumeRole",
      Version: "2011-06-15",
      RoleArn: this.config.roleArn,
      RoleSessionName: sessionName,
      DurationSeconds: durationSeconds.toString(),
    });

    if (this.config.externalId) {
      params.set("ExternalId", this.config.externalId);
    }

    if (policy) {
      params.set("Policy", JSON.stringify(policy));
    }

    const endpoint = `https://sts.${this.config.region}.amazonaws.com/`;
    const request = await this.signRequest(
      "POST",
      endpoint,
      params.toString(),
      baseCreds
    );

    const response = await fetch(endpoint, {
      method: "POST",
      headers: request.headers,
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`AWS STS AssumeRole failed: ${error}`);
    }

    // Parse XML response (simplified)
    const text = await response.text();
    const result = this.parseAssumeRoleResponse(text);

    return {
      accessKeyId: result.AccessKeyId,
      secretAccessKey: result.SecretAccessKey,
      sessionToken: result.SessionToken,
      expiration: result.Expiration,
    };
  }

  /**
   * Get base credentials for STS calls
   */
  private getBaseCredentials(): AWSCredentials {
    // First check config
    if (this.config.accessKeyId && this.config.secretAccessKey) {
      return {
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey,
      };
    }

    // Fall back to environment variables
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
    const sessionToken = process.env.AWS_SESSION_TOKEN;

    if (!accessKeyId || !secretAccessKey) {
      throw new Error(
        "AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY " +
        "environment variables or provide them in the provider configuration."
      );
    }

    return { accessKeyId, secretAccessKey, sessionToken };
  }

  /**
   * Sign an AWS request using Signature Version 4
   * (Simplified implementation - in production, use aws4 package)
   */
  private async signRequest(
    method: string,
    endpoint: string,
    body: string,
    credentials: AWSCredentials
  ): Promise<{ headers: Record<string, string> }> {
    const url = new URL(endpoint);
    const host = url.hostname;
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const dateStamp = amzDate.substring(0, 8);

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
      Host: host,
      "X-Amz-Date": amzDate,
    };

    if (credentials.sessionToken) {
      headers["X-Amz-Security-Token"] = credentials.sessionToken;
    }

    // Canonical request
    const canonicalHeaders = Object.entries(headers)
      .map(([k, v]) => `${k.toLowerCase()}:${v}`)
      .sort()
      .join("\n");
    const signedHeaders = Object.keys(headers)
      .map((k) => k.toLowerCase())
      .sort()
      .join(";");

    const payloadHash = await this.sha256(body);
    const canonicalRequest = [
      method,
      "/",
      "",
      canonicalHeaders + "\n",
      signedHeaders,
      payloadHash,
    ].join("\n");

    // String to sign
    const algorithm = "AWS4-HMAC-SHA256";
    const credentialScope = `${dateStamp}/${this.config.region}/sts/aws4_request`;
    const canonicalRequestHash = await this.sha256(canonicalRequest);
    const stringToSign = [algorithm, amzDate, credentialScope, canonicalRequestHash].join("\n");

    // Calculate signature
    const kDate = await this.hmac(`AWS4${credentials.secretAccessKey}`, dateStamp);
    const kRegion = await this.hmac(kDate, this.config.region);
    const kService = await this.hmac(kRegion, "sts");
    const kSigning = await this.hmac(kService, "aws4_request");
    const signature = await this.hmacHex(kSigning, stringToSign);

    // Authorization header
    headers["Authorization"] = [
      `${algorithm} Credential=${credentials.accessKeyId}/${credentialScope}`,
      `SignedHeaders=${signedHeaders}`,
      `Signature=${signature}`,
    ].join(", ");

    return { headers };
  }

  /**
   * SHA-256 hash
   */
  private async sha256(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * HMAC-SHA256
   */
  private async hmac(key: string | ArrayBuffer, data: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const keyBuffer = typeof key === "string" ? encoder.encode(key) : key;
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBuffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(data));
  }

  /**
   * HMAC-SHA256 returning hex string
   */
  private async hmacHex(key: ArrayBuffer, data: string): Promise<string> {
    const result = await this.hmac(key, data);
    return Array.from(new Uint8Array(result))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Parse STS AssumeRole XML response
   */
  private parseAssumeRoleResponse(xml: string): {
    AccessKeyId: string;
    SecretAccessKey: string;
    SessionToken: string;
    Expiration: string;
  } {
    // Simple XML parsing for STS response
    const extract = (tag: string): string => {
      const match = xml.match(new RegExp(`<${tag}>([^<]+)</${tag}>`));
      if (!match) throw new Error(`Missing ${tag} in STS response`);
      return match[1];
    };

    return {
      AccessKeyId: extract("AccessKeyId"),
      SecretAccessKey: extract("SecretAccessKey"),
      SessionToken: extract("SessionToken"),
      Expiration: extract("Expiration"),
    };
  }

  /**
   * Convert our scope format to AWS IAM policy with resource constraints
   */
  private scopeToPolicy(scope: string, resource: string): object | null {
    const basePolicy = SCOPE_TO_POLICY[scope];

    if (!basePolicy) {
      // No policy restriction - use role's default permissions
      return null;
    }

    // Clone the policy and apply resource constraints if specified
    const policy = JSON.parse(JSON.stringify(basePolicy));

    if (resource && resource !== "*") {
      // Apply resource constraint to all statements
      for (const statement of policy.Statement) {
        statement.Resource = this.expandResourcePattern(scope, resource);
      }
    }

    return policy;
  }

  /**
   * Expand a resource pattern to AWS ARN format
   */
  private expandResourcePattern(scope: string, resource: string): string | string[] {
    // S3 buckets
    if (scope.startsWith("aws:s3:")) {
      const parts = resource.split("/");
      const bucket = parts[0];
      const key = parts.slice(1).join("/") || "*";
      return [
        `arn:aws:s3:::${bucket}`,
        `arn:aws:s3:::${bucket}/${key}`,
      ];
    }

    // DynamoDB tables
    if (scope.startsWith("aws:dynamodb:")) {
      return `arn:aws:dynamodb:${this.config.region}:*:table/${resource}`;
    }

    // Lambda functions
    if (scope.startsWith("aws:lambda:")) {
      return `arn:aws:lambda:${this.config.region}:*:function:${resource}`;
    }

    // SQS queues
    if (scope.startsWith("aws:sqs:")) {
      return `arn:aws:sqs:${this.config.region}:*:${resource}`;
    }

    // SNS topics
    if (scope.startsWith("aws:sns:")) {
      return `arn:aws:sns:${this.config.region}:*:${resource}`;
    }

    // Default: use as-is
    return resource;
  }

  /**
   * Verify the AWS configuration is valid
   */
  async verify(): Promise<{ valid: boolean; error?: string }> {
    try {
      // Try to get caller identity to verify credentials
      const creds = this.getBaseCredentials();
      const params = new URLSearchParams({
        Action: "GetCallerIdentity",
        Version: "2011-06-15",
      });

      const endpoint = `https://sts.${this.config.region}.amazonaws.com/`;
      const request = await this.signRequest("POST", endpoint, params.toString(), creds);

      const response = await fetch(endpoint, {
        method: "POST",
        headers: request.headers,
        body: params.toString(),
      });

      if (!response.ok) {
        const error = await response.text();
        return { valid: false, error: `AWS credentials invalid: ${error}` };
      }

      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get the caller identity (useful for debugging)
   */
  async getCallerIdentity(): Promise<{ account: string; arn: string; userId: string }> {
    const creds = this.getBaseCredentials();
    const params = new URLSearchParams({
      Action: "GetCallerIdentity",
      Version: "2011-06-15",
    });

    const endpoint = `https://sts.${this.config.region}.amazonaws.com/`;
    const request = await this.signRequest("POST", endpoint, params.toString(), creds);

    const response = await fetch(endpoint, {
      method: "POST",
      headers: request.headers,
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error(`Failed to get caller identity: ${response.statusText}`);
    }

    const xml = await response.text();
    const extract = (tag: string): string => {
      const match = xml.match(new RegExp(`<${tag}>([^<]+)</${tag}>`));
      if (!match) throw new Error(`Missing ${tag} in response`);
      return match[1];
    };

    return {
      account: extract("Account"),
      arn: extract("Arn"),
      userId: extract("UserId"),
    };
  }
}
