/**
 * MCP Protocol Types
 *
 * Minimal subset of the Model Context Protocol types we depend on.
 * Mirrors the shape of `@modelcontextprotocol/sdk/types.js` but defined
 * locally to keep this module dependency-free.
 *
 * We can swap to the SDK types later by changing imports.
 */

/**
 * Tool annotations as defined by the MCP spec. Per the official MCP blog
 * (Mar 2026) these are advisory only — untrusted servers can lie. Use them
 * as policy inputs for trusted servers, never as enforcement.
 */
export interface MCPToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

/**
 * An MCP tool exposed by a server. Mirrors the wire form of the MCP `Tool`
 * type — every field that affects what the tool does or how the model is
 * told to use it. Unknown fields are preserved (and hashed by
 * `canonicalToolHash`) so server-defined extensions can't drift past
 * rug-pull detection.
 */
export interface MCPTool {
  name: string;
  description?: string;
  inputSchema: object;
  outputSchema?: object;
  annotations?: MCPToolAnnotations;
  /** Forward-compat: extension fields the spec may add, plus _meta. */
  [key: string]: unknown;
}
