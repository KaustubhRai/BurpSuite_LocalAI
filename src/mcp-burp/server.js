// server.js
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const BURP_BASE = process.env.BURP_BASE || "http://127.0.0.1:7071";
const BURP_TOKEN = process.env.BURP_TOKEN || "";

const server = new Server(
  { name: "mcp-burp", version: "0.1.0" },
  { capabilities: { resources: {}, tools: {} } }
);

// --- Resources ---
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: "burp://seed",
      name: "Current Burp seed request",
      description: "The request currently selected in Burp.",
      mimeType: "application/json",
    },
  ],
}));

server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
  const { uri } = req.params;
  if (uri !== "burp://seed") throw new Error(`Unknown resource: ${uri}`);
  const res = await fetch(`${BURP_BASE}/v1/seed`, {
    headers: BURP_TOKEN ? { Authorization: `Bearer ${BURP_TOKEN}` } : {},
  });
  const text = await res.text();
  return {
    contents: [{ uri, mimeType: "application/json", text }],
  };
});

// --- Tools ---
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_seed",
      description: "Return the current Burp seed (same payload as GET /v1/seed).",
      inputSchema: { type: "object", properties: {} }
    },
    {
      name: "send_payloads",
      description: "Send payloads via Burp bridge. Input matches /v1/send.",
      inputSchema: {
        type: "object",
        properties: {
          encode: {
            type: "object",
            properties: {
              enable: { type: "boolean" },
              kind: { type: "string", enum: ["URL", "Base64", "HTML"] },
            },
          },
          payloads: {
            type: "array",
            items: {
              type: "object",
              required: ["param", "payload"],
              properties: {
                name: { type: "string" },
                param: { type: "string" },
                payload: { type: "string" },
                type: { type: "string", enum: ["URL", "BODY", "JSON", "COOKIE"] },
              },
            },
          },
        },
        required: ["payloads"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const name = req.params.name;
  const args = req.params.arguments ?? {};

  if (name === "get_seed") {
    const res = await fetch(`${BURP_BASE}/v1/seed`, {
      headers: BURP_TOKEN ? { Authorization: `Bearer ${BURP_TOKEN}` } : {},
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`Burp returned ${res.status}: ${text}`);
    return { content: [{ type: "text", text }] };
  }

  if (name === "send_payloads") {
    const res = await fetch(`${BURP_BASE}/v1/send`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(BURP_TOKEN ? { Authorization: `Bearer ${BURP_TOKEN}` } : {}),
      },
      body: JSON.stringify(args),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`Burp returned ${res.status}: ${text}`);
    return { content: [{ type: "text", text }] };
  }

  throw new Error(`Unknown tool: ${name}`);
});

// Start over stdio
const transport = new StdioServerTransport();
await server.connect(transport);
