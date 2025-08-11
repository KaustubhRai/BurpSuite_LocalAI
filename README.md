# Local LLM Assistant for Burp Suite

Use your own LLM (local or remote) to generate payloads and fire them via Burp. No Burp AI credits.

## Highlights

* **Seed from any request** (context-menu) and mutate it automatically
* **Generate → Parse → Send** in one click (URL/BODY/JSON/COOKIE params)
* Robust **JSON/YAML parsing** with auto-repair for common quoting issues
* **Timing**: prints generation finish and send completion with ms totals
* **Encoding variants**: optionally send URL/Base64/HTML-encoded payloads
* **Repeater integration**: also queue each mutation in Repeater (optional)
* **MCP bridge**: expose an HTTP bridge + stdio MCP server for tools like Claude Desktop or VS Code Copilot Chat to read the seed and call “send\_payloads”

> Only use on systems you’re authorized to test.

---

## What’s new

### v2

* Better defaults (fast local models)
* Stream OFF by default; YAML-only ON
* Added **Clear** output button
* **Timing markers**: `[gen]` and `[fire] Done … (fire=…, total=…)`
* **Encoding** toggle: send normal + encoded variants (URL/Base64/HTML)
* More robust YAML/JSON block extraction and quoting fixes

### v3

* **MCP bridge** inside the extension (`/v1/seed`, `/v1/send`)
* Small **Node stdio MCP server** exposing:

  * `get_seed` – returns the selected Burp seed
  * `send_payloads` – posts payloads to the bridge
* Works with **Claude Desktop** and **VS Code Copilot Chat** (MCP)

---

## Requirements

* Burp Suite (Pro/Community) with Montoya API
* Java **17+**
* For local models: **Ollama** or any OpenAI-compatible endpoint
* For MCP: **Node 18+**
* (Optional) Claude Desktop ≥ version with MCP; VS Code with Copilot Chat (MCP)

---

## Build

```bash
# from repo root
mvn -q -DskipTests clean package
# Output:
# target/local-llm-assistant-<version>.jar  (shaded/fat JAR)
```

Load in Burp: **Extensions → Add → Select JAR**.

---

## Default settings (extension UI)

* Base URL: `http://127.0.0.1:11434/api/chat`
* Model: `gemma3:4b`
* Temperature: `0.15`
* Max tokens: `256`

Toggles:

* Stream: **OFF**
* Payloads only (YAML): **ON**
* Strip `<think>`: **OFF**
* Debug lines: **OFF**
* Send via Burp: **ON**
* Also add to Repeater: **OFF**
* Command mode: **ON** (prompt box may be empty; uses seed + controls)
* Encode variants: **OFF** by default (pick URL/Base64/HTML to enable)

---

## Usage (Local LLM tab)

1. In **Proxy/Repeater**, right-click a request → **Local LLM → Use this request as seed**.
   The tab shows: `Seed: <METHOD PATH @ http(s)://host:port>`
2. Either:

   * Leave prompt empty and keep **Command mode ON** → choose **Family** (NoSQL/SQL/…), **Where** (URL/BODY/JSON/COOKIE), **#** (count), then **Send**.
     **or**
   * Write your own prompt. The model can return either **JSON** or **YAML** (the extension handles both).
3. Watch output and **Logger → Sources: Extensions** for sent traffic.

**Example minimal free-form prompt** (when not using Command mode):

> “Generate 5 low-noise NoSQL detection probes for likely URL params in the seed. Return a single JSON object: `{"payloads":[...]}` with fields `{name,param,payload,type}`.”

---

## Payload format (either is fine)

**JSON (preferred)**

```json
{
  "payloads": [
    { "name":"boolean_true", "param":"q", "payload":"' OR '1'='1", "type":"URL" },
    { "name":"regex", "param":"q", "payload":"/.*/", "type":"URL" }
  ]
}
```

**YAML**

```yaml
payloads:
  - { name: boolean_true, param: q, payload: "' OR '1'='1", type: URL }
  - { name: regex, param: q, payload: "/.*/", type: URL }
```

The extension auto-repairs common single-quote/escape mistakes.

---

## Encoding variants

Enable **Encode variants** and choose one:

* URL → `URLEncoder` UTF-8
* Base64 → standard base64
* HTML → HTML entity escaping

For each payload the extension sends **normal** and **encoded** variants, e.g.:

```
- CategorySQL_Regex (category.URL) => 200 3556B 1487ms
- CategorySQL_Regex [enc=URL] (category.URL) => 200 3556B 1668ms
```

---

## MCP mode (Claude Desktop / VS Code)

### 1) Start the HTTP bridge (in the extension)

In the tab, tick **Expose MCP bridge**.

* Port (default): `7071`
* Optional **Token**: set any string; clients must send `Authorization: Bearer <token>`

Bridge endpoints:

* `GET /v1/seed` → `{"method","url","headers","params":{url,body,json,cookie}}`
* `POST /v1/send` → `{"encode":{"enable":bool,"kind":"URL|Base64|HTML"},"payloads":[…]}`
  Returns: `{"count", "results":[{"name","status","bytes","ms"}], "timing":{"fire_ms"}}`

> Requires JDK with the `jdk.httpserver` module (present on standard JDKs 17+). If Burp’s runtime lacks it, run Burp on a JDK that includes it.

### 2) Run the stdio MCP server (Node)

`src/mcp-burp/server.js` (ESM) exposes tools over stdio:

* `get_seed` → fetches `/v1/seed`
* `send_payloads` → POSTs to `/v1/send`

Install & run:

```bash
cd src/mcp-burp
npm i
node server.js
```

Set env if you customized bridge:

```bash
BURP_BASE=http://127.0.0.1:7071 BURP_TOKEN=yourtoken node server.js
```

### 3) Hook into a client

**Claude Desktop**
Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "burp": {
      "command": "node",
      "args": ["/absolute/path/to/src/mcp-burp/server.js"],
      "env": {
        "BURP_BASE": "http://127.0.0.1:7071",
        "BURP_TOKEN": "your-bridge-token-or-empty"
      }
    }
  }
}
```

**VS Code Copilot Chat (MCP)**
Create `.vscode/mcp.json`:

```json
{
  "servers": {
    "burp": {
      "type": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/src/mcp-burp/server.js"],
      "env": {
        "BURP_BASE": "http://127.0.0.1:7071",
        "BURP_TOKEN": "your-bridge-token-or-empty"
      }
    }
  }
}
```

### Example MCP prompt (minimal)

> “Use only burp tools. Call `get_seed`, pick a likely URL param, generate 5 benign NoSQL probes, then call `send_payloads` with `{"encode":{"enable":true,"kind":"URL"}}`. Respond only with tool calls.”


---

## Troubleshooting

* **No seed found**: Right-click inside request editor → “Use this request as seed”.
* **Bridge 401**: Token mismatch. Set the same token in the extension and MCP env.
* **Nothing in HTTP history**: Extension requests appear in **Logger → Sources: Extensions**.
* **Model too slow**: Use `gemma3:4b` or similar, `temp=0.15`, `max_tokens=256`, **Stream OFF**.

---


## Options Explained:

- Stream: stream output from the model (nice when it works; turn off for easier debug).
- Payloads only (YAML): enforce a single fenced YAML block with payloads: [...].
- Strip <think>: remove chain-of-thought noise if your model emits <think> blocks.
- Send via Burp: actually fire the generated payloads (through Burp’s HTTP stack).
- Also add to Repeater: each mutation is queued in Repeater with caption LLM/<name>.
