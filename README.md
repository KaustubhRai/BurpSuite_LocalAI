# BurpSuite_LocalAI (Burp Suite extension)

> Use your **local** LLM (e.g., Ollama + DeepSeek R1) inside Burp Suite, generate payloads, and **fire them** via Burp — no BurpSuite credits needed.

## Why this exists

- **GPT-5** dropped and Burp Suite(v2025.8) added an AI helper in Repeater. Great feature… but the **credit model burns through usage** fast. I don’t want to keep buying more just to test a couple endpoints.
- So I built a bare-bones alternative that **talks to a local model** (Ollama) and wires the output straight into Burp. It’s not a feature-for-feature clone of Burp’s AI — yet — but it’s enough to speed up exploration without a running meter.

## What it does (today)

- Adds a **“Local LLM”** Suite tab with:
  - **Base URL / Model** for your local OpenAI-compatible endpoint (tested with `ollama serve`).
  - Toggle to return **YAML-only payload lists** (no filler).
  - **One-click send**: parse YAML → **mutate the seeded request** → **send via Burp**.
  - Optional: **also push each mutation to Repeater** for manual tweaking.
  - Optional: **strip `<think>`** blocks if your model emits them.
  - Debug mode to print what it’s actually sending.

- Adds a **context menu action**:
  - Right-click any request → **Local LLM → Use this request as seed**.
  - The tab shows the seed, then you prompt for payloads and fire.

- Supports parameters in: **URL**, **BODY**, **JSON**, **COOKIE**.
  - If a parameter doesn’t exist, we **add** it (using `withParameter` or `Cookie` header merge).

> **Where to watch the traffic:** Open **Logger** → filter → enable **Sources: Extensions**. Extension-sent requests appear here (not in HTTP history).

## Screenshots

<img width="1512" height="917" alt="Screenshot 2025-08-09 at 9 15 58 AM" src="https://github.com/user-attachments/assets/734077e5-de11-413a-be49-f673774d7fbc" />

<img width="1512" height="919" alt="Screenshot 2025-08-09 at 9 13 14 AM" src="https://github.com/user-attachments/assets/12b483fc-dd34-4ed6-9c51-c5ce52dfeb78" />


## Requirements

- Burp Suite (Pro or Community) with **Montoya API**.
- Java 17+.
- **Ollama** running locally:  
  ```bash
  ollama serve
  ollama list
  # make sure your model is present, e.g. deepseek-r1:14b
- Endpoint URL in the UI defaults to `http://127.0.0.1:11434/v1/chat/completions`.

## Build

  ```bash
  mvn -q -DskipTests package
  # Load the shaded jar:
  # target/local-llm-assistant-1.0.0-shaded.jar
  ```
We build a fat JAR (shaded) so Jackson is available at runtime inside Burp.


## Requirements

- Extensions → Add → Select JAR: target/local-llm-assistant-1.0.0-shaded.jar.
- Open the Local LLM tab.
- In Repeater, right-click inside a request editor → Local LLM → Use this request as seed.
- In the tab, write a prompt (or paste your YAML), click Send.
- Watch Logger (Sources → Extensions) for sent traffic.


## Example YAML Format

- To force clean output (no filler), keep the “Payloads only (YAML)” option on. Example prompt:
  ```yaml
  payloads:
    - { name: sqli_true, param: q, payload: "1' OR '1'='1", type: URL }
    - { name: time_oracle, param: q, payload: "'; WAITFOR DELAY '0:0:05'--", type: URL }
    - { name: xss_cookie, param: name, payload: "<script>alert(1)</script>", type: COOKIE }
    - { name: json_flip, param: admin, payload: "true", type: JSON }
  ```
  

## Notes

- All payload values must be quoted strings, even if they contain JSON.
If the model forgets, the extension attempts a safe auto-fix.


## Options Explained:

- Stream: stream output from the model (nice when it works; turn off for easier debug).
- Payloads only (YAML): enforce a single fenced YAML block with payloads: [...].
- Strip <think>: remove chain-of-thought noise if your model emits <think> blocks.
- Send via Burp: actually fire the generated payloads (through Burp’s HTTP stack).
- Also add to Repeater: each mutation is queued in Repeater with caption LLM/<name>.
