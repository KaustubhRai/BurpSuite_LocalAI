# BurpSuite_LocalAI (Burp Suite extension)

> Use your **local** LLM (e.g., Ollama + DeepSeek R1) inside Burp Suite, generate payloads, and **fire them** via Burp — no BurpSuite credits needed.

## Why this exists

- **GPT-5** dropped and Burp Suite added an AI helper in Repeater. Great feature… but the **credit model burns through usage** fast. I don’t want to keep buying more just to test a couple endpoints.
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
