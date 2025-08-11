# MCP-Burp

A Model Context Protocol (MCP) server that bridges Burp Suite with AI assistants for enhanced security testing workflows.

## Overview

MCP-Burp enables AI assistants to interact with Burp Suite, allowing for automated security analysis, request/response examination, and intelligent testing workflows.

## Prerequisites

- Burp Suite Professional or Community Edition
- Python 3.8+
- MCP client (Claude Desktop, etc.)

## Installation

1. Clone or download the MCP-Burp server
2. Install dependencies:
    ```bash
    npm i
    ```

## Configuration

### 1. Burp Suite Setup

1. Load the Burp extension (`.jar` file)
2. Go to the extension's settings tab
3. **Enable the bridge** - this is crucial for communication
4. Generate or set an authentication token (eg - abcd123)
5. Note the server port (default: 7071)

### 2. MCP Client Configuration

Add the MCP-Burp server to your MCP client configuration:

```json
{
  "mcpServers": {
     "mcp-burp": {
        "command": "node",
        "args": ["/path/to/mcp-burp/server.js"],
        "env": {
          "BURP_TOKEN": "abcd123",
          "BURP_BASE": "http://127.0.0.1:7071"
        }
     }
  }
}
```

**Important**: Use the **same token** in both:
- Burp Suite extension settings
- MCP client configuration file

### 3. Start the Server

```bash
node server.js
```

## Usage

Once configured, your AI assistant can:
- Analyze HTTP requests/responses
- Generate custom payloads

## Troubleshooting

- Ensure the Burp bridge is **enabled**
- Verify tokens match between Burp and MCP config
- Check that Burp Suite is running and accessible
- Confirm firewall settings allow local connections

## Security Notes

- Keep authentication tokens secure
- Only run on trusted networks
- Review AI-generated payloads before execution
