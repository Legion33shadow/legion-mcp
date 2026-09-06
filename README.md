# Legion AI Intelligence — MCP Server

Connect AI agents to real-time AI ecosystem intelligence.

## Tools

| Tool | Description |
|------|-------------|
| get_ai_incidents | 1,178+ classified AI security incidents |
| get_ai_model_pricing | 28 models, 7 providers |
| get_gpu_pricing | GPU cloud pricing from 7 providers |
| get_ai_route | Smart model routing (cost/speed/reliability) |
| get_ai_status | Live provider availability |
| get_company_intelligence | Cross-signal company analysis |
| scan_n8n | n8n CVE-2026-21858 scanner |

## Setup

Add to claude_desktop_config.json:

    {
      "mcpServers": {
        "legion-ai": {
          "command": "python3",
          "args": ["path/to/server.py"]
        }
      }
    }

## Links

- API: https://api.legion-api.com
- RapidAPI: https://rapidapi.com/gemmozero/api/legion-ai-security-incidents
- Datasets: https://huggingface.co/gemmozero
- Site: https://legion-api.com
