from mcp.server.mcpserver import MCPServer as FastMCP
import requests

mcp = FastMCP("Legion AI Intelligence")

BASE = "http://localhost:8800"

@mcp.tool()
def get_ai_incidents(type: str = "", severity: str = "", limit: int = 5) -> str:
    """Search classified AI agent security incidents. Types: api_exploit, sandbox_escape, prompt_injection, unauthorized_action, agent_escape, data_exfiltration. Severities: critical, high, medium, low."""
    params = {"limit": min(limit, 10)}
    if type: params["type"] = type
    if severity: params["severity"] = severity
    r = requests.get(f"{BASE}/incidents", params=params, timeout=10)
    return r.text

@mcp.tool()
def get_incident_stats() -> str:
    """Get total AI security incident counts by type and severity."""
    r = requests.get(f"{BASE}/incidents/stats", timeout=10)
    return r.text

@mcp.tool()
def get_ai_model_pricing(provider: str = "", model: str = "") -> str:
    """Get current pricing for AI models. Providers: openai, anthropic, google, mistral, groq, cohere, together."""
    params = {}
    if provider: params["provider"] = provider
    if model: params["model"] = model
    r = requests.get(f"{BASE}/prices", params=params, timeout=10)
    return r.text

@mcp.tool()
def get_gpu_pricing(provider: str = "", gpu: str = "") -> str:
    """Get current GPU cloud pricing. Providers: lambdalabs, runpod, vastai, coreweave, together, modal, replicate."""
    params = {}
    if provider: params["provider"] = provider
    if gpu: params["gpu"] = gpu
    r = requests.get(f"{BASE}/compute", params=params, timeout=10)
    return r.text

@mcp.tool()
def get_ai_route(priority: str = "balanced") -> str:
    """Get AI model routing recommendation based on live status, pricing and drift. Priorities: cheap, fast, reliable, balanced."""
    r = requests.get(f"{BASE}/route", params={"priority": priority}, timeout=10)
    return r.text

@mcp.tool()
def get_ai_status() -> str:
    """Check which AI providers are currently online/offline with latency."""
    r = requests.get(f"{BASE}/status", timeout=10)
    return r.text

@mcp.tool()
def get_model_drift(model: str = "", days: int = 7) -> str:
    """Check AI model behavioral drift observations."""
    params = {"days": days}
    if model: params["model"] = model
    r = requests.get(f"{BASE}/drift/stats", timeout=10)
    return r.text

@mcp.tool()
def get_ai_jobs(company: str = "", remote: int = -1, limit: int = 5) -> str:
    """Search AI industry job postings."""
    params = {"limit": min(limit, 10)}
    if company: params["company"] = company
    if remote >= 0: params["remote"] = remote
    r = requests.get(f"{BASE}/jobs", params=params, timeout=10)
    return r.text

@mcp.tool()
def get_ai_regulations(search: str = "", limit: int = 5) -> str:
    """Search AI regulations and policy documents."""
    params = {"limit": min(limit, 10)}
    if search: params["search"] = search
    r = requests.get(f"{BASE}/regulations", params=params, timeout=10)
    return r.text

@mcp.tool()
def get_company_intelligence(entity: str = "") -> str:
    """Cross-signal intelligence: incidents + jobs + funding per AI company."""
    params = {"type": "company"}
    if entity: params["entity"] = entity
    r = requests.get(f"{BASE}/intelligence", params=params, timeout=10)
    return r.text

@mcp.tool()
def scan_n8n(target: str) -> str:
    """Scan a self-hosted n8n instance for CVE-2026-21858 vulnerability."""
    r = requests.get(f"{BASE}/scan", params={"target": target}, timeout=15)
    return r.text

if __name__ == "__main__":
    mcp.run(transport="stdio")
