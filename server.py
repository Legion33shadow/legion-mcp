import os
from mcp.server.mcpserver import MCPServer as FastMCP
import requests

mcp = FastMCP("Legion AI Intelligence")

BASE = os.environ.get("LEGION_API_URL", "https://api.legion-api.com")

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

def main():
    if os.environ.get("MCP_TRANSPORT") == "http":
        host, port = "127.0.0.1", int(os.environ.get("MCP_PORT", "8802"))
        try:
            from mcp.server.transport_security import TransportSecuritySettings
            ts = TransportSecuritySettings(enable_dns_rebinding_protection=True,
                 allowed_hosts=["mcp.legion-api.com", "127.0.0.1:8802", "localhost:8802"],
                 allowed_origins=["https://mcp.legion-api.com", "https://smithery.ai", "https://*.smithery.ai"])
            mcp.run(transport="streamable-http", host=host, port=port, stateless_http=True, transport_security=ts)
        except TypeError:
            import uvicorn
            uvicorn.run(mcp.streamable_http_app(), host=host, port=port, log_level="warning")
    else:
        mcp.run(transport="stdio")

@mcp.tool()
def get_gpu_decision(gpu: str = "H100", hours_per_day: float = 8, budget: float = 0) -> str:
    """EXPERIMENTAL. Get a BUY/WAIT/AVOID decision for GPU rental based on real-time pricing, security incidents, provider status, and policy changes."""
    r = requests.get(f"{BASE}/decide", params={"gpu": gpu, "hours_per_day": hours_per_day, "budget": budget}, timeout=15)
    return r.text

@mcp.tool()
def get_risk_assessment(provider: str = "", framework: str = "") -> str:
    """Get aggregated risk assessment for an AI provider or framework from LEGION signals (incidents, policy drift, pricing)."""
    params = {}
    if provider: params["provider"] = provider
    if framework: params["framework"] = framework
    r = requests.get(f"{BASE}/risk", params=params, timeout=15)
    return r.text


@mcp.tool()
def get_oracle(limit: int = 5) -> str:
    """Get AI pricing forecasts based on cross-signal analysis (incidents + funding + pricing history)."""
    r = requests.get(f"{BASE}/oracle", params={"limit": limit}, timeout=15)
    return r.text

@mcp.tool()
def get_sentinel(providers: str = "openai.com,anthropic.com") -> str:
    """Monitor DNS/IP changes for AI providers. Detects infrastructure migrations."""
    r = requests.get(f"{BASE}/sentinel", params={"providers": providers}, timeout=15)
    return r.text

@mcp.tool()
def get_autopsy(company: str = "openai") -> str:
    """Cross-reference incident with all LEGION signals for automated post-mortem analysis."""
    r = requests.get(f"{BASE}/autopsy", params={"company": company}, timeout=15)
    return r.text

@mcp.tool()
def nexus_search(q: str = "", limit: int = 10) -> str:
    """Universal search across 7 LEGION databases: incidents, models, research, CVE, GitHub, arxiv, events."""
    r = requests.get(f"{BASE}/nexus", params={"q": q, "limit": limit}, timeout=15)
    return r.text

@mcp.tool()
def get_attest(subject: str = "openai", days: int = 30) -> str:
    """Get signed attestation of absence/presence of critical incidents for any AI provider."""
    r = requests.get(f"{BASE}/attest", params={"subject": subject, "days": days}, timeout=15)
    return r.text


@mcp.tool()
def notarize(sha256: str) -> str:
    """Horodate l'empreinte sha256 d'un document (jamais son contenu) dans le registre d'empire LEGION: chaine sha256, signature Ed25519, publie sur Hugging Face."""
    import requests
    return requests.post(f"{BASE}/notary/stamp", json={"sha256": sha256}, timeout=15).text

@mcp.tool()
def notary_status(sha256: str) -> str:
    """Etat d'une empreinte: pending ou anchored (avec date et hash du maillon)."""
    import requests
    return requests.get(f"{BASE}/notary/{sha256}", timeout=15).text

@mcp.tool()
def verify_empire_ledger() -> str:
    """Etat de verification du registre d'empire LEGION (empreintes quotidiennes de tous les datasets)."""
    import requests
    return requests.get(f"{BASE}/empire-ledger", timeout=15).text

if __name__ == "__main__":
    main()

@mcp.tool()
async def swarm_vote(question: str) -> dict:
    """Ask LEGION swarm (5 agents) to vote collectively on a security/risk question."""
    import httpx
    r = httpx.get(f"{BASE}/swarm", timeout=15)
    return r.json()

@mcp.tool()
async def get_predictions(domain: str = "", min_confidence: float = 0.7) -> dict:
    """Get ORACLE PRIME autonomous predictions with Ed25519 signatures."""
    import httpx
    r = httpx.get(f"{BASE}/predictions?domain={domain}&min_confidence={min_confidence}&limit=5", timeout=15)
    return r.json()

@mcp.tool()
async def inference_frontier(input_tokens: int = 1000000, output_tokens: int = 500000) -> dict:
    """Get Pareto-optimal AI providers for given token volume. Real prices + live latency."""
    import httpx
    r = httpx.get(f"{BASE}/inference-frontier?input_tokens={input_tokens}&output_tokens={output_tokens}&pareto_only=1&limit=5", timeout=15)
    return r.json()

@mcp.tool()
async def get_sentinel_anomalies(severity: str = "HIGH") -> dict:
    """Get anomalies detected by SENTINEL PRIME — unexpected changes in AI ecosystem."""
    import httpx
    r = httpx.get(f"{BASE}/sentinel?severity={severity}&limit=10", timeout=15)
    return r.json()

@mcp.tool()
async def get_memory(keyword: str = "", category: str = "") -> dict:
    """Query LEGION institutional memory — what happened, when, why."""
    import httpx
    r = httpx.get(f"{BASE}/memory?keyword={keyword}&category={category}&limit=10", timeout=15)
    return r.json()

@mcp.tool()
async def get_convergence(entity: str = "") -> dict:
    """Cross-domain intelligence signals — incidents x lobbying x water x talent x carbon."""
    import httpx
    r = httpx.get(f"{BASE}/convergence?entity={entity}&limit=10", timeout=15)
    return r.json()

@mcp.tool()
async def check_phantom(company: str) -> dict:
    """Check if a company has a history of AI vaporware — announced but undelivered."""
    import httpx
    r = httpx.get(f"{BASE}/phantom?company={company}&limit=5", timeout=15)
    return r.json()

@mcp.tool()
async def get_entity_score(entity: str) -> dict:
    """Composite trustworthiness score for any AI entity — immunity + trust + incidents + lobbying."""
    import httpx
    r = httpx.get(f"{BASE}/score/{entity}", timeout=15)
    return r.json()

