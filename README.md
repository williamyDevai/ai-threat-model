# threatscan — AI System Threat Modeling CLI

Generate a structured, multi-framework threat model for any AI/ML system from a plain-text or YAML architecture description.

Maps every threat to **STRIDE**, **MITRE ATLAS v2.1**, **OWASP LLM Top 10 (2025)**, and **NIST AI RMF 1.0** — in one pass, without manual cross-referencing.

---

## Why

AI systems introduce attack surfaces that traditional threat modeling misses: prompt injection via retrieved context, RAG corpus poisoning, embedding inversion, agentic privilege escalation, and model supply chain compromise. This tool applies the frameworks security engineers actually use for AI systems, grounded in the specific architecture you provide.

---

## Quick Start

```bash
git clone https://github.com/williamyDevai/ai-threat-model
cd ai-threat-model
pip install -r requirements.txt

# --- No API key required --- run fully local with Ollama
ollama pull llama3
python threatscan.py --file examples/rag_pipeline.yaml --backend ollama --verbose

# --- With Claude API (higher quality) ---
cp .env.example .env   # add ANTHROPIC_API_KEY=sk-ant-...
python threatscan.py --file examples/rag_pipeline.yaml --backend claude --verbose

# Auto-detect: uses Claude if key is set, Ollama otherwise
python threatscan.py --file examples/rag_pipeline.yaml

# Save report to file
python threatscan.py --file examples/rag_pipeline.yaml --output reports/rag.md

# JSON output (for downstream tooling)
python threatscan.py --file examples/agentic_security_triage.yaml --format json

# Different local model
python threatscan.py --file examples/rag_pipeline.yaml --backend ollama --ollama-model mistral
```

---

## Output

Each run produces a complete Markdown report with:

| Section | What's included |
|---------|-----------------|
| **Executive Summary** | Overall risk posture, top threats, immediate priorities |
| **Threat Inventory** | Table: ID, severity, component, STRIDE, ATLAS technique, OWASP LLM category |
| **Detailed Findings** | Per-threat: attack path, mitigation, detection signal |
| **NIST AI RMF Gap Analysis** | GOVERN / MAP / MEASURE / MANAGE gaps with recommendations |
| **Remediation Roadmap** | Phased action plan: 0-30 / 30-90 / 90+ days |

---

## Architecture YAML Format

```yaml
name: "My AI System"
description: "What it does, who uses it, deployment context"

components:
  - name: "Foundation Model (Claude claude-sonnet-4-6)"
    type: "foundation_model"
    provider: "Anthropic API"
  - name: "Vector Store (Pinecone)"
    type: "external_service"
  - name: "Tool: CRM Lookup"
    type: "internal_api"

data_flows:
  - "User → API Gateway → Orchestration Layer"
  - "Orchestration Layer → Foundation Model (query + retrieved context)"
  - "Foundation Model → CRM Lookup (tool call)"

trust_boundaries:
  - "Public internet (unauthenticated users)"
  - "Anthropic cloud (external LLM API)"
  - "Internal network (CRM)"
```

See [`examples/`](examples/) for complete worked examples including a customer support RAG chatbot and an autonomous security triage agent.

---

## Frameworks

| Framework | Version | What it covers |
|-----------|---------|----------------|
| STRIDE | Microsoft (classic) | Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege |
| MITRE ATLAS | v2.1 | AI/ML-specific adversary techniques (prompt injection, data poisoning, supply chain, inference attacks) |
| OWASP LLM Top 10 | 2025 | Top 10 LLM application risks (LLM01–LLM10) |
| NIST AI RMF | 1.0 | AI governance gap analysis (GOVERN / MAP / MEASURE / MANAGE) |

---

## Options

```
usage: threatscan [-h] [--file PATH] [--format {markdown,json}]
                  [--output PATH] [--model MODEL] [--verbose]
                  [DESCRIPTION]

positional arguments:
  DESCRIPTION           Plain-text architecture description

options:
  -f, --file PATH       YAML architecture file
  --format              Output format: markdown (default) or json
  -o, --output PATH     Write to file instead of stdout
  -m, --model MODEL     Anthropic model (default: claude-sonnet-4-6)
  -v, --verbose         Show progress
```

---

## License

MIT
