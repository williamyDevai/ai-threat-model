"""Ollama backend — no API key required, runs fully local."""

import json
import re

import requests

OLLAMA_PROMPT = """You are a senior AI security engineer specializing in threat modeling AI/ML systems.
Analyze the system described below. Output ONLY a single JSON object — no explanation, no markdown, no preamble.

Use these frameworks:
STRIDE: Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege

MITRE ATLAS techniques:
AML.T0051 LLM Prompt Injection (direct) | AML.T0051.001 Indirect Prompt Injection (via RAG/tools) |
AML.T0057 LLM Jailbreak | AML.T0054 Membership Inference | AML.T0020 Poison Training Data |
AML.T0047 ML-Enabled Product Abuse | AML.T0025 Exfiltration via Cyber Means |
AML.T0040 ML Model Inference API Access | AML.T0043 Craft Adversarial Data |
AML.T0010 ML Supply Chain Compromise

OWASP LLM Top 10 (2025):
LLM01 Prompt Injection | LLM02 Sensitive Information Disclosure | LLM03 Supply Chain |
LLM04 Data and Model Poisoning | LLM05 Improper Output Handling | LLM06 Excessive Agency |
LLM07 System Prompt Leakage | LLM08 Vector and Embedding Weaknesses |
LLM09 Misinformation | LLM10 Unbounded Consumption

NIST AI RMF functions: GOVERN | MAP | MEASURE | MANAGE

Required JSON structure:
{{
  "executive_summary": "2-3 paragraph risk overview for this specific system",
  "threats": [
    {{
      "id": "T-01",
      "title": "Short threat name",
      "description": "What the threat is and why it matters for this system",
      "component": "Specific component from the architecture",
      "stride_category": "Tampering",
      "atlas_id": "AML.T0051",
      "atlas_name": "LLM Prompt Injection",
      "owasp_llm": "LLM01",
      "severity": "HIGH",
      "likelihood": "MEDIUM",
      "attack_path": "1. Attacker does X\\n2. This causes Y\\n3. Result is Z",
      "mitigation": "Concrete technical controls to apply",
      "detection": "How to detect or monitor for this threat"
    }}
  ],
  "nist_gaps": [
    {{
      "function": "GOVERN",
      "category_id": "GV-1.1",
      "category_name": "AI risk policy",
      "status": "Missing",
      "recommendation": "What to implement"
    }}
  ],
  "remediation_roadmap": [
    {{
      "phase": "Immediate (0-30 days)",
      "actions": ["Action 1", "Action 2"]
    }},
    {{
      "phase": "Short-term (30-90 days)",
      "actions": ["Action 1", "Action 2"]
    }},
    {{
      "phase": "Long-term (90+ days)",
      "actions": ["Action 1", "Action 2"]
    }}
  ]
}}

Rules:
- Identify 8-12 threats
- Reference actual component names from the system description
- Every threat needs a numbered attack_path with at least 3 steps
- severity must be one of: CRITICAL, HIGH, MEDIUM, LOW
- likelihood must be one of: HIGH, MEDIUM, LOW
- stride_category must be one of the 6 STRIDE categories exactly as written above
- function must be one of: GOVERN, MAP, MEASURE, MANAGE

System to analyze:
{arch_text}"""


def analyze(arch_text: str, system_name: str, ollama_url: str, model: str) -> dict:
    prompt = OLLAMA_PROMPT.format(arch_text=arch_text)

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_ctx": 8192,
        },
    }

    try:
        resp = requests.post(
            f"{ollama_url}/api/chat",
            json=payload,
            timeout=300,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Cannot connect to Ollama at {ollama_url}.\n"
            "  Start it with:  ollama serve\n"
            "  Then pull a model:  ollama pull llama3"
        )
    except requests.exceptions.Timeout:
        raise RuntimeError(
            "Ollama request timed out after 300s. "
            "Try a smaller model (e.g. --ollama-model llama3) or increase system RAM."
        )

    data = resp.json()
    raw = data.get("message", {}).get("content", "")
    return _parse_and_validate(raw)


def _parse_and_validate(content: str) -> dict:
    # Try direct JSON parse
    try:
        return _fill_defaults(json.loads(content))
    except json.JSONDecodeError:
        pass

    # Strip markdown code fences if present
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if match:
        try:
            return _fill_defaults(json.loads(match.group(1)))
        except json.JSONDecodeError:
            pass

    # Find the outermost JSON object
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if match:
        try:
            return _fill_defaults(json.loads(match.group(0)))
        except json.JSONDecodeError:
            pass

    raise RuntimeError(
        "Could not parse JSON from model output.\n"
        "  Try a larger model:  --ollama-model llama3:70b\n"
        "  Or use Claude:       --backend claude"
    )


def _fill_defaults(result: dict) -> dict:
    result.setdefault("executive_summary", "Threat model generated via local model.")
    result.setdefault("threats", [])
    result.setdefault("nist_gaps", [])
    result.setdefault("remediation_roadmap", [])

    valid_severities  = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    valid_likelihoods = {"HIGH", "MEDIUM", "LOW"}
    valid_stride = {
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege",
    }

    for i, t in enumerate(result["threats"]):
        t.setdefault("id", f"T-{i+1:02d}")
        t.setdefault("component", "—")
        t.setdefault("atlas_id", "—")
        t.setdefault("atlas_name", "")
        t.setdefault("owasp_llm", "—")
        t.setdefault("detection", "")
        if t.get("severity") not in valid_severities:
            t["severity"] = "MEDIUM"
        if t.get("likelihood") not in valid_likelihoods:
            t["likelihood"] = "MEDIUM"
        if t.get("stride_category") not in valid_stride:
            t["stride_category"] = "Tampering"

    for g in result["nist_gaps"]:
        g.setdefault("category_id", "")
        g.setdefault("status", "Missing")

    return result
