"""Claude API interaction — structured threat model generation."""

import anthropic

SYSTEM_PROMPT = """You are a senior AI security engineer with deep expertise in threat modeling AI/ML systems.
You specialize in STRIDE, MITRE ATLAS v2.1, OWASP LLM Top 10 (2025), and NIST AI RMF 1.0.

Your job: perform a comprehensive, technically accurate threat model of the described AI system.
Be specific to the architecture — do not generate generic threats. Reference actual components.
Identify 8-15 distinct threats. Each must have a concrete, step-by-step attack path.

STRIDE categories:
- Spoofing: Impersonating users, models, APIs, or services
- Tampering: Modifying prompts, retrieved context, outputs, model weights, or training data
- Repudiation: Denying AI-generated actions, predictions, or tool invocations
- Information Disclosure: Leaking system prompts, training data, user PII, or model internals
- Denial of Service: Exhausting tokens, compute, rate limits, or vector DB capacity
- Elevation of Privilege: Bypassing guardrails, gaining unauthorized tool/API access via the model

Key MITRE ATLAS v2.1 techniques:
- AML.T0051 / AML.T0051.000: LLM Prompt Injection (direct)
- AML.T0051.001: Indirect Prompt Injection (via retrieved context/tool output)
- AML.T0057: LLM Jailbreak
- AML.T0054: Membership Inference Attack
- AML.T0020: Poison Training Data
- AML.T0047: ML-Enabled Product Abuse
- AML.T0025: Exfiltration via Cyber Means
- AML.T0040: ML Model Inference API Access
- AML.T0043: Craft Adversarial Data
- AML.T0010: ML Supply Chain Compromise
- AML.T0033: Spearphishing for Information
- AML.T0048: Erode ML Model Integrity

OWASP LLM Top 10 (2025):
- LLM01: Prompt Injection
- LLM02: Sensitive Information Disclosure
- LLM03: Supply Chain
- LLM04: Data and Model Poisoning
- LLM05: Improper Output Handling
- LLM06: Excessive Agency
- LLM07: System Prompt Leakage
- LLM08: Vector and Embedding Weaknesses
- LLM09: Misinformation
- LLM10: Unbounded Consumption

NIST AI RMF 1.0 — assess gaps across all four functions:
- GOVERN (GV): Policies, accountability, culture, risk tolerance for AI
- MAP (MP): Categorize AI context, risk identification, impact assessment
- MEASURE (MS): Metrics, testing, monitoring, bias/robustness evaluation
- MANAGE (MG): Risk prioritization, response plans, residual risk tracking"""


TOOL_SCHEMA = {
    "name": "generate_threat_model",
    "description": "Output a structured AI system threat model",
    "input_schema": {
        "type": "object",
        "properties": {
            "executive_summary": {
                "type": "string",
                "description": "2-3 paragraph executive summary covering overall risk posture, most critical threats, and top priorities"
            },
            "threats": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id":          {"type": "string", "description": "T-01, T-02, ..."},
                        "title":       {"type": "string"},
                        "description": {"type": "string", "description": "What the threat is and why it matters for this specific system"},
                        "component":   {"type": "string", "description": "The specific system component affected"},
                        "stride_category": {
                            "type": "string",
                            "enum": ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"]
                        },
                        "atlas_id":    {"type": "string", "description": "MITRE ATLAS technique ID, e.g. AML.T0051"},
                        "atlas_name":  {"type": "string", "description": "MITRE ATLAS technique name"},
                        "owasp_llm":   {"type": "string", "description": "OWASP LLM Top 10 category, e.g. LLM01"},
                        "severity":    {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                        "likelihood":  {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                        "attack_path": {"type": "string", "description": "Numbered step-by-step attack scenario specific to this system"},
                        "mitigation":  {"type": "string", "description": "Concrete technical mitigation steps"},
                        "detection":   {"type": "string", "description": "How to detect or monitor for this threat"}
                    },
                    "required": ["id", "title", "description", "component", "stride_category", "severity", "likelihood", "attack_path", "mitigation"]
                }
            },
            "nist_gaps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "function":      {"type": "string", "enum": ["GOVERN", "MAP", "MEASURE", "MANAGE"]},
                        "category_id":   {"type": "string", "description": "e.g. GV-1.1, MP-2.3"},
                        "category_name": {"type": "string"},
                        "status":        {"type": "string", "enum": ["Missing", "Partial", "Present"]},
                        "recommendation":{"type": "string"}
                    },
                    "required": ["function", "category_name", "status", "recommendation"]
                }
            },
            "remediation_roadmap": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "phase":   {"type": "string", "enum": ["Immediate (0-30 days)", "Short-term (30-90 days)", "Long-term (90+ days)"]},
                        "actions": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["phase", "actions"]
                }
            }
        },
        "required": ["executive_summary", "threats", "nist_gaps", "remediation_roadmap"]
    }
}


def analyze(arch_text: str, system_name: str, api_key: str, model: str) -> dict:
    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model=model,
        max_tokens=8000,
        system=SYSTEM_PROMPT,
        tools=[TOOL_SCHEMA],
        tool_choice={"type": "tool", "name": "generate_threat_model"},
        messages=[
            {
                "role": "user",
                "content": (
                    f"Perform a comprehensive threat model for the following AI system.\n\n"
                    f"{arch_text}\n\n"
                    "Be specific to this architecture. Reference the actual component names. "
                    "Do not generate generic AI threats — every finding must be grounded in the system described."
                )
            }
        ]
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "generate_threat_model":
            return block.input

    raise RuntimeError(
        "Claude did not return a structured threat model. "
        f"Stop reason: {response.stop_reason}. Try again or check your API key."
    )
