"""Report generation — Markdown and JSON output from threat model data."""

import json
from datetime import date

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

STRIDE_ABBREV = {
    "Spoofing":              "S",
    "Tampering":             "T",
    "Repudiation":           "R",
    "Information Disclosure":"I",
    "Denial of Service":     "D",
    "Elevation of Privilege":"E",
}

STATUS_EMOJI = {
    "Missing": "❌",
    "Partial": "⚠️",
    "Present": "✅",
}


def generate_markdown(result: dict, system_name: str) -> str:
    today = date.today().isoformat()
    threats  = result.get("threats", [])
    gaps     = result.get("nist_gaps", [])
    roadmap  = result.get("remediation_roadmap", [])

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in threats:
        counts[t.get("severity", "MEDIUM")] = counts.get(t.get("severity", "MEDIUM"), 0) + 1

    lines = [
        f"# AI Threat Model — {system_name}",
        "",
        f"**Date:** {today}  ",
        f"**Frameworks:** STRIDE · MITRE ATLAS v2.1 · OWASP LLM Top 10 (2025) · NIST AI RMF 1.0  ",
        f"**Threats found:** "
        + " · ".join(f"{SEVERITY_EMOJI[s]} {n} {s}" for s, n in counts.items() if n > 0),
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        result.get("executive_summary", ""),
        "",
        "---",
        "",
        "## Threat Inventory",
        "",
        "| ID | Severity | Threat | Component | STRIDE | ATLAS | OWASP LLM |",
        "|----|----------|--------|-----------|--------|-------|-----------|",
    ]

    for t in threats:
        sev    = t.get("severity", "MEDIUM")
        emoji  = SEVERITY_EMOJI.get(sev, "⚪")
        stride = STRIDE_ABBREV.get(t.get("stride_category", ""), "?")
        atlas  = t.get("atlas_id", "—")
        owasp  = t.get("owasp_llm", "—")
        lines.append(
            f"| {t['id']} | {emoji} {sev} | {t['title']} "
            f"| {t.get('component', '—')} | {stride} | {atlas} | {owasp} |"
        )

    lines += [
        "",
        "> **STRIDE key:** S=Spoofing  T=Tampering  R=Repudiation  "
        "I=Info Disclosure  D=Denial of Service  E=Elevation of Privilege",
        "",
        "---",
        "",
        "## Detailed Findings",
        "",
    ]

    for t in threats:
        sev   = t.get("severity", "MEDIUM")
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        atlas_str = f"{t.get('atlas_id', '')} {t.get('atlas_name', '')}".strip() or "—"

        lines += [
            f"### {t['id']} — {t['title']}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {emoji} {sev} |",
            f"| **Likelihood** | {t.get('likelihood', '—')} |",
            f"| **Component** | {t.get('component', '—')} |",
            f"| **STRIDE** | {t.get('stride_category', '—')} |",
            f"| **MITRE ATLAS** | {atlas_str} |",
            f"| **OWASP LLM** | {t.get('owasp_llm', '—')} |",
            "",
            t.get("description", ""),
            "",
            "**Attack Path**",
            "",
            t.get("attack_path", "—"),
            "",
            "**Mitigation**",
            "",
            t.get("mitigation", "—"),
        ]

        detection = t.get("detection", "").strip()
        if detection:
            lines += ["", "**Detection**", "", detection]

        lines.append("")

    # NIST AI RMF gaps
    lines += ["---", "", "## NIST AI RMF Gap Analysis", ""]

    for fn in ["GOVERN", "MAP", "MEASURE", "MANAGE"]:
        fn_gaps = [g for g in gaps if g.get("function") == fn]
        if not fn_gaps:
            continue
        lines += [f"### {fn}", "", "| Category | Status | Recommendation |", "|----------|--------|----------------|"]
        for g in fn_gaps:
            st    = g.get("status", "Missing")
            emoji = STATUS_EMOJI.get(st, "❓")
            cat   = f"{g.get('category_id', '')} {g.get('category_name', '')}".strip()
            lines.append(f"| {cat} | {emoji} {st} | {g['recommendation']} |")
        lines.append("")

    # Remediation roadmap
    lines += ["---", "", "## Remediation Roadmap", ""]

    phase_order = [
        "Immediate (0-30 days)",
        "Short-term (30-90 days)",
        "Long-term (90+ days)",
    ]
    phase_map = {p.get("phase"): p for p in roadmap}

    for phase in phase_order:
        data = phase_map.get(phase)
        if not data:
            continue
        lines += [f"### {phase}", ""]
        for action in data.get("actions", []):
            lines.append(f"- {action}")
        lines.append("")

    lines += [
        "---",
        "",
        "_Generated with [threatscan](https://github.com/williamyuan/ai-threat-model) · "
        "STRIDE · MITRE ATLAS v2.1 · OWASP LLM Top 10 (2025) · NIST AI RMF 1.0_",
    ]

    return "\n".join(lines)


def generate_json(result: dict, system_name: str) -> str:
    payload = {
        "system":     system_name,
        "date":       date.today().isoformat(),
        "frameworks": ["STRIDE", "MITRE ATLAS v2.1", "OWASP LLM Top 10 (2025)", "NIST AI RMF 1.0"],
        **result,
    }
    return json.dumps(payload, indent=2)
