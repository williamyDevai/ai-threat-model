#!/usr/bin/env python3
"""threatscan — AI System Threat Modeling CLI

Usage:
  # No API key needed — runs on local Ollama (auto-detected)
  python threatscan.py --file examples/rag_pipeline.yaml

  # Explicit Ollama backend
  python threatscan.py --file examples/rag_pipeline.yaml --backend ollama

  # Claude backend (requires ANTHROPIC_API_KEY in .env)
  python threatscan.py --file examples/rag_pipeline.yaml --backend claude

  # Save report
  python threatscan.py --file examples/rag_pipeline.yaml --output reports/rag.md

  # JSON output
  python threatscan.py --file examples/agentic_security_triage.yaml --format json
"""

import argparse
import os
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

from threats.report import generate_markdown, generate_json

load_dotenv()

DEFAULT_CLAUDE_MODEL  = "claude-sonnet-4-6"
DEFAULT_OLLAMA_MODEL  = "llama3"
DEFAULT_OLLAMA_URL    = "http://localhost:11434"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatscan",
        description="Generate a STRIDE + MITRE ATLAS + OWASP LLM + NIST AI RMF threat model for any AI system.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
backends:
  ollama  — runs locally, no API key required (default when no ANTHROPIC_API_KEY is set)
  claude  — Anthropic API, higher quality (requires ANTHROPIC_API_KEY in .env)

examples:
  # Fully local — no API key
  python threatscan.py --file examples/rag_pipeline.yaml --backend ollama

  # Auto-detect backend (ollama if no key, claude if key present)
  python threatscan.py --file examples/rag_pipeline.yaml --verbose

  # Save Markdown report
  python threatscan.py --file examples/rag_pipeline.yaml --output reports/rag.md

  # JSON output
  python threatscan.py --file examples/agentic_security_triage.yaml --format json

  # Different local model
  python threatscan.py --file examples/rag_pipeline.yaml --backend ollama --ollama-model mistral

  # Higher-quality Claude output
  python threatscan.py --file examples/rag_pipeline.yaml --backend claude --model claude-opus-4-8
        """,
    )
    parser.add_argument(
        "arch",
        nargs="?",
        metavar="DESCRIPTION",
        help="Plain-text architecture description",
    )
    parser.add_argument(
        "--file", "-f",
        metavar="PATH",
        help="YAML architecture file (see examples/)",
    )
    parser.add_argument(
        "--backend",
        choices=["claude", "ollama", "auto"],
        default="auto",
        help="LLM backend: claude | ollama | auto (default: auto)",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PATH",
        help="Write report to file instead of stdout",
    )
    parser.add_argument(
        "--model", "-m",
        default=None,
        help=f"Claude model name (default: {DEFAULT_CLAUDE_MODEL})",
    )
    parser.add_argument(
        "--ollama-model",
        default=DEFAULT_OLLAMA_MODEL,
        help=f"Ollama model name (default: {DEFAULT_OLLAMA_MODEL})",
    )
    parser.add_argument(
        "--ollama-url",
        default=DEFAULT_OLLAMA_URL,
        help=f"Ollama base URL (default: {DEFAULT_OLLAMA_URL})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show progress messages",
    )
    return parser


def resolve_backend(args) -> str:
    """Resolve 'auto' to a concrete backend."""
    if args.backend != "auto":
        return args.backend
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    return "claude" if api_key.startswith("sk-ant") else "ollama"


def load_yaml_arch(path: str) -> tuple[str, str]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    name = data.get("name", Path(path).stem)
    desc = data.get("description", "")
    parts = [f"System: {name}", f"\nDescription:\n{desc}"]

    components = data.get("components", [])
    if components:
        comp_lines = "\n".join(
            f"  - {c['name']} (type: {c.get('type', 'unknown')})"
            + (f", provider: {c['provider']}" if "provider" in c else "")
            for c in components
        )
        parts.append(f"\nComponents:\n{comp_lines}")

    flows = data.get("data_flows", [])
    if flows:
        parts.append("\nData Flows:\n" + "\n".join(f"  - {fl}" for fl in flows))

    boundaries = data.get("trust_boundaries", [])
    if boundaries:
        parts.append("\nTrust Boundaries:\n" + "\n".join(f"  - {b}" for b in boundaries))

    return name, "\n".join(parts)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.arch and not args.file:
        parser.error("Provide an architecture description (positional) or --file PATH")
    if args.arch and args.file:
        parser.error("Provide either a description or --file, not both")

    backend = resolve_backend(args)

    # Load architecture
    if args.file:
        if not Path(args.file).exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        system_name, arch_text = load_yaml_arch(args.file)
    else:
        system_name = "AI System"
        arch_text = args.arch

    # Route to backend
    if backend == "claude":
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            print(
                "Error: ANTHROPIC_API_KEY not set.\n"
                "  cp .env.example .env  # then add your key\n"
                "  Or run without a key:  --backend ollama",
                file=sys.stderr,
            )
            sys.exit(1)
        from threats.analyzer import analyze
        model = args.model or DEFAULT_CLAUDE_MODEL
        if args.verbose:
            print(f"System:   {system_name}", file=sys.stderr)
            print(f"Backend:  Claude ({model})", file=sys.stderr)
            print(f"Calling Anthropic API...", file=sys.stderr)
        run_analyze = lambda: analyze(arch_text, system_name, api_key, model)

    else:  # ollama
        from threats.ollama_analyzer import analyze as ollama_analyze
        model = args.ollama_model
        if args.verbose:
            print(f"System:   {system_name}", file=sys.stderr)
            print(f"Backend:  Ollama ({model}) at {args.ollama_url}", file=sys.stderr)
            print(f"Running local model — this may take 1-3 minutes...", file=sys.stderr)
        run_analyze = lambda: ollama_analyze(arch_text, system_name, args.ollama_url, model)

    # Run analysis
    try:
        result = run_analyze()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    threat_count = len(result.get("threats", []))
    if args.verbose:
        print(f"Done — {threat_count} threats identified.", file=sys.stderr)

    # Format
    output = generate_json(result, system_name) if args.format == "json" \
             else generate_markdown(result, system_name)

    # Output
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
