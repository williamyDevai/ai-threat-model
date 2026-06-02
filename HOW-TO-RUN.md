# How to Run This Project

A beginner-friendly, copy-paste guide. Everything needed is already installed on this PC.

---

## The fastest way (no API key, no internet)

### Step 1 — Open PowerShell
Press the **Windows key**, type **`PowerShell`**, press **Enter**. A terminal window opens.

### Step 2 — Paste these two lines
```powershell
cd C:\Users\willi\ai-threat-model
python threatscan.py --file examples/rag_pipeline.yaml --backend ollama --verbose
```

That's it. It uses the local **llama3** model already on this machine — no API key, no internet required. After 1–3 minutes it prints a complete threat model (STRIDE + MITRE ATLAS + OWASP LLM Top 10 + NIST AI RMF) to the screen.

---

## Common things you'll want to do

### Save the report to a file
```powershell
python threatscan.py --file examples/rag_pipeline.yaml --backend ollama --output reports/my-report.md
```
The file is saved in `C:\Users\willi\ai-threat-model\reports\`.

### Run it on the other built-in example (autonomous SOC agent)
```powershell
python threatscan.py --file examples/agentic_security_triage.yaml --backend ollama --verbose
```

### Run it on your OWN idea (just describe a system in quotes)
```powershell
python threatscan.py "A chatbot that reads customer emails and issues refunds automatically" --backend ollama --verbose
```

### See the full help menu
```powershell
python threatscan.py --help
```

---

## Optional: much higher quality with Claude

The local llama3 model is small and weak. For sharp, senior-level output, use the Claude API instead. You only set this up once.

```powershell
copy .env.example .env
notepad .env
```
In Notepad, set the line to your real key, then save and close:
```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```
(Get a key at https://console.anthropic.com → API Keys.)

Now run **without** `--backend ollama` — it automatically uses Claude:
```powershell
python threatscan.py --file examples/rag_pipeline.yaml --verbose
```

---

## Cheat-sheet

| I want to… | Command |
|------------|---------|
| Run it (no setup) | `python threatscan.py --file examples/rag_pipeline.yaml --backend ollama -v` |
| Save to a file | add `--output reports/my-report.md` |
| Use my own idea | `python threatscan.py "describe your system" --backend ollama -v` |
| Use Claude (better) | set up `.env`, then drop `--backend ollama` |
| Help menu | `python threatscan.py --help` |

---

## Writing your own system file (optional)

Instead of a quoted sentence, you can write a detailed YAML file like the ones in `examples/`. Copy one and edit it:

```yaml
name: "My AI System"
description: "What it does, who uses it, where it's deployed"

components:
  - name: "Foundation Model (Claude)"
    type: "foundation_model"
    provider: "Anthropic API"
  - name: "Vector Store (Pinecone)"
    type: "external_service"

data_flows:
  - "User -> API Gateway -> Orchestration Layer"
  - "Orchestration Layer -> Foundation Model (query + retrieved context)"

trust_boundaries:
  - "Public internet (unauthenticated users)"
  - "Anthropic cloud (external LLM API)"
```

Then point the tool at it:
```powershell
python threatscan.py --file path/to/your-file.yaml --backend ollama --verbose
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `python: command not found` | Python isn't on PATH — reopen PowerShell, or reinstall Python with "Add to PATH" checked |
| `Cannot connect to Ollama` | Start it: open the **Ollama** app from the Start menu, then retry |
| `ANTHROPIC_API_KEY not set` | You used the Claude path without a key — either add it to `.env`, or add `--backend ollama` to run locally |
| Output looks thin / generic | That's the small local model — use the Claude backend for depth |
