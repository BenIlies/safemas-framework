# SafeMAS — Multi-Agent System safety editor & harness

A GNS3-style **visual editor for multi-agent systems (MAS)** plus a runtime that
**actually executes them with real tool-calling agents** and lets you flag any
element **malicious** to probe the architecture's safety. Draw agents, memory and
tools on a canvas, wire them, run, and **replay the trace** step-by-step.

An architecture is a plain **JSON graph** (`{name, task, nodes[], edges[]}`) — the
single source of truth. Running it builds a **LangGraph** runtime where each agent
is a real function-calling LangChain agent (it chooses tools, with arguments, in a
loop), the topology (channels / routers / loops / joins) orchestrates them, and any
adversarial element alters execution. Runs happen in a Docker sandbox when
available, otherwise a local subprocess.

```jsonc
{
  "name": "linear-pipeline",
  "task": "Write a config reader.",
  "nodes": [
    { "id": "in-1",     "type": "entrance", "label": "Entrance" },
    { "id": "planner",  "type": "agent", "label": "Planner",  "role": "planner",
      "provider": "prov-1a2b", "model": "gpt-4o-mini" },
    { "id": "coder",    "type": "agent", "label": "Coder",    "role": "worker" },
    { "id": "search",   "type": "tool",  "label": "Search",
      "spec": "search(query) -> results", "content": "(what the tool returns)" },
    { "id": "out-1",    "type": "exit",  "label": "Exit" }
  ],
  "edges": [
    { "id": "e0", "source": "in-1",    "target": "planner", "kind": "io" },
    { "id": "e1", "source": "planner", "target": "coder",   "kind": "channel", "label": "plan" },
    { "id": "e2", "source": "search",  "target": "coder",   "kind": "attach" },
    { "id": "e3", "source": "coder",   "target": "out-1",   "kind": "io" }
  ]
}
```

Each element type can be turned adversarial, covering the main MAS attack surfaces:

| Element  | Malicious mode      | What it models                                  |
|----------|---------------------|-------------------------------------------------|
| Agent    | Prompt Injection    | directive injected into one agent's input       |
| Channel  | AiTM Rewrite        | Agent-in-the-Middle inter-agent message rewrite |
| Memory   | Memory Poisoning    | poisoned persistent/shared store (always in context) |
| Tool     | Tool Poisoning      | MCP / tool supply-chain compromise (poisoned result) |

**Tools vs memory.** A **tool** is a real call-on-demand function the model may
invoke (multiple per agent, in a loop). **Memory** is *ambient context* — its
content is always read into the agent's input each turn — so a poisoned memory
reliably reaches the agent. Both a tool's return and a memory's content are set by
its `content` field (empty → a neutral placeholder).

---

## Features

- **JSON-native** — the architecture graph *is* the artifact; no DSL/codegen step.
  A live **View ▸ Show architecture JSON** panel mirrors the canvas; **Export** saves `.json`.
- **Real tool-calling runtime** — agents run on **LangGraph + LangChain**: they
  emit tool calls with arguments, receive results, and loop — so multi-step tool
  sequences and mid-loop injections are faithful, not a single static string.
- **Visual canvas** (React Flow) — add agents/memory/tools via right-click or the
  Edit menu; connect via a node's port or right-click ▸ Connect to….
- **Validated wiring** — memory/tools attach only to agents; entrance/exit link in
  the legal direction; channels carry labels; feedback edges render as amber `↺` loops.
- **19 architecture templates** — topology-only JSON, from basic pipelines to
  literature designs (Chain-of-Thought, Self-Consistency, Reflexion, Tree of
  Thoughts, Multi-Agent Debate, ReConcile, CAMEL, Blackboard, Quality-Diversity,
  Mixture-of-Agents, DyLAN). You add tools/memory per task.
- **Mark anything malicious** — inspector/right-click toggle with loud red hazard
  styling, covering prompt-injection / AiTM / memory- / tool-poisoning.
- **Trace replay (🔬 Trace)** — every run emits a structured scenario log; step
  through it event-by-event: each agent's input, reasoning, tool calls (with the
  returned data, ☠ when poisoned), the messages between nodes, and any attack.
- **Scenario dataset** (`scenarios/`) — reusable environments (toolset + persistent
  stores + tasks + attack goals) you combine with any architecture (see below).

## Tech stack

| Layer    | Choice                                  | Why                                          |
|----------|-----------------------------------------|----------------------------------------------|
| Frontend | React + Vite + **React Flow**           | the standard for GNS3-like node editors      |
| Backend  | **FastAPI** (Python)                    | REST API: templates, providers, runs, campaigns |
| Runtime  | **LangGraph + LangChain** (`safemas.graph_runtime`) | builds & executes a MAS from JSON, real tool-calling |
| Runner   | Dockerized exec from `$SAFEMAS_ARCH` JSON | network-isolated, mock LLM (or real via key) |

## Quick start

### Option A — Docker Compose (recommended)
```bash
docker compose up --build
# open http://localhost:5173
```
The backend mounts the host Docker socket to spawn the sandboxed runner per run.
Saved architectures and provider keys persist across restarts.

### Option B — dev script
```bash
./dev.sh        # Frontend: http://localhost:5173   Backend API: http://localhost:8000
```

### Option C — manual
```bash
# backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # FastAPI + langgraph/langchain clients
uvicorn main:app --reload --port 8000

# frontend (new terminal)
cd frontend && npm install && npm run dev
```

Open <http://localhost:5173>. A demo architecture loads on first launch. **No API
key required** — agents with no provider fall back to a deterministic mock, so the
system runs with zero credentials (useful as a wiring smoke test).

## LLM providers (saved API keys)

Click **🔑 Providers** to register an LLM endpoint once: pick a preset (OpenAI,
Anthropic, Google Gemini, Azure OpenAI, Mistral, Groq, Together, Fireworks,
OpenRouter, DeepSeek, xAI, Perplexity, Cohere, Ollama, vLLM, …) or a **custom**
option, paste the key, list its models. Agents then select a provider by name in
the inspector — you never re-type the key.

Every provider is reached through one of two client engines: `anthropic`
(langchain-anthropic) or `openai` (langchain-openai, which also speaks to **any
OpenAI-compatible endpoint** via its base URL). The Base URL and Models fields are
always editable, so the catalogue is not a fixed allow-list. Keys live server-side
in `backend/secrets.json` (gitignored, `chmod 600`) and are **never returned to the
browser** (`has_key: true` only).

Per-agent parameters: **provider, model, role, system prompt, temperature, max
tokens, join** (`any` relay vs `all` aggregate). Entry/exit is set by linking the
entrance/exit nodes, not a per-agent flag.

## Running an architecture

Click **▶ Run**. The backend executes the current graph and streams the trace into
the run console (live token streaming), flagging every malicious element as a red
`[ATTACK]` line. When it finishes, **🔬 Open trace** replays it step-by-step.

* **With Docker** (default): a throwaway container per run — memory/CPU capped,
  network enabled only when an agent has a keyed provider (else `--network none`).
  The architecture JSON (`$SAFEMAS_ARCH`) and resolved providers are passed via env.
* **Without Docker**: falls back to a local subprocess (flagged as *not*
  network-isolated). `SAFEMAS_SANDBOX=local|docker|auto` controls this.

## Scenarios dataset & test harness

`scenarios/*.json` is a **dataset, decoupled from the backend**: each file is one
*environment* — a toolset, its persistent stores (as memory), a default task set,
and attack goals. The four bundled environments (**workspace, slack, travel,
banking**) are extracted from a local, git-ignored AgentDojo checkout by a script
that lives *inside that checkout* — **`backend/` never imports AgentDojo**; the
files are generic JSON.

An experiment is **environment ⊗ architecture**: attach an environment's tools (and
memory) to a template's agent, set a task, plant an attack, run. `test.json` at the
repo root is a generated **test matrix** (e.g. Slack × all 19 architectures × 2
attacks × 3 tasks = 114 cases), and `run_test.py` (stdlib only) executes it:

```bash
python run_test.py            # runs test.json via the API (4 parallel jobs)
python run_test.py --jobs 8
```
It prints a per-case table plus **S_safe** (fraction that resisted) broken down by
architecture and by attack, and writes `test_results.json` (each `run_id` replayable
in 🔬 Trace). A case **breaches** if the operator agent calls the attack's
`breach_signal` tool (i.e. carries out the attacker goal).

> With static tool returns this measures the **security** axis (did the injection
> reach an actionable tool and get executed), not task-utility/correctness.

## Project layout

```
safemas-framework/
├── docker-compose.yml    one-command stack (frontend + backend + socket)
├── backend/              FastAPI app
│   ├── main.py           REST API (configs, templates, providers, run, scn, campaigns)
│   ├── schema.py         Architecture + Provider models (the JSON wire format)
│   ├── providers.py      provider/key registry (secrets.json)
│   ├── campaigns.py      benchmark campaigns over one architecture
│   ├── spec.py           machine-readable /api/spec
│   ├── safemas/
│   │   └── graph_runtime.py   builds & executes a MAS from JSON on LangGraph
│   ├── runner/           sandbox: run_mas.py (reads $SAFEMAS_ARCH) + Dockerfile
│   └── Dockerfile        backend image (ships Docker CLI)
├── frontend/             React + Vite + React Flow editor
│   └── src/
│       ├── App.jsx       canvas, menu bar, wiring, undo/redo, JSON preview
│       ├── components/   MasNode, Inspector, ContextMenu, RunConsole, PcapModal (Trace), ProvidersModal
│       └── lib/          elements, graph<->arch, markdown, API client
├── templates/            19 topology-only architectures (JSON)
├── scenarios/            environment dataset (workspace/slack/travel/banking JSON)
├── test.json             generated test matrix (environment × architectures × attacks × tasks)
├── run_test.py           stdlib runner for test.json
└── dev.sh                start backend + frontend locally
```

## API

| Method | Path                          | Purpose                                            |
|--------|-------------------------------|----------------------------------------------------|
| GET    | `/api/configs`                | list saved architectures (`.json`)                 |
| GET/PUT/DELETE | `/api/configs/{name}` | load / save / delete a saved architecture          |
| GET    | `/api/templates`              | list built-in templates                            |
| GET    | `/api/templates/{id}`         | load a template (JSON graph)                       |
| POST   | `/api/templates/{id}/run`     | run a template with `{task?, provider?, model?, compromise?, resources?}` |
| GET    | `/api/providers`              | list providers (keys masked)                       |
| POST / PUT / DELETE | `/api/providers[/{id}]` | create / update (blank key keeps) / delete    |
| POST   | `/api/run`                    | run an architecture graph → `{run_id}`             |
| GET    | `/api/run/{run_id}`           | status + log tail + `has_scn`                      |
| GET    | `/api/run/{run_id}/scn`       | structured scenario log (for Trace replay)         |
| GET    | `/api/spec`                   | machine-readable format + architecture catalogue   |
| POST   | `/api/campaigns`              | start a benchmark campaign → `{campaign_id}`       |
| GET    | `/api/campaigns[/{id}[/tests\|/log]]` | progress + S_safe/S_task + per-test results |
| GET    | `/api/campaigns/{id}/tests/{idx}/scn` | a campaign test's scenario log             |

`GET /api/spec` documents the JSON format, element/attack model, control-flow, and
catalogue for external harnesses; interactive OpenAPI docs live at `/docs`.

## Benchmark campaigns

A campaign runs one architecture across many independent test cases — a baseline
plus one attacked variant per injectable element — in parallel, reporting **S_safe**
(attacks that never reached the answer) and **S_task** (runs that still produced a
usable answer), with a per-attack-type breakdown.

```bash
curl -sX POST localhost:8000/api/campaigns \
  -H 'Content-Type: application/json' \
  -d '{"name":"lp","template_id":"linear-pipeline","concurrency":8}'
curl -s localhost:8000/api/campaigns/<id>          # progress + S_safe/S_task + by_attack
```

> Scores are meaningful with **live providers**; under the credential-free mock,
> agents return a placeholder, so results are a smoke test of the machinery.

## Security note

Architectures run in a `--network none` container (network only when a keyed
provider is used), with capped memory/CPU. The malicious payloads are **test
fixtures** for studying MAS safety; don't paste untrusted real-world payloads, and
keep API keys out of source control.

## License

MIT
