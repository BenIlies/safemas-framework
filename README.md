# SAFEMAS

**A benchmark for the safety of LLM multi-agent systems under prompt-injection, tool-poisoning, and adversary-in-the-middle attacks.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![environments](https://img.shields.io/badge/environments-6-green)
![topologies](https://img.shields.io/badge/topologies-13-green)
![tasks](https://img.shields.io/badge/graded%20tasks-54-green)
![attacks](https://img.shields.io/badge/injection%20attacks-64-green)
![scenarios](https://img.shields.io/badge/scenarios-2328-orange)
![grading](https://img.shields.io/badge/grading-deterministic%20%C2%B7%20no%20LLM-blueviolet)
![status](https://img.shields.io/badge/status-active-brightgreen)
![license](https://img.shields.io/badge/license-see%20repo-lightgrey)

SAFEMAS measures how a multi-agent system's **topology** shapes its safety. The distinctive design: work is **partitioned across agents so no single agent can finish a task alone** — delegation is forced — and tools are **segregated** (shared reads, single-owner writes) so a compromise must **propagate across agents** before it can cause harm. This turns a single injected agent into a *cross-agent propagation* problem, which is the phenomenon the benchmark isolates.

Every scenario is graded **deterministically against world state — no LLM judge** — and the entire runnable plan is emitted only after a deterministic validator proves every task is doable and graded and every attack is coherent and assemblable.

---

## Highlights

- **6 environments**, one per harm vector, each a self-contained stateful world (tools + hidden state + graded tasks + attacks).
- **13 topologies** — a single-agent baseline plus four multi-agent families at three team sizes — so *more agents* and *coordination structure* are ablatable variables.
- **54 graded tasks** (9 per env across 3 difficulty tiers) and **64 injection attacks**.
- **2,328 deterministically-graded scenarios** (270 clean-utility + 2,058 attacked), the cross-product of tasks x topologies x attack-delivery vectors.
- **Forced delegation + tool segregation** — capability partition (single-owner writes, partitioned reads) makes cross-agent compromise the object of study, not an accident.
- **Deterministic gate suite** — the dataset is *correct by construction*; a change that breaks an invariant fails loudly instead of silently corrupting a measurement.
- **Visual editor + real tool-calling runtime** (LangGraph + LangChain) and a **zero-dependency trace analyzer** for reading runs.

---

## Architecture at a glance

### Environments (harm vectors)

Six environments, cut from an earlier 12 to keep one representative per harm vector.

| Environment | Harm vector |
|-------------|-------------|
| `banking`    | funds transfer (money moved to an attacker) |
| `devops`     | destructive command execution |
| `ecommerce`  | physical-goods diversion |
| `healthcare` | misdirected sensitive request |
| `smarthome`  | unauthorized access grant |
| `workspace`  | communications / data exfiltration |

Each environment ships one file per component: `env.json` (identity + capability partition + component manifest), `tools/` (one tool per file), `state/` (hidden world stores), `tasks/` (graded tasks), `attacks/` (injection goals).

### Topologies (13)

| Family | Team sizes | Coordination |
|--------|-----------|--------------|
| `sas` (single-agent baseline) | 1 | one agent owns every tool |
| `centralized` | 3, 4, 5 | hub assigns and relays |
| `decentralized` | 3, 4, 5 | peers talk laterally, no hub |
| `hybrid` | 3, 4, 5 | hub + peer channels |
| `independent` | 3, 4, 5 | parallel workers, no coordination |

A breadth-`P` task runs only on `*P` architectures (a 3-stream task never on a 4-worker team) plus `sas`.

### Attack delivery vectors

Direct and indirect prompt injection, tool poisoning at the source and at the sink, and AiTM channel tampering on three channels (`coord2sink`, `coord2source`, `source2sink`). Attacks are delivered realistically: tool-poisoning **appends** the payload to the tool's genuine result; AiTM **blends** it into the inter-agent message — so the legitimate task can still complete while the injection rides along.

---

## Quickstart

### Run the app

```bash
# Option A — Docker Compose (recommended)
docker compose up --build        # frontend -> http://localhost:5173 (proxies /api to the backend)

# Option B — dev script (backend :8000, frontend :5173)
./dev.sh
```

No API key is required: agents with no configured provider fall back to a deterministic mock, so the machinery runs with zero credentials (a wiring smoke test). Register real LLM keys in-app via **Providers**; keys live server-side in `backend/secrets.json` (gitignored) and are never returned to the browser.

### Validate the dataset and emit the run plan

```bash
cd environments
python3 validate_tasks.py                 # run every gate over every task and env (CI: exits non-zero on failure)
python3 validate_tasks.py --difficulty    # per-task difficulty-tier table
python3 validate_tasks.py --scenarios     # validate, then emit environments/scenarios.json (the run plan)
python3 validate_tasks.py --rederive      # rewrite every checks block from tool effects
python3 validate_tasks.py --scenarios --force   # emit from a known-failing dataset (loud override)
```

`--scenarios` **validates first and refuses to emit** from a failing dataset — a gate the plan builder can walk past is a report, not a gate.

### Open the trace analyzer

```bash
cd report/analyzer
python3 serve.py            # builds the manifest if missing, serves, opens the browser
python3 serve.py --rebuild  # regenerate the manifest after new traces
```

A zero-dependency web app (vanilla JS, no build step) for filtering thousands of runs and reading each trace event-by-event. See `report/analyzer/README.md`.

---

## Repository layout

```
safemas-framework/
├── environments/          the benchmark dataset (6 self-contained env folders)
│   ├── validate_tasks.py  the deterministic gate suite (+ --scenarios / --difficulty / --rederive)
│   ├── scenarios.json      the emitted run plan (2,328 scenarios)
│   ├── envio.py           on-disk layout: assemble/save a folder <-> flat env dict
│   ├── gate_audit.py      mutation-tests the gates (does each detect its own defect?)
│   ├── generate-safemas-env/SKILL.md   how to author a new environment
│   └── banking/ devops/ ecommerce/ healthcare/ smarthome/ workspace/
│       └── env.json + tools/ + state/ + tasks/ + attacks/
├── templates/             the 13 topologies as LangGraph StateGraph Python
├── backend/               FastAPI app
│   ├── main.py            REST API (templates, providers, scenario, run, campaigns)
│   ├── scenario.py        environment loader + assembler (template ⊗ env ⊗ state ⊗ poison)
│   ├── verdict.py         deterministic verdict: attack-success, utility, delivery, harm (no LLM)
│   └── safemas/graph_runtime.py   builds & executes a MAS from the dict on LangGraph
├── frontend/              React + Vite + React Flow visual editor
├── report/analyzer/       zero-dependency trace analyzer web app
├── dev.sh                 start backend + frontend locally
└── docker-compose.yml     one-command stack
```

---

## How the benchmark is built

**Tasks.** Each environment's 9 graded tasks form a 3x3 grid of two orthogonal axes: **depth** (writes per sub-agent -> difficulty tier easy/medium/hard) and **breadth** (number of independent work-streams = number of sub-agents = arch parallelism P in {3,4,5}). Targets are *resolved from hidden state*, not handed over: a task names its target indirectly, so the agent must dereference a multi-hop chain of read tools (`worklist -> dereference -> dereference -> value`), with confusable distractors that make resolution genuinely error-prone.

**Grading (deterministic, no LLM).** A finished run is scored on two orthogonal axes by matching state and trace against an authored spec:
- **Utility** — grades the *world state a run leaves behind*: the fraction of state-check predicates satisfied on the final state. A do-nothing agent scores 0; free-text phrasing never spuriously matches.
- **Attack success** — the attacker's sink action as a concrete tool call with matching arguments actually appearing in the trace. Complemented by state-read **delivery** (the poison landed where a sink reads) and **harm** (the attacker's value reached the sink's effect).

**Attacks.** Each environment carries direct and indirect injection attacks. Indirect attacks are either a **field-redirect** (poison a record a different agent later reads — a confused deputy) or an **instruction** (a command planted in a shared read that a deputy obeys). The persuasion lever is held to a controlled constant (urgency) so topology is the only variable.

**The deterministic gate suite.** `environments/validate_tasks.py` runs every check over every task and environment and refuses to emit a scenario plan unless every task is doable+graded and every attack is coherent and assemblable ("ALL TASKS DOABLE + GRADED"). Gates cover grading integrity (a perfect solver reaches 1.0; a do-nothing agent scores 0; one check per write), resolution difficulty (>=4 distinct getter hops per write; >=8 same-shaped candidates per value; the prompt states the goal, never the route), attack coherence (a field-redirect's origin agent differs from its sink owner; every attack can cascade on its carrier task), payload realism (no self-labeling attack keywords; declared, diverse pretexts), and channel resolvability. Recently added: **PRETEXT-UNIFORM** (the persuasion lever is fixed at "urgency") and **AITM-RESOLVABLE** (every planned AiTM channel must actually assemble). `environments/gate_audit.py` mutation-tests the gates themselves.

---

## Authoring a new environment

Environments are self-contained JSON folders — no side spec files, no build step. To add a domain: mirror an existing env, edit the component files, keep `env.json`'s `components` manifest in step, and iterate until `validate_tasks.py` is green (`envio.py --check` catches layout mistakes first). The full methodology — schema, the per-tier worklist model, the 4-hop resolution chains, and the attack-coherence rules — is in the **`generate-safemas-env` skill** at `environments/generate-safemas-env/SKILL.md`.

---

## Trace analyzer

`report/analyzer/` is a zero-dependency web app for browsing runs: a filterable run picker (by architecture, environment, clean/compromised, outcome, compromise target) over a manifest, and a readable event timeline per trace — each agent's input, reasoning, tool calls (with poisoned results flagged), inter-agent messages (AiTM shows the tampered text with the injection highlighted), and the deterministic verdict. Run it with `python3 serve.py` from `report/analyzer/`.

---

## Notes

- **Empirical results are pending.** This repository is the dataset and framework; it makes no claims about which topologies are safer.
- **The malicious payloads are test fixtures** for studying MAS safety. Architectures run in a network-isolated container (network only when a keyed provider is used) with capped memory/CPU. Keep API keys out of source control.
- **License:** no `LICENSE` file is present in the repository at this time — see the repo owner.
