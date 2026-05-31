#!/usr/bin/env python3
"""Generate the built-in template library as SafeMAS DSL .py files.

Each template is built with the DSL itself, then written via the codegen, so the
files are byte-for-byte what the editor round-trips — the templates *are* code.

    python backend/scripts/gen_templates.py        # writes templates/*.py
"""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from safemas import MAS                       # noqa: E402
from safemas.codegen import arch_to_code, mas_to_arch  # noqa: E402

OUT = BACKEND.parent / "templates"
HEADER = (
    "# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).\n"
    "# Clean: no malicious elements (add attacks in the editor, or call\n"
    "# .compromise(payload) on any element, to probe a design).\n"
    "# Regenerate with:  python backend/scripts/gen_templates.py\n\n"
)

TEMPLATES: dict[str, "MAS"] = {}


def reg(file_id: str, mas: MAS) -> MAS:
    TEMPLATES[file_id] = mas
    return mas


# --------------------------------------------------------------------------- #
# Basics
# --------------------------------------------------------------------------- #
m = reg("starter", MAS("new-mas", task="Solve the assigned task.",
                       group="Basics", title="Starter (entrance → exit)"))
a = m.agent("Agent", role="assistant", at=(300, 150))
m.entry(a, at=(60, 160)); m.exit(a, at=(560, 160))

m = reg("single-agent", MAS("single-agent", task="Answer the user’s question.",
                            group="Basics", title="Single agent + tool"))
assistant = m.agent("Assistant", role="assistant", at=(330, 150))
assistant.uses(m.tool("Calculator", spec="def calc(expr: str) -> str", at=(330, 330)))
m.entry(assistant, at=(60, 160)); m.exit(assistant, at=(600, 160))

# --------------------------------------------------------------------------- #
# Workflows
# --------------------------------------------------------------------------- #
m = reg("linear-pipeline", MAS("linear-pipeline",
        task="Write a function that reads a config file and returns its contents.",
        group="Workflows", title="Linear pipeline"))
planner = m.agent("Planner", role="planner", at=(100, 150))
coder = m.agent("Coder", role="worker", at=(360, 150))
reviewer = m.agent("Reviewer", role="finaliser", at=(620, 150))
planner.to(coder, label="plan")
coder.to(reviewer, label="code")
coder.uses(m.memory("Shared Memory", backend="vector", at=(360, 330)))
coder.uses(m.tool("Search Tool", spec="def search(q: str) -> str", at=(360, -30)))
m.entry(planner, at=(-120, 160)); m.exit(reviewer, at=(860, 160))

m = reg("planner-workers-aggregator", MAS("planner-workers-aggregator",
        task="Research a topic and produce a concise summary.",
        group="Workflows", title="Planner / workers / aggregator"))
planner = m.agent("Planner", role="planner", at=(100, 170))
worker_a = m.agent("Worker A", role="worker", at=(380, 50))
worker_b = m.agent("Worker B", role="worker", at=(380, 300))
agg = m.agent("Aggregator", role="finaliser", join="all", at=(660, 170))
planner.to(worker_a, label="subtask A")
planner.to(worker_b, label="subtask B")
worker_a.to(agg, label="result A")
worker_b.to(agg, label="result B")
worker_a.uses(m.tool("Web Tool", spec="def fetch(url: str) -> str", at=(380, -130)))
m.entry(planner, at=(-120, 180)); m.exit(agg, at=(900, 180))

m = reg("router-specialists", MAS("router-specialists",
        task="Handle a mixed request that may need code or math.",
        group="Workflows", title="Router → specialists"))
router = m.agent("Router", role="router", at=(100, 190))
code_spec = m.agent("Code Specialist", role="coder", at=(380, 70))
math_spec = m.agent("Math Specialist", role="mathematician", at=(380, 310))
collector = m.agent("Collector", role="finaliser", at=(660, 190))
router.to(code_spec, label="route: code", when="code")
router.to(math_spec, label="route: math", when="math")
code_spec.to(collector, label="answer")
math_spec.to(collector, label="answer")
code_spec.uses(m.tool("Python REPL", spec="def run(code: str) -> str", at=(380, -70)))
math_spec.uses(m.tool("Calculator", spec="def calc(expr: str) -> str", at=(380, 470)))
m.entry(router, at=(-120, 200)); m.exit(collector, at=(900, 200))

m = reg("rag-pipeline", MAS("rag-pipeline",
        task="Answer a question using the knowledge base.",
        group="Workflows", title="RAG (retriever + knowledge base)"))
retriever = m.agent("Retriever", role="retriever", at=(100, 150))
answerer = m.agent("Answerer", role="finaliser", at=(360, 150))
retriever.to(answerer, label="retrieved context")
retriever.uses(m.memory("Knowledge Base", backend="vector", at=(100, 330)))
m.entry(retriever, at=(-120, 160)); m.exit(answerer, at=(600, 160))

m = reg("supervisor-hierarchy", MAS("supervisor-hierarchy",
        task="Plan and execute a multi-step task.",
        group="Workflows", title="Supervisor hierarchy"))
supervisor = m.agent("Supervisor", role="supervisor", at=(360, 60))
researcher = m.agent("Researcher", role="worker", at=(140, 280))
writer = m.agent("Writer", role="worker", at=(580, 280))
supervisor.to(researcher, label="assign")
supervisor.to(writer, label="assign")
researcher.to(supervisor, label="report", loop=True, max_iters=2)
writer.to(supervisor, label="report", loop=True, max_iters=2)
scratch = m.memory("Scratchpad", backend="in-memory", at=(360, 470))
supervisor.uses(scratch); researcher.uses(scratch); writer.uses(scratch)
m.entry(supervisor, at=(60, 60)); m.exit(supervisor, at=(660, 60))

# --------------------------------------------------------------------------- #
# Reasoning & reflection
# --------------------------------------------------------------------------- #
m = reg("chain-of-thought", MAS("chain-of-thought",
        task="Solve a multi-step reasoning problem, showing the steps.",
        group="Reasoning & reflection", title="Chain-of-Thought (Wei 2022)"))
cot = m.agent("CoT Reasoner", role="reasoner",
              prompt="Reason step by step, then state the final answer.", at=(340, 170))
m.entry(cot, at=(40, 180)); m.exit(cot, at=(640, 180))

m = reg("self-consistency", MAS("self-consistency",
        task="Solve a reasoning problem and vote over several sampled solutions.",
        group="Reasoning & reflection", title="Self-Consistency (Wang 2023)"))
# A single entrance feeds one dispatcher, which broadcasts the task to the
# parallel samplers; the vote aggregates all of them (join="all").
dispatch = m.agent("Dispatcher", role="dispatcher",
                   prompt="Relay the task to each sampler unchanged.", at=(-40, 210))
s1 = m.agent("CoT Sample 1", role="reasoner", temperature=0.7, at=(220, 40))
s2 = m.agent("CoT Sample 2", role="reasoner", temperature=0.7, at=(220, 210))
s3 = m.agent("CoT Sample 3", role="reasoner", temperature=0.7, at=(220, 380))
vote = m.agent("Majority Vote", role="aggregator", join="all",
               prompt="Return the answer that the most reasoning paths agree on.", at=(520, 210))
dispatch.to(s1, label="task"); dispatch.to(s2, label="task"); dispatch.to(s3, label="task")
s1.to(vote, label="answer"); s2.to(vote, label="answer"); s3.to(vote, label="answer")
m.entry(dispatch, at=(-260, 210)); m.exit(vote, at=(820, 210))

m = reg("reflection", MAS("reflection", task="Draft and refine a short blog post.",
        group="Reasoning & reflection", title="Reflection (generator ↺ critic)"))
gen = m.agent("Generator", role="drafter", at=(120, 150))
critic = m.agent("Critic", role="reviewer", at=(400, 150))
finaliser = m.agent("Finaliser", role="finaliser", at=(680, 150))
gen.to(critic, label="draft")
critic.to(gen, label="critique", loop=True, max_iters=3, until="approved")
critic.to(finaliser, label="approved")
draft_store = m.memory("Draft Store", backend="kv", at=(260, 340))
gen.uses(draft_store); critic.uses(draft_store)
m.entry(gen, at=(-120, 160)); m.exit(finaliser, at=(860, 160))

m = reg("reflexion", MAS("reflexion",
        task="Solve a task, learn from failed attempts, and retry until it succeeds.",
        group="Reasoning & reflection", title="Reflexion (Shinn 2023)"))
actor = m.agent("Actor", role="policy", at=(140, 190))
evaluator = m.agent("Evaluator", role="scorer", at=(460, 60))
reflect = m.agent("Self-Reflection", role="verbal-critic", join="all", at=(460, 330))
actor.to(evaluator, label="trajectory")
actor.to(reflect, label="trajectory")
evaluator.to(reflect, label="reward")
reflect.to(actor, label="reflection", loop=True, max_iters=3, until="success")
episodic = m.memory("Episodic Memory", backend="vector", at=(180, 440))
actor.uses(episodic); reflect.uses(episodic)
m.entry(actor, at=(-220, 110)); m.exit(actor, at=(-220, 270))

m = reg("tree-of-thoughts", MAS("tree-of-thoughts",
        task="Solve a problem by searching over a tree of reasoning steps.",
        group="Reasoning & reflection", title="Tree of Thoughts (Yao 2023)"))
gen = m.agent("Thought Generator", role="proposer",
              prompt="Propose k candidate next reasoning steps from the current state.", at=(180, 170))
ev = m.agent("State Evaluator", role="evaluator",
             prompt="Score candidate states (sure / likely / impossible) to guide the search.", at=(500, 170))
gen.to(ev, label="k candidate thoughts")
ev.to(gen, label="expand / prune (BFS/DFS)", loop=True, max_iters=3, until="solved")
m.entry(gen, at=(-140, 180)); m.exit(ev, at=(820, 180))

# --------------------------------------------------------------------------- #
# Debate & collaboration
# --------------------------------------------------------------------------- #
m = reg("multi-agent-debate", MAS("multi-agent-debate",
        task="Reach a correct answer through several rounds of debate.",
        group="Debate & collaboration", title="Multi-Agent Debate (Du/Liang 2023)"))
d1 = m.agent("Debater 1", role="debater", at=(300, 30))
d2 = m.agent("Debater 2", role="debater", at=(150, 380))
d3 = m.agent("Debater 3", role="debater", at=(450, 380))
# A bounded round-robin: each debater revises in turn, looping back for 2 rounds.
d1.to(d2, label="argue")
d2.to(d3, label="argue")
d3.to(d1, label="next round", loop=True, max_iters=2)
m.entry(d1, at=(-200, 210)); m.exit(d3, at=(780, 210))

m = reg("reconcile", MAS("reconcile",
        task="Answer via a round-table of diverse models and a weighted consensus vote.",
        group="Debate & collaboration", title="ReConcile (Chen 2024)"))
ra = m.agent("Agent A (e.g. GPT)", role="round-table", at=(240, 40))
rb = m.agent("Agent B (e.g. Claude)", role="round-table", at=(130, 380))
rc = m.agent("Agent C (e.g. Gemini)", role="round-table", at=(430, 380))
consensus = m.agent("Weighted Consensus", role="aggregator", join="all",
                    prompt="Combine the agents’ answers weighted by their confidence scores.", at=(700, 210))
# A bounded round-table, then every agent casts a final vote into the consensus.
ra.to(rb, label="answer · explanation · confidence")
rb.to(rc, label="answer · explanation · confidence")
rc.to(ra, label="next round", loop=True, max_iters=2)
ra.to(consensus, label="final vote"); rb.to(consensus, label="final vote"); rc.to(consensus, label="final vote")
# Single entry: the task enters the ring head and circulates (ra → rb → rc).
m.entry(ra, at=(-200, 210)); m.exit(consensus, at=(960, 210))

m = reg("camel-role-play", MAS("camel-role-play",
        task="Cooperatively solve a task through instructor / assistant role-play.",
        group="Debate & collaboration", title="CAMEL role-play (Li 2023)"))
specifier = m.agent("Task Specifier", role="specifier",
                    prompt="Rewrite the vague idea into one concrete, specific task.", at=(140, 180))
ai_user = m.agent("AI User", role="instructor",
                 prompt="Give one instruction at a time; never solve the task yourself.", at=(450, 60))
ai_asst = m.agent("AI Assistant", role="executor",
                 prompt="Respond to each instruction with a concrete solution.", at=(450, 320))
specifier.to(ai_user, label="specified task")
ai_user.to(ai_asst, label="instruction")
ai_asst.to(ai_user, label="solution", loop=True, max_iters=3, until="task complete")
m.entry(specifier, at=(-180, 180)); m.exit(ai_asst, at=(780, 300))

m = reg("blackboard", MAS("blackboard",
        task="Solve a problem by coordinating specialists through a shared blackboard.",
        group="Debate & collaboration", title="Blackboard (Hayes-Roth 1985)"))
control = m.agent("Control", role="scheduler",
                 prompt="Inspect the blackboard and pick which specialist should act next.", at=(170, 170))
sp1 = m.agent("Specialist 1", role="specialist", at=(500, 30))
sp2 = m.agent("Specialist 2", role="specialist", at=(500, 190))
sp3 = m.agent("Specialist 3", role="specialist", at=(500, 350))
for sp in (sp1, sp2, sp3):
    control.to(sp, label="activate")
    sp.to(control, label="updated", loop=True, max_iters=2)
board = m.memory("Blackboard", backend="in-memory", at=(300, 480))
control.uses(board); sp1.uses(board); sp2.uses(board); sp3.uses(board)
m.entry(control, at=(-200, 90)); m.exit(control, at=(-200, 250))

# --------------------------------------------------------------------------- #
# Population & layered
# --------------------------------------------------------------------------- #
m = reg("quality-diversity", MAS("quality-diversity",
        task="Evolve a diverse population of high-quality solutions.",
        group="Population & layered", title="Quality-Diversity (MAP-Elites)"))
selector = m.agent("Selector", role="selector", at=(140, 260))
gen_a = m.agent("Generator A", role="generator", at=(440, 80))
gen_b = m.agent("Generator B", role="generator", at=(440, 260))
gen_c = m.agent("Generator C", role="generator", at=(440, 440))
evaluator = m.agent("Evaluator", role="evaluator", join="all",
                   prompt="Score each candidate’s quality and its behaviour descriptor.", at=(740, 260))
# Selector broadcasts elite parents to every generator (so all fire); the
# evaluator aggregates the candidates and the single evolutionary loop is bounded.
for g in (gen_a, gen_b, gen_c):
    selector.to(g, label="elite parent")
    g.to(evaluator, label="candidate")
evaluator.to(selector, label="scored → archive", loop=True, max_iters=3)
archive = m.memory("Elite Archive", backend="vector", at=(440, 620))
selector.uses(archive); evaluator.uses(archive)
m.entry(selector, at=(-220, 180)); m.exit(selector, at=(-220, 340))

m = reg("mixture-of-agents", MAS("mixture-of-agents",
        task="Answer by layering and aggregating multiple proposer models.",
        group="Population & layered", title="Mixture-of-Agents (Wang 2024)"))
dispatch = m.agent("Dispatcher", role="dispatcher",
                   prompt="Relay the task to each layer-1 proposer.", at=(-120, 260))
l1 = [m.agent(f"Layer 1 · Proposer {c}", role="proposer", at=(120, 80 + i * 180))
      for i, c in enumerate("ABC")]
l2 = [m.agent(f"Layer 2 · Proposer {c}", role="proposer", join="all", at=(440, 80 + i * 180))
      for i, c in enumerate("ABC")]
aggregator = m.agent("Aggregator", role="aggregator", join="all",
                    prompt="Synthesise the last layer’s proposals into one final answer.", at=(740, 260))
# One entrance → dispatcher → broadcast to the (parallel) layer-1 proposers.
for p1 in l1:
    dispatch.to(p1, label="task")
for p1 in l1:
    for p2 in l2:
        p1.to(p2, label="proposal")
for p2 in l2:
    p2.to(aggregator, label="proposal")
m.entry(dispatch, at=(-340, 260)); m.exit(aggregator, at=(960, 260))

m = reg("dylan", MAS("dylan",
        task="Collaborate over rounds while pruning low-contribution agents.",
        group="Population & layered", title="DyLAN (Liu 2024)"))
sv1 = m.agent("Solver 1", role="solver", at=(180, 30))
sv2 = m.agent("Solver 2", role="solver", at=(180, 180))
sv3 = m.agent("Solver 3", role="solver", at=(180, 330))
ranker = m.agent("LLM Ranker", role="ranker", join="all",
                prompt="Rate this round’s responses and keep only the top-ranked agents.", at=(470, 470))
# Solvers share context down a ring, each rates into the ranker (which waits for
# all three), and the ranker prunes / re-opens one more round.
sv1.to(sv2, label="peer context")
sv2.to(sv3, label="peer context")
sv1.to(ranker, label="rate")
sv2.to(ranker, label="rate")
sv3.to(ranker, label="rate")
ranker.to(sv1, label="keep / prune", loop=True, max_iters=1)
m.entry(sv1, at=(-220, 180)); m.exit(ranker, at=(840, 180))


def main() -> int:
    OUT.mkdir(exist_ok=True)
    for file_id, mas in TEMPLATES.items():
        code = HEADER + arch_to_code(mas_to_arch(mas))
        (OUT / f"{file_id}.py").write_text(code)
        print("wrote", f"{file_id}.py")
    print(f"\n{len(TEMPLATES)} template(s) written to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
