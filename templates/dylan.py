# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('dylan', task='Collaborate over rounds while pruning low-contribution agents.', group='Population & layered', title='DyLAN (Liu 2024)')

# agents
solver_1 = mas.agent('Solver 1', role='solver', at=(180, 30))
solver_2 = mas.agent('Solver 2', role='solver', at=(180, 180))
solver_3 = mas.agent('Solver 3', role='solver', at=(180, 330))
llm_ranker = mas.agent('LLM Ranker', role='ranker', prompt='Rate this round’s responses and keep only the top-ranked agents.', join='all', at=(470, 470))

# wiring
solver_1.to(solver_2, label='peer context')
solver_2.to(solver_3, label='peer context')
solver_1.to(llm_ranker, label='rate')
solver_2.to(llm_ranker, label='rate')
solver_3.to(llm_ranker, label='rate')
llm_ranker.to(solver_1, label='keep / prune', loop=True, max_iters=1)

# entry / exit
mas.entry(solver_1, at=(-220, 180))
mas.exit(llm_ranker, at=(840, 180))

if __name__ == "__main__":
    mas.run()
