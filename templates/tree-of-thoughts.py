# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('tree-of-thoughts', task='Solve a problem by searching over a tree of reasoning steps.', group='Reasoning & reflection', title='Tree of Thoughts (Yao 2023)')

# agents
thought_generator = mas.agent('Thought Generator', role='proposer', prompt='Propose k candidate next reasoning steps from the current state.', at=(180, 170))
state_evaluator = mas.agent('State Evaluator', role='evaluator', prompt='Score candidate states (sure / likely / impossible) to guide the search.', at=(500, 170))

# wiring
thought_generator.to(state_evaluator, label='k candidate thoughts')
state_evaluator.to(thought_generator, label='expand / prune (BFS/DFS)', loop=True, max_iters=3, until='solved')

# entry / exit
mas.entry(thought_generator, at=(-140, 180))
mas.exit(state_evaluator, at=(820, 180))

if __name__ == "__main__":
    mas.run()
