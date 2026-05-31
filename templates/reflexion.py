# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('reflexion', task='Solve a task, learn from failed attempts, and retry until it succeeds.', group='Reasoning & reflection', title='Reflexion (Shinn 2023)')

# agents
actor = mas.agent('Actor', role='policy', at=(140, 190))
evaluator = mas.agent('Evaluator', role='scorer', at=(460, 60))
self_reflection = mas.agent('Self-Reflection', role='verbal-critic', join='all', at=(460, 330))

# resources
episodic_memory = mas.memory('Episodic Memory', backend='vector', at=(180, 440))

# wiring
actor.to(evaluator, label='trajectory')
actor.to(self_reflection, label='trajectory')
evaluator.to(self_reflection, label='reward')
self_reflection.to(actor, label='reflection', loop=True, max_iters=3, until='success')
actor.uses(episodic_memory)
self_reflection.uses(episodic_memory)

# entry / exit
mas.entry(actor, at=(-220, 110))
mas.exit(actor, at=(-220, 270))

if __name__ == "__main__":
    mas.run()
