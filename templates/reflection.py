# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('reflection', task='Draft and refine a short blog post.', group='Reasoning & reflection', title='Reflection (generator ↺ critic)')

# agents
generator = mas.agent('Generator', role='drafter', at=(120, 150))
critic = mas.agent('Critic', role='reviewer', at=(400, 150))
finaliser = mas.agent('Finaliser', role='finaliser', at=(680, 150))

# resources
draft_store = mas.memory('Draft Store', backend='kv', at=(260, 340))

# wiring
generator.to(critic, label='draft')
critic.to(generator, label='critique', loop=True, max_iters=3, until='approved')
critic.to(finaliser, label='approved')
generator.uses(draft_store)
critic.uses(draft_store)

# entry / exit
mas.entry(generator, at=(-120, 160))
mas.exit(finaliser, at=(860, 160))

if __name__ == "__main__":
    mas.run()
