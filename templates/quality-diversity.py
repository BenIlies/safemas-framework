# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('quality-diversity', task='Evolve a diverse population of high-quality solutions.', group='Population & layered', title='Quality-Diversity (MAP-Elites)')

# agents
selector = mas.agent('Selector', role='selector', at=(140, 260))
generator_a = mas.agent('Generator A', role='generator', at=(440, 80))
generator_b = mas.agent('Generator B', role='generator', at=(440, 260))
generator_c = mas.agent('Generator C', role='generator', at=(440, 440))
evaluator = mas.agent('Evaluator', role='evaluator', prompt='Score each candidate’s quality and its behaviour descriptor.', join='all', at=(740, 260))

# resources
elite_archive = mas.memory('Elite Archive', backend='vector', at=(440, 620))

# wiring
selector.to(generator_a, label='elite parent')
generator_a.to(evaluator, label='candidate')
selector.to(generator_b, label='elite parent')
generator_b.to(evaluator, label='candidate')
selector.to(generator_c, label='elite parent')
generator_c.to(evaluator, label='candidate')
evaluator.to(selector, label='scored → archive', loop=True, max_iters=3)
selector.uses(elite_archive)
evaluator.uses(elite_archive)

# entry / exit
mas.entry(selector, at=(-220, 180))
mas.exit(selector, at=(-220, 340))

if __name__ == "__main__":
    mas.run()
