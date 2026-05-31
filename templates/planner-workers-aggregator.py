# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('planner-workers-aggregator', task='Research a topic and produce a concise summary.', group='Workflows', title='Planner / workers / aggregator')

# agents
planner = mas.agent('Planner', role='planner', at=(100, 170))
worker_a = mas.agent('Worker A', role='worker', at=(380, 50))
worker_b = mas.agent('Worker B', role='worker', at=(380, 300))
aggregator = mas.agent('Aggregator', role='finaliser', join='all', at=(660, 170))

# resources
web_tool = mas.tool('Web Tool', spec='def fetch(url: str) -> str', at=(380, -130))

# wiring
planner.to(worker_a, label='subtask A')
planner.to(worker_b, label='subtask B')
worker_a.to(aggregator, label='result A')
worker_b.to(aggregator, label='result B')
worker_a.uses(web_tool)

# entry / exit
mas.entry(planner, at=(-120, 180))
mas.exit(aggregator, at=(900, 180))

if __name__ == "__main__":
    mas.run()
