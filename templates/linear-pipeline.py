# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('linear-pipeline', task='Write a function that reads a config file and returns its contents.', group='Workflows', title='Linear pipeline')

# agents
planner = mas.agent('Planner', role='planner', at=(100, 150))
coder = mas.agent('Coder', role='worker', at=(360, 150))
reviewer = mas.agent('Reviewer', role='finaliser', at=(620, 150))

# resources
shared_memory = mas.memory('Shared Memory', backend='vector', at=(360, 330))
search_tool = mas.tool('Search Tool', spec='def search(q: str) -> str', at=(360, -30))

# wiring
planner.to(coder, label='plan')
coder.to(reviewer, label='code')
coder.uses(shared_memory)
coder.uses(search_tool)

# entry / exit
mas.entry(planner, at=(-120, 160))
mas.exit(reviewer, at=(860, 160))

if __name__ == "__main__":
    mas.run()
