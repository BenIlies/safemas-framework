# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('supervisor-hierarchy', task='Plan and execute a multi-step task.', group='Workflows', title='Supervisor hierarchy')

# agents
supervisor = mas.agent('Supervisor', role='supervisor', at=(360, 60))
researcher = mas.agent('Researcher', role='worker', at=(140, 280))
writer = mas.agent('Writer', role='worker', at=(580, 280))

# resources
scratchpad = mas.memory('Scratchpad', backend='in-memory', at=(360, 470))

# wiring
supervisor.to(researcher, label='assign')
supervisor.to(writer, label='assign')
researcher.to(supervisor, label='report', loop=True, max_iters=2)
writer.to(supervisor, label='report', loop=True, max_iters=2)
supervisor.uses(scratchpad)
researcher.uses(scratchpad)
writer.uses(scratchpad)

# entry / exit
mas.entry(supervisor, at=(60, 60))
mas.exit(supervisor, at=(660, 60))

if __name__ == "__main__":
    mas.run()
