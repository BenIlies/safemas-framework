# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('new-mas', task='Solve the assigned task.', group='Basics', title='Starter (entrance → exit)')

# agents
agent = mas.agent('Agent', role='assistant', at=(300, 150))

# entry / exit
mas.entry(agent, at=(60, 160))
mas.exit(agent, at=(560, 160))

if __name__ == "__main__":
    mas.run()
