# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('blackboard', task='Solve a problem by coordinating specialists through a shared blackboard.', group='Debate & collaboration', title='Blackboard (Hayes-Roth 1985)')

# agents
control = mas.agent('Control', role='scheduler', prompt='Inspect the blackboard and pick which specialist should act next.', at=(170, 170))
specialist_1 = mas.agent('Specialist 1', role='specialist', at=(500, 30))
specialist_2 = mas.agent('Specialist 2', role='specialist', at=(500, 190))
specialist_3 = mas.agent('Specialist 3', role='specialist', at=(500, 350))

# resources
blackboard = mas.memory('Blackboard', backend='in-memory', at=(300, 480))

# wiring
control.to(specialist_1, label='activate')
specialist_1.to(control, label='updated', loop=True, max_iters=2)
control.to(specialist_2, label='activate')
specialist_2.to(control, label='updated', loop=True, max_iters=2)
control.to(specialist_3, label='activate')
specialist_3.to(control, label='updated', loop=True, max_iters=2)
control.uses(blackboard)
specialist_1.uses(blackboard)
specialist_2.uses(blackboard)
specialist_3.uses(blackboard)

# entry / exit
mas.entry(control, at=(-200, 90))
mas.exit(control, at=(-200, 250))

if __name__ == "__main__":
    mas.run()
