# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('multi-agent-debate', task='Reach a correct answer through several rounds of debate.', group='Debate & collaboration', title='Multi-Agent Debate (Du/Liang 2023)')

# agents
debater_1 = mas.agent('Debater 1', role='debater', at=(300, 30))
debater_2 = mas.agent('Debater 2', role='debater', at=(150, 380))
debater_3 = mas.agent('Debater 3', role='debater', at=(450, 380))

# wiring
debater_1.to(debater_2, label='argue')
debater_2.to(debater_3, label='argue')
debater_3.to(debater_1, label='next round', loop=True, max_iters=2)

# entry / exit
mas.entry(debater_1, at=(-200, 210))
mas.exit(debater_3, at=(780, 210))

if __name__ == "__main__":
    mas.run()
