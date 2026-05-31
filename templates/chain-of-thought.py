# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('chain-of-thought', task='Solve a multi-step reasoning problem, showing the steps.', group='Reasoning & reflection', title='Chain-of-Thought (Wei 2022)')

# agents
cot_reasoner = mas.agent('CoT Reasoner', role='reasoner', prompt='Reason step by step, then state the final answer.', at=(340, 170))

# entry / exit
mas.entry(cot_reasoner, at=(40, 180))
mas.exit(cot_reasoner, at=(640, 180))

if __name__ == "__main__":
    mas.run()
