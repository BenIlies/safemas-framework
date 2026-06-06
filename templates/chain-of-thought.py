from safemas import StateGraph

g = StateGraph('chain-of-thought', task='Solve a multi-step reasoning problem, showing the steps.', group='Reasoning & reflection', title='Chain-of-Thought (Wei 2022)')

# agents
g.add_node('CoT Reasoner', role='reasoner', prompt='Reason step by step, then state the final answer.', at=(340, 170))

# entry / exit
g.set_entry('CoT Reasoner', at=(40, 180))
g.set_finish('CoT Reasoner', at=(640, 180))
