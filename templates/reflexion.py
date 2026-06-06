from safemas import StateGraph

g = StateGraph('reflexion', task='Solve a task, learn from failed attempts, and retry until it succeeds.', group='Reasoning & reflection', title='Reflexion (Shinn 2023)')

# agents
g.add_node('Actor', role='policy', at=(140, 190))
g.add_node('Evaluator', role='scorer', at=(460, 60))
g.add_node('Self-Reflection', role='verbal-critic', join='all', at=(460, 330))

# edges
g.add_edge('Actor', 'Evaluator', label='trajectory')
g.add_edge('Actor', 'Self-Reflection', label='trajectory')
g.add_edge('Evaluator', 'Self-Reflection', label='reward')
g.add_conditional_edge('Self-Reflection', 'Actor', label='reflection', loop=True, max_iters=3, until='success')

# entry / exit
g.set_entry('Actor', at=(-220, 110))
g.set_finish('Actor', at=(-220, 270))
