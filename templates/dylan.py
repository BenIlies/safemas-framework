from safemas import StateGraph

g = StateGraph('dylan', task='Collaborate over rounds while pruning low-contribution agents.', group='Population & layered', title='DyLAN (Liu 2024)')

# agents
g.add_node('Solver 1', role='solver', at=(180, 30))
g.add_node('Solver 2', role='solver', at=(180, 180))
g.add_node('Solver 3', role='solver', at=(180, 330))
g.add_node('LLM Ranker', role='ranker', prompt='Rate this round’s responses and keep only the top-ranked agents.', join='all', at=(470, 470))

# edges
g.add_edge('Solver 1', 'Solver 2', label='peer context')
g.add_edge('Solver 2', 'Solver 3', label='peer context')
g.add_edge('Solver 1', 'LLM Ranker', label='rate')
g.add_edge('Solver 2', 'LLM Ranker', label='rate')
g.add_edge('Solver 3', 'LLM Ranker', label='rate')
g.add_conditional_edge('LLM Ranker', 'Solver 1', label='keep / prune', loop=True, max_iters=1)

# entry / exit
g.set_entry('Solver 1', at=(-220, 180))
g.set_finish('LLM Ranker', at=(840, 180))
