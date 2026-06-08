from safemas import StateGraph

g = StateGraph('dylan', task='Collaborate over rounds while pruning low-contribution agents.', group='Population & layered', title='DyLAN (Liu 2024)')

# agents
g.add_node('Specialist A', group='A', role='solver', at=(180, 30))
g.add_node('Specialist B', group='B', role='solver', at=(180, 180))
g.add_node('Specialist C', group='C', role='solver', at=(180, 330))
g.add_node('LLM Ranker', role='ranker', prompt='Rate this round’s responses and keep only the top-ranked agents.', join='all', at=(470, 470))

# edges
g.add_edge('Specialist A', 'Specialist B', label='peer context')
g.add_edge('Specialist B', 'Specialist C', label='peer context')
g.add_edge('Specialist A', 'LLM Ranker', label='rate')
g.add_edge('Specialist B', 'LLM Ranker', label='rate')
g.add_edge('Specialist C', 'LLM Ranker', label='rate')
g.add_conditional_edge('LLM Ranker', 'Specialist A', label='keep / prune', loop=True, max_iters=1)

# entry / exit
g.set_entry('Specialist A', at=(-220, 180))
g.set_finish('LLM Ranker', at=(840, 180))
