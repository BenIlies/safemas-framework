from safemas import StateGraph

g = StateGraph('mixture-of-agents', task='Answer by layering and aggregating multiple proposer models.', group='Population & layered', title='Mixture-of-Agents (Wang 2024)')

# agents
g.add_node('Dispatcher', role='dispatcher', prompt='Relay the task to each layer-1 proposer.', at=(-120, 260))
g.add_node('Layer 1 · Proposer A', role='proposer', at=(120, 80))
g.add_node('Layer 1 · Proposer B', role='proposer', at=(120, 260))
g.add_node('Layer 1 · Proposer C', role='proposer', at=(120, 440))
g.add_node('Layer 2 · Proposer A', role='proposer', join='all', at=(440, 80))
g.add_node('Layer 2 · Proposer B', role='proposer', join='all', at=(440, 260))
g.add_node('Layer 2 · Proposer C', role='proposer', join='all', at=(440, 440))
g.add_node('Aggregator', role='aggregator', prompt='Synthesise the last layer’s proposals into one final answer.', join='all', at=(740, 260))

# edges
g.add_edge('Dispatcher', 'Layer 1 · Proposer A', label='task')
g.add_edge('Dispatcher', 'Layer 1 · Proposer B', label='task')
g.add_edge('Dispatcher', 'Layer 1 · Proposer C', label='task')
g.add_edge('Layer 1 · Proposer A', 'Layer 2 · Proposer A', label='proposal')
g.add_edge('Layer 1 · Proposer A', 'Layer 2 · Proposer B', label='proposal')
g.add_edge('Layer 1 · Proposer A', 'Layer 2 · Proposer C', label='proposal')
g.add_edge('Layer 1 · Proposer B', 'Layer 2 · Proposer A', label='proposal')
g.add_edge('Layer 1 · Proposer B', 'Layer 2 · Proposer B', label='proposal')
g.add_edge('Layer 1 · Proposer B', 'Layer 2 · Proposer C', label='proposal')
g.add_edge('Layer 1 · Proposer C', 'Layer 2 · Proposer A', label='proposal')
g.add_edge('Layer 1 · Proposer C', 'Layer 2 · Proposer B', label='proposal')
g.add_edge('Layer 1 · Proposer C', 'Layer 2 · Proposer C', label='proposal')
g.add_edge('Layer 2 · Proposer A', 'Aggregator', label='proposal')
g.add_edge('Layer 2 · Proposer B', 'Aggregator', label='proposal')
g.add_edge('Layer 2 · Proposer C', 'Aggregator', label='proposal')

# entry / exit
g.set_entry('Dispatcher', at=(-340, 260))
g.set_finish('Aggregator', at=(960, 260))
