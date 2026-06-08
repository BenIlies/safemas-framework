from safemas import StateGraph

g = StateGraph('reconcile', task='Answer via a round-table of diverse models and a weighted consensus vote.', group='Debate & collaboration', title='ReConcile (Chen 2024)')

# agents
g.add_node('Specialist A', group='A', role='round-table', at=(240, 40))
g.add_node('Specialist B', group='B', role='round-table', at=(130, 380))
g.add_node('Specialist C', group='C', role='round-table', at=(430, 380))
g.add_node('Weighted Consensus', role='aggregator', prompt='Combine the agents’ answers weighted by their confidence scores.', join='all', at=(700, 210))

# edges
g.add_edge('Specialist A', 'Specialist B', label='answer · explanation · confidence')
g.add_edge('Specialist B', 'Specialist C', label='answer · explanation · confidence')
g.add_conditional_edge('Specialist C', 'Specialist A', label='next round', loop=True, max_iters=2)
g.add_edge('Specialist A', 'Weighted Consensus', label='final vote')
g.add_edge('Specialist B', 'Weighted Consensus', label='final vote')
g.add_edge('Specialist C', 'Weighted Consensus', label='final vote')

# entry / exit
g.set_entry('Specialist A', at=(-200, 210))
g.set_finish('Weighted Consensus', at=(960, 210))
