from safemas import StateGraph

g = StateGraph('planner-workers-aggregator', task='Decompose a task across specialists and aggregate their results.', group='Workflows', title='Planner / workers / aggregator')

# agents
g.add_node('Planner', role='planner', at=(100, 200))
g.add_node('Specialist A', role='specialist', group='A', at=(380, 40))
g.add_node('Specialist B', role='specialist', group='B', at=(380, 200))
g.add_node('Specialist C', role='specialist', group='C', at=(380, 360))
g.add_node('Aggregator', role='finaliser', join='all', at=(660, 200))

# edges
g.add_edge('Planner', 'Specialist A', label='subtask A')
g.add_edge('Planner', 'Specialist B', label='subtask B')
g.add_edge('Planner', 'Specialist C', label='subtask C')
g.add_edge('Specialist A', 'Aggregator', label='result A')
g.add_edge('Specialist B', 'Aggregator', label='result B')
g.add_edge('Specialist C', 'Aggregator', label='result C')

# entry / exit
g.set_entry('Planner', at=(-120, 210))
g.set_finish('Aggregator', at=(900, 210))
