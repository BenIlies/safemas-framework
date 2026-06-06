from safemas import StateGraph

g = StateGraph('planner-workers-aggregator', task='Research a topic and produce a concise summary.', group='Workflows', title='Planner / workers / aggregator')

# agents
g.add_node('Planner', role='planner', at=(100, 170))
g.add_node('Worker A', role='worker', at=(380, 50))
g.add_node('Worker B', role='worker', at=(380, 300))
g.add_node('Aggregator', role='finaliser', join='all', at=(660, 170))

# edges
g.add_edge('Planner', 'Worker A', label='subtask A')
g.add_edge('Planner', 'Worker B', label='subtask B')
g.add_edge('Worker A', 'Aggregator', label='result A')
g.add_edge('Worker B', 'Aggregator', label='result B')

# entry / exit
g.set_entry('Planner', at=(-120, 180))
g.set_finish('Aggregator', at=(900, 180))
