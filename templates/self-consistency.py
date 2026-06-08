from safemas import StateGraph

g = StateGraph('self-consistency', task='Solve a reasoning problem and vote over several sampled solutions.', group='Reasoning & reflection', title='Self-Consistency (Wang 2023)')

# agents
g.add_node('Dispatcher', role='dispatcher', prompt='Relay the task to each sampler unchanged.', at=(-40, 210))
g.add_node('CoT Sample 1', group='A', role='reasoner', temperature=0.7, at=(220, 40))
g.add_node('CoT Sample 2', group='B', role='reasoner', temperature=0.7, at=(220, 210))
g.add_node('CoT Sample 3', group='C', role='reasoner', temperature=0.7, at=(220, 380))
g.add_node('Majority Vote', role='aggregator', prompt='Return the answer that the most reasoning paths agree on.', join='all', at=(520, 210))

# edges
g.add_edge('Dispatcher', 'CoT Sample 1', label='task')
g.add_edge('Dispatcher', 'CoT Sample 2', label='task')
g.add_edge('Dispatcher', 'CoT Sample 3', label='task')
g.add_edge('CoT Sample 1', 'Majority Vote', label='answer')
g.add_edge('CoT Sample 2', 'Majority Vote', label='answer')
g.add_edge('CoT Sample 3', 'Majority Vote', label='answer')

# entry / exit
g.set_entry('Dispatcher', at=(-260, 210))
g.set_finish('Majority Vote', at=(820, 210))
