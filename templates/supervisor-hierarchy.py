from safemas import StateGraph

g = StateGraph('supervisor-hierarchy', task='Plan and execute a multi-step task across specialists.', group='Workflows', title='Supervisor hierarchy')

# agents
g.add_node('Supervisor', role='supervisor', at=(360, 60))
g.add_node('Specialist A', role='specialist', group='A', at=(120, 280))
g.add_node('Specialist B', role='specialist', group='B', at=(360, 280))
g.add_node('Specialist C', role='specialist', group='C', at=(600, 280))

# edges
g.add_edge('Supervisor', 'Specialist A', label='assign')
g.add_edge('Supervisor', 'Specialist B', label='assign')
g.add_edge('Supervisor', 'Specialist C', label='assign')
g.add_conditional_edge('Specialist A', 'Supervisor', label='report', loop=True, max_iters=2)
g.add_conditional_edge('Specialist B', 'Supervisor', label='report', loop=True, max_iters=2)
g.add_conditional_edge('Specialist C', 'Supervisor', label='report', loop=True, max_iters=2)

# entry / exit
g.set_entry('Supervisor', at=(60, 60))
g.set_finish('Supervisor', at=(660, 60))
