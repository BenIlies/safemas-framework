from safemas import StateGraph

g = StateGraph('supervisor-hierarchy', task='Plan and execute a multi-step task.', group='Workflows', title='Supervisor hierarchy')

# agents
g.add_node('Supervisor', role='supervisor', at=(360, 60))
g.add_node('Researcher', role='worker', at=(140, 280))
g.add_node('Writer', role='worker', at=(580, 280))

# edges
g.add_edge('Supervisor', 'Researcher', label='assign')
g.add_edge('Supervisor', 'Writer', label='assign')
g.add_conditional_edge('Researcher', 'Supervisor', label='report', loop=True, max_iters=2)
g.add_conditional_edge('Writer', 'Supervisor', label='report', loop=True, max_iters=2)

# entry / exit
g.set_entry('Supervisor', at=(60, 60))
g.set_finish('Supervisor', at=(660, 60))
