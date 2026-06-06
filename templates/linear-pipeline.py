from safemas import StateGraph

g = StateGraph('linear-pipeline', task='Write a function that reads a config file and returns its contents.', group='Workflows', title='Linear pipeline')

# agents
g.add_node('Planner', role='planner', at=(100, 150))
g.add_node('Coder', role='worker', at=(360, 150))
g.add_node('Reviewer', role='finaliser', at=(620, 150))

# edges
g.add_edge('Planner', 'Coder', label='plan')
g.add_edge('Coder', 'Reviewer', label='code')

# entry / exit
g.set_entry('Planner', at=(-120, 160))
g.set_finish('Reviewer', at=(860, 160))
