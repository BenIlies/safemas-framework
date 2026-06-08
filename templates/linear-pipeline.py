from safemas import StateGraph

g = StateGraph('linear-pipeline', task='Write a function that reads a config file and returns its contents.', group='Workflows', title='Linear pipeline')

# agents
g.add_node('Specialist A', group='A', role='planner', at=(100, 150))
g.add_node('Specialist B', group='B', role='worker', at=(360, 150))
g.add_node('Specialist C', group='C', role='finaliser', at=(620, 150))

# edges
g.add_edge('Specialist A', 'Specialist B', label='plan')
g.add_edge('Specialist B', 'Specialist C', label='code')

# entry / exit
g.set_entry('Specialist A', at=(-120, 160))
g.set_finish('Specialist C', at=(860, 160))
