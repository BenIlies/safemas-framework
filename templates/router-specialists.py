from safemas import StateGraph

g = StateGraph('router-specialists', task='Handle a mixed request that may need code or math.', group='Workflows', title='Router → specialists')

# agents
g.add_node('Router', role='router', at=(100, 190))
g.add_node('Code Specialist', role='coder', at=(380, 70))
g.add_node('Math Specialist', role='mathematician', at=(380, 310))
g.add_node('Collector', role='finaliser', at=(660, 190))

# edges
g.add_conditional_edge('Router', 'Code Specialist', label='route: code', when='code')
g.add_conditional_edge('Router', 'Math Specialist', label='route: math', when='math')
g.add_edge('Code Specialist', 'Collector', label='answer')
g.add_edge('Math Specialist', 'Collector', label='answer')

# entry / exit
g.set_entry('Router', at=(-120, 200))
g.set_finish('Collector', at=(900, 200))
