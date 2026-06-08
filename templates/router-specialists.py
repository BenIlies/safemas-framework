from safemas import StateGraph

g = StateGraph('router-specialists', task='Route a request to the right specialist and collect the answer.', group='Workflows', title='Router → specialists')

# agents
g.add_node('Router', role='router', at=(100, 200))
g.add_node('Specialist A', role='specialist', group='A', at=(380, 40))
g.add_node('Specialist B', role='specialist', group='B', at=(380, 200))
g.add_node('Specialist C', role='specialist', group='C', at=(380, 360))
g.add_node('Collector', role='finaliser', at=(660, 200))

# edges
g.add_conditional_edge('Router', 'Specialist A', label='route A', when='a')
g.add_conditional_edge('Router', 'Specialist B', label='route B', when='b')
g.add_conditional_edge('Router', 'Specialist C', label='route C', when='c')
g.add_edge('Specialist A', 'Collector', label='answer')
g.add_edge('Specialist B', 'Collector', label='answer')
g.add_edge('Specialist C', 'Collector', label='answer')

# entry / exit
g.set_entry('Router', at=(-120, 210))
g.set_finish('Collector', at=(900, 210))
