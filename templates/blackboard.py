from safemas import StateGraph

g = StateGraph('blackboard', task='Solve a problem by coordinating specialists through a shared blackboard.', group='Debate & collaboration', title='Blackboard (Hayes-Roth 1985)')

# agents
g.add_node('Control', role='scheduler', prompt='Inspect the blackboard and pick which specialist should act next.', at=(170, 170))
g.add_node('Specialist A', group='A', role='specialist', at=(500, 30))
g.add_node('Specialist B', group='B', role='specialist', at=(500, 190))
g.add_node('Specialist C', group='C', role='specialist', at=(500, 350))

# edges
g.add_edge('Control', 'Specialist A', label='activate')
g.add_conditional_edge('Specialist A', 'Control', label='updated', loop=True, max_iters=2)
g.add_edge('Control', 'Specialist B', label='activate')
g.add_conditional_edge('Specialist B', 'Control', label='updated', loop=True, max_iters=2)
g.add_edge('Control', 'Specialist C', label='activate')
g.add_conditional_edge('Specialist C', 'Control', label='updated', loop=True, max_iters=2)

# entry / exit
g.set_entry('Control', at=(-200, 90))
g.set_finish('Control', at=(-200, 250))
