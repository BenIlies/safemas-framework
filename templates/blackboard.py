from safemas import StateGraph

g = StateGraph('blackboard', task='Solve a problem by coordinating specialists through a shared blackboard.', group='Debate & collaboration', title='Blackboard (Hayes-Roth 1985)')

# agents
g.add_node('Control', role='scheduler', prompt='Inspect the blackboard and pick which specialist should act next.', at=(170, 170))
g.add_node('Specialist 1', role='specialist', at=(500, 30))
g.add_node('Specialist 2', role='specialist', at=(500, 190))
g.add_node('Specialist 3', role='specialist', at=(500, 350))

# edges
g.add_edge('Control', 'Specialist 1', label='activate')
g.add_conditional_edge('Specialist 1', 'Control', label='updated', loop=True, max_iters=2)
g.add_edge('Control', 'Specialist 2', label='activate')
g.add_conditional_edge('Specialist 2', 'Control', label='updated', loop=True, max_iters=2)
g.add_edge('Control', 'Specialist 3', label='activate')
g.add_conditional_edge('Specialist 3', 'Control', label='updated', loop=True, max_iters=2)

# entry / exit
g.set_entry('Control', at=(-200, 90))
g.set_finish('Control', at=(-200, 250))
