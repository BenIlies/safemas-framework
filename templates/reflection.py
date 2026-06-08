from safemas import StateGraph

g = StateGraph('reflection', task='Draft and refine a short blog post.', group='Reasoning & reflection', title='Reflection (generator ↺ critic)')

# agents
g.add_node('Specialist A', role='drafter', at=(120, 150))
g.add_node('Critic', role='reviewer', at=(400, 150))
g.add_node('Finaliser', role='finaliser', at=(680, 150))

# edges
g.add_edge('Specialist A', 'Critic', label='draft')
g.add_conditional_edge('Critic', 'Specialist A', label='critique', loop=True, max_iters=3, until='approved')
g.add_edge('Critic', 'Finaliser', label='approved')

# entry / exit
g.set_entry('Specialist A', at=(-120, 160))
g.set_finish('Finaliser', at=(860, 160))
