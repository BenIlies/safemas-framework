from safemas import StateGraph

g = StateGraph('multi-agent-debate', task='Reach a correct answer through several rounds of debate.', group='Debate & collaboration', title='Multi-Agent Debate (Du/Liang 2023)')

# agents
g.add_node('Debater 1', role='debater', at=(300, 30))
g.add_node('Debater 2', role='debater', at=(150, 380))
g.add_node('Debater 3', role='debater', at=(450, 380))

# edges
g.add_edge('Debater 1', 'Debater 2', label='argue')
g.add_edge('Debater 2', 'Debater 3', label='argue')
g.add_conditional_edge('Debater 3', 'Debater 1', label='next round', loop=True, max_iters=2)

# entry / exit
g.set_entry('Debater 1', at=(-200, 210))
g.set_finish('Debater 3', at=(780, 210))
