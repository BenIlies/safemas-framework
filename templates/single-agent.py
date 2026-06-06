from safemas import StateGraph

g = StateGraph('single-agent', task='Answer the user’s question.', group='Basics', title='Single agent + tool')

# agents
g.add_node('Assistant', role='assistant', at=(330, 150))

# entry / exit
g.set_entry('Assistant', at=(60, 160))
g.set_finish('Assistant', at=(600, 160))
