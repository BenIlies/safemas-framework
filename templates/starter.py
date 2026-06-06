from safemas import StateGraph

g = StateGraph('new-mas', task='Solve the assigned task.', group='Basics', title='Starter (entrance → exit)')

# agents
g.add_node('Agent', role='assistant', at=(300, 150))

# entry / exit
g.set_entry('Agent', at=(60, 160))
g.set_finish('Agent', at=(560, 160))
