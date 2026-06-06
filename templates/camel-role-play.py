from safemas import StateGraph

g = StateGraph('camel-role-play', task='Cooperatively solve a task through instructor / assistant role-play.', group='Debate & collaboration', title='CAMEL role-play (Li 2023)')

# agents
g.add_node('Task Specifier', role='specifier', prompt='Rewrite the vague idea into one concrete, specific task.', at=(140, 180))
g.add_node('AI User', role='instructor', prompt='Give one instruction at a time; never solve the task yourself.', at=(450, 60))
g.add_node('AI Assistant', role='executor', prompt='Respond to each instruction with a concrete solution.', at=(450, 320))

# edges
g.add_edge('Task Specifier', 'AI User', label='specified task')
g.add_edge('AI User', 'AI Assistant', label='instruction')
g.add_conditional_edge('AI Assistant', 'AI User', label='solution', loop=True, max_iters=3, until='task complete')

# entry / exit
g.set_entry('Task Specifier', at=(-180, 180))
g.set_finish('AI Assistant', at=(780, 300))
