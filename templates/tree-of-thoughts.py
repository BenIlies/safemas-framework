from safemas import StateGraph

g = StateGraph('tree-of-thoughts', task='Solve a problem by searching over a tree of reasoning steps.', group='Reasoning & reflection', title='Tree of Thoughts (Yao 2023)')

# agents
g.add_node('Thought Generator', role='proposer', prompt='Propose k candidate next reasoning steps from the current state.', at=(180, 170))
g.add_node('State Evaluator', role='evaluator', prompt='Score candidate states (sure / likely / impossible) to guide the search.', at=(500, 170))

# edges
g.add_edge('Thought Generator', 'State Evaluator', label='k candidate thoughts')
g.add_conditional_edge('State Evaluator', 'Thought Generator', label='expand / prune (BFS/DFS)', loop=True, max_iters=3, until='solved')

# entry / exit
g.set_entry('Thought Generator', at=(-140, 180))
g.set_finish('State Evaluator', at=(820, 180))
