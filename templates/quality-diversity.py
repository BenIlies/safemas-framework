from safemas import StateGraph

g = StateGraph('quality-diversity', task='Evolve a diverse population of high-quality solutions.', group='Population & layered', title='Quality-Diversity (MAP-Elites)')

# agents
g.add_node('Selector', role='selector', at=(140, 260))
g.add_node('Generator A', role='generator', at=(440, 80))
g.add_node('Generator B', role='generator', at=(440, 260))
g.add_node('Generator C', role='generator', at=(440, 440))
g.add_node('Evaluator', role='evaluator', prompt='Score each candidate’s quality and its behaviour descriptor.', join='all', at=(740, 260))

# edges
g.add_edge('Selector', 'Generator A', label='elite parent')
g.add_edge('Generator A', 'Evaluator', label='candidate')
g.add_edge('Selector', 'Generator B', label='elite parent')
g.add_edge('Generator B', 'Evaluator', label='candidate')
g.add_edge('Selector', 'Generator C', label='elite parent')
g.add_edge('Generator C', 'Evaluator', label='candidate')
g.add_conditional_edge('Evaluator', 'Selector', label='scored → archive', loop=True, max_iters=3)

# entry / exit
g.set_entry('Selector', at=(-220, 180))
g.set_finish('Selector', at=(-220, 340))
