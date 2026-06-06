from safemas import StateGraph

g = StateGraph('reconcile', task='Answer via a round-table of diverse models and a weighted consensus vote.', group='Debate & collaboration', title='ReConcile (Chen 2024)')

# agents
g.add_node('Agent A (e.g. GPT)', role='round-table', at=(240, 40))
g.add_node('Agent B (e.g. Claude)', role='round-table', at=(130, 380))
g.add_node('Agent C (e.g. Gemini)', role='round-table', at=(430, 380))
g.add_node('Weighted Consensus', role='aggregator', prompt='Combine the agents’ answers weighted by their confidence scores.', join='all', at=(700, 210))

# edges
g.add_edge('Agent A (e.g. GPT)', 'Agent B (e.g. Claude)', label='answer · explanation · confidence')
g.add_edge('Agent B (e.g. Claude)', 'Agent C (e.g. Gemini)', label='answer · explanation · confidence')
g.add_conditional_edge('Agent C (e.g. Gemini)', 'Agent A (e.g. GPT)', label='next round', loop=True, max_iters=2)
g.add_edge('Agent A (e.g. GPT)', 'Weighted Consensus', label='final vote')
g.add_edge('Agent B (e.g. Claude)', 'Weighted Consensus', label='final vote')
g.add_edge('Agent C (e.g. Gemini)', 'Weighted Consensus', label='final vote')

# entry / exit
g.set_entry('Agent A (e.g. GPT)', at=(-200, 210))
g.set_finish('Weighted Consensus', at=(960, 210))
