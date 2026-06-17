from safemas import StateGraph

# Centralized MAS — Kim et al., "Towards a Science of Scaling Agent Systems"
# (Google DeepMind, 2025), §3.2 / Table 2.
#   A = {a_orch, a_1..a_n}, C = {(a_orch, a_i)} (orchestrator→agents only),
#   Ω = hierarchical. LLM calls O(rnk)+O(r), sequential depth r, comm overhead r·n.
#   A single orchestrator decomposes the task, dispatches to n sub-agents over r
#   rounds, and verifies/aggregates their reports — the "validation bottleneck"
#   that intercepts errors before aggregation (paper: contains trace-level error
#   amplification to 4.4× vs. 17.2× for Independent). Stabilises reasoning, but
#   the orchestrator is the bottleneck.
g = StateGraph('centralized',
               task='Coordinate sub-agents through a central orchestrator that decomposes, verifies and aggregates.',
               group='Scaling Agent Systems (DeepMind)',
               title='MAS · Centralized (hierarchical orchestrator)')

# agents
g.add_node('Orchestrator', role='orchestrator', join='all',
           prompt='Decompose the task, assign sub-tasks, then verify and '
                  'synthesise the sub-agents\' reports. Override any unsound result.',
           at=(360, 60))
g.add_node('Sub-Agent 1', role='worker', at=(120, 300))
g.add_node('Sub-Agent 2', role='worker', at=(360, 300))
g.add_node('Sub-Agent 3', role='worker', at=(600, 300))

# edges — star out (assign), star back (report) over r rounds
g.add_edge('Orchestrator', 'Sub-Agent 1', label='assign')
g.add_edge('Orchestrator', 'Sub-Agent 2', label='assign')
g.add_edge('Orchestrator', 'Sub-Agent 3', label='assign')
g.add_conditional_edge('Sub-Agent 1', 'Orchestrator', label='report', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 2', 'Orchestrator', label='report', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 3', 'Orchestrator', label='report', loop=True, max_iters=1)

# entry / exit — the orchestrator is both the entry and the verified sink
g.set_entry('Orchestrator', at=(60, 60))
g.set_finish('Orchestrator', at=(660, 60))
