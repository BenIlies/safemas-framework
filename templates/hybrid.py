from safemas import StateGraph

# Hybrid MAS — Kim et al., "Towards a Science of Scaling Agent Systems"
# (Google DeepMind, 2025), §3.2 / Table 2.
#   A = {a_orch, a_1..a_n}, C = C_centralized ∪ C_peer (star + limited peer edges),
#   Ω = hierarchical + lateral. LLM calls O(rnk)+O(r)+O(p), comm overhead r·n+p·m.
#   Inherits orchestrator control (decompose / verify / aggregate) while allowing
#   bounded lateral exchange between sub-agents — hierarchy plus peer flexibility.
g = StateGraph('hybrid',
               task='Coordinate sub-agents under an orchestrator while allowing limited peer-to-peer exchange.',
               group='Scaling Agent Systems (DeepMind)',
               title='MAS · Hybrid (orchestrator + peer)')

# agents
g.add_node('Orchestrator', role='orchestrator', join='all',
           prompt='Decompose the task, assign sub-tasks, then verify and '
                  'synthesise reports. Let sub-agents share findings laterally.',
           at=(360, 60))
g.add_node('Sub-Agent 1', role='worker', at=(120, 300))
g.add_node('Sub-Agent 2', role='worker', at=(360, 300))
g.add_node('Sub-Agent 3', role='worker', at=(600, 300))

# edges — star control (assign / report over r rounds) ...
g.add_edge('Orchestrator', 'Sub-Agent 1', label='assign')
g.add_edge('Orchestrator', 'Sub-Agent 2', label='assign')
g.add_edge('Orchestrator', 'Sub-Agent 3', label='assign')
g.add_conditional_edge('Sub-Agent 1', 'Orchestrator', label='report', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 2', 'Orchestrator', label='report', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 3', 'Orchestrator', label='report', loop=True, max_iters=1)
# ... plus LIMITED lateral peer edges (not all-to-all), bounded (loop, max_iters=1)
# so a peer shares its findings ONCE and the chain doesn't cascade into endless
# re-activation.
g.add_conditional_edge('Sub-Agent 1', 'Sub-Agent 2', label='peer', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 2', 'Sub-Agent 3', label='peer', loop=True, max_iters=1)

# entry / exit
g.set_entry('Orchestrator', at=(60, 60))
g.set_finish('Orchestrator', at=(660, 60))
