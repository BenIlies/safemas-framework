from safemas import StateGraph

# Hybrid MAS — Kim et al., "Towards a Science of Scaling Agent Systems"
# (Google DeepMind, 2025), §3.2 / Table 2.
#   A = {a_orch, a_1..a_n}, C = C_centralized ∪ C_peer (star + limited peer edges),
#   Ω = hierarchical + lateral. LLM calls O(rnk)+O(r)+O(p), comm overhead r·n+p·m.
#   Inherits orchestrator control (decompose / verify / aggregate) while allowing
#   bounded lateral exchange between sub-agents — hierarchy plus peer flexibility.
#
#   Like Centralized, the star (assign/report) is cycled over r ROUNDS via bounded
#   loop edges (max_iters implicit → SAFEMAS_MAX_ROUNDS). On TOP of the star sits a
#   CURATED, denser-than-a-chain peer mesh (Sub-Agent 2 is the lateral hub:
#   1↔2 and 2↔3 — selective, NOT the all-to-all of Decentralized). Because the
#   orchestration is multi-round, a peer message shared in one round is folded into
#   that sub-agent's report in the NEXT round, so lateral findings genuinely reach
#   the orchestrator's synthesis (in the old one-round build the peer pass was inert).
g = StateGraph('hybrid',
               task='Coordinate sub-agents under an orchestrator while allowing limited peer-to-peer exchange.',
               group='Scaling Agent Systems (DeepMind)',
               title='MAS · Hybrid (orchestrator + peer)')

# agents
g.add_node('Orchestrator', role='orchestrator', join='all',
           prompt='Decompose the task, assign sub-tasks, then verify and '
                  'synthesise reports. Let sub-agents share findings laterally.',
           at=(360, 60))
g.add_node('Sub-Agent 1', role='worker',
           prompt='Do your sub-task; fold in any peer findings you receive, then report.', at=(120, 300))
g.add_node('Sub-Agent 2', role='worker',
           prompt='Do your sub-task; fold in any peer findings you receive, then report.', at=(360, 300))
g.add_node('Sub-Agent 3', role='worker',
           prompt='Do your sub-task; fold in any peer findings you receive, then report.', at=(600, 300))

# edges — star control (assign / report) CYCLED over r rounds (bounded loops, like
# Centralized) so the orchestrator re-tasks and re-verifies each round ...
g.add_conditional_edge('Orchestrator', 'Sub-Agent 1', label='assign', loop=True)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 2', label='assign', loop=True)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 3', label='assign', loop=True)
g.add_conditional_edge('Sub-Agent 1', 'Orchestrator', label='report', loop=True)
g.add_conditional_edge('Sub-Agent 2', 'Orchestrator', label='report', loop=True)
g.add_conditional_edge('Sub-Agent 3', 'Orchestrator', label='report', loop=True)
# ... plus a CURATED lateral peer mesh (hub on Sub-Agent 2; bidirectional 1↔2, 2↔3
# — denser than a one-way chain but NOT the all-to-all of Decentralized). Bounded
# loops cap the lateral traffic at p shares per edge.
g.add_conditional_edge('Sub-Agent 1', 'Sub-Agent 2', label='peer', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 2', 'Sub-Agent 1', label='peer', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 2', 'Sub-Agent 3', label='peer', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 3', 'Sub-Agent 2', label='peer', loop=True, max_iters=1)

# entry / exit
g.set_entry('Orchestrator', at=(60, 60))
g.set_finish('Orchestrator', at=(660, 60))
