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
#
#   r ORCHESTRATION ROUNDS: both the assign (orch→sub) and report (sub→orch) edges
#   are bounded LOOP edges, so the cycle orch → subs → orch runs r times: each round
#   the orchestrator reviews the sub-agents' reports and re-tasks them, and only when
#   the round budget is spent does its last activation emit the final synthesis (it
#   is the exit). r is the loop bound — left implicit so it tracks the engine's
#   SAFEMAS_MAX_ROUNDS budget (default 3; set it to 5 to match the paper's App. E.2
#   max of r=5 rounds). This is the iterative dispatch→verify→re-dispatch loop that
#   distinguishes Centralized from a one-shot Independent ensemble.
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

# edges — star out (assign), star back (report), cycled over r rounds. Both legs
# are bounded loop edges so the orchestrator re-tasks its sub-agents each round
# (max_iters left implicit → the engine's SAFEMAS_MAX_ROUNDS, the paper's r).
g.add_conditional_edge('Orchestrator', 'Sub-Agent 1', label='assign', loop=True)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 2', label='assign', loop=True)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 3', label='assign', loop=True)
g.add_conditional_edge('Sub-Agent 1', 'Orchestrator', label='report', loop=True)
g.add_conditional_edge('Sub-Agent 2', 'Orchestrator', label='report', loop=True)
g.add_conditional_edge('Sub-Agent 3', 'Orchestrator', label='report', loop=True)

# entry / exit — the orchestrator is both the entry and the verified sink
g.set_entry('Orchestrator', at=(60, 60))
g.set_finish('Orchestrator', at=(660, 60))
