from safemas import StateGraph

# Independent MAS — Kim et al., "Towards a Science of Scaling Agent Systems"
# (Google DeepMind, 2025), §3.2 / Table 2 / App. E.2.
#   A = {a_1..a_n}, C = {(a_i, a_agg)} (agent→aggregator only, NO peer comms),
#   Ω = synthesis_only. The SAME task is dispatched to every agent — the entrance
#   broadcasts the user prompt to all n workers directly (there is NO dispatcher
#   relay in the paper). They explore IN PARALLEL and the aggregator merely
#   CONCATENATES their outputs — no cross-validation, no majority voting (that is
#   Decentralized's mechanism) — so any delta over SAS comes purely from parallel
#   exploration, not error correction. "3 agents with synthesis-only coordination."
g = StateGraph('independent',
               task='Answer by running independent agents in parallel and synthesising their outputs.',
               group='Scaling Agent Systems (DeepMind)',
               title='MAS · Independent (parallel + synthesis)')

# agents — n parallel workers + a synthesis aggregator (no dispatcher node)
g.add_node('Agent 1', role='solver', at=(320, 40))
g.add_node('Agent 2', role='solver', at=(320, 220))
g.add_node('Agent 3', role='solver', at=(320, 400))
g.add_node('Aggregator', role='aggregator', join='all',
           prompt='Concatenate the agents\' answers into one response. Do NOT '
                  'cross-validate, compare, or vote — synthesis only.',
           at=(620, 220))

# edges — each worker reports to the aggregator (no peer-to-peer links)
g.add_edge('Agent 1', 'Aggregator', label='answer')
g.add_edge('Agent 2', 'Aggregator', label='answer')
g.add_edge('Agent 3', 'Aggregator', label='answer')

# entry / exit — the entrance dispatches the SAME task to all three workers at once
g.set_entry('Agent 1', 'Agent 2', 'Agent 3', at=(80, 220))
g.set_finish('Aggregator', at=(840, 220))
