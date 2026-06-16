from safemas import StateGraph

# Independent MAS — Kim et al., "Towards a Science of Scaling Agent Systems"
# (Google DeepMind, 2025), §3.2 / Table 2.
#   A = {a_1..a_n}, C = {(a_i, a_agg)} (agent→aggregator only, NO peer comms),
#   Ω = synthesis_only. LLM calls O(nk)+O(1), sequential depth k, comm overhead 1.
#   n parallel agents explore independently; the aggregator merely concatenates
#   their outputs with NO cross-validation or majority voting — so any delta over
#   SAS comes purely from parallel exploration, not error correction. Maximal
#   parallelization, minimal coordination (ensemble reasoning).
g = StateGraph('independent',
               task='Answer by running independent agents in parallel and synthesising their outputs.',
               group='Scaling Agent Systems (DeepMind)',
               title='MAS · Independent (parallel + synthesis)')

# agents
g.add_node('Dispatcher', role='dispatcher',
           prompt='Relay the task verbatim to every parallel agent.', at=(80, 220))
g.add_node('Agent 1', role='solver', at=(360, 40))
g.add_node('Agent 2', role='solver', at=(360, 220))
g.add_node('Agent 3', role='solver', at=(360, 400))
g.add_node('Aggregator', role='aggregator', join='all',
           prompt='Concatenate the agents\' answers into one response. Do NOT '
                  'cross-validate, compare, or vote — synthesis only.',
           at=(660, 220))

# edges — fan out, then aggregate (no peer-to-peer links)
g.add_edge('Dispatcher', 'Agent 1', label='task')
g.add_edge('Dispatcher', 'Agent 2', label='task')
g.add_edge('Dispatcher', 'Agent 3', label='task')
g.add_edge('Agent 1', 'Aggregator', label='answer')
g.add_edge('Agent 2', 'Aggregator', label='answer')
g.add_edge('Agent 3', 'Aggregator', label='answer')

# entry / exit
g.set_entry('Dispatcher', at=(-140, 220))
g.set_finish('Aggregator', at=(880, 220))
