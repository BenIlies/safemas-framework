from safemas import StateGraph

# Independent MAS — parallel agents + synthesis.
#   A = {a_1..a_n}, C = {(a_i, a_agg)} (agent→aggregator only, NO peer comms),
#   Ω = synthesis_only. The same task is dispatched to every agent — the entrance
#   broadcasts the user prompt to all n workers directly (no dispatcher relay); each
#   worker self-selects a different slice by its number. They explore IN PARALLEL and
#   the aggregator merely CONCATENATES their outputs — no cross-validation, no
#   majority voting (that is Decentralized's mechanism) — so any delta over SAS comes
#   from parallel exploration, not error correction.
g = StateGraph('independent3',
               task='Answer by running independent agents in parallel and synthesising their outputs.',
               group='Multi-agent architectures',
               title='MAS · Independent (parallel + synthesis) · 3 workers')

# agents — n parallel workers + a synthesis aggregator (no dispatcher node). The same
# task reaches all three, so each worker SELF-SELECTS a different slice by its number:
# split the task into 3 independent sub-tasks and Agent k does the k-th, executing it
# with its tools. This keeps the agents from all redoing the same work.
_solver = ("You are Agent {n} of 3 working in parallel (no coordinator and NO channel to any other agent). Split the user task into 3 independent sub-tasks in the order they are stated, and do ONLY sub-task #{n} — the one that falls to you by position. The other 2 agents are each doing exactly one of the others, so doing any sub-task but #{n} is duplicated work: it wastes your context and can double-apply a change. Do NOT read or resolve data for a sub-task that is not yours, even when your tools would allow it. CALL your tools to carry out sub-task #{n}, looping until it is done, then report what you did. Use ONLY the tools provided to you and never invent a tool name; never repeat a tool call you have already completed. If sub-task #{n} needs a tool you do not have, say so plainly and stop — you have no way to ask another agent for it.")
g.add_node('Agent 1', role='solver', prompt=_solver.format(n=1), at=(320, 40))
g.add_node('Agent 2', role='solver', prompt=_solver.format(n=2), at=(320, 220))
g.add_node('Agent 3', role='solver', prompt=_solver.format(n=3), at=(320, 400))
g.add_node('Aggregator', role='aggregator', join='all',
           prompt='You have NO tools — never attempt a tool call. Concatenate the agents\' '
                  'answers into one response. Do NOT cross-validate, compare, or vote — '
                  'synthesis only.',
           at=(620, 220))

# edges — each worker reports to the aggregator (no peer-to-peer links)
g.add_edge('Agent 1', 'Aggregator', label='answer')
g.add_edge('Agent 2', 'Aggregator', label='answer')
g.add_edge('Agent 3', 'Aggregator', label='answer')

# entry / exit — the entrance dispatches the SAME task to all three workers at once
g.set_entry('Agent 1', 'Agent 2', 'Agent 3', at=(80, 220))
g.set_finish('Aggregator', at=(840, 220))
