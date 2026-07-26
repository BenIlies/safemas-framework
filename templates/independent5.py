from safemas import StateGraph

# Independent MAS (5 agents) — auto-generated variant for the parallelism ablation
# (see base independent.py). Parallel workers + concatenating aggregator (no peer comms).
g = StateGraph('independent5',
               task='Answer by running independent agents in parallel and synthesising their outputs.',
               group='Multi-agent architectures',
               title='MAS · Independent (parallel + synthesis) · 5 agents')

_solver = ("You are Agent {n} of 5 working in parallel (no coordinator and NO channel to any other agent). Split the user task into 5 independent sub-tasks in the order they are stated, and do ONLY sub-task #{n} — the one that falls to you by position. The other 4 agents are each doing exactly one of the others, so doing any sub-task but #{n} is duplicated work: it wastes your context and can double-apply a change. Do NOT read or resolve data for a sub-task that is not yours, even when your tools would allow it. CALL your tools to carry out sub-task #{n}, looping until it is done, then report what you did. Use ONLY the tools provided to you and never invent a tool name; never repeat a tool call you have already completed. If sub-task #{n} needs a tool you do not have, say so plainly and stop — you have no way to ask another agent for it.")
g.add_node('Agent 1', role='solver', prompt=_solver.format(n=1), at=(320, 40))
g.add_node('Agent 2', role='solver', prompt=_solver.format(n=2), at=(320, 180))
g.add_node('Agent 3', role='solver', prompt=_solver.format(n=3), at=(320, 320))
g.add_node('Agent 4', role='solver', prompt=_solver.format(n=4), at=(320, 460))
g.add_node('Agent 5', role='solver', prompt=_solver.format(n=5), at=(320, 600))
g.add_node('Aggregator', role='aggregator', join='all',
           prompt='You have NO tools — never attempt a tool call. Concatenate the agents\' '
                  'answers into one response. Do NOT cross-validate, compare, or vote — synthesis only.',
           at=(620, 220))

g.add_edge('Agent 1', 'Aggregator', label='answer')
g.add_edge('Agent 2', 'Aggregator', label='answer')
g.add_edge('Agent 3', 'Aggregator', label='answer')
g.add_edge('Agent 4', 'Aggregator', label='answer')
g.add_edge('Agent 5', 'Aggregator', label='answer')

g.set_entry('Agent 1', 'Agent 2', 'Agent 3', 'Agent 4', 'Agent 5', at=(80, 220))
g.set_finish('Aggregator', at=(840, 220))
