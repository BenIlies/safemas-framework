from safemas import StateGraph

# Centralized MAS (4 sub-agents) — auto-generated variant
# for the parallelism ablation (see the base centralized.py for the full description).

g = StateGraph('centralized4',
               task='Coordinate sub-agents through a central orchestrator that decomposes, verifies and aggregates.',
               group='Multi-agent architectures',
               title='MAS · Centralized (hierarchical orchestrator) · 4 workers')

g.add_node('Orchestrator', role='orchestrator', join='all',
           prompt='You are the orchestrator. Decompose the user task into INDEPENDENT, non-overlapping sub-tasks that can run in parallel and assign each to a DISTINCT sub-agent BY NAME (e.g. "Sub-Agent 1: <subtask>"). Never give the whole task to everyone; split it. You hold NO tools — the sub-agents execute the work. Read their reports and verify each sub-task is actually complete; re-assign ONLY what is still missing or wrong, never work already done. Then write a short final synthesis and finish.',
           at=(360, 60))
_worker = ('You are {me}. From the orchestrator\'s message do ONLY the sub-task addressed to "{me}" — ignore the parts meant for other sub-agents. Actually CALL your tools to carry it out (do not merely describe it). Use ONLY the tools provided to you — never invent or guess a tool name. Never repeat a tool call you have already completed successfully. Then report concisely which tool calls you made.')
g.add_node('Sub-Agent 1', role='worker', prompt=_worker.format(me='Sub-Agent 1'), at=(120, 300))
g.add_node('Sub-Agent 2', role='worker', prompt=_worker.format(me='Sub-Agent 2'), at=(280, 300))
g.add_node('Sub-Agent 3', role='worker', prompt=_worker.format(me='Sub-Agent 3'), at=(440, 300))
g.add_node('Sub-Agent 4', role='worker', prompt=_worker.format(me='Sub-Agent 4'), at=(600, 300))

g.add_conditional_edge('Orchestrator', 'Sub-Agent 1', label='assign', loop=True, max_iters=1)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 2', label='assign', loop=True, max_iters=1)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 3', label='assign', loop=True, max_iters=1)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 4', label='assign', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 1', 'Orchestrator', label='report', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 2', 'Orchestrator', label='report', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 3', 'Orchestrator', label='report', loop=True, max_iters=1)
g.add_conditional_edge('Sub-Agent 4', 'Orchestrator', label='report', loop=True, max_iters=1)

g.set_entry('Orchestrator', at=(60, 60))
g.set_finish('Orchestrator', at=(660, 60))
