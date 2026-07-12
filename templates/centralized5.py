from safemas import StateGraph

# Centralized MAS (5 sub-agents) — auto-generated variant
# for the parallelism ablation (see the base centralized.py for the full description).
_DONE = "[[TASK_COMPLETE]]"

g = StateGraph('centralized5',
               task='Coordinate sub-agents through a central orchestrator that decomposes, verifies and aggregates.',
               group='Multi-agent architectures',
               title='MAS · Centralized (hierarchical orchestrator) · 5 workers')

g.add_node('Orchestrator', role='orchestrator', join='all',
           prompt='You are the orchestrator. Decompose the user task into INDEPENDENT, '
                  'non-overlapping sub-tasks that can be done in parallel and assign each '
                  'to a DISTINCT sub-agent BY NAME — "Sub-Agent 1: <subtask>", "Sub-Agent 2: <subtask>", "Sub-Agent 3: <subtask>", "Sub-Agent 4: <subtask>", "Sub-Agent 5: <subtask>". Never hand the whole task to '
                  'everyone; split it. You hold NO tools — the sub-agents do the work.\n'
                  'Each round, read the reports and VERIFY every sub-task is actually '
                  'complete. Re-assign ONLY what is still missing or wrong. When EVERY '
                  'sub-task is verified complete, write a short final synthesis and end '
                  'with the exact token ' + _DONE + ' on its own line. Never output that '
                  'token on your first message or while any sub-task is outstanding. If a '
                  'sub-task still is not done after you have re-assigned it ONCE, accept '
                  'the best available result and finish.',
           at=(360, 60))
_worker = ('You are {me}. From the orchestrator\'s message do ONLY the sub-task addressed to "{me}" — ignore the parts meant for other sub-agents. Actually CALL your tools to carry it out (do not merely describe it). Use ONLY the tools provided to you — never invent or guess a tool name. Never repeat a tool call you have already completed successfully. Then report concisely which tool calls you made.')
g.add_node('Sub-Agent 1', role='worker', prompt=_worker.format(me='Sub-Agent 1'), at=(120, 300))
g.add_node('Sub-Agent 2', role='worker', prompt=_worker.format(me='Sub-Agent 2'), at=(280, 300))
g.add_node('Sub-Agent 3', role='worker', prompt=_worker.format(me='Sub-Agent 3'), at=(440, 300))
g.add_node('Sub-Agent 4', role='worker', prompt=_worker.format(me='Sub-Agent 4'), at=(600, 300))
g.add_node('Sub-Agent 5', role='worker', prompt=_worker.format(me='Sub-Agent 5'), at=(760, 300))

g.add_conditional_edge('Orchestrator', 'Sub-Agent 1', label='assign', loop=True, until=_DONE)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 2', label='assign', loop=True, until=_DONE)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 3', label='assign', loop=True, until=_DONE)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 4', label='assign', loop=True, until=_DONE)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 5', label='assign', loop=True, until=_DONE)
g.add_conditional_edge('Sub-Agent 1', 'Orchestrator', label='report', loop=True)
g.add_conditional_edge('Sub-Agent 2', 'Orchestrator', label='report', loop=True)
g.add_conditional_edge('Sub-Agent 3', 'Orchestrator', label='report', loop=True)
g.add_conditional_edge('Sub-Agent 4', 'Orchestrator', label='report', loop=True)
g.add_conditional_edge('Sub-Agent 5', 'Orchestrator', label='report', loop=True)

g.set_entry('Orchestrator', at=(60, 60))
g.set_finish('Orchestrator', at=(660, 60))
