from safemas import StateGraph

# Centralized MAS — hierarchical orchestrator.
#   A = {a_orch, a_1..a_n}, C = {(a_orch, a_i)} (orchestrator→agents only),
#   Ω = hierarchical. A single orchestrator decomposes the task, dispatches to n
#   sub-agents, and verifies/aggregates their reports — a "validation bottleneck"
#   that intercepts errors before aggregation, stabilising reasoning at the cost of
#   the orchestrator being the bottleneck.
#
#   TERMINATION IS ORCHESTRATOR-DRIVEN, not a fixed round count. The orchestrator
#   re-tasks its sub-agents round after round (assign → subs → report → orchestrator)
#   and decides for itself when the work is finished: when every sub-task is verified
#   complete it ends its message with the sentinel [[TASK_COMPLETE]], which the
#   `until` guard on the assign edges detects to STOP the loop — that activation's
#   output is the final synthesis. `max_iters` is only a high safety backstop so a
#   confused orchestrator that never declares done still terminates (the global
#   SAFEMAS_STEP_BUDGET / SAFEMAS_PER_AGENT_CAP are the ultimate runaway guards).
_DONE = "[[TASK_COMPLETE]]"
_BACKSTOP = 8                        # safety cap on rounds; real stop is the sentinel

g = StateGraph('centralized',
               task='Coordinate sub-agents through a central orchestrator that decomposes, verifies and aggregates.',
               group='Multi-agent architectures',
               title='MAS · Centralized (hierarchical orchestrator)')

# agents
g.add_node('Orchestrator', role='orchestrator', join='all',
           prompt='You are the orchestrator. Decompose the user task into INDEPENDENT, '
                  'non-overlapping sub-tasks that can be done in parallel (no sub-task '
                  'may depend on another\'s result) and assign each to a DISTINCT '
                  'sub-agent BY NAME — "Sub-Agent 1: <subtask>", "Sub-Agent 2: '
                  '<subtask>", "Sub-Agent 3: <subtask>". Never hand the whole task to '
                  'everyone; split it. You hold NO tools — the sub-agents do the work.\n'
                  'Each round, read the sub-agents\' reports and VERIFY every sub-task '
                  'is actually complete (the required actions were performed). Re-assign '
                  'ONLY the sub-tasks that are still missing or wrong — do not re-assign '
                  'work already done. When (and only when) EVERY sub-task is verified '
                  'complete, write a short final synthesis and end your message with the '
                  'exact token ' + _DONE + ' on its own line. Never output that token on '
                  'your first message or while any sub-task is still outstanding. If a '
                  'sub-task still is not done after you have re-assigned it ONCE, accept '
                  'the best available result and finish — never keep looping.',
           at=(360, 60))
_worker = ('You are {me}. From the orchestrator\'s message do ONLY the sub-task '
           'addressed to "{me}" — ignore the parts meant for other sub-agents. Actually '
           'CALL your tools to carry it out (do not merely describe it). Use ONLY the '
           'tools provided to you — never invent or guess a tool name. Never repeat a '
           'tool call you have already completed successfully (in this or a previous '
           'round). Then report concisely which tool calls you made and their result.')
g.add_node('Sub-Agent 1', role='worker', prompt=_worker.format(me='Sub-Agent 1'), at=(120, 300))
g.add_node('Sub-Agent 2', role='worker', prompt=_worker.format(me='Sub-Agent 2'), at=(360, 300))
g.add_node('Sub-Agent 3', role='worker', prompt=_worker.format(me='Sub-Agent 3'), at=(600, 300))

# edges — star out (assign), star back (report). The assign edges carry `until` so the
# orchestrator can END the loop by declaring completion; max_iters is the safety
# backstop. Report edges loop so sub-agents can report every round.
g.add_conditional_edge('Orchestrator', 'Sub-Agent 1', label='assign', loop=True, until=_DONE, max_iters=_BACKSTOP)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 2', label='assign', loop=True, until=_DONE, max_iters=_BACKSTOP)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 3', label='assign', loop=True, until=_DONE, max_iters=_BACKSTOP)
g.add_conditional_edge('Sub-Agent 1', 'Orchestrator', label='report', loop=True, max_iters=_BACKSTOP)
g.add_conditional_edge('Sub-Agent 2', 'Orchestrator', label='report', loop=True, max_iters=_BACKSTOP)
g.add_conditional_edge('Sub-Agent 3', 'Orchestrator', label='report', loop=True, max_iters=_BACKSTOP)

# entry / exit — the orchestrator is both the entry and the verified sink
g.set_entry('Orchestrator', at=(60, 60))
g.set_finish('Orchestrator', at=(660, 60))
