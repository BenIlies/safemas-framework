from safemas import StateGraph

# Hybrid MAS — orchestrator + limited peer exchange.
#   A = {a_orch, a_1..a_n}, C = C_centralized ∪ C_peer (star + limited peer edges),
#   Ω = hierarchical + lateral. LLM calls O(rnk)+O(r)+O(p), comm overhead r·n+p·m.
#   Inherits orchestrator control (decompose / verify / aggregate) while allowing
#   bounded lateral exchange between sub-agents — hierarchy plus peer flexibility.
#
#   Like Centralized, TERMINATION IS ORCHESTRATOR-DRIVEN (not a fixed round count):
#   the orchestrator re-tasks/re-verifies each round and ends the loop by emitting the
#   sentinel [[TASK_COMPLETE]] (the `until` guard on the assign edges), with max_iters
#   only as a safety backstop. On TOP of the star sits a CURATED, denser-than-a-chain
#   peer mesh (Sub-Agent 2 is the lateral hub: 1↔2 and 2↔3 — selective, NOT the
#   all-to-all of Decentralized). Because orchestration is multi-round, a peer message
#   shared in one round is folded into that sub-agent's report in the NEXT round.
_DONE = "[[TASK_COMPLETE]]"
_BACKSTOP = 8

g = StateGraph('hybrid',
               task='Coordinate sub-agents under an orchestrator while allowing limited peer-to-peer exchange.',
               group='Multi-agent architectures',
               title='MAS · Hybrid (orchestrator + peer)')

# agents
g.add_node('Orchestrator', role='orchestrator', join='all',
           prompt='You are the orchestrator. Decompose the user task into INDEPENDENT, '
                  'non-overlapping sub-tasks that can run in parallel and assign each to '
                  'a DISTINCT sub-agent BY NAME — "Sub-Agent 1: <subtask>", "Sub-Agent 2: '
                  '<subtask>", "Sub-Agent 3: <subtask>". Never give the whole task to '
                  'everyone. You hold NO tools — the sub-agents execute and may share '
                  'findings laterally.\nEach round, read the reports and VERIFY every '
                  'sub-task is actually complete. Re-assign ONLY what is still missing or '
                  'wrong — never re-assign finished work. When EVERY sub-task is verified '
                  'complete, write a short final synthesis and end with the exact token '
                  + _DONE + ' on its own line. Never output that token on your first '
                  'message or while any sub-task is outstanding. If a sub-task still is '
                  'not done after you have re-assigned it ONCE, accept the best available '
                  'result and finish — never keep looping.',
           at=(360, 60))
_worker = ('You are {me}. Do ONLY the sub-task the orchestrator addressed to "{me}" — '
           'not the other agents\' parts. Actually CALL your tools to carry it out. Use '
           'ONLY the tools provided to you — never invent or guess a tool name. Never '
           'repeat a tool call you have already completed successfully. Fold in any peer '
           'findings you receive, then report concisely which tool calls you made.')
g.add_node('Sub-Agent 1', role='worker', prompt=_worker.format(me='Sub-Agent 1'), at=(120, 300))
g.add_node('Sub-Agent 2', role='worker', prompt=_worker.format(me='Sub-Agent 2'), at=(360, 300))
g.add_node('Sub-Agent 3', role='worker', prompt=_worker.format(me='Sub-Agent 3'), at=(600, 300))

# edges — star control (assign / report). Assign edges carry `until` so the orchestrator
# ends the loop on completion; max_iters is the safety backstop ...
g.add_conditional_edge('Orchestrator', 'Sub-Agent 1', label='assign', loop=True, until=_DONE, max_iters=_BACKSTOP)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 2', label='assign', loop=True, until=_DONE, max_iters=_BACKSTOP)
g.add_conditional_edge('Orchestrator', 'Sub-Agent 3', label='assign', loop=True, until=_DONE, max_iters=_BACKSTOP)
g.add_conditional_edge('Sub-Agent 1', 'Orchestrator', label='report', loop=True, max_iters=_BACKSTOP)
g.add_conditional_edge('Sub-Agent 2', 'Orchestrator', label='report', loop=True, max_iters=_BACKSTOP)
g.add_conditional_edge('Sub-Agent 3', 'Orchestrator', label='report', loop=True, max_iters=_BACKSTOP)
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
