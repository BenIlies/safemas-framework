from safemas import StateGraph

# Decentralized MAS — peer debate + majority vote.
#   A = {a_1..a_n}, C = {(a_i, a_j) : i≠j} (all-to-all, NO hierarchy),
#   Ω = consensus. LLM calls O(dnk)+O(1), sequential depth d, comm overhead d·n.
#   Peers exchange across d sequential debate rounds and reach consensus by majority
#   voting — peer-to-peer information fusion without an orchestrator. With no central
#   validation, errors can propagate laterally (this topology tends to amplify errors
#   the most).
#
#   TRUE ALL-TO-ALL: every peer is wired to every OTHER peer (6 directed edges for
#   n=3), as bounded loop edges so the mesh debates over d rounds (max_iters left
#   implicit → the engine's SAFEMAS_MAX_ROUNDS; default 3). Each peer has join='all',
#   so it waits to hear from BOTH other peers before forming its next position — that
#   is what makes the rounds SYNCHRONISED (a peer fuses all peers' views per round)
#   rather than a runaway cascade. Consensus is the post-debate majority.
g = StateGraph('decentralized',
               task='Reach a consensus answer through peer-to-peer debate and majority voting.',
               group='Multi-agent architectures',
               title='MAS · Decentralized (peer debate + vote)')

# agents — three peers, no orchestrator. join='all' = integrate every peer's
# message each round (synchronised debate), not run on the first one that arrives.
# No orchestrator, so peers SELF-DIVIDE the work by position: split the user task into
# independent sub-tasks and let Peer A own the 1st, Peer B the 2nd, Peer C the 3rd (wrap
# around if there are more). Each peer EXECUTES its own sub-task with its tools, then the
# peers exchange so the group collectively covers every sub-task.
_debate = ('You are {me}, one of three peers (Peer A, Peer B, Peer C) with no leader. '
           'Split the user task into independent sub-tasks and do ONLY the one that falls '
           'to {me} by position ({me} owns sub-task #{n}). CALL your tools to carry out '
           'YOUR sub-task only — do NOT redo a peer\'s sub-task that they report as done, '
           'or you will duplicate work. Use ONLY the tools provided to you — never invent '
           'a tool name. Never repeat a tool call you have already completed. Only pick up '
           'another sub-task if a peer explicitly reports they could not do it. Read the '
           'peer positions you receive, then restate what YOU have done this round.')
g.add_node('Peer A', role='debater', join='all', prompt=_debate.format(me='Peer A', n=1), at=(330, 40))
g.add_node('Peer B', role='debater', join='all', prompt=_debate.format(me='Peer B', n=2), at=(140, 320))
g.add_node('Peer C', role='debater', join='all', prompt=_debate.format(me='Peer C', n=3), at=(520, 320))
g.add_node('Consensus', role='aggregator', join='all',
           prompt='You have NO tools — never attempt a tool call. Take the peers\' final '
                  'positions and return the majority answer; no agent has authority, '
                  'decide purely by vote.',
           at=(330, 560))

# edges — ALL-TO-ALL peer exchange {(a_i, a_j) : i≠j}, bounded loops over d rounds
g.add_conditional_edge('Peer A', 'Peer B', label='exchange', loop=True)
g.add_conditional_edge('Peer A', 'Peer C', label='exchange', loop=True)
g.add_conditional_edge('Peer B', 'Peer A', label='exchange', loop=True)
g.add_conditional_edge('Peer B', 'Peer C', label='exchange', loop=True)
g.add_conditional_edge('Peer C', 'Peer A', label='exchange', loop=True)
g.add_conditional_edge('Peer C', 'Peer B', label='exchange', loop=True)
# majority-voting consensus (Ω = consensus) — peers vote their current position;
# the sink's post-debate firing is the answer (final = last exit output).
g.add_edge('Peer A', 'Consensus', label='vote')
g.add_edge('Peer B', 'Consensus', label='vote')
g.add_edge('Peer C', 'Consensus', label='vote')

# entry / exit — the task seeds every peer; the vote is the sink
g.set_entry('Peer A', 'Peer B', 'Peer C', at=(-60, 180))
g.set_finish('Consensus', at=(330, 720))
