from safemas import StateGraph

# Decentralized MAS — Kim et al., "Towards a Science of Scaling Agent Systems"
# (Google DeepMind, 2025), §3.2 / Table 2.
#   A = {a_1..a_n}, C = {(a_i, a_j) : i≠j} (all-to-all, NO hierarchy),
#   Ω = consensus. LLM calls O(dnk)+O(1), sequential depth d, comm overhead d·n.
#   Peers exchange across d sequential debate rounds and reach consensus by
#   majority voting — peer-to-peer information fusion without an orchestrator.
#   No central validation: errors can propagate laterally (highest trace-level
#   amplification in the paper).
#
#   TRUE ALL-TO-ALL: every peer is wired to every OTHER peer (6 directed edges for
#   n=3), as bounded loop edges so the mesh debates over d rounds (max_iters left
#   implicit → the engine's SAFEMAS_MAX_ROUNDS, the paper's d; default 3). Each peer
#   has join='all', so it waits to hear from BOTH other peers before forming its next
#   position — that is what makes the rounds SYNCHRONISED (a peer fuses all peers'
#   views per round) rather than a runaway cascade, and it is the peer-to-peer
#   information fusion the paper specifies. Consensus is the post-debate majority.
g = StateGraph('decentralized',
               task='Reach a consensus answer through peer-to-peer debate and majority voting.',
               group='Scaling Agent Systems (DeepMind)',
               title='MAS · Decentralized (peer debate + vote)')

# agents — three peers, no orchestrator. join='all' = integrate every peer's
# message each round (synchronised debate), not run on the first one that arrives.
_debate = ('Debate with your peers: read every peer position you receive, then '
           'restate your own best answer for this round.')
g.add_node('Peer A', role='debater', join='all', prompt=_debate, at=(330, 40))
g.add_node('Peer B', role='debater', join='all', prompt=_debate, at=(140, 320))
g.add_node('Peer C', role='debater', join='all', prompt=_debate, at=(520, 320))
g.add_node('Consensus', role='aggregator', join='all',
           prompt='Take the peers\' final positions and return the majority '
                  'answer. No agent has authority — decide purely by vote.',
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
