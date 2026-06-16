from safemas import StateGraph

# Decentralized MAS — Kim et al., "Towards a Science of Scaling Agent Systems"
# (Google DeepMind, 2025), §3.2 / Table 2.
#   A = {a_1..a_n}, C = {(a_i, a_j) : i≠j} (all-to-all, NO hierarchy),
#   Ω = consensus. LLM calls O(dnk)+O(1), sequential depth d, comm overhead d·n.
#   Peers exchange across d sequential debate rounds and reach consensus by
#   majority voting — peer-to-peer information fusion without an orchestrator.
#   No central validation: errors can propagate laterally (highest trace-level
#   amplification in the paper).
g = StateGraph('decentralized',
               task='Reach a consensus answer through peer-to-peer debate and majority voting.',
               group='Scaling Agent Systems (DeepMind)',
               title='MAS · Decentralized (peer debate + vote)')

# agents — three peers, no orchestrator
g.add_node('Peer A', role='debater', at=(330, 40))
g.add_node('Peer B', role='debater', at=(140, 320))
g.add_node('Peer C', role='debater', at=(520, 320))
g.add_node('Consensus', role='aggregator', join='all',
           prompt='Take the peers\' final positions and return the majority '
                  'answer. No agent has authority — decide purely by vote.',
           at=(330, 560))

# edges — peer-to-peer exchange (all-to-all flavour) over d debate rounds
g.add_edge('Peer A', 'Peer B', label='exchange')
g.add_edge('Peer A', 'Peer C', label='exchange')
g.add_edge('Peer B', 'Peer C', label='exchange')
g.add_conditional_edge('Peer C', 'Peer A', label='next round', loop=True, max_iters=2)
# majority-voting consensus (Ω = consensus)
g.add_edge('Peer A', 'Consensus', label='vote')
g.add_edge('Peer B', 'Consensus', label='vote')
g.add_edge('Peer C', 'Consensus', label='vote')

# entry / exit — the task seeds every peer; the vote is the sink
g.set_entry('Peer A', 'Peer B', 'Peer C', at=(-60, 180))
g.set_finish('Consensus', at=(330, 720))
