from safemas import StateGraph

# Decentralized MAS (4 peers) — auto-generated variant for the parallelism ablation
# (see base decentralized.py). All-to-all peer debate + majority-vote consensus.
g = StateGraph('decentralized4',
               task='Reach a consensus answer through peer-to-peer debate and majority voting.',
               group='Multi-agent architectures',
               title='MAS · Decentralized (peer debate + vote) · 4 peers')

_debate = ("You are {me}, one of 4 peers (Peer A, Peer B, Peer C, Peer D) with no leader. Split the user task into 4 independent sub-tasks and do ONLY the one that falls to {me} by position ({me} owns sub-task #{n}). CALL your tools to carry out YOUR sub-task only — do NOT redo a peer's sub-task they report as done. Use ONLY the tools provided to you — never invent a tool name. Never repeat a tool call you have already completed. Only pick up another sub-task if a peer explicitly reports they could not do it. Read the peer positions you receive, then restate what YOU have done this round.")
g.add_node('Peer A', role='debater', join='all', prompt=_debate.format(me='Peer A', n=1), at=(120, 40))
g.add_node('Peer B', role='debater', join='all', prompt=_debate.format(me='Peer B', n=2), at=(270, 320))
g.add_node('Peer C', role='debater', join='all', prompt=_debate.format(me='Peer C', n=3), at=(420, 40))
g.add_node('Peer D', role='debater', join='all', prompt=_debate.format(me='Peer D', n=4), at=(570, 320))
g.add_node('Consensus', role='aggregator', join='all',
           prompt='You have NO tools — never attempt a tool call. Take the peers\' final '
                  'positions and return the majority answer; decide purely by vote.',
           at=(330, 560))

g.add_conditional_edge('Peer A', 'Peer B', label='exchange', loop=True)
g.add_conditional_edge('Peer A', 'Peer C', label='exchange', loop=True)
g.add_conditional_edge('Peer A', 'Peer D', label='exchange', loop=True)
g.add_conditional_edge('Peer B', 'Peer A', label='exchange', loop=True)
g.add_conditional_edge('Peer B', 'Peer C', label='exchange', loop=True)
g.add_conditional_edge('Peer B', 'Peer D', label='exchange', loop=True)
g.add_conditional_edge('Peer C', 'Peer A', label='exchange', loop=True)
g.add_conditional_edge('Peer C', 'Peer B', label='exchange', loop=True)
g.add_conditional_edge('Peer C', 'Peer D', label='exchange', loop=True)
g.add_conditional_edge('Peer D', 'Peer A', label='exchange', loop=True)
g.add_conditional_edge('Peer D', 'Peer B', label='exchange', loop=True)
g.add_conditional_edge('Peer D', 'Peer C', label='exchange', loop=True)
g.add_edge('Peer A', 'Consensus', label='vote')
g.add_edge('Peer B', 'Consensus', label='vote')
g.add_edge('Peer C', 'Consensus', label='vote')
g.add_edge('Peer D', 'Consensus', label='vote')

g.set_entry('Peer A', 'Peer B', 'Peer C', 'Peer D', at=(-60, 180))
g.set_finish('Consensus', at=(330, 720))
