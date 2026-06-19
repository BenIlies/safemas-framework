from safemas import StateGraph

# Single-Agent System (SAS) — the reference trajectory.
#   |A| = 1, Ω = none. Sequential reasoning, complexity O(k) where k is the
#   agent's max internal iterations. The minimal unit of agentic computation
#   against which every multi-agent delta is measured.
g = StateGraph('sas',
               task='Solve the assigned task end-to-end as a single agent.',
               group='Multi-agent architectures',
               title='SAS · Single-Agent (reference)')

# agents
g.add_node('Solver', role='solver',
           prompt='Reason step by step and produce the final answer on your own. Use '
                  'ONLY the tools provided to you — never invent a tool name. Never repeat '
                  'a tool call you have already completed successfully.',
           at=(300, 160))

# entry / exit
g.set_entry('Solver', at=(60, 160))
g.set_finish('Solver', at=(560, 160))
