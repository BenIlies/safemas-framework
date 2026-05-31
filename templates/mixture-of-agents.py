# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('mixture-of-agents', task='Answer by layering and aggregating multiple proposer models.', group='Population & layered', title='Mixture-of-Agents (Wang 2024)')

# agents
dispatcher = mas.agent('Dispatcher', role='dispatcher', prompt='Relay the task to each layer-1 proposer.', at=(-120, 260))
layer_1_proposer_a = mas.agent('Layer 1 · Proposer A', role='proposer', at=(120, 80))
layer_1_proposer_b = mas.agent('Layer 1 · Proposer B', role='proposer', at=(120, 260))
layer_1_proposer_c = mas.agent('Layer 1 · Proposer C', role='proposer', at=(120, 440))
layer_2_proposer_a = mas.agent('Layer 2 · Proposer A', role='proposer', join='all', at=(440, 80))
layer_2_proposer_b = mas.agent('Layer 2 · Proposer B', role='proposer', join='all', at=(440, 260))
layer_2_proposer_c = mas.agent('Layer 2 · Proposer C', role='proposer', join='all', at=(440, 440))
aggregator = mas.agent('Aggregator', role='aggregator', prompt='Synthesise the last layer’s proposals into one final answer.', join='all', at=(740, 260))

# wiring
dispatcher.to(layer_1_proposer_a, label='task')
dispatcher.to(layer_1_proposer_b, label='task')
dispatcher.to(layer_1_proposer_c, label='task')
layer_1_proposer_a.to(layer_2_proposer_a, label='proposal')
layer_1_proposer_a.to(layer_2_proposer_b, label='proposal')
layer_1_proposer_a.to(layer_2_proposer_c, label='proposal')
layer_1_proposer_b.to(layer_2_proposer_a, label='proposal')
layer_1_proposer_b.to(layer_2_proposer_b, label='proposal')
layer_1_proposer_b.to(layer_2_proposer_c, label='proposal')
layer_1_proposer_c.to(layer_2_proposer_a, label='proposal')
layer_1_proposer_c.to(layer_2_proposer_b, label='proposal')
layer_1_proposer_c.to(layer_2_proposer_c, label='proposal')
layer_2_proposer_a.to(aggregator, label='proposal')
layer_2_proposer_b.to(aggregator, label='proposal')
layer_2_proposer_c.to(aggregator, label='proposal')

# entry / exit
mas.entry(dispatcher, at=(-340, 260))
mas.exit(aggregator, at=(960, 260))

if __name__ == "__main__":
    mas.run()
