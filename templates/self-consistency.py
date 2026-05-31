# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('self-consistency', task='Solve a reasoning problem and vote over several sampled solutions.', group='Reasoning & reflection', title='Self-Consistency (Wang 2023)')

# agents
dispatcher = mas.agent('Dispatcher', role='dispatcher', prompt='Relay the task to each sampler unchanged.', at=(-40, 210))
cot_sample_1 = mas.agent('CoT Sample 1', role='reasoner', temperature=0.7, at=(220, 40))
cot_sample_2 = mas.agent('CoT Sample 2', role='reasoner', temperature=0.7, at=(220, 210))
cot_sample_3 = mas.agent('CoT Sample 3', role='reasoner', temperature=0.7, at=(220, 380))
majority_vote = mas.agent('Majority Vote', role='aggregator', prompt='Return the answer that the most reasoning paths agree on.', join='all', at=(520, 210))

# wiring
dispatcher.to(cot_sample_1, label='task')
dispatcher.to(cot_sample_2, label='task')
dispatcher.to(cot_sample_3, label='task')
cot_sample_1.to(majority_vote, label='answer')
cot_sample_2.to(majority_vote, label='answer')
cot_sample_3.to(majority_vote, label='answer')

# entry / exit
mas.entry(dispatcher, at=(-260, 210))
mas.exit(majority_vote, at=(820, 210))

if __name__ == "__main__":
    mas.run()
