# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('reconcile', task='Answer via a round-table of diverse models and a weighted consensus vote.', group='Debate & collaboration', title='ReConcile (Chen 2024)')

# agents
agent_a_e_g_gpt = mas.agent('Agent A (e.g. GPT)', role='round-table', at=(240, 40))
agent_b_e_g_claude = mas.agent('Agent B (e.g. Claude)', role='round-table', at=(130, 380))
agent_c_e_g_gemini = mas.agent('Agent C (e.g. Gemini)', role='round-table', at=(430, 380))
weighted_consensus = mas.agent('Weighted Consensus', role='aggregator', prompt='Combine the agents’ answers weighted by their confidence scores.', join='all', at=(700, 210))

# wiring
agent_a_e_g_gpt.to(agent_b_e_g_claude, label='answer · explanation · confidence')
agent_b_e_g_claude.to(agent_c_e_g_gemini, label='answer · explanation · confidence')
agent_c_e_g_gemini.to(agent_a_e_g_gpt, label='next round', loop=True, max_iters=2)
agent_a_e_g_gpt.to(weighted_consensus, label='final vote')
agent_b_e_g_claude.to(weighted_consensus, label='final vote')
agent_c_e_g_gemini.to(weighted_consensus, label='final vote')

# entry / exit
mas.entry(agent_a_e_g_gpt, at=(-200, 210))
mas.exit(weighted_consensus, at=(960, 210))

if __name__ == "__main__":
    mas.run()
