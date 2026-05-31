# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('camel-role-play', task='Cooperatively solve a task through instructor / assistant role-play.', group='Debate & collaboration', title='CAMEL role-play (Li 2023)')

# agents
task_specifier = mas.agent('Task Specifier', role='specifier', prompt='Rewrite the vague idea into one concrete, specific task.', at=(140, 180))
ai_user = mas.agent('AI User', role='instructor', prompt='Give one instruction at a time; never solve the task yourself.', at=(450, 60))
ai_assistant = mas.agent('AI Assistant', role='executor', prompt='Respond to each instruction with a concrete solution.', at=(450, 320))

# wiring
task_specifier.to(ai_user, label='specified task')
ai_user.to(ai_assistant, label='instruction')
ai_assistant.to(ai_user, label='solution', loop=True, max_iters=3, until='task complete')

# entry / exit
mas.entry(task_specifier, at=(-180, 180))
mas.exit(ai_assistant, at=(780, 300))

if __name__ == "__main__":
    mas.run()
