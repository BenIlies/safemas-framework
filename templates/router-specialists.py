# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('router-specialists', task='Handle a mixed request that may need code or math.', group='Workflows', title='Router → specialists')

# agents
router = mas.agent('Router', role='router', at=(100, 190))
code_specialist = mas.agent('Code Specialist', role='coder', at=(380, 70))
math_specialist = mas.agent('Math Specialist', role='mathematician', at=(380, 310))
collector = mas.agent('Collector', role='finaliser', at=(660, 190))

# resources
python_repl = mas.tool('Python REPL', spec='def run(code: str) -> str', at=(380, -70))
calculator = mas.tool('Calculator', spec='def calc(expr: str) -> str', at=(380, 470))

# wiring
router.to(code_specialist, label='route: code', when='code')
router.to(math_specialist, label='route: math', when='math')
code_specialist.to(collector, label='answer')
math_specialist.to(collector, label='answer')
code_specialist.uses(python_repl)
math_specialist.uses(calculator)

# entry / exit
mas.entry(router, at=(-120, 200))
mas.exit(collector, at=(900, 200))

if __name__ == "__main__":
    mas.run()
