from safemas import MAS

mas = MAS('single-agent', task='Answer the user’s question.', group='Basics', title='Single agent + tool')

# agents
assistant = mas.agent('Assistant', role='assistant', at=(330, 150))

# resources
calculator = mas.tool('Calculator', spec='def calc(expr: str) -> str', at=(330, 330))

# wiring
assistant.uses(calculator)

# entry / exit
mas.entry(assistant, at=(60, 160))
mas.exit(assistant, at=(600, 160))

if __name__ == "__main__":
    mas.run()
