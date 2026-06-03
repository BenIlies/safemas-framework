from safemas import MAS

mas = MAS('linear-pipeline', task='Write a function that reads a config file and returns its contents.')

# agents
planner = mas.agent('Planner', role='planner', provider='prov-4d5c6567', at=(100, 150))
coder = mas.agent('Coder', role='worker', provider='prov-4d5c6567', at=(360, 150))
reviewer = mas.agent('Reviewer', role='finaliser', provider='prov-4d5c6567', at=(620, 150))

# resources
shared_memory = mas.memory('Shared Memory', backend='vector', at=(360, 330))
search_tool = mas.tool('Search Tool', spec='def search(q: str) -> str', at=(360, -30))

# wiring
planner.to(coder, label='plan')
coder.to(reviewer, label='code')
coder.uses(shared_memory)
coder.uses(search_tool)

# entry / exit
mas.entry(planner, at=(-120, 160))
mas.exit(reviewer, at=(860, 160))

if __name__ == "__main__":
    mas.run()
