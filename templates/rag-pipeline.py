from safemas import StateGraph

g = StateGraph('rag-pipeline', task='Answer a question using the knowledge base.', group='Workflows', title='RAG (retriever + knowledge base)')

# agents
g.add_node('Retriever', role='retriever', at=(100, 150))
g.add_node('Answerer', role='finaliser', at=(360, 150))

# edges
g.add_edge('Retriever', 'Answerer', label='retrieved context')

# entry / exit
g.set_entry('Retriever', at=(-120, 160))
g.set_finish('Answerer', at=(600, 160))
