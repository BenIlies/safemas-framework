# SafeMAS template — a multi-agent system as code (the SafeMAS DSL).
# Clean: no malicious elements (add attacks in the editor, or call
# .compromise(payload) on any element, to probe a design).
# Regenerate with:  python backend/scripts/gen_templates.py

from safemas import MAS

mas = MAS('rag-pipeline', task='Answer a question using the knowledge base.', group='Workflows', title='RAG (retriever + knowledge base)')

# agents
retriever = mas.agent('Retriever', role='retriever', at=(100, 150))
answerer = mas.agent('Answerer', role='finaliser', at=(360, 150))

# resources
knowledge_base = mas.memory('Knowledge Base', backend='vector', at=(100, 330))

# wiring
retriever.to(answerer, label='retrieved context')
retriever.uses(knowledge_base)

# entry / exit
mas.entry(retriever, at=(-120, 160))
mas.exit(answerer, at=(600, 160))

if __name__ == "__main__":
    mas.run()
