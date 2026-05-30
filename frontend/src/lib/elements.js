// Definitions for the palette elements and the attack each can carry.
// Mirrors backend/schema.py and the SafeMAS threat model.

export const NODE_TYPES = {
  agent: {
    label: 'Agent',
    icon: '🤖',
    color: '#3b82f6',
    attack: 'prompt-injection',
    attackLabel: 'Prompt Injection',
    defaults: { model: 'gpt-4o-mini', role: 'worker', prompt: '', entry: false },
  },
  memory: {
    label: 'Memory',
    icon: '🧠',
    color: '#8b5cf6',
    attack: 'memory-poisoning',
    attackLabel: 'Memory Poisoning',
    defaults: { backend: 'in-memory' },
  },
  tool: {
    label: 'Tool',
    icon: '🛠️',
    color: '#10b981',
    attack: 'tool-poisoning',
    attackLabel: 'Tool Poisoning',
    defaults: { spec: 'def tool(query: str) -> str' },
  },
}

// Channel (agent->agent) edges can be turned into Agent-in-the-Middle rewrites.
export const EDGE_ATTACK = {
  attack: 'aitm',
  attackLabel: 'AiTM Rewrite',
}

export const MODELS = [
  'gpt-4o-mini',
  'gpt-4o',
  'claude-opus-4-8',
  'claude-sonnet-4-6',
  'claude-haiku-4-5',
  'llama-3.3-70b',
]

export function blankMalicious() {
  return { enabled: false, attack: null, payload: '' }
}
