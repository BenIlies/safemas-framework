// Definitions for the palette elements and the attack each can carry.
// Mirrors backend/schema.py and the SafeMAS threat model.

export const NODE_TYPES = {
  agent: {
    label: 'Agent',
    icon: '🤖',
    color: '#3b82f6',
    attack: 'prompt-injection',
    attackLabel: 'Prompt Injection',
    defaults: {
      provider: null, model: '', role: 'worker', prompt: '',
      temperature: null, max_tokens: null, entry: false, exit: false,
    },
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

// Provider kinds and the default model lists shown when none are configured.
export const PROVIDER_KINDS = {
  openai: { label: 'OpenAI', needsBaseUrl: false, models: ['gpt-4o', 'gpt-4o-mini', 'o3-mini'] },
  anthropic: { label: 'Anthropic', needsBaseUrl: false, models: ['claude-opus-4-8', 'claude-sonnet-4-6', 'claude-haiku-4-5'] },
  'openai-compatible': { label: 'OpenAI-compatible', needsBaseUrl: true, models: ['llama-3.3-70b', 'mistral-large'] },
  mock: { label: 'Mock (no key)', needsBaseUrl: false, models: ['mock'] },
}

export const MEMORY_BACKENDS = ['in-memory', 'vector', 'redis', 'sqlite', 'kv']

export function blankMalicious() {
  return { enabled: false, attack: null, payload: '' }
}
