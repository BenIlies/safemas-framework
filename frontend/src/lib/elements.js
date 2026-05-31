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
      temperature: null, max_tokens: null, join: 'any', entry: false, exit: false,
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
  // Structural flow markers. Not draggable from the palette and not deletable;
  // every graph keeps exactly one of each, wired to an agent via an "io" edge.
  entrance: {
    label: 'Entrance',
    icon: '▶',
    color: '#38bdf8',
    structural: true,
    defaults: {},
  },
  exit: {
    label: 'Exit',
    icon: '⏹',
    color: '#34d399',
    structural: true,
    defaults: {},
  },
}

// Channel (agent->agent) edges can be turned into Agent-in-the-Middle rewrites.
export const EDGE_ATTACK = {
  attack: 'aitm',
  attackLabel: 'AiTM Rewrite',
}

// Provider catalogue. SafeMAS supports *any* LLM provider: every backend is
// reached through one of two client engines — `api: 'anthropic'` (the Anthropic
// SDK) or `api: 'openai'` (the OpenAI SDK, which also speaks to every
// OpenAI-compatible endpoint via `baseUrl`). The presets below just pre-fill the
// base URL + a starter model list; the two "custom" kinds plus the always-editable
// Base URL / Models fields mean you can register a provider that isn't listed.
//
//   label        – shown in the dropdown / tag
//   api          – client engine: 'openai' | 'anthropic' | 'mock'
//   baseUrl      – pre-filled endpoint (editable); '' = the engine's default
//   needsBaseUrl – base URL is required (self-hosted / per-resource endpoints)
//   needsKey     – false for keyless local/mock backends
//   models       – starter model list (editable)
export const PROVIDER_KINDS = {
  openai: { label: 'OpenAI', api: 'openai', baseUrl: '', models: ['gpt-4o', 'gpt-4o-mini', 'o3', 'o3-mini', 'o1'] },
  anthropic: { label: 'Anthropic', api: 'anthropic', baseUrl: '', models: ['claude-opus-4-8', 'claude-sonnet-4-6', 'claude-haiku-4-5'] },
  google: { label: 'Google Gemini', api: 'openai', baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai/', models: ['gemini-2.5-pro', 'gemini-2.0-flash', 'gemini-1.5-pro'] },
  'azure-openai': { label: 'Azure OpenAI', api: 'openai', needsBaseUrl: true, models: ['gpt-4o', 'gpt-4o-mini'] },
  mistral: { label: 'Mistral AI', api: 'openai', baseUrl: 'https://api.mistral.ai/v1', models: ['mistral-large-latest', 'mistral-small-latest', 'codestral-latest'] },
  groq: { label: 'Groq', api: 'openai', baseUrl: 'https://api.groq.com/openai/v1', models: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768'] },
  together: { label: 'Together AI', api: 'openai', baseUrl: 'https://api.together.xyz/v1', models: ['meta-llama/Llama-3.3-70B-Instruct-Turbo', 'Qwen/Qwen2.5-72B-Instruct-Turbo'] },
  fireworks: { label: 'Fireworks AI', api: 'openai', baseUrl: 'https://api.fireworks.ai/inference/v1', models: ['accounts/fireworks/models/llama-v3p3-70b-instruct'] },
  openrouter: { label: 'OpenRouter', api: 'openai', baseUrl: 'https://openrouter.ai/api/v1', models: ['openai/gpt-4o', 'anthropic/claude-3.7-sonnet', 'meta-llama/llama-3.3-70b-instruct'] },
  deepseek: { label: 'DeepSeek', api: 'openai', baseUrl: 'https://api.deepseek.com', models: ['deepseek-chat', 'deepseek-reasoner'] },
  xai: { label: 'xAI Grok', api: 'openai', baseUrl: 'https://api.x.ai/v1', models: ['grok-2-latest', 'grok-beta'] },
  perplexity: { label: 'Perplexity', api: 'openai', baseUrl: 'https://api.perplexity.ai', models: ['sonar-pro', 'sonar'] },
  cohere: { label: 'Cohere', api: 'openai', baseUrl: 'https://api.cohere.ai/compatibility/v1', models: ['command-r-plus', 'command-r'] },
  ollama: { label: 'Ollama (local)', api: 'openai', baseUrl: 'http://localhost:11434/v1', needsKey: false, models: ['llama3.3', 'qwen2.5', 'mistral'] },
  vllm: { label: 'vLLM (self-hosted)', api: 'openai', needsBaseUrl: true, needsKey: false, models: [] },
  'openai-compatible': { label: 'OpenAI-compatible (custom)', api: 'openai', needsBaseUrl: true, models: [] },
  'anthropic-compatible': { label: 'Anthropic-compatible (custom)', api: 'anthropic', needsBaseUrl: true, models: [] },
  mock: { label: 'Mock (no key)', api: 'mock', needsKey: false, models: ['mock'] },
}

export const MEMORY_BACKENDS = ['in-memory', 'vector', 'redis', 'sqlite', 'kv']

export function blankMalicious() {
  return { enabled: false, attack: null, payload: '' }
}
