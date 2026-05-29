// Clean starting points for a new architecture. Templates never contain
// malicious elements — you add attacks yourself to probe a design. Every
// template has exactly one entrance (receives the task) and one exit (produces
// the final answer).

// The minimal MAS: an entrance agent wired to an exit agent. Also what "New"
// generates, so a fresh canvas always has a defined entrance and exit.
export const STARTER = {
  name: 'new-mas',
  version: 1,
  task: 'Solve the assigned task.',
  nodes: [
    { id: 'agent-1', type: 'agent', label: 'Entrance', role: 'entry', entry: true, position: { x: 120, y: 160 } },
    { id: 'agent-2', type: 'agent', label: 'Exit', role: 'output', exit: true, position: { x: 460, y: 160 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
  ],
}

// A single agent that is both the entrance and the exit.
const SOLO = {
  name: 'single-agent',
  version: 1,
  task: 'Answer the user’s question.',
  nodes: [
    { id: 'agent-1', type: 'agent', label: 'Assistant', role: 'assistant', entry: true, exit: true, position: { x: 280, y: 160 } },
    { id: 'tool-1', type: 'tool', label: 'Calculator', spec: 'def calc(expr: str) -> str', position: { x: 280, y: 340 } },
  ],
  edges: [
    { id: 'edge-1', source: 'tool-1', target: 'agent-1', kind: 'attach' },
  ],
}

const LINEAR = {
  name: 'linear-pipeline',
  version: 1,
  task: 'Write a function that reads a config file and returns its contents.',
  nodes: [
    { id: 'agent-1', type: 'agent', label: 'Planner', role: 'planner', entry: true, position: { x: 80, y: 160 } },
    { id: 'agent-2', type: 'agent', label: 'Coder', role: 'worker', position: { x: 360, y: 160 } },
    { id: 'agent-3', type: 'agent', label: 'Reviewer', role: 'finaliser', exit: true, position: { x: 640, y: 160 } },
    { id: 'mem-1', type: 'memory', label: 'Shared Memory', backend: 'vector', position: { x: 360, y: 340 } },
    { id: 'tool-1', type: 'tool', label: 'Search Tool', spec: 'def search(q: str) -> str', position: { x: 360, y: -20 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-2', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'mem-1', target: 'agent-2', kind: 'attach' },
    { id: 'edge-4', source: 'tool-1', target: 'agent-2', kind: 'attach' },
  ],
}

const FANOUT = {
  name: 'planner-workers-aggregator',
  version: 1,
  task: 'Research a topic and produce a concise summary.',
  nodes: [
    { id: 'agent-1', type: 'agent', label: 'Planner', role: 'planner', entry: true, position: { x: 80, y: 180 } },
    { id: 'agent-2', type: 'agent', label: 'Worker A', role: 'worker', position: { x: 360, y: 60 } },
    { id: 'agent-3', type: 'agent', label: 'Worker B', role: 'worker', position: { x: 360, y: 300 } },
    { id: 'agent-4', type: 'agent', label: 'Aggregator', role: 'finaliser', exit: true, position: { x: 660, y: 180 } },
    { id: 'tool-1', type: 'tool', label: 'Web Tool', spec: 'def fetch(url: str) -> str', position: { x: 360, y: -120 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-1', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'agent-2', target: 'agent-4', kind: 'channel' },
    { id: 'edge-4', source: 'agent-3', target: 'agent-4', kind: 'channel' },
    { id: 'edge-5', source: 'tool-1', target: 'agent-2', kind: 'attach' },
  ],
}

// Generator → Critic → Finaliser (reflection / self-critique loop, unrolled).
const REFLECTION = {
  name: 'reflection',
  version: 1,
  task: 'Draft and refine a short blog post.',
  nodes: [
    { id: 'agent-1', type: 'agent', label: 'Generator', role: 'drafter', entry: true, position: { x: 80, y: 160 } },
    { id: 'agent-2', type: 'agent', label: 'Critic', role: 'reviewer', position: { x: 360, y: 160 } },
    { id: 'agent-3', type: 'agent', label: 'Finaliser', role: 'finaliser', exit: true, position: { x: 640, y: 160 } },
    { id: 'mem-1', type: 'memory', label: 'Draft Store', backend: 'kv', position: { x: 360, y: 340 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-2', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'mem-1', target: 'agent-1', kind: 'attach' },
    { id: 'edge-4', source: 'mem-1', target: 'agent-2', kind: 'attach' },
  ],
}

// Router dispatches to specialists; a collector merges their answers.
const ROUTER = {
  name: 'router-specialists',
  version: 1,
  task: 'Handle a mixed request that may need code or math.',
  nodes: [
    { id: 'agent-1', type: 'agent', label: 'Router', role: 'router', entry: true, position: { x: 80, y: 200 } },
    { id: 'agent-2', type: 'agent', label: 'Code Specialist', role: 'coder', position: { x: 360, y: 80 } },
    { id: 'agent-3', type: 'agent', label: 'Math Specialist', role: 'mathematician', position: { x: 360, y: 320 } },
    { id: 'agent-4', type: 'agent', label: 'Collector', role: 'finaliser', exit: true, position: { x: 660, y: 200 } },
    { id: 'tool-1', type: 'tool', label: 'Python REPL', spec: 'def run(code: str) -> str', position: { x: 360, y: -60 } },
    { id: 'tool-2', type: 'tool', label: 'Calculator', spec: 'def calc(expr: str) -> str', position: { x: 360, y: 480 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-1', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'agent-2', target: 'agent-4', kind: 'channel' },
    { id: 'edge-4', source: 'agent-3', target: 'agent-4', kind: 'channel' },
    { id: 'edge-5', source: 'tool-1', target: 'agent-2', kind: 'attach' },
    { id: 'edge-6', source: 'tool-2', target: 'agent-3', kind: 'attach' },
  ],
}

// Retrieval-augmented generation: a retriever backed by a knowledge base feeds
// an answerer.
const RAG = {
  name: 'rag-pipeline',
  version: 1,
  task: 'Answer a question using the knowledge base.',
  nodes: [
    { id: 'agent-1', type: 'agent', label: 'Retriever', role: 'retriever', entry: true, position: { x: 120, y: 160 } },
    { id: 'agent-2', type: 'agent', label: 'Answerer', role: 'finaliser', exit: true, position: { x: 460, y: 160 } },
    { id: 'mem-1', type: 'memory', label: 'Knowledge Base', backend: 'vector', position: { x: 120, y: 340 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'mem-1', target: 'agent-1', kind: 'attach' },
  ],
}

// Supervisor delegates to sub-agents and produces the final result itself.
const HIERARCHY = {
  name: 'supervisor-hierarchy',
  version: 1,
  task: 'Plan and execute a multi-step task.',
  nodes: [
    { id: 'agent-1', type: 'agent', label: 'Supervisor', role: 'supervisor', entry: true, exit: true, position: { x: 360, y: 60 } },
    { id: 'agent-2', type: 'agent', label: 'Researcher', role: 'worker', position: { x: 160, y: 280 } },
    { id: 'agent-3', type: 'agent', label: 'Writer', role: 'worker', position: { x: 560, y: 280 } },
    { id: 'mem-1', type: 'memory', label: 'Scratchpad', backend: 'in-memory', position: { x: 360, y: 460 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-1', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'mem-1', target: 'agent-2', kind: 'attach' },
    { id: 'edge-4', source: 'mem-1', target: 'agent-3', kind: 'attach' },
  ],
}

export const TEMPLATES = [
  { id: 'starter', label: 'Starter (entrance → exit)', arch: STARTER },
  { id: 'solo', label: 'Single agent', arch: SOLO },
  { id: 'linear', label: 'Linear pipeline', arch: LINEAR },
  { id: 'fanout', label: 'Planner / workers / aggregator', arch: FANOUT },
  { id: 'reflection', label: 'Reflection (generator → critic)', arch: REFLECTION },
  { id: 'router', label: 'Router → specialists', arch: ROUTER },
  { id: 'rag', label: 'RAG (retriever + knowledge base)', arch: RAG },
  { id: 'hierarchy', label: 'Supervisor hierarchy', arch: HIERARCHY },
]

export const DEFAULT_TEMPLATE = LINEAR
