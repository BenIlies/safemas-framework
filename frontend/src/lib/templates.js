// Clean starting points for a new architecture. Templates never contain
// malicious elements — you add attacks yourself to probe a design.
//
// Entrance and exit are their own structural nodes (not agent flags): an
// "io" edge runs entrance → entry-agent and exit-agent → exit. Every template
// has exactly one entrance and one exit, each wired to an agent.

// Wrap a set of agents/memory/tools with an entrance and exit node + io edges.
function mas({ name, task, inner, edges, entry, exit, entrancePos, exitPos }) {
  return {
    name,
    version: 1,
    task,
    nodes: [
      { id: 'in-1', type: 'entrance', label: 'Entrance', position: entrancePos },
      ...inner,
      { id: 'out-1', type: 'exit', label: 'Exit', position: exitPos },
    ],
    edges: [
      { id: 'io-in', source: 'in-1', target: entry, kind: 'io' },
      ...edges,
      { id: 'io-out', source: exit, target: 'out-1', kind: 'io' },
    ],
  }
}

// The minimal MAS: entrance → one agent → exit. Also what "New" generates.
export const STARTER = mas({
  name: 'new-mas',
  task: 'Solve the assigned task.',
  entrancePos: { x: 60, y: 160 }, exitPos: { x: 560, y: 160 },
  inner: [
    { id: 'agent-1', type: 'agent', label: 'Agent', role: 'assistant', position: { x: 300, y: 150 } },
  ],
  edges: [],
  entry: 'agent-1', exit: 'agent-1',
})

const SOLO = mas({
  name: 'single-agent',
  task: 'Answer the user’s question.',
  entrancePos: { x: 60, y: 160 }, exitPos: { x: 600, y: 160 },
  inner: [
    { id: 'agent-1', type: 'agent', label: 'Assistant', role: 'assistant', position: { x: 330, y: 150 } },
    { id: 'tool-1', type: 'tool', label: 'Calculator', spec: 'def calc(expr: str) -> str', position: { x: 330, y: 330 } },
  ],
  edges: [{ id: 'edge-1', source: 'tool-1', target: 'agent-1', kind: 'attach' }],
  entry: 'agent-1', exit: 'agent-1',
})

const LINEAR = mas({
  name: 'linear-pipeline',
  task: 'Write a function that reads a config file and returns its contents.',
  entrancePos: { x: -120, y: 160 }, exitPos: { x: 860, y: 160 },
  inner: [
    { id: 'agent-1', type: 'agent', label: 'Planner', role: 'planner', position: { x: 100, y: 150 } },
    { id: 'agent-2', type: 'agent', label: 'Coder', role: 'worker', position: { x: 360, y: 150 } },
    { id: 'agent-3', type: 'agent', label: 'Reviewer', role: 'finaliser', position: { x: 620, y: 150 } },
    { id: 'mem-1', type: 'memory', label: 'Shared Memory', backend: 'vector', position: { x: 360, y: 330 } },
    { id: 'tool-1', type: 'tool', label: 'Search Tool', spec: 'def search(q: str) -> str', position: { x: 360, y: -30 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-2', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'mem-1', target: 'agent-2', kind: 'attach' },
    { id: 'edge-4', source: 'tool-1', target: 'agent-2', kind: 'attach' },
  ],
  entry: 'agent-1', exit: 'agent-3',
})

const FANOUT = mas({
  name: 'planner-workers-aggregator',
  task: 'Research a topic and produce a concise summary.',
  entrancePos: { x: -120, y: 180 }, exitPos: { x: 900, y: 180 },
  inner: [
    { id: 'agent-1', type: 'agent', label: 'Planner', role: 'planner', position: { x: 100, y: 170 } },
    { id: 'agent-2', type: 'agent', label: 'Worker A', role: 'worker', position: { x: 380, y: 50 } },
    { id: 'agent-3', type: 'agent', label: 'Worker B', role: 'worker', position: { x: 380, y: 300 } },
    { id: 'agent-4', type: 'agent', label: 'Aggregator', role: 'finaliser', position: { x: 660, y: 170 } },
    { id: 'tool-1', type: 'tool', label: 'Web Tool', spec: 'def fetch(url: str) -> str', position: { x: 380, y: -130 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-1', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'agent-2', target: 'agent-4', kind: 'channel' },
    { id: 'edge-4', source: 'agent-3', target: 'agent-4', kind: 'channel' },
    { id: 'edge-5', source: 'tool-1', target: 'agent-2', kind: 'attach' },
  ],
  entry: 'agent-1', exit: 'agent-4',
})

const REFLECTION = mas({
  name: 'reflection',
  task: 'Draft and refine a short blog post.',
  entrancePos: { x: -120, y: 160 }, exitPos: { x: 860, y: 160 },
  inner: [
    { id: 'agent-1', type: 'agent', label: 'Generator', role: 'drafter', position: { x: 100, y: 150 } },
    { id: 'agent-2', type: 'agent', label: 'Critic', role: 'reviewer', position: { x: 360, y: 150 } },
    { id: 'agent-3', type: 'agent', label: 'Finaliser', role: 'finaliser', position: { x: 620, y: 150 } },
    { id: 'mem-1', type: 'memory', label: 'Draft Store', backend: 'kv', position: { x: 360, y: 330 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-2', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'mem-1', target: 'agent-1', kind: 'attach' },
    { id: 'edge-4', source: 'mem-1', target: 'agent-2', kind: 'attach' },
  ],
  entry: 'agent-1', exit: 'agent-3',
})

const ROUTER = mas({
  name: 'router-specialists',
  task: 'Handle a mixed request that may need code or math.',
  entrancePos: { x: -120, y: 200 }, exitPos: { x: 900, y: 200 },
  inner: [
    { id: 'agent-1', type: 'agent', label: 'Router', role: 'router', position: { x: 100, y: 190 } },
    { id: 'agent-2', type: 'agent', label: 'Code Specialist', role: 'coder', position: { x: 380, y: 70 } },
    { id: 'agent-3', type: 'agent', label: 'Math Specialist', role: 'mathematician', position: { x: 380, y: 310 } },
    { id: 'agent-4', type: 'agent', label: 'Collector', role: 'finaliser', position: { x: 660, y: 190 } },
    { id: 'tool-1', type: 'tool', label: 'Python REPL', spec: 'def run(code: str) -> str', position: { x: 380, y: -70 } },
    { id: 'tool-2', type: 'tool', label: 'Calculator', spec: 'def calc(expr: str) -> str', position: { x: 380, y: 470 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'agent-1', target: 'agent-3', kind: 'channel' },
    { id: 'edge-3', source: 'agent-2', target: 'agent-4', kind: 'channel' },
    { id: 'edge-4', source: 'agent-3', target: 'agent-4', kind: 'channel' },
    { id: 'edge-5', source: 'tool-1', target: 'agent-2', kind: 'attach' },
    { id: 'edge-6', source: 'tool-2', target: 'agent-3', kind: 'attach' },
  ],
  entry: 'agent-1', exit: 'agent-4',
})

const RAG = mas({
  name: 'rag-pipeline',
  task: 'Answer a question using the knowledge base.',
  entrancePos: { x: -120, y: 160 }, exitPos: { x: 600, y: 160 },
  inner: [
    { id: 'agent-1', type: 'agent', label: 'Retriever', role: 'retriever', position: { x: 100, y: 150 } },
    { id: 'agent-2', type: 'agent', label: 'Answerer', role: 'finaliser', position: { x: 360, y: 150 } },
    { id: 'mem-1', type: 'memory', label: 'Knowledge Base', backend: 'vector', position: { x: 100, y: 330 } },
  ],
  edges: [
    { id: 'edge-1', source: 'agent-1', target: 'agent-2', kind: 'channel' },
    { id: 'edge-2', source: 'mem-1', target: 'agent-1', kind: 'attach' },
  ],
  entry: 'agent-1', exit: 'agent-2',
})

const HIERARCHY = mas({
  name: 'supervisor-hierarchy',
  task: 'Plan and execute a multi-step task.',
  entrancePos: { x: 60, y: 60 }, exitPos: { x: 660, y: 60 },
  inner: [
    { id: 'agent-1', type: 'agent', label: 'Supervisor', role: 'supervisor', position: { x: 360, y: 60 } },
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
  entry: 'agent-1', exit: 'agent-1',
})

export const TEMPLATES = [
  { id: 'starter', label: 'Starter (entrance → exit)', arch: STARTER },
  { id: 'single-agent', label: 'Single agent', arch: SOLO },
  { id: 'linear-pipeline', label: 'Linear pipeline', arch: LINEAR },
  { id: 'planner-workers-aggregator', label: 'Planner / workers / aggregator', arch: FANOUT },
  { id: 'reflection', label: 'Reflection (generator → critic)', arch: REFLECTION },
  { id: 'router-specialists', label: 'Router → specialists', arch: ROUTER },
  { id: 'rag-pipeline', label: 'RAG (retriever + knowledge base)', arch: RAG },
  { id: 'supervisor-hierarchy', label: 'Supervisor hierarchy', arch: HIERARCHY },
]

export const DEFAULT_TEMPLATE = LINEAR
