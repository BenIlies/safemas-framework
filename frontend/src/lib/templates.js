// The built-in MAS templates now live as SafeMAS DSL Python in `templates/*.py`
// and are served by the backend (GET /api/templates). The editor fetches them;
// they are no longer defined here.
//
// This file keeps only the minimal STARTER graph, used for "New" and as an
// offline fallback if the backend is unreachable. Entrance/exit are structural
// nodes wired to an agent via an "io" edge.

export const STARTER = {
  name: 'untitled-mas',
  version: 1,
  task: 'Solve the assigned task.',
  nodes: [
    { id: 'in-1', type: 'entrance', label: 'Entrance', position: { x: 60, y: 160 } },
    { id: 'agent-1', type: 'agent', label: 'Agent', role: 'assistant', position: { x: 300, y: 150 } },
    { id: 'out-1', type: 'exit', label: 'Exit', position: { x: 560, y: 160 } },
  ],
  edges: [
    { id: 'io-in', source: 'in-1', target: 'agent-1', kind: 'io' },
    { id: 'io-out', source: 'agent-1', target: 'out-1', kind: 'io' },
  ],
}
