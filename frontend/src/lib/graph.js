// Convert between the React Flow graph (nodes/edges with `data`) and the
// Architecture object the backend persists as YAML. The architecture *is* the
// document — this is just (de)serialisation.
import { blankMalicious, NODE_TYPES } from './elements.js'

export function graphToArch({ name, task, nodes, edges }) {
  return {
    name: name || 'untitled-mas',
    version: 1,
    task: task || 'Solve the assigned task.',
    nodes: nodes.map((n) => ({
      id: n.id,
      type: n.data.type,
      label: n.data.label || '',
      position: { x: Math.round(n.position.x), y: Math.round(n.position.y) },
      provider: n.data.provider ?? null,
      model: n.data.model ?? null,
      role: n.data.role ?? null,
      prompt: n.data.prompt ?? null,
      temperature: n.data.temperature ?? null,
      max_tokens: n.data.max_tokens ?? null,
      entry: !!n.data.entry,
      exit: !!n.data.exit,
      backend: n.data.backend ?? null,
      spec: n.data.spec ?? null,
      malicious: n.data.malicious || blankMalicious(),
    })),
    edges: edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      kind: e.data?.kind || 'channel',
      label: e.data?.label || '',
      malicious: e.data?.malicious || blankMalicious(),
    })),
  }
}

export function archToGraph(arch) {
  const nodes = (arch.nodes || []).map((n) => ({
    id: n.id,
    type: 'masNode',
    position: n.position || { x: 0, y: 0 },
    data: {
      type: n.type,
      label: n.label || NODE_TYPES[n.type]?.label || n.type,
      provider: n.provider ?? null,
      model: n.model,
      role: n.role,
      prompt: n.prompt,
      temperature: n.temperature ?? null,
      max_tokens: n.max_tokens ?? null,
      entry: !!n.entry,
      exit: !!n.exit,
      backend: n.backend,
      spec: n.spec,
      malicious: n.malicious || blankMalicious(),
    },
  }))
  const edges = (arch.edges || []).map((e) => decorateEdge({
    id: e.id,
    source: e.source,
    target: e.target,
    data: { kind: e.kind || 'channel', label: e.label || '', malicious: e.malicious || blankMalicious() },
  }))
  return { name: arch.name, task: arch.task, nodes, edges }
}

// Style an edge based on kind + malicious flag.
export function decorateEdge(edge) {
  const m = edge.data?.malicious
  const kind = edge.data?.kind || 'channel'
  const evil = m?.enabled
  return {
    ...edge,
    type: 'smoothstep',
    animated: evil,
    label: evil ? '☠ AiTM' : edge.data?.label || (kind === 'attach' ? '' : ''),
    labelStyle: { fill: evil ? '#ef4444' : '#94a3b8', fontWeight: 700, fontSize: 11 },
    labelBgStyle: { fill: evil ? '#2a0a0a' : '#1e293b' },
    style: {
      stroke: evil ? '#ef4444' : kind === 'attach' ? '#475569' : '#64748b',
      strokeWidth: evil ? 2.5 : 1.5,
      strokeDasharray: kind === 'attach' ? '4 4' : undefined,
    },
  }
}
