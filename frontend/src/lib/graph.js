// Convert between the React Flow graph (nodes/edges with `data`) and the
// Architecture object the backend persists as YAML. The architecture *is* the
// document — this is just (de)serialisation.
import { MarkerType } from 'reactflow'
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
      join: n.data.join ?? null,
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
      loop: !!e.data?.loop,
      when: e.data?.when || '',
      max_iters: e.data?.max_iters ?? null,
      until: e.data?.until || '',
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
      join: n.join ?? null,
      backend: n.backend,
      spec: n.spec,
      malicious: n.malicious || blankMalicious(),
    },
  }))
  const edges = (arch.edges || []).map((e) => decorateEdge({
    id: e.id,
    source: e.source,
    target: e.target,
    data: {
      kind: e.kind || 'channel', label: e.label || '', loop: !!e.loop,
      when: e.when || '', max_iters: e.max_iters ?? null, until: e.until || '',
      malicious: e.malicious || blankMalicious(),
    },
  }))
  return { name: arch.name, task: arch.task, nodes, edges }
}

// Edge colours, kept in one place so the canvas and the legend agree.
const EDGE_COLORS = {
  evil: '#ef4444',   // AiTM / malicious
  loop: '#f59e0b',   // feedback / iteration (amber)
  io: '#22d3ee',     // entrance -> agent / agent -> exit
  channel: '#64748b',// agent -> agent information flow
  attach: '#475569', // memory / tool -> agent (attachment, not flow)
}

// Style an edge from its kind + flags. Directional edges (channel/io/loop) get
// an arrowhead so information-flow direction is unambiguous; loops are amber,
// animated and ↺-labelled so feedback paths are obvious; attachments stay dashed
// with no arrowhead because they wire a resource to an agent rather than carry
// pipeline flow.
export function decorateEdge(edge) {
  const m = edge.data?.malicious
  const kind = edge.data?.kind || 'channel'
  const loop = !!edge.data?.loop && kind === 'channel'
  const evil = m?.enabled
  const baseLabel = edge.data?.label || ''

  const color = evil
    ? EDGE_COLORS.evil
    : loop
      ? EDGE_COLORS.loop
      : EDGE_COLORS[kind] || EDGE_COLORS.channel

  // attachments are not flow → no arrowhead; everything else points where it flows.
  const directional = kind !== 'attach'
  // Build a control-flow-aware label: a `[guard]` prefix for conditional
  // (router) edges, and the bound/stop for loops — so the canvas reads like the
  // execution (cf. xstate transition labels).
  const guard = edge.data?.when || ''
  let label
  if (evil) {
    label = '☠ AiTM'
  } else if (loop) {
    const until = edge.data?.until
    const cap = edge.data?.max_iters
    const tail = until ? `until “${until}”` : `×${cap ?? 3}`
    label = `↺ ${baseLabel || 'loop'} ${tail}`
  } else {
    label = baseLabel
  }
  if (guard && !evil) label = `[${guard}] ${label}`.trim()

  return {
    ...edge,
    // attachments float border-to-border (see FloatingEdge); flow edges stay
    // orthogonal left→right.
    type: kind === 'attach' ? 'floatingAttach' : 'smoothstep',
    animated: evil || loop,
    label,
    labelStyle: { fill: evil ? EDGE_COLORS.evil : loop ? EDGE_COLORS.loop : '#94a3b8', fontWeight: 700, fontSize: 11 },
    labelBgStyle: { fill: evil ? '#2a0a0a' : loop ? '#2a1c05' : '#1e293b' },
    labelBgPadding: [4, 2],
    labelBgBorderRadius: 4,
    markerEnd: directional
      ? { type: MarkerType.ArrowClosed, color, width: 18, height: 18 }
      : undefined,
    style: {
      stroke: color,
      strokeWidth: evil ? 2.5 : loop ? 2 : kind === 'io' ? 2 : 1.5,
      strokeDasharray: kind === 'attach' ? '4 4' : loop ? '6 3' : undefined,
    },
  }
}
