import { Handle, Position } from 'reactflow'
import { NODE_TYPES } from '../lib/elements.js'

// A single canvas element. Agents/memory/tools are full nodes; entrance and exit
// are compact structural markers with a single port. Malicious elements render
// loudly: red hazard border, pulsing glow, ☠ badge and attack label.
export default function MasNode({ data, selected }) {
  const def = NODE_TYPES[data.type] || {}

  // Structural flow markers (entrance / exit).
  if (data.type === 'entrance' || data.type === 'exit') {
    const isEntrance = data.type === 'entrance'
    const cls = ['mas-io', `mas-io-${data.type}`]
    if (selected) cls.push('mas-selected')
    return (
      <div className={cls.join(' ')} style={{ '--node-color': def.color }}>
        {!isEntrance && <Handle type="target" position={Position.Left} className="mas-handle" />}
        <span className="mas-icon">{def.icon}</span>
        <span className="mas-io-label">{data.label || def.label}</span>
        {isEntrance && <Handle type="source" position={Position.Right} className="mas-handle" />}
      </div>
    )
  }

  const evil = data.malicious?.enabled
  // Execution-lens hints injected by the editor (see simulateExecution): the
  // 1-based run order, or that the engine never reaches this node.
  const order = typeof data.__order === 'number' ? data.__order : null
  const runs = data.__runs || 0
  const dead = !!data.__dead
  const cls = ['mas-node', `mas-${data.type}`]
  if (evil) cls.push('mas-evil')
  if (dead) cls.push('mas-skipped')
  if (selected) cls.push('mas-selected')

  return (
    <div className={cls.join(' ')} style={{ '--node-color': def.color }}>
      <Handle type="target" position={Position.Left} className="mas-handle" />

      {order !== null && <div className="mas-order" title={`runs #${order}`}>{order}</div>}
      {dead && <div className="mas-order mas-order-skip" title="never executes at runtime">⊘</div>}
      {runs > 1 && <div className="mas-runs" title={`runs ${runs}× (loop)`}>↻{runs}</div>}

      {evil && <div className="mas-evil-badge" title={data.malicious.attack}>☠</div>}

      <div className="mas-node-head">
        <span className="mas-icon">{def.icon}</span>
        <span className="mas-title">{data.label || def.label}</span>
      </div>
      <div className="mas-node-sub">
        {data.type === 'agent' && <span>{data.__model || data.model || 'mock'}</span>}
        {data.type === 'memory' && <span>{data.backend || 'in-memory'}</span>}
        {data.type === 'tool' && <span>tool</span>}
        {data.type === 'agent' && data.join === 'all' && <span className="mas-join" title="waits for all inputs, then aggregates">⋈ join all</span>}
      </div>
      {data.type === 'agent' && data.role && <div className="mas-node-role">{data.role}</div>}

      {evil && <div className="mas-evil-label">⚠ {def.attackLabel}</div>}

      <Handle type="source" position={Position.Right} className="mas-handle" />
    </div>
  )
}
