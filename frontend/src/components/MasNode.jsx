import { Handle, Position } from 'reactflow'
import { NODE_TYPES } from '../lib/elements.js'

// A single canvas element (agent / memory / tool). When flagged malicious it is
// rendered loudly: red hazard border, pulsing glow, ☠ badge and attack label.
export default function MasNode({ data, selected }) {
  const def = NODE_TYPES[data.type] || {}
  const evil = data.malicious?.enabled
  const cls = ['mas-node', `mas-${data.type}`]
  if (evil) cls.push('mas-evil')
  if (selected) cls.push('mas-selected')

  return (
    <div className={cls.join(' ')} style={{ '--node-color': def.color }}>
      <Handle type="target" position={Position.Left} className="mas-handle" />

      {data.entry && <div className="mas-entry-tag">▶ ENTRANCE</div>}
      {data.exit && <div className="mas-exit-tag">EXIT ⏹</div>}
      {evil && <div className="mas-evil-badge" title={data.malicious.attack}>☠</div>}

      <div className="mas-node-head">
        <span className="mas-icon">{def.icon}</span>
        <span className="mas-title">{data.label || def.label}</span>
      </div>
      <div className="mas-node-sub">
        {data.type === 'agent' && <span>{data.model || data._providerName || 'mock'}</span>}
        {data.type === 'memory' && <span>{data.backend || 'in-memory'}</span>}
        {data.type === 'tool' && <span>tool</span>}
      </div>
      {data.type === 'agent' && data.role && <div className="mas-node-role">{data.role}</div>}

      {evil && <div className="mas-evil-label">⚠ {def.attackLabel}</div>}

      <Handle type="source" position={Position.Right} className="mas-handle" />
    </div>
  )
}
