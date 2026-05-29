import { NODE_TYPES, PALETTE_TYPES } from '../lib/elements.js'

// Left rail. Drag an item onto the canvas to add a node (GNS3-style).
// Entrance/exit are structural fixtures and intentionally not listed here.
export default function Palette() {
  const onDragStart = (e, type) => {
    e.dataTransfer.setData('application/safemas-node', type)
    e.dataTransfer.effectAllowed = 'move'
  }

  return (
    <div className="palette">
      <div className="palette-title">Elements</div>
      {PALETTE_TYPES.map((type) => {
        const def = NODE_TYPES[type]
        return (
          <div
            key={type}
            className="palette-item"
            draggable
            onDragStart={(e) => onDragStart(e, type)}
            style={{ '--node-color': def.color }}
          >
            <span className="mas-icon">{def.icon}</span>
            <div>
              <div className="palette-item-label">{def.label}</div>
              <div className="palette-item-hint">can be {def.attackLabel}</div>
            </div>
          </div>
        )
      })}
      <div className="palette-note">
        Drag onto canvas. Wire agent→agent for channels, attach memory/tools to an
        agent. The <b style={{ color: '#38bdf8' }}>▶ entrance</b> and{' '}
        <b style={{ color: '#34d399' }}>⏹ exit</b> link to the agents that receive
        the task and produce the answer.
      </div>
    </div>
  )
}
