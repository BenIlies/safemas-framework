import { NODE_TYPES } from '../lib/elements.js'

// Left rail. Drag an item onto the canvas to add a node (GNS3-style).
export default function Palette() {
  const onDragStart = (e, type) => {
    e.dataTransfer.setData('application/safemas-node', type)
    e.dataTransfer.effectAllowed = 'move'
  }

  return (
    <div className="palette">
      <div className="palette-title">Elements</div>
      {Object.entries(NODE_TYPES).map(([type, def]) => (
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
      ))}
      <div className="palette-note">
        Drag onto canvas. Connect node ports to wire channels (agent→agent) or
        attach memory/tools to an agent.
      </div>
    </div>
  )
}
