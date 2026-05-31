import { useCallback } from 'react'
import { useStore, getStraightPath } from 'reactflow'

// A "floating" edge for attachments: it draws straight from the border of the
// resource node to the border of the agent node, picking whichever sides face
// each other. Unlike a fixed left→right handle edge, it never loops around when a
// memory/tool sits directly above or below its agent — so an attachment always
// clearly points at its agent and can't be mistaken for a resource↔resource link.

// Point where the ray from `node`'s centre toward `other`'s centre exits `node`'s
// rectangle (standard centre-to-border intersection).
function borderPoint(node, other) {
  const w = (node.width || 160) / 2
  const h = (node.height || 60) / 2
  const p = node.positionAbsolute || node.position || { x: 0, y: 0 }
  const op = other.positionAbsolute || other.position || { x: 0, y: 0 }
  const cx = p.x + w
  const cy = p.y + h
  const dx = (op.x + (other.width || 160) / 2) - cx
  const dy = (op.y + (other.height || 60) / 2) - cy
  if (dx === 0 && dy === 0) return { x: cx, y: cy }
  const scale = 1 / Math.max(Math.abs(dx) / w, Math.abs(dy) / h)
  return { x: cx + dx * scale, y: cy + dy * scale }
}

export default function FloatingEdge({ id, source, target, markerEnd, style }) {
  const sourceNode = useStore(useCallback((s) => s.nodeInternals.get(source), [source]))
  const targetNode = useStore(useCallback((s) => s.nodeInternals.get(target), [target]))
  if (!sourceNode || !targetNode) return null

  const s = borderPoint(sourceNode, targetNode)
  const t = borderPoint(targetNode, sourceNode)
  const [path] = getStraightPath({ sourceX: s.x, sourceY: s.y, targetX: t.x, targetY: t.y })

  return (
    <>
      <path id={id} className="react-flow__edge-path" d={path} style={style} markerEnd={markerEnd} />
      {/* wider transparent hit area so the thin dashed edge is still clickable */}
      <path d={path} fill="none" stroke="transparent" strokeWidth={12} className="react-flow__edge-interaction" />
    </>
  )
}
