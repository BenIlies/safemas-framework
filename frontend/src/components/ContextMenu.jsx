import { useEffect, useLayoutEffect, useRef, useState } from 'react'

// A small right-click context menu. Items are plain objects so callers can build
// them inline:
//   { separator: true }
//   { header: 'text' }                              non-clickable section label
//   { icon, label, hint, onClick, danger, disabled }
//   { icon, label, submenu: [ ...items ] }          opens a nested menu on hover
//
// The menu is `position: fixed` at (x, y) and clamps itself into the viewport.
// It closes on outside mousedown, Escape, or after an item is chosen.
export default function ContextMenu({ x, y, items, onClose }) {
  const ref = useRef(null)
  const [pos, setPos] = useState({ x, y })
  const [openSub, setOpenSub] = useState(null)

  // Open submenus to the left when the menu sits in the right half of the screen.
  const openLeft = x > window.innerWidth / 2

  // After mount, measure and nudge fully on-screen.
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    let nx = x
    let ny = y
    if (x + r.width > window.innerWidth) nx = Math.max(4, window.innerWidth - r.width - 4)
    if (y + r.height > window.innerHeight) ny = Math.max(4, window.innerHeight - r.height - 4)
    setPos({ x: nx, y: ny })
  }, [x, y])

  useEffect(() => {
    const onDown = (e) => {
      // Clicks inside the menu, or on a menu-bar button that toggles its own
      // dropdown, are handled by their own onClick — don't auto-close on those.
      if (ref.current && ref.current.contains(e.target)) return
      if (e.target?.closest?.('[data-menu-trigger]')) return
      onClose()
    }
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    // Capture phase: the React Flow pane stops propagation of bubbling mousedowns
    // (it uses them to pan), so a bubble listener would never see clicks on the
    // canvas. Capturing runs first and guarantees the menu closes on any outside click.
    window.addEventListener('mousedown', onDown, true)
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('mousedown', onDown, true)
      window.removeEventListener('keydown', onKey)
    }
  }, [onClose])

  const choose = (item) => {
    if (item.disabled || !item.onClick) return
    item.onClick()
    onClose()
  }

  const renderItems = (list, sub = false) => (
    <div className={`ctx-menu${sub ? ' ctx-sub' : ''}`}>
      {list.map((item, i) => {
        if (item.separator) return <div key={i} className="ctx-sep" />
        if (item.header) return <div key={i} className="ctx-header">{item.header}</div>
        if (item.submenu) {
          const empty = !item.submenu.length
          return (
            <div
              key={i}
              className={`ctx-item${empty ? ' disabled' : ''}`}
              onMouseEnter={() => !sub && setOpenSub(i)}
            >
              {item.icon && <span className="ctx-icon">{item.icon}</span>}
              <span className="ctx-label">{item.label}</span>
              <span className="ctx-arrow">{openLeft ? '‹' : '›'}</span>
              {!sub && openSub === i && !empty && (
                <div className={`ctx-sub-wrap ${openLeft ? 'left' : 'right'}`}>
                  {renderItems(item.submenu, true)}
                </div>
              )}
            </div>
          )
        }
        const cls = ['ctx-item']
        if (item.danger) cls.push('danger')
        if (item.disabled) cls.push('disabled')
        return (
          <div key={i} className={cls.join(' ')} onClick={() => choose(item)}>
            {item.icon && <span className="ctx-icon">{item.icon}</span>}
            <span className="ctx-label">{item.label}</span>
            {item.hint && <span className="ctx-hint">{item.hint}</span>}
          </div>
        )
      })}
    </div>
  )

  return (
    <div
      ref={ref}
      className="ctx-root"
      style={{ left: pos.x, top: pos.y }}
      onContextMenu={(e) => e.preventDefault()}
    >
      {renderItems(items)}
    </div>
  )
}
