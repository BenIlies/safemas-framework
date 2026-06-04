import { useEffect, useRef, useState } from 'react'

// Bottom drawer showing the Docker run output. ANSI colours from the runner are
// stripped and re-styled; [ATTACK] lines are highlighted red. The drawer folds
// down to just its header bar (it does not close) and its expanded height is
// drag-resizable from the top edge. It starts folded on each new run.
const MIN_H = 120
const MAX_H = () => Math.max(MIN_H, window.innerHeight - 160)
const DEFAULT_H = 260

export default function RunConsole({ run, onAnalyze }) {
  const [collapsed, setCollapsed] = useState(true)
  const [height, setHeight] = useState(DEFAULT_H)
  const drag = useRef(null)

  // Re-fold whenever a new run begins.
  useEffect(() => { if (run) setCollapsed(true) }, [run?.run_id])

  useEffect(() => {
    const onMove = (e) => {
      if (!drag.current) return
      const delta = drag.current.startY - e.clientY     // drag up → taller
      const next = Math.min(MAX_H(), Math.max(MIN_H, drag.current.startH + delta))
      setHeight(next)
    }
    const onUp = () => {
      if (drag.current) document.body.style.cursor = ''
      drag.current = null
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
  }, [])

  const lines = (run?.log || '').replace(/\033\[[0-9;]*m/g, '').split('\n')

  const startDrag = (e) => {
    if (collapsed) return
    e.preventDefault()
    drag.current = { startY: e.clientY, startH: height }
    document.body.style.cursor = 'ns-resize'
  }

  return (
    <div className="console" style={{ height: collapsed ? undefined : height }}>
      {!collapsed && <div className="console-resize" onMouseDown={startDrag} title="Drag to resize" />}
      <div className="console-head">
        <button
          className="console-fold"
          onClick={() => setCollapsed((c) => !c)}
          title={collapsed ? 'Expand console' : 'Fold console'}
        >
          {collapsed ? '▴' : '▾'}
        </button>
        <span>
          {run ? (
            <>
              ▶ Run <code>{run.run_id}</code> — <b className={`status-${run.status}`}>{run.status}</b>
              {run.result && (
                <span className="console-summary">
                  {run.result.attack_count > 0
                    ? ` · ☠ ${run.result.attack_count} attack(s) fired`
                    : ' · no attacks triggered'}
                </span>
              )}
            </>
          ) : (
            <span className="console-summary">▶ Console — no run yet</span>
          )}
        </span>
        {run?.has_scn && onAnalyze && (
          <button className="btn small console-pcap" title="Step through this run's recorded trace"
            onClick={() => onAnalyze(run.run_id)}>
            🔬 Open trace
          </button>
        )}
      </div>
      {!collapsed && (
        <pre className="console-body">
          {!run && <div className="console-summary">Run an architecture to see output here.</div>}
          {run && lines.map((l, i) => (
            <div key={i} className={l.includes('[ATTACK]') ? 'log-attack' : l.includes('final answer') ? 'log-final' : ''}>
              {l || ' '}
            </div>
          ))}
        </pre>
      )}
    </div>
  )
}
