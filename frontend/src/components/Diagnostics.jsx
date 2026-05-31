// Execution-lens side panel: lists where the drawn graph and the engine's real
// behaviour diverge (loops that don't loop, joins that drop inputs, routers that
// broadcast, unreachable agents). Each row selects the offending element.
export default function Diagnostics({ items, onSelect, onClose }) {
  const counts = items.reduce((a, d) => ((a[d.level] = (a[d.level] || 0) + 1), a), {})
  return (
    <div className="diag-panel">
      <div className="diag-head">
        <span className="diag-title">Execution diagnostics</span>
        <span className="diag-counts">
          {counts.error ? <em className="diag-c-error">{counts.error} ✕</em> : null}
          {counts.warn ? <em className="diag-c-warn">{counts.warn} ⚠</em> : null}
          {counts.info ? <em className="diag-c-info">{counts.info} ℹ</em> : null}
        </span>
        <button className="btn ghost diag-close" onClick={onClose} title="Hide execution lens">✕</button>
      </div>

      {items.length === 0 ? (
        <div className="diag-ok">✓ The graph runs as drawn — no execution surprises.</div>
      ) : (
        <div className="diag-list">
          {items.map((d, i) => (
            <button
              key={i}
              className={`diag-item diag-${d.level}`}
              onClick={() => onSelect(d)}
              title={d.nodeId || d.edgeId ? 'Select this element' : undefined}
            >
              <span className="diag-dot" aria-hidden="true" />
              <span className="diag-msg">{d.msg}</span>
            </button>
          ))}
        </div>
      )}
      <div className="diag-foot">Reflects today’s single-pass engine. Layer 2 will make these constructs real.</div>
    </div>
  )
}
