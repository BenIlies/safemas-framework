// Bottom drawer showing the Docker run output. ANSI colours from the runner are
// stripped and re-styled; [ATTACK] lines are highlighted red.
export default function RunConsole({ run, onClose }) {
  if (!run) return null
  const lines = (run.log || '').replace(/\033\[[0-9;]*m/g, '').split('\n')

  return (
    <div className="console">
      <div className="console-head">
        <span>
          ▶ Run <code>{run.run_id}</code> — <b className={`status-${run.status}`}>{run.status}</b>
          {run.result && (
            <span className="console-summary">
              {run.result.attack_count > 0
                ? ` · ☠ ${run.result.attack_count} attack(s) fired`
                : ' · no attacks triggered'}
            </span>
          )}
        </span>
        <button className="btn ghost" onClick={onClose}>✕</button>
      </div>
      <pre className="console-body">
        {lines.map((l, i) => (
          <div key={i} className={l.includes('[ATTACK]') ? 'log-attack' : l.includes('final answer') ? 'log-final' : ''}>
            {l || ' '}
          </div>
        ))}
      </pre>
    </div>
  )
}
