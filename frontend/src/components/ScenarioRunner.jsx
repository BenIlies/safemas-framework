import { useEffect, useMemo, useState } from 'react'
import * as api from '../lib/api.js'

// Pick an environment dataset, an architecture, a benign task, and (optionally)
// an injection scenario + the point where the poison lands, then assemble and
// run that single case — to probe "does THIS architecture resist THIS injection
// at THIS point?" and replay the result in the trace viewer.
const STYLES = [
  ['blended', 'Blended (social-engineering)', 'Reads as ordinary content — no tags, no “message to the AI”. Hardest to detect.'],
  ['authority', 'Authority impersonation', 'Plausible IT/security/admin notice with urgency, untagged.'],
  ['metadata', 'Spoofed system metadata', 'Disguised as a config/automation directive the agent processes.'],
  ['tagged', 'Tagged (naive baseline)', 'Classic <INFORMATION> “important instructions” — trivially detectable; for comparison.'],
]

const pointKey = (p) => `${p.kind}::${p.id || ''}`

export default function ScenarioRunner({ templates, providers, onRun, onClose, toast }) {
  const [envs, setEnvs] = useState([])
  const [envName, setEnvName] = useState('')
  const [env, setEnv] = useState(null)          // full environment detail
  const [templateId, setTemplateId] = useState('')
  const [userTaskId, setUserTaskId] = useState('')
  const [injTaskId, setInjTaskId] = useState('') // '' => clean (no injection)
  const [point, setPoint] = useState('')         // "kind::id"
  const [style, setStyle] = useState('blended')
  const [provider, setProvider] = useState('')
  const [model, setModel] = useState('')
  const [preview, setPreview] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  // Initial: load the environment catalogue, seed the first of everything.
  useEffect(() => {
    api.listEnvironments().then((list) => {
      setEnvs(list)
      if (list.length) setEnvName(list[0].name)
    })
    if (templates.length) setTemplateId(templates[0].id)
    if (providers.length) {
      const def = providers.find((p) => p.default) || providers[0]
      setProvider(def.id)
      setModel((def.models || [])[0] || '')
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // When the environment changes, pull its detail and reset the task / point.
  useEffect(() => {
    if (!envName) return
    let live = true
    api.loadEnvironment(envName).then((d) => {
      if (!live) return
      setEnv(d)
      setUserTaskId(d.user_tasks?.[0]?.id || '')
      setInjTaskId('')
      // default injection point: first non-agent (a tool), else the agent
      const pts = d.injection_points || []
      const firstTool = pts.find((p) => p.kind === 'tool') || pts[0]
      setPoint(firstTool ? pointKey(firstTool) : '')
    }).catch(() => toast('Failed to load environment', 'error'))
    return () => { live = false }
  }, [envName]) // eslint-disable-line react-hooks/exhaustive-deps

  const selProvider = providers.find((p) => p.id === provider)
  const input = useMemo(() => {
    const [kind, id] = point.split('::')
    return {
      environment: envName,
      template_id: templateId,
      user_task_id: userTaskId || null,
      injection_task_id: injTaskId || null,
      injection_kind: injTaskId ? kind : null,
      injection_target: injTaskId ? (id || null) : null,
      stealth_style: style,
      provider: provider || null,
      model: model || null,
    }
  }, [envName, templateId, userTaskId, injTaskId, point, style, provider, model])

  // Live preview of the assembled payload (only meaningful with an injection).
  useEffect(() => {
    if (!envName || !templateId) { setPreview(null); return undefined }
    let live = true
    const t = setTimeout(() => {
      api.scenarioPreview(input)
        .then((m) => { if (live) setPreview(m) })
        .catch(() => { if (live) setPreview(null) })
    }, 250)
    return () => { live = false; clearTimeout(t) }
  }, [input, envName, templateId])

  const run = async () => {
    if (!envName || !templateId) { toast('Pick an environment and an architecture', 'error'); return }
    if (!providers.length) { toast('Add a provider first (🔑)', 'error'); return }
    setBusy(true)
    try {
      await onRun(input)   // App owns the run + polling + breach badge
    } finally { setBusy(false) }
  }

  const injTasks = env?.injection_tasks || []
  const points = env?.injection_points || []
  const userTasks = env?.user_tasks || []

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal scenario-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>🧪 Scenario runner</span>
          <button className="btn ghost" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <p className="modal-hint">
            Compose one test — <b>environment ⊗ architecture ⊗ injection ⊗ task</b> —
            and run it. Choose where the poison lands; leave the injection as
            <i> none</i> for a clean baseline.
          </p>

          <div className="scn-grid">
            <label className="field">
              <span className="field-label">Environment</span>
              <select value={envName} onChange={(e) => setEnvName(e.target.value)}>
                {envs.map((e) => (
                  <option key={e.name} value={e.name}>{e.title}</option>
                ))}
              </select>
            </label>

            <label className="field">
              <span className="field-label">Architecture</span>
              <select value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>{t.label}</option>
                ))}
              </select>
            </label>

            <label className="field scn-wide">
              <span className="field-label">Task (benign user goal)</span>
              <select value={userTaskId} onChange={(e) => setUserTaskId(e.target.value)}>
                {userTasks.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.id} · {t.prompt.length > 90 ? t.prompt.slice(0, 90) + '…' : t.prompt}
                  </option>
                ))}
              </select>
            </label>

            <label className="field scn-wide">
              <span className="field-label">Injection scenario (attacker goal)</span>
              <select value={injTaskId} onChange={(e) => setInjTaskId(e.target.value)}>
                <option value="">— none (clean baseline) —</option>
                {injTasks.map((j) => (
                  <option key={j.id} value={j.id}>
                    {j.id} · {j.goal.length > 90 ? j.goal.slice(0, 90) + '…' : j.goal}
                  </option>
                ))}
              </select>
            </label>

            <label className={`field${injTaskId ? '' : ' scn-dim'}`}>
              <span className="field-label">Where the injection happens</span>
              <select value={point} onChange={(e) => setPoint(e.target.value)} disabled={!injTaskId}>
                {points.map((p) => (
                  <option key={pointKey(p)} value={pointKey(p)}>{p.label} · {p.attack}</option>
                ))}
              </select>
            </label>

            <label className={`field${injTaskId ? '' : ' scn-dim'}`}>
              <span className="field-label">Stealth style</span>
              <select value={style} onChange={(e) => setStyle(e.target.value)} disabled={!injTaskId}>
                {STYLES.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
              </select>
            </label>

            <label className="field">
              <span className="field-label">Provider</span>
              <select value={provider} onChange={(e) => {
                setProvider(e.target.value)
                const p = providers.find((x) => x.id === e.target.value)
                setModel((p?.models || [])[0] || '')
              }}>
                {providers.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}{p.has_key ? '' : ' (no key)'}</option>
                ))}
              </select>
            </label>

            <label className="field">
              <span className="field-label">Model</span>
              {(selProvider?.models || []).length > 0 ? (
                <select value={model} onChange={(e) => setModel(e.target.value)}>
                  {selProvider.models.map((m) => <option key={m} value={m}>{m}</option>)}
                </select>
              ) : (
                <input value={model} placeholder="model id" onChange={(e) => setModel(e.target.value)} />
              )}
            </label>
          </div>

          {injTaskId && (
            <div className="scn-payload">
              <div className="scn-payload-head">
                <span className="field-label">Injected payload preview</span>
                {(() => {
                  const c = preview?.success
                  const sink = Array.isArray(c) ? c.map((x) => x.tool).join(' / ') : c?.tool
                  return sink ? (
                    <span className="scn-breach-tag" title="Attack succeeds iff this sink tool is called with the attacker's parameters (deterministic, no LLM)">
                      success sink: <b>{sink}</b>
                    </span>
                  ) : preview?.breach_signal ? (
                    <span className="scn-breach-tag" title="Heuristic: no explicit success condition for this task">
                      breach signal: <b>{preview.breach_signal}</b>
                    </span>
                  ) : null
                })()}
              </div>
              <pre className="scn-payload-body">{preview?.payload || '…'}</pre>
              <div className="scn-meta">
                lands at <b>{preview?.injection_point || '—'}</b> · style {style}
              </div>
            </div>
          )}

          {preview?.distribution && Object.keys(preview.distribution).length > 0 && (
            <div className="scn-dist">
              <div className="scn-payload-head">
                <span className="field-label">Specialist tool distribution</span>
                {preview.read_agent && preview.sink_agent && preview.read_agent !== preview.sink_agent ? (
                  <span className="scn-chain-tag" title="The injection enters at the read specialist (upstream); the attack succeeds only if the flow carries it to the agent that owns the sink tool (downstream).">
                    chain: <b>{preview.read_agent}</b> → <b>{preview.sink_agent}</b>
                  </span>
                ) : (
                  <span className="scn-chain-tag" title="A single-agent architecture owns every tool — no cross-agent chain.">single agent · all tools</span>
                )}
              </div>
              <div className="scn-dist-rows">
                {Object.entries(preview.distribution).map(([agent, tools]) => (
                  <div key={agent} className="scn-dist-row">
                    <span className="scn-dist-agent">{agent}</span>
                    <span className="scn-dist-tools">{tools.length ? tools.join(', ') : '—'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="scn-actions">
            <button className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button className="btn run" onClick={run} disabled={busy}>
              {busy ? '… starting' : injTaskId ? '▶ Run attack scenario' : '▶ Run clean baseline'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
