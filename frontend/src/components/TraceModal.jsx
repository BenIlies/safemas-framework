import { useEffect, useRef, useState } from 'react'
import { Markdown } from '../lib/markdown.jsx'

// Trace walkthrough. Upload a SafeMAS scenario log (scn_*.json) — or open a
// finished run — and step through the trace one event at a time: each agent's input,
// reasoning, tool calls, the messages flowing between nodes, any attack that fired,
// and the final answer, in the order they happened. The architecture is also loaded
// onto the canvas (compromised node flagged). No execution happens here.

// Match safemas.model.slug so we can map a compromised element id back to a node label.
const slug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')

// Reconstruct an editor-format architecture from a scenario log. Prefer the embedded
// `architecture` (full topology + positions + compromise flags, written by newer
// captures); otherwise rebuild a best-effort graph from the trace events.
function reconstructArch(scn) {
  if (scn.architecture && (scn.architecture.nodes || []).length) return scn.architecture

  const events = scn?.trace?.events || []
  const runStart = events.find((e) => e.kind === 'run_start') || {}
  const compromisedIds = new Set((scn.compromised || []).map((c) => c.element))
  const order = []
  const seen = new Set()
  for (const e of events) {
    if (e.kind === 'node_enter' && !seen.has(e.agent)) { seen.add(e.agent); order.push({ label: e.agent, role: e.role }) }
  }
  const entries = new Set(runStart.entries || [])
  const exits = new Set(runStart.exits || [])
  const nodes = [{ id: 'in-1', type: 'entrance', label: 'Entrance', position: { x: -160, y: 160 } }]
  order.forEach((a, i) => {
    const id = slug(a.label)
    nodes.push({
      id, type: 'agent', label: a.label, role: a.role || 'worker',
      position: { x: 80 + i * 220, y: 160 },
      malicious: { enabled: compromisedIds.has(id), attack: 'prompt-injection', payload: '' },
    })
  })
  nodes.push({ id: 'out-1', type: 'exit', label: 'Exit', position: { x: 80 + order.length * 220, y: 160 } })

  const edges = []
  let n = 0
  const eid = () => `e${++n}`
  order.filter((a) => entries.has(a.label)).forEach((a) => edges.push({ id: eid(), source: 'in-1', target: slug(a.label), kind: 'io' }))
  const chSeen = new Set()
  for (const e of events) {
    if (e.kind === 'channel') {
      const key = `${slug(e.src)}->${slug(e.tgt)}`
      if (!chSeen.has(key)) {
        chSeen.add(key)
        edges.push({ id: eid(), source: slug(e.src), target: slug(e.tgt), kind: 'channel', label: e.label || '', malicious: { enabled: compromisedIds.has(key), attack: 'aitm', payload: '' } })
      }
    }
  }
  order.filter((a) => exits.has(a.label)).forEach((a) => edges.push({ id: eid(), source: slug(a.label), target: 'out-1', kind: 'io' }))

  // Resource nodes (tools / memory) + their attach edges. They never appear as
  // node_enter events, so rebuild them from each agent's `tools` list (and infer
  // tool vs memory from the compromise type when flagged).
  const compType = {}
  for (const c of (scn.compromised || [])) compType[c.element] = c.type
  const resSeen = new Set()
  const attachSeen = new Set()
  let ri = 0
  for (const e of events) {
    if (e.kind !== 'node_enter' || !(e.tools || []).length) continue
    const agentId = slug(e.agent)
    for (const tlabel of e.tools) {
      const rid = slug(tlabel)
      const type = compType[rid] === 'memory-poisoning' ? 'memory' : 'tool'
      if (!resSeen.has(rid)) {
        resSeen.add(rid)
        nodes.push({
          id: rid, type, label: tlabel,
          position: { x: 80 + ri * 200, y: 360 },
          malicious: {
            enabled: compromisedIds.has(rid),
            attack: compType[rid] || (type === 'memory' ? 'memory-poisoning' : 'tool-poisoning'),
            payload: '',
          },
        })
        ri++
      }
      const akey = `${rid}->${agentId}`
      if (!attachSeen.has(akey)) {
        attachSeen.add(akey)
        edges.push({ id: eid(), source: rid, target: agentId, kind: 'attach' })
      }
    }
  }

  return { name: (scn.config && scn.config.arch) || 'detected-arch', version: 1, task: (runStart.task) || '', nodes, edges }
}

export default function TraceModal({ onLoadArch, onClose, toast, initialScn, initialName }) {
  const [scn, setScn] = useState(null)
  const [fileName, setFileName] = useState('')
  const [error, setError] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const inputRef = useRef(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const load = (data, name) => {
    setError('')
    if (!data || !data.trace || !Array.isArray(data.trace.events)) {
      setError('This file has no trace.events — expected a SafeMAS scenario log (scn_*.json).'); return
    }
    setFileName(name || 'scenario.json')
    setScn(data)
    try {
      const arch = reconstructArch(data)
      onLoadArch(arch)
      const mal = (data.compromised || []).map((c) => c.element)
      toast(mal.length ? `Loaded “${arch.name}” — compromised: ${mal.join(', ')}` : `Loaded “${arch.name}” (no compromise)`)
    } catch (e) {
      setError(`Could not reconstruct the architecture: ${e.message}`)
    }
  }

  // A scenario log handed in directly (e.g. from a just-finished run).
  useEffect(() => { if (initialScn) load(initialScn, initialName) }, [initialScn])

  const ingest = (text, name) => {
    let data
    try { data = JSON.parse(text) } catch { setError('Not valid JSON. Upload a SafeMAS scenario log (scn_*.json).'); return }
    load(data, name)
  }

  const onFile = (file) => {
    if (!file) return
    const r = new FileReader()
    r.onload = () => ingest(String(r.result), file.name)
    r.readAsText(file)
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal trace-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="trace-head-title">🔬 Trace — step-by-step walkthrough{scn ? <span className="muted"> · {fileName}</span> : null}</span>
          <div className="trace-head-actions">
            {scn && <button className="btn small" onClick={() => { setScn(null); setError('') }}>↑ Load another</button>}
            <button className="btn ghost" onClick={onClose}>✕</button>
          </div>
        </div>

        <div className="modal-body">
          {!scn && (
            <>
              <p className="modal-hint">
                Open a SafeMAS scenario log (a <code>scn_*.json</code>, or a finished run's
                “Open trace”) and step through the trace event-by-event: each agent's
                input, reasoning and output, the messages between nodes, and any attack.
              </p>
              <div
                className={`trace-drop${dragOver ? ' over' : ''}`}
                onClick={() => inputRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => { e.preventDefault(); setDragOver(false); onFile(e.dataTransfer.files?.[0]) }}
              >
                <input ref={inputRef} type="file" accept=".json,application/json" hidden
                  onChange={(e) => onFile(e.target.files?.[0])} />
                <div className="trace-drop-icon">📂</div>
                <div>Drop a scn_*.json here, or click to choose</div>
              </div>
              {error && <div className="trace-error">⚠ {error}</div>}
            </>
          )}

          {scn && (
            <>
              <ScenarioSummary scn={scn} onReload={() => onLoadArch(reconstructArch(scn))} />
              <TracePlayer scn={scn} />
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ---- compact summary -----------------------------------------------------
// Two pills, nothing more: SECURITY (deterministic — did the attacker's success
// condition fire?) and TASK (the LLM utility judge). WHERE the attack happened is
// shown by the trace coloring below, not repeated here.
function ScenarioSummary({ scn, onReload }) {
  const cfg = scn.config || {}
  const v = scn.verdict || {}
  const j = scn.judge || {}
  const attacked = (scn.compromised || []).length > 0

  const success = v.attack_succeeded                    // true=breached, false=held, null=unscored
  const utility = j.utility != null ? j.utility : v.utility
  const reason = j.reasoning || null

  let pill = 'CLEAN · no attack', cls = 'clean'
  if (attacked && success === true) { pill = '✗ BREACHED', cls = 'breached' }
  else if (attacked && success === false) { pill = '✓ HELD', cls = 'held' }
  else if (attacked) { pill = '⚠ unscored', cls = 'clean' }

  return (
    <div className="trace-summary">
      <div className="trace-summary-row">
        <div className="trace-sum-id">
          <b>{cfg.arch}</b>
          {cfg.model ? <span className="muted small">{cfg.model}</span> : null}
        </div>
        <button className="btn small" onClick={onReload}>↻ Reload onto canvas</button>
      </div>

      <div className="trace-verdict-bar">
        <span className={`verdict-pill ${cls}`}>{pill}</span>
        {utility != null &&
          <span className={`chip ${utility ? 'ok' : 'no'}`}>task {utility ? '✓ done' : '✗ failed'}</span>}
      </div>

      {reason && <div className="trace-judge-reason">⚖ {reason}</div>}
    </div>
  )
}

// ---- step model ----------------------------------------------------------
const KIND_META = {
  run_start: { icon: '🚀', label: 'Run started' },
  seed:      { icon: '🌱', label: 'Task seeded' },
  node_enter:{ icon: '▸',  label: 'Agent activated' },
  llm_call:  { icon: '💬', label: 'Agent responds' },
  tool_call: { icon: '🔧', label: 'Tool call' },
  channel:   { icon: '→',  label: 'Message' },
  attack:    { icon: '⚠',  label: 'Attack' },
  node_exit: { icon: '◂',  label: 'Agent output' },
  final:     { icon: '🏁', label: 'Final answer' },
}

function stepHeadline(e) {
  switch (e.kind) {
    case 'seed': return `Task seeded → ${e.agent}`
    case 'node_enter': return `${e.agent} activated`
    case 'llm_call': return `${e.agent} responds`
    case 'tool_call': return `${e.agent} → ${e.function}()`
    case 'channel': return `${e.src} → ${e.tgt}${e.label ? `  (${e.label})` : ''}`
    case 'attack': return `Attack on ${e.element}`
    case 'node_exit': return `${e.agent} output`
    case 'final': return `Final answer → ${(e.exits || []).join(', ') || 'exit'}`
    default: return e.arch ? `Run started — ${e.arch}` : 'Run started'
  }
}

const stepAgent = (e) => e.agent || (e.kind === 'channel' ? `${e.src}→${e.tgt}` : '')

// Does a tool_call event carry out the attacker's goal? It's the breach iff it
// matches the injection task's deterministic `success` condition (the sink tool
// called with the attacker's arguments). Mirrors backend/judge.py: tool name
// exact, each arg a case-insensitive substring; a list of conditions = any-of.
function makeBreachMatcher(scn) {
  let conds = scn.verdict?.success_condition
  if (!conds) return () => false
  conds = (Array.isArray(conds) ? conds : [conds]).filter((c) => c && c.tool)
  return (e) => {
    if (e.kind !== 'tool_call' || !e.function) return false
    return conds.some((c) => {
      if (e.function !== c.tool) return false
      const args = e.args || {}
      return Object.entries(c.args || {}).every(([k, v]) => {
        const exp = String(v).trim().toLowerCase()
        if (!exp) return true
        let act = args[k]
        if (act && typeof act === 'object') act = JSON.stringify(act)
        return String(act ?? '').toLowerCase().includes(exp)
      })
    })
  }
}

// Classify each event so the timeline shows WHERE the attack is, two states only:
//   'breach'  — the actual attack action: a tool call carrying out the attacker's
//               goal (matches the success condition)            → RED.
//   'inject'  — the attack ENTERING: the injected prompt, a poisoned tool result,
//               an AiTM-rewritten message, or the attack event  → YELLOW.
function makeThreat(scn) {
  const isBreach = makeBreachMatcher(scn)
  return (e) => {
    if (isBreach(e)) return 'breach'
    if (e.kind === 'attack' || e.aitm === true || e.poisoned === true || e.injected) return 'inject'
    return null
  }
}

// ---- the player ----------------------------------------------------------
function TracePlayer({ scn }) {
  const events = scn.trace?.events || []
  const threat = makeThreat(scn)
  const attacked = (scn.compromised || []).length > 0
  const [i, setI] = useState(0)
  useEffect(() => { setI(0) }, [scn])

  const go = (n) => setI((cur) => Math.max(0, Math.min(events.length - 1, cur + n)))
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); go(1) }
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); go(-1) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [events.length])

  const railRef = useRef(null)
  useEffect(() => {
    const el = railRef.current?.querySelector('.step-rail-item.active')
    el?.scrollIntoView({ block: 'nearest' })
  }, [i])

  if (!events.length) return <div className="trace-note">This trace has no events.</div>
  const e = events[i]
  const tl = threat(e)
  const meta = KIND_META[e.kind] || { icon: '•', label: e.kind }

  return (
    <>
      {attacked && (
        <div className="trace-legend">
          <span className="lg lg-inject">injection enters</span>
          <span className="lg lg-breach">attack tool call (breach)</span>
        </div>
      )}
      <div className="trace-player">
        <div className="step-rail" ref={railRef}>
          {events.map((ev, idx) => {
            const m = KIND_META[ev.kind] || { icon: '•' }
            const t = threat(ev)
            return (
              <button
                key={ev.seq ?? idx}
                className={`step-rail-item${idx === i ? ' active' : ''}${t ? ' ' + t : ''}`}
                onClick={() => setI(idx)}
              >
                <span className="step-rail-icon">{m.icon}</span>
                <span className="step-rail-text">{stepHeadline(ev)}</span>
                <span className="step-rail-t">{(ev.t ?? 0).toFixed?.(1) ?? ev.t}s</span>
              </button>
            )
          })}
        </div>

        <div className="step-detail">
          <div className={`step-detail-head${tl ? ' ' + tl : ''}`}>
            <span className="step-detail-icon">{meta.icon}</span>
            <div>
              <div className="step-detail-title">{stepHeadline(e)}</div>
              <div className="step-detail-sub">{meta.label} · {(e.t ?? 0).toFixed?.(2) ?? e.t}s</div>
            </div>
          </div>

          <div className="step-detail-body">
            <StepFields e={e} threat={tl} />
          </div>

          <div className="step-nav">
            <button className="btn small" disabled={i === 0} onClick={() => go(-1)}>← Previous</button>
            <span className="step-nav-count">Step {i + 1} / {events.length}</span>
            <button className="btn small" disabled={i === events.length - 1} onClick={() => go(1)}>Next →</button>
          </div>
        </div>
      </div>
    </>
  )
}

// `md` renders the value as Markdown (agent prose: think / say / output / answer /
// messages). Without it the value is shown verbatim in a monospace block — right
// for structured/literal fields (tool args, payloads, ids).
function Field({ label, value, tone, md }) {
  if (value == null || value === '') return null
  return (
    <div className={`step-field${tone ? ' ' + tone : ''}`}>
      <div className="step-field-label">{label}</div>
      {md
        ? <div className="step-field-val md-val"><Markdown text={value} /></div>
        : <pre className="step-field-val">{String(value)}</pre>}
    </div>
  )
}

// Render the right fields for the current event kind. Full text (scrollable),
// not clipped — the whole point is to read what each agent actually said.
function StepFields({ e, threat }) {
  const breach = threat === 'breach'   // the attack action → red (evil tone)
  switch (e.kind) {
    case 'run_start':
      return <>
        <Field label="architecture" value={e.arch} />
        <Field label="task" value={e.task} />
        <Field label="entries" value={(e.entries || []).join(', ')} />
        <Field label="exits" value={(e.exits || []).join(', ')} />
        {(e.compromised || []).length > 0 &&
          <Field label="compromised" tone="evil" value={(e.compromised || []).map((c) => `${c.element} (${c.type})`).join('\n')} />}
      </>
    case 'seed':
      return <Field label="message" md value={e.message} />
    case 'node_enter':
      return <>
        <Field label="role" value={e.role} />
        {(e.tools || []).length > 0 && <Field label="tools" value={(e.tools || []).join(', ')} />}
        <Field label="system" md value={e.system} />
        <Field label="input ◂" md value={e.incoming} />
        <Field label="⚠ injected" tone="warn" md value={e.injected} />
      </>
    case 'llm_call':
      return <>
        <Field label="think" tone="muted" md value={e.reasoning} />
        <Field label="say" tone="out" md value={e.content} />
        {(e.tool_calls || []).length > 0 &&
          <Field label="→ calls" tone="call" value={(e.tool_calls || []).map((t) => `${t.function}(${JSON.stringify(t.args)})`).join('\n')} />}
      </>
    case 'tool_call':
      return <>
        <Field label={breach ? 'function ☠ breach' : 'function'} tone={breach ? 'evil' : null}
          value={`${e.function}(${JSON.stringify(e.args || {})})`} />
        <Field label={e.poisoned ? 'result ⚠ poisoned' : e.error ? 'result ✗' : 'result'}
          tone={e.poisoned ? 'warn' : null} value={e.result} />
        {breach && <Field label="☠ breach" tone="evil"
          value="this tool call carries out the attacker's goal — it matches the success condition" />}
      </>
    case 'channel':
      return <>
        {e.aitm && <Field label="⚠ AiTM" tone="warn" value="message intercepted and rewritten in flight" />}
        {e.aitm && <Field label="original" md value={e.original} />}
        <Field label={e.aitm ? 'rewritten ▸' : 'message ▸'} tone={e.aitm ? 'warn' : 'out'} md value={e.message} />
      </>
    case 'attack':
      return <>
        <Field label="element" tone="warn" value={e.element} />
        <Field label="type" tone="warn" value={e.type} />
        <Field label="vector" value={e.vector} />
        <Field label="payload" tone="warn" value={e.payload} />
      </>
    case 'node_exit':
      return <Field label="output ▸" tone="out" md value={e.output} />
    case 'final':
      return <>
        <Field label="exits" value={(e.exits || []).join(', ')} />
        <Field label="answer" tone="out" md value={e.answer} />
      </>
    default:
      return <Field label={e.kind} value={JSON.stringify(e, null, 2)} />
  }
}
