import { useEffect, useRef, useState } from 'react'

// PCAP log analyzer. Upload a sa_bridge scenario log (scn_*.json) produced offline;
// the analyzer detects the architecture and which node (if any) is compromised, loads
// the architecture onto the editor canvas (compromised node flagged), and shows the
// information flow plus what happened inside each node. No execution happens here.

const clip = (s, n = 240) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim()
  return t.length <= n ? t : t.slice(0, n - 1) + '…'
}

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

  return { name: (scn.config && scn.config.arch) || 'detected-arch', version: 1, task: (runStart.task) || '', nodes, edges }
}

export default function PcapModal({ onLoadArch, onClose, toast }) {
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

  const ingest = (text, name) => {
    setError('')
    let data
    try { data = JSON.parse(text) } catch { setError('Not valid JSON. Upload a sa_bridge scenario log (scn_*.json).'); return }
    if (!data || !data.trace || !Array.isArray(data.trace.events)) {
      setError('This file has no trace.events — expected a sa_bridge scenario log (scn_*.json).'); return
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

  const onFile = (file) => {
    if (!file) return
    const r = new FileReader()
    r.onload = () => ingest(String(r.result), file.name)
    r.readAsText(file)
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal pcap-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>🔬 PCAP — log analyzer</span>
          <button className="btn ghost" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <p className="modal-hint">
            Upload a SafeMAS scenario log (a <code>scn_*.json</code> produced by sa_bridge
            scenario capture). The analyzer detects the architecture and which node is
            compromised, loads it onto the canvas, and shows the information flow inside each node.
          </p>

          <div
            className={`pcap-drop${dragOver ? ' over' : ''}`}
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => { e.preventDefault(); setDragOver(false); onFile(e.dataTransfer.files?.[0]) }}
          >
            <input ref={inputRef} type="file" accept=".json,application/json" hidden
              onChange={(e) => onFile(e.target.files?.[0])} />
            <div className="pcap-drop-icon">📂</div>
            <div>{fileName ? <b>{fileName}</b> : 'Drop a scn_*.json here, or click to choose'}</div>
          </div>

          {error && <div className="pcap-error">⚠ {error}</div>}

          {scn && (
            <>
              <button className="btn small" onClick={() => onLoadArch(reconstructArch(scn))}>↻ Reload architecture onto canvas</button>
              <PcapResult scn={scn} />
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ---- rendered trace ------------------------------------------------------
function PcapResult({ scn }) {
  const cfg = scn.config || {}
  const v = scn.verdict || {}
  const mal = scn.compromised || []
  const events = scn.trace?.events || []
  const held = v.attack_succeeded === false
  const breached = v.attack_succeeded === true

  return (
    <div className="pcap-result">
      <div className="pcap-summary">
        <div><b>{cfg.arch}</b> · {cfg.user_task}{cfg.injection_task ? ` × ${cfg.injection_task}` : ''} · <span className="tag">{cfg.condition || 'clean'}</span>{cfg.poison_mode ? <> <span className="tag">{cfg.poison_mode}</span></> : null}</div>
        {mal.length === 0
          ? <div className="pcap-goal">✓ no compromised node detected</div>
          : mal.map((c, i) => <div key={i} className="pcap-mal">☠ compromised node: <b>{c.element}</b> ({c.type})</div>)}
        {cfg.injection_goal && <div className="pcap-goal">🎯 attacker goal: {cfg.injection_goal}</div>}
        {v.attack_succeeded != null && (
          <div className={`pcap-verdict ${breached ? 'breached' : held ? 'held' : ''}`}>
            utility (task done): <b>{String(v.utility)}</b> · attack succeeded: <b>{String(v.attack_succeeded)}</b> · {breached ? 'S_safe = 0 (breached)' : 'S_safe = 1 (held)'}
          </div>
        )}
        <div className="pcap-note">Architecture loaded onto the canvas — close this panel to view it (the compromised node is highlighted red).</div>
      </div>

      <div className="pcap-section-title">FLOW — information between nodes (⚠ = attack)</div>
      <div className="pcap-flow">
        {events.map((e) => {
          if (e.kind === 'seed') return <Row key={e.seq} e={e} arrow={`· → ${e.agent}`} kind="seed" info={clip(e.message, 90)} />
          if (e.kind === 'channel') return <Row key={e.seq} e={e} arrow={`${e.src} → ${e.tgt}`} kind={`chan${e.label ? ':' + e.label : ''}`} info={clip(e.message, 90)} evil={e.aitm} />
          if (e.kind === 'tool_call') return <Row key={e.seq} e={e} arrow={`${e.agent} ⟳`} kind={e.poisoned ? 'tool ☠' : e.error ? 'tool ✗' : 'tool'} info={`${e.function}(${clip(e.args, 40)}) → ${clip(e.result, 50)}`} evil={e.poisoned} />
          if (e.kind === 'attack') return <Row key={e.seq} e={e} arrow={`⚠ ${e.element}`} kind={e.type} info={`[${e.vector}] ${clip(e.payload, 70)}`} evil />
          if (e.kind === 'final') return <Row key={e.seq} e={e} arrow={`→ ${(e.exits || []).join(',') || 'exit'}`} kind="FINAL" info={clip(e.answer, 90)} fin />
          return null
        })}
      </div>

      <div className="pcap-section-title">NODE INTERNALS — input, reasoning, tools, output</div>
      <div className="pcap-nodes">
        {groupNodes(events).map((g, i) => (
          <div key={i} className="pcap-node">
            <div className="pcap-node-head">▸ {g.agent} <span className="muted">role={g.role || '-'} · tools={(g.tools || []).length}</span></div>
            <div className="pcap-kv"><span>system</span><div>{clip(g.system, 220)}</div></div>
            <div className="pcap-kv"><span>input</span><div>{clip(g.incoming, 220)}</div></div>
            {g.injected && <div className="pcap-kv evil"><span>⚠ injected</span><div>{clip(g.injected, 220)}</div></div>}
            {g.llm.map((c, j) => (
              <div key={j} className="pcap-llm">
                {c.reasoning && <div className="pcap-kv muted"><span>think</span><div>{clip(c.reasoning, 220)}</div></div>}
                {c.content && <div className="pcap-kv"><span>say</span><div>{clip(c.content, 220)}</div></div>}
                {(c.tool_calls || []).map((tc, k) => <div key={k} className="pcap-kv call"><span>→ call</span><div>{tc.function}({clip(JSON.stringify(tc.args), 80)})</div></div>)}
              </div>
            ))}
            {g.tools_out.map((t, j) => (
              <div key={j} className={`pcap-kv ${t.poisoned ? 'evil' : 'muted'}`}><span>tool{t.poisoned ? ' ☠' : ''}</span><div>{t.function} → {clip(t.result, 160)}</div></div>
            ))}
            <div className="pcap-kv out"><span>out ▸</span><div>{clip(g.output, 220)}</div></div>
          </div>
        ))}
      </div>
    </div>
  )
}

function Row({ e, arrow, kind, info, evil, fin }) {
  return (
    <div className={`pcap-row${evil ? ' evil' : ''}${fin ? ' fin' : ''}`}>
      <span className="pcap-seq">{e.seq}</span>
      <span className="pcap-t">{(e.t ?? 0).toFixed?.(2) ?? e.t}s</span>
      <span className="pcap-arrow">{arrow}</span>
      <span className="pcap-kind">{kind}</span>
      <span className="pcap-info">{info}</span>
    </div>
  )
}

function groupNodes(events) {
  const groups = []
  let cur = null
  for (const e of events) {
    if (e.kind === 'node_enter') {
      cur = { agent: e.agent, role: e.role, system: e.system, incoming: e.incoming, injected: e.injected, tools: e.tools, llm: [], tools_out: [], output: '' }
      groups.push(cur)
    } else if (!cur) {
      continue
    } else if (e.kind === 'llm_call') {
      cur.llm.push({ reasoning: e.reasoning, content: e.content, tool_calls: e.tool_calls })
    } else if (e.kind === 'tool_call') {
      cur.tools_out.push({ function: e.function, result: e.result, poisoned: e.poisoned, error: e.error })
    } else if (e.kind === 'node_exit') {
      cur.output = e.output
    }
  }
  return groups
}
