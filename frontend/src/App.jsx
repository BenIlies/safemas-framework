import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ReactFlow, {
  Background, Controls, addEdge,
  useNodesState, useEdgesState, ReactFlowProvider,
} from 'reactflow'
import 'reactflow/dist/style.css'

import MasNode from './components/MasNode.jsx'
import FloatingEdge from './components/FloatingEdge.jsx'
import Inspector from './components/Inspector.jsx'
import RunConsole from './components/RunConsole.jsx'
import ProvidersModal from './components/ProvidersModal.jsx'
import ScenarioRunner from './components/ScenarioRunner.jsx'
import TraceModal, { reconstructArch } from './components/TraceModal.jsx'
import ContextMenu from './components/ContextMenu.jsx'
import Diagnostics from './components/Diagnostics.jsx'
import { simulateExecution } from './lib/simulate.js'
import { NODE_TYPES, EDGE_ATTACK, blankMalicious } from './lib/elements.js'
import { archToGraph, graphToArch, decorateEdge } from './lib/graph.js'
import * as api from './lib/api.js'
import { STARTER } from './lib/templates.js'

const nodeTypes = { masNode: MasNode }
const edgeTypes = { floatingAttach: FloatingEdge }
let idSeq = 1
const nextId = (t) => `${t}-${idSeq++}`

// The menu-bar dropdowns share the ContextMenu component with the right-click
// menus; these kinds mark a menu as a top-bar dropdown (vs. node/edge/pane).
const BAR_KINDS = ['file', 'edit', 'view', 'templates']

// Group the backend's template list by `group`, preserving first-seen order.
function groupTemplates(list) {
  return list.reduce((acc, t) => {
    const g = t.group || 'Templates'
    const bucket = acc.find(([name]) => name === g)
    if (bucket) bucket[1].push(t)
    else acc.push([g, [t]])
    return acc
  }, [])
}

// Mirror backend graph_runtime._build_global_memory: the auto-generated shared
// board (who-does-what + all tools + any shared data) that every agent reads. It
// is inspect-only — regenerated live from the canvas, never user-authored.
function buildGlobalMemory(name, task, nodes, edges = []) {
  const clip = (s, n = 200) => { s = (s || '').replace(/\s+/g, ' ').trim(); return s.length <= n ? s : s.slice(0, n - 1) + '…' }
  const agents = nodes.filter((n) => n.data.type === 'agent')
  const tools = nodes.filter((n) => n.data.type === 'tool')
  const stores = nodes.filter((n) => n.data.type === 'memory' && (n.data.content || '').trim())
  const typeOf = Object.fromEntries(nodes.map((n) => [n.id, n.data.type]))
  const labelOf = Object.fromEntries(nodes.map((n) => [n.id, n.data.label]))
  const ownedBy = {}  // agent id -> [tool labels]
  for (const e of edges) {
    if ((e.data?.kind || e.kind) !== 'attach') continue
    const [tool, agent] = typeOf[e.source] === 'tool' ? [e.source, e.target] : [e.target, e.source]
    if (typeOf[tool] === 'tool' && typeOf[agent] === 'agent') (ownedBy[agent] ||= []).push(labelOf[tool])
  }
  const L = [`# Shared memory — multi-agent system '${name}'`, `Overall task: ${task}`, '', '## Agents (who does what)']
  for (const a of agents) {
    const role = a.data.role ? ` · role: ${a.data.role}` : ''
    const desc = clip(a.data.prompt)
    L.push(`- **${a.data.label}**${role}` + (desc ? ` — ${desc}` : ''))
    if (ownedBy[a.id]?.length) L.push(`    tools it can call: ${ownedBy[a.id].join(', ')}`)
  }
  if (tools.length) {
    L.push('', '## Tools available (whole system)')
    for (const t of tools) L.push(`- \`${t.data.label}\` — ${(t.data.spec || '').trim() || 'no signature'}`)
  }
  if (stores.length) {
    // List data stores by NAME only — their contents are private and reached by
    // calling the relevant tool, not handed to every agent as ambient context.
    L.push('', '## Data stores (private — read with the matching tool, not shown here)')
    for (const s of stores) L.push(`- \`${s.data.label}\``)
  }
  return L.join('\n')
}

// Validate a connection against the SafeMAS wiring rules and return the edge
// `kind` (or an error explaining the refusal). `flip` means the edge should be
// stored in its canonical direction (memory/tool -> agent) regardless of which
// way it was drawn. This is what guarantees memory and tools only ever attach to
// agents — never to each other.
function classifyConnection(s, t) {
  const isResource = (x) => x === 'memory' || x === 'tool'
  if (!s || !t) return { error: 'Unknown node — could not wire that connection.' }
  if (s === t && isResource(s)) {
    return { error: 'Memory and tools attach to an agent, not to each other.' }
  }
  if (t === 'entrance') return { error: 'The entrance is the start of the flow — it takes no inputs.' }
  if (s === 'exit') return { error: 'The exit is the end of the flow — it produces no outputs.' }
  if (s === 'entrance') {
    return t === 'agent' ? { kind: 'io' } : { error: 'The entrance can only feed an agent.' }
  }
  if (t === 'exit') {
    return s === 'agent' ? { kind: 'io' } : { error: 'Only an agent can feed the exit.' }
  }
  if (s === 'agent' && t === 'agent') return { kind: 'channel' }
  if (s === 'agent' && isResource(t)) return { kind: 'attach', flip: true }
  if (isResource(s) && t === 'agent') return { kind: 'attach' }
  if (isResource(s) && isResource(t)) {
    return { error: 'Memory and tools attach to an agent, not to each other.' }
  }
  return { error: 'Unsupported connection.' }
}

// Resolve a desired source→target pair into the edge that should actually be
// stored: classify it, then normalise to the canonical direction (attachments
// are always stored resource→agent regardless of which node was the origin).
function canonicalEdge(sType, tType, sId, tId) {
  const res = classifyConnection(sType, tType)
  if (res.error) return { error: res.error }
  return {
    kind: res.kind,
    source: res.flip ? tId : sId,
    target: res.flip ? sId : tId,
  }
}

// The entrance feeds exactly one agent and the exit collects from exactly one.
// Returns an error message if a (canonical) io edge would add a second.
function ioRuleError(source, target, kind, nodes, edges) {
  if (kind !== 'io') return null
  const typeOf = (id) => nodes.find((n) => n.id === id)?.data.type
  if (typeOf(source) === 'entrance' && edges.some((e) => e.data?.kind === 'io' && e.source === source)) {
    return 'The entrance feeds one agent — re-link it (drag its port to a different agent) instead.'
  }
  if (typeOf(target) === 'exit' && edges.some((e) => e.data?.kind === 'io' && e.target === target)) {
    return 'The exit takes its answer from one agent — re-link it instead.'
  }
  return null
}

function Editor() {
  const wrapper = useRef(null)
  const rf = useRef(null)
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [name, setName] = useState('untitled-mas')
  const [task, setTask] = useState('Solve the assigned task.')
  const [selId, setSelId] = useState(null)
  const [selKind, setSelKind] = useState(null)        // 'node' | 'edge'
  const [menu, setMenu] = useState(null)              // right-click + menu-bar dropdowns: { kind, id?, x, y }
  const [linkFrom, setLinkFrom] = useState(null)      // node id we're drawing a link from
  const [linkCursor, setLinkCursor] = useState(null)  // { x, y } in canvas-local px
  const [run, setRun] = useState(null)
  const [running, setRunning] = useState(false)
  const [codeOpen, setCodeOpen] = useState(false)   // the LangGraph (StateGraph) code panel
  const [code, setCode] = useState('')              // StateGraph source shown / edited in the panel
  const [codeDirty, setCodeDirty] = useState(false) // user is editing code (suspends auto-regen)
  const [codeError, setCodeError] = useState('')    // last "Apply code" / generation error
  const [memOpen, setMemOpen] = useState(false)     // the auto-generated shared-memory panel
  const [execView, setExecView] = useState(false)   // execution lens: run order + diagnostics
  const [saved, setSaved] = useState([])
  const [templates, setTemplates] = useState([])    // built-in templates (from the backend)
  const [providers, setProviders] = useState([])
  const [providersLoaded, setProvidersLoaded] = useState(false)  // first fetch done
  const [providersOpen, setProvidersOpen] = useState(false)
  const [scenarioOpen, setScenarioOpen] = useState(false)  // scenario test runner modal
  const [traceOpen, setTraceOpen] = useState(false)   // scenario-trace modal
  const [traceScn, setTraceScn] = useState(null)      // loaded scenario log (persists across modal open/close)
  const [traceName, setTraceName] = useState('')      // label for the loaded trace
  const [health, setHealth] = useState({ docker: true, sandbox: 'docker' })
  const [toasts, setToasts] = useState([])
  const [history, setHistory] = useState({ undo: 0, redo: 0 })  // depths, for menu enable
  const pollRef = useRef(null)
  const toastSeq = useRef(0)
  const saveRef = useRef(() => {})  // latest doSave, for the Ctrl+S shortcut
  // Undo/redo stacks of {nodes, edges, name, task} + coalescing metadata.
  const hist = useRef({ past: [], future: [], tag: null, t: 0, applying: false })
  const stateRef = useRef({ nodes, edges, name, task })
  const dragStart = useRef(null)  // pre-drag snapshot + position, for move-undo
  const defaultProviderRef = useRef(null)  // provider id new/loaded agents inherit
  const prevProvCount = useRef(0)

  const toast = useCallback((msg, type = 'ok') => {
    const id = ++toastSeq.current
    setToasts((t) => [...t, { id, msg, type }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200)
  }, [])

  const loadArch = useCallback((a) => {
    const g = archToGraph(a)
    // Agents with no provider inherit the default (templates ship provider-less).
    const def = defaultProviderRef.current
    const nodes = def
      ? g.nodes.map((n) => (n.data.type === 'agent' && !n.data.provider
          ? { ...n, data: { ...n.data, provider: def } } : n))
      : g.nodes
    setNodes(nodes); setEdges(g.edges); setName(a.name); setTask(a.task || '')
    setSelId(null); setSelKind(null); setLinkFrom(null)
    setCodeDirty(false); setCodeError('')   // regenerate code from the new arch
    hist.current = { past: [], future: [], tag: null, t: 0, applying: false }
    setHistory({ undo: 0, redo: 0 })
    idSeq = 100
  }, [setNodes, setEdges])

  const refreshSaved = useCallback(() => api.listConfigs().then(setSaved).catch(() => {}), [])
  const refreshProviders = useCallback(() => api.listProviders().then((list) => {
    setProviders(list)
    setProvidersLoaded(true)
    if (!list.length) setProvidersOpen(true)   // force ≥1 provider: prompt when none exist
  }).catch(() => {}), [])

  // Keep the default-provider ref current, and when the first provider is
  // configured, give it to every agent that doesn't have one (the editor's
  // "first provider becomes the default for all agents" behaviour).
  useEffect(() => {
    const def = providers.find((p) => p.default)?.id || null
    defaultProviderRef.current = def
    if (prevProvCount.current === 0 && providers.length > 0 && def) {
      setNodes((ns) => ns.map((n) => (
        n.data.type === 'agent' && !n.data.provider
          ? { ...n, data: { ...n.data, provider: def } } : n
      )))
    }
    prevProvCount.current = providers.length
  }, [providers, setNodes])

  useEffect(() => {
    api.health().then(setHealth).catch(() => {})
    refreshSaved()
    refreshProviders()
    // Templates are served by the backend (each is a SafeMAS DSL .py file); load
    // a sensible default to start, falling back to the offline STARTER graph.
    api.listTemplates().then((list) => {
      setTemplates(list)
      const def = list.find((x) => x.id === 'sas') || list[0]
      if (def) api.loadTemplate(def.id).then(loadArch).catch(() => loadArch(STARTER))
      else loadArch(STARTER)
    }).catch(() => loadArch(STARTER))
  }, [loadArch, refreshSaved, refreshProviders])

  const arch = useMemo(() => graphToArch({ name, task, nodes, edges }), [name, task, nodes, edges])
  // The auto-generated shared-memory board, regenerated live as the arch changes.
  const globalMemory = useMemo(() => buildGlobalMemory(name, task, nodes, edges), [name, task, nodes, edges])

  // How the engine will REALLY run this graph (order, dead edges, diagnostics).
  // Cheap, so always computed; the execution lens decides whether to show it.
  const sim = useMemo(() => simulateExecution(nodes, edges), [nodes, edges])

  // ---- undo / redo ----
  // Mirror the document synchronously so a snapshot can be taken the instant
  // before a mutation, without waiting for a re-render.
  useEffect(() => { stateRef.current = { nodes, edges, name, task } }, [nodes, edges, name, task])

  const applySnapshot = useCallback((s) => {
    hist.current.applying = true
    setNodes(s.nodes); setEdges(s.edges); setName(s.name); setTask(s.task)
    setSelId(null); setSelKind(null)
    setTimeout(() => { hist.current.applying = false }, 0)
  }, [setNodes, setEdges])

  // Snapshot the current document before a change. `tag` coalesces a burst of
  // same-kind edits (e.g. typing in a field) into one undo step.
  const commit = useCallback((tag = null) => {
    const h = hist.current
    if (h.applying) return
    const now = Date.now()
    if (tag && tag === h.tag && now - h.t < 600) { h.t = now; return }
    h.past.push(stateRef.current)
    if (h.past.length > 100) h.past.shift()
    h.future = []
    h.tag = tag; h.t = now
    setHistory({ undo: h.past.length, redo: 0 })
  }, [])

  const undo = useCallback(() => {
    const h = hist.current
    if (!h.past.length) return
    h.future.push(stateRef.current)
    applySnapshot(h.past.pop())
    h.tag = null
    setHistory({ undo: h.past.length, redo: h.future.length })
  }, [applySnapshot])

  const redo = useCallback(() => {
    const h = hist.current
    if (!h.future.length) return
    h.past.push(stateRef.current)
    applySnapshot(h.future.pop())
    h.tag = null
    setHistory({ undo: h.past.length, redo: h.future.length })
  }, [applySnapshot])

  // ---- selection ----
  const selected = useMemo(() => {
    if (selKind === 'node') {
      const n = nodes.find((x) => x.id === selId)
      return n && { kind: 'node', id: n.id, data: n.data }
    }
    if (selKind === 'edge') {
      const e = edges.find((x) => x.id === selId)
      return e && { kind: 'edge', id: e.id, data: e.data }
    }
    return null
  }, [selId, selKind, nodes, edges])

  const updateSelected = useCallback((data) => {
    commit(`prop:${selId}`)
    if (selKind === 'node') {
      setNodes((ns) => ns.map((n) => (n.id === selId ? { ...n, data } : n)))
    } else if (selKind === 'edge') {
      setEdges((es) => es.map((e) => (e.id === selId ? decorateEdge({ ...e, data }) : e)))
    }
  }, [selId, selKind, setNodes, setEdges, commit])

  // ---- delete ----
  const deleteNode = useCallback((id) => {
    const n = nodes.find((x) => x.id === id)
    if (!n) return false
    if (n.data.type === 'entrance' || n.data.type === 'exit') {
      toast(`The ${n.data.type} can’t be deleted — move it or re-link it`, 'error')
      return false
    }
    if (n.data.type === 'agent' && nodes.filter((x) => x.data.type === 'agent').length <= 1) {
      toast('A graph needs at least one agent', 'error')
      return false
    }
    commit('delete')
    setNodes((ns) => ns.filter((x) => x.id !== id))
    setEdges((es) => es.filter((e) => e.source !== id && e.target !== id))
    return true
  }, [nodes, setNodes, setEdges, toast, commit])

  const deleteEdge = useCallback((id) => {
    commit('delete')
    setEdges((es) => es.filter((e) => e.id !== id))
  }, [setEdges, commit])

  const deleteSelected = useCallback(() => {
    if (selKind === 'node') { if (!deleteNode(selId)) return }
    else if (selKind === 'edge') { deleteEdge(selId) }
    else return
    setSelId(null); setSelKind(null)
  }, [selId, selKind, deleteNode, deleteEdge])

  // ---- linking (right-click "Connect to…" → drag a wire to the target) ----
  const cancelLink = useCallback(() => { setLinkFrom(null); setLinkCursor(null) }, [])
  const startLink = useCallback((id) => {
    setMenu(null); setSelId(null); setSelKind(null); setLinkFrom(id); setLinkCursor(null)
  }, [])

  // ---- wiring edges ----
  const onConnect = useCallback((params) => {
    const s = nodes.find((n) => n.id === params.source)?.data.type
    const t = nodes.find((n) => n.id === params.target)?.data.type
    const res = classifyConnection(s, t)
    if (res.error) { toast(res.error, 'error'); return }
    const source = res.flip ? params.target : params.source
    const target = res.flip ? params.source : params.target
    const ioErr = ioRuleError(source, target, res.kind, nodes, edges)
    if (ioErr) { toast(ioErr, 'error'); return }
    const sourceHandle = res.flip ? params.targetHandle : params.sourceHandle
    const targetHandle = res.flip ? params.sourceHandle : params.targetHandle
    commit('connect')
    setEdges((es) => addEdge(
      decorateEdge({
        ...params, source, target, sourceHandle, targetHandle,
        id: nextId('edge'),
        data: { kind: res.kind, label: '', loop: false, malicious: blankMalicious() },
      }),
      es,
    ))
  }, [nodes, edges, setEdges, toast, commit])

  // Wire two nodes by id (the right-click link flow). Resolves the legal kind +
  // canonical direction, refuses illegal pairs and existing duplicates.
  const connect = useCallback((sourceId, targetId) => {
    const sType = nodes.find((n) => n.id === sourceId)?.data.type
    const tType = nodes.find((n) => n.id === targetId)?.data.type
    const res = canonicalEdge(sType, tType, sourceId, targetId)
    if (res.error) { toast(res.error, 'error'); return }
    if (edges.some((e) => e.source === res.source && e.target === res.target)) {
      toast('Those elements are already connected', 'error'); return
    }
    const ioErr = ioRuleError(res.source, res.target, res.kind, nodes, edges)
    if (ioErr) { toast(ioErr, 'error'); return }
    commit('connect')
    setEdges((es) => addEdge(
      decorateEdge({
        source: res.source, target: res.target,
        id: nextId('edge'),
        data: { kind: res.kind, label: '', loop: false, malicious: blankMalicious() },
      }),
      es,
    ))
  }, [nodes, edges, setEdges, toast, commit])

  // Toggle the malicious flag on a node (prompt-injection / poisoning, per type)
  // or an edge (AiTM rewrite). Enabling stamps the element's canonical attack.
  const toggleNodeMalicious = useCallback((id) => {
    commit('attack')
    setNodes((ns) => ns.map((n) => {
      if (n.id !== id) return n
      const def = NODE_TYPES[n.data.type]
      const on = n.data.malicious?.enabled
      const malicious = on ? blankMalicious() : { enabled: true, attack: def.attack, payload: '' }
      return { ...n, data: { ...n.data, malicious } }
    }))
  }, [setNodes, commit])

  const toggleEdgeMalicious = useCallback((id) => {
    commit('attack')
    setEdges((es) => es.map((e) => {
      if (e.id !== id) return e
      const on = e.data?.malicious?.enabled
      const malicious = on ? blankMalicious() : { enabled: true, attack: EDGE_ATTACK.attack, payload: '' }
      return decorateEdge({ ...e, data: { ...e.data, malicious } })
    }))
  }, [setEdges, commit])

  const toggleEdgeLoop = useCallback((id) => {
    commit('loop')
    setEdges((es) => es.map((e) => (
      e.id === id ? decorateEdge({ ...e, data: { ...e.data, loop: !e.data?.loop } }) : e
    )))
  }, [setEdges, commit])

  // ---- adding nodes ----
  const addNodeAt = useCallback((type, clientX, clientY) => {
    if (!NODE_TYPES[type] || !rf.current) return
    const pos = rf.current.screenToFlowPosition({ x: clientX, y: clientY })
    const def = NODE_TYPES[type]
    const id = nextId(type)
    commit('add')
    // A new agent inherits the default provider, so it produces real answers out
    // of the box (rather than silently falling back to the mock).
    const extra = type === 'agent' && defaultProviderRef.current
      ? { provider: defaultProviderRef.current } : {}
    setNodes((ns) => ns.concat({
      id, type: 'masNode', position: pos,
      data: { type, label: def.label, ...def.defaults, ...extra, malicious: blankMalicious() },
    }))
    setSelId(id); setSelKind('node')
  }, [setNodes, commit])

  const addNodeCenter = useCallback((type) => {
    const r = wrapper.current?.getBoundingClientRect()
    addNodeAt(type, r ? r.left + r.width / 2 : 400, r ? r.top + r.height / 2 : 300)
  }, [addNodeAt])

  const onDrop = useCallback((event) => {
    event.preventDefault()
    addNodeAt(event.dataTransfer.getData('application/safemas-node'), event.clientX, event.clientY)
  }, [addNodeAt])
  const onDragOver = useCallback((e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move' }, [])

  // ---- toolbar / menu actions ----
  const doSave = async () => {
    try { await api.saveConfig(name, arch); refreshSaved(); toast(`Saved “${name}”`) }
    catch (e) { toast(e.message || 'Save failed', 'error') }
  }
  saveRef.current = doSave
  const doLoad = async (n) => {
    try { const a = await api.loadConfig(n); loadArch(a); toast(`Loaded “${a.name}”`) }
    catch { toast('Load failed', 'error') }
  }
  const doTemplate = async (id) => {
    try { const a = await api.loadTemplate(id); loadArch(a); toast(`Template: ${a.title || a.name}`) }
    catch { toast('Template load failed', 'error') }
  }
  const doDeleteSaved = async () => {
    if (!confirm(`Delete saved architecture “${name}”?`)) return
    await api.deleteConfig(name); refreshSaved(); toast(`Deleted “${name}”`)
  }
  const doExport = async () => {
    try {
      const text = await api.codeFromArch(arch)
      const url = URL.createObjectURL(new Blob([text], { type: 'text/x-python' }))
      const a = document.createElement('a')
      a.href = url; a.download = `${name}.py`; a.click()
      URL.revokeObjectURL(url)
      toast(`Exported ${name}.py`)
    } catch { toast('Export failed', 'error') }
  }
  // Apply the (possibly hand-edited) StateGraph code to the canvas.
  const applyCode = async () => {
    try {
      const a = await api.codeToArch(code)
      loadArch(a)   // resets codeDirty -> the panel re-syncs to canonical code
      toast('Applied LangGraph code')
    } catch (e) { setCodeError(e.message || 'code is invalid') }
  }
  // A new MAS always starts with one entrance and one exit agent.
  const doNew = () => { loadArch({ ...STARTER, name: 'untitled-mas' }); toast('New MAS — one entrance, one exit') }

  const doRun = async () => {
    if (running) return
    if (!providers.length) {
      toast('Add a provider first (🔑) — use the “Mock (no key)” kind to run keyless', 'error')
      setProvidersOpen(true)
      return
    }
    setRunning(true)
    try {
      const { run_id } = await api.startRun(arch)
      setRun({ run_id, status: 'queued', log: 'starting…' })
      clearInterval(pollRef.current)
      pollRef.current = setInterval(async () => {
        const s = await api.runStatus(run_id)
        setRun(s)
        if (s.status === 'done' || s.status === 'error') { clearInterval(pollRef.current); setRunning(false) }
      }, 700)
    } catch { toast('Run failed to start', 'error'); setRunning(false) }
  }
  useEffect(() => () => clearInterval(pollRef.current), [])

  // After an injected scenario finishes, report the backend's verdict. Security
  // is DETERMINISTIC: the backend checked the injection task's `success` condition
  // (a specific sink tool called with the attacker's parameters) against the
  // trace — no LLM. Task completion (utility) is the only LLM-judged axis.
  const checkBreach = useCallback(async (runId) => {
    try {
      const scn = await api.runScn(runId)
      const success = scn.verdict?.attack_succeeded     // true=breached, false=held, null=unscored
      const cond = scn.verdict?.success_condition
      const tool = Array.isArray(cond) ? cond.map((c) => c.tool).join('/') : cond?.tool
      if (success === true) toast(`☠ BREACHED — sink "${tool || 'tool'}" called with the attacker's parameters`, 'error')
      else if (success === false) toast('✓ Held — the attacker’s sink call never fired')
      const util = scn.judge?.utility
      if (util != null) toast(util ? '⚖ Task judged complete' : '⚖ Task judged NOT complete')
    } catch { /* no scn for this run */ }
  }, [toast])

  // Run an assembled scenario (env ⊗ template ⊗ injection ⊗ task). Reuses the
  // same run state + polling as ▶ Run, then scores the breach on completion.
  const runScenario = useCallback(async (input) => {
    if (!providers.length) { toast('Add a provider first (🔑)', 'error'); setProvidersOpen(true); return }
    let resp
    try { resp = await api.runScenario(input) }
    catch (e) { toast(e.message || 'Scenario failed to start', 'error'); return }
    const { run_id, arch } = resp
    setScenarioOpen(false)
    // Switch the canvas to the architecture actually being run — the template
    // with the environment's tools/memory attached and the injection in place.
    if (arch) { loadArch(arch); toast(`Scenario loaded: ${arch.name}`) }
    setRunning(true)
    setRun({ run_id, status: 'queued', log: 'starting…' })
    clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      const s = await api.runStatus(run_id)
      setRun(s)
      if (s.status === 'done' || s.status === 'error') {
        clearInterval(pollRef.current); setRunning(false)
        if (input.injection_task_id) checkBreach(run_id)
      }
    }, 700)
  }, [providers, toast, checkBreach, loadArch])

  // Pull a finished run's structured scenario log into the trace analyzer. Loading
  // it also mirrors the arch onto the canvas (compromised node flagged) and toasts,
  // matching an in-modal upload; the trace then persists across modal open/close.
  const analyzeRunInTrace = useCallback(async (runId) => {
    try {
      const scn = await api.runScn(runId)
      setTraceScn(scn)
      setTraceName(`run ${runId}`)
      try {
        const arch = reconstructArch(scn)
        loadArch(arch)
        const mal = (scn.compromised || []).map((c) => c.element)
        toast(mal.length ? `Loaded “${arch.name}” — compromised: ${mal.join(', ')}` : `Loaded “${arch.name}” (no compromise)`)
      } catch { /* arch reconstruction is best-effort; the trace still opens */ }
      setTraceOpen(true)
    } catch { toast('No scenario log for this run', 'error') }
  }, [toast, loadArch])

  // Live LangGraph-code panel: generate the StateGraph source from the canvas
  // (debounced). While the user is hand-editing the code (codeDirty), suspend
  // regeneration so their edits aren't clobbered until they Apply.
  useEffect(() => {
    if (!codeOpen || codeDirty) return undefined
    let cancelled = false
    const t = setTimeout(async () => {
      try {
        const c = await api.codeFromArch(arch)
        if (!cancelled) { setCode(c); setCodeError('') }
      } catch {
        if (!cancelled) setCodeError('could not generate code')
      }
    }, 300)
    return () => { cancelled = true; clearTimeout(t) }
  }, [codeOpen, codeDirty, arch])

  // ---- keyboard shortcuts ----
  useEffect(() => {
    const onKey = (e) => {
      const el = document.activeElement
      const typing = el && ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName)
      const mod = e.ctrlKey || e.metaKey
      if (mod && (e.key === 's' || e.key === 'S')) { e.preventDefault(); saveRef.current(); return }
      // Undo/redo apply to the canvas; in a text field, let the browser undo text.
      if (mod && !typing && (e.key === 'z' || e.key === 'Z')) {
        e.preventDefault(); e.shiftKey ? redo() : undo(); return
      }
      if (mod && !typing && (e.key === 'y' || e.key === 'Y')) { e.preventDefault(); redo(); return }
      if (e.key === 'Escape') {
        if (linkFrom) cancelLink()
        else if (menu) setMenu(null)
        else { setSelId(null); setSelKind(null) }
        return
      }
      if (typing) return
      if ((e.key === 'Delete' || e.key === 'Backspace') && selId && !linkFrom) {
        e.preventDefault(); deleteSelected()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [selId, menu, linkFrom, deleteSelected, cancelLink, undo, redo])

  const evilCount = nodes.filter((n) => n.data.malicious?.enabled).length +
    edges.filter((e) => e.data?.malicious?.enabled).length
  const nameIsSaved = saved.some((s) => s.name === name)

  // ---- menus (right-click context menus + top-bar dropdowns) ----
  const onNodeContextMenu = useCallback((e, n) => {
    e.preventDefault()
    if (linkFrom) return
    setMenu({ kind: 'node', id: n.id, x: e.clientX, y: e.clientY })
  }, [linkFrom])
  const onEdgeContextMenu = useCallback((e, ed) => {
    e.preventDefault()
    if (linkFrom) return
    setMenu({ kind: 'edge', id: ed.id, x: e.clientX, y: e.clientY })
  }, [linkFrom])
  const onPaneContextMenu = useCallback((e) => {
    e.preventDefault()
    if (linkFrom) { cancelLink(); return }
    setMenu({ kind: 'pane', id: null, x: e.clientX, y: e.clientY })
  }, [linkFrom, cancelLink])

  // Top-bar menu: click to toggle, hover to switch while one is already open.
  const openBarMenu = useCallback((kind, e) => {
    const r = e.currentTarget.getBoundingClientRect()
    setMenu((m) => (m && m.kind === kind ? null : { kind, x: r.left, y: r.bottom + 4 }))
  }, [])
  const hoverBarMenu = useCallback((kind, e) => {
    const r = e.currentTarget.getBoundingClientRect()
    setMenu((m) => (m && BAR_KINDS.includes(m.kind) && m.kind !== kind ? { kind, x: r.left, y: r.bottom + 4 } : m))
  }, [])

  const menuItems = useMemo(() => {
    if (!menu) return []
    switch (menu.kind) {
      case 'file':
        return [
          { icon: '📄', label: 'New', onClick: doNew },
          { icon: '📂', label: 'Open', submenu: saved.map((s) => ({ label: s.name, onClick: () => doLoad(s.name) })) },
          { icon: '💾', label: 'Save', hint: 'Ctrl S', onClick: doSave },
          ...(nameIsSaved ? [{ icon: '🗑', label: `Delete “${name}”`, danger: true, onClick: doDeleteSaved }] : []),
          { separator: true },
          { icon: '⬇', label: 'Export architecture.py', onClick: doExport },
          { separator: true },
          { icon: '🔑', label: 'Providers…', onClick: () => setProvidersOpen(true) },
        ]
      case 'edit':
        return [
          { icon: '↶', label: 'Undo', hint: 'Ctrl Z', disabled: !history.undo, onClick: undo },
          { icon: '↷', label: 'Redo', hint: 'Ctrl Y', disabled: !history.redo, onClick: redo },
          { separator: true },
          { icon: NODE_TYPES.agent.icon, label: 'Add Agent', onClick: () => addNodeCenter('agent') },
          { icon: NODE_TYPES.tool.icon, label: 'Add Tool', onClick: () => addNodeCenter('tool') },
          { separator: true },
          { icon: '🗑', label: 'Delete selection', danger: !!selId, disabled: !selId, onClick: deleteSelected },
        ]
      case 'view':
        return [
          { icon: '◳', label: execView ? 'Hide execution lens' : 'Show execution lens (run order + diagnostics)', onClick: () => setExecView((v) => !v) },
          { icon: '🧩', label: codeOpen ? 'Hide LangGraph code' : 'Show LangGraph code', onClick: () => setCodeOpen((v) => !v) },
          { icon: '🧠', label: memOpen ? 'Hide shared memory' : 'Show shared memory (auto)', onClick: () => setMemOpen((v) => !v) },
          { icon: '⤢', label: 'Fit view', onClick: () => rf.current?.fitView({ duration: 300 }) },
        ]
      case 'templates':
        return groupTemplates(templates).map(([group, items]) => ({
          label: group,
          submenu: items.map((t) => ({ label: t.label, onClick: () => doTemplate(t.id) })),
        }))
      case 'pane':
        return [
          { header: 'Add element here' },
          { icon: NODE_TYPES.agent.icon, label: 'Agent', onClick: () => addNodeAt('agent', menu.x, menu.y) },
          { icon: NODE_TYPES.tool.icon, label: 'Tool', onClick: () => addNodeAt('tool', menu.x, menu.y) },
          { separator: true },
          { icon: '⤢', label: 'Fit view', onClick: () => rf.current?.fitView({ duration: 300 }) },
        ]
      case 'node': {
        const node = nodes.find((n) => n.id === menu.id)
        if (!node) return []
        const def = NODE_TYPES[node.data.type]
        const structural = node.data.type === 'entrance' || node.data.type === 'exit'
        const on = node.data.malicious?.enabled
        return [
          { header: `${def.icon} ${node.data.label || def.label}` },
          { icon: '🔗', label: 'Connect to…', onClick: () => startLink(node.id) },
          { icon: '✎', label: 'Edit properties', onClick: () => { setSelId(node.id); setSelKind('node') } },
          ...(def.attack ? [{
            icon: '☠', label: on ? 'Clear malicious' : `Mark malicious — ${def.attackLabel}`, danger: !on,
            onClick: () => toggleNodeMalicious(node.id),
          }] : []),
          ...(structural ? [] : [
            { separator: true },
            { icon: '🗑', label: 'Delete', danger: true, onClick: () => { if (deleteNode(node.id) && selId === node.id) { setSelId(null); setSelKind(null) } } },
          ]),
        ]
      }
      case 'edge': {
        const edge = edges.find((e) => e.id === menu.id)
        if (!edge) return []
        const isChannel = (edge.data?.kind || 'channel') === 'channel'
        const on = edge.data?.malicious?.enabled
        return [
          { header: '🔗 Link' },
          ...(isChannel ? [
            { icon: '☠', label: on ? 'Clear AiTM attack' : 'Mark as AiTM attack', danger: !on, onClick: () => toggleEdgeMalicious(edge.id) },
            { icon: '↺', label: edge.data?.loop ? 'Remove feedback loop' : 'Make feedback loop', onClick: () => toggleEdgeLoop(edge.id) },
          ] : []),
          { icon: '✎', label: 'Edit properties', onClick: () => { setSelId(edge.id); setSelKind('edge') } },
          { separator: true },
          { icon: '🗑', label: 'Delete link', danger: true, onClick: () => { deleteEdge(edge.id); if (selId === edge.id) { setSelId(null); setSelKind(null) } } },
        ]
      }
      default: return []
    }
  }, [menu, nodes, edges, saved, templates, history, nameIsSaved, name, selId, codeOpen, memOpen, execView, addNodeAt, addNodeCenter, startLink, undo, redo, toggleNodeMalicious, toggleEdgeMalicious, toggleEdgeLoop, deleteNode, deleteEdge, deleteSelected]) // eslint-disable-line react-hooks/exhaustive-deps

  // ---- node decoration: execution-lens badges + link-mode target highlight ----
  const providersById = useMemo(() => new Map(providers.map((p) => [p.id, p])), [providers])
  const displayNodes = useMemo(() => {
    const srcType = linkFrom ? nodes.find((n) => n.id === linkFrom)?.data.type : null
    return nodes.map((n) => {
      let node = n
      if (n.data.type === 'agent') {
        // Resolve the model the canvas shows: the explicit one if the user set
        // it, else the agent's provider's default model (what it actually runs
        // on). Only truly provider-less agents fall back to "mock".
        const prov = n.data.provider ? providersById.get(n.data.provider) : null
        const data = { ...node.data, __model: n.data.model || prov?.models?.[0] || '' }
        if (execView) {
          data.__order = sim.fireOrder.get(n.id) ?? null
          data.__runs = sim.runCount.get(n.id) ?? 0
          data.__dead = sim.neverFired.has(n.id)
        }
        node = { ...node, data }
      }
      if (linkFrom) {
        if (n.id === linkFrom) return { ...node, className: 'link-source' }
        const res = canonicalEdge(srcType, n.data.type, linkFrom, n.id)
        const ok = !res.error && !edges.some((e) => e.source === res.source && e.target === res.target)
        return { ...node, className: ok ? 'link-valid' : 'link-invalid' }
      }
      return node
    })
  }, [linkFrom, nodes, edges, execView, sim, providersById])

  // Dim the channel edges the engine will skip (visited-pruned) when the lens is on.
  const displayEdges = useMemo(() => {
    if (!execView) return edges
    return edges.map((e) => (
      sim.deadEdges.has(e.id)
        ? { ...e, className: `${e.className || ''} edge-dead`.trim(), animated: false }
        : e
    ))
  }, [edges, execView, sim])

  const selectDiag = useCallback((d) => {
    if (d.nodeId) { setSelId(d.nodeId); setSelKind('node') }
    else if (d.edgeId) { setSelId(d.edgeId); setSelKind('edge') }
  }, [])

  const linkGhost = useMemo(() => {
    if (!linkFrom || !linkCursor || !rf.current || !wrapper.current) return null
    const node = nodes.find((n) => n.id === linkFrom)
    if (!node) return null
    const w = node.width || 160
    const h = node.height || 60
    const pa = node.positionAbsolute || node.position
    const s = rf.current.flowToScreenPosition({ x: pa.x + w, y: pa.y + h / 2 })
    const r = wrapper.current.getBoundingClientRect()
    return { x1: s.x - r.left, y1: s.y - r.top, x2: linkCursor.x, y2: linkCursor.y }
  }, [linkFrom, linkCursor, nodes])

  const onCanvasMouseMove = useCallback((e) => {
    if (!linkFrom || !wrapper.current) return
    const r = wrapper.current.getBoundingClientRect()
    setLinkCursor({ x: e.clientX - r.left, y: e.clientY - r.top })
  }, [linkFrom])

  const onNodeClick = useCallback((_, n) => {
    if (linkFrom) {
      if (n.id !== linkFrom) connect(linkFrom, n.id)
      cancelLink()
      return
    }
    setSelId(n.id); setSelKind('node')
  }, [linkFrom, connect, cancelLink])

  const onPaneClick = useCallback(() => {
    if (linkFrom) { cancelLink(); return }
    setSelId(null); setSelKind(null)
  }, [linkFrom, cancelLink])

  // React Flow fires onNodeDragStart on pointer-down (even for a plain click), so
  // snapshot the pre-drag doc but only push it to history if the node truly moved.
  const onNodeDragStart = useCallback((_, node) => {
    dragStart.current = { snap: stateRef.current, x: node.position.x, y: node.position.y }
  }, [])
  const onNodeDragStop = useCallback((_, node) => {
    const d = dragStart.current
    dragStart.current = null
    if (!d || (node.position.x === d.x && node.position.y === d.y)) return
    const h = hist.current
    h.past.push(d.snap)
    if (h.past.length > 100) h.past.shift()
    h.future = []; h.tag = null
    setHistory({ undo: h.past.length, redo: 0 })
  }, [])

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">🛰️ <b>SafeMAS</b></div>
        <nav className="menubar">
          {[['file', 'File'], ['edit', 'Edit'], ['view', 'View'], ['templates', 'Templates']].map(([kind, label]) => (
            <button
              key={kind}
              data-menu-trigger
              className={`menu-btn${menu?.kind === kind ? ' active' : ''}`}
              onClick={(e) => openBarMenu(kind, e)}
              onMouseEnter={(e) => hoverBarMenu(kind, e)}
            >
              {label}
            </button>
          ))}
        </nav>

        <div className="doc-fields">
          <input className="name-input" value={name} onChange={(e) => setName(e.target.value)} title="Architecture name" />
          <input className="task-input" value={task} onChange={(e) => setTask(e.target.value)} placeholder="task / objective" title="Task given to entry agents" />
        </div>

        {evilCount > 0 && <span className="evil-count">☠ {evilCount} malicious</span>}
        <button
          className={`btn exec-pill${execView ? ' active' : ''}${sim.diagnostics.some((d) => d.level === 'error') ? ' has-error' : ''}`}
          onClick={() => setExecView((v) => !v)}
          title="Execution lens — run order & diagnostics"
        >
          ◳ {sim.diagnostics.length ? `${sim.diagnostics.length} issue${sim.diagnostics.length > 1 ? 's' : ''}` : 'trace'}
        </button>
        <span className={`sandbox-pill sandbox-${health.sandbox}`} title="Execution sandbox">
          {health.sandbox === 'docker' ? '🐳 docker' : '🖥 local'}
        </span>
        <button className="btn" onClick={() => setTraceOpen(true)} title="Step through a recorded run trace: each agent's input/output, the messages between nodes, and any attack. The last loaded trace stays open across visits — use “Upload a new trace” inside to swap it.">
          🔬 Trace
        </button>
        <button className="btn" onClick={() => setScenarioOpen(true)} title="Run a benchmark scenario: pick an environment, architecture, task, and where an injection lands">
          🧪 Scenario
        </button>
        <button className="btn run" onClick={doRun} disabled={running}>
          {running ? '… running' : '▶ Run'}
        </button>
      </header>

      <div className="body">
        <div
          className={`canvas${linkFrom ? ' linking' : ''}`}
          ref={wrapper}
          onDrop={onDrop}
          onDragOver={onDragOver}
          onMouseMove={onCanvasMouseMove}
        >
          <ReactFlow
            nodes={displayNodes}
            edges={displayEdges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            nodesDraggable={!linkFrom}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onInit={(inst) => (rf.current = inst)}
            onNodeClick={onNodeClick}
            onNodeDragStart={onNodeDragStart}
            onNodeDragStop={onNodeDragStop}
            onEdgeClick={(_, e) => { if (!linkFrom) { setSelId(e.id); setSelKind('edge') } }}
            onPaneClick={onPaneClick}
            onMove={() => { if (menu) setMenu(null) }}
            onNodeContextMenu={onNodeContextMenu}
            onEdgeContextMenu={onEdgeContextMenu}
            onPaneContextMenu={onPaneContextMenu}
            deleteKeyCode={null}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#1e293b" gap={20} />
            <Controls />
          </ReactFlow>

          {linkGhost && (
            <svg className="link-ghost">
              <defs>
                <marker id="link-arrow" markerWidth="10" markerHeight="10" refX="7" refY="3" orient="auto">
                  <path d="M0,0 L8,3 L0,6 Z" fill="#38bdf8" />
                </marker>
              </defs>
              <line
                x1={linkGhost.x1} y1={linkGhost.y1} x2={linkGhost.x2} y2={linkGhost.y2}
                stroke="#38bdf8" strokeWidth="2" strokeDasharray="6 4" markerEnd="url(#link-arrow)"
              />
            </svg>
          )}
          {linkFrom && <div className="link-hint">Click a highlighted element to connect · Esc to cancel</div>}

          {nodes.length === 0 && (
            <div className="canvas-empty">Right-click the canvas, or use Edit ▸ Add, to place an element →</div>
          )}
          {codeOpen && (
            <div className="yaml-overlay">
              <div className="yaml-head">
                LangGraph code {codeDirty && <span className="code-dirty">• edited</span>}
                <span className="yaml-head-actions">
                  <button className="btn small accent" onClick={applyCode}>Apply</button>
                  <button className="btn ghost" onClick={() => setCodeOpen(false)}>✕</button>
                </span>
              </div>
              <textarea
                className="code-edit"
                spellCheck={false}
                value={code || ''}
                placeholder="# generating…"
                onChange={(e) => { setCode(e.target.value); setCodeDirty(true); setCodeError('') }}
              />
              {codeError && <div className="code-error">{codeError}</div>}
            </div>
          )}
          {memOpen && (
            <div className="yaml-overlay mem-overlay">
              <div className="yaml-head">
                Shared memory <span className="muted small">· auto · read by every agent</span>
                <span className="yaml-head-actions">
                  <button className="btn ghost" onClick={() => setMemOpen(false)}>✕</button>
                </span>
              </div>
              <textarea className="code-edit" spellCheck={false} readOnly value={globalMemory}
                placeholder="# add agents/tools to populate the shared memory" />
              <div className="mem-note">Auto-generated from the architecture — agents, the whole-system toolset, and any shared data. Every agent reads this; it isn’t editable and can’t be attacked.</div>
            </div>
          )}
          {execView && (
            <Diagnostics items={sim.diagnostics} onSelect={selectDiag} onClose={() => setExecView(false)} />
          )}
        </div>
        {selected && (
          <Inspector
            selected={selected}
            providers={providers}
            onChange={updateSelected}
            onDelete={deleteSelected}
            onManageProviders={() => setProvidersOpen(true)}
          />
        )}
      </div>

      <RunConsole run={run} onAnalyze={analyzeRunInTrace} />

      {(providersOpen || (providersLoaded && providers.length === 0)) && (
        <ProvidersModal
          providers={providers}
          onSaved={refreshProviders}
          onClose={() => setProvidersOpen(false)}
          toast={toast}
        />
      )}

      {scenarioOpen && (
        <ScenarioRunner
          templates={templates}
          providers={providers}
          onRun={runScenario}
          onClose={() => setScenarioOpen(false)}
          toast={toast}
        />
      )}


      {traceOpen && (
        <TraceModal onLoadArch={loadArch} onClose={() => setTraceOpen(false)} toast={toast}
          scn={traceScn} fileName={traceName}
          onLoaded={(data, name) => { setTraceScn(data); setTraceName(name) }}
          onClear={() => { setTraceScn(null); setTraceName('') }} />
      )}

      {menu && menuItems.length > 0 && (
        <ContextMenu x={menu.x} y={menu.y} items={menuItems} onClose={() => setMenu(null)} />
      )}

      <div className="toasts">
        {toasts.map((t) => <div key={t.id} className={`toast toast-${t.type}`}>{t.msg}</div>)}
      </div>
    </div>
  )
}

export default function App() {
  return (
    <ReactFlowProvider>
      <Editor />
    </ReactFlowProvider>
  )
}
