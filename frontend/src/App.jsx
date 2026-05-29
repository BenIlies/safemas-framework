import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ReactFlow, {
  Background, Controls, MiniMap, addEdge,
  useNodesState, useEdgesState, ReactFlowProvider,
} from 'reactflow'
import 'reactflow/dist/style.css'
import yaml from 'js-yaml'

import MasNode from './components/MasNode.jsx'
import Palette from './components/Palette.jsx'
import Inspector from './components/Inspector.jsx'
import RunConsole from './components/RunConsole.jsx'
import ProvidersModal from './components/ProvidersModal.jsx'
import { NODE_TYPES, blankMalicious } from './lib/elements.js'
import { archToGraph, graphToArch, decorateEdge } from './lib/graph.js'
import * as api from './lib/api.js'
import { TEMPLATES, STARTER, DEFAULT_TEMPLATE } from './lib/templates.js'

const nodeTypes = { masNode: MasNode }
let idSeq = 1
const nextId = (t) => `${t}-${idSeq++}`

function Editor() {
  const wrapper = useRef(null)
  const rf = useRef(null)
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [name, setName] = useState('untitled-mas')
  const [task, setTask] = useState('Solve the assigned task.')
  const [selId, setSelId] = useState(null)
  const [selKind, setSelKind] = useState(null) // 'node' | 'edge'
  const [run, setRun] = useState(null)
  const [running, setRunning] = useState(false)
  const [yamlOpen, setYamlOpen] = useState(false)
  const [saved, setSaved] = useState([])
  const [providers, setProviders] = useState([])
  const [providersOpen, setProvidersOpen] = useState(false)
  const [health, setHealth] = useState({ docker: true, sandbox: 'docker' })
  const [toasts, setToasts] = useState([])
  const pollRef = useRef(null)
  const toastSeq = useRef(0)

  const toast = useCallback((msg, type = 'ok') => {
    const id = ++toastSeq.current
    setToasts((t) => [...t, { id, msg, type }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200)
  }, [])

  // load a clean template on first mount
  const loadArch = useCallback((a) => {
    const g = archToGraph(a)
    setNodes(g.nodes); setEdges(g.edges); setName(a.name); setTask(a.task || '')
    setSelId(null); setSelKind(null)
    idSeq = 100
  }, [setNodes, setEdges])

  useEffect(() => {
    loadArch(DEFAULT_TEMPLATE)
    api.health().then(setHealth).catch(() => {})
    refreshSaved()
    refreshProviders()
  }, [])

  const refreshSaved = () => api.listConfigs().then(setSaved).catch(() => {})
  const refreshProviders = () => api.listProviders().then(setProviders).catch(() => {})

  const arch = useMemo(() => graphToArch({ name, task, nodes, edges }), [name, task, nodes, edges])

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
    if (selKind === 'node') {
      setNodes((ns) => ns.map((n) => (n.id === selId ? { ...n, data } : n)))
    } else if (selKind === 'edge') {
      setEdges((es) => es.map((e) => (e.id === selId ? decorateEdge({ ...e, data }) : e)))
    }
  }, [selId, selKind, setNodes, setEdges])

  const deleteSelected = useCallback(() => {
    if (selKind === 'node') {
      setNodes((ns) => ns.filter((n) => n.id !== selId))
      setEdges((es) => es.filter((e) => e.source !== selId && e.target !== selId))
    } else if (selKind === 'edge') {
      setEdges((es) => es.filter((e) => e.id !== selId))
    }
    setSelId(null); setSelKind(null)
  }, [selId, selKind, setNodes, setEdges])

  // ---- keyboard shortcuts ----
  useEffect(() => {
    const onKey = (e) => {
      const el = document.activeElement
      const typing = el && ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName)
      if (typing) return
      if ((e.key === 'Delete' || e.key === 'Backspace') && selId) { e.preventDefault(); deleteSelected() }
      else if (e.key === 'Escape') { setSelId(null); setSelKind(null) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [selId, deleteSelected])

  // ---- wiring edges ----
  const onConnect = useCallback((params) => {
    const src = nodes.find((n) => n.id === params.source)
    const tgt = nodes.find((n) => n.id === params.target)
    const kind = src?.data.type === 'agent' && tgt?.data.type === 'agent' ? 'channel' : 'attach'
    setEdges((es) => addEdge(
      decorateEdge({ ...params, id: nextId('edge'), data: { kind, label: '', malicious: blankMalicious() } }),
      es,
    ))
  }, [nodes, setEdges])

  // ---- drag from palette ----
  const onDrop = useCallback((event) => {
    event.preventDefault()
    const type = event.dataTransfer.getData('application/safemas-node')
    if (!type || !NODE_TYPES[type]) return
    const pos = rf.current.screenToFlowPosition({ x: event.clientX, y: event.clientY })
    const def = NODE_TYPES[type]
    const id = nextId(type)
    setNodes((ns) => ns.concat({
      id,
      type: 'masNode',
      position: pos,
      data: { type, label: def.label, ...def.defaults, malicious: blankMalicious() },
    }))
    setSelId(id); setSelKind('node')
  }, [setNodes])

  const onDragOver = useCallback((e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move' }, [])

  // ---- toolbar actions ----
  const doSave = async () => {
    try { await api.saveConfig(name, arch); refreshSaved(); toast(`Saved “${name}”`) }
    catch (e) { toast(e.message || 'Save failed', 'error') }
  }
  const doLoad = async (n) => {
    try {
      const a = await api.loadConfig(n)
      loadArch(a)
      toast(`Loaded “${a.name}”`)
    } catch (e) { toast('Load failed', 'error') }
  }
  const doTemplate = (id) => {
    const t = TEMPLATES.find((x) => x.id === id)
    if (t) { loadArch(t.arch); toast(`Template: ${t.label}`) }
  }
  const doDeleteSaved = async () => {
    if (!confirm(`Delete saved architecture “${name}”?`)) return
    await api.deleteConfig(name); refreshSaved(); toast(`Deleted “${name}”`)
  }
  const doExport = async () => {
    const text = await api.exportYaml(arch)
    const blob = new Blob([text], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `${name}.yml`; a.click()
    URL.revokeObjectURL(url)
    toast('Exported YAML')
  }
  // A new MAS always starts with one entrance and one exit agent.
  const doNew = () => {
    loadArch({ ...STARTER, name: 'untitled-mas' })
    toast('New MAS — one entrance, one exit')
  }

  const doRun = async () => {
    if (running) return
    setRunning(true)
    try {
      const { run_id } = await api.startRun(arch)
      setRun({ run_id, status: 'queued', log: 'starting…' })
      clearInterval(pollRef.current)
      pollRef.current = setInterval(async () => {
        const s = await api.runStatus(run_id)
        setRun(s)
        if (s.status === 'done' || s.status === 'error') {
          clearInterval(pollRef.current)
          setRunning(false)
        }
      }, 700)
    } catch (e) { toast('Run failed to start', 'error'); setRunning(false) }
  }
  useEffect(() => () => clearInterval(pollRef.current), [])

  const yamlText = useMemo(() => {
    try { return yaml.dump(stripArch(arch)) } catch { return '' }
  }, [arch])

  const evilCount = nodes.filter((n) => n.data.malicious?.enabled).length +
    edges.filter((e) => e.data?.malicious?.enabled).length
  const nameIsSaved = saved.some((s) => s.name === name)

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">🛰️ <b>SafeMAS</b> <span className="brand-sub">multi-agent system editor</span></div>
        <div className="field-inline">
          <input className="name-input" value={name} onChange={(e) => setName(e.target.value)} title="Architecture name" />
          <input className="task-input" value={task} onChange={(e) => setTask(e.target.value)} placeholder="task / objective" title="Task given to entry agents" />
        </div>
        <div className="spacer" />
        {evilCount > 0 && <span className="evil-count">☠ {evilCount} malicious</span>}
        <span className={`sandbox-pill sandbox-${health.sandbox}`} title="Execution sandbox">
          {health.sandbox === 'docker' ? '🐳 docker' : '🖥 local'}
        </span>

        <div className="btn-group">
          <button className="btn" onClick={doNew}>New</button>
          <select className="btn" value="" onChange={(e) => e.target.value && doTemplate(e.target.value)} title="Start from a clean template">
            <option value="">Templates…</option>
            {TEMPLATES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
          <select className="btn" value="" onChange={(e) => e.target.value && doLoad(e.target.value)} title="Load saved architecture">
            <option value="">Load…</option>
            {saved.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
          </select>
          <button className="btn" onClick={doSave}>Save</button>
          {nameIsSaved && <button className="btn ghost-danger" onClick={doDeleteSaved} title="Delete this saved architecture">🗑</button>}
        </div>

        <div className="btn-group">
          <button className="btn" onClick={() => setProvidersOpen(true)} title="Manage LLM providers & API keys">🔑 Providers</button>
          <button className="btn" onClick={() => setYamlOpen((v) => !v)}>YAML</button>
          <button className="btn" onClick={doExport}>Export</button>
        </div>
        <button className="btn run" onClick={doRun} disabled={running}>
          {running ? '… running' : '▶ Run'}
        </button>
      </header>

      <div className="body">
        <Palette />
        <div className="canvas" ref={wrapper} onDrop={onDrop} onDragOver={onDragOver}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onInit={(inst) => (rf.current = inst)}
            onNodeClick={(_, n) => { setSelId(n.id); setSelKind('node') }}
            onEdgeClick={(_, e) => { setSelId(e.id); setSelKind('edge') }}
            onPaneClick={() => { setSelId(null); setSelKind(null) }}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#1e293b" gap={20} />
            <Controls />
            <MiniMap nodeColor={(n) => (n.data.malicious?.enabled ? '#ef4444' : NODE_TYPES[n.data.type]?.color)} pannable />
          </ReactFlow>
          {nodes.length === 0 && (
            <div className="canvas-empty">Drag an element from the left to start building →</div>
          )}
          {yamlOpen && (
            <div className="yaml-overlay">
              <div className="yaml-head">architecture.yml <button className="btn ghost" onClick={() => setYamlOpen(false)}>✕</button></div>
              <pre>{yamlText}</pre>
            </div>
          )}
        </div>
        <Inspector
          selected={selected}
          providers={providers}
          onChange={updateSelected}
          onDelete={deleteSelected}
          onManageProviders={() => setProvidersOpen(true)}
        />
      </div>

      <RunConsole run={run} onClose={() => setRun(null)} />

      {providersOpen && (
        <ProvidersModal
          providers={providers}
          onSaved={refreshProviders}
          onClose={() => setProvidersOpen(false)}
          toast={toast}
        />
      )}

      <div className="toasts">
        {toasts.map((t) => <div key={t.id} className={`toast toast-${t.type}`}>{t.msg}</div>)}
      </div>
    </div>
  )
}

// drop position field for YAML preview readability
function stripArch(a) {
  const clean = (o) => {
    const r = {}
    for (const [k, v] of Object.entries(o)) {
      if (v == null || v === '' || (Array.isArray(v) && !v.length)) continue
      if (k === 'malicious' && !v.enabled) continue
      if ((k === 'entry' || k === 'exit') && !v) continue
      r[k] = v
    }
    return r
  }
  return {
    name: a.name, version: a.version, task: a.task,
    nodes: a.nodes.map(clean), edges: a.edges.map(clean),
  }
}

export default function App() {
  return (
    <ReactFlowProvider>
      <Editor />
    </ReactFlowProvider>
  )
}
