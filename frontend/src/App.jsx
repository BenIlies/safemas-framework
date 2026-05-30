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
import { NODE_TYPES, blankMalicious } from './lib/elements.js'
import { archToGraph, graphToArch, decorateEdge } from './lib/graph.js'
import * as api from './lib/api.js'
import { EXAMPLE } from './lib/example.js'

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
  const [yamlOpen, setYamlOpen] = useState(false)
  const [saved, setSaved] = useState([])
  const [docker, setDocker] = useState(true)
  const pollRef = useRef(null)

  // load example on first mount
  useEffect(() => {
    const g = archToGraph(EXAMPLE)
    setNodes(g.nodes); setEdges(g.edges); setName(g.name); setTask(g.task)
    idSeq = 100
    api.health().then((h) => setDocker(!!h.docker))
    refreshSaved()
  }, [])

  const refreshSaved = () => api.listConfigs().then(setSaved).catch(() => {})

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
    setNodes((ns) => ns.concat({
      id: nextId(type),
      type: 'masNode',
      position: pos,
      data: { type, label: def.label, ...def.defaults, malicious: blankMalicious() },
    }))
  }, [setNodes])

  const onDragOver = useCallback((e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move' }, [])

  // ---- toolbar actions ----
  const doSave = async () => { await api.saveConfig(name, arch); refreshSaved() }
  const doLoad = async (n) => {
    const a = await api.loadConfig(n)
    const g = archToGraph(a)
    setNodes(g.nodes); setEdges(g.edges); setName(a.name); setTask(a.task || '')
    setSelId(null); setSelKind(null)
  }
  const doExport = async () => {
    const text = await api.exportYaml(arch)
    const blob = new Blob([text], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `${name}.yml`; a.click()
    URL.revokeObjectURL(url)
  }
  const doNew = () => { setNodes([]); setEdges([]); setName('untitled-mas'); setTask('Solve the assigned task.'); setSelId(null) }

  const doRun = async () => {
    const { run_id } = await api.startRun(arch)
    setRun({ run_id, status: 'queued', log: 'starting…' })
    clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      const s = await api.runStatus(run_id)
      setRun(s)
      if (s.status === 'done' || s.status === 'error') clearInterval(pollRef.current)
    }, 800)
  }
  useEffect(() => () => clearInterval(pollRef.current), [])

  const yamlText = useMemo(() => {
    try { return yaml.dump(stripArch(arch)) } catch { return '' }
  }, [arch])

  const evilCount = nodes.filter((n) => n.data.malicious?.enabled).length +
    edges.filter((e) => e.data?.malicious?.enabled).length

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">🛰️ <b>SafeMAS</b> <span className="brand-sub">multi-agent system editor</span></div>
        <input className="name-input" value={name} onChange={(e) => setName(e.target.value)} />
        <input className="task-input" value={task} onChange={(e) => setTask(e.target.value)} placeholder="task / objective" />
        <div className="spacer" />
        {evilCount > 0 && <span className="evil-count">☠ {evilCount} malicious</span>}
        <button className="btn" onClick={doNew}>New</button>
        <select className="btn" value="" onChange={(e) => e.target.value && doLoad(e.target.value)}>
          <option value="">Load…</option>
          {saved.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
        </select>
        <button className="btn" onClick={doSave}>Save</button>
        <button className="btn" onClick={() => setYamlOpen((v) => !v)}>YAML</button>
        <button className="btn" onClick={doExport}>Export</button>
        <button className="btn run" onClick={doRun} title={docker ? '' : 'Docker not detected'}>▶ Run</button>
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
          {yamlOpen && (
            <div className="yaml-overlay">
              <div className="yaml-head">architecture.yml <button className="btn ghost" onClick={() => setYamlOpen(false)}>✕</button></div>
              <pre>{yamlText}</pre>
            </div>
          )}
        </div>
        <Inspector selected={selected} onChange={updateSelected} onDelete={deleteSelected} />
      </div>

      <RunConsole run={run} onClose={() => setRun(null)} />
      {!docker && <div className="docker-warn">⚠ Docker not detected — runs will report an error. Editing/export still work.</div>}
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
      if (k === 'entry' && !v) continue
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
