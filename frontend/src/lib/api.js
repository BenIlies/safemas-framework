// Thin REST client for the SafeMAS backend.
const J = { 'Content-Type': 'application/json' }

async function jsonOrThrow(r, msg) {
  if (!r.ok) throw new Error(msg || `request failed (${r.status})`)
  return r.json()
}

// ---- configs ----
export async function listConfigs() {
  return (await fetch('/api/configs')).json()
}
export async function loadConfig(name) {
  return jsonOrThrow(await fetch(`/api/configs/${encodeURIComponent(name)}`), 'load failed')
}
export async function saveConfig(name, arch) {
  return jsonOrThrow(await fetch(`/api/configs/${encodeURIComponent(name)}`, {
    method: 'PUT', headers: J, body: JSON.stringify(arch),
  }), 'save failed')
}
export async function deleteConfig(name) {
  return (await fetch(`/api/configs/${encodeURIComponent(name)}`, { method: 'DELETE' })).json()
}

// ---- providers ----
export async function listProviders() {
  try { return await (await fetch('/api/providers')).json() } catch { return [] }
}
export async function createProvider(p) {
  return jsonOrThrow(await fetch('/api/providers', { method: 'POST', headers: J, body: JSON.stringify(p) }), 'create failed')
}
export async function updateProvider(id, p) {
  return jsonOrThrow(await fetch(`/api/providers/${id}`, { method: 'PUT', headers: J, body: JSON.stringify(p) }), 'update failed')
}
export async function deleteProvider(id) {
  return (await fetch(`/api/providers/${id}`, { method: 'DELETE' })).json()
}
export async function setDefaultProvider(id) {
  return jsonOrThrow(await fetch(`/api/providers/${id}/default`, { method: 'PUT' }), 'set default failed')
}

// ---- templates (built-in MAS, authored as native-LangGraph StateGraph code) ----
export async function listTemplates() {
  try { return await (await fetch('/api/templates')).json() } catch { return [] }
}
export async function loadTemplate(id) {
  return jsonOrThrow(await fetch(`/api/templates/${encodeURIComponent(id)}`), 'template load failed')
}
export async function templateCode(id) {
  const r = await fetch(`/api/templates/${encodeURIComponent(id)}/code`)
  if (!r.ok) throw new Error('template code load failed')
  return r.text()
}

// ---- code <-> architecture graph (the StateGraph DSL is the source of truth) ----
export async function codeFromArch(arch) {
  const { code } = await jsonOrThrow(await fetch('/api/code/from-arch', {
    method: 'POST', headers: J, body: JSON.stringify(arch),
  }), 'code generation failed')
  return code
}
export async function codeToArch(code) {
  const r = await fetch('/api/code/to-arch', { method: 'POST', headers: J, body: JSON.stringify({ code }) })
  if (!r.ok) {
    let msg = 'code is invalid'
    try { msg = (await r.json()).detail || msg } catch { /* keep default */ }
    throw new Error(msg)
  }
  return r.json()
}

// ---- environments + scenario runner (env ⊗ template ⊗ injection ⊗ task) ----
export async function listEnvironments() {
  try { return await (await fetch('/api/environments')).json() } catch { return [] }
}
export async function loadEnvironment(name) {
  return jsonOrThrow(await fetch(`/api/environments/${encodeURIComponent(name)}`), 'environment load failed')
}
export async function scenarioPreview(input) {
  return jsonOrThrow(await fetch('/api/scenario/preview', {
    method: 'POST', headers: J, body: JSON.stringify(input),
  }), 'preview failed')
}
export async function runScenario(input) {
  return jsonOrThrow(await fetch('/api/scenario/run', {
    method: 'POST', headers: J, body: JSON.stringify(input),
  }), 'scenario run failed')
}

// ---- run ----
export async function startRun(arch) {
  return (await fetch('/api/run', { method: 'POST', headers: J, body: JSON.stringify(arch) })).json()
}
export async function runStatus(runId) {
  return (await fetch(`/api/run/${runId}`)).json()
}
// The run's structured scenario log (trace scn_*.json format). Throws if absent.
export async function runScn(runId) {
  const r = await fetch(`/api/run/${runId}/scn`)
  if (!r.ok) throw new Error('no scenario log for this run')
  return r.json()
}
export async function health() {
  try { return await (await fetch('/api/health')).json() } catch { return { ok: false } }
}
