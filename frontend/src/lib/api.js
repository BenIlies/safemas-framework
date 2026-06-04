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

// ---- templates (built-in MAS, served as DSL code) ----
export async function listTemplates() {
  try { return await (await fetch('/api/templates')).json() } catch { return [] }
}
export async function loadTemplate(id) {
  return jsonOrThrow(await fetch(`/api/templates/${encodeURIComponent(id)}`), 'template load failed')
}

// ---- run ----
export async function startRun(arch) {
  return (await fetch('/api/run', { method: 'POST', headers: J, body: JSON.stringify(arch) })).json()
}
export async function runStatus(runId) {
  return (await fetch(`/api/run/${runId}`)).json()
}
// The run's structured scenario log (PCAP scn_*.json format). Throws if absent.
export async function runScn(runId) {
  const r = await fetch(`/api/run/${runId}/scn`)
  if (!r.ok) throw new Error('no scenario log for this run')
  return r.json()
}
export async function health() {
  try { return await (await fetch('/api/health')).json() } catch { return { ok: false } }
}
