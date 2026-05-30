// Thin REST client for the SafeMAS backend.
const J = { 'Content-Type': 'application/json' }

export async function listConfigs() {
  return (await fetch('/api/configs')).json()
}

export async function loadConfig(name) {
  const r = await fetch(`/api/configs/${encodeURIComponent(name)}`)
  if (!r.ok) throw new Error('load failed')
  return r.json()
}

export async function saveConfig(name, arch) {
  return (await fetch(`/api/configs/${encodeURIComponent(name)}`, {
    method: 'PUT',
    headers: J,
    body: JSON.stringify(arch),
  })).json()
}

export async function deleteConfig(name) {
  return (await fetch(`/api/configs/${encodeURIComponent(name)}`, { method: 'DELETE' })).json()
}

export async function exportYaml(arch) {
  return (await fetch('/api/export', { method: 'POST', headers: J, body: JSON.stringify(arch) })).text()
}

export async function startRun(arch) {
  return (await fetch('/api/run', { method: 'POST', headers: J, body: JSON.stringify(arch) })).json()
}

export async function runStatus(runId) {
  return (await fetch(`/api/run/${runId}`)).json()
}

export async function health() {
  try {
    return await (await fetch('/api/health')).json()
  } catch {
    return { ok: false }
  }
}
