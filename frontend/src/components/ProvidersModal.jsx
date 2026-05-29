import { useEffect, useState } from 'react'
import { PROVIDER_KINDS } from '../lib/elements.js'
import * as api from '../lib/api.js'

// Manage saved LLM providers. The API key is write-only: once stored the server
// never sends it back, so editing shows a "saved — leave blank to keep" hint and
// only overwrites the key when a new value is typed.
const empty = () => ({ name: '', kind: 'openai', base_url: '', api_key: '', models: '' })

export default function ProvidersModal({ providers, onSaved, onClose, toast }) {
  const [editing, setEditing] = useState(null) // provider id or 'new'
  const [form, setForm] = useState(empty())
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const startNew = () => {
    setForm({ ...empty(), models: PROVIDER_KINDS.openai.models.join(', ') })
    setEditing('new')
  }
  const startEdit = (p) => {
    setForm({ name: p.name, kind: p.kind, base_url: p.base_url || '', api_key: '', models: (p.models || []).join(', ') })
    setEditing(p.id)
  }
  const cancel = () => { setEditing(null); setForm(empty()) }

  const submit = async () => {
    if (!form.name.trim()) { toast('Name is required', 'error'); return }
    setBusy(true)
    const payload = {
      name: form.name.trim(),
      kind: form.kind,
      base_url: form.base_url.trim(),
      models: form.models.split(',').map((s) => s.trim()).filter(Boolean),
    }
    // Only include api_key when the user typed one (blank = keep existing).
    if (form.api_key) payload.api_key = form.api_key
    try {
      if (editing === 'new') await api.createProvider(payload)
      else await api.updateProvider(editing, payload)
      toast('Provider saved')
      cancel()
      onSaved()
    } catch (e) {
      toast(e.message || 'Save failed', 'error')
    } finally { setBusy(false) }
  }

  const remove = async (p) => {
    if (!confirm(`Delete provider "${p.name}"?`)) return
    await api.deleteProvider(p.id)
    toast('Provider deleted')
    onSaved()
  }

  const kind = PROVIDER_KINDS[form.kind] || {}
  const editingExisting = editing && editing !== 'new'
  const existing = editingExisting && providers.find((p) => p.id === editing)

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>🔑 LLM Providers</span>
          <button className="btn ghost" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <p className="modal-hint">
            Save an endpoint and its API key once. Agents reference a provider by
            name — the key stays on the server and is never shown again.
          </p>

          <div className="provider-list">
            {providers.length === 0 && <div className="empty-row">No providers yet.</div>}
            {providers.map((p) => (
              <div key={p.id} className="provider-row">
                <div className="provider-row-main">
                  <b>{p.name}</b>
                  <span className="tag">{PROVIDER_KINDS[p.kind]?.label || p.kind}</span>
                  {p.has_key
                    ? <span className="tag key-ok">key saved</span>
                    : <span className="tag key-missing">no key</span>}
                </div>
                <div className="provider-row-models">{(p.models || []).join(', ') || '—'}</div>
                <div className="provider-row-actions">
                  <button className="btn small" onClick={() => startEdit(p)}>Edit</button>
                  <button className="btn small danger" onClick={() => remove(p)}>Delete</button>
                </div>
              </div>
            ))}
          </div>

          {!editing && <button className="btn" onClick={startNew}>+ Add provider</button>}

          {editing && (
            <div className="provider-form">
              <div className="provider-form-title">{editing === 'new' ? 'New provider' : `Edit "${existing?.name}"`}</div>
              <label className="field">
                <span className="field-label">Name</span>
                <input value={form.name} placeholder="My OpenAI key" onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </label>
              <label className="field">
                <span className="field-label">Kind</span>
                <select value={form.kind} onChange={(e) => {
                  const k = e.target.value
                  setForm({ ...form, kind: k, models: PROVIDER_KINDS[k].models.join(', ') })
                }}>
                  {Object.entries(PROVIDER_KINDS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </label>
              {kind.needsBaseUrl && (
                <label className="field">
                  <span className="field-label">Base URL</span>
                  <input value={form.base_url} placeholder="https://api.example.com/v1" onChange={(e) => setForm({ ...form, base_url: e.target.value })} />
                </label>
              )}
              {form.kind !== 'mock' && (
                <label className="field">
                  <span className="field-label">API key</span>
                  <input
                    type="password"
                    value={form.api_key}
                    placeholder={existing?.has_key ? '•••••••• saved — leave blank to keep' : 'sk-…'}
                    onChange={(e) => setForm({ ...form, api_key: e.target.value })}
                  />
                </label>
              )}
              <label className="field">
                <span className="field-label">Models (comma-separated)</span>
                <input value={form.models} placeholder="gpt-4o, gpt-4o-mini" onChange={(e) => setForm({ ...form, models: e.target.value })} />
              </label>
              <div className="provider-form-actions">
                <button className="btn" onClick={cancel} disabled={busy}>Cancel</button>
                <button className="btn run" onClick={submit} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
