import { EDGE_ATTACK, MEMORY_BACKENDS, NODE_TYPES, PROVIDER_KINDS } from '../lib/elements.js'

// Right panel: edit the selected node or edge, including its malicious flag.
export default function Inspector({ selected, providers, onChange, onDelete, onManageProviders }) {
  if (!selected) {
    return (
      <div className="inspector">
        <div className="inspector-empty">
          <div className="inspector-empty-icon">🖱️</div>
          Select a node or link on the canvas to edit its properties.
        </div>
      </div>
    )
  }

  const isEdge = selected.kind === 'edge'
  const data = selected.data
  const def = isEdge ? null : NODE_TYPES[data.type]
  const attackLabel = isEdge ? EDGE_ATTACK.attackLabel : def.attackLabel
  const attackType = isEdge ? EDGE_ATTACK.attack : def.attack

  const set = (patch) => onChange({ ...data, ...patch })
  const setMal = (patch) => set({ malicious: { ...data.malicious, ...patch } })
  const toggleEvil = (enabled) => setMal({ enabled, attack: enabled ? attackType : null })

  const provider = !isEdge && providers.find((p) => p.id === data.provider)
  const modelOptions = provider ? provider.models : PROVIDER_KINDS[data.providerKind]?.models || []

  return (
    <div className="inspector">
      <div className="inspector-head">
        <span className="mas-icon">{isEdge ? '🔗' : def.icon}</span>
        <span>{isEdge ? 'Channel / Link' : def.label}</span>
      </div>

      {!isEdge && (
        <Field label="Label">
          <input value={data.label || ''} onChange={(e) => set({ label: e.target.value })} />
        </Field>
      )}

      {!isEdge && data.type === 'agent' && (
        <>
          <Field label="Provider">
            <div className="row-with-action">
              <select value={data.provider || ''} onChange={(e) => set({ provider: e.target.value || null })}>
                <option value="">— mock (no provider) —</option>
                {providers.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}{p.has_key ? '' : ' (no key)'}
                  </option>
                ))}
              </select>
              <button className="btn small" title="Manage providers" onClick={onManageProviders}>⚙</button>
            </div>
          </Field>

          <Field label="Model">
            <input
              list="model-options"
              value={data.model || ''}
              placeholder={provider ? (provider.models[0] || 'model name') : 'pick a provider first'}
              onChange={(e) => set({ model: e.target.value })}
            />
            <datalist id="model-options">
              {modelOptions.map((m) => <option key={m} value={m} />)}
            </datalist>
          </Field>

          <Field label="Role">
            <input value={data.role || ''} onChange={(e) => set({ role: e.target.value })} />
          </Field>

          <Field label="System prompt">
            <textarea rows={4} value={data.prompt || ''} placeholder="You are a helpful agent that…" onChange={(e) => set({ prompt: e.target.value })} />
          </Field>

          <div className="field-row">
            <Field label="Temperature">
              <input
                type="number" step="0.1" min="0" max="2"
                value={data.temperature ?? ''}
                placeholder="default"
                onChange={(e) => set({ temperature: e.target.value === '' ? null : Number(e.target.value) })}
              />
            </Field>
            <Field label="Max tokens">
              <input
                type="number" step="1" min="1"
                value={data.max_tokens ?? ''}
                placeholder="default"
                onChange={(e) => set({ max_tokens: e.target.value === '' ? null : Number(e.target.value) })}
              />
            </Field>
          </div>

          <label className="checkbox">
            <input type="checkbox" checked={!!data.entry} onChange={(e) => set({ entry: e.target.checked })} />
            Entry agent (receives the task)
          </label>
        </>
      )}

      {!isEdge && data.type === 'memory' && (
        <Field label="Backend">
          <input list="mem-backends" value={data.backend || ''} onChange={(e) => set({ backend: e.target.value })} />
          <datalist id="mem-backends">
            {MEMORY_BACKENDS.map((b) => <option key={b} value={b} />)}
          </datalist>
        </Field>
      )}

      {!isEdge && data.type === 'tool' && (
        <Field label="Spec / signature">
          <textarea rows={3} value={data.spec || ''} onChange={(e) => set({ spec: e.target.value })} />
        </Field>
      )}

      {isEdge && (
        <Field label="Kind">
          <select value={data.kind} onChange={(e) => set({ kind: e.target.value })}>
            <option value="channel">channel (agent → agent)</option>
            <option value="attach">attach (memory / tool → agent)</option>
          </select>
        </Field>
      )}

      <div className="evil-box">
        <label className="checkbox evil-toggle">
          <input type="checkbox" checked={!!data.malicious?.enabled} onChange={(e) => toggleEvil(e.target.checked)} />
          <span>☠ Mark as malicious — <b>{attackLabel}</b></span>
        </label>
        {data.malicious?.enabled && (
          <Field label="Attacker payload">
            <textarea
              rows={3}
              placeholder={payloadHint(attackType)}
              value={data.malicious.payload || ''}
              onChange={(e) => setMal({ payload: e.target.value })}
            />
          </Field>
        )}
      </div>

      <button className="btn danger" onClick={onDelete}>Delete element</button>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  )
}

function payloadHint(attack) {
  switch (attack) {
    case 'prompt-injection': return 'Directive injected into this agent’s input...'
    case 'aitm': return 'Replacement message written onto this channel...'
    case 'memory-poisoning': return 'Poisoned content returned on every read...'
    case 'tool-poisoning': return 'Malicious result this tool returns...'
    default: return ''
  }
}
