import { EDGE_ATTACK, MODELS, NODE_TYPES } from '../lib/elements.js'

// Right panel: edit the selected node or edge, including its malicious flag.
export default function Inspector({ selected, onChange, onDelete }) {
  if (!selected) {
    return (
      <div className="inspector">
        <div className="inspector-empty">Select an element to edit its properties.</div>
      </div>
    )
  }

  const isEdge = selected.kind === 'edge'
  const data = selected.data
  const def = isEdge ? null : NODE_TYPES[data.type]
  const attackLabel = isEdge ? EDGE_ATTACK.attackLabel : def.attackLabel
  const attackType = isEdge ? EDGE_ATTACK.attack : def.attack

  const set = (patch) => onChange({ ...data, ...patch })
  const setMal = (patch) =>
    set({ malicious: { ...data.malicious, ...patch } })

  const toggleEvil = (enabled) =>
    setMal({ enabled, attack: enabled ? attackType : null })

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
          <Field label="Model">
            <select value={data.model || ''} onChange={(e) => set({ model: e.target.value })}>
              {MODELS.map((m) => <option key={m}>{m}</option>)}
            </select>
          </Field>
          <Field label="Role">
            <input value={data.role || ''} onChange={(e) => set({ role: e.target.value })} />
          </Field>
          <Field label="System prompt">
            <textarea rows={3} value={data.prompt || ''} onChange={(e) => set({ prompt: e.target.value })} />
          </Field>
          <label className="checkbox">
            <input type="checkbox" checked={!!data.entry} onChange={(e) => set({ entry: e.target.checked })} />
            Entry agent (receives the task)
          </label>
        </>
      )}

      {!isEdge && data.type === 'memory' && (
        <Field label="Backend">
          <input value={data.backend || ''} onChange={(e) => set({ backend: e.target.value })} />
        </Field>
      )}

      {!isEdge && data.type === 'tool' && (
        <Field label="Spec / signature">
          <textarea rows={2} value={data.spec || ''} onChange={(e) => set({ spec: e.target.value })} />
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
          <input
            type="checkbox"
            checked={!!data.malicious?.enabled}
            onChange={(e) => toggleEvil(e.target.checked)}
          />
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

      <button className="btn danger" onClick={onDelete}>Delete</button>
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
