import { EDGE_ATTACK, MEMORY_BACKENDS, NODE_TYPES, PROVIDER_KINDS } from '../lib/elements.js'

const EDGE_KIND_LABEL = {
  channel: 'channel — agent → agent',
  attach: 'attach — memory / tool → agent',
  io: 'io — entrance / exit link',
}

// Right panel: edit the selected node or edge, including its malicious flag.
// Only rendered when something is selected (App gates it), so `selected` is set.
export default function Inspector({ selected, providers, onChange, onDelete, onManageProviders }) {
  const isEdge = selected.kind === 'edge'
  const data = selected.data
  const isStructural = !isEdge && (data.type === 'entrance' || data.type === 'exit')
  const def = isEdge ? null : NODE_TYPES[data.type]
  // AiTM rewrites only make sense on agent→agent channels; attach/io edges
  // carry no rewritable inter-agent message.
  const edgeAttackable = isEdge && data.kind === 'channel'
  const attackLabel = isEdge ? EDGE_ATTACK.attackLabel : def.attackLabel
  const attackType = isEdge ? (edgeAttackable ? EDGE_ATTACK.attack : null) : def.attack

  const set = (patch) => onChange({ ...data, ...patch })
  const setMal = (patch) => set({ malicious: { ...data.malicious, ...patch } })
  const toggleEvil = (enabled) => setMal({ enabled, attack: enabled ? attackType : null })

  const provider = !isEdge && providers.find((p) => p.id === data.provider)
  // With a provider chosen, suggest its models; otherwise the agent runs on the
  // built-in mock, so suggest that.
  const modelOptions = provider ? provider.models : PROVIDER_KINDS.mock.models

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
                    {p.name}{p.default ? ' ★ default' : ''}{p.has_key ? '' : ' (no key)'}
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

          <Field label="Join (multiple inputs)">
            <select value={data.join || 'any'} onChange={(e) => set({ join: e.target.value })}>
              <option value="any">any — run on the first input (relay)</option>
              <option value="all">all — wait for every input, then aggregate (join)</option>
            </select>
            <span className="field-hint">
              Use <b>all</b> on an aggregator (vote / merge) so it actually receives all upstream outputs.
            </span>
          </Field>
        </>
      )}

      {!isEdge && (data.type === 'entrance' || data.type === 'exit') && (
        <p className="io-note">
          {data.type === 'entrance'
            ? 'The entrance feeds the task to whichever agent it links to. Drag from its port to a different agent to re-route it.'
            : 'The exit takes its final answer from whichever agent links into it. Drag an agent’s port here to re-route it.'}
          <br />This node can’t be deleted — move or re-link it instead.
        </p>
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
        <>
          <Field label="Kind">
            <div className="kind-readout" title="Determined by what you connected — rewire to change it">
              {EDGE_KIND_LABEL[data.kind] || data.kind}
            </div>
          </Field>
          <Field label="Label">
            <input
              value={data.label || ''}
              placeholder={data.kind === 'channel' ? 'what flows here — e.g. draft, critique, vote' : 'optional'}
              onChange={(e) => set({ label: e.target.value })}
            />
          </Field>
          {data.kind === 'channel' && (
            <>
              <Field label="Condition / guard (when)">
                <input
                  value={data.when || ''}
                  placeholder='take only if output mentions… e.g. "code"'
                  onChange={(e) => set({ when: e.target.value })}
                />
                <span className="field-hint">
                  Give a source two or more guarded edges to make it a <b>router</b> — it takes the
                  first edge whose guard matches the agent’s output (else a default / the first edge).
                </span>
              </Field>
              <label className="checkbox">
                <input type="checkbox" checked={!!data.loop} onChange={(e) => set({ loop: e.target.checked })} />
                <span>↺ Feedback / loop edge — re-runs the target</span>
              </label>
              {data.loop && (
                <div className="field-row">
                  <Field label="Max iterations">
                    <input
                      type="number" min="1" step="1"
                      value={data.max_iters ?? ''}
                      placeholder="3"
                      onChange={(e) => set({ max_iters: e.target.value === '' ? null : Number(e.target.value) })}
                    />
                  </Field>
                  <Field label="Stop when (until)">
                    <input
                      value={data.until || ''}
                      placeholder='e.g. "approved"'
                      onChange={(e) => set({ until: e.target.value })}
                    />
                  </Field>
                </div>
              )}
            </>
          )}
        </>
      )}

      {attackType && (
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
      )}

      {!isStructural && <button className="btn danger" onClick={onDelete}>Delete element</button>}
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
