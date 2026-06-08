// Simulate how the SafeMAS runtime will run a graph, so the canvas can tell the
// truth about it. This mirrors backend/safemas/graph_runtime.py's message-driven
// scheduler: a work queue of agent activations with bounded loop edges, guarded
// routing (select one branch), and join="all" agents that wait for every inbound
// channel and aggregate. Guards/`until` depend on live model output, which the
// lens can't see — so it reproduces the *keyless mock* run exactly (guards never
// match → a router falls to its first branch; loops iterate to their bound).
//
// Returns:
//   fireOrder   Map<agentId, number>   1-based order each agent first runs
//   runCount    Map<agentId, number>   how many times each agent runs (loops > 1)
//   liveEdges   Set<edgeId>            channel edges a message traverses
//   deadEdges   Set<edgeId>            channel edges that never carry a message
//   neverFired  Set<agentId>           agents the run never activates
//   entries, exits  string[]           resolved entry / exit agent ids
//   diagnostics Diagnostic[]           { level:'error'|'warn'|'info', msg, nodeId?, edgeId? }

const DEFAULT_MAX_ITERS = 3
const STEP_BUDGET = 256
const PER_AGENT_CAP = 64

const isChannel = (e) => (e.data?.kind || 'channel') === 'channel'
const isIo = (e) => e.data?.kind === 'io'
const isLoop = (e) => !!e.data?.loop
const guardOf = (e) => e.data?.when || ''

export function simulateExecution(nodes, edges) {
  const nodeById = new Map(nodes.map((n) => [n.id, n]))
  const typeOf = (id) => nodeById.get(id)?.data?.type
  const labelOf = (id) => nodeById.get(id)?.data?.label || id
  const joinAll = (id) => nodeById.get(id)?.data?.join === 'all'
  const isAgent = (id) => typeOf(id) === 'agent'

  const channels = edges.filter(isChannel)
  const ioEdges = edges.filter(isIo)
  const agents = nodes.filter((n) => n.data?.type === 'agent')

  const outCh = new Map() // source -> [channel edges] in order
  for (const e of channels) {
    if (!outCh.has(e.source)) outCh.set(e.source, [])
    outCh.get(e.source).push(e)
  }
  const inFwd = new Map() // target -> [inbound non-loop edges] (what a join waits for)
  for (const e of channels) {
    if (isLoop(e)) continue
    if (!inFwd.has(e.target)) inFwd.set(e.target, [])
    inFwd.get(e.target).push(e)
  }

  let entries = [...new Set(
    ioEdges.filter((e) => typeOf(e.source) === 'entrance' && isAgent(e.target)).map((e) => e.target),
  )]
  if (!entries.length) {
    const targeted = new Set(channels.filter((e) => !isLoop(e)).map((e) => e.target))
    entries = agents.map((n) => n.id).filter((id) => !targeted.has(id))
    if (!entries.length && agents.length) entries = [agents[0].id]
  }
  const exits = [...new Set(
    ioEdges.filter((e) => isAgent(e.source) && typeOf(e.target) === 'exit').map((e) => e.source),
  )]

  // --- the scheduler (mirror of engine.run_mas) ---
  const fireOrder = new Map()
  const runCount = new Map()
  const loopIters = new Map()
  const liveEdges = new Set()
  const joinBuf = new Map() // target -> Set<edgeId delivered this round>
  const queue = []
  let seq = 0

  const takeable = (e) => {
    if (isLoop(e)) return (loopIters.get(e.id) || 0) < (e.data?.max_iters ?? DEFAULT_MAX_ITERS)
    return !guardOf(e) // a guard can't be evaluated without a model → not taken under mock
  }

  // Which out-edges fire after `agentId` runs (see engine.chosen_edges).
  const chosenEdges = (agentId) => {
    const outs = outCh.get(agentId) || []
    if (!outs.length) return []
    if (!outs.some((e) => guardOf(e) || isLoop(e))) return outs // broadcast
    let pick = outs.find(takeable)
    if (!pick) {
      const forwards = outs.filter((e) => !isLoop(e))
      pick = forwards.find((e) => !guardOf(e)) || forwards[0] || null
    }
    if (pick && isLoop(pick)) loopIters.set(pick.id, (loopIters.get(pick.id) || 0) + 1)
    return pick ? [pick] : []
  }

  const deliver = (e) => {
    liveEdges.add(e.id)
    const tgt = e.target
    if (joinAll(tgt)) {
      const needed = inFwd.get(tgt) || []
      const buf = joinBuf.get(tgt) || new Set()
      buf.add(e.id)
      joinBuf.set(tgt, buf)
      if (needed.length && needed.every((c) => buf.has(c.id))) {
        joinBuf.set(tgt, new Set())
        queue.push(tgt)
      }
    } else {
      queue.push(tgt)
    }
  }

  for (const a of entries) queue.push(a)
  let steps = 0
  while (queue.length && steps < STEP_BUDGET) {
    const a = queue.shift()
    if ((runCount.get(a) || 0) >= PER_AGENT_CAP) continue
    runCount.set(a, (runCount.get(a) || 0) + 1)
    if (!fireOrder.has(a)) fireOrder.set(a, ++seq)
    steps++
    for (const e of chosenEdges(a)) deliver(e)
  }

  const deadEdges = new Set(channels.filter((e) => !liveEdges.has(e.id)).map((e) => e.id))
  const neverFired = new Set(agents.filter((n) => !fireOrder.has(n.id)).map((n) => n.id))

  const diagnostics = diagnose({
    channels, agents, entries, exits, outCh, inFwd, fireOrder, runCount,
    neverFired, joinAll, labelOf, nodeById, liveEdges,
  })

  return { fireOrder, runCount, liveEdges, deadEdges, neverFired, entries, exits, diagnostics }
}

function diagnose(ctx) {
  const { channels, agents, entries, exits, outCh, inFwd, runCount, neverFired, joinAll, labelOf, liveEdges } = ctx
  const out = []
  const add = (level, msg, ref = {}) => out.push({ level, msg, ...ref })
  const arrow = (e) => `${labelOf(e.source)} → ${labelOf(e.target)}`

  if (!entries.length) add('error', 'No entry agent — nothing will run. Link the ▶ entrance to an agent.')
  if (!exits.length && agents.length) add('info', 'No exit agent — the final answer falls back to the last agent that ran.')

  // Loops now really iterate — surface the bound (and flag unbounded defaults).
  for (const e of channels) {
    if (!e.data?.loop) continue
    const cap = e.data?.max_iters ?? null
    const until = e.data?.until || ''
    if (cap == null && !until) {
      add('warn', `Feedback loop ${arrow(e)} has no bound — it defaults to ${3} iterations. Set max iterations or a stop phrase.`, { edgeId: e.id })
    } else {
      const bits = [cap != null ? `up to ${cap}×` : 'until match', until ? `stops on “${until}”` : ''].filter(Boolean)
      add('info', `Feedback loop ${arrow(e)} iterates (${bits.join(', ')}).`, { edgeId: e.id })
    }
  }

  // Fan-in: ≥2 inbound forward channels. join="all" aggregates; join="any" drops.
  // Count inputs that ACTUALLY arrive at runtime (liveEdges), not just wired ones,
  // so a routed merge point (e.g. a collector after a router, where only one
  // branch fires) isn't falsely flagged — there, join="any" is correct.
  for (const a of agents) {
    const fwd = inFwd.get(a.id) || []
    if (fwd.length < 2) continue
    if (joinAll(a.id)) {
      add('info', `${labelOf(a.id)} joins ${fwd.length} inputs (waits for all, then aggregates).`, { nodeId: a.id })
      continue
    }
    const delivered = liveEdges ? fwd.filter((e) => liveEdges.has(e.id)).length : fwd.length
    if (delivered >= 2) {
      add('warn', `${labelOf(a.id)} receives ${delivered} inputs but join = “any” — it runs on the first and ignores the rest. Set join = “all” to aggregate.`, { nodeId: a.id })
    }
  }

  // Out-edge shape: router (guards) vs broadcast (parallel fan-out).
  for (const a of agents) {
    const outs = outCh.get(a.id) || []
    const guarded = outs.filter((e) => e.data?.when)
    const forwards = outs.filter((e) => !e.data?.loop)
    if (guarded.length) {
      const hasDefault = forwards.some((e) => !e.data?.when)
      add('info', `${labelOf(a.id)} routes by guard — one branch is taken per run${hasDefault ? '' : '; with no default branch and no model, it falls to the first'}.`, { nodeId: a.id })
    } else if (forwards.length >= 2) {
      add('info', `${labelOf(a.id)} broadcasts to ${forwards.length} agents in parallel (fan-out).`, { nodeId: a.id })
    }
  }

  // Join that can never complete → deadlock (waits for inputs that never arrive).
  for (const a of agents) {
    if (joinAll(a.id) && neverFired.has(a.id) && (inFwd.get(a.id) || []).length) {
      add('error', `${labelOf(a.id)} never runs — join = “all” waits for ${(inFwd.get(a.id) || []).length} inputs but not all of them arrive.`, { nodeId: a.id })
    }
  }

  // Unreachable agents. If only reachable through a guard, it's conditional, not broken.
  for (const id of neverFired) {
    if (joinAll(id) && (inFwd.get(id) || []).length) continue // reported as deadlock above
    const inbound = channels.filter((e) => e.target === id)
    const conditional = inbound.length && inbound.every((e) => e.data?.when || isFromRouter(e, outCh))
    if (conditional) {
      add('info', `${labelOf(id)} only runs when a guard routes to it — not exercised in a keyless (mock) run.`, { nodeId: id })
    } else {
      add('error', `${labelOf(id)} never executes — no path from an entry reaches it.`, { nodeId: id })
    }
  }

  // Note loop nodes that run many times (helps explain the ×N badges).
  for (const a of agents) {
    const n = runCount.get(a.id) || 0
    if (n >= 4) add('info', `${labelOf(a.id)} runs ${n}× (inside a loop).`, { nodeId: a.id })
  }

  return out
}

// True if an edge's source is a router (has any guarded out-edge), so an
// unmatched target is conditional rather than truly unreachable.
function isFromRouter(edge, outCh) {
  return (outCh.get(edge.source) || []).some((e) => e.data?.when)
}
