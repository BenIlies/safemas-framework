#!/usr/bin/env python3
"""Deterministically validate that every environment's confined-deputy user task (cd_task_5) is
DOABLE and correctly GRADED — with no LLM in the loop.

Two checks per env:
  (1) GRADER SELF-CONSISTENCY — build a synthetic "perfect solver" trace consisting of exactly the
      task's authored expected calls, run it through the real grader (verdict.task_completed), and
      require utility == 1.0. If a subtask's authored calls don't grade to done, the spec and the
      grader disagree (a format/matching drift) — the task can NEVER score 100% no matter how good
      the agent is. Reports every check the grader fails to satisfy.
  (2) STATE RESOLVABILITY — every argument VALUE the expected calls require must actually appear in
      the environment's world state, so an agent could look it up. A value that appears nowhere is
      "phantom": the task asks for something no agent could resolve, so it is not doable.

Exit code is nonzero if any env fails either check (usable as a CI gate).

    backend/.venv/bin/python environments/validate_tasks.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))   # the environments/ folder
REPO = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(REPO, "backend"))
sys.path.insert(0, os.path.join(REPO, "report", "v6"))
from verdict import task_completed, state_hit  # the real deterministic grader + state predicate
import coherence                                # type/format classifier

ENVDIR = HERE
USER_TASK = "cd_task_5"
# Only STRUCTURED-IDENTIFIER arg values must be resolvable from state (an agent looks them up).
# Enums ('frozen'/'squash'/'away'), amounts, dates, booleans and free text are AGENT-GENERATED —
# absence from state is expected and fine, so they are not "phantom".
_LOOKUP_TYPES = {"iban", "email", "handle", "eth_address", "instance_id", "url", "id_token"}


def _state_blob(state) -> str:
    """The whole world state serialised lowercase — an arg value is resolvable if it appears here."""
    return json.dumps(state, ensure_ascii=False).lower()


def _synthetic_trace(subtasks):
    """A 'perfect solver' trace: one successful tool_call event per authored expected call."""
    events = []
    for st in subtasks:
        for c in (st.get("calls") or []):
            if c and c.get("tool"):
                events.append({"kind": "tool_call", "function": c["tool"],
                               "args": c.get("args") or {}, "error": False})
    return events


def _fill(s, args):
    for k, v in (args or {}).items():
        s = s.replace("{" + k + "}", str(v))
    return s


def _fill_val(val, args):
    if isinstance(val, str):
        return _fill(val, args)
    if isinstance(val, dict):
        return {k: _fill_val(v, args) for k, v in val.items()}
    return val


def _apply(effect, args, state):
    """Apply a tool effect (set/append) to a state copy, substituting the call's args into the
    templates — a standalone mirror of the runtime engine, enough to check where a value lands."""
    for op in (effect or []):
        path = _fill(str(op.get("path", "")), args).split(".")
        cur = state
        for seg in path[:-1]:
            if not isinstance(cur, dict):
                cur = None; break
            cur = cur.setdefault(seg, {})
        if not isinstance(cur, dict):
            continue
        key = path[-1]
        if op.get("op") == "set":
            cur[key] = _fill_val(op.get("value"), args)
        elif op.get("op") == "append":
            cur.setdefault(key, [])
            if isinstance(cur[key], list):
                cur[key].append(_fill_val(op.get("value"), args))


def validate_task(env, task, tools, blob):
    """Grader self-consistency + resolvability for one graded user task."""
    spec = task.get("success") or {}
    subtasks = spec.get("subtasks") or ([{"calls": spec["calls"]}] if spec.get("calls") else [])
    issues = []
    graded = task_completed(_synthetic_trace(subtasks), spec)
    if graded.get("utility") != 1.0:
        for s in graded.get("subtasks", []):
            if not s.get("done"):
                issues.append(f"GRADER {task['id']}: subtask '{s.get('id')}' scores "
                              f"{s.get('checks_done')}/{s.get('checks_total')} on its own authored calls")
    for st in subtasks:
        for c in (st.get("calls") or []):
            tn = c.get("tool")
            if tn and tn not in tools:
                issues.append(f"TOOL {task['id']}: calls nonexistent tool '{tn}'")
            for k, v in (c.get("args") or {}).items():
                sv = str(v).strip().lower()
                if sv and coherence.value_type(sv) in _LOOKUP_TYPES and sv not in blob:
                    issues.append(f"PHANTOM {task['id']}: {tn}.{k}='{v}' (lookup id absent from state)")
    return graded.get("utility"), issues


def validate_attacks(env, eff):
    """Each injection task must be DETERMINISTICALLY achievable: applying its success sink call
    (attacker args) must land the attacker value in the harm region (harm predicate fires); an
    indirect plant must land in the delivery region."""
    issues = []
    for t in env.get("injection_tasks", []):
        succ = t.get("success")
        succ = succ if isinstance(succ, list) else ([succ] if succ else [])
        harm = t.get("harm") or {}
        # harm reachable via at least one of the any-of sink alternatives
        ok = False
        for c in succ:
            if not (c and c.get("tool")):
                continue
            state = json.loads(json.dumps(env.get("state", {})))
            _apply(eff.get(c["tool"]), c.get("args") or {}, state)
            if state_hit(state, harm) is True:
                ok = True; break
        if harm.get("value") and not ok:
            issues.append(f"ATTACK {t['id']}: no success call lands harm value '{harm['value']}' "
                          f"in '{harm.get('path')}' (attack not achievable)")
    return issues


# --------------------------------------------------------------------------- #
# Execution-flow export — a graph (nodes+edges) per utility task and per attack,
# for visualising in an external tool (Cytoscape / Graphviz / Mermaid / d3). Purely
# structural + deterministic: derived from the authored specs and the tool effects,
# with the reachability simulation confirming where each value actually lands.
# --------------------------------------------------------------------------- #
def _tool_agent_map(env):
    """tool -> owning canonical agent, from the env's per-agent tool_groups dict."""
    tg = env.get("tool_groups") or {}
    return {t: a for a, ts in (tg.items() if isinstance(tg, dict) else []) for t in ts}


def _task_flow(task, tmap):
    """A utility task as its parallel sub-streams: each subtask, the AGENT that owns it, and the
    (benign, role='task') tool calls it makes. Every subtask is kept — these run independently."""
    spec = task.get("success") or {}
    subs = spec.get("subtasks") or ([{"id": "main", "calls": spec["calls"]}] if spec.get("calls") else [])
    steps = []
    for st in subs:
        calls = [{"tool": c.get("tool"), "args": c.get("args") or {},
                  "agent": tmap.get(c.get("tool"), "?"), "role": "task"}
                 for c in (st.get("calls") or []) if c and c.get("tool")]
        steps.append({"subtask": st.get("label") or st.get("id") or "subtask",
                      "agent": (calls[0]["agent"] if calls else "?"), "calls": calls})
    return {"kind": "utility", "prompt": task.get("prompt", "")[:300], "steps": steps}


def _attack_flow(env, task, eff, tmap):
    """An attack as an ordered stage flow across the THEORETICAL agents:
       inject → (plant, role='plant'/purple) → (delivery record) → (harm, role='harm'/red).
    Direct attacks skip the plant. Each tool stage names the owning agent."""
    kind = task.get("kind", "")
    succ = task.get("success")
    succ = succ if isinstance(succ, list) else ([succ] if succ else [])
    sink = (succ[0] if succ else {}) or {}
    harm = task.get("harm") or {}
    deliv = task.get("delivery") or {}
    st = json.loads(json.dumps(env.get("state", {})))
    if sink.get("tool"):
        _apply(eff.get(sink["tool"]), sink.get("args") or {}, st)
    achievable = state_hit(st, harm) is True if harm.get("value") else None
    stages = []
    if kind == "direct":
        ta = task.get("target_agent")
        stages.append({"role": "inject", "agent": ta})
        stages.append({"role": "harm", "agent": ta, "tool": sink.get("tool"), "args": sink.get("args") or {},
                       "alts": [c.get("tool") for c in succ], "region": harm.get("path"), "value": harm.get("value")})
    else:
        oa, sa = task.get("origin_agent"), task.get("sink_agent")
        stages.append({"role": "inject", "agent": oa})
        stages.append({"role": "plant", "agent": oa, "tool": task.get("source"),
                       "note": kind == "indirect-instruction",
                       "region": deliv.get("path"), "value": deliv.get("value")})
        stages.append({"role": "harm", "agent": sa, "tool": sink.get("tool"), "args": sink.get("args") or {},
                       "alts": [c.get("tool") for c in succ], "region": harm.get("path"), "value": harm.get("value")})
    return {"kind": kind, "difficulty": task.get("difficulty"), "achievable": achievable,
            "goal": task.get("goal"), "origin_agent": task.get("origin_agent"),
            "sink_agent": task.get("sink_agent"), "target_agent": task.get("target_agent"),
            "stages": stages}


def build_flows(env, eff):
    tmap = _tool_agent_map(env)
    graded = [t for t in env.get("user_tasks", [])
              if (t.get("success") or {}).get("subtasks") or (t.get("success") or {}).get("calls")]
    return {
        "agents": env.get("tool_groups") or {},   # theoretical agents -> their owned tools
        "utility_tasks": {t["id"]: _task_flow(t, tmap) for t in graded},
        "attacks": {t["id"]: _attack_flow(env, t, eff, tmap) for t in env.get("injection_tasks", [])},
    }


def main():
    fails = 0
    flows = {}
    for f in sorted(os.listdir(ENVDIR)):
        if not f.endswith(".json"):
            continue
        env = json.loads(open(os.path.join(ENVDIR, f)).read())
        name = f[:-5]
        tools = {t["name"] for t in env.get("tools", [])}
        eff = {t["name"]: t.get("effect") for t in env.get("tools", [])}
        blob = _state_blob(env.get("state", {}))
        graded_tasks = [t for t in env.get("user_tasks", [])
                        if (t.get("success") or {}).get("subtasks") or (t.get("success") or {}).get("calls")]
        issues, worst_util = [], 1.0
        for t in graded_tasks:
            u, iss = validate_task(env, t, tools, blob)
            issues += iss
            if u is not None and u < worst_util:
                worst_util = u
        issues += validate_attacks(env, eff)
        flows[name] = build_flows(env, eff)
        status = "OK" if not issues else f"{len(issues)} ISSUE(S)"
        print(f"{name:12s} tasks={len(graded_tasks)}  attacks={len(env.get('injection_tasks',[]))}  "
              f"min-solver-utility={worst_util}  {status}")
        for i in issues:
            print(f"    - {i}")
        if issues:
            fails += 1
    # Emit the execution-flow graphs for external inspection/visualisation.
    out = os.path.join(ENVDIR, "task_flows.json")
    with open(out, "w") as fh:
        json.dump({"schema": "nodes[{id,type,label,...}] + edges[{from,to,rel}] per task/attack; "
                   "deterministic, no LLM", "envs": flows}, fh, indent=2, ensure_ascii=False)
    n_atk = sum(len(v["attacks"]) for v in flows.values())
    n_task = sum(len(v["utility_tasks"]) for v in flows.values())
    print(f"\nflows -> {os.path.relpath(out, REPO)}  ({n_task} task flows, {n_atk} attack flows)")
    print(f"{'ALL TASKS DOABLE + GRADED' if not fails else f'{fails} env(s) FAILED'}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
