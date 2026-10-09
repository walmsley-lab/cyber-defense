"""Variable-length, branching security assessment campaigns; offline deterministic checks.

No commands or network requests are executed by this scheduler. Observations are
supplied by an approved lab harness or operator and recorded as evidence.
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

STATES = {"pending", "running", "passed", "failed", "blocked", "inconclusive"}
FINAL = {"passed", "failed", "blocked", "inconclusive"}

def validate(campaign):
    actions = campaign.get("actions", [])
    ids = [a["id"] for a in actions]
    if len(ids) != len(set(ids)) or len(actions) > 1000:
        raise ValueError("Duplicate action or too many actions")
    known = set(ids)
    for a in actions:
        if a.get("status", "pending") not in STATES:
            raise ValueError("Invalid status")
        if set(a.get("requires_all", [])) - known:
            raise ValueError("Unknown required step")
        if set(a.get("requires_any", [])) - known:
            raise ValueError("Unknown alternative step")
        if a["id"] in a.get("requires_all", []) + a.get("requires_any", []):
            raise ValueError("Self dependency")
    graph = {a["id"]: a.get("requires_all", []) + a.get("requires_any", []) for a in actions}
    def visit(n, pending, seen):
        if n in pending: raise ValueError("Dependency cycle")
        if n in seen: return
        pending.add(n)
        for dep in graph[n]: visit(dep, pending, seen)
        pending.remove(n)
        seen.add(n)
    seen = set()
    for n in ids: visit(n, set(), seen)
    return actions

def ranked(campaign):
    actions = validate(campaign)
    state = {a["id"]: a.get("status", "pending") for a in actions}
    result = []
    for a in actions:
        if state[a["id"]] != "pending":
            continue
        all_deps = a.get("requires_all", [])
        any_deps = a.get("requires_any", [])
        ready = all(state[d] == "passed" for d in all_deps) and (
            not any_deps or any(state[d] == "passed" for d in any_deps))
        dead = any(state[d] in ("failed", "blocked") for d in all_deps) or (
            bool(any_deps) and all(state[d] in ("failed", "blocked") for d in any_deps))
        classification = "ready" if ready else "blocked-by-prerequisite" if dead else "waiting"
        priority = a.get("impact", 1) * a.get("confidence", 0.5) * a.get("information_gain", 1) / max(
            a.get("cost", 1) + a.get("risk", 0), 0.1)
        result.append({"id": a["id"], "title": a.get("title", a["id"]),
                       "readiness": classification, "priority": round(priority, 3)})
    return sorted(result, key=lambda x: (x["readiness"] != "ready", -x["priority"], x["id"]))

def apply_event(campaign, event):
    if event.get("status") not in STATES - {"pending"}:
        raise ValueError("Invalid transition")
    actions = validate(campaign)
    target = next((a for a in actions if a["id"] == event.get("action_id")), None)
    if not target: raise ValueError("Unknown action")
    if target.get("status", "pending") in FINAL:
        raise ValueError("Already finalized; start a new run to retry")
    if event["status"] == "passed":
        readiness = {r["id"]: r["readiness"] for r in ranked(campaign)}
        if readiness.get(target["id"]) != "ready" and target.get("status") != "running":
            raise ValueError("Prerequisites not met")
    target["status"] = event["status"]
    return campaign

def main():
    p = argparse.ArgumentParser(description="Offline attack assessment campaign tracker")
    p.add_argument("campaign", type=Path)
    p.add_argument("--events", type=Path, default=Path("campaign-events.jsonl"))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    update = sub.add_parser("record")
    update.add_argument("action_id")
    update.add_argument("outcome", choices=sorted(STATES-{"pending"}))
    update.add_argument("--evidence", default="", help="Evidence artifact reference (not secrets)")
    args = p.parse_args()
    campaign = json.loads(args.campaign.read_text())
    validate(campaign)
    if args.events.exists():
        for line in args.events.read_text().splitlines():
            if line.strip(): apply_event(campaign, json.loads(line))
    if args.command == "record":
        event = {"timestamp": datetime.now(timezone.utc).isoformat(),
                 "action_id": args.action_id, "status": args.outcome,
                 "evidence": args.evidence}
        apply_event(campaign, event)
        with args.events.open("a") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
    for a in campaign["actions"]:
        mark = {"pending": "?", "running": "~", "passed": "+",
                "failed": "x", "blocked": "!", "inconclusive": "-"}[a.get("status","pending")]
        print(f"[{mark}] {a['id']}: {a.get('title', a['id'])}")
    print("\nNEXT CHECKS")
    for item in ranked(campaign):
        print(f"  {item['readiness']:24s} {item['priority']:6.2f}  {item['id']}  {item['title']}")
if __name__ == "__main__": main()
