"""Repeatable, offline assessment campaign executor for deterministic lab fixtures.

The runner only invokes internal, allowlisted fixture predicates; it never executes
shell commands, performs network requests, or handles arbitrary plugin code.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from src.campaign import ranked, validate, apply_event

def fixture_check(action, fixture):
    rule = action.get("check")
    if not isinstance(rule, dict) or rule.get("kind") != "fixture-equals":
        return "inconclusive", "No approved fixture predicate"
    key, expected = rule.get("key"), rule.get("equals")
    if not isinstance(key, str) or key not in fixture:
        return "inconclusive", "Fixture field unavailable"
    return ("passed", "Fixture condition matched") if fixture[key] == expected else ("failed", "Fixture condition did not match")

def run_once(template, fixture, run_id):
    campaign=json.loads(json.dumps(template))
    validate(campaign)
    events=[]
    completed=set()
    while True:
        candidates=[a for a in ranked(campaign) if a["readiness"]=="ready"]
        if not candidates: break
        choice=candidates[0]
        action=next(a for a in campaign["actions"] if a["id"]==choice["id"])
        outcome, explanation=fixture_check(action, fixture)
        event={"run_id":run_id,"action_id":action["id"],"status":outcome,
               "method":"offline-fixture-equals","explanation":explanation,
               "sequence":len(events)+1}
        apply_event(campaign,event)
        events.append(event)
        completed.add(action["id"])
    final={a["id"]:a.get("status","pending") for a in campaign["actions"]}
    return {"run_id":run_id,"events":events,"states":final,
            "passed":sum(x=="passed" for x in final.values()),
            "failed":sum(x=="failed" for x in final.values()),
            "inconclusive":sum(x=="inconclusive" for x in final.values()),
            "waiting":sum(x=="pending" for x in final.values())}

def run_batch(template, fixture, repetitions):
    if not 1 <= repetitions <= 100: raise ValueError("Repetitions must be 1..100")
    fingerprint=hashlib.sha256(json.dumps({"campaign":template,"fixture":fixture},sort_keys=True).encode()).hexdigest()
    runs=[run_once(template,fixture,i+1) for i in range(repetitions)]
    return {"schema_version":"cyber-defense/campaign-batch/v1",
            "mode":"offline-deterministic-fixture","fingerprint":fingerprint,
            "created_at":datetime.now(timezone.utc).isoformat(),"runs":runs,
            "summary":{"repetitions":repetitions,
                       "steps_per_run":[len(r["events"]) for r in runs],
                       "fully_passed_runs":sum(all(x=="passed" for x in r["states"].values()) for r in runs),
                       "note":"Repeated deterministic fixtures check regression/replay, not real-world attack reliability."}}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--campaign",type=Path,required=True)
    p.add_argument("--fixture",type=Path,required=True)
    p.add_argument("--repeat",type=int,default=3)
    p.add_argument("--out",type=Path,default=Path("campaign-batch.json"))
    p.add_argument("--events",type=Path,default=Path("campaign-batch.jsonl"))
    args=p.parse_args()
    result=run_batch(json.loads(args.campaign.read_text()),json.loads(args.fixture.read_text()),args.repeat)
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    with args.events.open("w") as stream:
        for run in result["runs"]:
            for event in run["events"]:
                stream.write(json.dumps(event,sort_keys=True)+"\n")
    print(f"{result['summary']['repetitions']} runs; {result['summary']['fully_passed_runs']} fully passing; fingerprint {result['fingerprint'][:12]}")
if __name__=="__main__": main()
