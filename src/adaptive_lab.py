"""Evidence-driven campaign validation for an explicitly approved disposable lab.

Built-in checks only. No shell, arbitrary URLs, exploit strings, or model-generated
code execution. Checks consume operator-collected evidence artifacts.
"""
import argparse
import json
from pathlib import Path
from src.campaign import ranked, validate, apply_event
from src.ai_hypotheses import validate_output, CHECKS

# Map AI proposals to bounded, independently testable predicates.
SPECS = {
    "review-rbac": ("rbac", "result", {"allowed"}),
    "inspect-networkpolicy": ("networkpolicy", "isolation", {"present"}),
    "verify-lab-reachability": ("network", "result", {"reachable"}),
    "review-advisory-applicability": ("advisory", "applicable", {True}),
    "inspect-tls-config": ("tls", "certificate_valid", {True}),
    "inspect-ssh-config": ("ssh", "secure", {True}),
    "collect-telemetry": ("telemetry", "complete", {True}),
}

def check(hypothesis, evidence):
    kind, field, expected = SPECS[hypothesis["check"]]
    records = [e for e in evidence if e.get("kind")==kind and
               e.get("source_id") in hypothesis["evidence_ids"]]
    if not records:
        return "inconclusive", "No matching independent observation"
    states=[]
    for record in records:
        if field not in record: continue
        states.append(record[field] in expected)
    if not states: return "inconclusive", "Required observation field unavailable"
    if any(states) and not all(states): return "inconclusive", "Contradictory observations"
    return ("passed", "Check predicate observed") if all(states) else ("failed", "Check predicate disproven")

def generate_campaign(hypotheses):
    actions=[]
    for i,h in enumerate(hypotheses["hypotheses"],1):
        actions.append({"id":f"hyp-{i:03d}","title":h["claim"][:110],
                        "check":h["check"],"evidence_ids":h["evidence_ids"],
                        "impact":2,"confidence":0.5,"information_gain":2,"cost":1})
    campaign={"name":"AI proposals awaiting evidence","actions":actions}
    validate(campaign)
    return campaign

def evaluate(hypotheses, evidence, *, budget=20):
    if not 1<=budget<=20: raise ValueError("Budget must be 1..20")
    evidence_ids={str(e.get("source_id")) for e in evidence if e.get("source_id") is not None}
    # Input hypothesis IDs are validated against an operator-approved evidence catalog.
    validate_output(hypotheses,evidence_ids)
    campaign=generate_campaign(hypotheses)
    events=[]
    for candidate in ranked(campaign)[:budget]:
        action=next(a for a in campaign["actions"] if a["id"]==candidate["id"])
        state, explanation=check(action,evidence)
        event={"action_id":action["id"],"status":state,
               "evidence":action["evidence_ids"],"explanation":explanation,
               "method":"bounded-artifact-validation"}
        apply_event(campaign,event)
        events.append(event)
    return {"campaign":campaign,"events":events,"remaining":ranked(campaign),
            "summary":{"passed":sum(e["status"]=="passed" for e in events),
                       "failed":sum(e["status"]=="failed" for e in events),
                       "inconclusive":sum(e["status"]=="inconclusive" for e in events)},
            "limitations":"Artifact-backed tests are not proof of an actual exploit chain."}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--hypotheses",type=Path,required=True)
    p.add_argument("--evidence",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--budget",type=int,default=20)
    a=p.parse_args()
    result=evaluate(json.loads(a.hypotheses.read_text()),
                    json.loads(a.evidence.read_text())["observations"],budget=a.budget)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print(result["summary"])
if __name__=="__main__":main()
