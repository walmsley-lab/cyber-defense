"""Evaluate discovered security relationships against labeled disposable-lab cases.

Offline, non-destructive. No exploit commands, remote targets, or LLM calls.
"""
import argparse
import json
from pathlib import Path

def score(cases, predictions):
    by_id={c["id"]:c for c in cases}
    if len(by_id)!=len(cases): raise ValueError("Duplicate case IDs")
    keys=set()
    for c in cases:
        if c.get("expected") not in ("vulnerable","not-vulnerable"):
            raise ValueError("Expected binary ground truth for each benchmark case")
        if not c.get("category") or not c.get("scenario"): raise ValueError("Missing case metadata")
        keys.add(c["id"])
    if set(predictions)-keys: raise ValueError("Predictions contain unknown cases")
    counters={"tp":0,"fp":0,"tn":0,"fn":0,"abstain":0}
    details=[]
    for c in cases:
        observed=predictions.get(c["id"],"unknown")
        if observed not in ("vulnerable","not-vulnerable","unknown"):
            raise ValueError("Invalid prediction")
        truth=c["expected"]
        if observed=="unknown": classification="abstain"
        elif truth=="vulnerable": classification="tp" if observed==truth else "fn"
        else: classification="tn" if observed==truth else "fp"
        counters[classification]+=1
        details.append({"id":c["id"],"category":c["category"],
                        "expected":truth,"predicted":observed,"outcome":classification})
    precision=counters["tp"]/(counters["tp"]+counters["fp"]) if counters["tp"]+counters["fp"] else None
    recall=counters["tp"]/(counters["tp"]+counters["fn"]) if counters["tp"]+counters["fn"] else None
    return {"totals":counters,"precision":precision,"recall":recall,
            "coverage":(len(cases)-counters["abstain"])/len(cases) if cases else 0,
            "details":details}

def compare(benchmark, systems):
    cases=benchmark["cases"]
    outputs={name:score(cases, predictions) for name,predictions in systems.items()}
    return {"schema_version":"cyber-defense/scenario-benchmark/v1",
            "benchmark":benchmark.get("name","unnamed"),
            "systems":outputs,
            "note":"Labeled synthetic cases measure classifier quality, not live exploit success."}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--benchmark",type=Path,required=True)
    p.add_argument("--baseline",type=Path,required=True)
    p.add_argument("--candidate",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    benchmark=json.loads(a.benchmark.read_text())
    systems={"baseline":json.loads(a.baseline.read_text()),
             "candidate":json.loads(a.candidate.read_text())}
    result=compare(benchmark,systems)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    for name,s in result["systems"].items():
        print(name, s["totals"], "precision=",s["precision"],"recall=",s["recall"])
if __name__=="__main__":main()
