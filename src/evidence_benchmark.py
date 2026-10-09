"""Convert provenance-bearing, scenario-scoped observations into benchmark predictions.

Requires independent observations, never derives ground truth from a model suggestion.
"""
import argparse
import json
from pathlib import Path
from src.scenario_benchmark import score

ALLOWED_RESULTS={"vulnerable","not-vulnerable","unknown"}
METHODS={"network-canary","rbac-review","tls-inspection","app-canary","ssh-config-review","advisory-review"}

def to_predictions(benchmark, observations, *, run_id):
    cases={c["id"]:c for c in benchmark["cases"]}
    if len(cases)!=len(benchmark["cases"]): raise ValueError("Duplicate benchmark case")
    matched={key:[] for key in cases}
    rejected=[]
    for idx,obs in enumerate(observations):
        case=cases.get(obs.get("case_id"))
        if not case or obs.get("run_id")!=run_id:
            rejected.append({"index":idx,"reason":"unknown-case-or-wrong-run"})
            continue
        if obs.get("method") not in METHODS or not obs.get("evidence_ref") or not isinstance(obs.get("evidence_ref"),str):
            rejected.append({"index":idx,"reason":"missing-independent-method-or-evidence"})
            continue
        if obs.get("result") not in ALLOWED_RESULTS:
            rejected.append({"index":idx,"reason":"invalid-result"})
            continue
        if obs.get("kind")!=case["category"]:
            rejected.append({"index":idx,"reason":"category-mismatch"})
            continue
        if obs.get("source")=="ai-hypothesis":
            rejected.append({"index":idx,"reason":"model-claim-is-not-evidence"})
            continue
        matched[case["id"]].append(obs["result"])
    predictions={}
    for case_id,results in matched.items():
        resolved=set(results)-{"unknown"}
        predictions[case_id]=next(iter(resolved)) if len(resolved)==1 and "unknown" not in results else "unknown"
    return {"run_id":run_id,"predictions":predictions,"rejected":rejected,
            "score":score(benchmark["cases"],predictions),
            "note":"Predictions reflect scoped evidence assertions, not proven real-world exploitability."}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--benchmark",required=True,type=Path)
    p.add_argument("--observations",required=True,type=Path)
    p.add_argument("--run-id",required=True)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    benchmark=json.loads(args.benchmark.read_text())
    observations=json.loads(args.observations.read_text())["observations"]
    result=to_predictions(benchmark,observations,run_id=args.run_id)
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(result["score"]["totals"],"coverage",result["score"]["coverage"])
if __name__=="__main__":main()
