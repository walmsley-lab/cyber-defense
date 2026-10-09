#!/usr/bin/env python3
"""Reconcile offline predicted connectivity with authorized lab observations."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

def reconcile(graph, observations):
    predictions = {(p["from"], p["to"]): p for p in graph.get("paths", [])}
    records = []
    for obs in observations:
        key = (obs["source"], obs["target"])
        path = predictions.get(key)
        predicted = "potentially-reachable" if path else "not-predicted"
        observed = obs["result"]
        if observed not in ("reachable", "blocked", "inconclusive"):
            raise ValueError("Unsupported observation result: " + str(observed))
        if observed == "inconclusive":
            verdict = "unknown"
        elif path and observed == "reachable":
            verdict = "corroborated"
        elif path and observed == "blocked":
            verdict = "prediction-disagrees-with-observation"
        elif not path and observed == "reachable":
            verdict = "unexpected-reachability"
        else:
            verdict = "consistent-block"
        records.append({
            "finding_id": "FIND-%03d" % (len(records) + 1),
            "source": obs["source"], "target": obs["target"],
            "prediction": predicted, "observed": observed,
            "verdict": verdict, "path": path["nodes"] if path else [],
            "evidence": {"method": obs.get("method", "lab-canary-http"),
                         "timestamp": obs.get("timestamp"),
                         "context": obs.get("context"),
                         "http_status": obs.get("http_status")},
            "recommended_next_step": (
                "Investigate missing network or policy constraints" if verdict == "prediction-disagrees-with-observation"
                else "Investigate an unmodeled path; review policy scope" if verdict == "unexpected-reachability"
                else "Review least-privilege segmentation with owner" if verdict == "corroborated"
                else "Collect more evidence" if verdict == "unknown"
                else "Retain and regression-test the restrictive control"),
            "exploit_verified": False
        })
    return {"schema_version": "cyber-defense/findings/v1", "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": records, "summary": {"observations": len(records),
                "discrepancies": sum(r["verdict"] in ("unexpected-reachability", "prediction-disagrees-with-observation") for r in records)}}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--graph", type=Path, required=True)
    p.add_argument("--observations", type=Path, required=True)
    p.add_argument("--out", type=Path, default=Path("findings.json"))
    a = p.parse_args()
    report = reconcile(json.loads(a.graph.read_text()), json.loads(a.observations.read_text())["observations"])
    a.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['summary']['observations']} observations, {report['summary']['discrepancies']} discrepancies -> {a.out}")
if __name__ == "__main__":
    main()
