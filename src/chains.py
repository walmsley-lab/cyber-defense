"""Evidence-labeled, offline multi-step security path reasoning for lab scenarios."""
import argparse
import json
from collections import deque
from pathlib import Path

ALLOWED = {"network", "identity", "permission", "asset-access"}
MAX_DEPTH = 10

def analyze(scenario):
    assets = {a["id"]: a for a in scenario["assets"]}
    edges = scenario["relationships"]
    if len(assets) > 5000 or len(edges) > 20000:
        raise ValueError("Scenario exceeds bounds")
    adjacency = {a: [] for a in assets}
    for e in edges:
        if e["from"] not in assets or e["to"] not in assets:
            raise ValueError("Unknown graph endpoint")
        if e["type"] not in ALLOWED:
            raise ValueError("Unknown relationship type")
        if e.get("state") not in ("configuration-supported", "observed", "lab-validated", "hypothesis"):
            raise ValueError("Missing or unsupported evidence state")
        adjacency[e["from"]].append(e)
    paths = []
    for entry in scenario.get("entrypoints", []):
        if entry not in assets:
            raise ValueError("Unknown entrypoint")
        queue = deque([(entry, [], {entry})])
        while queue:
            current, path, visited = queue.popleft()
            if assets[current].get("protected") and path:
                paths.append({
                    "entrypoint": entry, "target": current,
                    "steps": [{"from": e["from"], "to": e["to"], "type": e["type"],
                               "state": e["state"], "rationale": e.get("rationale", ""),
                               "source": e.get("source", "")} for e in path],
                    "status": "candidate",
                    "fully_lab_validated": all(e["state"] == "lab-validated" for e in path),
                    "note": "Connectivity or permissions do not alone establish exploitability."
                })
                continue
            if len(path) >= MAX_DEPTH:
                continue
            for edge in adjacency[current]:
                if edge["to"] not in visited:
                    queue.append((edge["to"], path + [edge], visited | {edge["to"]}))
    paths.sort(key=lambda p: (len(p["steps"]), p["entrypoint"], p["target"]))
    return {"environment": scenario.get("environment", "synthetic"), "paths": paths,
            "metrics": {"candidate_paths": len(paths),
                        "multi_step_paths": sum(len(p["steps"]) >= 3 for p in paths),
                        "fully_lab_validated": sum(p["fully_lab_validated"] for p in paths)}}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--out", type=Path, default=Path("chain-report.json"))
    args = parser.parse_args()
    result = analyze(json.loads(args.scenario.read_text()))
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(result["metrics"])

if __name__ == "__main__":
    main()
