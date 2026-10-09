#!/usr/bin/env python3
"""Compare controlled before/after observations; fail closed on missing evidence."""
import argparse
import json
from pathlib import Path

def compare(before, after):
    a = before["observations"]
    b = after["observations"]
    if len(a) != 1 or len(b) != 1:
        raise ValueError("Exactly one observation is required in each phase")
    x, y = a[0], b[0]
    for key in ("source", "target", "context"):
        if x.get(key) != y.get(key):
            raise ValueError(f"Mismatched {key} between phases")
    success = x["result"] == "reachable" and y["result"] == "blocked"
    return {
        "schema_version": "cyber-defense/comparison/v1",
        "before": x, "after": y,
        "change": "reachability-removed" if success else "not-demonstrated",
        "confirmed_remediation": False,
        "note": "A before/after reachability change is evidence of altered network behavior, not evidence of exploit mitigation. Check CNI policy and legitimate access separately."
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    report = compare(json.loads(a.before.read_text()), json.loads(a.after.read_text()))
    a.out.write_text(json.dumps(report, indent=2) + "\n")
    print(report["change"])
if __name__ == "__main__":
    main()
