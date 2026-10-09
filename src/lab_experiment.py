"""Reproducible *authorized disposable-lab* policy experiment.

Fixed-scoped orchestrator, not a general exploit runner. Requires explicit consent.
"""
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from src.lab_evidence import measure, CONTEXT
from src.rbac_canary import check_access
from src.lab_compare import compare
from src.chain_evidence import combine

def execute(argv, *, timeout=90):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout)

def experiment(outdir, *, command=execute, network=measure, authorization=check_access):
    current=command(["kubectl","config","current-context"],timeout=10).stdout.strip()
    if current!=CONTEXT:
        raise RuntimeError(f"Refusing context {current!r}; required {CONTEXT}")
    outdir=Path(outdir)
    if outdir.exists() and any(outdir.iterdir()):
        raise FileExistsError("Choose a new empty output directory: " + str(outdir))
    outdir.mkdir(parents=True,exist_ok=True)
    def kubectl(*args):
        return command(["kubectl","--context",CONTEXT,*args],timeout=90)
    def save(name, value):
        (outdir/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
    # All mutations target objects named in owned lab manifests.
    kubectl("apply","-f","lab/manifests.yaml")
    kubectl("apply","-f","lab/rbac-honeypot.yaml")
    kubectl("-n","cyber-lab","rollout","status","deployment/frontend","--timeout=120s")
    kubectl("-n","cyber-lab","rollout","status","deployment/canary","--timeout=120s")
    kubectl("-n","cyber-lab","delete","networkpolicy","canary-deny-ingress","--ignore-not-found")
    baseline_net=network()
    baseline_auth=authorization()
    save("baseline-network.json",{"observations":[baseline_net]})
    save("baseline-auth.json",baseline_auth)
    kubectl("apply","-f","lab/policies/restrict.yaml")
    kubectl("-n","cyber-lab","delete","rolebinding","honeypot-canary-reader","--ignore-not-found")
    restricted_net=network()
    restricted_auth=authorization()
    save("restricted-network.json",{"observations":[restricted_net]})
    save("restricted-auth.json",restricted_auth)
    report={
        "schema_version":"cyber-defense/lab-experiment/v1",
        "timestamp":datetime.now(timezone.utc).isoformat(),
        "context":CONTEXT,
        "network_comparison":compare({"observations":[baseline_net]},{"observations":[restricted_net]}),
        "baseline_chain":combine({"observations":[baseline_net]},baseline_auth),
        "restricted_chain":combine({"observations":[restricted_net]},restricted_auth),
        "interpretation":"Prerequisite observations only. No exploitation or end-to-end chain traversal verified.",
        "environment_left_restricted":True
    }
    save("report.json",report)
    return report

def main():
    parser=argparse.ArgumentParser(description="Two-phase authorized kind lab assessment")
    parser.add_argument("--i-own-this-lab",action="store_true",required=True)
    parser.add_argument("--outdir",type=Path,required=True)
    args=parser.parse_args()
    result=experiment(args.outdir)
    print("Network:",result["network_comparison"]["change"])
    print("Before:",result["baseline_chain"]["state"],"After:",result["restricted_chain"]["state"])
    print("Saved:",args.outdir,"; lab remains restricted")
if __name__=="__main__":main()
