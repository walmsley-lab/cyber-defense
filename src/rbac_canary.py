"""Bounded Kubernetes RBAC authorization check for a fixed synthetic ConfigMap."""
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CONTEXT="kind-cyber-defense"
NAMESPACE="cyber-lab"
PRINCIPAL="system:serviceaccount:cyber-lab:honeypot-reader"
RESOURCE="configmaps"
NAME="honeypot-canary"

def command(args,timeout=15):
    return subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=True).stdout.strip()

def parse_review(review):
    status=review.get("status",{})
    if status.get("evaluationError"):
        return "inconclusive"
    if status.get("allowed") is True:
        return "allowed"
    if status.get("denied") is True or status.get("allowed") is False:
        return "denied"
    return "inconclusive"

def check_access():
    current=command(["kubectl","config","current-context"])
    if current!=CONTEXT:
        raise RuntimeError("Refusing unexpected Kubernetes context: "+current)
    # kubectl auth can-i performs an authorization review; no ConfigMap data is retrieved.
    result=command(["kubectl","--context",CONTEXT,"auth","can-i","get",RESOURCE,
                    "--resource-name",NAME,"--namespace",NAMESPACE,
                    "--as",PRINCIPAL],timeout=15).lower()
    if result not in ("yes","no"):
        raise RuntimeError("Unrecognized authorization response")
    return {"schema_version":"cyber-defense/rbac-canary/v1",
            "timestamp":datetime.now(timezone.utc).isoformat(),
            "context":CONTEXT,"principal":PRINCIPAL,"resource":RESOURCE,
            "resource_name":NAME,"namespace":NAMESPACE,
            "permission":"get","result":"allowed" if result=="yes" else "denied",
            "method":"SubjectAccessReview-via-kubectl-auth-can-i",
            "limitations":["Checks Kubernetes authorization only; does not execute as the workload.",
                           "Not evidence of network access, stolen tokens, or exploitation."]}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--i-own-this-lab",action="store_true",required=True)
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args()
    result=check_access()
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(result["result"],args.out)

if __name__=="__main__":main()
