"""Join independent lab network and authorization evidence without overstating exploitation."""
import argparse
import json
from pathlib import Path

def combine(network, authorization):
    rows=network.get("observations",[])
    if len(rows)!=1: raise ValueError("Exactly one network observation required")
    net=rows[0]
    if net.get("context")!="kind-cyber-defense" or authorization.get("context")!="kind-cyber-defense":
        raise ValueError("Only the expected disposable lab context is supported")
    if net.get("target","").split("/")[-1].split("-")[0]!="canary":
        raise ValueError("Expected canary target")
    if authorization.get("principal")!="system:serviceaccount:cyber-lab:honeypot-reader":
        raise ValueError("Unexpected test principal")
    if authorization.get("resource")!="configmaps" or authorization.get("resource_name")!="honeypot-canary":
        raise ValueError("Authorization test is not the expected harmless canary")
    reachable=net.get("result")=="reachable"
    authorized=authorization.get("result")=="allowed"
    if net.get("result") not in ("reachable","blocked","inconclusive"): raise ValueError("Unknown network result")
    if authorization.get("result") not in ("allowed","denied","inconclusive"): raise ValueError("Unknown authorization result")
    if reachable and authorized: state="both-prerequisites-observed"
    elif net.get("result")=="blocked" or authorization.get("result")=="denied": state="prerequisite-denied"
    else: state="indeterminate"
    return {"schema_version":"cyber-defense/chain-evidence/v1",
            "environment":"kind-cyber-defense",
            "state":state,
            "network":{"source":net.get("source"),"target":net.get("target"),
                       "result":net["result"],"timestamp":net.get("timestamp")},
            "authorization":{"principal":authorization["principal"],
                             "resource":"configmaps/honeypot-canary",
                             "result":authorization["result"],
                             "timestamp":authorization.get("timestamp")},
            "exploit_verified":False,
            "limitations":["Network access and RBAC authorization are separate prerequisites.",
                           "No evidence a network-facing application yields control of the privileged identity.",
                           "This is not proof of a complete attack chain or compromise."]}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--network",type=Path,required=True)
    p.add_argument("--authorization",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    result=combine(json.loads(a.network.read_text()),json.loads(a.authorization.read_text()))
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print(result["state"])

if __name__=="__main__": main()
