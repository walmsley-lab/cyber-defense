"""Offline security configuration checks for authorized Kubernetes labs."""
import argparse
import json
from collections import defaultdict
from pathlib import Path

def inspect(snapshot):
    resources=snapshot.get("resources",[])
    grouped=defaultdict(list)
    for r in resources: grouped[r.get("kind","")].append(r)
    findings=[]
    def emit(rule,obj,why,evidence):
        findings.append({"rule":rule,"asset":obj.get("metadata",{}).get("name"),"reason":why,
                         "evidence":evidence,"state":"configuration-supported","exploit_verified":False})
    for p in grouped["Pod"]:
        labels=p.get("metadata",{}).get("labels",{})
        spec=p.get("spec",{})
        ns=p.get("metadata",{}).get("namespace","default")
        if labels.get("cyber-defense/protected")=="true":
            selected=False
            for policy in grouped["NetworkPolicy"]:
                ps=policy.get("spec",{})
                if policy.get("metadata",{}).get("namespace","default")!=ns: continue
                if "Ingress" not in ps.get("policyTypes",["Ingress"]): continue
                selector=ps.get("podSelector",{})
                match=selector.get("matchLabels",{})
                if not selector or (not selector.get("matchExpressions") and all(labels.get(k)==v for k,v in match.items())):
                    selected=True
            if not selected: emit("K8S-NET-001",p,"Protected pod lacks ingress-isolating NetworkPolicy",{"namespace":ns})
        if spec.get("automountServiceAccountToken") is True:
            emit("K8S-ID-001",p,"Service account token explicitly auto-mounted",{"namespace":ns})
        for c in spec.get("containers",[]):
            if c.get("securityContext",{}).get("privileged") is True:
                emit("K8S-POD-001",p,"Privileged container",{"container":c.get("name")})
    for s in grouped["Service"]:
        if s.get("spec",{}).get("type") in ("NodePort","LoadBalancer"):
            emit("K8S-NET-002",s,"Potential external exposure, not proof of internet reachability",{"type":s["spec"]["type"]})
    for role in grouped["Role"]+grouped["ClusterRole"]:
        for index,rule in enumerate(role.get("rules",[])):
            if {"*","secrets","roles","clusterroles","rolebindings","clusterrolebindings"} & set(rule.get("resources",[])) and set(rule.get("verbs",[])):
                emit("K8S-RBAC-001",role,"Sensitive resource permissions; bindings not evaluated",
                     {"rule":index,"resources":rule.get("resources"),"verbs":rule.get("verbs")})
    findings.sort(key=lambda f:(f["rule"],f["asset"] or ""))
    for i,f in enumerate(findings,1): f["id"]=f"FIND-{i:03d}"
    return {"schema_version":"cyber-defense/attacker-findings/v1",
            "environment":snapshot.get("environment","unknown"),
            "findings":findings,"counts":{"resources":len(resources),"findings":len(findings)},
            "limitations":["Static checks, not exploitation","Network reachability, RBAC bindings and CNI enforcement not evaluated"]}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("snapshot",type=Path)
    p.add_argument("--out",type=Path,default=Path("attacker-report.json"))
    a=p.parse_args()
    report=inspect(json.loads(a.snapshot.read_text()))
    a.out.write_text(json.dumps(report,indent=2)+"\n")
    print(f"{report['counts']['resources']} resources; {report['counts']['findings']} findings -> {a.out}")
if __name__=="__main__": main()
