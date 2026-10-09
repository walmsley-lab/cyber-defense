"""Read-only Kubernetes RBAC graph and synthetic honeypot access assessment."""
import argparse
import json
import subprocess
from pathlib import Path

def named(obj):
    m=obj.get("metadata",{})
    return m.get("namespace","default"),m.get("name","")

def assess(snapshot):
    pods=snapshot.get("pods",{}).get("items",[])
    roles=snapshot.get("roles",{}).get("items",[])
    clusterroles=snapshot.get("clusterroles",{}).get("items",[])
    bindings=snapshot.get("rolebindings",{}).get("items",[])+snapshot.get("clusterrolebindings",{}).get("items",[])
    role_index={(r["kind"],)+named(r):r for r in roles+clusterroles}
    findings=[]
    for pod in pods:
        ns,pname=named(pod)
        labels=pod.get("metadata",{}).get("labels",{})
        if labels.get("cyber-defense/entrypoint")!="true":continue
        sa=pod.get("spec",{}).get("serviceAccountName","default")
        token=pod.get("spec",{}).get("automountServiceAccountToken",None)
        # This is only a potential credential route if token mounting was not explicitly disabled.
        if token is False:continue
        for binding in bindings:
            bns,bname=named(binding)
            is_cluster=binding.get("kind")=="ClusterRoleBinding"
            if not is_cluster and bns!=ns:continue
            if not any(s.get("kind")=="ServiceAccount" and s.get("name")==sa and s.get("namespace",bns)==ns for s in binding.get("subjects",[])):continue
            ref=binding.get("roleRef",{})
            role_ns="default" if ref.get("kind")=="ClusterRole" else bns
            role=role_index.get((ref.get("kind"),role_ns,ref.get("name")))
            # ClusterRole objects are cluster-scoped, namespace defaults to default in index.
            if not role:continue
            for rule in role.get("rules",[]):
                if ("secrets" in rule.get("resources",[]) or "*" in rule.get("resources",[])) and ("get" in rule.get("verbs",[]) or "*" in rule.get("verbs",[])):
                    findings.append({"entrypoint":f"pod:{ns}/{pname}","identity":f"sa:{ns}/{sa}",
                      "grant":f"{binding.get('kind')}:{bns}/{bname}",
                      "role":f"{ref.get('kind')}:{ref.get('name')}",
                      "target":f"secrets:{'cluster' if is_cluster else ns}",
                      "state":"configuration-supported",
                      "claim":"Potential read permission to secrets; does not prove code execution or credential compromise."})
    return {"schema_version":"cyber-defense/honeypot-assessment/v1","paths":findings,"exploit_verified":False}

def acquire():
    result={}
    for item in ("pods","roles","clusterroles","rolebindings","clusterrolebindings"):
        output=subprocess.check_output(["kubectl","get",item,"-A","-o","json"],text=True,timeout=30)
        result[item]=json.loads(output)
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--snapshot",type=Path)
    parser.add_argument("--out",type=Path,default=Path("honeypot-report.json"))
    args=parser.parse_args()
    snapshot=json.loads(args.snapshot.read_text()) if args.snapshot else acquire()
    report=assess(snapshot)
    args.out.write_text(json.dumps(report,indent=2)+"\n")
    print(f"{len(report['paths'])} candidate identity-to-canary paths -> {args.out}")
if __name__=="__main__":main()
