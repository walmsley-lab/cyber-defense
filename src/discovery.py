"""Offline defensive discovery over supplied inventories, TLS facts, SSH configs and OSV records."""
import argparse
import json
from pathlib import Path

def discover(data):
    findings=[]
    def emit(rule,asset,detail,evidence,confidence="configuration-supported"):
        findings.append({"id":f"D-{len(findings)+1:03d}","rule":rule,"asset":asset,
            "detail":detail,"evidence":evidence,"state":confidence,"exploit_verified":False})
    advisories=data.get("advisories",[])
    for package in data.get("packages",[]):
        for advisory in advisories:
            for affected in advisory.get("affected",[]):
                p=affected.get("package",{})
                if (p.get("ecosystem"),p.get("name"))!=(package.get("ecosystem"),package.get("name")):
                    continue
                if package.get("version") in affected.get("versions",[]):
                    emit("OSV-EXACT",package.get("name"),"Installed version listed in advisory",
                        {"advisory":advisory.get("id"),"version":package.get("version")})
                elif affected.get("ranges") and not affected.get("versions"):
                    emit("OSV-REVIEW",package.get("name"),"Advisory contains version ranges requiring ecosystem-aware resolution",
                         {"advisory":advisory.get("id"),"version":package.get("version")},"needs-review")
    for endpoint in data.get("tls_observations",[]):
        asset=endpoint.get("id","unknown")
        if endpoint.get("verified") is False:
            emit("TLS-TRUST",asset,"TLS certificate validation failed",{"source":endpoint.get("source")})
        if endpoint.get("redirect_http_to_https") is False:
            emit("TLS-REDIRECT",asset,"HTTP-to-HTTPS redirect missing",{"source":endpoint.get("source")})
        if endpoint.get("hsts") is False:
            emit("TLS-HSTS",asset,"HSTS absent",{"source":endpoint.get("source")})
        if endpoint.get("min_tls") in ("TLSv1","TLSv1.0","TLSv1.1"):
            emit("TLS-LEGACY",asset,"Legacy TLS protocol observed",{"min_tls":endpoint.get("min_tls")})
    for server in data.get("ssh_configurations",[]):
        asset=server.get("id","unknown")
        options={str(k).lower():str(v).lower() for k,v in server.get("options",{}).items()}
        if options.get("permitrootlogin")=="yes":
            emit("SSH-ROOT",asset,"Direct root login enabled",{"option":"PermitRootLogin"})
        if options.get("passwordauthentication")=="yes":
            emit("SSH-PASSWORD",asset,"Password authentication explicitly enabled",{"option":"PasswordAuthentication"})
        if options.get("allowtcpforwarding")=="yes":
            emit("SSH-FORWARD",asset,"Unrestricted TCP forwarding may cross trust boundaries",{"option":"AllowTcpForwarding"})
    return {"schema_version":"cyber-defense/discovery/v1","findings":findings,
        "note":"Configuration/advisory indicators only; no exploit attempts or external probes performed."}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",required=True,type=Path)
    ap.add_argument("--out",default="discovery.json",type=Path)
    args=ap.parse_args()
    result=discover(json.loads(args.input.read_text()))
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(f"{len(result['findings'])} findings -> {args.out}")
if __name__=="__main__":main()
