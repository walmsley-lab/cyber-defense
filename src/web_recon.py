"""Passive HTTP recon that turns observed response metadata into a discovery snapshot.

Non-intrusive by design: one GET per URL, headers/status only, no payloads, no
authentication, no crawling. The emitted snapshot feeds discovery.py unchanged.
"""
import argparse
import json
import urllib.request
from pathlib import Path

SECURITY_HEADERS=("content-security-policy","strict-transport-security","x-frame-options",
                  "x-content-type-options","referrer-policy","permissions-policy")

def build_snapshot(url,status,headers,final_url=None):
    """Pure mapping from observed response metadata to a discovery-compatible snapshot."""
    lowered={str(k).lower():str(v) for k,v in dict(headers).items()}
    asset=final_url or url
    scheme=asset.split("://",1)[0].lower()
    tls={"id":asset,"source":url,
         "redirect_http_to_https":(scheme=="https") or bool(final_url and final_url.lower().startswith("https://")),
         "hsts":"strict-transport-security" in lowered}
    if scheme!="https":
        tls["min_tls"]="none-plaintext-http"
    web={"id":asset,"source":url,"status":status,
         "headers":{k:lowered[k] for k in lowered if k in SECURITY_HEADERS
                    or k in ("server","access-control-allow-origin")}}
    return {"tls_observations":[tls],"web_observations":[web]}

def fetch(url,timeout=20):
    req=urllib.request.Request(url,method="GET",headers={"User-Agent":"cyber-defense-web-recon/1"})
    with urllib.request.urlopen(req,timeout=timeout) as resp:
        return resp.getcode(),resp.headers.items(),resp.geturl()

def recon(url,timeout=20):
    status,headers,final_url=fetch(url,timeout=timeout)
    return build_snapshot(url,status,headers,final_url)

def main():
    ap=argparse.ArgumentParser(description="Passive HTTP recon -> discovery snapshot (metadata only).")
    ap.add_argument("--url",required=True)
    ap.add_argument("--out",default="web-recon-snapshot.json",type=Path)
    ap.add_argument("--timeout",type=int,default=20)
    args=ap.parse_args()
    snapshot=recon(args.url,timeout=args.timeout)
    args.out.write_text(json.dumps(snapshot,indent=2)+"\n")
    print(f"{len(snapshot['web_observations'])} web observation(s) -> {args.out}")
if __name__=="__main__":main()
