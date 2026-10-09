"""Optional AI-assisted triage of sanitized defensive findings.

No model-proposed commands are executed. Output is untrusted hypotheses requiring verification.
"""
import argparse
import json
import os
from pathlib import Path

CHECKS={"review-rbac","inspect-networkpolicy","verify-lab-reachability",
        "review-advisory-applicability","inspect-tls-config","inspect-ssh-config",
        "collect-telemetry"}
SYSTEM=("You are a defensive security analyst for an authorized test lab. "
        "Using only supplied evidence, suggest plausible missing relationships, "
        "alternative explanations and non-destructive verification steps. "
        "Never propose executable commands, exploit payloads, privilege escalation "
        "procedures or accessing secrets. Return a JSON object with 'hypotheses' "
        "as a list of objects: 'claim' (string), 'evidence_ids' (array of IDs), "
        "'check' (one of approved check names), 'reason' (string). "
        "Do not assert that hypotheses are facts.")

def validate_output(raw, allowed_ids):
    if not isinstance(raw,dict) or not isinstance(raw.get("hypotheses"),list):
        raise ValueError("Invalid hypothesis document")
    if len(raw["hypotheses"])>20: raise ValueError("Too many hypotheses")
    result=[]
    for h in raw["hypotheses"]:
        if not isinstance(h,dict) or h.get("check") not in CHECKS:
            raise ValueError("Unsupported proposed check")
        ids=h.get("evidence_ids",[])
        if not isinstance(ids,list) or any(not isinstance(i,str) or i not in allowed_ids for i in ids):
            raise ValueError("Ungrounded evidence ID")
        claim,reason=h.get("claim"),h.get("reason")
        if not all(isinstance(s,str) and 0<len(s)<=700 for s in (claim,reason)):
            raise ValueError("Invalid text length")
        result.append({"claim":claim,"reason":reason,"evidence_ids":ids,
                       "check":h["check"],"state":"hypothesis","executable":False})
    return {"schema_version":"cyber-defense/ai-hypotheses/v1","hypotheses":result}

def propose(source, client, model):
    findings=source.get("findings",[])
    sanitized=[]
    for i,f in enumerate(findings[:40]):
        # Strict allowlist avoids exfiltrating raw logs, tokens, PII or diagnostic text.
        sanitized.append({"id":f.get("id",f"E-{i+1}"),"rule":f.get("rule"),
                          "asset_kind":f.get("asset_kind","unspecified"),
                          "state":f.get("state"),"summary":str(f.get("detail",f.get("reason","")))[:240]})
    ids={str(x["id"]) for x in sanitized}
    response=client.responses.create(model=model,instructions=SYSTEM,
        input="Analyze these **untrusted, synthetic/authorized** finding summaries only. Return JSON, nothing else:\n"+json.dumps(sanitized),
        max_output_tokens=1200)
    raw=json.loads(response.output_text)
    return validate_output(raw,ids)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--findings",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--model",required=True,help="Model selected by operator")
    p.add_argument("--allow-api",action="store_true",help="Explicitly permit sending sanitized finding summaries")
    args=p.parse_args()
    if not args.allow_api: raise SystemExit("API disabled; pass --allow-api after reviewing the input")
    if not os.getenv("OPENAI_API_KEY"): raise SystemExit("OPENAI_API_KEY is not set")
    from openai import OpenAI
    data=json.loads(args.findings.read_text())
    result=propose(data,OpenAI(),args.model)
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(f"{len(result['hypotheses'])} unverified hypotheses -> {args.out}")
if __name__=="__main__":main()
