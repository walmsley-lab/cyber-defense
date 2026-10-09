#!/usr/bin/env python3
"""Single, allowlisted Kubernetes canary observation with structured evidence.

Only connects to a fixed service inside a disposable kind-cyber-defense lab.
This is NOT an exploitation or arbitrary target scanning facility.
"""
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CONTEXT = "kind-cyber-defense"
NAMESPACE = "cyber-lab"
TARGET = "http://canary.cyber-lab.svc.cluster.local:8080/"
SOURCE_LABEL = "app=frontend"

def kubectl(*args, timeout=30, check=True):
    command = ["kubectl", "--context", CONTEXT, *args]
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=check)

def measure():
    current = subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if current != CONTEXT:
        raise RuntimeError(f"Refusing unexpected context {current!r}; required {CONTEXT!r}")
    pods = json.loads(kubectl("-n", NAMESPACE, "get", "pods", "-l", SOURCE_LABEL, "-o", "json").stdout)["items"]
    ready = [p for p in pods if p.get("status", {}).get("phase") == "Running" and
             all(s.get("ready", False) for s in p.get("status", {}).get("containerStatuses", []))]
    if not ready:
        raise RuntimeError("No running, ready lab frontend pod found")
    pod = sorted(ready, key=lambda p: p["metadata"]["name"])[0]["metadata"]["name"]
    source = f"pod:{NAMESPACE}/{pod}"
    target = None
    canaries = json.loads(kubectl("-n", NAMESPACE, "get", "pods", "-l", "app=canary", "-o", "json").stdout)["items"]
    if len(canaries) != 1:
        raise RuntimeError("Expected exactly one canary pod")
    target = f"pod:{NAMESPACE}/{canaries[0]['metadata']['name']}"
    result = kubectl("-n", NAMESPACE, "exec", pod, "-c", "client", "--",
                     "curl", "--silent", "--show-error", "--max-time", "3",
                     "--output", "/dev/null", "--write-out", "%{http_code}", TARGET,
                     timeout=12, check=False)
    status = result.stdout.strip()
    http_status = int(status) if status.isdecimal() else None
    if result.returncode == 0 and http_status is not None and 200 <= http_status < 400:
        state = "reachable"
    elif result.returncode == 28:
        state = "blocked"  # Observed timeout, not proof NetworkPolicy is the cause.
    else:
        state = "inconclusive"
    return {"source": source, "target": target, "result": state,
            "method": "lab-canary-http", "timestamp": datetime.now(timezone.utc).isoformat(),
            "context": CONTEXT, "namespace": NAMESPACE, "http_status": http_status,
            "exit_code": result.returncode, "diagnostic": result.stderr[-500:],
            "interpretation": "Timeout does not establish which network control caused failure."}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--i-own-this-lab", action="store_true", required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    observation = measure()
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"schema_version": "cyber-defense/observations/v1", "observations": [observation]}, indent=2) + "\n")
    print(f"{observation['result']}: {observation['source']} -> {observation['target']}; saved {a.out}")

if __name__ == "__main__":
    main()
