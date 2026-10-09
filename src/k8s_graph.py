#!/usr/bin/env python3
"""Read-only, simplified Kubernetes service exposure analyzer.

Does not send packets. NetworkPolicy interpretation is intentionally conservative:
only simple ingress policies with podSelector and namespaceSelector are supported.
Unsupported policy constructs make results indeterminate, never 'allowed'.
"""
import argparse
import json
import subprocess
from collections import deque
from pathlib import Path

def labels_match(actual, selector):
    return all(actual.get(k) == v for k, v in selector.items())

def metadata(obj):
    m = obj.get("metadata", {})
    return m.get("namespace", "default"), m.get("name", ""), m.get("labels", {})

def permits(source, dest, policies, namespaces):
    """Classify source->dest ingress as 'allowed', 'denied' or 'indeterminate'.

    Unmodeled policy constructs (port-scoped rules, ipBlock peers) are reported
    as 'indeterminate' rather than dropped: for a path finder, silently removing
    a possibly-real edge is a false negative, the dangerous direction. A bounded
    probe is what promotes an indeterminate edge to observed or prunes it.
    """
    d_ns, _, d_labels = metadata(dest)
    s_ns, _, s_labels = metadata(source)
    relevant = []
    for policy in policies:
        p_ns, _, _ = metadata(policy)
        spec = policy.get("spec", {})
        types = spec.get("policyTypes", ["Ingress"])
        if p_ns == d_ns and "Ingress" in types and labels_match(d_labels, spec.get("podSelector", {}).get("matchLabels", {})):
            relevant.append(spec)
    if not relevant:
        return "allowed"
    indeterminate = False
    for spec in relevant:
        for rule in spec.get("ingress", []):
            port_scoped = "ports" in rule  # We don't model ports; can't confirm the service port.
            if "from" not in rule:  # Allow from all sources.
                if port_scoped:
                    indeterminate = True
                    continue
                return "allowed"
            matched = False
            for peer in rule["from"]:
                if "ipBlock" in peer:
                    indeterminate = True  # Source is a pod, not a CIDR we can evaluate.
                    continue
                if "namespaceSelector" in peer:
                    wanted_ns = peer["namespaceSelector"].get("matchLabels", {})
                    if not labels_match(namespaces.get(s_ns, {}), wanted_ns):
                        continue
                elif s_ns != d_ns:
                    continue
                if "podSelector" in peer and not labels_match(s_labels, peer["podSelector"].get("matchLabels", {})):
                    continue
                matched = True
                break
            if matched:
                if port_scoped:
                    indeterminate = True
                else:
                    return "allowed"
    return "indeterminate" if indeterminate else "denied"

def analyze(snapshot):
    pods = snapshot.get("pods", {}).get("items", [])
    services = snapshot.get("services", {}).get("items", [])
    policies = snapshot.get("networkpolicies", {}).get("items", [])
    namespaces = {n["metadata"]["name"]: n.get("metadata", {}).get("labels", {})
                  for n in snapshot.get("namespaces", {}).get("items", [])}
    vertices = {}
    for pod in pods:
        ns, name, labels = metadata(pod)
        vertices[f"pod:{ns}/{name}"] = {"type": "pod", "namespace": ns, "name": name,
            "protected": labels.get("cyber-defense/protected") == "true"}
    for service in services:
        ns, name, _ = metadata(service)
        vertices[f"svc:{ns}/{name}"] = {"type": "service", "namespace": ns, "name": name}
    edges = []
    for service in services:
        ns, name, _ = metadata(service)
        selector = service.get("spec", {}).get("selector", {})
        if not selector:
            continue
        targets = [pod for pod in pods if metadata(pod)[0] == ns and
                   labels_match(metadata(pod)[2], selector)]
        for target in targets:
            target_key = "pod:%s/%s" % metadata(target)[:2]
            edges.append({"from": f"svc:{ns}/{name}", "to": target_key,
                          "relation": "SELECTS", "evidence": "service-selector"})
            for source in pods:
                source_key = "pod:%s/%s" % metadata(source)[:2]
                if source_key == target_key:
                    continue
                verdict = permits(source, target, policies, namespaces)
                if verdict == "denied":
                    continue
                edges.append({"from": source_key, "to": f"svc:{ns}/{name}",
                              "relation": "POTENTIAL_REACHABILITY",
                              "evidence": "simplified-ingress-policy",
                              "confidence": "indeterminate" if verdict == "indeterminate"
                                            else "configuration-supported"})
    edge_conf = {(e["from"], e["to"]): e.get("confidence", "configuration-supported") for e in edges}
    adj = {n: [] for n in vertices}
    for e in edges:
        adj[e["from"]].append(e["to"])
    entrypoints = [k for k, v in vertices.items() if v["type"] == "pod" and
                   any(p for p in pods if "pod:%s/%s" % metadata(p)[:2] == k and
                       metadata(p)[2].get("cyber-defense/entrypoint") == "true")]
    paths = []
    for start in entrypoints:
        queue = deque([(start, [start])])
        while queue:
            current, path = queue.popleft()
            if len(path) > 1 and vertices[current].get("protected"):
                confidence = "configuration-supported"
                for a, b in zip(path, path[1:]):
                    if edge_conf.get((a, b)) == "indeterminate":
                        confidence = "indeterminate"
                        break
                paths.append({"from": start, "to": current, "nodes": path,
                              "status": "hypothesis", "confidence": confidence,
                              "validated": False})
                continue
            for nxt in adj.get(current, []):
                if nxt not in path:
                    queue.append((nxt, path + [nxt]))
    return {"nodes": vertices, "edges": edges, "paths": paths,
            "limitations": ["Offline configuration reasoning only; no exploitation or packet tests.",
                            "Only simplified ingress policy matching; egress, ports, DNS, CNI behavior, service mesh and external firewalls are not modeled.",
                            "Unmodeled constructs (port-scoped rules, ipBlock peers) yield 'indeterminate' edges/paths, not confirmed ones; a bounded probe must resolve them.",
                            "Reads standard NetworkPolicy only; CiliumNetworkPolicy and other CNI-specific CRDs are not evaluated.",
                            "Potential paths are not proof of reachability or privilege escalation."]}

def acquire():
    def get(resource):
        cmd = ["kubectl", "get", resource, "-A", "-o", "json"]
        return json.loads(subprocess.check_output(cmd, text=True, timeout=30))
    return {k: get(k) for k in ("pods", "services", "networkpolicies", "namespaces")}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, help="Offline inventory JSON; omit for read-only kubectl API queries")
    parser.add_argument("--out", type=Path, default=Path("report.json"))
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text()) if args.snapshot else acquire()
    report = analyze(snapshot)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(report['nodes'])} nodes, {len(report['edges'])} edges, {len(report['paths'])} hypothetical paths. Output: {args.out}")

if __name__ == "__main__":
    main()
