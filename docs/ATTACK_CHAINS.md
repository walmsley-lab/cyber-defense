# Chained attack-path reasoning: first experiment

The attacker should reason over **combinations of weaknesses**, not report a collection of unrelated scanner alerts. For the initial controlled benchmark, use a synthetic chain:

```
external entrypoint
  -> gateway workload (network configuration)
  -> workload identity (service account)
  -> granted role (RBAC)
  -> protected synthetic canary (candidate authorization path)
```

The last edge is deliberately labeled *hypothesis*. A policy grant can support a hypothesis about access without establishing an actual exploit.

## Run

```sh
python3 -m src.chains lab/scenarios/chains.json --out chain-report.json
python3 -m unittest discover -s tests -v
```

## Attack repertoire: progressive lab benchmarks

| Benchmark | Initial state | Chain question | Validating evidence |
|---|---|---|---|
| A: exposed workload + overbroad RBAC | Public service and granted workload identity | Does exposed app access combine with permissions to endanger canary data? | Configuration graph, then controlled canary authorization result |
| B: lateral reachability | Internal services with intentionally permissive policies | Can a permitted service call reach a protected synthetic endpoint? | Bounded HTTP canary observations |
| C: workload privilege boundary | Intentionally permissive container security context | Could the pod's runtime configuration increase impact if compromised? | Configuration evidence and isolated environment verification |
| D: patched dependency | Pinned intentionally obsolete demo component | Does a published advisory apply to the exact installed build and configuration? | SBOM, advisory, remediation comparison; no unbounded exploit execution |

## Research rationale
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/): discovery, initial access, credential access, privilege escalation and lateral movement concepts.
- [Kubernetes RBAC practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/): role grants and identity boundaries.
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/): ingress/egress exposure.
- [Kubernetes security checklist](https://kubernetes.io/docs/concepts/security/security-checklist/): workload hardening.
- [OWASP Kubernetes Top Ten](https://owasp.org/www-project-kubernetes-top-ten/): prioritization of common misconfiguration classes.

## Interpretation and next engineering work
- Mark edges as `hypothesis`, `configuration-supported`, `observed`, or `lab-validated`; never silently promote states.
- The current solver enumerates directed paths through authored lab facts. It does **not** automatically derive these facts from a deployed cluster and does not verify exploitability.
- Next connect Kubernetes service accounts, RoleBindings and effective RBAC rules to these same facts, and use bounded canary checks to validate relevant edges.
- Score precision and recall against seeded ground truth, then add plausible-but-broken decoy chains to measure false positives.
- Keep experimentation to disposable infrastructure under explicit authorization, with no production secrets, persistence, or destructive stress testing.
