# Attacker benchmark: five seeded Kubernetes configurations

This scenario exercises five independently testable detections in a synthetic environment.

| Rule | Weakness | Hardening oracle |
|---|---|---|
| K8S-NET-001 | Protected pod without ingress-isolating policy | Add NetworkPolicy selecting protected pod |
| K8S-NET-002 | NodePort or LoadBalancer exposure | Change to ClusterIP if external access unnecessary |
| K8S-POD-001 | Privileged container | Disable privileged mode |
| K8S-ID-001 | Automatically mounted service account token | Disable token mount |
| K8S-RBAC-001 | Broad access to sensitive Kubernetes resources | Reduce verbs/resources and inspect bindings |

Run with standard-library Python:

```bash
python3 -m src.attacker lab/scenarios/scenarios.json --out attacker-report.json
python3 -m unittest discover -s tests -v
```

This is an offline test fixture, not a deployed exploit target. Findings are potential weaknesses rather than verified exploitability. Next: add read-only Kubernetes API snapshot collection, bound RBAC role grants to actual principals, and validate canary access in an isolated cluster.
