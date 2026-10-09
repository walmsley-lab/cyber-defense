# Cyber Defense — north star and roadmap

## Goal
Build an evidence-driven graph security assessor for **owned or explicitly authorized** Kubernetes/cloud infrastructure. Discover infrastructure, reason about potential multi-hop attack paths, perform bounded validation, and propose minimal changes while preserving legitimate workflows.

**Demo:** a disposable Kubernetes cluster contains a public application, internal service, and protected canary. An intentionally permissive network policy or service identity permits an unexpected route. The assessor discovers the path, collects evidence, and demonstrates that a targeted configuration fix closes the path.

## Pipeline
1. **Discover:** read-only inventory of workloads, services, Ingress, NetworkPolicy, RBAC, service accounts, images, versions and cloud policy.
2. **Model:** typed graph with provenance, trust boundaries, identities, permissions and possible reachability edges.
3. **Hypothesize:** identify paths to protected canaries; label assumptions with relevant ATT&CK/CWE references.
4. **Validate:** offline simulation, then low-rate permitted canary checks.
5. **Remediate:** recommend minimal policy/permission changes; hand evidence to an environment owner.
6. **Learn:** re-test, ingest telemetry, and update confidence and detections.

Never equate a graph path with actual code execution or confirmed exploitation. Evidence states: hypothesized, configuration-supported, observed, lab-validated, remediated.

## Milestones
- M0: scope, taxonomy, references, data contracts and attack catalog.
- M1: parse Kubernetes manifests, RBAC and NetworkPolicy into a graph; seeded synthetic case.
- M2: disposable kind/k3d cluster with permissive and restricted variants, synthetic canary and legitimate workflow tests.
- M3: read-only Kubernetes connector; authorized scoped probe with timeouts, rate limits, audit trail.
- M4: score uncertain paths, export findings, simulate counterfactual remediation.
- M5: AWS/Akash inventory adapters, telemetry correlation and distributed workers.

## Research questions
How accurately can topology, IAM, NetworkPolicy, and observed connectivity be reconciled? Which test reduces the most uncertainty? How do load balancers, cloud firewalls, service meshes and pod churn affect observed routes? How can the smallest intervention break a risky path without breaking legitimate access?

## Deployment
Controller (graph/planner/reports) -> scoped assessment workers -> disposable authorized lab.
Keep workers narrowly permissioned. Treat network policies, ingress, cloud firewalls and load balancing as distinct controls. Store observation source and time. A Kubernetes namespace alone does not isolate an untrusted attack lab.

## Success metrics
Known seeded issues found, inferred vs proven path ratio, false positives, time/requests per validation, paths removed, legitimate workflow regressions.

## Boundaries
No third-party probing, real credential harvesting, persistence, stealth, destructive operations or uncontrolled load. Active tests need explicit written scope, approved destinations, timeout/concurrency caps and logs.

## Read next
[Technique catalog](ATTACK_CATALOG.md) · [References](REFERENCES.md) · [Kubernetes lab](KUBERNETES_LAB.md)
