# Kubernetes lab specification (proposed)

## Purpose
Create a **disposable owned** Kubernetes environment where a configuration gap creates a potential path from a public application to a protected synthetic canary. Assess the path, fix it, and verify no legitimate workflow was broken.

## Topology
- Isolated kind/k3d cluster with CNI that actually enforces NetworkPolicy.
- Public-facing mock HTTP service and internal mock backend in separate namespaces.
- Protected test canary with no production credentials/data.
- Intentionally permissive and restrictive NetworkPolicy/RBAC variants.
- Read-only assessment identity, distinct from the application identities.
- Event logs with synthetic request IDs and expected outcomes.

## Exercise
1. Ingest manifests into a provenance-tagged typed graph.
2. Predict potential routes to the canary from an allowed entrypoint.
3. Check only named lab destinations within a strict request budget.
4. Compare observations with inference, documenting uncertainty and load-balancer variation.
5. Suggest least-privilege policy correction, apply with environment owner's approval.
6. Repeat permitted checks and legitimate app regression tests.

## Safeguards
No production clusters or privileged assessment pods. No host network, host mounts, real credentials, persistence or uncontrolled traffic. Workload runs as non-root with minimal capabilities, an explicit scope file, timeouts, concurrency caps and audit log. Kubernetes namespace separation alone is insufficient isolation.

## Cloud extensibility
AWS/Akash adapters should emit the same graph vocabulary (identity, principal, grant, ingress, firewall, load balancer, workload, endpoint, evidence). Their worker placement determines which routes are observable; keep provenance/location/time for every result.
