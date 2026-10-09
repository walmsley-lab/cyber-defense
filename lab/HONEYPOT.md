# Honeypot exercise: identity and protected canary

## Goal
Add a second seeded route beyond service-level network reachability: workload -> service account -> RoleBinding -> Role -> potential access to a synthetic protected Kubernetes Secret. The attacker infers this from read-only Kubernetes inventory. The canary is never an actual credential.

## Quick start: offline
```sh
python3 -m src.k8s_honeypot --snapshot examples/honeypot-snapshot.json --out honeypot-report.json
python3 -m unittest discover -s tests -v
```

Expected: exactly one candidate identity path. Remove RoleBinding, disable automount in the snapshot, or remove the sensitive Role permission; expected result is zero candidate paths.

## Cluster extension
For an authorized **disposable** cluster, the same command can collect pods, roles, clusterroles, RoleBindings and ClusterRoleBindings with read-only kubectl API calls. Use the correct kubeconfig and a least-privileged audit identity. No secret values are read, and no impersonation or Kubernetes API authorization attempts are performed.

This is configuration evidence rather than a live exploitation result. The current model deliberately does not infer that an attacker can obtain a mounted token from an exposed service. The graph also does not yet model Role resourceNames, deny conditions from admission, projected token expiration, API group/resource subresources, or effective permissions from multiple rules. Validate authorization with a separate intentionally scoped, non-sensitive canary and explicit operator approval. Do not use production secrets.

## Next
Seed matching workload/service account/Role/RoleBinding objects in the isolated kind lab, implement an authorization-only SelfSubjectAccessReview fixture, and combine the new identity path with the network reachability observation without conflating the two.
