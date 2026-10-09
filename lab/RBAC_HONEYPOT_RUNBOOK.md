# Authorization canary: real Kubernetes RBAC review

This provides a **real Kubernetes authorization review** to complement synthetic attack-path inference. It never reads canary contents, assumes a pod identity, executes inside a pod, or attempts privilege escalation.

## Prerequisites
An **owned disposable** kind cluster named `cyber-defense`, with `kubectl` context `kind-cyber-defense`. The operator must have authorization to create the test Role/RoleBinding and perform a SubjectAccessReview using `kubectl auth can-i --as`. Some clusters deny impersonation or access-review calls; report that as an operator permissions limitation, not a security block.

## Steps

```sh
kubectl config current-context
kubectl --context kind-cyber-defense apply -f lab/rbac-honeypot.yaml
python3 -m src.rbac_canary --i-own-this-lab --out allowed-review.json

# Demonstrate removing one permission breaks the authorization route:
kubectl --context kind-cyber-defense -n cyber-lab delete rolebinding honeypot-canary-reader
python3 -m src.rbac_canary --i-own-this-lab --out denied-review.json

# Cleanup:
kubectl --context kind-cyber-defense delete -f lab/rbac-honeypot.yaml --ignore-not-found
```

The first result should be `allowed`; the second should be `denied`. Authorization is evaluated for a synthetic ConfigMap, not a Secret. A confirmed `allowed` finding proves that **the named test principal has the specified Kubernetes permission**; it does not show that an external attacker obtained the identity, reached the API server, or read protected data.

## Roadmap
- Compare snapshot-inferred RoleBinding paths to authorization-review evidence in one report.
- Add negative-control identities and unrelated ConfigMaps for least-privilege verification.
- Trace path prerequisites with separate observations: network -> workload identity -> authorization, without treating any one as proof of the others.

## References
- [Kubernetes Authorization Overview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [kubectl auth can-i](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/)
