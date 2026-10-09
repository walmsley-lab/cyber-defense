# Kubernetes lab (configuration-first MVP)

The example uses a **synthetic inventory snapshot** to verify graph reasoning without any cluster access:

```sh
python3 -m unittest discover -s tests -v
python3 -m src.k8s_graph --snapshot examples/k8s-snapshot.json --out report.json
```

To read from a Kubernetes cluster where you have explicit authorization, run:

```sh
kubectl auth can-i list pods --all-namespaces
kubectl auth can-i list networkpolicies --all-namespaces
python3 -m src.k8s_graph --out report.json
```

The collector makes read-only `kubectl get` requests and does not transmit test packets, attempt code execution, or perform exploitation. Scope `kubectl` context and RBAC to your owned disposable cluster. Review context first with `kubectl config current-context`.

The fixture intentionally has no NetworkPolicies: default ingress allowance is one *necessary* condition for a possible path, not sufficient proof of accessibility. The unit test applies a synthetic deny-ingress policy to demonstrate disappearance of the hypothesized path.

## Boundaries of v0
The model does not evaluate egress policies, actual CNI enforcement, port numbers, route tables, service meshes, cloud security groups, external load balancers, node health, IAM or API authorization. It creates candidate edges, **not validated exploit findings**. Next step: build a disposable kind cluster with policy-enforcing CNI, then add a low-rate, allowlisted observation component and measured evidence records.
