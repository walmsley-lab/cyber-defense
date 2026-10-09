# Disposable Kubernetes experiment

This extension to [the graph MVP](README.md) deploys **two synthetic workloads** to a local **kind** cluster, then changes canary ingress policy to test whether predicted accessibility changes. The exercise uses a harmless HTTP endpoint, not a vulnerability exploit.

## Prerequisites
Docker, kubectl, kind, and the Cilium CLI installed. Use a disposable local machine/VM. This lab requires a CNI that implements NetworkPolicy; bare kind's default networking setup is not sufficient for this experiment. Verify compatibility between your installed Kubernetes and Cilium versions using the official docs before installing.

## Setup
1. `kind create cluster --name cyber-defense --config lab/kind-config.yaml`
2. `cilium install --context kind-cyber-defense`
3. `cilium status --wait --context kind-cyber-defense`
4. `kubectl --context kind-cyber-defense apply -f lab/manifests.yaml`
5. `sh lab/check.sh --i-own-this-lab` — intentionally exposed case (expected HTTP response).
6. `kubectl --context kind-cyber-defense apply -f lab/policies/restrict.yaml`
7. `sh lab/check.sh --i-own-this-lab` — restricted case (expected failed connection).
8. `kubectl --context kind-cyber-defense -n cyber-lab delete networkpolicy canary-deny-ingress --ignore-not-found` to restore exposure.
9. `kind delete cluster --name cyber-defense` to clean up.

The `check.sh` script refuses arbitrary cluster contexts and only makes one request to the fixed in-lab canary URL on each invocation. Tests can fail because of image downloads, CNI support, DNS, service health or rollout timing; distinguish these from intentional network blocks.

## Graph export
Run the inventory analyzer once the lab is ready:
```sh
python3 -m src.k8s_graph --out report.json
```
This performs **read-only** Kubernetes inventory requests. Record each observation along with cluster version, CNI version, time and applied policies.

## Interpretation
- **Exposed:** default-allow ingress predicts potential access, and the canary responds.
- **Restricted:** canary ingress policy predicts denial, and the request fails.
- Reachability is not exploitability: no credential theft, authentication bypass, code execution, or cloud privilege escalation is performed.
- The current graph engine does not model egress, ports, gateway policies, service meshes, external firewalls, IAM or scheduling variability. Mark these as unknown, not proven safe.

## References
- [kind](https://kind.sigs.k8s.io/)
- [Cilium kind instructions](https://docs.cilium.io/en/stable/installation/kind/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
