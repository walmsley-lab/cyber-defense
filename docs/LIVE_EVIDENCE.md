# Live evidence capture — authorized disposable lab only

The first live measurement is a single HTTP request from the lab frontend pod to a synthetic canary, executed with `kubectl exec`. It is **not** a scanner or exploit runner.

## Prerequisites
Complete `lab/RUNBOOK.md` on a disposable kind cluster with functioning Cilium NetworkPolicy. Confirm that the current kubectl context is `kind-cyber-defense`. The script rejects any other context and does not accept arbitrary hosts or commands.

## End-to-end manual walkthrough

```sh
# First, in the exposed test configuration:
kubectl --context kind-cyber-defense -n cyber-lab delete networkpolicy canary-deny-ingress --ignore-not-found
python3 -m src.lab_evidence --i-own-this-lab --out before.json

# Then apply the test-only canary deny policy:
kubectl --context kind-cyber-defense apply -f lab/policies/restrict.yaml
python3 -m src.lab_evidence --i-own-this-lab --out after.json

python3 -m src.lab_compare --before before.json --after after.json --out comparison.json
python3 -m src.k8s_graph --out graph.json
python3 -m src.reconcile --graph graph.json --observations after.json --out findings.json
```

The graph command collects the *current* state, so rerun it in each phase if you want a phase-matched prediction. The original graph model is simplified; a correct NetworkPolicy prediction also depends on DNS, egress, CNI, ports, and service configuration. The `src.reconcile` component compares exact pod identifiers; the live evidence emitter uses actual deployed pod names.

## Reporting rules
- HTTP 2xx/3xx: `reachable`.
- Curl timeout: `blocked` means only **observed timeout**, not attribution to a firewall/NetworkPolicy.
- Other failures: `inconclusive`, with bounded diagnostic text.
- A before/after difference is **not** proof a vulnerability was exploited or securely remediated.
- Manual application of the policy and separate legitimate workflow checks remain necessary.

## Limitations
No cluster was deployed or live-tested during authoring. Image availability, Cilium compatibility, runtime privilege defaults, and CNI behavior may need adjustment. The detector only checks one hardcoded canary and does not test load balancer behavior, privilege escalation, authentication, or unrelated infrastructure. Review logs and delete the disposable cluster after the experiment.
