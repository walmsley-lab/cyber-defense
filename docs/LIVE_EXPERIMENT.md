# Two-phase local Kubernetes lab experiment

This automation compares a **disposable kind/Cilium** lab before and after applying restrictive NetworkPolicy and removing a synthetic RBAC binding. It does not perform exploitation. Use only on an isolated owned local cluster.

## Run
Prepare Docker, kind, kubectl, Cilium and the local kind cluster per `lab/RUNBOOK.md`. Check active context and that `lab/manifests.yaml` can deploy. From repository root:

```sh
python3 -m unittest discover -s tests -v
python3 -m src.lab_experiment --i-own-this-lab --outdir runs/experiment-001
```

The command checks the exact `kind-cyber-defense` current context, applies only the hardcoded lab manifests, collects **one fixed HTTP canary observation and one RBAC authorization review per phase**, and writes JSON artifacts. The lab is intentionally left **restricted** afterward; runbook cleanup removes the lab. Choose a new empty output folder for each repeat.

## Expectations and caveats
- Baseline: canary reachable; synthetic ConfigMap authorization allowed.
- Restricted: timeout observed; RBAC access denied.
- HTTP timeouts may occur for reasons other than NetworkPolicy.
- The frontend still uses a different service account from the RBAC canary principal, so even successful parallel checks **do not prove an actual end-to-end exploit chain**.
- Baseline setup temporarily removes the *test-only* deny policy. Never aim this at real infrastructure.
- This experiment mutates a disposable lab. It is *not* a dry-run against Kubernetes; unit tests instead inject fake command handlers without cluster access.
- Live kind/Cilium environment and test execution must be verified by Claude prior to merge.

## Reviewer acceptance
1. Run all unit tests.
2. Check Cilium policy enforcement, image availability and mock HTTP service readiness.
3. Run this experiment twice with fresh output directories and restored lab baselines.
4. Verify observations truly come from the fixed lab targets and that positive, negative and inconclusive cases are distinguished.
5. Never label the outcome as confirmed exploitation.
6. Follow up by fixing identity alignment and adding an independent canary-based complete-chain test.
