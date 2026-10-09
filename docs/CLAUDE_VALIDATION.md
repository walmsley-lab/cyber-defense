# Reviewer checklist for Claude / merge owner

This PR is **stacked on PR #10** and should be merged only after its ancestors (#2, #3, #4, #5, #7, #8, #9, #10). PR #1 is independent documentation. PR #6 was closed and should not be merged.

## Required verification
1. Run `python3 -m unittest discover -s tests -v`; correct failures before merging.
2. Run all offline CLIs: `src.attacker`, `src.chains`, `src.k8s_honeypot` against provided fixtures. Verify expected findings and no verified-exploit claims.
3. Create owned disposable kind/Cilium lab and follow `lab/RUNBOOK.md` and `lab/RBAC_HONEYPOT_RUNBOOK.md`. Confirm CNI actually enforces NetworkPolicy.
4. Capture `before-network.json`, `after-network.json`, `allowed-review.json`, `denied-review.json` using the provided lab tools. Do not upload kubeconfig, tokens, or private data.
5. While network is exposed and authorization allowed, combine:
   ```sh
   python3 -m src.chain_evidence --network before-network.json --authorization allowed-review.json --out chain-before.json
   ```
   After applying restrictive NetworkPolicy and removing test RoleBinding, combine:
   ```sh
   python3 -m src.chain_evidence --network after-network.json --authorization denied-review.json --out chain-after.json
   ```
6. Confirm `both-prerequisites-observed` changes to `prerequisite-denied`. Neither state implies actual exploitation.
7. Fix discrepancies, add regression tests, then merge stacked PRs in dependency order.

## Important integration blockers to check
- Existing `src.k8s_graph` path inference is simplified and may not accurately represent real ingress/egress, CNI, or ports.
- The live HTTP canary request and RBAC authorization review concern **different assets and identities**: joining them demonstrates simultaneous prerequisite observations, **not** one validated end-to-end compromise.
- The earlier lab frontend uses service account `lab-workloads`, whereas the authorization experiment uses `honeypot-reader`. Do not treat them as the same identity.
- The current tests assert code behavior against fixture data; they are not full live-cluster end-to-end tests.
- Watch for differences in Pod metadata/role identity, namespace scoping, and module imports in the stacked branches.

## Success criteria
Repeatable lab results, explicit uncertainty, good logs, no production environment contact, no synthetic secret values leaked, and a reviewer-verified pass of regression suite. Avoid adding general-purpose exploit execution until the current narrow lab is stable.
