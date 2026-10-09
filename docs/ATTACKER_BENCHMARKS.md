# Attacker chaining benchmark / reviewer acceptance

The four-action sequence is illustrative, not a fixed architecture. Automated regression tests exercise zero, one, six and branching checks, AND/OR prerequisites, cycles, independently failed alternatives and inconclusive observations.

## Run
```sh
python3 -m unittest discover -s tests -v
python3 -m src.campaign examples/campaign-branching.json status
python3 -m src.chains lab/scenarios/chains.json --out /tmp/cyber-chain-report.json
```

## Repertoire tracked
1. Kubernetes network segmentation / unexpected service exposure.
2. Runtime security context and privilege risk.
3. Service account mapping and RBAC grants.
4. Protected canary reachability and authorization.
5. Dependency/CVE applicability (future actual SBOM ingestion).
6. TLS trust and risky forwarding configuration (future).
7. Multi-path alternatives and independently failed observations.

Only the first four categories have initial coded checks; listing future techniques does **not** mean implemented exploitation. Our current test oracles are synthetic data or fixed-scope lab observations. A *green* status means its specified check passed, not that a hostile principal achieved an end-to-end compromise.

## Immediate integration notes for Claude
- The frontend deployment now references the `honeypot-reader` service account named by the RBAC review; token automount remains **disabled**.
- The Kubernetes policy experiment still checks HTTP network reachability to an HTTP canary, while the RBAC review checks authorization to a different ConfigMap. These may be correlated but are not a completed attack chain.
- Please run kind/Cilium deployment, the all-tests suite, and each CLI. Verify `kubectl auth can-i` impersonation review permissions and cluster context guard before approving.
- Current `src.campaign` marks permanently failed prerequisites as blocked; inconclusive dependencies remain waiting and require a future retry/resolution design. Replaying old events is also an area for stricter transition checking.
- Measure false positives with negative fixtures as repertoire expands. Prioritize eliminating false chain claims over increasing the number of checks.

### Demonstration success
We can show that an intentionally exposed lab service is observable, the workload identity is known, the identity's authorization is independently checked, and restricting network/RBAC policies changes the relevant evidence. Do **not** claim actual compromise, credential recovery, or privilege escalation.
