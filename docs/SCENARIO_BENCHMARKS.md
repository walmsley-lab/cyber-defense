# Scenario-driven attacker benchmark

The initial fixture covers 8 *labeled synthetic security conditions* in four categories, each with a vulnerable and a secure negative control. A case also names a future lab oracle that must produce independent evidence. These labels are **illustrative** and are not claims about deployed systems.

## Run (offline, no API or cluster access)
```sh
python3 -m src.scenario_benchmark --benchmark examples/scenario-benchmark.json \
  --baseline examples/scenario-baseline.json \
  --candidate examples/scenario-candidate.json \
  --out scenario-comparison.json
python3 -m unittest discover -s tests -v
```

A prediction is vulnerable, not-vulnerable or unknown. Report precision, recall, coverage and confusion counts; a missing prediction is an abstention, never quietly treated as a secure system. Predictions currently come from static fixture files, **not** directly from the AI hypothesis module; the next integration should map validated findings to case IDs with a provenance record.

## Experiment protocol for Claude
1. Verify all offline tests and sample comparisons.
2. Create isolated, disposable scenarios with explicit setup/cleanup and timeouts.
3. Run baseline and candidate against exactly the same scenarios, record scope, build hash, environment, probe evidence and timing.
4. Hold out scenario variations from hypothesis generation; avoid leaking labels into model prompts.
5. Only use independent canary outcomes as ground truth, not the AI's own explanation.
6. Compare false positives and search cost alongside detection recall. An exploit-chain success metric must require complete verified transitions, not concatenated unrelated checks.

## Repertoire roadmap
Prioritize reproducible examples from network policy, RBAC, service identity, dependency/version advisories, TLS and SSH config, and application authorization. Add one checked positive and one checked negative example for each. Do not expand to arbitrary third-party targets or execute model-generated payloads.
