# Reproducible attacker campaigns

Repeatability matters at three levels: deterministic regressions, consistency across fresh lab deployments, and measured reliability under realistic conditions. **Do not conflate these.**

## Run offline fixtures
```sh
python3 -m src.campaign_runner --campaign examples/repeatable-campaign.json --fixture examples/repeatable-fixture.json --repeat 5 --out campaign-batch.json --events campaign-batch.jsonl
python3 -m unittest discover -s tests -v
```
The CLI executes only built-in fixture comparisons. It cannot execute arbitrary commands, network probes or exploits from campaign JSON.

## Outputs
- Batch report: input SHA-256 fingerprint, per-run action states, summary.
- Event log: ordered JSONL action outcomes with run identifiers; suitable for per-run filtering and future Svelte playback.
- A failed check leaves dependent checks pending rather than incorrectly marking them failed.
- `inconclusive` means a result was unavailable and does not imply denial.

## Important limitations / next steps
A deterministic fixture repeated five times is still **one scenario**, not five independent exploit attempts. It establishes regression/replay consistency, not estimated real-world success probability. Add actual isolated lab runs only after the collector, live probe, and authorization verification are validated. Real experiments should record cluster/CNI versions, manifests digest, controls, per-attempt timeouts, fixture resets and observed outcomes. Bound retries; never replay unreviewed commands against changing third-party infrastructure.

## Reviewer checklist
- Check all unit tests and CLI repeatability across two invocations.
- Verify a failing RBAC fixture prevents the dependent report check while leaving unrelated branches unaffected.
- Confirm event records include no secrets.
- Note: this PR is stacked on the Svelte viewer PR #14 and depends on earlier attack-campaign CLI changes.
