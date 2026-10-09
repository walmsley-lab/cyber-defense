# Campaigns: variable-length and branching attack investigations

**A four-step exploit chain is a test example, not a model restriction.** Real investigations may have zero, one, or many hypotheses; concurrent branches, alternative prerequisites, dead ends and retries. Do not imply that every path contains four actions or that each action is an exploit.

The offline tracker uses dependency constraints:
- `requires_all`: **AND** prerequisites.
- `requires_any`: **OR** alternatives.
- No fixed path length; graph cycles are rejected.
- Each attempt has an independent state: pending (yellow), running (blue), passed (green), failed (red), blocked (gray), inconclusive (gray).
- `passed` means the **specific check** met its success condition, not that an exploit succeeded.
- `failed` is an outcome for an attempted check; other branches remain eligible.
- Completion is evidence-driven, not a count of steps.

## CLI
```sh
python3 -m src.campaign examples/campaign-branching.json status
python3 -m src.campaign examples/campaign-branching.json record inventory passed --evidence evidence/inventory.json
python3 -m src.campaign examples/campaign-branching.json status
```
Events are appended to `campaign-events.jsonl`; use `--events runs/demo.jsonl` for a separate replayable run. Inputs are data only. The tracker **does not execute tests, exploits, subprocesses or network calls**.

## Ranking
A simple heuristic orders currently ready checks by expected value: impact × confidence × information gain / (cost + risk). Scores are subjective, not calibrated exploit likelihood. Paths blocked by prerequisites appear separately.

## UI roadmap
Svelte Flow (@xyflow/svelte) can visualize asset nodes, attempt nodes and their prerequisite edges; consume the same JSONL event log, not a new cross-team inventory contract. A selected step shows status, prerequisites, evidence, attempt history and result. Later: alternatives, temporal playback and critical-path highlighting.

## Reviewer notes
Check CLI replay and validation using `python3 -m unittest discover -s tests -v`. Keep the event log free of credentials and sensitive output. This branch stacks on the existing honeypot PR series; no live cluster testing is claimed.
