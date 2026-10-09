# Evidence-backed scenario scoring

Bridge between labeled synthetic benchmark scenarios and **operator-supplied lab observations**. Predictions must have a matching case, run ID, category, approved observation method and nonempty evidence artifact reference. AI hypotheses do not count as independent evidence. Missing, contradictory or unsupported observations lead to abstention.

## Run
```sh
python3 -m src.evidence_benchmark --benchmark examples/scenario-benchmark.json \
  --observations examples/evidence-benchmark-observations.json \
  --run-id demo-001 --out benchmark-evidence-report.json
python3 -m unittest discover -s tests -v
```

## Important trust boundary
A populated `evidence_ref` is only a **claim that an artifact exists**. This module does not verify the file contents, hashes, identities, timestamps or independent execution. The sample observation references are fictional placeholders. Claude should ensure that real collection attaches actual file hashes and that the observation oracle checks resource identity and effective reachability or permission.

No AI output becomes ground truth, and no model-generated test commands are executed.

## Next empirical study
- Run exact same isolated scenarios with and without AI hypothesis suggestions.
- Resolve predictions from matched signed/hash-checked evidence only.
- Compare coverage, discovery precision/recall, time-to-first-confirmation and validated chain success, including negative controls.
