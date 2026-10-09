# Evidence-driven hypothesis validation and replanning

Use fixed, operator-approved evidence observations to validate AI-proposed checks. The validator maps approved categories to specific predicates and rejects invented evidence references. This is **not** an exploit harness, a general target scanner, or proof of successful compromise.

```sh
python3 -m src.adaptive_lab --hypotheses examples/adaptive-hypotheses.json --evidence examples/adaptive-observations.json --out adaptive-report.json
python3 -m unittest discover -s tests -v
```

A validation action has three meaningful outcomes:
- **passed**: that particular expected predicate was observed.
- **failed**: available evidence contradicts that predicate.
- **inconclusive**: missing or contradictory evidence.

`src.adaptive_replan.replan` recomputes next checks after evidence updates while honoring AND/OR prerequisites. Successful independent routes remain available when another branch fails. No hardcoded chain depth or number of alternatives.

## Repertoire and remaining boundary

Our implemented inventory now covers Kubernetes misconfiguration, RBAC, reachability, dependency advisories, TLS and SSH misconfiguration, plus bounded observations in an owned test lab. This is **not a broad validated exploit repertoire**: there is no autonomous arbitrary payload execution, RCE, persistence, or third-party target exploitation. Advancing to actual vulnerability-exploit verification should use explicit per-scenario authorization, disposable resettable targets, strict test predicates and isolation, with no credential extraction.

Reviewer: execute regression tests; audit evidence schema semantics; ensure default API behavior stays opt-in, with AI recommendations never mapped to arbitrary commands.
