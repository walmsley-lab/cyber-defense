# Evidence reconciliation

The analyzer produces candidate paths from inventory snapshots, never proof of an exploit. The reconciliation step compares these predictions to independently collected **authorized canary** observations.

## Offline demo
```sh
python3 -m src.k8s_graph --snapshot examples/k8s-snapshot.json --out graph.json
python3 -m src.reconcile --graph graph.json --observations examples/observations.json --out findings.json
```

The sample observation is **synthetic, not a real captured HTTP request**. Actual lab observations must document source/target identities, timestamp, cluster context, relevant policies and diagnostic status. The check script in the earlier PR prints HTTP status; it does not yet emit observations.json automatically.

## Verdict semantics
- corroborated: a predicted possible route also returned a successful reachability observation
- consistent-block: no modeled route, and blocked observation
- prediction-disagrees-with-observation: modeled path, blocked in practice
- unexpected-reachability: no modeled path, but observed reachable
- unknown: measurement inconclusive

Reachability is not a demonstrated exploit. Any unexpected or disagreeing outcome may be due to omitted egress, port, DNS, proxy, load balancer, CNI or timing considerations. Never mark a vulnerability validated from a single canary HTTP status.

## Findings contract
Schema `cyber-defense/findings/v1` contains source, target, path, evidence metadata, verdict, suggested next step and `exploit_verified: false`. Remediation owner should return change details and independent regression evidence. Future versions should use JSON Schema validation, immutable artifact hashes, and repeated bounded measurements.
