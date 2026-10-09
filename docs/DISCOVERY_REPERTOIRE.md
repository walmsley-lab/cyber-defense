# Discovery repertoire

This expands the existing Kubernetes checks with **offline advisory matching, TLS fact assessment, and SSH configuration review**. It does not add exploit payloads or unattended active scanning.

## Run

```sh
python3 -m src.discovery --input examples/discovery-fixture.json --out discovery.json
python3 -m unittest discover -s tests -v
```

## Sources and scope
- OSV: [schema](https://ossf.github.io/osv-schema/). Exact `affected[].versions` matches are flagged. Range-only advisories produce **needs-review**, never a false precise match. A production integration should use OSV's ecosystem-aware resolver; do not compare version strings lexicographically.
- TLS: findings based on externally supplied observations about certificate verification, redirects, HSTS and supported protocol minimum. [OWASP transport guidance](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- SSH: findings based on operator-supplied effective configurations, such as root login, password authentication, and unrestricted forwarding. [OpenSSH sshd_config](https://man.openbsd.org/sshd_config). `Include`, `Match` and policy inheritance must be resolved by the collector prior to assessment.
- Kubernetes: existing `src.attacker` and related RBAC/network lab findings stay in place.

All sample advisories are synthetic. This pipeline is not an exploit engine. A reported weakness requires context and verification; for example, password authentication might be intentional behind other controls.

## Next: AI hypotheses, not AI truth
An AI-assisted discovery component should consume *sanitized finding summaries*, identify missing relationships or competing explanations, and return specific proposed **non-destructive checks** with cited evidence IDs. Keep predictions yellow until observed. Never let model text turn into an executable shell command or direct infrastructure mutation.

## Reviewer
Run the tests and check detection negatives. Verify no API tokens or real credentials are required. Integrate real SBOM feeds and observation collectors only with explicit lab scope.
