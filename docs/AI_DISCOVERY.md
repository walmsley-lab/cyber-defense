# Optional AI-assisted hypothesis discovery

AI supplements deterministic rules and attack-chain planning. Its role is to suggest **unobserved relationships**, competing explanations, and useful low-risk validation checks, especially where no existing rule identifies a potential chain. It is not an exploit executor or a source of verified facts.

## Usage
```sh
pip install openai
export OPENAI_API_KEY='...' # configure privately; never commit or paste keys
python3 -m src.discovery --input examples/discovery-fixture.json --out discovery.json
python3 -m src.ai_hypotheses --findings discovery.json --model YOUR_AVAILABLE_MODEL --allow-api --out hypotheses.json
```

The external API call is **opt-in**. Only a small allowlist of summary fields is sent; nevertheless review supplied finding summaries before invoking it. The model's result is validated against allowlisted checks and evidence identifiers. Nothing proposed by the model runs automatically.

## Integration
- Preserve the hypotheses as **yellow** until independent observations confirm their predicates.
- Feed supported checks into the campaign planner as *proposed* actions after an operator approves their scope.
- The UI can render them in a separate unverified lane.
- Measure proposal precision, evidence coverage, false relationships, and reduction in search cost against held-out synthetic lab fixtures.
- Never infer a compromise merely because a model can narrate an attack chain.

## Limitations
Uses an operator-selected model via the OpenAI Responses API. Parser expects JSON text and does not yet use strict JSON-schema mode. SDK and network tests are not run in CI; unit tests use a mock client. The program does not sanitize arbitrary log contents, only allowlisted summary fields—do not supply sensitive strings in those fields. Include stronger structured-output schemas, budget controls and telemetry minimization before wider use.

References: https://developers.openai.com/api/reference/python and https://ossf.github.io/osv-schema/
