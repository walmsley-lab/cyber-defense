# Campaign viewer (Svelte Flow)

This is a **read-only** investigation dashboard for the variable-length/branching Python campaign tracker. It shows step states, AND/OR prerequisites, and the evidence log. No exploit execution, API calls, or privileged browser actions.

## Run

```sh
cd ui
npm install
npm run dev
```

Open the local URL shown by Vite. The bundled demo loads automatically. Select a step in the right-hand sidebar to view its evidence. Graph nodes are positioned automatically by dependency depth.

To inspect your own run, load a campaign JSON and matching append-only JSONL event log using the file inputs. Generate the event log with:

```sh
python3 -m src.campaign examples/campaign-branching.json record inventory passed --events campaign-events.jsonl --evidence evidence/inventory.json
```

## Status interpretation
Pending = yellow; running = blue; passed = green; failed = red; blocked/inconclusive = grey. **Passed means a check succeeded**, not that arbitrary code execution, identity compromise, or a complete attack was demonstrated.

## Current limitations
This is a file-based replay visualization, not live streaming. It does not run the CLI, monitor an actual cluster, or show real network topology. The read-only approach lets the attacker operate without a web browser and minimizes accidental privileged actions. Event replay performs structural validation but does not replace the Python command's readiness validation.

Svelte Flow: https://svelteflow.dev/learn
