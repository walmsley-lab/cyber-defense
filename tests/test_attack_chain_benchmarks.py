"""Adversarial campaign planning regressions: no fixed attack-chain length."""
import copy
import unittest
from src.campaign import validate, ranked, apply_event

def ready(c):
    return {r["id"] for r in ranked(c) if r["readiness"] == "ready"}
def flags(c):
    return {r["id"]: r["readiness"] for r in ranked(c)}

class AttackChainBenchmarks(unittest.TestCase):
    def test_zero_step_campaign(self):
        self.assertEqual(ranked({"actions":[]}), [])
    def test_single_step_campaign(self):
        self.assertEqual(ready({"actions":[{"id":"only"}]}), {"only"})
    def test_six_step_serial_chain(self):
        c={"actions":[{"id":str(i),"requires_all":[str(i-1)] if i else []} for i in range(6)]}
        for i in range(6):
            self.assertEqual(ready(c), {str(i)})
            apply_event(c,{"action_id":str(i),"status":"passed"})
        self.assertEqual(ready(c), set())
    def test_alternative_route_survives_failed_check(self):
        c={"actions":[{"id":"start"},{"id":"a","requires_all":["start"]},
                      {"id":"b","requires_all":["start"]},
                      {"id":"goal","requires_any":["a","b"]}]}
        apply_event(c,{"action_id":"start","status":"passed"})
        apply_event(c,{"action_id":"a","status":"failed"})
        self.assertIn("b",ready(c))
        self.assertEqual(flags(c)["goal"],"waiting")
        apply_event(c,{"action_id":"b","status":"passed"})
        self.assertIn("goal", ready(c))
    def test_conjunctive_chain_rejects_failed_prerequisite(self):
        c={"actions":[{"id":"a"},{"id":"b"},{"id":"goal","requires_all":["a","b"]}]}
        apply_event(c,{"action_id":"a","status":"passed"})
        apply_event(c,{"action_id":"b","status":"failed"})
        self.assertEqual(flags(c)["goal"],"blocked-by-prerequisite")
    def test_inconclusive_does_not_become_failure_or_success(self):
        c={"actions":[{"id":"a"},{"id":"goal","requires_all":["a"]}]}
        apply_event(c,{"action_id":"a","status":"inconclusive"})
        self.assertEqual(flags(c)["goal"],"waiting")
        self.assertNotIn("goal",ready(c))
    def test_cyclic_dependencies_rejected(self):
        c={"actions":[{"id":"a","requires_all":["b"]},{"id":"b","requires_all":["a"]}]}
        with self.assertRaises(ValueError):
            validate(c)
    def test_unknown_dep_rejected(self):
        with self.assertRaises(ValueError):
            validate({"actions":[{"id":"a","requires_any":["unseen"]}]})
    def test_no_unjustified_pass(self):
        c={"actions":[{"id":"start"},{"id":"goal","requires_all":["start"]}]}
        with self.assertRaises(ValueError):
            apply_event(c,{"action_id":"goal","status":"passed"})

if __name__ == "__main__":
    unittest.main()
