import unittest
from src.adaptive_lab import evaluate
from src.adaptive_replan import replan

H={"hypotheses":[
 {"claim":"Network accessible","reason":"Validate","evidence_ids":["N"],"check":"verify-lab-reachability"},
 {"claim":"RBAC accessible","reason":"Validate","evidence_ids":["R"],"check":"review-rbac"}]}
E=[{"source_id":"N","kind":"network","result":"reachable"},
   {"source_id":"R","kind":"rbac","result":"denied"}]

class AdaptiveTests(unittest.TestCase):
 def test_mixed_evidence(self):
  r=evaluate(H,E)
  self.assertEqual(r["summary"]["passed"],1)
  self.assertEqual(r["summary"]["failed"],1)
 def test_budget(self):
  self.assertEqual(len(evaluate(H,E,budget=1)["events"]),1)
 def test_contradiction_is_inconclusive(self):
  r=evaluate({"hypotheses":[H["hypotheses"][0]]},E+[{"source_id":"N","kind":"network","result":"blocked"}])
  self.assertEqual(r["summary"]["inconclusive"],1)
 def test_fabricated_reference_rejected(self):
  with self.assertRaises(ValueError):
   evaluate({"hypotheses":[dict(H["hypotheses"][0],evidence_ids=["FAKE"])]},E)
 def test_replan_alternative(self):
  c={"actions":[{"id":"root"},{"id":"a","requires_all":["root"]},
    {"id":"b","requires_all":["root"]},{"id":"goal","requires_any":["a","b"]}]}
  r=replan(c,[{"action_id":"root","status":"passed"},{"action_id":"a","status":"failed"},
              {"action_id":"b","status":"passed"}])
  self.assertIn("goal",{x["id"] for x in r["ready"]})
 def test_replan_join_blocked(self):
  c={"actions":[{"id":"a"},{"id":"b"},{"id":"goal","requires_all":["a","b"]}]}
  r=replan(c,[{"action_id":"a","status":"failed"},{"action_id":"b","status":"passed"}])
  self.assertIn("goal",{x["id"] for x in r["blocked"]})
if __name__=="__main__":unittest.main()
