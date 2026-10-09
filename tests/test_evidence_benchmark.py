import unittest
from src.evidence_benchmark import to_predictions
BENCH={"cases":[{"id":"N1","category":"network","scenario":"exposed","expected":"vulnerable"},{"id":"N2","category":"network","scenario":"denied","expected":"not-vulnerable"}]}
def obs(case,result,**extra):
 return {"case_id":case,"run_id":"r1","kind":"network","method":"network-canary",
         "source":"lab-probe","result":result,"evidence_ref":"run/r1/artifact.json",**extra}
class IntegrationTests(unittest.TestCase):
 def test_scored_evidence(self):
  s=to_predictions(BENCH,[obs("N1","vulnerable"),obs("N2","not-vulnerable")],run_id="r1")
  self.assertEqual(s["score"]["totals"]["tp"],1)
  self.assertEqual(s["score"]["totals"]["tn"],1)
 def test_wrong_run_cannot_pollute(self):
  s=to_predictions(BENCH,[dict(obs("N1","vulnerable"),run_id="r2")],run_id="r1")
  self.assertEqual(s["predictions"]["N1"],"unknown")
 def test_conflict_abstains(self):
  s=to_predictions(BENCH,[obs("N1","vulnerable"),obs("N1","not-vulnerable")],run_id="r1")
  self.assertEqual(s["predictions"]["N1"],"unknown")
 def test_model_claim_is_rejected(self):
  s=to_predictions(BENCH,[dict(obs("N1","vulnerable"),source="ai-hypothesis")],run_id="r1")
  self.assertEqual(s["predictions"]["N1"],"unknown")
 def test_wrong_category_rejected(self):
  s=to_predictions(BENCH,[dict(obs("N1","vulnerable"),kind="tls")],run_id="r1")
  self.assertEqual(s["predictions"]["N1"],"unknown")
 def test_missing_evidence_rejected(self):
  s=to_predictions(BENCH,[dict(obs("N1","vulnerable"),evidence_ref="")],run_id="r1")
  self.assertEqual(s["predictions"]["N1"],"unknown")
if __name__=="__main__":unittest.main()
