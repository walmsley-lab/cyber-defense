import json
import unittest
from types import SimpleNamespace
from src.ai_hypotheses import propose,validate_output

class FakeResponses:
 def create(self,**kwargs):
  self.request=kwargs
  return SimpleNamespace(output_text=json.dumps({"hypotheses":[{"claim":"Check policy scope",
        "evidence_ids":["D-001"],"check":"inspect-networkpolicy","reason":"Missing segmentation evidence"}]}))
class AIHypothesesTests(unittest.TestCase):
 def test_mocked_inference_is_unverified(self):
  fake=FakeResponses()
  output=propose({"findings":[{"id":"D-001","rule":"K8S-NET-001","detail":"No ingress isolation"}]},
                 SimpleNamespace(responses=fake),"mock")
  self.assertEqual(output["hypotheses"][0]["state"],"hypothesis")
  self.assertFalse(output["hypotheses"][0]["executable"])
 def test_reject_unsupported_check(self):
  with self.assertRaises(ValueError):
   validate_output({"hypotheses":[{"claim":"a","reason":"b","check":"run-shell","evidence_ids":[]}]},set())
 def test_reject_fake_citation(self):
  with self.assertRaises(ValueError):
   validate_output({"hypotheses":[{"claim":"a","reason":"b","check":"review-rbac","evidence_ids":["invented"]}]},{"D-001"})
if __name__=="__main__":unittest.main()
