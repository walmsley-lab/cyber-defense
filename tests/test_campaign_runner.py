import copy
import unittest
from src.campaign_runner import run_once,run_batch

CAMPAIGN={"actions":[{"id":"a","check":{"kind":"fixture-equals","key":"a","equals":True}},
{"id":"b","requires_all":["a"],"check":{"kind":"fixture-equals","key":"b","equals":True}},
{"id":"c","requires_any":["a","b"],"check":{"kind":"fixture-equals","key":"c","equals":True}}]}
class RunnerTests(unittest.TestCase):
    def test_repeat_deterministic(self):
        batch=run_batch(CAMPAIGN,{"a":True,"b":True,"c":True},3)
        self.assertEqual(batch["summary"]["fully_passed_runs"],3)
        self.assertEqual(batch["runs"][0]["states"],batch["runs"][2]["states"])
    def test_failure_blocks_required_path(self):
        r=run_once(CAMPAIGN,{"a":False,"b":True,"c":True},1)
        self.assertEqual(r["states"]["a"],"failed")
        self.assertEqual(r["states"]["b"],"pending")
    def test_branching(self):
        r=run_once(CAMPAIGN,{"a":True,"b":False,"c":True},1)
        self.assertEqual(r["states"]["c"],"passed")
    def test_missing_evidence(self):
        self.assertEqual(run_once(CAMPAIGN,{},1)["states"]["a"],"inconclusive")
    def test_repetition_cap(self):
        with self.assertRaises(ValueError):run_batch(CAMPAIGN,{},101)
if __name__=="__main__":unittest.main()
