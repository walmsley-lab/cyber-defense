import unittest
from src.scenario_benchmark import compare,score
CASES=[{"id":"a","category":"network","scenario":"x","expected":"vulnerable"},
       {"id":"b","category":"network","scenario":"y","expected":"not-vulnerable"}]
class BenchmarkTests(unittest.TestCase):
 def test_perfect_classifier(self):
  s=score(CASES,{"a":"vulnerable","b":"not-vulnerable"})
  self.assertEqual(s["precision"],1)
  self.assertEqual(s["recall"],1)
  self.assertEqual(s["coverage"],1)
 def test_false_positive_and_negative(self):
  s=score(CASES,{"a":"not-vulnerable","b":"vulnerable"})
  self.assertEqual(s["totals"]["fp"],1)
  self.assertEqual(s["totals"]["fn"],1)
 def test_abstain_is_not_failure(self):
  s=score(CASES,{"a":"unknown"})
  self.assertEqual(s["totals"]["abstain"],1)
  self.assertEqual(s["coverage"],0.5)
 def test_unknown_case_rejected(self):
  with self.assertRaises(ValueError):score(CASES,{"not-in-benchmark":"vulnerable"})
 def test_compare_both(self):
  r=compare({"name":"demo","cases":CASES},{"a":{"a":"vulnerable"},"b":{"b":"not-vulnerable"}})
  self.assertEqual(set(r["systems"]),{"a","b"})
if __name__=="__main__":unittest.main()
