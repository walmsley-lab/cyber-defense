import unittest
from src.lab_compare import compare

def obs(state, source="pod:cyber-lab/frontend-1"):
    return {"observations": [{"source": source, "target": "pod:cyber-lab/canary-1",
                               "context": "kind-cyber-defense", "result": state}]}

class CompareTests(unittest.TestCase):
    def test_before_after(self):
        result = compare(obs("reachable"), obs("blocked"))
        self.assertEqual(result["change"], "reachability-removed")
        self.assertFalse(result["confirmed_remediation"])
    def test_inconclusive_cannot_pass(self):
        self.assertEqual(compare(obs("reachable"), obs("inconclusive"))["change"], "not-demonstrated")
    def test_wrong_source_rejected(self):
        with self.assertRaises(ValueError):
            compare(obs("reachable"), obs("blocked", source="pod:cyber-lab/other"))
    def test_missing_observation_rejected(self):
        with self.assertRaises(ValueError):
            compare({"observations": []}, obs("blocked"))

if __name__ == "__main__":
    unittest.main()
