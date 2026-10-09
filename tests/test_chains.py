import copy
import json
import unittest
from pathlib import Path
from src.chains import analyze

FIXTURE = json.loads((Path(__file__).parents[1] / "lab/scenarios/chains.json").read_text())

class ChainTests(unittest.TestCase):
    def test_multistep_candidate(self):
        result = analyze(FIXTURE)
        self.assertEqual(result["metrics"]["candidate_paths"], 1)
        self.assertEqual(result["metrics"]["multi_step_paths"], 1)
        self.assertFalse(result["paths"][0]["fully_lab_validated"])
        self.assertEqual([s["type"] for s in result["paths"][0]["steps"]],
                         ["network", "identity", "permission", "asset-access"])
    def test_no_path_when_grant_removed(self):
        data = copy.deepcopy(FIXTURE)
        data["relationships"] = [r for r in data["relationships"] if r["type"] != "permission"]
        self.assertEqual(analyze(data)["paths"], [])
    def test_no_false_path_from_disconnected_branch(self):
        result = analyze(FIXTURE)
        self.assertNotIn("isolated-canary", [p["target"] for p in result["paths"]])
    def test_bad_edge_is_rejected(self):
        data = copy.deepcopy(FIXTURE)
        data["relationships"][0]["to"] = "missing"
        with self.assertRaises(ValueError):
            analyze(data)
    def test_validation_requires_every_edge(self):
        data = copy.deepcopy(FIXTURE)
        for edge in data["relationships"]:
            edge["state"] = "lab-validated"
        self.assertTrue(analyze(data)["paths"][0]["fully_lab_validated"])

if __name__ == "__main__":
    unittest.main()
