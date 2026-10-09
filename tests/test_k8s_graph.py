import json
import unittest
from copy import deepcopy
from pathlib import Path
from src.k8s_graph import analyze

FIXTURE = Path(__file__).parent.parent / "examples" / "k8s-snapshot.json"

class LabTest(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads(FIXTURE.read_text())

    def test_default_allow_exposes_canary(self):
        report = analyze(self.snapshot)
        self.assertTrue(any(p["to"] == "pod:internal/canary" for p in report["paths"]))
        self.assertTrue(all(not p["validated"] for p in report["paths"]))

    def test_deny_ingress_removes_path(self):
        modified = deepcopy(self.snapshot)
        modified["networkpolicies"]["items"] = [{
          "metadata": {"namespace": "internal", "name": "deny-canary"},
          "spec": {"podSelector": {"matchLabels": {"app": "canary"}},
                   "policyTypes": ["Ingress"], "ingress": []}
        }]
        report = analyze(modified)
        self.assertFalse(any(p["to"] == "pod:internal/canary" for p in report["paths"]))

    def test_service_selector(self):
        self.snapshot["services"]["items"][1]["spec"]["selector"] = {"app":"not-present"}
        report = analyze(self.snapshot)
        self.assertFalse(any(p["to"] == "pod:internal/canary" for p in report["paths"]))

if __name__ == "__main__":
    unittest.main()
