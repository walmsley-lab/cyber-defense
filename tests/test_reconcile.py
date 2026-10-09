import unittest
from src.reconcile import reconcile

GRAPH = {"paths": [{"from": "pod:public/frontend", "to": "pod:internal/canary",
                    "nodes": ["pod:public/frontend", "svc:internal/canary", "pod:internal/canary"]}]}
BASE = {"source": "pod:public/frontend", "target": "pod:internal/canary", "context": "synthetic"}

class ReconcileTests(unittest.TestCase):
    def test_corroborated(self):
        report = reconcile(GRAPH, [dict(BASE, result="reachable")])
        self.assertEqual(report["findings"][0]["verdict"], "corroborated")
        self.assertFalse(report["findings"][0]["exploit_verified"])
    def test_disagreement(self):
        report = reconcile(GRAPH, [dict(BASE, result="blocked")])
        self.assertEqual(report["summary"]["discrepancies"], 1)
    def test_unexpected(self):
        report = reconcile({"paths": []}, [dict(BASE, result="reachable")])
        self.assertEqual(report["findings"][0]["verdict"], "unexpected-reachability")
    def test_inconclusive(self):
        report = reconcile(GRAPH, [dict(BASE, result="inconclusive")])
        self.assertEqual(report["findings"][0]["verdict"], "unknown")

if __name__ == "__main__":
    unittest.main()
