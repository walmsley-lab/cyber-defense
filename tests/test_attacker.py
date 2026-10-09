import copy
import json
import unittest
from pathlib import Path
from src.attacker import inspect

LAB=json.loads((Path(__file__).resolve().parents[1]/"lab/scenarios/scenarios.json").read_text())

class AttackerTests(unittest.TestCase):
    def test_all_five_seeded_findings(self):
        report=inspect(LAB)
        self.assertEqual(len(report["findings"]),5)
        self.assertEqual({x["rule"] for x in report["findings"]},{"K8S-NET-001","K8S-NET-002","K8S-POD-001","K8S-ID-001","K8S-RBAC-001"})
        self.assertTrue(all(not x["exploit_verified"] for x in report["findings"]))
    def test_ingress_policy_closes_detection(self):
        lab=copy.deepcopy(LAB)
        lab["resources"].append({"kind":"NetworkPolicy","metadata":{"name":"restrict","namespace":"demo"},"spec":{"podSelector":{"matchLabels":{"app":"protected-db"}},"policyTypes":["Ingress"],"ingress":[]}})
        self.assertFalse(any(x["rule"]=="K8S-NET-001" for x in inspect(lab)["findings"]))
    def test_harden_worker(self):
        lab=copy.deepcopy(LAB)
        worker=next(x for x in lab["resources"] if x["kind"]=="Pod" and x["metadata"]["name"]=="worker")
        worker["spec"]["automountServiceAccountToken"]=False
        worker["spec"]["containers"][0]["securityContext"]["privileged"]=False
        self.assertEqual(len(inspect(lab)["findings"]),3)
if __name__=="__main__":unittest.main()
