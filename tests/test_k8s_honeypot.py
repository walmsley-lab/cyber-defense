import copy
import json
import unittest
from pathlib import Path
from src.k8s_honeypot import assess

CASE=json.loads((Path(__file__).parents[1]/"examples/honeypot-snapshot.json").read_text())

class HoneypotTests(unittest.TestCase):
    def test_seeded_chain(self):
        r=assess(CASE)
        self.assertEqual(len(r["paths"]),1)
        self.assertFalse(r["exploit_verified"])
    def test_remove_role_binding(self):
        fixture=copy.deepcopy(CASE)
        fixture["rolebindings"]["items"]=[]
        self.assertEqual(assess(fixture)["paths"],[])
    def test_disable_token(self):
        fixture=copy.deepcopy(CASE)
        fixture["pods"]["items"][0]["spec"]["automountServiceAccountToken"]=False
        self.assertEqual(assess(fixture)["paths"],[])
    def test_remove_sensitive_permission(self):
        fixture=copy.deepcopy(CASE)
        fixture["roles"]["items"][0]["rules"][0]["resources"]=["configmaps"]
        self.assertEqual(assess(fixture)["paths"],[])

if __name__=="__main__":unittest.main()
