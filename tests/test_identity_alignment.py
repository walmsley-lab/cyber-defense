"""Test the actual manifest's workload/RBAC identity linkage without PyYAML."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]

class IdentityAlignmentTests(unittest.TestCase):
    def test_frontend_identity_matches_rbac_subject(self):
        manifests=(ROOT/"lab/manifests.yaml").read_text()
        rbac=(ROOT/"lab/rbac-honeypot.yaml").read_text()
        frontend=manifests.split("  name: frontend\n",1)[1].split("---",1)[0]
        self.assertIn("serviceAccountName: honeypot-reader",frontend)
        self.assertIn("automountServiceAccountToken: false",frontend)
        self.assertIn("name: honeypot-reader",rbac)
        self.assertIn("kind: RoleBinding",rbac)
    def test_canary_does_not_rely_on_same_privileged_identity(self):
        manifests=(ROOT/"lab/manifests.yaml").read_text()
        canary=manifests.split("  name: canary\n",1)[1].split("---",1)[0]
        self.assertIn("serviceAccountName: lab-workloads",canary)
if __name__=="__main__":
    unittest.main()
