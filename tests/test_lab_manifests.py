import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
class ManifestTests(unittest.TestCase):
    def test_fixture_labels(self):
        text = (ROOT / "lab/manifests.yaml").read_text()
        self.assertIn('cyber-defense/entrypoint: "true"', text)
        self.assertIn('cyber-defense/protected: "true"', text)
        self.assertIn('automountServiceAccountToken: false', text)
    def test_policy_targets_canary(self):
        text = (ROOT / "lab/policies/restrict.yaml").read_text()
        self.assertIn('app: canary', text)
        self.assertIn('ingress: []', text)
    def test_check_guard(self):
        text = (ROOT / "lab/check.sh").read_text()
        self.assertIn('kind-cyber-defense', text)
        self.assertIn('canary.cyber-lab.svc.cluster.local', text)
if __name__ == "__main__":
    unittest.main()
