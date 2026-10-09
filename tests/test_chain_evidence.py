import unittest
from src.chain_evidence import combine

NETWORK={"observations":[{"context":"kind-cyber-defense","source":"pod:cyber-lab/frontend-1","target":"pod:cyber-lab/canary-1","result":"reachable"}]}
AUTH={"context":"kind-cyber-defense","principal":"system:serviceaccount:cyber-lab:honeypot-reader","resource":"configmaps","resource_name":"honeypot-canary","result":"allowed"}

class ChainEvidenceTests(unittest.TestCase):
    def test_both(self):
        result=combine(NETWORK,AUTH)
        self.assertEqual(result["state"],"both-prerequisites-observed")
        self.assertFalse(result["exploit_verified"])
    def test_network_block(self):
        n={"observations":[dict(NETWORK["observations"][0],result="blocked")]}
        self.assertEqual(combine(n,AUTH)["state"],"prerequisite-denied")
    def test_permission_denied(self):
        self.assertEqual(combine(NETWORK,dict(AUTH,result="denied"))["state"],"prerequisite-denied")
    def test_unknown(self):
        n={"observations":[dict(NETWORK["observations"][0],result="inconclusive")]}
        self.assertEqual(combine(n,AUTH)["state"],"indeterminate")
    def test_wrong_principal_rejected(self):
        with self.assertRaises(ValueError): combine(NETWORK,dict(AUTH,principal="unexpected"))
if __name__=="__main__":unittest.main()
