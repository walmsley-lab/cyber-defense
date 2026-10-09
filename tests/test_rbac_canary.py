import unittest
from src.rbac_canary import parse_review,CONTEXT,PRINCIPAL,NAME

class AuthorizationTests(unittest.TestCase):
    def test_allowed(self):
        self.assertEqual(parse_review({"status":{"allowed":True}}),"allowed")
    def test_denied(self):
        self.assertEqual(parse_review({"status":{"allowed":False}}),"denied")
    def test_error_is_not_denial(self):
        self.assertEqual(parse_review({"status":{"allowed":False,"evaluationError":"incomplete"}}),"inconclusive")
    def test_scope_is_fixed(self):
        self.assertEqual(CONTEXT,"kind-cyber-defense")
        self.assertEqual(NAME,"honeypot-canary")
        self.assertIn("cyber-lab:honeypot-reader",PRINCIPAL)

if __name__=="__main__":unittest.main()
