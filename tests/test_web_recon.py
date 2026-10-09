import unittest
from src.web_recon import build_snapshot
from src.discovery import discover
class WebReconTests(unittest.TestCase):
 def test_plaintext_http_maps_to_tls_gaps(self):
  snap=build_snapshot("http://lab/",200,{"Server":"nginx","Access-Control-Allow-Origin":"*"})
  tls=snap["tls_observations"][0]
  self.assertFalse(tls["redirect_http_to_https"])
  self.assertFalse(tls["hsts"])
  self.assertEqual(tls["min_tls"],"none-plaintext-http")
 def test_https_final_url_marks_redirect_and_hsts(self):
  snap=build_snapshot("http://lab/",200,{"Strict-Transport-Security":"max-age=31536000"},final_url="https://lab/")
  tls=snap["tls_observations"][0]
  self.assertTrue(tls["redirect_http_to_https"])
  self.assertTrue(tls["hsts"])
  self.assertNotIn("min_tls",tls)
 def test_snapshot_feeds_discovery(self):
  snap=build_snapshot("http://lab/",200,{"Server":"nginx","Access-Control-Allow-Origin":"*"})
  rules={f["rule"] for f in discover(snap)["findings"]}
  self.assertIn("WEB-CORS-WILDCARD",rules)
  self.assertIn("TLS-HSTS",rules)
 def test_only_security_relevant_headers_retained(self):
  snap=build_snapshot("http://lab/",200,{"Date":"now","ETag":"abc","Server":"nginx"})
  self.assertEqual(set(snap["web_observations"][0]["headers"]),{"server"})
if __name__=="__main__":unittest.main()
