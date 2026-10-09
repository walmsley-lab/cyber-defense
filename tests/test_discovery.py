import unittest
from src.discovery import discover
class DiscoveryTests(unittest.TestCase):
 def test_affected_exact_version(self):
  x={"packages":[{"ecosystem":"PyPI","name":"demo","version":"1"}],"advisories":[{"id":"LOCAL", "affected":[{"package":{"ecosystem":"PyPI","name":"demo"},"versions":["1"]}]}]}
  self.assertEqual(discover(x)["findings"][0]["rule"],"OSV-EXACT")
 def test_unknown_range_not_assumed_vulnerable(self):
  x={"packages":[{"ecosystem":"PyPI","name":"demo","version":"7"}],"advisories":[{"id":"LOCAL","affected":[{"package":{"ecosystem":"PyPI","name":"demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1"}]}]}]}]}
  self.assertEqual(discover(x)["findings"][0]["state"],"needs-review")
 def test_tls_and_ssh(self):
  x={"tls_observations":[{"id":"lab","verified":False,"hsts":False,"min_tls":"TLSv1.1"}],"ssh_configurations":[{"id":"host","options":{"PermitRootLogin":"yes","AllowTcpForwarding":"yes"}}]}
  self.assertEqual(len(discover(x)["findings"]),5)
 def test_web_headers(self):
  x={"web_observations":[{"id":"app","source":"http://lab","headers":{"Server":"nginx","Access-Control-Allow-Origin":"*","X-Content-Type-Options":"nosniff"}}]}
  rules={f["rule"] for f in discover(x)["findings"]}
  self.assertEqual(rules,{"WEB-CSP","WEB-FRAME","WEB-CORS-WILDCARD","WEB-BANNER"})
 def test_web_headers_hardened_quiet(self):
  x={"web_observations":[{"id":"app","headers":{"Content-Security-Policy":"default-src 'self'","X-Content-Type-Options":"nosniff"}}]}
  self.assertEqual(discover(x)["findings"],[])
 def test_clean_case(self):
  self.assertEqual(discover({"packages":[],"tls_observations":[],"ssh_configurations":[]})["findings"],[])
if __name__=="__main__":unittest.main()
