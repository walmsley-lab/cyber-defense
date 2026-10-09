import copy
import unittest
from src.campaign import validate, ranked, apply_event

BASE={"actions":[{"id":"start"},{"id":"a","requires_all":["start"]},
                 {"id":"b","requires_all":["start"]},
                 {"id":"join","requires_all":["a","b"]},
                 {"id":"alternative","requires_any":["a","b"]}]}
class CampaignTests(unittest.TestCase):
    def test_initial(self):
        self.assertEqual([x["id"] for x in ranked(copy.deepcopy(BASE)) if x["readiness"]=="ready"],["start"])
    def test_branches_and_join(self):
        data=copy.deepcopy(BASE)
        apply_event(data,{"action_id":"start","status":"passed"})
        apply_event(data,{"action_id":"a","status":"passed"})
        status={x["id"]:x["readiness"] for x in ranked(data)}
        self.assertEqual(status["alternative"],"ready")
        self.assertEqual(status["join"],"waiting")
        apply_event(data,{"action_id":"b","status":"passed"})
        self.assertEqual({x["id"]:x["readiness"] for x in ranked(data)}["join"],"ready")
    def test_failed_branch_not_full_failure(self):
        data=copy.deepcopy(BASE)
        apply_event(data,{"action_id":"start","status":"passed"})
        apply_event(data,{"action_id":"a","status":"failed"})
        apply_event(data,{"action_id":"b","status":"passed"})
        self.assertEqual({x["id"]:x["readiness"] for x in ranked(data)}["alternative"],"ready")
    def test_cycle(self):
        data={"actions":[{"id":"a","requires_all":["b"]},{"id":"b","requires_all":["a"]}]}
        with self.assertRaises(ValueError):validate(data)
    def test_cannot_claim_pass_without_prereqs(self):
        with self.assertRaises(ValueError):
            apply_event(copy.deepcopy(BASE),{"action_id":"join","status":"passed"})
if __name__=="__main__":unittest.main()
