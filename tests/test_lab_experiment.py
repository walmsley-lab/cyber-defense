import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from src.lab_experiment import experiment

def evidence(result):
    return {"context":"kind-cyber-defense","source":"pod:cyber-lab/frontend-1",
            "target":"pod:cyber-lab/canary-1","result":result}
def access(result):
    return {"context":"kind-cyber-defense","principal":"system:serviceaccount:cyber-lab:honeypot-reader",
            "resource":"configmaps","resource_name":"honeypot-canary","result":result}

class LabExperimentTests(unittest.TestCase):
    def test_two_phase_run(self):
        calls=[]
        states=iter([evidence("reachable"),evidence("blocked")])
        permissions=iter([access("allowed"),access("denied")])
        def command(argv,timeout=90):
            calls.append(argv)
            if argv==["kubectl","config","current-context"]:
                return SimpleNamespace(stdout="kind-cyber-defense\n")
            return SimpleNamespace(stdout="")
        with tempfile.TemporaryDirectory() as tmp:
            result=experiment(Path(tmp)/"new",command=command,
                              network=lambda:next(states),authorization=lambda:next(permissions))
            self.assertEqual(result["network_comparison"]["change"],"reachability-removed")
            self.assertEqual(result["baseline_chain"]["state"],"both-prerequisites-observed")
            self.assertEqual(result["restricted_chain"]["state"],"prerequisite-denied")
            self.assertTrue((Path(tmp)/"new"/"report.json").exists())
            self.assertTrue(any("restrict.yaml" in c for c in calls))
    def test_refuse_unapproved_context(self):
        def command(argv,timeout=90):return SimpleNamespace(stdout="production-cluster\n")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                experiment(Path(tmp)/"new",command=command)
            self.assertFalse((Path(tmp)/"new").exists())
    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"results"
            path.mkdir()
            (path/"report.json").write_text("existing")
            def command(argv,timeout=90):return SimpleNamespace(stdout="kind-cyber-defense\n")
            with self.assertRaises(FileExistsError):
                experiment(path,command=command)
if __name__=="__main__":unittest.main()
