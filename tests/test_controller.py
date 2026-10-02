"""Independent observer assertions against synthetic records."""
import copy,unittest
from scripts.lrcs.controller import collect_ready
from scripts.lrcs.deployment import hash_base64

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.expected={'attempt_id':'synthetic','configuration':'C3','run_id':'123'}
        self.receipt=self.expected|{'outcome':'allow','deployment_attempted':True,'accepted_update':{'RevisionId':'fresh'},'pre_target':{'RevisionId':'old'},'final_sha256':'ab'*32}
        self.snapshot={'RevisionId':'fresh','State':'Active','LastUpdateStatus':'Successful','CodeSha256':hash_base64('ab'*32)}
    def test_independent_ready(self):self.assertTrue(collect_ready(self.receipt,self.snapshot,self.expected))
    def test_cross_run_receipt(self):
        self.receipt['run_id']='456'
        with self.assertRaises(ValueError):collect_ready(self.receipt,self.snapshot,self.expected)
    def test_old_code_not_completion(self):
        self.snapshot['RevisionId']='old';self.assertFalse(collect_ready(self.receipt,self.snapshot,self.expected))
    def test_allow_requires_api_acceptance(self):
        del self.receipt['accepted_update']
        with self.assertRaises(ValueError):collect_ready(self.receipt,self.snapshot,self.expected)
    def test_pending_is_not_an_outcome(self):
        self.receipt['outcome']=None;self.assertFalse(collect_ready(self.receipt,{},self.expected))
    def test_block_remains_block_without_deployment(self):
        self.receipt.update(outcome='block',deployment_attempted=False)
        self.assertTrue(collect_ready(self.receipt,{},self.expected))

if __name__=='__main__':unittest.main()
