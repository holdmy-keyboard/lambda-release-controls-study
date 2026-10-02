"""Synthetic preflight/transport integration tests; no cloud calls."""
import copy,json,os,runpy,tempfile,time,unittest,uuid
from pathlib import Path
from unittest.mock import patch
from scripts.lrcs.runtime import prepare,load_config,StageError,Runtime,dump

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.identifier=str(uuid.uuid4());self.sha='01234567'*5
        self.inputs={'attempt_id':self.identifier,'workload':'timing','configuration':'C1','marker':'a'*32,'policy_id':'test'}
        self.env={'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':self.sha,
          'GITHUB_REPOSITORY':'test-owner/test-repo','GITHUB_REF':'refs/tags/lrcs-controller-v1',
          'GITHUB_WORKFLOW_REF':'test-owner/test-repo/.github/workflows/controller.yml@refs/tags/lrcs-controller-v1','GITHUB_RUN_ID':'123'}
        self.config={'policies':{'test':{}},'identities':[{'repository':self.env['GITHUB_REPOSITORY'],'ref':self.env['GITHUB_REF'],'workflow_ref':self.env['GITHUB_WORKFLOW_REF'],'commit':self.sha,'role':'controller'}],
          'authorized_attempts':{self.identifier:{'inputs':copy.deepcopy(self.inputs),'phase':'prototype','run_id':'123'}}}
        self.clock={'clock_owner':'github_job','monotonic_ns':time.monotonic_ns(),'utc':'synthetic'}
    def call(self):return prepare(self.config,{'inputs':self.inputs},self.clock,self.env,self.sha)
    def test_exact_bound_first_attempt(self):self.assertEqual(self.call()['configuration'],'C1')
    def test_rerun_rejected(self):
        self.env['GITHUB_RUN_ATTEMPT']='2'
        with self.assertRaises(StageError):self.call()
    def test_other_workflow_commit_rejected(self):
        self.env['GITHUB_WORKFLOW_REF']=self.env['GITHUB_WORKFLOW_REF'].replace('controller','release')
        with self.assertRaises(StageError):self.call()
    def test_unreserved_input_rejected(self):
        self.inputs['configuration']='C0'
        with self.assertRaises(StageError):self.call()
    def test_other_run_replay_rejected(self):
        self.env['GITHUB_RUN_ID']='456'
        with self.assertRaises(StageError):self.call()
    def test_no_final_authorization(self):
        self.config['authorized_attempts'][self.identifier]['phase']='final'
        with self.assertRaises(StageError):self.call()
    def test_expired_clock(self):
        self.clock['monotonic_ns']-=601_000_000_000
        with self.assertRaises(StageError):self.call()
    def test_committed_config_disabled_without_network(self):
        with patch.dict(os.environ,{},clear=True),patch('subprocess.run',side_effect=AssertionError('Network/process forbidden')):
            with self.assertRaises(StageError):load_config(Path('config/runner_config.json'))
    def test_mutated_config_rejected_between_stages(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.json';dump(path,self.call())
            self.config['extra']='changed'
            with self.assertRaises(StageError):Runtime(self.config,path)
    def test_only_real_first_clock_can_authorize(self):
        self.clock['monotonic_ns']=time.monotonic_ns()+5_000_000_000
        with self.assertRaises(StageError):self.call()

if __name__=='__main__':unittest.main()
