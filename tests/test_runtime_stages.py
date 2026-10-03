"""Synthetic stage-boundary regressions for issues found during code review."""
import json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from scripts.lrcs.runtime import Runtime,StageError

class RuntimeStageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.r=Runtime.__new__(Runtime);self.r.d=Path(self.tmp.name);self.r.path=self.r.d/'state.json';self.r.artifact=self.r.d/'final.zip'
        self.r.s={'attempt_id':'unit','run_id':'123','workload':'functional','configuration':'C0','inputs':{'fixture_key':'outage'},'claim_reference':{'version':'unit'},'stage_events':[],
                  'clock':{'monotonic_ns':time.monotonic_ns()},'outcome':None}
        self.r.c={'fixtures':{'outage':{'artifact':{'version':'unit'},'bundle':{'version':'bundle'},'evidence_status':'timeout','marker':'a'*32}},'buckets':{'artifacts':'unit-bucket'}}
    def test_no_gate_arms_never_acquire_evidence_or_inject_outage(self):
        for arm in ('C0','C2'):
            self.r.s['configuration']=arm;self.r.get=Mock(return_value='ab'*32)
            with patch('scripts.lrcs.runtime.time.sleep',side_effect=AssertionError('Resolver must not run')):self.r.acquire()
            self.assertEqual(self.r.get.call_count,1);self.assertEqual(self.r.s['acquisition_status'],'not_applicable');self.assertIsNone(self.r.s['acquisition_elapsed_seconds'])
    def test_gate_arm_fault_invokes_resolver(self):
        self.r.s['configuration']='C1';self.r.get=Mock(return_value='ab'*32)
        with patch('scripts.lrcs.runtime.time.sleep') as sleep:self.r.acquire()
        sleep.assert_called_once_with(10);self.assertEqual(self.r.s['acquisition_status'],'unavailable')
    def test_readiness_receipt_precedes_diagnostics(self):
        calls=[]
        self.r.s.update(outcome='allow',validity='valid',deployment_attempted=True)
        self.r.put=lambda path,bucket,key:(calls.append(key) or {'version':'unit','key':key})
        self.r.publish_receipt()
        self.assertEqual(calls,['receipts/controller/unit/receipt.json']);self.assertFalse((self.r.d/'diagnostics.zip').exists())
        self.assertNotIn('stage_events',json.loads((self.r.d/'receipt.json').read_text()))
    def test_smoke_fails_validity_without_overwriting_outcome(self):
        self.r.s.update(outcome='allow',validity='valid',receipt_reference={'version':'unit'})
        def aws(*args,**kw):
            self.assertIn('--cli-binary-format',args[2]);(self.r.d/'smoke-response.json').write_text('{"errorMessage":"wrong handler"}')
            return {'StatusCode':200,'FunctionError':'Unhandled'}
        self.r.aws=aws;self.r.smoke();self.assertEqual(self.r.s['outcome'],'allow');self.assertEqual(self.r.s['validity'],'measurement_invalid')
    def test_stage_clock_reports_nonzero_elapsed_and_no_duplicate_open(self):
        self.r.start_stage('build')
        with self.assertRaises(StageError):self.r.start_stage('build')
        self.r.end_stage('build');self.assertGreater(self.r.s['stage_envelopes'][0]['duration_seconds'],0)
    def test_cleanup_has_separate_bounded_clock(self):
        self.r.s['clock']['monotonic_ns']-=610_000_000_000
        with self.assertRaises(StageError):self.r.remaining(10)
        self.r.s['active_end_monotonic_ns']=time.monotonic_ns();self.assertGreater(self.r.remaining(10),0)
        self.r.s['active_end_monotonic_ns']-=121_000_000_000
        with self.assertRaises(StageError):self.r.remaining(10)

if __name__=='__main__':unittest.main()
