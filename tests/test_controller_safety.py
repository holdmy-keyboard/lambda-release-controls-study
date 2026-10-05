"""Synthetic controller credential/deadline regressions; never live cloud calls."""
import json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from scripts.lrcs.controller import Controller
from scripts.lrcs.runtime import StageError

class ControllerSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.c=Controller({'account_id':'unit-account','study_repository':'unit/repo'},'observer',self.root/'attempt','unit-gh',self.root/'token','reset')
    def test_same_profile_rejected(self):
        with self.assertRaises(StageError):Controller({},'same',self.root/'other','gh',self.root/'token','same')
    def test_aliases_for_same_principal_rejected(self):
        self.c.aws=lambda *a,**kw:{'Account':'unit-account','Arn':'arn:aws:sts::unit:assumed-role/role/session-'+kw.get('profile','observer')}
        with self.assertRaises(StageError):self.c.validate_sessions()
    def test_exact_observer_and_operator_required(self):
        self.c.reset_principal_arn='arn:aws:iam::unit-account:user/operator'
        observer={'Account':'unit-account','Arn':'arn:aws:sts::unit-account:assumed-role/lrcs-20260928-observer/session'}
        reset={'Account':'unit-account','Arn':self.c.reset_principal_arn}
        self.c.aws=Mock(side_effect=[observer,reset])
        self.assertEqual(self.c.validate_sessions(),{'observer':observer,'reset':reset})
        self.c.aws=Mock(side_effect=[dict(observer,Arn=observer['Arn'].replace('lrcs-20260928-observer','Administrator')),reset])
        with self.assertRaises(StageError):self.c.validate_sessions()
        self.c.aws=Mock(side_effect=[observer,dict(reset,Arn=reset['Arn']+'-other')])
        with self.assertRaises(StageError):self.c.validate_sessions()
    def test_local_operator_identity_excluded_from_runner_config(self):
        config={'reset_principal_arn':'arn:aws:iam::unit-account:user/operator','study_repository':'unit/repo'}
        controller=Controller(config,'observer',self.root/'private-binding','gh',self.root/'token','reset')
        self.assertEqual(controller.reset_principal_arn,config['reset_principal_arn'])
        self.assertNotIn('reset_principal_arn',controller.c)
        self.assertIn('reset_principal_arn',config)
    def test_ambient_credentials_not_carried_into_observer(self):
        self.c.command=Mock(return_value={})
        with patch.dict(os.environ,{'AWS_ACCESS_KEY_ID':'SYNTHETIC','AWS_SECRET_ACCESS_KEY':'SYNTHETIC','AWS_SESSION_TOKEN':'SYNTHETIC'}):self.c.aws('sts','get-caller-identity',[])
        args=self.c.command.call_args.args;self.assertNotIn('AWS_ACCESS_KEY_ID',args[1]);self.assertIn('observer',args[0])
    def test_timeout_creates_persistent_hold_even_when_cancel_fails(self):
        self.c.gh_api=Mock(side_effect=StageError('synthetic cancellation failure'));self.c.aws=Mock(return_value={'State':'Active'})
        result=self.c.abort_and_reconcile('123','unit','C0',StageError('timeout'))
        self.assertTrue((self.root/'reconciliation-required.json').exists());self.assertTrue(result['requires_reconciliation']);self.assertFalse(result['reservation_refunded']);self.assertTrue((self.c.d/'cancellation-reconciliation.json').exists())
    def test_unknown_run_is_not_canceled_by_guess(self):
        self.c.gh_api=Mock();self.c.aws=Mock(return_value={})
        result=self.c.abort_and_reconcile(None,'unit','C0',StageError('ambiguous dispatch'))
        self.c.gh_api.assert_not_called();self.assertTrue(result['run_identity_unresolved'])
    def test_expired_deadline_never_starts_subprocess(self):
        self.c.deadline=time.monotonic()-1
        with patch('scripts.lrcs.controller.subprocess.run',side_effect=AssertionError('must not start')):
            with self.assertRaises(StageError):self.c.command(['unit'])

if __name__=='__main__':unittest.main()
