"""Unit tests use synthetic reservations, not expenditure observations."""
from pathlib import Path
import tempfile,unittest,uuid
from scripts.lrcs.budget import Ledger,BudgetStop

class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.ledger=Ledger(Path(self.tmp.name)/'unit.sqlite');self.addCleanup(self.ledger.close)
    def ready(self):self.ledger.reconcile('0','1.70','synthetic unit-test estimate')
    def reserve(self,**kw):
        args=dict(attempt_id=str(uuid.uuid4()),phase='prototype',units={'prototype_paths':1},eur='0.01');args.update(kw);return self.ledger.reserve(**args)
    def test_unreconciled_stops(self):
        with self.assertRaises(BudgetStop):self.reserve()
    def test_final_not_authorized(self):
        self.ready()
        with self.assertRaises(BudgetStop):self.reserve(phase='final')
    def test_atomic_count_limit(self):
        self.ready();self.reserve(units={'prototype_paths':60})
        with self.assertRaises(BudgetStop):self.reserve()
        self.assertEqual(self.ledger.totals()[0]['prototype_paths'],60)
    def test_setup_euro_limit(self):
        self.ready();self.reserve(eur='2')
        with self.assertRaises(BudgetStop):self.reserve()
    def test_pause_threshold(self):
        self.ledger.reconcile('6.99','0.01','synthetic')
        with self.assertRaises(BudgetStop):self.reserve()
    def test_no_nan_or_negative_bypass(self):
        self.ready()
        for val in ('NaN','Infinity','-1'):
            with self.assertRaises(BudgetStop):self.reserve(eur=val)
        with self.assertRaises(BudgetStop):self.reserve(units={'prototype_paths':-1})
    def test_replay_and_double_binding(self):
        self.ready();first=self.reserve();identifier=first['attempt_id']
        with self.assertRaises(BudgetStop):self.reserve(attempt_id=identifier)
        self.ledger.bind_run(identifier,123)
        with self.assertRaises(BudgetStop):self.ledger.bind_run(identifier,456)
    def test_failed_reservations_not_refunded(self):
        self.ready();self.reserve(units={'s3_versions':3000})
        with self.assertRaises(BudgetStop):self.reserve(units={'s3_versions':1})

if __name__=='__main__':unittest.main()
