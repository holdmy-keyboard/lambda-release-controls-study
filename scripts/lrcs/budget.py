"""Conservative local dispatch ledger; never a provider-enforced spending cap.

One operator/controller owns this SQLite file. Reserve before any dispatched
work, keep aborted reservations, and reconcile out-of-band actions separately.
No method authorizes final collection or refunds failed attempts.
"""
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import sqlite3
import uuid

CAPS = {'prototype_paths':60, 'pilot_paths':180, 'lambda_mutations':2000,
        'signing_jobs':200,'s3_versions':3000,'s3_tier1':10000,'s3_tier2':300000,
        'invocations':1000,'runner_minutes':9000,'egress_bytes':5_000_000_000}
# Includes a sentinel reset, final upload, bundle and two receipts; charge the
# worst supported path even where a particular treatment uses less.
PATH_RESERVATION = {'lambda_mutations':2,'signing_jobs':1,'s3_versions':10,
                    's3_tier1':16,'s3_tier2':500,'invocations':1,
                    'runner_minutes':12,'egress_bytes':8_000_000}

class BudgetStop(ValueError):
    pass


def money(value):
    try:
        result=Decimal(str(value))
    except InvalidOperation as error:
        raise BudgetStop('Invalid monetary value') from error
    if not result.is_finite() or result < 0:
        raise BudgetStop('Monetary amounts must be finite and nonnegative')
    return result


class Ledger:
    def __init__(self,path):
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.db=sqlite3.connect(self.path,timeout=10,isolation_level=None)
        self.path.chmod(0o600)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY, phase TEXT NOT NULL, units TEXT NOT NULL, eur TEXT NOT NULL, status TEXT NOT NULL, run_id TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS accounting (id INTEGER PRIMARY KEY CHECK(id=1), incurred_eur TEXT NOT NULL, remaining_projection_eur TEXT NOT NULL, evidence TEXT NOT NULL)')
    def close(self):self.db.close()
    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
    def reconcile(self,incurred_eur,remaining_projection_eur,evidence):
        incurred,remaining=money(incurred_eur),money(remaining_projection_eur)
        if not isinstance(evidence,str) or not evidence.strip():raise BudgetStop('Reconciliation requires an evidence reference')
        with self.transaction():
            self.db.execute('INSERT OR REPLACE INTO accounting VALUES(1,?,?,?)',(str(incurred),str(remaining),evidence))
    def totals(self):
        counts={k:0 for k in CAPS};reserved=Decimal('0')
        for encoded,cost in self.db.execute('SELECT units,eur FROM reservations'):
            for key,value in json.loads(encoded).items():counts[key]+=value
            reserved+=money(cost)
        return counts,reserved
    def reserve(self,attempt_id,phase,units,eur):
        try:
            if str(uuid.UUID(attempt_id))!=attempt_id:raise ValueError
        except (ValueError,TypeError,AttributeError) as error:raise BudgetStop('Canonical UUID required') from error
        if phase not in ('prototype','pilot','setup'):raise BudgetStop('G4 does not authorize final or diagnostic collection')
        if not units or any(k not in CAPS or type(v) is not int or v<0 for k,v in units.items()):raise BudgetStop('Unknown, fractional or negative quantity')
        if phase!='prototype' and units.get('prototype_paths',0):raise BudgetStop('Phase/count conflict')
        if phase!='pilot' and units.get('pilot_paths',0):raise BudgetStop('Phase/count conflict')
        cost=money(eur)
        with self.transaction():
            accounting=self.db.execute('SELECT incurred_eur,remaining_projection_eur FROM accounting WHERE id=1').fetchone()
            if accounting is None:raise BudgetStop('No recorded budget reconciliation')
            incurred,remaining=map(money,accounting)
            if incurred+remaining>=Decimal('7'):raise BudgetStop('€7 pause-and-reconcile threshold reached')
            counts,reserved=self.totals()
            if reserved+cost>Decimal('2') or incurred+remaining+cost>Decimal('10'):raise BudgetStop('G4 allocation/project ceiling exceeded')
            for key,value in units.items():
                if counts[key]+value>CAPS[key]:raise BudgetStop('Quantity ceiling exceeded: '+key)
            try:
                self.db.execute('INSERT INTO reservations VALUES(?,?,?,?,?,NULL)',(attempt_id,phase,json.dumps(units,sort_keys=True),str(cost),'reserved'))
            except sqlite3.IntegrityError as error:raise BudgetStop('Attempt already reserved; retries require new IDs') from error
        return {'attempt_id':attempt_id,'phase':phase,'units':units,'reserved_eur':str(cost)}
    def bind_run(self,attempt_id,run_id):
        if not str(run_id).isdigit():raise BudgetStop('Actual numeric GitHub run ID required')
        with self.transaction():
            changed=self.db.execute("UPDATE reservations SET run_id=?,status='dispatched' WHERE id=? AND status='reserved' AND run_id IS NULL",(str(run_id),attempt_id)).rowcount
            if changed!=1:raise BudgetStop('Reservation absent or already dispatched')
