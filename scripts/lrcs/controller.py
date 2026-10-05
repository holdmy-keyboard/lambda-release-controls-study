"""Serialized, budget-reserved dispatch and independent readiness collection.

Prototype only: real integration checks and protected refs must be completed
before the disabled configuration can be bound. This controller does not run a
final-data batch, manufacture fixtures or label observations from predictions.
"""
import argparse,datetime as dt,fcntl,hashlib,json,os
from pathlib import Path
import subprocess,time,uuid

from scripts.lrcs.budget import Ledger,PATH_RESERVATION
from scripts.lrcs.runtime import load_config,dump,StageError
from scripts.lrcs.deployment import ready,validate_target


def collect_ready(receipt,observed,expected):
    """Independent observer assertion; no golden-fixture digest authorization."""
    if any(receipt.get(k)!=v for k,v in expected.items()):raise ValueError('Receipt belongs to another attempt/configuration/run')
    if receipt.get('outcome') in ('allow','allow_with_warning'):
        if not receipt.get('deployment_attempted') or not receipt.get('accepted_update'):raise ValueError('Allow receipt lacks accepted update')
        if not ready(observed,receipt['accepted_update'],receipt['pre_target']['RevisionId'],receipt['final_sha256']):return False
    return receipt.get('outcome') in ('allow','allow_with_warning','block','operational_error')


class Controller:
    def __init__(self,config,profile,directory,gh,token_file,reset_profile):
        if not profile or not reset_profile or profile==reset_profile:
            raise StageError('Distinct observer and reset AWS profiles are required')
        # Operator identity is a local authentication binding, never runner
        # routing metadata. Keep it out of the repository-variable payload.
        self.reset_principal_arn=config.get('reset_principal_arn')
        self.c={key:value for key,value in config.items() if key!='reset_principal_arn'}
        self.profile=profile;self.reset_profile=reset_profile
        self.d=Path(directory);self.d.mkdir(mode=0o700,parents=True,exist_ok=False)
        self.gh=str(gh);self.token_file=Path(token_file);self.event=0;self.deadline=None
    def command(self,argv,env=None,timeout=30,stdin=None,allowed=(0,)):
        if self.deadline is not None:
            timeout=min(timeout,self.deadline-time.monotonic())
            if timeout<=0:raise StageError('Controller deadline exceeded',reason='timeout')
        before=time.monotonic_ns()
        record={'argv':argv,'started_monotonic_ns':before}
        try:
            p=subprocess.run(argv,input=stdin,capture_output=True,text=True,env=env,timeout=timeout)
            record.update(returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
        except subprocess.TimeoutExpired as error:
            def text(value):return value.decode('utf-8',errors='replace') if isinstance(value,bytes) else value
            record.update(returncode=None,timed_out=True,stdout=text(error.stdout),stderr=text(error.stderr))
            raise StageError('Controller subprocess timed out',reason='timeout') from error
        finally:
            record['ended_monotonic_ns']=time.monotonic_ns()
            dump(self.d/f'command-{self.event:04d}.json',record,True);self.event+=1
        if p.returncode not in allowed:raise StageError('Controller subprocess failed; see private command evidence')
        return json.loads(p.stdout) if p.stdout.strip() else {}
    def gh_api(self,endpoint,method='GET',body=None):
        env=dict(os.environ);env.update(GH_TOKEN=self.token_file.read_text().strip(),GH_PROMPT_DISABLED='1',GH_HOST='github.com');env.pop('GH_DEBUG',None)
        argv=[self.gh,'api',endpoint,'--hostname','github.com','--method',method,'-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2022-11-28']
        if body is not None:argv+=['--input','-']
        return self.command(argv,env,stdin=json.dumps(body) if body is not None else None)
    def aws(self,service,operation,args,timeout=30,*,profile=None):
        # Each local call resolves its explicitly selected profile. Never carry
        # ambient exported credentials across the reset/observer boundary.
        env=dict(os.environ)
        for key in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN',
                    'AWS_SECURITY_TOKEN','AWS_PROFILE','AWS_DEFAULT_PROFILE',
                    'AWS_ROLE_ARN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_SESSION_NAME'):
            env.pop(key,None)
        env.update(AWS_MAX_ATTEMPTS='1',AWS_RETRY_MODE='standard',AWS_PAGER='')
        return self.command(['aws',service,operation,*args,'--region','eu-central-1','--profile',profile or self.profile,'--output','json','--no-cli-pager'],env,timeout)
    def validate_sessions(self):
        observer=self.aws('sts','get-caller-identity',[])
        reset=self.aws('sts','get-caller-identity',[],profile=self.reset_profile)
        if any(identity.get('Account')!=self.c['account_id'] for identity in (observer,reset)):
            raise StageError('Observer/reset AWS account mismatch')
        # Different aliases for the same IAM role are not credential separation.
        def principal(arn):
            if not isinstance(arn,str) or not arn:raise StageError('Missing session principal ARN')
            if ':assumed-role/' in arn:return arn.rsplit('/',1)[0]
            return arn
        if principal(observer.get('Arn'))==principal(reset.get('Arn')):
            raise StageError('Observer and reset must use distinct IAM principals')
        expected_observer=f'arn:aws:sts::{self.c["account_id"]}:assumed-role/lrcs-20260928-observer'
        expected_reset=self.reset_principal_arn
        if principal(observer.get('Arn'))!=expected_observer:
            raise StageError('Observer must use the exact scoped study observer role')
        if not expected_reset or reset.get('Arn')!=expected_reset:
            raise StageError('Reset operator differs from the verified bound principal')
        return {'observer':observer,'reset':reset}
    def reset(self,arm):
        name='lrcs-20260928-'+arm.lower()
        before=self.aws('lambda','get-function-configuration',['--function-name',name],profile=self.reset_profile);validate_target(before,self.c['account_id'],arm)
        sentinel=self.c['sentinel']
        accepted=self.aws('lambda','update-function-code',['--function-name',name,'--s3-bucket',sentinel['bucket'],'--s3-key',sentinel['key'],
            '--s3-object-version',sentinel['version'],'--revision-id',before['RevisionId'],'--no-publish'],profile=self.reset_profile)
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            snapshot=self.aws('lambda','get-function-configuration',['--function-name',name],min(30,deadline-time.monotonic()),profile=self.reset_profile)
            if ready(snapshot,accepted,before['RevisionId'],sentinel['sha256']):return snapshot
            time.sleep(2)
        raise StageError('Sentinel reset did not become ready',reason='timeout')
    def hold(self,detail):
        # A released process lock is not permission to ignore uncertain remote
        # work. Reconciliation explicitly clears this persistent operator hold.
        path=self.d.parent/'reconciliation-required.json'
        if not path.exists():dump(path,{'attempt_directory':str(self.d),'detail':detail},True)
    def abort_and_reconcile(self,run_id,identifier,arm,error):
        self.hold(str(error))
        evidence={'attempt_id':identifier,'run_id':run_id,'reason':str(error),
                  'reservation_refunded':False,'late_deployment_possible':True,
                  'cancellation_confirmed':False,'requires_reconciliation':True}
        self.deadline=time.monotonic()+45
        repo=self.c['study_repository']
        if run_id is not None and str(run_id).isdigit():
            try:
                self.gh_api(f'repos/{repo}/actions/runs/{run_id}/cancel','POST')
                evidence['cancel_requested']=True
            except (OSError,ValueError,StageError,subprocess.SubprocessError) as failure:
                evidence['cancel_request_error']=str(failure)
            try:
                while time.monotonic()<self.deadline-10:
                    status=self.gh_api(f'repos/{repo}/actions/runs/{run_id}')
                    if str(status.get('id'))!=str(run_id):raise StageError('Cancellation response belongs to another run')
                    evidence['last_run_status']=status
                    if status.get('status')=='completed':
                        evidence['cancellation_confirmed']=status.get('conclusion')=='cancelled'
                        evidence['run_terminal']=True
                        break
                    time.sleep(2)
            except (OSError,ValueError,StageError,subprocess.SubprocessError) as failure:
                evidence['cancel_confirmation_error']=str(failure)
        else:
            evidence['cancel_requested']=False
            evidence['run_identity_unresolved']=True
        try:
            evidence['observed_target_after_abort']=self.aws('lambda','get-function-configuration',
                ['--function-name','lrcs-20260928-'+arm.lower()],timeout=10)
        except (OSError,ValueError,StageError,subprocess.SubprocessError) as failure:
            evidence['target_reconciliation_error']=str(failure)
        finally:
            self.deadline=None
            dump(self.d/'cancellation-reconciliation.json',evidence,True)
        # Even terminal workflow cancellation cannot undo an accepted Lambda
        # request; the operator must inspect this snapshot and settle late state.
        return evidence
    def read_versioned_receipt(self,key,filename):
        head=self.aws('s3api','head-object',['--bucket',self.c['buckets']['artifacts'],'--key',key],timeout=15)
        if not head.get('VersionId') or head['VersionId']=='null' or head.get('ContentLength',0)>1048576:
            raise StageError('Invalid receipt version/size')
        path=self.d/filename
        metadata=self.aws('s3api','get-object',['--bucket',self.c['buckets']['artifacts'],'--key',key,
            '--version-id',head['VersionId'],str(path)])
        if metadata.get('VersionId')!=head['VersionId']:raise StageError('Receipt version changed')
        return json.loads(path.read_text()),head['VersionId'],hashlib.sha256(path.read_bytes()).hexdigest()
    def reconcile_postrun(self,result,expected,deadline):
        # Readiness timing is already frozen. Post-job validity/diagnostic checks
        # are outside both measured endpoints and inside the serialization lock.
        repo=self.c['study_repository'];run_id=expected['run_id']
        while time.monotonic()<deadline:
            run=self.gh_api(f'repos/{repo}/actions/runs/{run_id}')
            if str(run.get('id'))!=run_id:raise StageError('Postrun status belongs to another run')
            if run.get('status')=='completed':break
            time.sleep(2)
        else:raise StageError('Job did not finish for postrun reconciliation',reason='timeout')
        post,version,digest=self.read_versioned_receipt(
            f'receipts/controller/{expected["attempt_id"]}/postrun.json','postrun.json')
        if any(post.get(k)!=v for k,v in expected.items()):raise StageError('Postrun manifest belongs to another attempt')
        result['reconciliation']={'postrun_version':version,'postrun_sha256':digest,
                                  'run_conclusion':run.get('conclusion'),'postrun':post}
        if result['outcome'] in ('allow','allow_with_warning'):
            if post.get('validity')!='valid' or run.get('conclusion')!='success':
                result['validity']=post.get('validity') if post.get('validity') in ('measurement_invalid','fixture_invalid') else 'unresolved'
                self.hold('Post-readiness correctness/finalization failed; inspect postrun manifest')
        dump(self.d/'reconciled-observation.json',result,True)
        return result
    def monitor(self,identifier,arm,expected_commit,reset,ledger,started,started_utc,deadline):
        repo=self.c['study_repository'];run_id=None
        try:
            while time.monotonic()<deadline:
                runs=self.gh_api(f'repos/{repo}/actions/workflows/controller.yml/runs?event=workflow_dispatch&per_page=100')['workflow_runs']
                matches=[r for r in runs if r.get('display_title')=='lrcs-'+identifier and r.get('head_sha')==expected_commit and r.get('run_attempt')==1]
                if len(matches)>1:raise StageError('Duplicate dispatches found; no measurement can be attributed')
                if matches:
                    run_id=str(matches[0]['id']);ledger.bind_run(identifier,run_id);break
                time.sleep(2)
            if not run_id:raise StageError('Dispatch run not identified within deadline',reason='timeout')
            expected={'attempt_id':identifier,'configuration':arm,'run_id':run_id}
            key=f'receipts/controller/{identifier}/receipt.json'
            while time.monotonic()<deadline:
                try:receipt,version,digest=self.read_versioned_receipt(key,'receipt.json')
                except StageError as error:
                    if error.reason=='timeout':raise
                    time.sleep(2);continue
                snapshot=self.aws('lambda','get-function-configuration',['--function-name','lrcs-20260928-'+arm.lower()])
                if not collect_ready(receipt,snapshot,expected):raise StageError('Terminal receipt not independently confirmed')
                if receipt['outcome']=='block' and any(snapshot.get(k)!=reset.get(k) for k in ('RevisionId','CodeSha256','State','LastUpdateStatus')):
                    raise StageError('Blocked attempt changed target state; no security detection may be credited')
                ended=time.monotonic_ns()
                result={'attempt_id':identifier,'run_id':run_id,'outcome':receipt['outcome'],'validity':receipt.get('validity','unresolved'),
                    'e2e_seconds':(ended-started)/1e9,'clock_owner':'local_controller','dispatch_start_utc':started_utc,
                    'receipt_version':version,'receipt_sha256':digest,'observed_target':snapshot}
                dump(self.d/'observation.json',result,True)
                return self.reconcile_postrun(result,expected,deadline)
            raise StageError('No matching independent terminal receipt before 900-second deadline',reason='timeout')
        except (OSError,ValueError,KeyError,StageError,subprocess.SubprocessError) as error:
            self.abort_and_reconcile(run_id,identifier,arm,error)
            raise
    def run(self,inputs,phase,ledger):
        if (self.d.parent/'reconciliation-required.json').exists():raise StageError('Prior remote attempt requires reconciliation before another dispatch')
        repo=self.c['study_repository']
        if repo!='holdmy-keyboard/lambda-release-controls-study':raise StageError('Unapproved dispatch repository')
        # Only a complete protected controller identity can select the frozen tag.
        identity=[row for row in self.c['identities'] if row['role']=='controller' and row['repository']==repo]
        if len(identity)!=1 or identity[0]['ref']!='refs/tags/lrcs-controller-v1':raise StageError('No unique frozen controller identity')
        expected_commit=identity[0]['commit']
        ref=self.gh_api(f'repos/{repo}/git/ref/tags/lrcs-controller-v1')
        if ref['object']['type']!='commit' or ref['object']['sha']!=expected_commit:raise StageError('Frozen controller tag moved or is not a direct commit ref')
        dump(self.d/'session-principals.json',self.validate_sessions(),True)
        arm=inputs['configuration'];identifier=inputs['attempt_id']
        if arm not in ('C0','C1','C2','C3') or inputs['workload'] not in ('functional','timing'):raise StageError('Unknown workload/treatment')
        if inputs['policy_id'] not in self.c['policies']:raise StageError('Unknown protected policy')
        if inputs['workload']=='functional' and inputs['fixture_key'] not in self.c['fixtures']:raise StageError('Unknown fixture')
        units=dict(PATH_RESERVATION);units[phase+'_paths']=1
        if inputs['workload']!='timing' or arm not in ('C2','C3'):units['signing_jobs']=0
        ledger.reserve(identifier,phase,units,'0.006')
        reset=self.reset(arm);dump(self.d/'reset.json',reset,True)
        # One exact ticket at a time. The S3 conditional claim prevents UUID reuse
        # by another workflow run, including a manual duplicate dispatch.
        config=dict(self.c);config['authorized_attempts']={identifier:{'phase':phase,'inputs':inputs,'run_id':None}}
        encoded=json.dumps(config,separators=(',',':'))
        if len(encoded.encode())>48000:raise StageError('Bound config exceeds safe repository variable size')
        self.gh_api(f'repos/{repo}/actions/variables/LRCS_BOUND_CONFIG','PATCH',{'name':'LRCS_BOUND_CONFIG','value':encoded})
        if self.gh_api(f'repos/{repo}/actions/variables/LRCS_BOUND_CONFIG')['value']!=encoded:raise StageError('Protected variable write not confirmed')
        started=time.monotonic_ns();started_utc=dt.datetime.now(dt.timezone.utc).isoformat();deadline=time.monotonic()+900
        dump(self.d/'dispatch-start.json',{'monotonic_ns':started,'utc':started_utc,'clock_owner':'local_controller'},True)
        self.deadline=deadline
        try:
            self.gh_api(f'repos/{repo}/actions/workflows/controller.yml/dispatches','POST',{'ref':'lrcs-controller-v1','inputs':inputs})
        except (OSError,ValueError,StageError,subprocess.SubprocessError) as error:
            # A dispatch transport failure may still have launched a run. Do not
            # cancel an uncorrelated run or silently allow another attempt.
            self.abort_and_reconcile(None,identifier,arm,error)
            raise
        return self.monitor(identifier,arm,expected_commit,reset,ledger,started,started_utc,deadline)



def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True);parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--phase',choices=['prototype','pilot'],required=True);parser.add_argument('--ledger',type=Path,required=True)
    parser.add_argument('--aws-profile',required=True,help='Read-only observer profile')
    parser.add_argument('--reset-aws-profile',required=True,help='Separate scoped reset/setup profile, used only before dispatch');parser.add_argument('--gh',type=Path,required=True);parser.add_argument('--github-token-file',type=Path,required=True)
    parser.add_argument('--evidence-root',type=Path,required=True)
    args=parser.parse_args(argv);ledger=None
    try:
        config=load_config(args.config);inputs=json.loads(args.request.read_text())
        identifier=inputs['attempt_id']
        if str(uuid.UUID(identifier))!=identifier:raise ValueError('Canonical attempt UUID required')
        args.evidence_root.mkdir(parents=True,mode=0o700,exist_ok=True)
        with (args.evidence_root/'controller.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            ledger=Ledger(args.ledger)
            controller=Controller(config,args.aws_profile,args.evidence_root/identifier,args.gh,args.github_token_file,args.reset_aws_profile)
            result=controller.run(inputs,args.phase,ledger);print(json.dumps(result))
            time.sleep(10)  # outside both clocks and while retaining serialization
        return 0 if result.get('validity')=='valid' or result.get('outcome')=='block' else 20
    except (OSError,ValueError,KeyError,StageError,subprocess.SubprocessError) as error:
        print(json.dumps({'outcome':'operational_error','detail':str(error),'reservation_refunded':False}))
        return 20
    finally:
        if ledger:ledger.close()

if __name__=='__main__':raise SystemExit(main())
