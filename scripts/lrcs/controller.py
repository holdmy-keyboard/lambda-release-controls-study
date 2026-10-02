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
    def __init__(self,config,profile,directory,gh,token_file):
        self.c=config;self.profile=profile;self.d=Path(directory);self.d.mkdir(mode=0o700,parents=True,exist_ok=False)
        self.gh=str(gh);self.token_file=Path(token_file);self.event=0
    def command(self,argv,env=None,timeout=30,stdin=None,allowed=(0,)):
        before=time.monotonic_ns()
        p=subprocess.run(argv,input=stdin,capture_output=True,text=True,env=env,timeout=timeout)
        record={'argv':argv,'started_monotonic_ns':before,'ended_monotonic_ns':time.monotonic_ns(),'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
        dump(self.d/f'command-{self.event:04d}.json',record,True);self.event+=1
        if p.returncode not in allowed:raise StageError('Controller subprocess failed; see private command evidence')
        return json.loads(p.stdout) if p.stdout.strip() else {}
    def gh_api(self,endpoint,method='GET',body=None):
        env=dict(os.environ);env.update(GH_TOKEN=self.token_file.read_text().strip(),GH_PROMPT_DISABLED='1',GH_HOST='github.com');env.pop('GH_DEBUG',None)
        argv=[self.gh,'api',endpoint,'--hostname','github.com','--method',method,'-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2022-11-28']
        if body is not None:argv+=['--input','-']
        return self.command(argv,env,stdin=json.dumps(body) if body is not None else None)
    def aws(self,service,operation,args,timeout=30):
        env=dict(os.environ);env.update(AWS_MAX_ATTEMPTS='1',AWS_RETRY_MODE='standard',AWS_PAGER='')
        return self.command(['aws',service,operation,*args,'--region','eu-central-1','--profile',self.profile,'--output','json','--no-cli-pager'],env,timeout)
    def reset(self,arm):
        name='lrcs-20260928-'+arm.lower()
        before=self.aws('lambda','get-function-configuration',['--function-name',name]);validate_target(before,self.c['account_id'],arm)
        sentinel=self.c['sentinel']
        accepted=self.aws('lambda','update-function-code',['--function-name',name,'--s3-bucket',sentinel['bucket'],'--s3-key',sentinel['key'],
            '--s3-object-version',sentinel['version'],'--revision-id',before['RevisionId'],'--no-publish'])
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            snapshot=self.aws('lambda','get-function-configuration',['--function-name',name],min(30,deadline-time.monotonic()))
            if ready(snapshot,accepted,before['RevisionId'],sentinel['sha256']):return snapshot
            time.sleep(2)
        raise StageError('Sentinel reset did not become ready',reason='timeout')
    def run(self,inputs,phase,ledger):
        repo=self.c['study_repository']
        if repo!='holdmy-keyboard/lambda-release-controls-study':raise StageError('Unapproved dispatch repository')
        # Only a complete protected controller identity can select the frozen tag.
        identity=[row for row in self.c['identities'] if row['role']=='controller' and row['repository']==repo]
        if len(identity)!=1 or identity[0]['ref']!='refs/tags/lrcs-controller-v1':raise StageError('No unique frozen controller identity')
        expected_commit=identity[0]['commit']
        ref=self.gh_api(f'repos/{repo}/git/ref/tags/lrcs-controller-v1')
        if ref['object']['type']!='commit' or ref['object']['sha']!=expected_commit:raise StageError('Frozen controller tag moved or is not a direct commit ref')
        if self.aws('sts','get-caller-identity',[])['Account']!=self.c['account_id']:raise StageError('Observer AWS account mismatch')
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
        self.gh_api(f'repos/{repo}/actions/workflows/controller.yml/dispatches','POST',{'ref':'lrcs-controller-v1','inputs':inputs})
        run_id=None
        while time.monotonic()<deadline:
            runs=self.gh_api(f'repos/{repo}/actions/workflows/controller.yml/runs?event=workflow_dispatch&per_page=100')['workflow_runs']
            matches=[r for r in runs if r.get('display_title')=='lrcs-'+identifier and r.get('head_sha')==expected_commit and r.get('run_attempt')==1]
            if len(matches)>1:raise StageError('Duplicate dispatches found; no measurement can be attributed')
            if matches:
                run_id=str(matches[0]['id']);ledger.bind_run(identifier,run_id);break
            time.sleep(2)
        if not run_id:raise StageError('Dispatch run not identified within deadline',reason='timeout')
        receipt_key=f'receipts/controller/{identifier}/receipt.json'
        # HEAD only in this polling loop. Missing-key 403 without ListBucket is
        # pending/unknown, never conclusive evidence absence or a security block.
        while time.monotonic()<deadline:
            try:
                head=self.aws('s3api','head-object',['--bucket',self.c['buckets']['artifacts'],'--key',receipt_key],min(15,deadline-time.monotonic()))
            except StageError:
                time.sleep(2);continue
            if not head.get('VersionId') or head.get('ContentLength',0)>1048576:raise StageError('Invalid receipt version/size')
            path=self.d/'receipt.json'
            metadata=self.aws('s3api','get-object',['--bucket',self.c['buckets']['artifacts'],'--key',receipt_key,'--version-id',head['VersionId'],str(path)])
            if metadata.get('VersionId')!=head['VersionId']:raise StageError('Receipt version changed')
            receipt=json.loads(path.read_text());snapshot={}
            if receipt.get('outcome') in ('allow','allow_with_warning'):
                snapshot=self.aws('lambda','get-function-configuration',['--function-name','lrcs-20260928-'+arm.lower()])
            expected={'attempt_id':identifier,'configuration':arm,'run_id':run_id}
            if not collect_ready(receipt,snapshot,expected):raise StageError('Terminal receipt not independently confirmed')
            ended=time.monotonic_ns()
            result={'attempt_id':identifier,'run_id':run_id,'outcome':receipt['outcome'],'validity':receipt.get('validity','unresolved'),
                'e2e_seconds':(ended-started)/1e9,'clock_owner':'local_controller','dispatch_start_utc':started_utc,
                'receipt_version':head['VersionId'],'receipt_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'observed_target':snapshot}
            dump(self.d/'observation.json',result,True);return result
        raise StageError('No matching independent terminal receipt before 900-second deadline',reason='timeout')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True);parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--phase',choices=['prototype','pilot'],required=True);parser.add_argument('--ledger',type=Path,required=True)
    parser.add_argument('--aws-profile',required=True);parser.add_argument('--gh',type=Path,required=True);parser.add_argument('--github-token-file',type=Path,required=True)
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
            controller=Controller(config,args.aws_profile,args.evidence_root/identifier,args.gh,args.github_token_file)
            result=controller.run(inputs,args.phase,ledger);print(json.dumps(result))
            time.sleep(10)  # outside both clocks and while retaining serialization
        return 0
    except (OSError,ValueError,KeyError,StageError,subprocess.SubprocessError) as error:
        print(json.dumps({'outcome':'operational_error','detail':str(error),'reservation_refunded':False}))
        return 20
    finally:
        if ledger:ledger.close()

if __name__=='__main__':raise SystemExit(main())
