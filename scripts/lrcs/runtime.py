"""Bound runner stages for the Phase 5 prototype.

The committed config is disabled. A reviewed nonsecret LRCS_BOUND_CONFIG
repository variable supplies real immutable bindings after setup; it must never
be populated from workflow-dispatch input. No network call occurs in prepare.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid
import zipfile

from scripts.build_package import build_package
from scripts.lrcs.gate import verify_artifact, validate_policy, _hash_file
from scripts.lrcs.deployment import validate_target, validate_csc, ready, classify_update_error

MAX_BYTES=1048576

class StageError(RuntimeError):
    def __init__(self,message,*,outcome='operational_error',reason='unexpected_configuration'):
        super().__init__(message);self.outcome=outcome;self.reason=reason


def dump(path,value,exclusive=False):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if exclusive:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
    else:
        temporary=path.with_suffix('.tmp')
        with temporary.open('w') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
        temporary.chmod(0o600);temporary.replace(path)


def utc():return dt.datetime.now(dt.timezone.utc).isoformat()


def load_config(path):
    committed=json.loads(Path(path).read_text())
    raw=os.environ.get('LRCS_BOUND_CONFIG')
    config=json.loads(raw) if raw else committed
    if config.get('deployment_enabled') is not True:
        raise StageError('Cloud runtime disabled until genuine bindings and integration checks are recorded')
    if config.get('schema_version')!='1.0' or config.get('g4_approved') is not True:
        raise StageError('G4/schema binding missing')
    if config.get('region')!='eu-central-1' or config.get('project_prefix')!='lrcs-20260928':
        raise StageError('Unapproved region/project')
    account=config.get('account_id','')
    if not re.fullmatch('[0-9]{12}',account):raise StageError('Missing account binding')
    prefix='lrcs-20260928-'
    for kind in ('artifacts','signed'):
        if config['buckets'][kind]!=f'{prefix}{account}-eu-central-1-{kind}':raise StageError('Wrong bucket binding')
    for key,name in {'build':'build-sign','fixtures':'fixture-sign','deploy':'deploy'}.items():
        if config['roles'][key]!=f'arn:aws:iam::{account}:role:{prefix}{name}':raise StageError('Wrong role binding')
    for policy in config['policies'].values():validate_policy(policy)
    return config


def prepare(config,event,clock,env,head,producer=None):
    """Pure preflight, injectable context for unit testing."""
    if env.get('GITHUB_EVENT_NAME')!='workflow_dispatch' or env.get('GITHUB_RUN_ATTEMPT')!='1':
        raise StageError('Only first-attempt manual dispatches are authorized; retries need new IDs')
    if not re.fullmatch('[0-9a-f]{40}',head) or head!=env.get('GITHUB_SHA'):
        raise StageError('Checked-out commit differs from authenticated job commit')
    role=producer or 'controller'
    actual={'repository':env.get('GITHUB_REPOSITORY'),'ref':env.get('GITHUB_REF'),
            'workflow_ref':env.get('GITHUB_WORKFLOW_REF'),'commit':head,'role':role}
    identities=config.get('identities',[])
    if actual not in identities:raise StageError('Repository/workflow/ref/commit tuple is not frozen in protected config')
    inputs=dict(event.get('inputs',{}))
    identity_only=inputs.pop('identity_only','false')
    if identity_only not in ('false',False):raise StageError('Identity discovery cannot run cloud stages')
    identifier=inputs.get('attempt_id','')
    try:
        if str(uuid.UUID(identifier))!=identifier:raise ValueError
    except ValueError as error:raise StageError('Canonical attempt UUID required') from error
    reservation=config.get('authorized_attempts',{}).get(identifier)
    # External controller writes only reserved, complete input records. This is
    # a trusted-operator guard, not a substitute for a distributed spend cap.
    if not reservation or reservation.get('inputs')!=inputs or reservation.get('phase') not in ('prototype','pilot'):
        raise StageError('No exact G4 dispatch reservation')
    if reservation.get('run_id') not in (None,env.get('GITHUB_RUN_ID')):
        raise StageError('Reservation bound to another run ID')
    if inputs.get('policy_id') not in config['policies']:raise StageError('Unregistered policy')
    if producer:
        if inputs.get('fixture_mode') not in ('valid','unsigned','negative_profile','boundary'):raise StageError('Unknown fixture mode')
        workload='producer';arm=None
        signing=inputs['fixture_mode']!='unsigned';attesting=True
    else:
        workload=inputs.get('workload');arm=inputs.get('configuration')
        if workload not in ('timing','functional') or arm not in ('C0','C1','C2','C3'):raise StageError('Invalid treatment/workload')
        signing=workload=='timing' and arm in ('C2','C3');attesting=workload=='timing' and arm in ('C1','C3')
        if workload=='functional' and inputs.get('fixture_key') not in config.get('fixtures',{}):raise StageError('Unregistered fixture')
    if workload in ('producer','timing') and not re.fullmatch('[0-9a-f]{32}',inputs.get('marker','')):
        raise StageError('Marker must be 32 lowercase hex characters')
    now=time.monotonic_ns()
    if clock.get('clock_owner')!='github_job' or type(clock.get('monotonic_ns')) is not int or not 0<=now-clock['monotonic_ns']<600_000_000_000:
        raise StageError('Missing/invalid active clock')
    return {'schema_version':'1.0','attempt_id':identifier,'phase':reservation['phase'],
            'workload':workload,'configuration':arm,'inputs':inputs,'identity':actual,
            'run_id':env.get('GITHUB_RUN_ID'),'clock':clock,'created_utc':utc(),
            'needs_signing':signing,'needs_attestation':attesting,'stage_events':[],
            'outcome':None,'reason':None,'validity':'unresolved','deployment_attempted':False,
            'config_sha256':hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()}


class Runtime:
    def __init__(self,config,state_path):
        self.c=config;self.path=Path(state_path);self.s=json.loads(self.path.read_text());self.d=self.path.parent
        if self.s['config_sha256']!=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest():
            raise StageError('Protected config changed during the attempt')
        self.artifact=self.d/'final.zip'
    def save(self):dump(self.path,self.s)
    def start_stage(self,name):
        if any(event['name']==name and event.get('ended_monotonic_ns') is None for event in self.s.get('stage_envelopes',[])):
            raise StageError('Stage clock is already open: '+name)
        event={'name':name,'clock_owner':'github_job','started_monotonic_ns':time.monotonic_ns(),
               'started_utc':utc(),'ended_monotonic_ns':None,'duration_seconds':None,'status':'running'}
        self.s.setdefault('stage_envelopes',[]).append(event);self.save()
    def end_stage(self,name,status='success',ended=None):
        matches=[event for event in self.s.get('stage_envelopes',[]) if event['name']==name and event.get('ended_monotonic_ns') is None]
        if len(matches)!=1:raise StageError('No unique open stage clock: '+name)
        event=matches[0];ended=ended if ended is not None else time.monotonic_ns()
        if ended<event['started_monotonic_ns']:raise StageError('Stage clock moved backwards')
        event.update(ended_monotonic_ns=ended,ended_utc=utc(),duration_seconds=(ended-event['started_monotonic_ns'])/1e9,status=status)
        self.save()
    def remaining(self,limit):
        if self.s.get('active_end_monotonic_ns') is not None or self.s.get('finalization_started_monotonic_ns') is not None:
            anchor=self.s.get('active_end_monotonic_ns',self.s.get('finalization_started_monotonic_ns'))
            cleanup=(time.monotonic_ns()-anchor)/1e9
            if cleanup>=120:raise StageError('Post-attempt reconciliation deadline exceeded',reason='timeout')
            return min(limit,120-cleanup)
        active=(time.monotonic_ns()-self.s['clock']['monotonic_ns'])/1e9
        if active>=600:raise StageError('Active deadline exceeded',reason='timeout')
        return min(limit,600-active)
    def aws(self,service,operation,arguments,limit=30):
        argv=['aws',service,operation,*arguments,'--region',self.c['region'],'--output','json','--no-cli-pager']
        env=dict(os.environ);env.update(AWS_MAX_ATTEMPTS='1',AWS_RETRY_MODE='standard',AWS_PAGER='')
        started=time.monotonic_ns()
        try:p=subprocess.run(argv,capture_output=True,text=True,env=env,timeout=self.remaining(limit))
        except subprocess.TimeoutExpired as error:raise StageError('AWS call timed out',reason='timeout') from error
        record={'service':service,'operation':operation,'started_monotonic_ns':started,'ended_monotonic_ns':time.monotonic_ns(),
                'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'request_id':None,
                'request_id_missing_reason':'AWS CLI normal JSON output does not expose response metadata'}
        dump(self.d/f'aws-{len(self.s["stage_events"]):04d}.json',record,True)
        self.s['stage_events'].append({'operation':service+'.'+operation,'exit_code':p.returncode,'evidence':f'aws-{len(self.s["stage_events"]):04d}.json'})
        self.save()
        if p.returncode:
            match=re.search(r'An error occurred \(([^)]+)\)',p.stderr);code=match.group(1) if match else 'unknown'
            outcome,reason=classify_update_error(code) if (service,operation)==('lambda','update-function-code') else ('operational_error','service_or_transport_failure')
            raise StageError(code,outcome=outcome,reason=reason)
        return json.loads(p.stdout or '{}')
    def put(self,path,bucket,key):
        path=Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_BYTES:raise StageError('Invalid or oversized evidence object')
        digest=_hash_file(path)
        response=self.aws('s3api','put-object',['--bucket',bucket,'--key',key,'--body',str(path),'--if-none-match','*'])
        version=response.get('VersionId')
        if not version or version=='null':raise StageError('S3 versioning not effective')
        if _hash_file(path)!=digest:raise StageError('Local upload bytes changed')
        return {'bucket':bucket,'key':key,'version':version,'sha256':digest,'size_bytes':path.stat().st_size}
    def get(self,reference,path,limit=30):
        if reference.get('bucket') not in self.c['buckets'].values() or not reference.get('version') or reference['version']=='null':raise StageError('Unbound object version')
        response=self.aws('s3api','get-object',['--bucket',reference['bucket'],'--key',reference['key'],'--version-id',reference['version'],str(path)],limit)
        if response.get('VersionId')!=reference['version'] or Path(path).stat().st_size>MAX_BYTES:raise StageError('Fetched version/size mismatch')
        digest=_hash_file(Path(path))
        if reference.get('sha256') and reference['sha256']!=digest:raise StageError('Transport differs from immutable fixture manifest')
        return digest
    def tools(self):
        # No silent use of runner image versions. Installation is a distinct
        # verified setup step; an absent/mismatched executable fails closed.
        from scripts.lrcs.install_tools import install
        self.s['tool_installation']=install(self.d/'tools')
        versions={}
        for program,wanted in [('gh','2.101.0'),('aws','2.37.4')]:
            p=subprocess.run([program,'--version'],capture_output=True,text=True,timeout=self.remaining(20))
            raw=(p.stdout+p.stderr).strip();versions[program]=raw
            pattern=r'^gh version '+re.escape(wanted)+r'(?:\s|$)' if program=='gh' else r'^aws-cli/'+re.escape(wanted)+r'(?:\s|$)'
            if p.returncode or not re.search(pattern,raw):raise StageError('Required pinned tool unavailable: '+program)
        if sys.version_info[:3]!=(3,13,15):raise StageError('Pinned Python patch unavailable')
        self.s['tool_versions']=versions|{'python':sys.version,'runner_image':os.environ.get('ImageVersion'),'runner_os':os.environ.get('RUNNER_OS')}
    def claim(self):
        if self.s.get('claim_reference'):raise StageError('Run has already claimed its reservation')
        prefix='fixtures' if self.s['workload']=='producer' else 'controller'
        claim=self.d/'claim.json'
        dump(claim,{'attempt_id':self.s['attempt_id'],'run_id':self.s['run_id'],
                    'identity':self.s['identity'],'config_sha256':self.s['config_sha256']},True)
        # S3 conditional creation is the replay guard across distinct workflow
        # runs; unlike a local flag it survives runner destruction.
        self.s['claim_reference']=self.put(claim,self.c['buckets']['artifacts'],f'receipts/{prefix}/{self.s["attempt_id"]}/claim.json')
    def require_claim(self):
        if not self.s.get('claim_reference'):raise StageError('No successful immutable dispatch claim')
    def build(self):
        self.require_claim()
        if self.s['workload'] not in ('timing','producer'):raise StageError('Functional fixtures must not be rebuilt')
        self.s['build']=build_package(Path('app'),self.artifact,self.s['inputs']['marker'],boundary=self.s['inputs'].get('fixture_mode')=='boundary')
        self.s['final_sha256']=_hash_file(self.artifact)
    def sign(self):
        if not self.s['needs_signing'] or 'build' not in self.s:raise StageError('Signing not authorized for this path')
        started=time.monotonic();prefix='fixtures' if self.s['workload']=='producer' else 'timing'
        profile_key='negative' if self.s['inputs'].get('fixture_mode')=='negative_profile' else 'allowed'
        profile=self.c['profiles'][profile_key]
        current=self.aws('signer','get-signing-profile',['--profile-name',profile['name']])
        if current.get('profileVersion')!=profile['version'] or current.get('status')!='Active':raise StageError('Signing profile drift')
        source=self.put(self.artifact,self.c['buckets']['artifacts'],f'source/{prefix}/{self.s["attempt_id"]}/unsigned.zip')
        result=self.aws('signer','start-signing-job',['--source',json.dumps({'s3':{'bucketName':source['bucket'],'key':source['key'],'version':source['version']}}),
            '--destination',json.dumps({'s3':{'bucketName':self.c['buckets']['signed'],'prefix':f'signed/{prefix}/{self.s["attempt_id"]}/'}}),
            '--profile-name',profile['name'],'--client-request-token',self.s['attempt_id']])
        self.s['signing']={'job_id':result['jobId'],'source':source,'profile':profile};self.save()
        while time.monotonic()-started<180:
            job=self.aws('signer','describe-signing-job',['--job-id',result['jobId']],min(30,180-(time.monotonic()-started)))
            if job.get('status')=='Failed':raise StageError('Signing job failed',reason='service_or_transport_failure')
            if job.get('status')=='Succeeded':break
            time.sleep(2)
        else:raise StageError('Signing deadline exceeded',reason='timeout')
        if job.get('profileVersion')!=profile['version'] or job.get('profileName')!=profile['name'] or job.get('source',{}).get('s3')!={'bucketName':source['bucket'],'key':source['key'],'version':source['version']}:
            raise StageError('Signing lineage mismatch')
        obj=job['signedObject']['s3']
        if obj['bucketName']!=self.c['buckets']['signed'] or not obj['key'].startswith(f'signed/{prefix}/{self.s["attempt_id"]}/'):raise StageError('Unexpected signing output')
        head=self.aws('s3api','head-object',['--bucket',obj['bucketName'],'--key',obj['key']])
        reference={'bucket':obj['bucketName'],'key':obj['key'],'version':head.get('VersionId')}
        signed=self.d/'signed.zip';digest=self.get(reference,signed)
        signed.replace(self.artifact);reference['sha256']=digest
        self.s['final_sha256']=digest;self.s['signing'].update(output=reference,job=job,elapsed_seconds=time.monotonic()-started)
    def record_bundle(self,path):
        if not self.s['needs_attestation'] or _hash_file(self.artifact)!=self.s.get('final_sha256'):raise StageError('Attestation stage/bytes mismatch')
        path=Path(path)
        if path.is_symlink() or path.stat().st_size>MAX_BYTES:raise StageError('Invalid bundle')
        target=self.d/'bundle.json';shutil.copyfile(path,target);target.chmod(0o600)
        self.s.update(bundle_sha256=_hash_file(target),acquisition_status='available',acquisition_elapsed_seconds=0.0)
    def acquire(self):
        self.require_claim()
        if self.s['workload']!='functional':raise StageError('Not a functional path')
        fixture=self.c['fixtures'][self.s['inputs']['fixture_key']]
        self.s['final_sha256']=self.get(fixture['artifact'],self.artifact)
        # The no-provenance arms consume the same candidate bytes but never
        # invoke the evidence resolver, including its S13 injected outage.
        if self.s['configuration'] in ('C0','C2'):
            self.s.update(acquisition_status='not_applicable',acquisition_elapsed_seconds=None,
                          fixture_key=self.s['inputs']['fixture_key'])
            return
        started=time.monotonic();status=fixture['evidence_status']
        if status=='absent':
            if fixture.get('bundle') is not None:raise StageError('Contradictory absence fixture')
        elif status=='timeout':
            # Fixed, documented resolver fault; the original bundle remains
            # intact and is checked during restoration outside measurement.
            time.sleep(10);status='unavailable'
        elif status=='available':
            try:self.get(fixture['bundle'],self.d/'bundle.json',limit=10)
            except StageError:status='unavailable'
        else:raise StageError('Unknown evidence resolver status')
        self.s.update(acquisition_status=status,acquisition_elapsed_seconds=time.monotonic()-started,fixture_key=self.s['inputs']['fixture_key'])
    def gate(self):
        if _hash_file(self.artifact)!=self.s.get('final_sha256'):raise StageError('Candidate transport/build mismatch')
        if self.s['configuration'] not in ('C1','C3'):
            self.s['gate']={'outcome':'not_applicable','reason':'treatment_has_no_provenance_gate'};return
        bundle=self.d/'bundle.json';status=self.s.get('acquisition_status','unavailable')
        result=verify_artifact(self.artifact,bundle if bundle.exists() else None,self.c['policies'][self.s['inputs']['policy_id']],
            acquisition_status=status,acquisition_elapsed_seconds=self.s.get('acquisition_elapsed_seconds',0.0))
        self.s['gate']=result;dump(self.d/'gate.json',result,True)
        if result['outcome']!='allow':raise StageError('Provenance gate did not allow',outcome=result['outcome'],reason=result['reason'])
    def deploy(self):
        self.require_claim()
        arm=self.s['configuration']
        if arm not in ('C0','C1','C2','C3') or 'gate' not in self.s:raise StageError('No controller gate stage')
        if arm in ('C1','C3') and self.s['gate']['outcome']!='allow':raise StageError('Deployment after blocked gate forbidden')
        if self.s['outcome'] is not None:raise StageError('Attempt already terminal')
        digest=_hash_file(self.artifact)
        if digest!=self.s['final_sha256']:raise StageError('Candidate changed after gate')
        name='lrcs-20260928-'+arm.lower()
        before=self.aws('lambda','get-function-configuration',['--function-name',name]);validate_target(before,self.c['account_id'],arm)
        if before['CodeSha256']!=self.c['sentinel']['sha256_base64']:raise StageError('Sentinel reset is not in effect')
        attached=self.aws('lambda','get-function-code-signing-config',['--function-name',name])
        definition=self.aws('lambda','get-code-signing-config',['--code-signing-config-arn',self.c['csc_arn']]) if arm in ('C2','C3') else {}
        validate_csc(arm,attached,definition,self.c['csc_arn'],self.c['profiles']['allowed']['version_arn'])
        reference=self.put(self.artifact,self.c['buckets']['artifacts'],f'deploy/{self.s["attempt_id"]}/final.zip')
        self.s.update(pre_target=before,deployment_object=reference,deployment_attempted=True);self.save()
        start=time.monotonic()
        accepted=self.aws('lambda','update-function-code',['--function-name',name,'--s3-bucket',reference['bucket'],'--s3-key',reference['key'],
            '--s3-object-version',reference['version'],'--revision-id',before['RevisionId'],'--no-publish'])
        self.s['accepted_update']=accepted;self.save()
        while time.monotonic()-start<180:
            snapshot=self.aws('lambda','get-function-configuration',['--function-name',name],min(30,180-(time.monotonic()-start)))
            if ready(snapshot,accepted,before['RevisionId'],digest):
                self.s.update(outcome='allow',reason='fresh_revision_ready_with_exact_hash',validity='valid',post_target=snapshot,
                    active_end_monotonic_ns=time.monotonic_ns(),active_end_utc=utc())
                self.s['active_seconds']=(self.s['active_end_monotonic_ns']-self.s['clock']['monotonic_ns'])/1e9
                self.save();self.publish_receipt();return
            time.sleep(2)
        raise StageError('Readiness deadline exceeded',reason='timeout')
    def publish_receipt(self):
        if self.s.get('receipt_reference'):return
        # Publish the compact readiness/decision receipt first. Diagnostics and
        # smoke checks occur after the active endpoint and receipt publication;
        # their treatment-dependent sizes must not enter the observed endpoint.
        prefix='fixtures' if self.s['workload']=='producer' else 'controller'
        receipt=self.d/'receipt.json'
        fields=('schema_version','attempt_id','phase','workload','configuration','run_id','identity',
                'config_sha256','outcome','reason','validity','deployment_attempted','final_sha256',
                'pre_target','accepted_update','post_target','active_end_monotonic_ns','active_end_utc',
                'active_seconds','inputs','artifact_reference','bundle_reference')
        compact={key:self.s[key] for key in fields if key in self.s}
        compact['postrun_key']=f'receipts/{prefix}/{self.s["attempt_id"]}/postrun.json'
        dump(receipt,compact,True)
        self.s['receipt_reference']=self.put(receipt,self.c['buckets']['artifacts'],f'receipts/{prefix}/{self.s["attempt_id"]}/receipt.json')
        self.save()
    def publish_diagnostics(self):
        if self.s.get('diagnostics_reference'):return
        prefix='fixtures' if self.s['workload']=='producer' else 'controller'
        archive=self.d/'diagnostics.zip'
        with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED) as z:
            for path in sorted(self.d.glob('*.json')):
                if path.name not in ('postrun.json',) and not path.is_symlink():
                    z.write(path,path.name)
        self.s['diagnostics_reference']=self.put(archive,self.c['buckets']['artifacts'],f'receipts/{prefix}/{self.s["attempt_id"]}/diagnostics.zip')
    def smoke(self):
        """Synchronous, bounded correctness check strictly after the receipt."""
        if self.s.get('outcome') not in ('allow','allow_with_warning'):return
        if not self.s.get('receipt_reference'):raise StageError('Smoke cannot precede readiness receipt')
        arm=self.s['configuration'];output=self.d/'smoke-response.json'
        marker=self.s['inputs'].get('marker')
        if self.s['workload']=='functional':
            marker=self.c['fixtures'][self.s['inputs']['fixture_key']].get('marker')
        if not re.fullmatch('[0-9a-f]{32}',marker or ''):raise StageError('Missing independently bound smoke marker')
        response=self.aws('lambda','invoke',['--function-name','lrcs-20260928-'+arm.lower(),
            '--invocation-type','RequestResponse','--cli-binary-format','raw-in-base64-out','--payload','{}',str(output)],limit=15)
        payload=json.loads(output.read_text())
        if response.get('FunctionError') or response.get('StatusCode')!=200 or payload!={'release_marker':marker}:
            self.s['smoke']={'status':'mismatch','reason':'handler_response_mismatch','response':response,'payload':payload}
            self.s['validity']='measurement_invalid';self.save()
            return
        self.s['smoke']={'status':'match','response':response,'release_marker':marker}
    def finalize(self):
        self.s.setdefault('finalization_started_monotonic_ns',time.monotonic_ns())
        # An interrupted action may not reach its explicit end step. Retain an
        # incomplete stage, never invent a measured end or a zero duration.
        for event in self.s.get('stage_envelopes',[]):
            if event.get('ended_monotonic_ns') is None:event['status']='interrupted_end_not_observed'
        if self.s['workload']=='producer' and self.s.get('bundle_sha256') and os.environ.get('LRCS_JOB_STATUS')=='success':
            if _hash_file(self.artifact)!=self.s['final_sha256']:raise StageError('Producer bytes changed')
            self.s['artifact_reference']=self.put(self.artifact,self.c['buckets']['artifacts'],f'source/fixtures/{self.s["attempt_id"]}/final.zip')
            self.s['bundle_reference']=self.put(self.d/'bundle.json',self.c['buckets']['artifacts'],f'source/fixtures/{self.s["attempt_id"]}/bundle.json')
            self.s.update(outcome='constructed',reason='fixture_not_yet_independently_validated',validity='unresolved')
        if self.s['outcome'] is None:self.s.update(outcome='operational_error',reason='upstream_job_failed_or_incomplete')
        self.publish_receipt()
        if self.s['workload']!='producer':
            try:self.smoke()
            except (StageError,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
                self.s.update(smoke={'status':'error','reason':str(error)},validity='unresolved')
        self.save();self.publish_diagnostics()
        prefix='fixtures' if self.s['workload']=='producer' else 'controller'
        postrun={'attempt_id':self.s['attempt_id'],'run_id':self.s['run_id'],'configuration':self.s['configuration'],
                 'readiness_receipt_reference':self.s.get('receipt_reference'),'diagnostics_reference':self.s.get('diagnostics_reference'),
                 'outcome':self.s['outcome'],'validity':self.s['validity'],'smoke_result':self.s.get('smoke'),
                 'job_status_at_finalize':os.environ.get('LRCS_JOB_STATUS'),'stage_envelopes':self.s.get('stage_envelopes',[])}
        path=self.d/'postrun.json';dump(path,postrun,True)
        self.s['postrun_reference']=self.put(path,self.c['buckets']['artifacts'],f'receipts/{prefix}/{self.s["attempt_id"]}/postrun.json')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['prepare','tools','claim','build','sign','record-bundle','acquire','gate','deploy','finalize','stage-start','stage-end'])
    parser.add_argument('--config',type=Path,required=True);parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--event',type=Path);parser.add_argument('--clock-start',type=Path);parser.add_argument('--output',type=Path)
    parser.add_argument('--producer',choices=['release','alternate']);parser.add_argument('--bundle',type=Path)
    parser.add_argument('--stage',choices=['attestation']);parser.add_argument('--status',choices=['success','failure','cancelled','skipped'],default='success')
    args=parser.parse_args(argv);runtime=None;instrumented=False
    try:
        config=load_config(args.config)
        if args.command=='prepare':
            head=subprocess.run(['git','rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
            state=prepare(config,json.loads(args.event.read_text()),json.loads(args.clock_start.read_text()),os.environ,head,args.producer)
            dump(args.state,state,True)
            outputs={'workload':state['workload'],'configuration':state['configuration'] or '',
                'needs_signing':str(state['needs_signing']).lower(),'needs_attestation':str(state['needs_attestation']).lower(),
                'build_role_arn':config['roles']['fixtures' if args.producer else 'build'],'deploy_role_arn':config['roles']['deploy'],
                'account_id':config['account_id'],'region':config['region'],'artifact_path':str(args.state.parent/'final.zip')}
            with args.output.open('a') as output:
                for k,v in outputs.items():
                    if '\n' in v or '\r' in v:raise StageError('Unsafe workflow output')
                    output.write(k+'='+v+'\n')
            return 0
        runtime=Runtime(config,args.state)
        if args.command in ('stage-start','stage-end'):
            if args.stage is None:raise StageError('An explicit external stage is required')
            if args.command=='stage-start':runtime.start_stage(args.stage)
            else:runtime.end_stage(args.stage,args.status)
        else:
            # Finalize lies outside both measured intervals and may contain
            # diagnostics publication; it is not an active release stage.
            instrumented=args.command!='finalize'
            if instrumented:runtime.start_stage(args.command)
            if args.command=='record-bundle':runtime.record_bundle(args.bundle)
            else:getattr(runtime,args.command)()
            if instrumented:
                end=runtime.s.get('active_end_monotonic_ns') if args.command=='deploy' else None
                runtime.end_stage(args.command,ended=end);instrumented=False
        runtime.save();return 0
    except (StageError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        outcome=getattr(error,'outcome','operational_error');reason=getattr(error,'reason','unexpected_configuration')
        if runtime:
            if instrumented:
                runtime.end_stage(args.command,'failure');instrumented=False
            if runtime.s['outcome'] in (None,'constructed'):
                runtime.s.update(outcome=outcome,reason=reason,validity='unresolved')
            runtime.s.setdefault('stage_failures',[]).append({'stage':args.command,'detail':str(error),'utc':utc()})
            runtime.save()
        print(json.dumps({'stage':args.command,'outcome':outcome,'reason':reason,'detail':str(error)}))
        return 10 if outcome=='block' else 20

if __name__=='__main__':raise SystemExit(main())
