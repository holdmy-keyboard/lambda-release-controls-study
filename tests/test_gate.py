"""Synthetic adapter tests only; no cloud/cryptographic experiment observations."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.lrcs.gate import verify_artifact, validate_policy

SHA = '0123456789abcdef0123456789abcdef01234567'

def policy():
    return {'schema_version':'1.0','policy_id':'unit_test_policy','github_cli_version':'2.101.0',
            'oidc_issuer':'https://token.actions.githubusercontent.com','deny_self_hosted_runners':True,
            'allowed_tuples':[{'source_repository':'unit-owner/unit-repo',
                'certificate_identity':'https://github.com/unit-owner/unit-repo/.github/workflows/release.yml@refs/heads/current',
                'signer_digest':SHA,'source_digest':SHA,'source_ref':'refs/heads/current',
                'predicate_type':'https://slsa.dev/provenance/v1'}]}

def verified(row, digest):
    return [{'attestation':{},'verificationResult':{'signature':{'certificate':{
        'sourceRepositoryURI':'https://github.com/'+row['source_repository'],
        'subjectAlternativeName':row['certificate_identity'],
        'buildSignerDigest':row['signer_digest'],'sourceRepositoryDigest':row['source_digest'],
        'sourceRepositoryRef':row['source_ref'],'issuer':'https://token.actions.githubusercontent.com',
        'runnerEnvironment':'github-hosted'}}, 'statement':{
            'predicateType':row['predicate_type'],'subject':[{'digest':{'sha256':digest}}]}}}]

class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.artifact = Path(self.tmp.name)/'unit.zip'; self.artifact.write_bytes(b'synthetic candidate')
        self.bundle = Path(self.tmp.name)/'unit.json'; self.bundle.write_text('{}')
        self.policy = policy(); self.calls=[]
        self.digest=hashlib.sha256(self.artifact.read_bytes()).hexdigest()
    def runner(self, args, **kwargs):
        self.calls.append(args)
        output='gh version 2.101.0 (unit test)' if args[1]=='--version' else json.dumps(verified(self.policy['allowed_tuples'][0],self.digest))
        return subprocess.CompletedProcess(args,0,output,'')
    def run_gate(self, **kw):
        return verify_artifact(self.artifact,self.bundle,self.policy,runner=kw.pop('runner',self.runner),**kw)
    def test_verified_complete_tuple_allows(self):
        self.assertEqual(self.run_gate()['outcome'],'allow')
        self.assertIn('--cert-identity',self.calls[-1]); self.assertNotIn('--signer-workflow',self.calls[-1])
    def test_exact_ref_postcheck_rejects_prefix_match(self):
        def run(args,**kw):
            out=self.runner(args,**kw)
            if args[1]!='--version':
                data=json.loads(out.stdout);data[0]['verificationResult']['signature']['certificate']['sourceRepositoryRef']+='-malicious';out.stdout=json.dumps(data)
            return out
        result=self.run_gate(runner=run)
        self.assertEqual((result['outcome'],result['reason']),('block','source_ref_not_allowed'))
    def test_missing_extension_never_allows(self):
        def run(args,**kw):
            out=self.runner(args,**kw)
            if args[1]!='--version':
                data=json.loads(out.stdout);del data[0]['verificationResult']['signature']['certificate']['issuer'];out.stdout=json.dumps(data)
            return out
        self.assertEqual(self.run_gate(runner=run)['outcome'],'operational_error')
    def test_explicit_absence_is_only_absence_block(self):
        self.assertEqual(verify_artifact(self.artifact,None,self.policy,acquisition_status='absent')['reason'],'evidence_absent')
        self.bundle.unlink();self.assertEqual(self.run_gate()['outcome'],'operational_error')
    def test_unavailable_is_not_a_detection(self):
        self.assertEqual(self.run_gate(acquisition_status='unavailable')['outcome'],'operational_error')
    def test_acquisition_timeout(self):
        self.assertEqual(self.run_gate(acquisition_elapsed_seconds=10.01)['reason'],'timeout')
    def test_opaque_sigstore_failure_is_not_a_detection(self):
        def run(args,**kw):
            return self.runner(args,**kw) if args[1]=='--version' else subprocess.CompletedProcess(args,1,'','Error: verifying with issuer "sigstore.dev"')
        self.assertEqual(self.run_gate(runner=run)['outcome'],'operational_error')
    def test_input_mutation_supersedes_allow(self):
        def run(args,**kw):
            out=self.runner(args,**kw)
            if args[1]!='--version':self.artifact.write_bytes(b'changed')
            return out
        self.assertEqual(self.run_gate(runner=run)['outcome'],'operational_error')
    def test_cross_product_cannot_allow(self):
        second=copy.deepcopy(self.policy['allowed_tuples'][0]); second['source_digest']='abcdef01' * 5;second['source_ref']='refs/tags/old';second['certificate_identity']=second['certificate_identity'].replace('refs/heads/current','refs/tags/old')
        self.policy['allowed_tuples'].append(second)
        def run(args,**kw):
            out=self.runner(args,**kw)
            if args[1]!='--version':
                data=json.loads(out.stdout);data[0]['verificationResult']['signature']['certificate']['sourceRepositoryDigest']=second['source_digest'];out.stdout=json.dumps(data)
            return out
        self.assertEqual(self.run_gate(runner=run)['outcome'],'block')
    def test_later_complete_tuple_can_allow(self):
        second=copy.deepcopy(self.policy['allowed_tuples'][0]); second['source_digest']='abcdef01' * 5;self.policy['allowed_tuples'].append(second)
        def run(args,**kw):
            if args[1]=='--version': return self.runner(args,**kw)
            self.calls.append(args)
            return subprocess.CompletedProcess(args,0,json.dumps(verified(second,self.digest)),'')
        result=self.run_gate(runner=run);self.assertEqual(result['outcome'],'allow');self.assertEqual(result['evidence']['matched_tuple_index'],1)
    def test_raw_subject_can_reject_never_accept(self):
        def bundle(digest):
            payload={'_type':'https://in-toto.io/Statement/v1','subject':[{'digest':{'sha256':digest}}]}
            return {'dsseEnvelope':{'payloadType':'application/vnd.in-toto+json','payload':base64.b64encode(json.dumps(payload).encode()).decode()}}
        self.bundle.write_text(json.dumps(bundle('a'*64))); result=self.run_gate();self.assertEqual(result['reason'],'artifact_digest_mismatch');self.assertFalse(result['evidence']['subject_precheck']['authenticated']);self.assertEqual(self.calls,[])
        self.bundle.write_text(json.dumps(bundle(self.digest)))
        def fail(args,**kw):return subprocess.CompletedProcess(args,1,'','')
        self.assertEqual(self.run_gate(runner=fail)['outcome'],'operational_error')
    def test_symbolic_policy_rejected(self):
        self.policy['allowed_tuples'][0]['source_digest']='__COMMIT__'
        with self.assertRaises(ValueError):validate_policy(self.policy)
    def test_unverified_predicate_identity_ignored(self):
        def run(args,**kw):
            out=self.runner(args,**kw)
            if args[1]!='--version':
                data=json.loads(out.stdout); data[0]['verificationResult']['signature']['certificate']['sourceRepositoryURI']='https://github.com/wrong/repo';data[0]['verificationResult']['statement']['predicate']={'source_repository':'unit-owner/unit-repo'};out.stdout=json.dumps(data)
            return out
        self.assertEqual(self.run_gate(runner=run)['reason'],'repository_not_allowed')

if __name__=='__main__':unittest.main()
