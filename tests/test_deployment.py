"""Synthetic readiness/error adapter cases, not measured Lambda outcomes."""
import unittest
from scripts.lrcs.deployment import ready,hash_base64,classify_update_error,validate_csc

class DeploymentTests(unittest.TestCase):
    def test_old_matching_hash_does_not_count(self):
        sha='ab'*32;s={'RevisionId':'before','State':'Active','LastUpdateStatus':'Successful','CodeSha256':hash_base64(sha)}
        self.assertFalse(ready(s,{'RevisionId':'after'},'before',sha))
    def test_fresh_exact_ready(self):
        sha='ab'*32;s={'RevisionId':'after','State':'Active','LastUpdateStatus':'Successful','CodeSha256':hash_base64(sha)}
        self.assertTrue(ready(s,{'RevisionId':'after'},'before',sha))
    def test_wrong_hash_and_interference_stop(self):
        for revision,sha in [('after','cd'*32),('unexpected','ab'*32)]:
            with self.assertRaises(ValueError):ready({'RevisionId':revision,'State':'Active','LastUpdateStatus':'Successful','CodeSha256':hash_base64(sha)},{'RevisionId':'after'},'before','ab'*32)
    def transition(self):
        accepted={'RevisionId':'pending','LastUpdateStatus':'InProgress','FunctionArn':'unit-target',
                  'LastModified':'2026-10-12T17:17:06.000+0000','CodeSha256':hash_base64('ab'*32)}
        settled=dict(accepted,RevisionId='settled',State='Active',LastUpdateStatus='Successful')
        return accepted,settled
    def test_service_completion_changes_revision(self):
        accepted,settled=self.transition()
        self.assertTrue(ready(settled,accepted,'before','ab'*32))
    def test_revision_transition_requires_operation_correlation(self):
        for field,value in [('LastModified','different'),('FunctionArn','other-target'),('CodeSha256',hash_base64('cd'*32)),('RevisionId',None)]:
            accepted,settled=self.transition();settled[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):ready(settled,accepted,'before','ab'*32)
    def test_completion_cannot_reuse_prior_revision(self):
        accepted,settled=self.transition();settled['RevisionId']='before'
        self.assertFalse(ready(settled,accepted,'before','ab'*32))
    def test_unsettled_transition_is_not_ready(self):
        accepted,settled=self.transition();settled['LastUpdateStatus']='InProgress'
        self.assertFalse(ready(settled,accepted,'before','ab'*32))
    def test_warn_not_enforce(self):
        c={'CodeSigningConfig':{'CodeSigningConfigArn':'unit-csc','CodeSigningPolicies':{'UntrustedArtifactOnDeployment':'Warn'},'AllowedPublishers':{'SigningProfileVersionArns':['unit-profile']}}}
        with self.assertRaises(ValueError):validate_csc('C2',{'CodeSigningConfigArn':'unit-csc'},c,'unit-csc','unit-profile')
    def test_access_denied_not_security_detection(self):
        self.assertEqual(classify_update_error('AccessDeniedException')[0],'operational_error')
        self.assertEqual(classify_update_error('CodeVerificationFailedException')[0],'block')
    def test_no_specific_profile_claim_from_generic_error(self):
        self.assertEqual(classify_update_error('CodeVerificationFailedException')[1],'cryptographic_verification_failed')

if __name__=='__main__':unittest.main()
