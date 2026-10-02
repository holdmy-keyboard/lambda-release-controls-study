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
    def test_warn_not_enforce(self):
        c={'CodeSigningConfig':{'CodeSigningConfigArn':'unit-csc','CodeSigningPolicies':{'UntrustedArtifactOnDeployment':'Warn'},'AllowedPublishers':{'SigningProfileVersionArns':['unit-profile']}}}
        with self.assertRaises(ValueError):validate_csc('C2',{'CodeSigningConfigArn':'unit-csc'},c,'unit-csc','unit-profile')
    def test_access_denied_not_security_detection(self):
        self.assertEqual(classify_update_error('AccessDeniedException')[0],'operational_error')
        self.assertEqual(classify_update_error('CodeVerificationFailedException')[0],'block')
    def test_no_specific_profile_claim_from_generic_error(self):
        self.assertEqual(classify_update_error('CodeVerificationFailedException')[1],'cryptographic_verification_failed')

if __name__=='__main__':unittest.main()
