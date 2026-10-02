"""Auditable Lambda readiness assertions; this module makes no network calls."""
import base64
import re


def hash_base64(hex_digest):
    if not re.fullmatch(r'[0-9a-f]{64}',hex_digest):raise ValueError('Invalid SHA-256')
    return base64.b64encode(bytes.fromhex(hex_digest)).decode('ascii')


def validate_target(snapshot, account, arm):
    name='lrcs-20260928-'+arm.lower()
    expected={'FunctionName':name,'FunctionArn':f'arn:aws:lambda:eu-central-1:{account}:function:{name}',
              'Runtime':'python3.13','Handler':'lambda_function.handler','MemorySize':128,'Timeout':3,
              'Architectures':['x86_64'],'PackageType':'Zip'}
    if arm not in ('C0','C1','C2','C3') or any(snapshot.get(k)!=v for k,v in expected.items()):
        raise ValueError('Target identity/runtime differs from the bound inventory')
    if snapshot.get('EphemeralStorage',{}).get('Size')!=512 or snapshot.get('VpcConfig',{}).get('VpcId') or snapshot.get('Layers'):
        raise ValueError('Unexpected storage, VPC or layers')
    if snapshot.get('Environment',{}).get('Variables'):
        raise ValueError('Unexpected application environment')
    if snapshot.get('State')!='Active' or snapshot.get('LastUpdateStatus')!='Successful':
        raise ValueError('Target is not ready before candidate update')
    if not snapshot.get('RevisionId'):raise ValueError('Missing pre-update revision')


def validate_csc(arm,attached,definition,expected_arn,allowed_profile_version):
    actual=attached.get('CodeSigningConfigArn')
    if arm in ('C0','C1'):
        if actual:raise ValueError('Unexpected CSC on non-signing treatment')
    elif arm in ('C2','C3'):
        c=definition.get('CodeSigningConfig',{})
        if actual!=expected_arn or c.get('CodeSigningConfigArn')!=expected_arn:
            raise ValueError('Wrong CSC binding')
        if c.get('CodeSigningPolicies',{}).get('UntrustedArtifactOnDeployment')!='Enforce':
            raise ValueError('CSC does not enforce')
        if c.get('AllowedPublishers',{}).get('SigningProfileVersionArns')!=[allowed_profile_version]:
            raise ValueError('CSC publisher version mismatch')
    else:raise ValueError('Unknown treatment')


def ready(snapshot,accepted,previous_revision,expected_digest):
    """Require the accepted candidate's fresh revision and exact copied bytes."""
    revision=accepted.get('RevisionId')
    if not revision or revision==previous_revision:
        raise ValueError('Accepted response has no fresh revision')
    if snapshot.get('LastUpdateStatus')=='Failed':raise ValueError('Update failed asynchronously')
    if snapshot.get('RevisionId')!=revision:
        if snapshot.get('RevisionId')!=previous_revision:raise ValueError('Concurrent target revision change')
        return False
    if snapshot.get('State')!='Active' or snapshot.get('LastUpdateStatus')!='Successful':return False
    if snapshot.get('CodeSha256')!=hash_base64(expected_digest):raise ValueError('Deployment hash mismatch')
    return True


def classify_update_error(code):
    # Specific AWS API error types only. The service message is retained as raw
    # evidence; this deliberately does not infer the violated profile predicate.
    if code=='CodeVerificationFailedException':return ('block','cryptographic_verification_failed')
    if code=='InvalidCodeSignatureException':return ('block','signature_integrity')
    if code in ('AccessDeniedException','UnrecognizedClientException','InvalidClientTokenId','ExpiredTokenException'):
        return ('operational_error','authentication_or_permission_failure')
    if code in ('TooManyRequestsException','ServiceException','ResourceConflictException'):
        return ('operational_error','service_or_transport_failure')
    return ('operational_error','unknown')
