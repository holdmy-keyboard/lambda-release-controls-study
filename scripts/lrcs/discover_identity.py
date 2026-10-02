"""Credential-free AWS setup discovery: emit only required nonsecret OIDC claims.

The short-lived JWT exists only in memory. It is not printed, written to disk or
sent to AWS. These observed claims inform trust-policy binding; later successful
STS assumption supplies the live AWS validation. This script is not a verifier.
"""
import base64,json,os,urllib.parse,urllib.request

FIELDS=('sub','iss','aud','repository','repository_id','repository_owner','repository_owner_id',
        'ref','sha','workflow_ref','workflow_sha','runner_environment')

def main():
    if os.environ.get('GITHUB_EVENT_NAME')!='workflow_dispatch':raise SystemExit('Discovery requires manual dispatch')
    url=os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'];parsed=urllib.parse.urlparse(url)
    if parsed.scheme!='https' or not (parsed.hostname or '').endswith('.actions.githubusercontent.com'):
        raise SystemExit('Unexpected Actions token endpoint')
    query=urllib.parse.parse_qsl(parsed.query);query.append(('audience','sts.amazonaws.com'))
    url=urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    with urllib.request.urlopen(request,timeout=15) as response:token=json.load(response)['value']
    payload=token.split('.')[1];claims=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))
    if claims['iss']!='https://token.actions.githubusercontent.com' or claims['aud']!='sts.amazonaws.com':raise SystemExit('Unexpected issuer/audience')
    for claim,env in [('repository','GITHUB_REPOSITORY'),('repository_id','GITHUB_REPOSITORY_ID'),('repository_owner_id','GITHUB_REPOSITORY_OWNER_ID'),('ref','GITHUB_REF'),('sha','GITHUB_SHA'),('workflow_ref','GITHUB_WORKFLOW_REF')]:
        if str(claims.get(claim))!=os.environ[env]:raise SystemExit('Claim differs from authenticated job context: '+claim)
    print('LRCS_OIDC_CLAIMS='+json.dumps({field:claims[field] for field in FIELDS},sort_keys=True))

if __name__=='__main__':main()
