"""Install verified release tools into a disposable Linux x86_64 job directory.

Archives are fetched from official vendor release endpoints. AWS's detached
signature is checked with GnuPG and the fingerprint-pinned vendor public key;
no installer runs before checksum and signature checks have succeeded.
"""
import hashlib,json,os,platform,subprocess,tarfile,urllib.request,zipfile
from pathlib import Path

GH_SHA='9bca2d1c16825f109907a23307628a2f0698fbf99662b73a5cf0b020293072b8'
AWS_SHA='0c59444563f4df735eeb5481f6165f95dae546c33761760d8be9855d5cfe2d12'
KEY_SHA='279541b6dd1c831a260ee0f9fb71d63bbcc14ebc4bf62c605336e86c11d4eefb'
FINGERPRINT='FB5DB77FD5C118B80511ADA8A6310ACC4672475C'

def download(url,path,expected=None):
    h=hashlib.sha256();size=0
    with urllib.request.urlopen(url,timeout=30) as source,Path(path).open('xb') as dest:
        while block:=source.read(1024*1024):
            size+=len(block)
            if size>250*1024*1024:raise ValueError('Unexpected tool archive size')
            h.update(block);dest.write(block)
    if expected and h.hexdigest()!=expected:raise ValueError('Release archive checksum mismatch')
    return h.hexdigest()


def install(directory):
    if (platform.system(),platform.machine())!=('Linux','x86_64'):raise ValueError('Installer is only for the locked Ubuntu x86_64 runner')
    d=Path(directory);d.mkdir(mode=0o700,exist_ok=False);bin_dir=d/'bin';bin_dir.mkdir()
    gh=d/'gh.tar.gz';aws=d/'aws.zip';signature=d/'aws.zip.sig'
    download('https://github.com/cli/cli/releases/download/v2.101.0/gh_2.101.0_linux_amd64.tar.gz',gh,GH_SHA)
    download('https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.37.4.zip',aws,AWS_SHA)
    signature_sha=download('https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.37.4.zip.sig',signature)
    key=Path(__file__).resolve().parents[1]/'keys/aws-cli-pgp.asc'
    if hashlib.sha256(key.read_bytes()).hexdigest()!=KEY_SHA:raise ValueError('Vendor key changed')
    keyring=d/'gnupg';keyring.mkdir(mode=0o700)
    subprocess.run(['gpg','--homedir',str(keyring),'--batch','--import',str(key)],check=True,capture_output=True,timeout=20)
    verified=subprocess.run(['gpg','--homedir',str(keyring),'--batch','--status-fd','1','--verify',str(signature),str(aws)],capture_output=True,text=True,timeout=20)
    if verified.returncode or '[GNUPG:] VALIDSIG '+FINGERPRINT+' ' not in verified.stdout:raise ValueError('AWS release signature not verified by the pinned key')
    with tarfile.open(gh,'r:gz') as archive:
        source=archive.extractfile('gh_2.101.0_linux_amd64/bin/gh')
        if source is None:raise ValueError('Missing pinned gh binary')
        (bin_dir/'gh').write_bytes(source.read());(bin_dir/'gh').chmod(0o700)
    extract=d/'unpacked';extract.mkdir()
    with zipfile.ZipFile(aws) as archive:
        for info in archive.infolist():
            target=extract/info.filename
            if not target.resolve().is_relative_to(extract.resolve()) or ((info.external_attr>>16)&0o170000)==0o120000:
                raise ValueError('Unsafe archive member')
            archive.extract(info,extract)
            if not info.is_dir():target.chmod(0o700 if (info.external_attr>>16)&0o111 else 0o600)
    subprocess.run([str(extract/'aws/install'),'--install-dir',str(d/'aws-cli'),'--bin-dir',str(bin_dir)],check=True,capture_output=True,timeout=60)
    evidence={'gh_archive_sha256':GH_SHA,'aws_archive_sha256':AWS_SHA,'aws_signature_sha256':signature_sha,
              'aws_key_fingerprint':FINGERPRINT,'aws_signature_verified':True,'aws_gpg_status':verified.stdout}
    (d/'verification.json').write_text(json.dumps(evidence,indent=2)+'\n')
    with Path(os.environ['GITHUB_PATH']).open('a') as out:out.write(str(bin_dir)+'\n')
    os.environ['PATH']=str(bin_dir)+os.pathsep+os.environ['PATH']
    return evidence
