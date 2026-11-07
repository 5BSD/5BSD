# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the private fixture's declared firstboot transitions in the real guest."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shlex
import tarfile
import uuid

from qualification_artifacts import resolve, digest
from firstboot_accounts import validate

ACCOUNT_FILES = ('/etc/master.passwd', '/etc/group', '/etc/passwd', '/etc/pwd.db', '/etc/spwd.db')


def load(path, report, authenticated_accounts):
    path = Path(path).resolve(strict=True)
    policy_bytes = path.read_bytes()
    policy = json.loads(policy_bytes)
    required = {'format', 'baseline_master', 'baseline_group', 'producer', 'changes',
                'group_additions', 'consumed_files', 'zfs_archive_tracking', 'db_compare'}
    if set(policy) != required or type(policy['format']) is not int or policy['format'] != 1:
        raise ValueError('exact format-1 firstboot audit policy required')
    if type(policy['zfs_archive_tracking']) is not bool:
        raise ValueError('explicit ZFS archive tracking selection required')
    if set(policy['changes']) != set(authenticated_accounts):
        raise ValueError('provisioned accounts must match the exercised authentication accounts')
    bindings = {str(path): hashlib.sha256(policy_bytes).hexdigest()}
    sources = {}
    for key, destination in (('baseline_master', '/etc/master.passwd'),
                             ('baseline_group', '/etc/group'), ('producer', '/etc/rc.local')):
        source = Path(policy[key]).resolve(strict=True)
        data = source.read_bytes()
        value = hashlib.sha256(data).hexdigest()
        if value != report['payload_sha256'][destination]:
            raise ValueError('firstboot input does not match captured image: '+destination)
        bindings[str(source)] = value
        sources[key] = data.decode()
    consumed = policy['consumed_files']
    if not isinstance(consumed, list) or len(set(consumed)) != len(consumed):
        raise ValueError('distinct explicit consumed marker paths required')
    for name in consumed:
        if (not isinstance(name, str) or not name.startswith('/') or name.startswith('//') or
                str(PurePosixPath(name)) != name or '..' in PurePosixPath(name).parts or
                any(c.isspace() or ord(c)<32 or ord(c)==127 for c in name)):
            raise ValueError('canonical consumed marker path required')
        if report['payload_sha256'].get(name) != hashlib.sha256(b'').hexdigest():
            raise ValueError('consumed firstboot marker must be a declared empty file')
    tool = policy['db_compare']
    if set(tool) != {'qualification', 'target', 'output'}:
        raise ValueError('captured database comparator selection required')
    helper, binding = resolve(Path(tool['qualification']), tool['target'], tool['output'])
    bindings[str(helper)] = digest(helper)
    return dict(policy=policy, policy_bytes=policy_bytes, sources=sources, bindings=bindings,
                helper=helper, helper_binding=binding)


def exercise(loaded, invoke, output, authenticated_accounts):
    """invoke streams only to this disposable VM and bounds time/output externally."""
    policy = loaded['policy']
    command = '/usr/bin/tar -cf - -C / '+ ' '.join(shlex.quote(p[1:]) for p in ACCOUNT_FILES)
    snapshot = invoke('account-snapshot', command)
    observed = {}
    with tarfile.open(fileobj=io.BytesIO(snapshot), mode='r:') as archive:
        for entry in archive.getmembers():
            path = '/' + entry.name
            if path not in ACCOUNT_FILES or path in observed or not entry.isfile() or not 0<=entry.size<=16*1024**2:
                raise ValueError('unexpected account snapshot object')
            observed[path] = archive.extractfile(entry).read()
    if set(observed) != set(ACCOUNT_FILES):
        raise ValueError('incomplete actual account snapshot')
    result = validate(loaded['sources']['baseline_master'],loaded['sources']['baseline_group'],
        observed['/etc/master.passwd'].decode(),observed['/etc/group'].decode(),
        observed['/etc/passwd'].decode(),policy['changes'],policy['group_additions'],authenticated_accounts)
    # Regenerate into a new guest-private directory. Never overwrite live state.
    work = '/root/.account-audit-' + uuid.uuid4().hex
    q = shlex.quote
    invoke('account-work', '/bin/mkdir -m 700 '+q(work))
    invoke('account-comparator-upload', 'umask 077; /bin/cat > '+q(work+'/db_compare')+
        ' && /bin/chmod 500 '+q(work+'/db_compare'), loaded['helper'])
    regenerate = ' && '.join((
        '/bin/mkdir -m 700 '+q(work+'/rebuilt'),
        '/bin/cp /etc/master.passwd '+q(work+'/rebuilt/input'),
        '/usr/sbin/pwd_mkdb -p -S /etc/shells -d '+q(work+'/rebuilt')+' '+q(work+'/rebuilt/input'),
        q(work+'/db_compare')+' /etc/pwd.db '+q(work+'/rebuilt/pwd.db'),
        q(work+'/db_compare')+' /etc/spwd.db '+q(work+'/rebuilt/spwd.db'),
        '/usr/bin/cmp /etc/passwd '+q(work+'/rebuilt/passwd')))
    proof = invoke('account-database-regeneration',regenerate)
    lines = proof.decode().splitlines()
    if len(lines)!=2 or any(not line.startswith('DB_RECORDS_EQUAL ') or not line.split()[-1].isdigit() or int(line.split()[-1])<=0 for line in lines):
        raise ValueError('both actual database comparisons must report equal nonempty records')
    for index, name in enumerate(policy['consumed_files']):
        invoke('consumed-marker-'+str(index),'test ! -e '+q(name)+' && test ! -L '+q(name))
    invoke('account-work-cleanup','/bin/rm -rf -- '+q(work))
    result.update(status='passed',helper=loaded['helper_binding'],
        payload_sha256={path:hashlib.sha256(data).hexdigest() for path,data in observed.items()},
        consumed_files=policy['consumed_files'],zfs_archive_tracking=policy['zfs_archive_tracking'],
        database_proof_sha256=hashlib.sha256(proof).hexdigest(),
        snapshot_sha256=hashlib.sha256(snapshot).hexdigest(),
        scope='Exact declared local account/group transitions and public projection; live DB logical records equal actual private pwd_mkdb regeneration; positive/negative authentication prerequisite')
    (output/'firstboot-proof.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
