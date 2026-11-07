# SPDX-License-Identifier: BSD-2-Clause
"""Real signed pkg upgrade, BE boot/rollback/removal in the owned disposable VM."""
import functools
import http.server
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import threading
import time
import uuid

from qualification_artifacts import digest


def absolute(value):
    if (not isinstance(value,str) or not value.startswith('/') or value.startswith('//') or
            str(PurePosixPath(value))!=value or '..' in PurePosixPath(value).parts or
            any(c.isspace() or ord(c)<32 or ord(c)==127 for c in value)):
        raise ValueError('canonical whitespace-free absolute guest path required')
    return value


def package_rows(data,names,version):
    rows=[line.split() for line in data.decode().splitlines()]
    if any(len(row)!=2 for row in rows) or len(rows)!=len(names) or {(row[0],row[1]) for row in rows}!={(name,version) for name in names}:
        raise ValueError('complete installed package names/versions differ')
    return len(rows)


def load(path,build_report):
    path=Path(path).resolve(strict=True);data=path.read_bytes();policy=json.loads(data)
    required={'format','repository','baseline_version','baseline_kernel_revision','kernel_revision',
              'kernel_sha256','candidate','guest_host_address','pkg_path','persistent_dataset','persistent_path','deadline_seconds','reclaim_deadline_seconds'}
    if set(policy)!=required or type(policy['format']) is not int or policy['format']!=1:
        raise ValueError('exact format-1 upgrade policy required')
    for field in ('baseline_version','baseline_kernel_revision','kernel_revision','candidate'):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',policy[field]):raise ValueError('invalid explicit upgrade identity')
    if not re.fullmatch(r'[a-f0-9]{64}',policy['kernel_sha256']):raise ValueError('explicit kernel digest required')
    for field in ('deadline_seconds','reclaim_deadline_seconds'):
        if type(policy[field]) is not int or policy[field]<=0:raise ValueError('positive upgrade/reclaim deadline required')
    policy['guest_host_address']=str(ipaddress.IPv4Address(policy['guest_host_address']))
    absolute(policy['pkg_path'])
    if policy['pkg_path'] not in build_report['payload_sha256']:raise ValueError('pkg tool must be a declared image payload')
    if policy['reclaim_deadline_seconds']>policy['deadline_seconds']:raise ValueError('reclaim deadline exceeds upgrade budget')
    old=build_report['bootfs'];parent,baseline_name=old.rsplit('/',1)
    if policy['candidate']==baseline_name:raise ValueError('candidate must differ from active baseline')
    mountpoints={d['name']:d['properties'].get('mountpoint') for d in build_report['datasets']}
    shared=policy['persistent_dataset'];mountpoint=mountpoints.get(shared)
    if shared.startswith(parent+'/') or not mountpoint or not mountpoint.startswith('/') or mountpoint=='/':
        raise ValueError('explicit shared dataset outside BE roots required')
    persistent=absolute(policy['persistent_path'])
    if not persistent.startswith(mountpoint.rstrip('/')+'/'):raise ValueError('persistent test object must reside in the shared dataset')
    repository=Path(policy['repository']).resolve(strict=True)
    receipt_path=repository/'receipt.json';receipt=json.loads(receipt_path.read_text())
    if receipt['status']!='passed' or not receipt.get('wrong_key_rejection') or receipt['version']==policy['baseline_version']:
        raise ValueError('passed signed next-version repository qualification required')
    bindings={str(path):digest(path),str(receipt_path):digest(receipt_path)}
    for name,sha in receipt['repository_files'].items():
        if PurePosixPath(name).name!=name or name in ('.','..'):raise ValueError('flat repository filenames required')
        file=repository/'repository'/name
        if file.is_symlink() or not file.is_file() or digest(file)!=sha:raise ValueError('repository bytes changed')
        bindings[str(file)]=sha
    actual={p.name for p in (repository/'repository').iterdir()}
    if actual!=set(receipt['repository_files']):raise ValueError('unexplained repository objects')
    for name,key in (('repository.pub','public_key_sha256'),('wrong.pub','wrong_public_key_sha256')):
        file=repository/'control'/name
        if digest(file)!=receipt[key]:raise ValueError('repository trust input changed')
        bindings[str(file)]=receipt[key]
    suffix='-'+receipt['version']+'.pkg'
    names=[]
    for binding in receipt['package_inputs']:
        name=PurePosixPath(binding['output_name']).name
        if not name.endswith(suffix):raise ValueError('package identity/version differs')
        names.append(name[:-len(suffix)])
    if len(names)!=receipt['packages'] or len(names)!=len(set(names)):raise ValueError('distinct complete package set required')
    return dict(policy=policy,policy_bytes=data,receipt=receipt,repository=repository,bindings=bindings,
                names=set(names),baseline=old,parent=parent,baseline_name=baseline_name,mountpoint=mountpoint)


def exercise(loaded,invoke,console,check,ssh,plan,build_report,output):
    p=loaded['policy'];r=loaded['receipt'];q=shlex.quote
    old=loaded['baseline'];new=loaded['parent']+'/'+p['candidate'];names=loaded['names']
    nonce=uuid.uuid4().hex;prefix='/root/.upgrade-'+nonce
    persistent=p['persistent_path'];shared=p['persistent_dataset'];be='/sbin/bectl -r '+q(loaded['parent'])
    pkg=q(p['pkg_path'])+' -C /dev/null -o PKG_ENABLE_PLUGINS=no -o SYSLOG=no'
    def command(label,text):return invoke('upgrade-'+label,text)
    def text(label,body):return command(label,body).decode().strip()
    def sha(label,path):return text(label,'/sbin/sha256 -q '+q(path))
    def guid(label,dataset):
        value=text(label,'/sbin/zfs get -Hp -o value guid '+q(dataset))
        if not value.isdecimal():raise ValueError('numeric dataset GUID required')
        return value
    def mounted(label,dataset,path):
        data=command(label,'/sbin/mount -p')
        if not any(line.split()[:3]==[dataset,path,'zfs'] for line in data.decode().splitlines()):
            raise ValueError('expected ZFS mount missing: '+dataset)
    def packages(label,version,program=pkg):
        value=command(label,program+" query -a '%n %v'")
        return package_rows(value,names,version)
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self,fmt,*args):
            with (output/'upgrade-http.log').open('a') as log:log.write(fmt%args+'\n')
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Handler,directory=str(loaded['repository']/'repository')))
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    url='http://'+p['guest_host_address']+':'+str(server.server_port)
    def upload(label,source,destination):return invoke('upgrade-'+label,'umask 077; /bin/cat > '+q(destination),source)
    def config(label,directory,key,remote_key):
        file=output/('upgrade-'+label+'.conf')
        file.write_text(json.dumps({'upgrade':dict(url=url,enabled=True,signature_type='pubkey',pubkey=remote_key,mirror_type='none')})+'\n')
        command(label+'-directory','/bin/mkdir -m 700 '+q(directory))
        upload(label+'-configuration',file,directory+'/upgrade.conf')
        upload(label+'-trust',loaded['repository']/'control'/key,remote_key)
    def login(label):
        console.expect(rb'BAZEL_SYSTEM_BOOT_READY pid1=',p['deadline_seconds'])
        console.expect(rb'login:\s*$',180);console.send(plan['console_user'])
        console.expect(rb'Password:\s*$',30);console.send(plan['password'])
        console.expect(rb'(?:^|[\r\n])[^\r\n]*[#$] $',60)
        check(label+'-console',lambda:console.command('test "$(id -u)" -eq 0 && echo UPGRADE_CONSOLE_OK'))
    def verify_boot(label,dataset,version,revision,expected_kernel,expected_guid):
        mounted(label+'-root',dataset,'/')
        if guid(label+'-guid',dataset)!=expected_guid:raise ValueError('booted dataset identity changed')
        if revision not in text(label+'-running-kernel','/usr/bin/uname -v'):raise ValueError('running kernel revision differs')
        if sha(label+'-kernel','/boot/kernel/kernel')!=expected_kernel:raise ValueError('installed kernel digest differs')
        packages(label+'-packages',version)
        if guid(label+'-shared-guid',shared)!=shared_guid:raise ValueError('persistent dataset identity changed')
        mounted(label+'-shared-mount',shared,loaded['mountpoint'])
        command(label+'-sshd','/usr/sbin/service sshd status')
        effective=command(label+'-sshd-pam','/usr/sbin/sshd -T').decode()
        if [row.split()[1:] for row in effective.splitlines() if row.split() and row.split()[0].lower()=='usepam']!=[['yes']]:
            raise ValueError('PAM must remain enabled after BE selection')
        process=command(label+'-pid1','/usr/bin/procstat -b 1').decode()
        if not any(len(row.split())==4 and row.split()[:2]==['1','capsule'] and row.split()[3]=='/sbin/capsule' for row in process.splitlines()):
            raise ValueError('Capsule PID 1 missing after BE selection')
        command(label+'-signal','probe=$(/bin/kill -0 1 2>&1); status=$?; test "$status" -eq 1 && printf "%s\\n" "$probe" | /usr/bin/grep -E "Permission denied|Operation not permitted"')
        check(label+'-ssh',lambda:ssh(label+'-ssh','test "$(id -u)" -eq '+str(plan['user_uid'])+' && echo UPGRADE_SSH_OK',plan['password']))
        check(label+'-ssh-wrong-password',lambda:ssh(label+'-ssh-negative','id -u',plan['password']+'-wrong',expected=255))
        check(label+'-su',lambda:ssh(label+'-su',"su -m root -c 'test \"$(id -u)\" -eq 0 && echo UPGRADE_SU_OK'",plan['password'],tty=True,answer=plan['password']))
        check(label+'-su-wrong-password',lambda:ssh(label+'-su-negative','su -m root -c "id -u"',plan['password'],expected=1,tty=True,answer=plan['password']+'-wrong'))
    try:
        mounted('baseline-root',old,'/');packages('baseline-packages',p['baseline_version'])
        old_guid=guid('baseline-guid',old);shared_guid=guid('shared-guid',shared)
        old_kernel=build_report['payload_sha256']['/boot/kernel/kernel']
        if sha('baseline-kernel','/boot/kernel/kernel')!=old_kernel:raise ValueError('baseline kernel differs')
        if p['baseline_kernel_revision'] not in text('baseline-running','/usr/bin/uname -v'):raise ValueError('baseline running revision differs')
        if sha('baseline-pkg-tool',p['pkg_path'])!=build_report['payload_sha256'][p['pkg_path']]:raise ValueError('pkg tool differs from image payload')
        old_db=sha('baseline-package-db','/var/db/pkg/local.sqlite')
        command('preflight-work','/bin/mkdir -m 700 '+q(prefix))
        config('preflight-good',prefix+'/good','repository.pub',prefix+'/good.pub')
        config('preflight-bad',prefix+'/bad','wrong.pub',prefix+'/bad.pub')
        def preflight(which):
            return pkg+' -R '+q(prefix+'/'+which)+' -o PKG_DBDIR='+q(prefix+'/'+which+'-db')+' -o PKG_CACHEDIR='+q(prefix+'/'+which+'-cache')
        command('catalogue-authentication',preflight('good')+' update -f -r upgrade')
        package_rows(command('catalogue-membership',preflight('good')+" rquery -U -r upgrade '%n %v'"),names,r['version'])
        command('wrong-key-rejection',preflight('bad')+' update -f -r upgrade > '+q(prefix+'/bad.out')+' 2> '+q(prefix+'/bad.err')+' || :; '+
            '/usr/bin/grep -Ei "signature|verification" '+q(prefix+'/bad.err')+' && { '+preflight('bad')+" rquery -U -r upgrade '%n' > "+q(prefix+'/bad.rows')+' 2> '+q(prefix+'/bad.queryerr')+' || :; } && test ! -s '+q(prefix+'/bad.rows'))
        if sha('post-preflight-db','/var/db/pkg/local.sqlite')!=old_db:raise ValueError('repository probe modified active package DB')
        command('preflight-cleanup','/bin/rm -rf -- '+q(prefix))
        command('new-name-absent','! /sbin/zfs list -H '+q(new)+' >/dev/null 2>&1')
        command('data-absent','test ! -e '+q(persistent)+' && test ! -L '+q(persistent))
        before='baseline-'+nonce+'\n';after=before+'after-upgrade-'+nonce+'\n'
        command('data-create','umask 077; printf %s '+q(before)+' > '+q(persistent))
        command('clone',be+' create -e '+q(loaded['baseline_name'])+' '+q(p['candidate']))
        new_guid=guid('candidate-guid',new)
        if new_guid==old_guid or not text('candidate-origin','/sbin/zfs get -Hp -o value origin '+q(new)).startswith(old+'@'):
            raise ValueError('candidate is not a distinct baseline clone')
        command('install-work','/bin/mkdir -m 700 '+q(prefix))
        root=prefix+'/root';command('mount',be+' mount '+q(p['candidate'])+' '+q(root));mounted('candidate-mount',new,root)
        inside='/.upgrade-input-'+nonce;inputs=root+inside
        command('input-directory','/bin/mkdir -m 700 '+q(inputs))
        command('pkg-copy','/bin/cp '+q(p['pkg_path'])+' '+q(inputs+'/pkg-static'))
        # Keys/config enter only the inactive root; no signing private key is copied.
        file=output/'upgrade-target.conf';file.write_text(json.dumps({'upgrade':dict(url=url,enabled=True,signature_type='pubkey',pubkey=inside+'/repository.pub',mirror_type='none')})+'\n')
        command('target-repositories','/bin/mkdir -m 700 '+q(inputs+'/repos'))
        upload('target-configuration',file,inputs+'/repos/upgrade.conf')
        upload('target-trust',loaded['repository']/'control/repository.pub',inputs+'/repository.pub')
        command('target-devfs','/sbin/mount -t devfs devfs '+q(root+'/dev'))
        target='/usr/sbin/chroot '+q(root)+' '+q(inside+'/pkg-static')+' -C /dev/null -R '+q(inside+'/repos')+' -o PKG_ENABLE_PLUGINS=no -o REPO_AUTOUPDATE=no -o PKG_DBDIR=/var/db/pkg -o PKG_CACHEDIR='+q(inside+'/cache')
        command('target-catalogue',target+' update -f -r upgrade')
        command('install',target+' upgrade -y -r upgrade')
        packages('candidate-packages',r['version'],target)
        command('candidate-checksums',target+' check -s -a')
        if sha('candidate-kernel',root+'/boot/kernel/kernel')!=p['kernel_sha256']:raise ValueError('new candidate kernel differs')
        if guid('candidate-identity-after-install',new)!=new_guid:raise ValueError('candidate replaced during install')
        command('target-devfs-unmount','/sbin/umount '+q(root+'/dev'))
        command('target-input-cleanup','/bin/rm -rf -- '+q(inputs))
        command('unmount',be+' unmount '+q(p['candidate']))
        command('install-work-cleanup','/bin/rm -rf -- '+q(prefix))
        if sha('active-db-after-install','/var/db/pkg/local.sqlite')!=old_db:raise ValueError('inactive installation modified active package DB')
        packages('active-still-old',p['baseline_version'])
        command('activate',be+' activate '+q(p['candidate']))
        if text('next-boot','/sbin/zpool get -Hp -o value bootfs '+q(build_report['pool']))!=new:raise ValueError('new BE not selected')
        console.send('/sbin/shutdown -r now');login('new-boot')
        verify_boot('new-boot',new,r['version'],p['kernel_revision'],p['kernel_sha256'],new_guid)
        if command('data-after-new-boot','/bin/cat '+q(persistent)).decode()!=before:raise ValueError('persistent data lost on upgrade')
        command('data-update','printf %s '+q(after)+' > '+q(persistent)+' && /bin/sync')
        command('rollback-select',be+' activate '+q(loaded['baseline_name']))
        if text('rollback-next-boot','/sbin/zpool get -Hp -o value bootfs '+q(build_report['pool']))!=old:raise ValueError('rollback BE not selected')
        console.send('/sbin/shutdown -r now');login('rollback')
        verify_boot('rollback',old,p['baseline_version'],p['baseline_kernel_revision'],old_kernel,old_guid)
        if command('data-after-rollback','/bin/cat '+q(persistent)).decode()!=after:raise ValueError('rollback rewound shared data')
        if guid('candidate-before-removal',new)!=new_guid:raise ValueError('unused BE identity differs')
        free_before=int(text('free-before-removal','/sbin/zpool get -Hp -o value free '+q(build_report['pool'])))
        command('active-removal-refused','if '+be+' destroy '+q(loaded['baseline_name'])+'; then exit 1; fi')
        command('remove-unused',be+' destroy -o '+q(p['candidate']))
        listed=text('remaining-datasets','/sbin/zfs list -H -o name -r '+q(loaded['parent'])).splitlines()
        if any(name==new or name.startswith(new+'/') for name in listed):raise ValueError('removed BE still exists')
        if guid('baseline-after-removal',old)!=old_guid or guid('shared-after-removal',shared)!=shared_guid:raise ValueError('removal affected retained datasets')
        until=time.monotonic()+p['reclaim_deadline_seconds']
        while True:
            command('pool-sync-'+uuid.uuid4().hex[:8],'/sbin/zpool sync '+q(build_report['pool']))
            free_after=int(text('free-after-'+uuid.uuid4().hex[:8],'/sbin/zpool get -Hp -o value free '+q(build_report['pool'])))
            if free_after>free_before:break
            if time.monotonic()>until:raise TimeoutError('unused BE removal did not reclaim space within explicit deadline')
            console.tick();time.sleep(1)
        if command('data-after-removal','/bin/cat '+q(persistent)).decode()!=after:raise ValueError('BE removal modified shared data')
        command('data-cleanup','/bin/rm -- '+q(persistent))
        result=dict(status='passed',scope='Actual complete signed-package inactive-BE upgrade, new-kernel boot, authentication, rollback and unused-BE deletion; explicit shared-file persistence, not application database/schema rollback or exhaustive upgraded-tree metadata',baseline=old,candidate=new,old_guid=old_guid,new_guid=new_guid,shared_guid=shared_guid,packages=len(names),new_version=r['version'],new_kernel_sha256=p['kernel_sha256'],reclaimed_bytes=free_after-free_before)
        (output/'upgrade-result.json').write_text(json.dumps(result,indent=2)+'\n');check('boot-environment-upgrade-rollback-removal',lambda:result)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)
