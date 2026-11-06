# SPDX-License-Identifier: BSD-2-Clause
"""VM-only real pkg installation and state-preserving reinstall verification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['root', 'inputs', 'pkg', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    root, inputs = args.root.resolve(strict=True), args.inputs.resolve(strict=True)
    if os.geteuid()!=0 or root==Path('/') or not inputs.is_relative_to(root/'.pkg-check'):
        raise ValueError('requires disposable VM root and separately mounted package inputs')
    expected=json.loads((inputs/'expected.json').read_text())
    assert expected['format']==1
    work=root/'.pkg-check';tool=work/'pkg-static'
    assert digest(args.pkg)==expected['pkg_sha256']
    shutil.copyfile(args.pkg,tool);tool.chmod(0o555)
    (work/'repos').mkdir();(work/'pkg.conf').write_text('{}\n')
    (work/'repos/fixture.conf').write_text(json.dumps(dict(fixture=dict(url='file:///.pkg-check/inputs/repository',enabled=True,signature_type='none')))+'\n')
    common=['/.pkg-check/pkg-static','-C','/.pkg-check/pkg.conf','-R','/.pkg-check/repos']
    for setting in ['ABI='+expected['abi'],'OSVERSION='+str(expected['osversion']),
                    'RUN_SCRIPTS=yes','PKG_ENABLE_PLUGINS=no','REPO_AUTOUPDATE=no','SYSLOG=no']:
        common+=['-o',setting]
    names=expected['packages']
    report=dict(status='running',scope='Real complete pkg install into disk-backed bootstrapped target and same-version reinstall with site state; not normal startup or new-version upgrade',packages=len(names),commands=[],checks=[])
    def save():
        data=json.dumps(report,indent=2)+'\n';args.output.write_text(data);(work/'report.json').write_text(data)
    def enter():
        os.setgroups([]);os.chroot(root);os.chdir('/');os.setgid(0);os.setuid(0)
    def run(argv,label):
        started=time.monotonic()
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            start_new_session=True,preexec_fn=enter,
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/root','LC_ALL':'C'})
        try:
            stdout,stderr=process.communicate(timeout=600)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.communicate();raise
        for kind,data in [('stdout',stdout),('stderr',stderr)]:
            (work/(label+'.'+kind)).write_bytes(data)
        report['commands'].append(dict(argv=argv,status=process.returncode,
            elapsed_seconds=round(time.monotonic()-started,3),
            stdout_sha256=digest(work/(label+'.stdout')),stderr_sha256=digest(work/(label+'.stderr'))))
        save()
        assert process.returncode==0,(label,stdout.decode(errors='replace')[-1800:],stderr.decode(errors='replace')[-1800:])
        return stdout.decode()
    def verify(label,overrides):
        errors=[];inodes={};observed={}
        for path,record in expected['files'].items():
            target=root/path.lstrip('/')
            try:
                info=target.lstat()
                assert (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_flags)==(record['uid'],record['gid'],record['mode'],record['flags']), 'ownership/mode/flags'
                if record['type']=='symlink':
                    assert stat.S_ISLNK(info.st_mode) and os.readlink(target)==record['link'],'symlink'
                else:
                    assert stat.S_ISREG(info.st_mode),'regular file'
                    assert digest(target)==overrides.get(path,record['sha256']),'contents'
                    inodes[path]=(info.st_dev,info.st_ino)
                observed[path]=True
            except Exception as error:errors.append(dict(path=path,error=repr(error)))
        for path,record in expected['directories'].items():
            try:
                info=(root/path.lstrip('/')).lstat()
                assert stat.S_ISDIR(info.st_mode) and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_flags)==(record['uid'],record['gid'],record['mode'],record['flags']),'directory attributes'
            except Exception as error:errors.append(dict(path=path,error=repr(error)))
        for package,groups in expected['inode_groups'].items():
            actual={}
            for group in groups:
                for path in group:
                    if path in inodes:actual.setdefault(inodes[path],set()).add(path)
            if {frozenset(g) for g in actual.values()}!={frozenset(g) for g in groups}:
                errors.append(dict(package=package,error='package-local inode groups'))
        report['checks'].append(dict(phase=label,files=len(observed),directories=len(expected['directories']),overrides=overrides,errors=errors));save()
        assert not errors,(label,len(errors),'file/directory/inode discrepancies; inspect report')
        installed=run(common+['query','-a','%n'],label+'-inventory').splitlines()
        assert sorted(installed)==names,'installed inventory differs'
    try:
        for name,sha in expected['archives'].items():
            assert digest(inputs/'repository'/name)==sha,name
        run(common+['update','-f','-r','fixture'],'catalogue')
        run(common+['install','-y','-U','-r','fixture',*names],'install')
        verify('installed',{})
        run(common+['check','-s','-a'],'checksums')
        # Explicit site inputs are validated against source package ownership.
        site=expected['site'];config=site['config'];assert config in expected['config_paths']
        config_file=root/config.lstrip('/');config_file.write_bytes(config_file.read_bytes()+b'\n# package qualification local configuration\n')
        account=site['user']
        run(['/usr/sbin/pw','useradd',account['name'],'-u',str(account['uid']),'-g',str(account['gid']),'-d','/nonexistent','-s','/usr/sbin/nologin','-w','no'],'site-user')
        overrides={path:digest(root/path.lstrip('/')) for path in [config,'/etc/master.passwd','/etc/group']}
        data=root/site['data'].lstrip('/');assert site['data'] not in expected['files']
        data.parent.mkdir(parents=True);data.write_bytes(b'package qualification persistent database data\n');data_hash=digest(data)
        run(common+['install','-f','-y','-U','-r','fixture',*names],'reinstall')
        verify('reinstalled',overrides)
        assert digest(data)==data_hash,'local variable data changed'
        user=run(['/usr/sbin/pw','usershow',account['name']],'preserved-user').strip().split(':')
        assert user[0]==account['name'] and int(user[2])==account['uid'] and int(user[3])==account['gid'],'local user changed'
        for path,record in expected['construction'].items():
            info=(root/path.lstrip('/')).stat()
            assert stat.S_ISREG(info.st_mode) and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(record['uid'],record['gid'],record['mode']),('generated state',path)
        report.update(status='passed',installed_packages=len(names),reinstalled_packages=len(names),preserved_data=dict(path=site['data'],sha256=data_hash),preserved_user=account)
        save()
    except Exception as error:
        report.update(status='failed',error=repr(error));save();raise


if __name__=='__main__':
    main()
