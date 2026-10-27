#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check real pkg config registration using a private disposable package stage."""
import argparse
import json
from pathlib import Path
import subprocess
import archive_verify
from libmd_environment import digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pkg', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    pkg = args.pkg.resolve(strict=True)
    root = args.output.resolve()
    if (not args.pkg.is_absolute() or not args.output.is_absolute() or args.output.is_symlink()
            or root.exists() or root == Path('/usr/obj') or not root.is_relative_to('/usr/obj')):
        parser.error('absolute pkg and fresh private output below /usr/obj required')
    src = Path(__file__).resolve().parents[3]
    awk = src / 'release/scripts/mtree-to-plist.awk'
    inputs = {str(p): digest(p) for p in (pkg, Path(__file__), Path(archive_verify.__file__), awk)}
    root.mkdir()
    workspace = root / 'workspace'; binary = workspace / 'bazel-bin'
    stage = binary / 'native_stage.root'; (stage / 'etc').mkdir(parents=True)
    data = b'configured=yes\n'; payload = stage / 'etc/example.conf'
    payload.write_bytes(data); payload.chmod(0o600); (stage/'etc').chmod(0o755)
    metadata = '. type=dir uname=root gname=wheel mode=0755\n./etc type=dir uname=root gname=wheel mode=0755\n'
    metadata += './etc/example.conf type=file uname=root gname=wheel mode=0600 tags=package=config-probe,config sha256='+digest(payload)+' size='+str(len(data))+'\n'
    metalog = binary / 'native_stage.METALOG'; metalog.write_text(metadata)
    (binary/'probe_install_manifest.json').write_text(json.dumps(dict(files=[dict(destination='/etc/example.conf',type='file',source='bazel-bin/native_stage.root/etc/example.conf')])))
    abi = subprocess.check_output([str(pkg),'config','ABI'],text=True).strip()
    commands = []
    def run(argv, cwd):
        result = subprocess.run(argv,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        commands.append(dict(argv=argv,cwd=str(cwd),status=result.returncode,stdout=result.stdout,stderr=result.stderr))
        (root/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode:raise RuntimeError('command failed; see commands.json')
    results = {}
    for name, omit in (('registered',False),('omitted',True)):
        case = root/name; case.mkdir(); meta=case/'metadata';meta.mkdir();packages=case/'packages';packages.mkdir()
        run(['/usr/bin/awk','-v','complete_dirs=yes','-f',str(awk),str(metalog)],case)
        plist = case/'config-probe.plist'
        if omit:
            text = plist.read_text(); assert '@config' in text
            plist.write_text(text.replace('@config','@'))
        (meta/'+MANIFEST').write_text(json.dumps(dict(name='5BSD-config-probe',version='1',origin='tests/config-probe',comment='Configuration verifier fixture',desc='Disposable configuration verifier fixture',maintainer='nobody@example.invalid',www='https://example.invalid',prefix='/',abi=abi)))
        run([str(pkg),'create','-r',str(stage),'-m',str(meta),'-p',str(plist),'-o',str(packages)],case)
        archives=list(packages.glob('*.pkg'));assert len(archives)==1
        try:
            result=archive_verify.verify(archives,workspace,['probe'],case/'inspection',abi,'1')
        except ValueError as error:
            if not omit or 'package config inventory differs' not in str(error):raise
            results[name]=dict(status='rejected',reason=str(error),archive_sha256=digest(archives[0]))
        else:
            if omit:raise AssertionError('missing config marker accepted')
            results[name]=dict(status=result['status'],archive_sha256=digest(archives[0]))
    for p,sha in inputs.items():
        if digest(Path(p))!=sha:raise ValueError('test input changed')
    (root/'receipt.json').write_text(json.dumps(dict(status='passed',scope='real pkg archive configuration registration and omission rejection; no installation or upgrade',results=results,input_sha256=inputs,host_installed=False),indent=2)+'\n')
    print(root/'receipt.json')


if __name__ == '__main__':
    main()
