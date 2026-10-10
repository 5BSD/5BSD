#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise operator argument handling and script selection without tracing.
This deliberately mocks dtrace; it does not establish D language/runtime validity.
"""
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path(sys.argv[1] if len(sys.argv) > 1 else '/usr/src/share/dtrace/capability-observe')
with tempfile.TemporaryDirectory(prefix='tracing-cli-') as tmp:
    root = Path(tmp)
    mock = root / 'dtrace'
    mock.write_text('''#!/usr/bin/env python3.12
import json, os, sys
from pathlib import Path
a=sys.argv[1:]
p=Path(os.environ['TRACE_TEST_LOG'])
with p.open('a') as f:
 f.write(json.dumps(a)+'\\n')
if '-l' in a:
 sys.exit(int(os.environ.get('TRACE_TEST_MISSING', '0')))
for i,v in enumerate(a[:-1]):
 if v == '-s' and 'capability-observe.' in a[i+1]:
  Path(os.environ['TRACE_TEST_CAPTURE']).write_text(Path(a[i+1]).read_text())
''')
    mock.chmod(0o755)
    log = root / 'calls'
    capture = root / 'capture'
    env = dict(os.environ, PATH=str(root)+':'+os.environ['PATH'],
               TRACE_TEST_LOG=str(log), TRACE_TEST_CAPTURE=str(capture))
    def run(args, **extra):
        log.unlink(missing_ok=True)
        return subprocess.run(['sh', str(script), *args], env=dict(env, **extra),
                              capture_output=True, text=True)
    invalid = [[], ['BSDTime'], ['unknown','12'], ['BSDTime','0'],
               ['BSDTime','00'], ['BSDTime','012'], ['BSDTime','-1'],
               ['BSDTime','1;exit'], ['BSDTime','12','0'], ['BSDTime','12','3601'],
               ['BSDTime','12','1sec'], ['BSDTime','12','999999999999'],
               ['BSDTime','12','1','extra'], ['--list','extra']]
    for args in invalid:
        r = run(args)
        assert r.returncode == 2, (args, r)
        assert not log.exists(), args
    names = run(['--list']).stdout.split()
    assert len(names) == 19 and len(set(names)) == 19
    for name in names:
        r = run([name,'123','1'])
        assert r.returncode == 0, (name, r.stderr)
        calls = [json.loads(x) for x in log.read_text().splitlines()]
        assert len(calls) == 2 and '-l' in calls[0]
        scripts = [calls[1][i+1] for i,a in enumerate(calls[1][:-1]) if a == '-s']
        expected = 'bsdmemory-observe' if name == 'BSDMemory' else 'channel-observe'
        assert len(scripts) == (1 if name == 'meshd' else 3 if name == 'BSDTime' else 2), (name, scripts)
        if name != 'meshd':
            assert Path(scripts[0]).name == expected
        assert not Path(scripts[-1]).exists(), 'temporary D script leaked'
        if name == 'BSDTime':
            assert Path(scripts[1]).name == 'fidl-observe'
        body = capture.read_text()
        # Check emitted probe names/argument indices against real declarations.
        source = script.parents[2]
        daemon_dir = source / 'usr.sbin' / name
        if name in ('BSDBluetooth', 'meshd'):
            daemon_dir = source / 'usr.sbin/bluetooth' / name
        declarations = {}
        provider_name = None
        code = '\n'.join(f.read_text() for f in daemon_dir.glob('*.c'))
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.S)
        headers = '\n'.join(f.read_text() for f in daemon_dir.glob('*.h'))
        headers = headers.replace('\\\n', '')
        macro_bodies = re.findall(r'^#define\s+(\w+)\([^\n]*?\)\s*([^\n]*)', headers, re.M)
        for provider_file in daemon_dir.glob('*provider.d'):
            text = re.sub(r'/\*.*?\*/', '', provider_file.read_text(), flags=re.S)
            provider_name = re.search(r'provider\s+(\w+)', text).group(1)
            for probe, args in re.findall(r'probe\s+(\w+)\s*\((.*?)\)', text, re.S):
                declarations[probe.replace('__', '-')] = len(args.split(',')) if args.strip() not in ('', 'void') else 0
        assert declarations, name
        for probe, clause in re.findall(r'\w+123:::([\w-]+)\s*\{(.*?)\}', body, re.S):
            assert probe in declarations, (name, probe)
            raw_probe = probe.replace('-', '__')
            generated = provider_name.upper() + '_' + probe.replace('-', '_').upper()
            aliases = [generated]
            for macro, expansion in macro_bodies:
                if generated + '(' in expansion or re.search(
                        r'\b' + provider_name + r'\s*,\s*' + raw_probe + r'\b', expansion):
                    aliases.append(macro)
            assert any(re.search(r'\b' + macro + r'\s*\(', code) for macro in aliases), (
                name, probe, 'declared probe has no daemon call site')
            for index in re.findall(r'\barg(\d+)\b', clause):
                assert int(index) < declarations[probe], (name, probe, index)

        assert 'copyinstr' not in body and 'stringof' not in body
        if name == 'BSDSysctl':
            assert '(int)arg3' in body and '(int)arg4' in body
        if name == 'BSDAudit':
            assert ':::submit { @status[probename, (int)arg3]' in body
    r = run(['BSDTime','123'], TRACE_TEST_MISSING='1')
    assert r.returncode != 0 and len(log.read_text().splitlines()) == 1
    print(json.dumps({'result':'pass', 'invalid_inputs':len(invalid),
                      'daemon_selections':len(names), 'missing_provider':'rejected',
                      'scope':'mocked CLI only; no DTrace runtime validation'}))
