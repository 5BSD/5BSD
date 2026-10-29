# SPDX-License-Identifier: BSD-2-Clause
"""Executable-level cases for the actual dtrace(1); loaded by coverage-cli.py.

Every case runs the real instrumented binary under cli-model-shim.so and
asserts its exit status and output.  Expected text is written from the
formats in dtrace.c and D semantics (record widths: an 8-byte trace() value
is " %16lld"; the non-flowindent probe prefix is "%3d %6d %32s "), never
captured from a run.  Probe IDs are the model's: dtrace:::BEGIN 1, END 2,
ERROR 3, test:kernel:alpha:entry 4, alpha:return 5, beta:entry 6,
beta:return 7, profile:::tick-1sec 8.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time

HDR = '%3s %6s %32s\n' % ('CPU', 'ID', 'FUNCTION:NAME')
FAST = ['-x', 'switchrate=10ms', '-x', 'aggrate=10ms', '-x', 'statusrate=10ms']


def probe(cpu, pid, func, name):
    return '%3d %6d %32s ' % (cpu, pid, f'{func}:{name}')


def t8(value):
    return ' %16d' % value


def t4(value):
    """A 4-byte record: an int, such as an integer constant (the compiler's
    type for it; the linker keeps the type the compiler knew)."""
    return ' %8d' % value


def matched(desc, n, kind='description'):
    return f"dtrace: {kind} '{desc}' matched {n} probe{'' if n == 1 else 's'}\n"


CASES = []


def case(name, args, **kw):
    kw['name'] = name
    kw['args'] = args
    CASES.append(kw)


# ---------------------------------------------------------------------------
# Modeled execution (dtrace_vopen with the dtrace(4) model).

case('exec-begin-exit', FAST + ['-n', 'BEGIN { trace(1); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 n:0',
     stdout=HDR + probe(0, 1, '', 'BEGIN') + t4(1) + '\n\n',
     stderr=matched('BEGIN ', 1))

case('exec-exit-status', FAST + ['-n', 'BEGIN { exit(3); }'],
     script='go 0 dtrace:::BEGIN n:3', status=3,
     stdout=HDR + probe(0, 1, '', 'BEGIN') + '\n\n',
     stderr=matched('BEGIN ', 1))

case('exec-quiet-printf', FAST + ['-q', '-n', 'BEGIN { printf("hello %d\\n", 42); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:42 n:0',
     stdout='hello 42\n\n', stderr='')

case('exec-aggregation-at-exit', FAST + ['-n', 'BEGIN { @c = count(); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 a:0:1 n:0',
     stdout=HDR + probe(0, 1, '', 'BEGIN') + '\n\n' + ' %16d\n' % 1,
     stderr=matched('BEGIN ', 1))

case('exec-sigint', FAST + ['-n', 'test:kernel:alpha:entry { trace(arg0); }'],
     script='go 1 test:kernel:alpha:entry n:7',
     signals=[('ROUND 2', signal.SIGINT)],
     stdout=HDR + probe(1, 4, 'alpha', 'entry') + t8(7) + '\n' + '\n' + '\n',
     stderr=matched('test:kernel:alpha:entry ', 1))

case('exec-sigterm', FAST + ['-n', 'test:kernel:beta:entry { trace(arg0); }'],
     script='go 2 test:kernel:beta:entry n:-5',
     signals=[('ROUND 2', signal.SIGTERM)],
     stdout=HDR + probe(2, 6, 'beta', 'entry') + t8(-5) + '\n' + '\n' + '\n',
     stderr=matched('test:kernel:beta:entry ', 1))

case('exec-siginfo-aggregation', FAST + ['-n', 'test:kernel:alpha:entry { @c = count(); }'],
     script='go 0 test:kernel:alpha:entry n:1 a:0:1',
     signals=[('ROUND 3', signal.SIGINFO), ('ROUND 6', signal.SIGINT)],
     # An ECB whose only actions aggregate records nothing in the principal
     # buffer (dtrace_ecb_resize), so no probe line or heading is printed.
     # SIGINFO's and SIGINT's newline requests coalesce when both arrive
     # before one pass of the consumer loop.
     stdout_re=' {16}1\n\n\n?\n {16}1\n',
     stderr=matched('test:kernel:alpha:entry ', 1))

case('exec-flowindent', FAST + ['-F', '-n', 'test:kernel:alpha:entry, test:kernel:alpha:return {}'],
     script='go 0 test:kernel:alpha:entry ; go 0 test:kernel:alpha:return',
     signals=[('ROUND 2', signal.SIGINT)],
     # libdtrace flow prefixes are " -> " and " <- " (dt_flowindent).
     stdout='%3s %-41s\n' % ('CPU', 'FUNCTION') + '%3d %-41s \n' % (0, ' -> alpha')
     + '%3d %-41s \n' % (0, ' <- alpha') + '\n\n',
     stderr=matched('test:kernel:alpha:entry, test:kernel:alpha:return ', 2))

case('exec-output-file', FAST + ['-o', '{d}/out.txt', '-n', 'BEGIN { trace(5); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:5 n:0', stdout='', stderr=matched('BEGIN ', 1),
     files={'out.txt': HDR + probe(0, 1, '', 'BEGIN') + t4(5) + '\n\n'})

case('exec-zero-probes-default', FAST + ['-n', 'nosuch:::probe'], status=1, stdout='',
     # No HyperTrace target: the conventional four-part description.
     stderr="dtrace: invalid probe specifier nosuch:::probe: probe description "
            "nosuch:::probe does not match any probes\n")


LISTHDR = '%5s %10s %17s %33s %s\n' % ('ID', 'PROVIDER', 'MODULE', 'FUNCTION', 'NAME')
MODEL_PROBES = [(1, 'dtrace', '', '', 'BEGIN'), (2, 'dtrace', '', '', 'END'),
                (3, 'dtrace', '', '', 'ERROR'), (4, 'test', 'kernel', 'alpha', 'entry'),
                (5, 'test', 'kernel', 'alpha', 'return'), (6, 'test', 'kernel', 'beta', 'entry'),
                (7, 'test', 'kernel', 'beta', 'return'), (8, 'profile', '', '', 'tick-1sec')]


def lrow(pid):
    p = MODEL_PROBES[pid - 1]
    return '%5d %10s %17s %33s %s\n' % p


PROBEINFO_NONE = ('\n\tProbe Description Attributes\n'
                  '\t\tIdentifier Names: Evolving\n\t\tData Semantics:   Evolving\n'
                  '\t\tDependency Class: Common\n\n\tArgument Attributes\n'
                  '\t\tIdentifier Names: Evolving\n\t\tData Semantics:   Evolving\n'
                  '\t\tDependency Class: Common\n\n\tArgument Types\n\t\tNone\n\n')

case('opt-version', ['-V'], stdout='dtrace: Sun D 1.13\n', stderr='')
case('opt-usage-no-arguments', [], status=2, stdout='',
     stderr_has=['Usage: dtrace [-32|-64] [-1aACdeFGhHlqSvVwZ] [-b bufsz]',
                 '\t-Z  permit probe descriptions that match zero probes\n'])
case('opt-illegal-32', ['-33', '-V'], status=2, stdout='',
     stderr_has=['dtrace: illegal option -- 33\n', 'Usage: dtrace'])
case('opt-illegal-64', ['-65'], status=2, stdout='',
     stderr_has=['dtrace: illegal option -- 65\n', 'Usage: dtrace'])
case('opt-model-32', ['-32', '-e', '-n', 'BEGIN { trace(1); }'], open='nodev',
     stdout='', stderr='', log_has=['NODEV-OPEN flags 0x8'])
case('opt-model-64', ['-64', '-e', '-n', 'BEGIN { trace(1); }'], open='nodev',
     stdout='', stderr='', log_has=['NODEV-OPEN flags 0x4'])
case('opt-anon-list-conflict', ['-A', '-l'], status=2, stdout='',
     stderr='dtrace: only one of the [-AGhlV] options can be specified at a time\n')
case('opt-no-probes-specified', FAST, status=1, stdout='',
     stderr='dtrace: no probes specified\n')
case('opt-include-libdir-undef', ['-e', '-I', '{d}', '-L', '{d}', '-U', 'FOO', '-H', '-S',
                                  '-n', 'BEGIN { trace(1); }'], open='nodev', stdout='',
     stderr_has=['DIFO'])
case('opt-sugar-dump', ['-e', '-d', '-n', 'BEGIN /1/ { trace(1); }'], open='nodev',
     stdout_has=['BEGIN'])
case('opt-cpp-script', ['-e', '-C', '-s', '{d}/s.d'], open='nodev',
     inputs={'s.d': '#define VALUE 3\nBEGIN { trace(VALUE); }\n'}, stdout='', stderr='')
case('opt-bench-path-too-long', ['-1', 'x' * 1100, '-e', '-n', 'BEGIN {}'], open='nodev',
     status=1, stdout='', stderr='dtrace: strlen(' + 'x' * 1100 + ') (1100) > 1023\n')
case('opt-bench-path', ['-1', '{d}/bench.json', '-e', '-n', 'BEGIN {}'], open='nodev',
     stdout='', stderr='')
case('opt-quiet-verbose-script', ['-e', '-v', '-s', '{d}/s.d'], open='nodev',
     inputs={'s.d': 'BEGIN { trace(1); }\n'},
     stdout_has=["\nStability attributes for script {d}/s.d:\n",
                 '\n\tMinimum Probe Description Attributes\n'])
case('opt-open-fails', ['-n', 'BEGIN {}'], open='fail:9:1', status=1, stdout='',
     stderr='dtrace: failed to initialize dtrace: Operation not permitted\n')
case('opt-open-retries-nodev', ['-e', '-n', 'BEGIN { trace(1); }'], open='fail:1:2',
     stdout='', stderr='', log_has=['OPEN-FAIL flags 0 err 2', 'NODEV-OPEN flags 0x1'])
case('opt-unsafe', ['-u', '-e', '-n', 'BEGIN { trace(1); }'], open='nodev', stdout='',
     stderr='')
case('opt-buffered-output-file', ['-B', '-o', '{d}/x', '-n', 'BEGIN {}'], status=2,
     stdout='', stderr='dtrace: -B not valid in combination with -o option\n')
case('opt-buffered-list', ['-B', '-l'], status=2, stdout='',
     stderr='dtrace: -B not valid in combination with [-AGl] options\n')

# Listing.
case('list-all', ['-l'], stdout=LISTHDR + ''.join(lrow(i) for i in range(1, 9)), stderr='')
case('list-entry', ['-l', '-n', 'test:::entry'], stdout=LISTHDR + lrow(4) + lrow(6),
     stderr='')
case('list-verbose', ['-l', '-v', '-n', 'dtrace:::BEGIN'],
     stdout=LISTHDR + lrow(1) + PROBEINFO_NONE, stderr='')
case('list-module-function-provider', ['-l', '-m', 'kernel', '-f', 'beta', '-P', 'profile',
                                       '-i', '1'],
     stdout=LISTHDR + lrow(4) + lrow(5) + lrow(6) + lrow(7) + lrow(6) + lrow(7) + lrow(8)
     + lrow(1), stderr='')
case('list-no-match', ['-l', '-P', 'nosuch'], stdout=LISTHDR,
     stderr='dtrace: failed to match nosuch:::: No probe matches description\n')
case('list-output-file', ['-l', '-o', '{d}/l.txt', '-n', 'BEGIN'], stdout='', stderr='',
     files={'l.txt': LISTHDR + lrow(1)})
case('list-output-unwritable', ['-l', '-o', '{d}/absent/l.txt'], status=1, stdout='',
     stderr="dtrace: failed to open output file '{d}/absent/l.txt': No such file or directory\n")
case('list-sigint-stops-iteration', ['-l'], signals=[], stdout_has=[LISTHDR])

# Verbose -e stability report and statement information.
case('info-exec-verbose', ['-e', '-v', '-n', 'BEGIN { trace(1); }'],
     stdout_has=["\nStability attributes for description BEGIN :\n",
                 '\n\tMinimum Statement Attributes\n', '\n:::BEGIN\n',
                 '\tArgument Types\n\t\tNone\n'])

# Anonymous enablings.
NEXTBOOT = ('NEXTBOOT nextboot -a -e dtraceall_load="YES" -e dtrace_dof_load="YES" '
            '-e dtrace_dof_name="/boot/dtrace.dof" -e dtrace_dof_type="dtrace_dof" ')


def anon_file_check(lines_expected, preserved=()):
    def check(d, stdout, stderr, shimlog, daemonlog):
        errors = []
        text = (d/'anon.dof').read_text()
        lines = text.splitlines()
        dof = [l for l in lines if l.startswith('dof-data-')]
        if [l.split('=')[0] for l in dof] != [f'dof-data-{i}' for i in range(lines_expected)]:
            errors.append(f'unexpected DOF properties {[l[:12] for l in dof]}')
        for l in dof:
            value = l.split('=', 1)[1]
            if not re.fullmatch('(?:[0-9a-f]{2})+', value) or \
                    bytes.fromhex(value)[:4] != b'\x7fDOF':
                errors.append('DOF property is not hex-encoded DOF')
            else:
                raw = bytes.fromhex(value)
                filesz = int.from_bytes(raw[0x30:0x38], 'little') if len(raw) >= 0x38 else -1
                if filesz != len(raw):
                    errors.append(f'DOF size {len(raw)} != dofh_filesz {filesz}')
        for keep in preserved:
            if keep not in lines:
                errors.append(f'pruning removed {keep!r}')
        if any(l.startswith('dof-data-') and 'old' in l for l in lines):
            errors.append('old DOF property survived pruning')
        return errors
    return check


case('anon-save', ['-A', '-o', '{d}/anon.dof', '-n', 'BEGIN { trace(1); }'],
     stdout='', stderr='dtrace: saved anonymous enabling in {d}/anon.dof\n',
     log_has=[NEXTBOOT], check=anon_file_check(3))
case('anon-prune-existing', ['-A', '-o', '{d}/anon.dof', '-n', 'BEGIN { trace(1); }',
                             '-n', 'END { trace(2); }'],
     inputs={'anon.dof': 'keep-first\ndof-data-0=old\nmiddle dof-data-1=kept\n'
                         'dof-data-9=old\nlast-line\n'},
     stdout='', stderr='dtrace: cleaned up old anonymous enabling in {d}/anon.dof\n'
                       'dtrace: saved anonymous enabling in {d}/anon.dof\n',
     check=anon_file_check(4, ('keep-first', 'middle dof-data-1=kept', 'last-line')))
case('anon-prune-trailing-property', ['-A', '-o', '{d}/anon.dof'],
     inputs={'anon.dof': 'dof-data-0=old\n'}, stdout='',
     stderr='dtrace: cleaned up old anonymous enabling in {d}/anon.dof\n',
     files={'anon.dof': ''}, log_lacks=['NEXTBOOT'])
case('anon-prune-unterminated', ['-A', '-o', '{d}/anon.dof'],
     inputs={'anon.dof': 'keep\ndof-data-0=old'}, stdout='',
     stderr='dtrace: cleaned up old anonymous enabling in {d}/anon.dof\n',
     files={'anon.dof': 'keep\n'})
case('anon-no-program-no-file', ['-A', '-o', '{d}/absent.dof'], stdout='', stderr='',
     log_lacks=['NEXTBOOT'])
case('anon-unreadable-file', ['-A', '-o', '{d}/anon.dof'], inputs={'anon.dof': 'x\n'},
     modes={'anon.dof': 0o000}, status=1, stdout='',
     stderr='dtrace: failed to open {d}/anon.dof: Permission denied\n')
case('anon-output-directory-missing', ['-A', '-o', '{d}/absent/anon.dof', '-n', 'BEGIN {}'],
     status=1, stdout='',
     stderr="dtrace: failed to open output file '{d}/absent/anon.dof': "
            "No such file or directory\n")
case('anon-nextboot-fails', ['-A', '-o', '{d}/anon.dof', '-n', 'BEGIN {}'], nextboot='fail',
     status=1, stdout='', stderr='dtrace: saved anonymous enabling in {d}/anon.dof\n'
                                 'dtrace: nextboot returned with status 256: '
                                 'No such file or directory\n')
case('anon-nextboot-spawn-fails', ['-A', '-o', '{d}/anon.dof', '-n', 'BEGIN {}'],
     nextboot='spawnfail', status=1, stdout='',
     stderr='dtrace: saved anonymous enabling in {d}/anon.dof\n'
            'dtrace: failed to execute nextboot: No such file or directory: '
            'No such file or directory\n')

# Provider link (-G) and header (-h) modes.
case('link-requires-program', ['-G'], status=2, stdout='',
     stderr='dtrace: -G requires one or more scripts or enabling options\n')
case('link-default-output', ['-64', '-G', '-x', 'syslibdir={drti}', '-n', 'BEGIN { trace(1); }'], open='nodev', stdout='',
     stderr='', files={'d.out': None})
case('link-script-derived-names', ['-64', '-G', '-x', 'syslibdir={drti}', '-s', '{d}/a.d', '-s', '{d}/b.d', '-o',
                                   '{d}/all.o'], open='nodev',
     inputs={'a.d': 'BEGIN { trace(1); }\n', 'b.d': 'END { trace(2); }\n'}, stdout='',
     stderr='', files={'all.o': None}, check=lambda d, *a: link_merge_check(d))
def link_merge_check(d):
    # dtrace_program_link(NULL, ...) runs ld -r over the per-script objects
    # and then unlinks them; both DOF sections must survive in the result.
    errors = [f'intermediate {n} was not removed' for n in ('a.o', 'b.o') if (d/n).exists()]
    # ld -r concatenates the two same-named sections into one.
    subprocess.run(['/usr/bin/objcopy', '-O', 'binary', '--only-section=.SUNW_dof',
                    str(d/'all.o'), str(d/'all.dof')], check=True)
    if (d/'all.dof').read_bytes().count(b'\x7fDOF') != 2:
        errors.append('merged .SUNW_dof does not hold both DOF images')
    return errors


case('link-numbered-outputs', ['-64', '-G', '-x', 'syslibdir={drti}', '-n', 'BEGIN { trace(1); }', '-n', 'END { trace(2); }'],
     open='nodev', stdout='', stderr='', files={'d.out.0': None, 'd.out.1': None})
# Without objects or -64 the provider object follows libdtrace's ILP32 ELF
# default and cannot link with the LP64 runtime object (stock behavior).
case('link-default-model-no-objects', ['-G', '-x', 'syslibdir={drti}', '-n', 'BEGIN {}'],
     open='nodev', status=1, stdout='',
     stderr_re=r"ld: error: .*/drti\.o is incompatible with d\.out\.\w+\n"
               r"dtrace: failed to link description BEGIN : failed to link d\.out: "
               r"ld exited with status 1\n")
case('header-requires-program', ['-h'], status=2, stdout='',
     stderr='dtrace: -h requires one or more scripts or enabling options\n')
case('header-multiple-without-output', ['-h', '-s', '{d}/a.d', '-s', '{d}/b.d'],
     inputs={'a.d': 'provider pa { probe x(); };\n', 'b.d': 'provider pb { probe y(); };\n'},
     status=2, stdout='',
     stderr='dtrace: -h requires an output file if multiple scripts are specified\n')
case('header-description-without-output', ['-h', '-n', 'BEGIN'], status=2, stdout='',
     stderr='dtrace: -h requires an output file if no scripts are specified\n')
case('header-derived-name', ['-h', '-s', '{d}/prov.d'], inputs={'prov.d':
     'provider derived { probe event(int); };\n'}, stdout='', stderr='',
     check=lambda d, *a: [] if 'DERIVED_EVENT' in (d/'prov.h').read_text() and
     (d/'prov.h').read_text().startswith('/*\n * Generated by dtrace(1M).\n */\n\n')
     else ['derived header missing or wrong'])
case('header-unwritable', ['-h', '-s', '{d}/prov.d', '-o', '{d}/absent/x.h'],
     inputs={'prov.d': 'provider pa { probe x(); };\n'}, status=1, stdout='',
     stderr="dtrace: failed to open header file '{d}/absent/x.h': No such file or directory\n")


# More modeled execution: handlers, options, kernel adjustments, failures.
ENTRY = 'test:kernel:alpha:entry'
case('exec-error-handler', FAST + ['-n', 'BEGIN { trace(1); }'],
     script='go 0 dtrace:::BEGIN n:1 ; go 0 dtrace:::ERROR n:1 n:1 n:8 n:1 n:16',
     signals=[('ROUND 2', signal.SIGINT)],
     stdout=HDR + probe(0, 1, '', 'BEGIN') + t4(1) + '\n\n\n',
     stderr=matched('BEGIN ', 1) + 'dtrace: error on enabled probe ID 1 (ID 1: dtrace:::BEGIN): '
     'invalid address (0x10) in action #1 at DIF offset 8\n')
case('exec-drops', ['-b', '64'] + FAST + ['-n', ENTRY + ' { trace(arg0); }'],
     script=';'.join(f'go 0 {ENTRY} n:{i}' for i in range(1, 5)),
     signals=[('ROUND 2', signal.SIGINT)],
     stdout=HDR + probe(0, 4, 'alpha', 'entry') + t8(1) + '\n' + probe(0, 4, 'alpha', 'entry')
     + t8(2) + '\n\n\n',
     stderr=matched(ENTRY + ' ', 1) + 'dtrace: 2 drops on CPU 0\n')
case('exec-setopt-records', FAST + ['-n', ENTRY + ' { setopt("quiet"); setopt("flowindent"); '
                                    'trace(arg0); }'],
     script=f'go 0 {ENTRY} s:quiet n:0 s:flowindent n:0 n:5',
     signals=[('ROUND 2', signal.SIGINT)],
     stdout=HDR + probe(0, 4, 'alpha', 'entry') + '5' + '\n\n',
     stderr=matched(ENTRY + ' ', 1))
case('exec-destructive-notice', FAST + ['-w', '-n', 'BEGIN { exit(0); }'],
     script='go 0 dtrace:::BEGIN n:0', stdout=HDR + probe(0, 1, '', 'BEGIN') + '\n\n',
     stderr=matched('BEGIN ', 1) + 'dtrace: allowing destructive actions\n')
for label, model, extra, message in (
        ('bufsize-lowered-round', 'setopt=bufsize:1048576', [], 'buffer size lowered to 1m\n'),
        ('bufsize-lowered-bytes', 'setopt=bufsize:1000000', [], 'buffer size lowered to 1000000 bytes\n'),
        ('dynvar-lowered', 'setopt=dynvarsize:2048', ['-x', 'dynvarsize=1m'],
         'dynamic variable size lowered to 2k\n'),
        ('statusrate-reduced-hz', 'setopt=statusrate:20000000', ['-x', 'statusrate=100hz'],
         'status rate reduced to 50 hz\n'),
        ('statusrate-increased-hz', 'setopt=statusrate:50000000', ['-x', 'statusrate=10hz'],
         'status rate increased to 20 hz\n'),
        ('cleanrate-seconds', 'setopt=cleanrate:3000000000', ['-x', 'cleanrate=100hz'],
         'cleaning rate reduced to once every 3 seconds\n'),
        ('cleanrate-nanoseconds', 'setopt=cleanrate:1500000007', ['-x', 'cleanrate=100hz'],
         'cleaning rate reduced to once every 1500000007 nanoseconds\n'),
        ('statusrate-unchanged', 'setopt=statusrate:10000000', ['-x', 'statusrate=100hz'], ''),
        ('statusrate-zero', 'setopt=statusrate:0', ['-x', 'statusrate=100hz'], '')):
    case('exec-kernel-' + label, ['-x', 'switchrate=10ms'] + extra +
         ['-n', 'BEGIN { exit(0); }'], script='go 0 dtrace:::BEGIN n:0', model=model,
         stdout=HDR + probe(0, 1, '', 'BEGIN') + '\n\n',
         stderr=matched('BEGIN ', 1) + ('dtrace: ' + message if message else ''))
case('exec-go-fails', FAST + ['-n', 'BEGIN { exit(0); }'], model='fail=GO:0:5', status=1,
     stdout='', stderr=matched('BEGIN ', 1) +
     'dtrace: could not enable tracing: Input/output error\n')
case('exec-stop-fails', FAST + ['-n', ENTRY + ' { trace(arg0); }'], model='fail=STOP:0:5',
     signals=[('ROUND 2', signal.SIGINT)], status=1, stdout='\n',
     stderr=matched(ENTRY + ' ', 1) + "dtrace: couldn't stop tracing: Input/output error\n")
case('exec-enable-fails', FAST + ['-n', 'BEGIN { exit(0); }'], model='fail=ENABLE:0:22',
     status=1, stdout='', stderr_re=r"dtrace: failed to enable 'BEGIN ': .+\n")
case('exec-consume-fails', FAST + ['-n', ENTRY + ' { trace(arg0); }'],
     model='fail=BUFSNAP:3:5', status=1, stdout_re='.*',
     stderr=matched(ENTRY + ' ', 1) + 'dtrace: processing aborted: Input/output error\n')
case('exec-consume-interrupted', FAST + ['-n', ENTRY + ' { trace(arg0); }'],
     model='fail=BUFSNAP:3:4', signals=[('ROUND 3', signal.SIGINT)], stdout='\n\n',
     stderr=matched(ENTRY + ' ', 1))
case('exec-zero-probes-allowed', FAST + ['-Z', '-n', 'nosuch:::probe'],
     signals=[('ROUND 2', signal.SIGINT)], stdout='\n\n',
     stderr=matched('nosuch:::probe', 0))


def enabled_before_go(count):
    """Every program is enabled before the one GO: the model, like
    dtrace(4), refuses ENABLE on an active state with EBUSY.  dtrace_go()
    itself adds two ENABLEs (the dtrace:::ERROR program and the option DOF)
    right before its GO."""
    def check(d, stdout, stderr, shimlog, daemonlog):
        lines = shimlog.splitlines()
        enables = [i for i, l in enumerate(lines) if l.startswith('ENABLE matched')]
        gos = [i for i, l in enumerate(lines) if l == 'GO']
        if len(enables) != count + 2 or len(gos) != 1 or max(enables) > gos[0]:
            return [f'expected {count} program ENABLEs and dtrace_go()\'s two, then one '
                    f'GO; got enables at {enables}, GO at {gos}']
        return []
    return check


# Several programs in one invocation (-s, -n, -P) are all enabled, then
# tracing starts once; each program's clauses fire.
case('exec-two-programs', FAST + ['-s', '{d}/a.d', '-n', ENTRY + ' { trace(arg0); exit(0); }'],
     inputs={'a.d': 'BEGIN { trace(1); }\n'},
     script=f'go 0 dtrace:::BEGIN n:1 ; go 0 {ENTRY} n:7 n:0',
     stdout=HDR + probe(0, 1, '', 'BEGIN') + t4(1) + '\n' + probe(0, 4, 'alpha', 'entry')
     + t8(7) + '\n\n',
     stderr=matched('{d}/a.d', 1, 'script') + matched(ENTRY + ' ', 1),
     check=enabled_before_go(2))
case('exec-three-programs', FAST + ['-n', 'BEGIN { trace(1); }', '-s', '{d}/a.d',
                                    '-P', 'test { exit(0); }'],
     inputs={'a.d': ENTRY + ' { trace(arg0); }\n'},
     script=f'go 0 dtrace:::BEGIN n:1 ; go 0 {ENTRY} n:7 ; go 0 test:kernel:beta:entry n:0',
     stdout=HDR + probe(0, 1, '', 'BEGIN') + t4(1) + '\n' + probe(0, 4, 'alpha', 'entry')
     + t8(7) + '\n' + probe(0, 6, 'beta', 'entry') + '\n\n',
     stderr=matched('BEGIN ', 1) + matched('{d}/a.d', 1, 'script') + matched('test ', 4),
     check=enabled_before_go(3))
case('exec-programs-zero-allowed', FAST + ['-Z', '-n', 'nosuch:::probe', '-n',
                                           'BEGIN { exit(0); }'],
     script='go 0 dtrace:::BEGIN n:0', stdout=HDR + probe(0, 1, '', 'BEGIN') + '\n\n',
     stderr=matched('nosuch:::probe', 0) + matched('BEGIN ', 1), check=enabled_before_go(2))
# Slow rates keep the consumer asleep while both signals are taken.
case('exec-impatient', ['-x', 'switchrate=500ms', '-x', 'statusrate=500ms', '-x',
                        'aggrate=500ms', '-n', ENTRY + ' { @c = count(); }'],
     script=f'go 0 {ENTRY} n:1 a:0:1',
     signals=[('ROUND 1', signal.SIGINT), ('ROUND 1', signal.SIGTERM)], stdout='\n\n',
     stderr=matched(ENTRY + ' ', 1))
case('exec-sigusr1', FAST + ['-n', ENTRY + ' { trace(arg0); }'], script=f'go 0 {ENTRY} n:9',
     signals=[('ROUND 2', signal.SIGUSR1)],
     stdout=HDR + probe(0, 4, 'alpha', 'entry') + t8(9) + '\n\n\n',
     stderr=matched(ENTRY + ' ', 1))
case('exec-sigpipe', FAST + ['-n', ENTRY + ' { trace(arg0); }'], script=f'go 0 {ENTRY} n:9',
     signals=[('ROUND 2', signal.SIGPIPE)],
     stdout=HDR + probe(0, 4, 'alpha', 'entry') + t8(9) + '\n\n\n',
     stderr=matched(ENTRY + ' ', 1))
case('exec-write-fails', FAST + ['-n', 'BEGIN { trace(1); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 n:0', faults='vfprintf:1:5', status=1, stdout='',
     stderr=matched('BEGIN ', 1) + 'dtrace: failed to write to <stdout>: Input/output error\n')
case('exec-write-fails-file', FAST + ['-o', '{d}/o', '-n', 'BEGIN { trace(1); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 n:0', faults='vfprintf:1:5', status=1, stdout='',
     stderr=matched('BEGIN ', 1) + 'dtrace: failed to write to {d}/o: Input/output error\n')
case('exec-write-interrupted', FAST + ['-n', 'BEGIN { trace(1); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 n:0', faults='vfprintf:1:4',
     stdout=probe(0, 1, '', 'BEGIN') + t4(1) + '\n\n', stderr=matched('BEGIN ', 1))
case('exec-output-file-unwritable', FAST + ['-o', '{d}/absent/o', '-n', 'BEGIN {}'],
     status=1, stdout='',
     stderr="dtrace: failed to open output file '{d}/absent/o': No such file or directory\n")
case('exec-buffered', FAST + ['-B', '-n', 'BEGIN { trace(1); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 n:0', stderr=matched('BEGIN ', 1),
     stdout_has=['dtrace: >>> Called buffer handler:\n', 'dtrace:   dtrace_bufdata:\n',
                 'dtrace:   dtrace_probedesc:\n', 'dtrace:   dtrace_recdesc:\n'])
case('exec-buffered-aggregation', FAST + ['-B', '-n', 'BEGIN { @c[1] = count(); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 n:1 a:0:1 n:0', stderr=matched('BEGIN ', 1),
     stdout_has=['dtrace:   dtrace_aggdesc:\n', 'AGGVAL', 'AGGKEY', 'AGGLAST'])


def json_probe_check(expect_output, aggregate=None):
    import json

    def check(d, stdout, stderr, shimlog, daemonlog):
        try:
            doc = json.loads(stdout)
        except ValueError as error:
            return [f'not JSON: {error}: {stdout!r}']
        probes = doc.get('dtrace', {}).get('probes', [])
        named = [p for p in probes if 'name' in p]
        errors = []
        if not named or {k: named[0].get(k) for k in ('cpu', 'id', 'provider', 'name')} != \
                {'cpu': 0, 'id': 1, 'provider': 'dtrace', 'name': 'BEGIN'}:
            errors.append(f'probe fields {named[:1]}')
        if named and named[0].get('output') != expect_output:
            errors.append(f'output {named[0].get("output")}')
        aggs = [p for p in probes if 'name' not in p]
        if aggregate is not None and aggs != aggregate:
            errors.append(f'aggregations {aggs}')
        return errors
    return check


case('exec-oformat-json', FAST + ['--libxo', 'json', '-n', 'BEGIN { trace(7); exit(0); }'],
     # quiet is forced for oformat after g_quiet was read, so the
     # "matched" notice still prints.
     script='go 0 dtrace:::BEGIN n:7 n:0', stderr=matched('BEGIN ', 1),
     check=json_probe_check([{'value': 7}]))
case('exec-oformat-print-on-exit', FAST + ['--libxo', 'json', '-O', '-n',
                                           'BEGIN { @c = count(); trace(7); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 a:0:1 n:7 n:0', stderr=matched('BEGIN ', 1),
     check=json_probe_check([{'value': 7}], [{'keys': [], 'count': 1}]))
case('exec-oformat-drop-silent', ['-b', '64', '--libxo', 'json'] + FAST +
     ['-n', ENTRY + ' { trace(arg0); }'],
     script=';'.join(f'go 0 {ENTRY} n:{i}' for i in range(1, 5)),
     signals=[('ROUND 2', signal.SIGINT)], stderr=matched(ENTRY + ' ', 1),
     stdout_has=['"probes"'])


# VM listing (-M) against the scripted daemon.
VMHDR = 'HyperTrace-aware VMs:\n\n'
case('listvms-forwarders', ['-M'], daemon='info names=vm1:2,vm2:2,host:1,vm1:2\n',
     stdout=VMHDR + 'vm1\nvm2\n', stderr='', daemon_has=['subs=16'])
case('listvms-empty', ['-M'], daemon='info count=0\n', stdout=VMHDR, stderr='')
case('listvms-no-daemon', ['-M'], status=1, stdout='',
     stderr='dtrace: cannot connect to dtraced: Connection refused\n')
case('listvms-wrong-type', ['-M'], daemon='info type=3 count=0\n', status=1, stdout='',
     stderr='dtrace: invalid dtraced information header\n')
case('listvms-count-too-large', ['-M'], daemon='info count=1000000000\n', status=1,
     stdout='', stderr='dtrace: invalid dtraced information header\n')
case('listvms-undecodable-header', ['-M'], daemon='info type=99\n', status=1, stdout='',
     stderr='dtrace: invalid dtraced information header: Protocol error\n')
case('listvms-short-header', ['-M'], daemon='info short=1\n', status=1, stdout='',
     stderr='dtrace: cannot receive dtraced information header: Connection reset by peer\n')
case('listvms-short-entries', ['-M'], daemon='info count=3 names=vm1:2\n', status=1,
     stdout='', stderr='dtrace: cannot receive dtraced information: Connection reset by peer\n')
case('listvms-invalid-entry', ['-M'], daemon='info names=vm1:2 badentry=1\n', status=1,
     stdout='', stderr='dtrace: invalid dtraced information entry: Protocol error\n')
case('listvms-unterminated-entry', ['-M'], daemon='info names=vm1:2 unterminated=1\n',
     status=1, stdout='', stderr='dtrace: invalid dtraced information entry: Protocol error\n')
case('listvms-allocation-fails', ['-M'], daemon='info names=vm1:2\n', faults='calloc:1:12',
     status=1, stdout='', stderr='dtrace: cannot allocate dtraced information: '
     'Cannot allocate memory\n')
case('listvms-listing-allocation-fails', ['-M'], daemon='info names=vm1:2\n',
     faults='calloc:2:12', status=1, stdout='',
     stderr='dtrace: cannot allocate VM listing: Cannot allocate memory\n')
case('listvms-deadline-fails', ['-M'], daemon='info names=vm1:2\n',
     faults='clock_gettime:1:22', status=1, stdout='',
     stderr='dtrace: cannot set dtraced information deadline: Invalid argument\n')
case('listvms-write-fails', ['-M'], daemon='info names=vm1:2\n', faults='vfprintf:1:5',
     status=1, stdout='', stderr='dtrace: failed to write to <stdout>: Input/output error\n')


# HyperTrace host consumer (-E) against the scripted daemon.
TOKEN = '77' * 16
HOST = ['-E', '-1', '{d}/bench.json'] + FAST
STOP_OK = f'stop token={TOKEN} vmid=3 epoch=9\n'
case('host-stop-unidentified', HOST + ['-n', 'BEGIN { trace(1); }'],
     daemon='wait-elf 1\nsend-elf base\nwait-log {d}/shim.log GO\n' + STOP_OK + 'hold\n',
     gate=f'held:{TOKEN}', stdout='',
     stderr_re=r'dtrace: matched 1 probe \([0-9a-f]+\) from 0\n',
     daemon_has=['REGISTERED conn=1 magic=HPI2', 'ELF conn=2 location=base',
                 'STOP-REPLY result=1 echo=1', 'COMMIT conn=3 valid=1 result=1'])


MATCHED0 = r'dtrace: matched 1 probe \([0-9a-f]+\) from 0\n'
RECONNECTING = 'dtrace: dtraced disconnected; reconnecting\n'
RECONNECTED = 'dtrace: dtraced reconnected\n'
# Continue only once the consumer has started tracing the program.
BASE = 'wait-elf 1\nsend-elf base\nwait-log {d}/shim.log GO\n'
END_ON_SIGNAL = 'wait-file {d}/signal-1\nclose\n'
GATE = f'held:{TOKEN}'
PROG = ['-n', 'BEGIN { trace(1); }']
NOTEMPORAL = ['-x', 'temporal=no', '-o', '{d}/trace.out']


def all_of(*patterns):
    """Regex requiring every pattern somewhere (threads interleave lines)."""
    return '(?s)' + ''.join(f'(?=.*{p})' for p in patterns) + '.*'


def host(name, daemon, **kw):
    kw.setdefault('gate', GATE)
    if 'stdout_re' not in kw:
        kw.setdefault('stdout', '')
    if daemon is not None:
        kw['daemon'] = daemon
    case('host-' + name, HOST + kw.pop('extra', []) + kw.pop('prog', PROG), **kw)


# Refused stop challenges: the consumer keeps tracing; SIGINT ends it, the
# daemon then closes and the receiver's reconnect loop observes the interrupt.
for label, line, gate in (
        ('gate-absent', STOP_OK, 'absent'),
        ('wrong-session', f'stop token={TOKEN} csession={"11" * 16}\n', GATE),
        ('wrong-digest', f'stop token={TOKEN} digest=bad\n', GATE),
        ('wrong-token', f'stop token={"12" * 16}\n', GATE),
        ('gate-query-error', STOP_OK, 'ioerr')):
    host('stop-' + label, BASE + line + END_ON_SIGNAL, gate=gate,
         signals=[('STOP-REPLY', signal.SIGINT)], stdout='\n\n',
         stderr_re=all_of(MATCHED0, RECONNECTING), daemon_has=['STOP-REPLY result=0 echo=1'],
         daemon_lacks=['COMMIT'])
host('stop-gate-released-during-quiesce', BASE + STOP_OK + 'hold\n', gate=f'held:{TOKEN}:1',
     stderr_re=MATCHED0, daemon_has=['STOP-REPLY result=0'], daemon_lacks=['COMMIT'])
host('stop-commit-retried', BASE + STOP_OK + 'frame-ack 26 1 0\nhold\n', stderr_re=MATCHED0,
     daemon_has=['STOP-REPLY result=1', 'COMMIT conn=3 valid=1', 'COMMIT conn=4 valid=1'])
host('stop-commit-rejected', BASE + STOP_OK + 'frame-ack 26 0 0\nhold\n', status=1,
     stderr_re=MATCHED0 + 'dtrace: failed to process dtraced stop challenge: '
     'Input/output error\n', daemon_has=['COMMIT conn=4 valid=1'])
host('stop-commit-unreachable', 'drop-conn 3\ndrop-conn 4\n' + BASE + STOP_OK + 'hold\n',
     status=1,
     stderr_re=MATCHED0 + 'dtrace: failed to process dtraced stop challenge: '
     'Connection reset by peer\n', daemon_has=['DROP conn=3', 'DROP conn=4'])
host('stop-then-signal-skips-report', BASE + STOP_OK + 'hold\n', stderr_re=MATCHED0,
     daemon_has=['COMMIT conn=3 valid=1 result=1'])
# Receiver failures before any program arrives: the consumer thread is idle,
# so fatal() cannot race it (see the open defect for the racing case).
for label, steps, message in (
        ('stop-malformed', f'stop token={TOKEN} badmagic=1 noreply=1\n',
         'failed to process dtraced stop challenge: Protocol error\n'),
        ('drain-malformed', f'drain token={TOKEN} zerotoken=1 noreply=1\n',
         'failed to process dtraced drain challenge: Protocol error\n'),
        ('header-invalid', 'header 99\n', 'invalid dtraced ELF header: Protocol error\n'),
        ('header-unexpected-type', 'header 7\n',
         'unexpected message on dtraced ELF connection\n'),
        ('frame-length-invalid', 'send-elf base len=2 headeronly=1\n',
         'invalid dtraced ELF frame length\n'),
        ('envelope-invalid', 'send-elf base vmid=3 envelope=bad\n',
         'invalid dtraced VM/ELF envelope\n'),
        ('delivery-identity-conflict', 'send-elf base vmid=3 delivery=5 hvmid=4\n',
         'dtraced delivery identity conflicts with VM envelope\n'),
        ('ingress-session-mismatch', 'send-elf base vmid=3 delivery=5 installed=mismatch\n',
         'dtraced ingress session is missing or mismatched\n'),
        ('ingress-header-undecodable', 'send-elf base vmid=3 delivery=5 isession=zero\n',
         'invalid dtraced ELF header: Protocol error\n')):
    host(label, 'wait-elf 1\n' + steps + 'hold\n', status=1, stderr='dtrace: ' + message)
host('header-receive-error', 'wait-elf 1\nhold\n', faults='recv:1:5', status=1,
     stderr='dtrace: failed to receive complete dtraced header: Input/output error\n')
host('frame-allocation-fails', 'wait-elf 1\nsend-elf base\nhold\n', faults='malloc:2:12',
     status=1, stderr='dtrace: failed to allocate dtraced ELF frame: Cannot allocate memory\n')
host('frame-receive-error', 'wait-elf 1\nsend-elf base\nhold\n', faults='recv_large:1:5',
     status=1,
     stderr='dtrace: failed to receive complete dtraced ELF frame: Input/output error\n')
# Default temporal ordering: the quiesced drain flushes the ordering queue
# behind the producer fence instead of refusing, so the drain certifies.
host('drain-temporal-ordered', BASE + f'drain token={TOKEN}\n' + STOP_OK + 'hold\n',
     extra=['-o', '{d}/trace.out'], stderr_re=MATCHED0,
     daemon_has=['DRAIN-REPLY result=1 echo=1', 'STOP-REPLY result=1'])
host('drain-regular-file', BASE + f'drain token={TOKEN}\n' + STOP_OK + 'hold\n',
     extra=NOTEMPORAL, stderr_re=MATCHED0,
     daemon_has=['DRAIN-REPLY result=1 echo=1', 'STOP-REPLY result=1'])
host('drain-stdout-not-regular', BASE + f'drain token={TOKEN}\n' + STOP_OK + 'hold\n',
     extra=['-x', 'temporal=no'], stderr_re=MATCHED0,
     daemon_has=['DRAIN-REPLY result=0 echo=1', 'STOP-REPLY result=1'])
host('drain-wrong-session', BASE + f'drain token={TOKEN} csession={"11" * 16}\n' + STOP_OK +
     'hold\n', extra=NOTEMPORAL, stderr_re=MATCHED0,
     daemon_has=['DRAIN-REPLY result=0', 'STOP-REPLY result=1'])
host('drain-gate-released', BASE + f'drain token={TOKEN}\n' + STOP_OK + END_ON_SIGNAL,
     extra=NOTEMPORAL, gate=f'held:{TOKEN}:1', signals=[('STOP-REPLY', signal.SIGINT)],
     stdout='', stderr_re=all_of(MATCHED0, RECONNECTING),
     daemon_has=['DRAIN-REPLY result=0', 'STOP-REPLY result=0'])
host('drain-reply-lost-reconnects', BASE + f'drain token={TOKEN}\n' + STOP_OK + 'hold\n',
     faults='send:1:32', stderr_re=all_of(MATCHED0, RECONNECTING + RECONNECTED),
     daemon_has=['DRAIN-REPLY-FAILED', 'REGISTERED conn=3', 'STOP-REPLY result=1'])
host('header-reconnect', BASE + 'close\nsend-elf base\nsleep 200\n' + STOP_OK + 'hold\n',
     stderr_re=all_of(MATCHED0, RECONNECTING + RECONNECTED),
     daemon_has=['REGISTERED conn=3', 'STOP-REPLY result=1'])
host('frame-truncated-reconnects', 'wait-elf 1\nsend-elf base headeronly=1\nclose\n'
     + BASE[11:] + STOP_OK + 'hold\n',
     stderr_re=RECONNECTING + RECONNECTED + MATCHED0, daemon_has=['STOP-REPLY result=1'])
host('unparsable-elf-ignored', 'wait-elf 1\nsend-elf garbage\n' + BASE[11:] + STOP_OK + 'hold\n',
     stderr_re='(?s).*' + MATCHED0, daemon_has=['STOP-REPLY result=1'])
host('augment-second-program', BASE + 'send-elf base\nwait-log {d}/shim.log AUGMENT\n'
     'sleep 100\n' + STOP_OK + 'hold\n',
     stderr_re=MATCHED0 + r'dtrace: augmented with probes from \([0-9a-f]+\) 0\n',
     log_has=['AUGMENT vmid 0'], daemon_has=['STOP-REPLY result=1'])
# Execution failures interrupt the consumer by themselves; the daemon then
# closes and the receiver's reconnect loop observes the interrupt.
host('augment-fails', BASE + 'send-elf base\nwait-log {d}/shim.log AUGMENT\nsleep 100\n'
     'close\n', model='fail=AUGMENT:0:5',
     stdout='\n', stderr_re=all_of(MATCHED0, 'failed to augment tracing: Input/output error',
                                    RECONNECTING))
host('options-update-fails', BASE + 'send-elf base\nhold\n',
     api_faults='dtrace_hypertrace_options_update:1:5', status=1, stdout_re='.*',
     stderr_re=MATCHED0 + r'dtrace: augmented with probes from \([0-9a-f]+\) 0\n'
     'dtrace: failed to load options\n')
host('enable-fails', 'wait-elf 1\nsend-elf base\nwait-log {d}/shim.log failed errno 5\n'
     'close\n', model='fail=ENABLE:0:5',
     stderr_re=all_of('failed to enable program: Input/output error', RECONNECTING))
host('worker-thread-fails', BASE + 'sleep 100\nclose\n', faults='pthread_create:4:35',
     stderr_re=MATCHED0 + 'failed to start tracing worker: Resource temporarily '
     'unavailable\n' + RECONNECTING)
host('interrupt-writes-benchmarks', BASE + END_ON_SIGNAL, signals=[('STEP wait-file',
     signal.SIGINT)], stdout='\n\n', stderr_re=all_of(MATCHED0, RECONNECTING))
host('no-daemon', None, status=1, stderr='dtrace: failed to open rx_sock: Connection refused\n')
host('registration-refused', 'reg-ack 0\n', status=1,
     stderr='dtrace: failed to bind HyperTrace consumer program: Protocol error\n')
host('readdata-unreachable', 'drop-conn 2\nhold\n', status=1,
     stderr='dtrace: failed to open wx_sock: Connection reset by peer\n')
host('base-send-refused', 'frame-ack 1 1 0\nhold\n', status=1,
     stderr='dtrace: failed to dtrace_send_elf(): Protocol error\n')
host('handle-identity-fails', 'hold\n', model='hid_mode=5', status=1,
     stderr_re='dtrace: cannot identify HyperTrace DTrace handle: .+\n')
host('digest-fails', 'hold\n', api_faults='dtrace_program_compiled_digest:1:5', status=1,
     stderr='dtrace: failed to identify compiled HyperTrace program: Input/output error\n')
host('reaper-fails', 'hold\n', faults='procctl:1:1', status=1,
     stderr='dtrace: cannot establish collector descendant ownership: '
     'Operation not permitted\n')
host('reaper-status-fails', 'hold\n', faults='procctl:2:3', status=1,
     stderr='dtrace: cannot establish collector descendant ownership: No such process\n')
host('mkstemp-fails', 'hold\n', faults='mkstemp:1:24', status=1,
     stderr='dtrace: failed to mkstemp(): Too many open files\n')
host('elf-create-fails', 'hold\n', api_faults='dtrace_elf_create:1:2', status=1,
     stderr='dtrace: failed to create elf file: ELF Creation failed: \n')
host('fsync-fails', 'hold\n', faults='fsync:1:5', status=1,
     stderr='dtrace: failed to sync file: Input/output error\n')
host('lseek-fails', 'hold\n', faults='lseek:1:5', status=1,
     stderr='dtrace: lseek() failed: Input/output error\n')
host('argument-allocation-fails', 'hold\n', faults='malloc:1:12', status=1,
     stderr='dtrace: failed to malloc dtd_arg: Cannot allocate memory\n')
host('reporter-thread-fails', 'hold\n', faults='pthread_create:2:35', status=1,
     stderr='dtrace: failed to create g_executiontd: Resource temporarily unavailable\n')
host('receiver-thread-fails', 'hold\n', faults='pthread_create:3:35', status=1,
     stderr='dtrace: failed to create g_dtracedtd: Resource temporarily unavailable\n')
host('verbose-dumps', BASE + STOP_OK + 'hold\n', extra=['-v', '-v'],
     stderr_has=['Initial program:\n', 'Processing new program from: \n'],
     daemon_has=['STOP-REPLY result=1'])
host('session-requires-one-program', 'hold\n',
     extra=['-x', 'hypertrace_session_file={d}/session'], prog=PROG + ['-n', 'END {}'],
     status=1, stderr='dtrace: HyperTrace consumer session requires one DTrace program\n')
host('session-file-missing', 'hold\n', extra=['-x', 'hypertrace_session_file={d}/session'],
     status=1, stderr='dtrace: cannot load exclusive HyperTrace consumer session: '
     'No such file or directory\n')


# Host/guest loop: the guest is the same real binary run with -Y on the
# derived program the host published; its outbound response is returned to the
# host as the guest's reply.  Both processes run under the shim and model.
def guest_runner(args=('-r',), script='', name='derived.elf', response='response.elf',
                 guest_status=(0,), stop_guest=True, expect_installed=True,
                 target='guest', direction='outbound'):
    def run(ctx, d, host_env, deadline):
        import hashlib
        errors = []
        while not (d/name).exists():
            if time.monotonic() > deadline:
                return ['derived program never published']
            time.sleep(0.02)
        gd = d/'guest'
        gd.mkdir(exist_ok=True)
        sock = ctx.sockdir/('g' + hashlib.sha1(str(d).encode()).hexdigest()[:12] + '.sock')
        (gd/'daemon.script').write_text(f'dump-dir {gd}\n')
        daemon = subprocess.Popen([str(ctx.harness['daemon']), str(sock), str(gd/'daemon.script'),
                                   str(gd/'daemon.log')], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        wait_marker([gd/'daemon.log'], 'LISTENING', time.monotonic() + 10)
        env = {k: v for k, v in host_env.items() if k not in
               ('CLI_FAULTS', 'CLI_API_FAULTS', 'CLI_GATE', 'CLI_CLOCK', 'CLI_MODEL')}
        (gd/'tmp').mkdir(exist_ok=True)
        env.update(CLI_SHIM_LOG=str(gd/'shim.log'), CLI_DTRACED_SOCK=str(sock), TMPDIR=str(gd/'tmp'),
                   CLI_SCRIPT=script, CLI_OPEN='model',
                   LLVM_PROFILE_FILE=str(d/'profiles'/'guest-%p-%m.profraw'))
        guest = subprocess.Popen([str(ctx.binary), '-x', 'switchrate=10ms', *args, '-Y',
                                  f'{d/name},{target}'], cwd=gd, env=env,
                                 stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        dumps = []
        while time.monotonic() < deadline and guest.poll() is None and not dumps:
            dumps = sorted(gd.glob(f'elf-*-{direction}.bin'))
            time.sleep(0.02)
        dumps = dumps or sorted(gd.glob(f'elf-*-{direction}.bin'))
        if stop_guest and guest.poll() is None:
            wait_marker([gd/'shim.log'], 'ROUND 1', time.monotonic() + 10)
            guest.send_signal(signal.SIGINT)
        try:
            out, err = guest.communicate(timeout=max(1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            guest.kill()
            out, err = guest.communicate()
            errors.append('guest timeout')
        daemon.terminate()
        daemon.wait()
        (gd/'stdout.txt').write_bytes(out)
        (gd/'stderr.txt').write_bytes(err)
        errors.extend(leftover_tmp(gd/'tmp', 'guest'))
        if guest.returncode not in guest_status:
            errors.append(f'guest status {guest.returncode}: {err[-600:]!r}')
        text = err.decode(errors='replace')
        for frag in ('dtrace: link_elf(', f'dtrace: send_elf({gd}/tmp/dtrace-process-elf.'):
            if frag not in text:
                errors.append(f'guest stderr lacks {frag!r}')
        if expect_installed and 'process_elf_hypertrace(): matched' not in text:
            errors.append('guest did not install the derived program')
        if not dumps:
            errors.append('guest sent no response')
            return errors
        data = dumps[0].read_bytes()
        if data[:4] != b'\x7fELF':
            data = data[24:]
        if data[:4] != b'\x7fELF':
            errors.append('guest response is not an ELF object')
        tmp = d/(response + '.tmp')
        tmp.write_bytes(data)
        tmp.rename(d/response)
        return errors
    return run


IDENT = 'send-elf base vmid=3 epoch=9 name=vm3 delivery=5\n'
LOOP = ('wait-elf 1\n' + IDENT + 'expect-ack\nwait-elf 2\nsave-elf derived {d}/derived.elf\n'
        'wait-file {d}/response.elf\nsend-elf file:{d}/response.elf vmid=3 epoch=9 name=vm3\n'
        'wait-log {d}/shim.log GO\n')
MATCHED3 = r'dtrace: matched \d+ probes? \([0-9a-f]+\) from 3\n'
host('loop-identified-stop', LOOP + 'sleep 200\n' + STOP_OK + 'hold\n', during=guest_runner(),
     stderr_re=MATCHED3,
     daemon_has=['ACK delivery=5 vmid=3 epoch=9 outcome=2', 'ELF conn=2 location=outbound',
                 'EXEC conn=', 'delivery=5 vmid=3 outcome=2 session_ok=1',
                 'STOP-REPLY result=1', 'COMMIT'],
     log_has=['VPROBE_CREATE vmid 3 epoch 9', 'ENABLE-GUEST vmid 3 epoch 9'])
# SIGINT with the daemon connection intact: the receiver leaves after its
# 10 s header deadline, then the guest program is revoked with KILL.
host('loop-identified-interrupt-kills-guest', LOOP + 'hold\n', during=guest_runner(),
     signals=[('EXEC conn=', signal.SIGINT)], stdout='\n\n', stderr_re=MATCHED3,
     daemon_has=['ACK delivery=5 vmid=3 epoch=9 outcome=2', 'KILL conn=2 pid=',
                 'vmid=3 epoch=9'], timeout=90)
# If the daemon connection is lost during shutdown the revocation cannot be
# sent (design limitation, reported); the failure is now reported with EBADF.
host('loop-reconnect-loses-kill', LOOP + END_ON_SIGNAL, during=guest_runner(),
     signals=[('EXEC conn=', signal.SIGINT)], stdout='\n\n',
     stderr_re=all_of(MATCHED3, RECONNECTING, 'file descriptor must be != -1\n',
                      r'send_kill\(\) failed with: Bad file descriptor\n'),
     daemon_lacks=['KILL conn='])
host('loop-unidentified', 'wait-elf 1\nsend-elf base vmid=3 epoch=9 name=vm3\nwait-elf 2\n'
     'save-elf derived {d}/derived.elf\nwait-file {d}/response.elf\n'
     'send-elf file:{d}/response.elf vmid=3 epoch=9 name=vm3\nwait-log {d}/shim.log GO\n'
     'sleep 200\n' + STOP_OK + 'hold\n', during=guest_runner(), stderr_re=MATCHED3,
     daemon_has=['ELF conn=2 location=outbound', 'STOP-REPLY result=1'],
     daemon_lacks=['ACK delivery', 'EXEC conn='])


# The host flow end to end for a program the host must link (a global
# variable: TYPECAST and type-checked loads/stores).  dtraced routes the
# consumer's base ELF to the traced machine's dtrace -Y <base>,host, which
# links it (process_elf_hypertrace()) and publishes it inbound; the consumer
# verifies that linked program and runs it.  The original rejection
# ("typecast was not set to nop") came from receiving an unlinked program.
host('roundtrip-global-variable', 'wait-elf 1\nsave-elf base {d}/base.elf\n'
     'wait-file {d}/linked.elf\nsend-elf file:{d}/linked.elf\nwait-log {d}/shim.log GO\n'
     'sleep 200\n' + STOP_OK + 'hold\n',
     prog=['-n', 'dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }'],
     script='go 0 dtrace:::END n:1',
     during=guest_runner(args=(), name='base.elf', response='linked.elf', target='host',
                         direction='inbound', stop_guest=False, expect_installed=False),
     stdout=HDR + probe(0, 2, '', 'END') + t4(1) + '\n',
     stderr_re=r'dtrace: matched 2 probes \([0-9a-f]+\) from 0\n',
     daemon_has=['ELF conn=2 location=base', 'STOP-REPLY result=1'])


# Identified derived-program replay, publication failures and receipts.
GEN = 'wait-elf 1\n' + IDENT + 'expect-ack\nwait-elf 2\n'
host('replay-identical-delivery', GEN + IDENT + 'expect-ack\nwait-elf 3\n'
     'save-elf derived {d}/derived.elf\nwait-file {d}/response.elf\n'
     'send-elf file:{d}/response.elf vmid=3 epoch=9 name=vm3\nwait-log {d}/shim.log GO\n'
     'sleep 300\n' + STOP_OK + 'hold\n', during=guest_runner(), stderr_re=MATCHED3,
     daemon_has=['ELF conn=2 location=outbound bytes=', 'STOP-REPLY result=1'],
     check=lambda d, out, err, slog, dlog: [] if dlog.count(
         'ACK delivery=5 vmid=3 epoch=9 outcome=2') == 2 and dlog.count(
         'location=outbound') == 2 and dlog.count('EXEC conn=') == 2
     else ['expected two derived ACKs, publications and receipts'])
host('replay-different-bytes', GEN + 'send-elf base vmid=3 epoch=9 name=vm4 delivery=5\n'
     'expect-ack\n' + STOP_OK + 'hold\n', gate=GATE,
     stderr='dtrace: failed to replay derived ELF: Protocol error\n',
     daemon_has=['ACK delivery=5 vmid=3 epoch=9 outcome=0'])
host('replay-after-execution', LOOP + IDENT + 'expect-ack\nsleep 300\n' + STOP_OK + 'hold\n',
     during=guest_runner(), stderr_re=MATCHED3,
     check=lambda d, out, err, slog, dlog: [] if dlog.count(
         'ACK delivery=5 vmid=3 epoch=9 outcome=2') == 2 and dlog.count(
         'location=outbound') == 2 else ['expected the executed program to be replayed'])
host('derived-send-refused-reconnects', 'frame-ack 1 2 0\nwait-elf 1\n' + IDENT +
     'expect-ack\n' + IDENT + 'expect-ack\nwait-elf 3\n' + STOP_OK + 'hold\n',
     stderr_re=all_of('failed to dtrace_send_elf\\(\\): Protocol error\n',
                      RECONNECTING + RECONNECTED),
     daemon_has=['ACK-READ-FAILED', 'REGISTERED conn=3',
                 'ACK delivery=5 vmid=3 epoch=9 outcome=2'])
host('unidentified-async-send-refused', 'frame-ack 1 2 0\nwait-elf 1\n'
     'send-elf base vmid=3 epoch=9 name=vm3\nwait-elf 2\nsleep 300\n' + STOP_OK + 'hold\n',
     stderr='dtrace: asynchronous ELF send failed: Protocol error\n',
     daemon_has=['STOP-REPLY result=1'])
host('guest-generation-fails', 'wait-elf 1\n' + IDENT + 'expect-ack\n' + STOP_OK + 'hold\n',
     api_faults='dtrace_vprog_from:1:5',
     stderr='failed to create guest forwarding program from vm3 (3)\n',
     daemon_has=['ACK delivery=5 vmid=3 epoch=9 outcome=0'])
host('guest-generation-verbose', GEN + STOP_OK + 'hold\n', extra=['-v', '-v'],
     stderr_has=['GENERATED PROGRAM:\n'], daemon_has=['outcome=2'])
for label, faults, api, message in (
        ('mkstemp', 'mkstemp:3:24', None, 'failed to create guest ELF file: Too many open files\n'),
        ('elf-create', None, 'dtrace_elf_create:2:2', 'failed to create guest ELF: '
         'ELF Creation failed: \n'),
        ('fsync', 'fsync:3:5', None, 'failed to sync guest ELF: Input/output error\n'),
        ('lseek', 'lseek:2:1', None, 'failed to rewind guest ELF: Operation not permitted\n')):
    host('guest-' + label + '-fails', 'wait-elf 1\n' + IDENT + 'expect-ack\n' + STOP_OK +
         'hold\n', faults=faults, api_faults=api, stderr=message,
         daemon_has=['ACK delivery=5 vmid=3 epoch=9 outcome=0'])
host('received-elf-mkstemp-aborts', 'wait-elf 1\nsend-elf base\nhold\n', faults='mkstemp:2:24',
     status=134, allow_abort=True, log_has=['ABORT'],
     stderr='dtrace: failed to create a temporary file (Too many open files): '
     'Too many open files\n')
host('received-elf-fsync-aborts', 'wait-elf 1\nsend-elf base\nhold\n', faults='fsync:2:5',
     status=134, allow_abort=True, log_has=['ABORT'],
     stderr='dtrace: failed to sync file: Input/output error\n')
host('received-elf-write-interrupted', BASE + STOP_OK + 'hold\n', faults='write:1:1',
     stderr_re=MATCHED0, daemon_has=['STOP-REPLY result=1'])
host('received-elf-write-fails', 'wait-elf 1\nsend-elf base\nhold\n', faults='write:1:5',
     status=1, stderr='dtrace: failed to write received ELF file: Input/output error\n')
host('host-verify-fails', 'wait-elf 1\nsend-elf base\n' + STOP_OK + 'hold\n',
     api_faults='dt_prog_verify:1:0', stderr='failed to verify DIF from host (0)\n',
     daemon_has=['STOP-REPLY result=1'])
host('guest-response-verify-fails', LOOP.replace('wait-log {d}/shim.log GO\n', '') + 'sleep 300\n'
     + STOP_OK + 'hold\n', during=guest_runner(), api_faults='dt_prog_verify:2:0',
     stderr='failed to verify guest response from vm3 (3)\n', daemon_has=['STOP-REPLY result=1'])
host('response-for-unknown-program', GEN + 'send-elf file:{fx}/derived.elf vmid=3 epoch=9 '
     'name=vm3 delivery=7\nexpect-ack\nsleep 200\n' + STOP_OK + 'hold\n',
     stderr='', daemon_has=['ACK delivery=7 vmid=3 epoch=9 outcome=1',
                            'EXEC conn=', 'delivery=7 vmid=3 outcome=1'])
# Host-program lookup compares stored dp_ident with the incoming dp_srcident,
# so an unidentified duplicate is a new program and derives a second guest
# program (observed behavior, reported).
host('duplicate-pending-host-program', 'wait-elf 1\nsend-elf base vmid=3 epoch=9 name=vm3\n'
     'wait-elf 2\nsend-elf base vmid=3 epoch=9 name=vm3\nwait-elf 3\n' + STOP_OK + 'hold\n',
     stderr='', daemon_has=['STOP-REPLY result=1'],
     check=lambda d, out, err, slog, dlog: [] if dlog.count('location=outbound') == 2
     else ['expected two derived guest programs'])
host('notice-allocation-fails', 'wait-elf 1\n' + IDENT + 'expect-ack\nhold\n',
     faults='calloc:1:12', status=1,
     stderr='dtrace: failed to allocate identified execution notice: Cannot allocate memory\n')
host('receipt-retried', LOOP + 'frame-ack 16 1 0\nsleep 500\n' + STOP_OK + 'hold\n',
     during=guest_runner(), stderr_re=MATCHED3,
     check=lambda d, out, err, slog, dlog: [] if dlog.count('EXEC conn=') == 2
     else ['expected one rejected and one accepted receipt'])
host('receipt-interrupted', LOOP.replace('wait-log {d}/shim.log GO\n', '') +
     'frame-ack 16 0 0\n' + END_ON_SIGNAL, during=guest_runner(),
     signals=[('EXEC conn=', signal.SIGINT)], stdout='\n\n',
     stderr_re=all_of(MATCHED3, 'dtrace: host execution receipt failed: '
                      'Interrupted system call\n'))
host('vprobe-creation-fails', LOOP.replace('wait-log {d}/shim.log GO\n',
     'wait-log {d}/shim.log failed errno 5\nsleep 100\nclose\n'), during=guest_runner(),
     model='fail=VPROBE_CREATE:0:5', stdout='',
     stderr_re=all_of('failed to create vprobes: Input/output error\n', RECONNECTING),
     daemon_lacks=['EXEC conn='])


def session_file(mode=0o600, body=None, links=1, kind='file'):
    import hashlib

    def setup(d):
        session = bytes(range(1, 17))
        wire = b'HCS1' + session
        data = wire + hashlib.sha256(wire).digest() if body is None else body
        target = d/'session'
        if kind == 'dir':
            target.mkdir()
            return
        if kind == 'symlink':
            (d/'real').write_bytes(data)
            (d/'real').chmod(mode)
            target.symlink_to(d/'real')
            return
        target.write_bytes(data)
        target.chmod(mode)
        if links > 1:
            (d/'session.link').hardlink_to(target)
    return setup


SESSION = ['-x', 'hypertrace_session_file={d}/session']
host('session-file-loaded', BASE + STOP_OK + 'hold\n', extra=SESSION, setup=session_file(),
     stderr_re=MATCHED0, daemon_has=['session=0102030405060708090a0b0c0d0e0f10',
                                     'STOP-REPLY result=1'])
import hashlib as _hashlib
for label, kw, message in (
        ('mode', {'mode': 0o644}, 'Protocol error'),
        ('links', {'links': 2}, 'Protocol error'),
        ('directory', {'kind': 'dir'}, 'Protocol error'),
        # FreeBSD reports O_NOFOLLOW on a symbolic link as EMLINK.
        ('symlink', {'kind': 'symlink'}, 'Too many links'),
        ('size', {'body': b'HCS1' + bytes(10)}, 'Protocol error'),
        ('magic', {'body': b'XXXX' + bytes(range(1, 17)) + bytes(32)}, 'Protocol error'),
        ('digest', {'body': b'HCS1' + bytes(range(1, 17)) + bytes(32)}, 'Protocol error'),
        ('zero', {'body': b'HCS1' + bytes(16) + _hashlib.sha256(b'HCS1' + bytes(16)).digest()},
         'Protocol error')):
    host('session-file-' + label, 'hold\n', extra=SESSION, setup=session_file(**kw), status=1,
         stderr='dtrace: cannot load exclusive HyperTrace consumer session: ' + message + '\n')
host('session-file-fstat-fails', 'hold\n', extra=SESSION, setup=session_file(),
     faults='fstat:1:5', status=1,
     stderr='dtrace: cannot load exclusive HyperTrace consumer session: Input/output error\n')
host('session-file-read-fails', 'hold\n', extra=SESSION, setup=session_file(),
     faults='pread:1:5', status=1,
     stderr='dtrace: cannot load exclusive HyperTrace consumer session: Input/output error\n')
host('session-file-short-read', 'hold\n', extra=SESSION, setup=session_file(),
     faults='pread:1:1', status=1,
     stderr='dtrace: cannot load exclusive HyperTrace consumer session: Protocol error\n')
host('session-file-locked', 'hold\n', extra=SESSION, setup=session_file(),
     faults='flock:1:35', status=1, stderr='dtrace: cannot load exclusive HyperTrace '
     'consumer session: Resource temporarily unavailable\n')
# system() launches a descendant; quiescence reaps it before proving the stop.
host('stop-reaps-descendants', 'wait-elf 1\nsend-elf base\nwait-log {d}/shim.log GO\n'
     'sleep 300\n' + STOP_OK + 'hold\n', prog=['-w', '-n', 'BEGIN { system("/usr/bin/true"); }'],
     script='go 0 dtrace:::BEGIN n:0', stderr_re='(?s).*' + MATCHED0 + '.*', stdout_re='.*',
     daemon_has=['STOP-REPLY result=1', 'COMMIT'])
host('stop-reaper-query-fails', BASE + STOP_OK + 'hold\n', faults='procctl:3:5',
     stderr_re=MATCHED0, daemon_has=['STOP-REPLY result=0'], daemon_lacks=['COMMIT'])


# Fixtures produced by real runs before the parallel cases: a derived guest
# program (DT_PROG_EXEC) published by a host, and an ELF from -E -e.
FIXTURES = []


def fixture(name, args, **kw):
    kw['name'] = name
    kw['args'] = args
    FIXTURES.append(kw)


def elf_path_check(target):
    def check(d, stdout, stderr, shimlog, daemonlog):
        path = Path(stdout.strip())
        # Created in the case's TMPDIR, which dtrace(1) honours.
        tmpdir = '/tmp' if os.environ.get('CLI_NO_TMPDIR') else str(d/'tmp')
        if not re.fullmatch(re.escape(tmpdir) + r'/dtrace-execprog\.\w{12}', str(path)) \
                or not path.exists():
            return [f'no ELF path printed: {stdout!r}']
        if path.read_bytes()[:4] != b'\x7fELF':
            return ['printed path is not an ELF object']
        shutil.move(str(path), str(d/target))
        return []
    return check


fixture('fixture-base-elf', ['-E', '-e', '-n', 'BEGIN { trace(1); exit(0); }'], open='nodev',
        stderr='', check=elf_path_check('base.elf'), output='base.elf')
fixture('fixture-modref-elf', ['-E', '-e', '-n', 'dtrace:::BEGIN { x = 1; } dtrace:::END '
        '{ trace(x); }'], open='nodev', stderr='', check=elf_path_check('modref.elf'),
        output='modref.elf')
fixture('fixture-derived-elf', HOST + PROG, gate=GATE, stdout='', stderr_re=r'(?s).*',
        daemon='wait-elf 1\nsend-elf base vmid=3 epoch=9 name=vm3\nwait-elf 2\n'
        'save-elf derived {d}/derived.elf\n' + STOP_OK + 'hold\n', output='derived.elf')


def fx(name):
    return '{fx}/' + name


def program_srcident(ctx, path):
    """The dt_elf_prog_t source identifier stored in .dtrace_prog."""
    listing = subprocess.run(['/usr/bin/readelf', '-SW', str(path)], capture_output=True,
                             text=True, check=True).stdout
    row = next(l for l in listing.splitlines() if '.dtrace_prog ' in l)
    offset = int(row.split('.dtrace_prog')[1].split()[2], 16)
    data = Path(path).read_bytes()
    start = offset + ctx.harness['srcident_offset']
    return data[start:start + ctx.harness['identlen']]


def idents_stdin(count=1, bad=False):
    """Build the -N handshake at run time from the fixture's identifier."""
    def make(ctx):
        ident = program_srcident(ctx, ctx.out/'fixtures'/'derived.elf')
        if bad:
            ident = bytes(b ^ 0xff for b in ident)
        return count.to_bytes(8, 'little') + ident * count
    return make


# Guest-side processing of a derived program (-Y FILE[,host|guest]).
def guest(name, extra, **kw):
    kw.setdefault('daemon', 'dump-dir {d}\n')
    case('guest-' + name, ['-x', 'switchrate=10ms'] + extra, **kw)


def response_check(installed_exec=True):
    def check(d, stdout, stderr, shimlog, daemonlog):
        dumps = sorted(d.glob('elf-*.bin'))
        if not dumps:
            return ['no ELF reached the daemon']
        return []
    return check


GUEST_DONE = ('dtrace: link_elf({fx}/derived.elf)\ndtrace_elf_parse() call\n')
guest('install-root-srcident', ['-r', '-Y', fx('derived.elf') + ',guest'],
      script='go 0 dtrace:::BEGIN n:1', signals=[('ROUND 2', signal.SIGINT)],
      stdout_re='.*', stderr_re=r'dtrace: link_elf\(.*/derived\.elf\)\ndtrace_elf_parse\(\) call\n'
      r'prog = 0x[0-9a-f]+\nprog_exec = 1\n'
      r'dtrace: process_elf_hypertrace\(\): matched 1 probe\n'
      r'dtrace: send_elf\(.*/tmp/dtrace-process-elf\.\w{12}\)\n',
      daemon_has=['location=outbound', 'ident=0'], check=response_check())
guest('install-host-inbound', ['-r', '-Y', fx('derived.elf') + ',host'],
      signals=[('ROUND 2', signal.SIGINT)], stdout_re='.*',
      stderr_has=['process_elf_hypertrace(): matched 1 probe\n'],
      daemon_has=['location=inbound', 'ident=0'])
guest('not-installed-sends-exec', ['-Y', fx('derived.elf')], stdout='',
      stderr_re=r'(?s).*prog_exec = 1\ndtrace: send_elf\(.*\)\n',
      daemon_has=['location=outbound', 'ident=0'], log_lacks=['GO'])
guest('base-program-sends-ident', ['-Y', fx('base.elf') + ',guest'], stdout='',
      stderr_re=r'(?s).*prog_exec = 0\ndtrace: send_elf\(.*\)\n',
      daemon_has=['location=outbound', 'ident=1'])
guest('verbose', ['-v', '-v', '-Y', fx('derived.elf')], stdout='',
      stderr_has=['Unrelocated program:\n', 'ECBs from an unrelocated program:\n',
                  'Relocated program:\n', 'ECBs from a relocated program:\n'])
guest('identifiers-launch-report', ['-N', '-Y', fx('derived.elf') + ',guest'],
      stdin=idents_stdin(), stdout_socket=True,
      env={'HYPERTRACE_LAUNCH_REPORT': '1'}, script='go 0 dtrace:::BEGIN n:1',
      signals=[('ROUND 2', signal.SIGINT)], stdout_re='(?s).*',
      stderr_has=['process_elf_hypertrace(): matched 1 probe\n'],
      check=lambda d, out, *a: launch_report_check(d, out))
guest('identifiers-unknown', ['-N', '-Y', fx('derived.elf')], stdin=idents_stdin(bad=True),
      status=1, stdout_re='.*', stderr_re=r'(?s).*dtrace: failed to parse the ELF file .*: '
      r'Identifier not found: \n')
def launch_report_check(d, out):
    # dtraced_launch_result_t on the wire: u64 magic, installed byte, 7
    # reserved, 128-byte source identifier (DTRACED_LAUNCH_WIRE_SIZE 144).
    raw = out.encode('latin-1')
    at = raw.find((0x3154534e495448).to_bytes(8, 'little'))
    if at < 0 or len(raw) < at + 144:
        return [f'no launch report on stdout: {raw[:64]!r}']
    if raw[at + 8] != 1 or raw[at + 9:at + 16] != bytes(7):
        return ['launch report does not say installed']
    return []


guest('identifiers-short', ['-N', '-Y', fx('derived.elf')], stdin=b'\x01\x00', status=1,
      stdout='', stderr='dtrace: failed to read complete identifier handshake: Broken pipe\n')
guest('identifiers-zero-count', ['-N', '-Y', fx('derived.elf')], stdin=bytes(8), status=1,
      stdout='', stderr='dtrace: failed to read complete identifier handshake: '
      'Invalid argument\n')
guest('identifiers-deadline-fails', ['-N', '-Y', fx('derived.elf')], stdin=bytes(8),
      faults='clock_gettime:1:22', status=1, stdout='',
      stderr='dtrace: failed to set identifier deadline: Invalid argument\n')
guest('identifiers-compile-fails', ['-N', '-Y', fx('derived.elf')],
      stdin=idents_stdin(),
      api_faults='dtrace_compile_idents_set:1:5', status=1, stdout='',
      stderr='dtrace: failed to compile identifiers: Input/output error\n')
guest('report-deadline-fails', ['-N', '-Y', fx('derived.elf')],
      stdin=idents_stdin(), env={'HYPERTRACE_LAUNCH_REPORT': '1'},
      faults='clock_gettime:4:22', status=1, stdout_re='.*',
      stderr_re=r'(?s).*dtrace: failed to set guest report deadline: Invalid argument\n')
guest('unexpected-target', ['-Y', fx('derived.elf') + ',sideways'], status=1, stdout='',
      stderr='dtrace: unexpected string in -Y: sideways\n')
guest('untokenizable', ['-Y', ','], status=1, stdout='', stderr='dtrace: failed to tokenize ,\n')
guest('missing-file', ['-Y', '{d}/absent.elf'], status=1, stdout='',
      stderr='dtrace: link_elf({d}/absent.elf)\ndtrace: failed to open {d}/absent.elf with '
      'No such file or directory\n')
guest('unparsable-file', ['-Y', '{d}/bad.elf'], inputs={'bad.elf': b'\x7fELF' + b'\0' * 60},
      status=1, stdout='', stderr_re=r'(?s).*dtrace: failed to parse the ELF file .*bad\.elf: .*\n')
guest('relocation-fails', ['-Y', fx('derived.elf')], api_faults='hypertrace_link:1:9',
      status=1, stdout='', stderr_re=r'(?s).*dtrace: Failed to apply relocations: '
      r'Linking error: injected\n')
guest('enable-fails', ['-r', '-Y', fx('derived.elf')], model='fail=ENABLE:0:5', status=1,
      stdout='', stderr_re=r'(?s).*dtrace: failed to enable program: .+\n')
guest('worker-fails', ['-r', '-Y', fx('derived.elf')], faults='pthread_create:2:35',
      status=1, stdout_re='.*', stderr_re=r'(?s).*dtrace: failed to start tracing worker: '
      'Resource temporarily unavailable\n')
guest('no-daemon', ['-Y', fx('derived.elf')], daemon=None, status=1, stdout='',
      stderr_re=r'(?s).*dtrace: failed to open dtraced: Connection refused\n')
guest('mkstemp-fails', ['-Y', fx('derived.elf')], faults='mkstemp:1:24', status=1, stdout='',
      stderr_re=r'(?s).*dtrace: mkstemp\(\) failed \(.*/tmp/dtrace-process-elf\.X{12}\): '
      'Too many open files\n')
guest('elf-create-fails', ['-Y', fx('derived.elf')], api_faults='dtrace_elf_create:1:2',
      status=1, stdout='', stderr_re=r'(?s).*dtrace: failed to create ELF file: '
      'ELF Creation failed: \n')
guest('fsync-fails', ['-Y', fx('derived.elf')], faults='fsync:1:5', status=1, stdout='',
      stderr_re=r'(?s).*dtrace: failed to sync file: Input/output error\n')
guest('lseek-fails', ['-Y', fx('derived.elf')], faults='lseek:1:5', status=1, stdout='',
      stderr_re=r'(?s).*dtrace: lseek\(\) failed: Input/output error\n')
guest('send-refused', ['-Y', fx('derived.elf')], daemon='frame-ack 1 0 0\n', status=1,
      stdout='', stderr_re=r'(?s).*dtrace: failed to dtrace_send_elf\(\): Protocol error\n')
guest('report-write-fails', ['-N', '-Y', fx('derived.elf')],
      stdin=idents_stdin(), env={'HYPERTRACE_LAUNCH_REPORT': '1'}, stdout_socket=True,
      faults='send:1:32', status=1, stdout_re='(?s).*',
      stderr_re=r'(?s).*dtrace: failed to report guest installation: Broken pipe\n')

# Running a provided ELF (-y): a program marked for execution is enabled, traced
# and consumed to its end, and the command exits; it never continues into the
# host consumer path (no rx_sock connection).  An ELF not marked for execution
# is an error.
case('elfrun-exec', FAST + ['-y', fx('derived.elf')],
     signals=[('ROUND 2', signal.SIGINT)], status=0,
     stdout_re='.*', stderr_re=r'(?s)dtrace_elf_parse\(\) call\nprog = 0x[0-9a-f]+\n'
     r'prog_exec = 1\ndtrace: matched 1 probe\n')
case('elfrun-not-executed', FAST + ['-v', '-y', fx('base.elf')], status=1, stdout='',
     stderr_re=r'(?s).*prog_exec = 0\nnot executing .*base\.elf\n'
     r'dtrace: .*base\.elf: program is not marked for execution\n')
case('elfrun-missing', ['-y', '{d}/absent.elf'], status=1, stdout='',
     stderr='dtrace: failed to open {d}/absent.elf with No such file or directory\n')

# ELF creation for inspection (-E -e).
case('elf-create-print-path', ['-E', '-e', '-n', 'BEGIN { trace(1); }'], open='nodev',
     stderr='', check=elf_path_check('created.elf'))
case('elf-create-mkstemp-fails', ['-E', '-e', '-n', 'BEGIN { trace(1); }'], open='nodev',
     faults='mkstemp:1:24', status=1, stdout='',
     stderr='dtrace: failed to mkstemp(): Too many open files\n')
case('elf-create-fails', ['-E', '-e', '-n', 'BEGIN { trace(1); }'], open='nodev',
     api_faults='dtrace_elf_create:1:2', status=1, stdout='',
     stderr='dtrace: failed to create elf file: ELF Creation failed: \n')

# Ordinary execution: relocation and verification failures.
case('exec-relocation-fails', FAST + ['-n', 'BEGIN { exit(0); }'],
     api_faults='hypertrace_link:1:9', status=1, stdout='',
     stderr='dtrace: failed to apply relocations: Linking error: injected\n')
# A program error found by the type checker (the modeled kernel has no CTF,
# so strlen()'s return type cannot be resolved): libdtrace prints it and
# returns it; dtrace(1) reports the program's error and exits 1, as when
# libdtrace ended the process itself.
case('exec-program-type-error', FAST + ['-n', 'BEGIN { trace(strlen(execname)); }'],
     status=1, stdout='', stderr='strlen(): kernel type information is unavailable\n'
     'dtrace: strlen(): kernel type information is unavailable\n')
case('exec-verify-fails', FAST + ['-n', 'BEGIN { exit(0); }'], api_faults='dt_prog_verify:1:0',
     status=1, stdout='', stderr_re=r'dtrace: failed to verify 0x[0-9a-f]+: .*\n')
case('exec-verbose-stability', FAST + ['-v', '-n', 'BEGIN { exit(0); }'],
     script='go 0 dtrace:::BEGIN n:0', stdout_has=['\nStability attributes for description '
     'BEGIN :\n', '\tMinimum Statement Attributes\n'], stderr_has=[matched('BEGIN ', 1)])
for label, fn, msg in (('err', 'dtrace_handle_err', 'error'),
                       ('drop', 'dtrace_handle_drop', 'drop'),
                       ('proc', 'dtrace_handle_proc', 'proc'),
                       ('setopt', 'dtrace_handle_setopt', 'setopt')):
    case('exec-handler-' + label + '-fails', ['-e', '-n', 'BEGIN {}'], open='nodev',
         api_faults=f'{fn}:1:0', status=1, stdout='',
         stderr_re=f'dtrace: failed to establish {msg} handler: .*\\n')
case('exec-handler-buffered-fails', ['-B', '-e', '-n', 'BEGIN {}'], open='nodev',
     api_faults='dtrace_handle_buffered:1:0', status=1, stdout='',
     stderr_re='dtrace: failed to establish buffered handler: .*\n')
case('header-generation-fails', ['-h', '-s', '{d}/p.d', '-o', '{d}/p.h'],
     inputs={'p.d': 'provider pa { probe x(); };\n'}, api_faults='dtrace_program_header:1:0',
     status=1, stdout='', stderr_re=r"dtrace: failed to create header file .*/p\.h: .*\n")
case('header-close-fails', ['-h', '-s', '{d}/p.d', '-o', '{d}/p.h'],
     inputs={'p.d': 'provider pa { probe x(); };\n'}, faults='fclose:2:28',
     status=1, stdout='', stderr_re=r"dtrace: failed to create header file .*/p\.h: .*\n")
case('anon-dof-fails', ['-A', '-o', '{d}/anon.dof', '-n', 'BEGIN {}'],
     api_faults='dtrace_dof_create:1:0', status=1, stdout='',
     stderr_re="dtrace: failed to create DOF image for 'BEGIN ': .*\\n")
case('anon-close-fails', ['-A', '-o', '{d}/anon.dof', '-n', 'BEGIN {}'], faults='fclose:1:28',
     status=1, stdout='', stderr="dtrace: failed to close output file '{d}/anon.dof': "
     'No space left on device\n')


# Remaining CLI paths: process control, arguments, object models, setup
# failures, typed probe arguments and replay failures.
case('proc-create-and-interrupt', FAST + ['-c', '/bin/sleep 30', '-n', 'BEGIN {}'],
     signals=[('ROUND 2', signal.SIGINT)], stdout_re='.*', stderr_re=r'(?s).*matched 1 probe\n.*')
case('proc-create-empty-command', FAST + ['-c', '', '-n', 'BEGIN {}'], status=1, stdout='',
     stderr_re='dtrace: .+\n')
case('proc-create-fails', FAST + ['-c', '/nonexistent/cmd', '-n', 'BEGIN {}'], status=1,
     stdout='', stderr_re='dtrace: .+\n')
case('proc-grab-invalid-pid', FAST + ['-p', '12x', '-n', 'BEGIN {}'], status=1, stdout='',
     stderr='dtrace: invalid pid: 12x\n')
case('proc-grab-fails', FAST + ['-p', '99999999', '-n', 'BEGIN {}'], status=1, stdout='',
     stderr_re='dtrace: .+\n')
case('proc-argv-allocation-fails', FAST + ['-c', '/bin/sleep 30', '-n', 'BEGIN {}'],
     faults='malloc:1:12', status=1, stdout='',
     stderr='dtrace: failed to allocate memory: Cannot allocate memory\n')
case('macro-argument', ['-e', '-n', 'BEGIN { trace($1); }', '42'], open='nodev', stdout='',
     stderr='')
# -a with no program still starts tracing (dtrace_go() claims anonymous
# state); the model has none to claim, so the consumer runs until stopped.
case('grab-anonymous', FAST + ['-a'], signals=[('ROUND 2', signal.SIGINT)], stdout='\n\n',
     stderr='', log_has=['GO'])
case('libxo-invalid', ['--libxo', 'no-such-style', '-V'], status=2, stdout='',
     stderr_re=r'(?s).*Usage: dtrace.*')
case('script-unreadable', ['-e', '-s', '{d}/s.d'], open='nodev', inputs={'s.d': 'BEGIN {}\n'},
     modes={'s.d': 0}, status=1, stdout='',
     stderr='dtrace: failed to open {d}/s.d: Permission denied\n')
case('script-does-not-compile', ['-e', '-s', '{d}/s.d'], open='nodev',
     inputs={'s.d': 'BEGIN { trace(; }\n'}, status=1, stdout='',
     stderr_re=r'dtrace: failed to compile script .*/s\.d: line 1: syntax error .*\n')
case('list-shared-ecb', ['-l', '-n', 'BEGIN { trace(1); trace(2); }'],
     stdout=LISTHDR + lrow(1), stderr='')
case('info-shared-ecb', ['-e', '-v', '-n', 'BEGIN { trace(1); trace(2); }'],
     stdout_re=r'(?s).*\n:::BEGIN\n(?!.*:::BEGIN\n).*', stderr='')
case('list-typed-arguments', ['-l', '-v', '-n', ENTRY],
     stdout=LISTHDR + lrow(4) + PROBEINFO_NONE.replace(
         '\t\tNone\n', '\t\targs[0]: int\n\t\targs[1]: (unknown)\n'
         '\t\targs[2]: userland char *\n'), stderr='')
case('exec-flowindent-other-probe', FAST + ['-F', '-n', 'BEGIN { exit(0); }'],
     script='go 0 dtrace:::BEGIN n:0',
     stdout='%3s %-41s\n' % ('CPU', 'FUNCTION') + '%3d %-41s \n' % (0, '| :BEGIN') + '\n',
     stderr=matched('BEGIN ', 1))
case('exec-aggregation-print-fails', FAST + ['-n', 'BEGIN { @c = count(); exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 a:0:1 n:0', api_faults='dtrace_aggregate_print:1:5',
     status=1, stdout_re='.*', stderr_re=matched('BEGIN ', 1) +
     'dtrace: failed to print aggregations: .*\n')
case('exec-option-fetch-fails', FAST + ['-n', 'BEGIN { exit(0); }'],
     api_faults='dtrace_getopt:4:5', status=1, stdout='',
     stderr=matched('BEGIN ', 1) + "dtrace: couldn't get option bufsize: Input/output error\n")
case('exec-rate-fetch-fails', FAST + ['-n', 'BEGIN { exit(0); }'],
     api_faults='dtrace_getopt:8:5', status=1, stdout='',
     stderr=matched('BEGIN ', 1) + "dtrace: couldn't get option cleanrate: "
     'Input/output error\n')
case('exec-buffered-string-key', FAST + ['-B', '-n', 'BEGIN { @c["a-long-key"] = count(); '
                                         'exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 s:a-long-key a:0:1 n:0', stderr=matched('BEGIN ', 1),
     stdout_has=['dtrace:          dtrd_offset => ', ' ...)\n'])
# -e with -y links only (nothing traces, so no rounds) and prints the linked
# ELF's path for inspection.
case('exec-run-elf-then-compile-only', FAST + ['-e', '-y', fx('derived.elf')],
     stdout_re='(?s).*', stderr_re=r'(?s).*prog_exec = 1\n.*',
     check=lambda d, out, *a: elf_path_check('printed.elf')(
         d, out.strip().splitlines()[-1] if out.strip() else '', *a))
for n, name in ((1, 'the dtp mutex'), (2, 'pgplistmtx'), (3, 'benchlistmtx')):
    case(f'init-mutex-{n}-fails', ['-e', '-n', 'BEGIN {}'], open='nodev',
         faults=f'pthread_mutex_init:{n}:12', status=1, stdout='',
         stderr=f'dtrace: failed to {"create" if n == 1 else "init"} {name}: '
         'Cannot allocate memory\n')
case('init-cond-fails', ['-e', '-n', 'BEGIN {}'], open='nodev', faults='pthread_cond_init:1:12',
     status=1, stdout='', stderr='dtrace: failed to init pgpcond: Cannot allocate memory\n')
case('signal-thread-create-fails', FAST + ['-n', 'BEGIN { exit(0); }'],
     faults='pthread_create:1:35', status=134, allow_abort=True, log_has=['ABORT'],
     stdout_re='.*', stderr=matched('BEGIN ', 1))
case('signal-wait-fails', FAST + ['-n', ENTRY + ' { trace(arg0); }'], faults='sigwait:1:22',
     status=1, stdout_re='.*', stderr_re=r'(?s).*dtrace: failed to sigwait: '
     r'Invalid argument\n')
for label, fn in (('a', 'grabanon'), ('F', 'flowindent'), ('H', 'cpphdrs'),
                  ('q', 'quiet'), ('w', 'destructive')):
    pass
SETOPT_BASE = 4    # bufsize, aggsize, temporal, strsize precede option parsing
for label, args, msg in (
        ('a', ['-a'], 'failed to set -a'), ('b', ['-b', '4m'], 'failed to set -b 4m'),
        ('D', ['-D', 'X=1'], 'failed to set -D X=1'), ('F', ['-F'], 'failed to set -F'),
        ('H', ['-H'], 'failed to set -H'), ('I', ['-I', '/tmp'], 'failed to set -I /tmp'),
        ('L', ['-L', '/tmp'], 'failed to set -L /tmp'), ('q', ['-q'], 'failed to set -q'),
        ('U', ['-U', 'X'], 'failed to set -U X'), ('w', ['-w'], 'failed to set -w')):
    case(f'setopt-{label}-fails', ['-e'] + args + ['-n', 'BEGIN {}'], open='nodev',
         api_faults=f'dtrace_setopt:{SETOPT_BASE + 1}:5', status=1, stdout='',
         stderr_re=f'dtrace: {re.escape(msg)}: .*\n')
case('setopt-oformat-quiet-fails', ['--libxo', 'json', '-e', '-n', 'BEGIN {}'], open='nodev',
     api_faults=f'dtrace_setopt:{SETOPT_BASE + 1}:5', status=1, stdout_re='.*',
     stderr_re=r'dtrace: failed to set quiet \(caused by oformat\): .*\n')
case('anon-default-output-refused', ['-A', '-n', 'BEGIN {}'], status=1, stdout='',
     allow_refused=['open /boot/dtrace.dof'],
     stderr='dtrace: failed to open /boot/dtrace.dof: Permission denied\n')
case('anon-oformat', ['--libxo', 'json', '-A', '-o', '{d}/anon.dof', '-n', 'BEGIN {}'],
     stdout_re='.*', stderr='dtrace: saved anonymous enabling in {d}/anon.dof\n')
case('link-final-merge-fails', ['-64', '-G', '-x', 'syslibdir={drti}', '-s', '{d}/a.d',
                                '-s', '{d}/b.d', '-o', '{d}'], open='nodev',
     inputs={'a.d': 'BEGIN { trace(1); }\n', 'b.d': 'END { trace(2); }\n'}, status=1,
     stdout='', stderr_re=r'(?s).*dtrace: failed to link .*\n')


def objects(d):
    src = d/'o.c'
    src.write_text('int value;\n')
    subprocess.run(['/usr/bin/cc', '-c', str(src), '-o', str(d/'o64.o')], check=True)
    subprocess.run(['/usr/bin/cc', '-m32', '-c', str(src), '-o', str(d/'o32.o')], check=True)
    (d/'text.o').write_text('not an object\n')


case('link-model-mixed-64-then-32', ['-G', '-s', '{d}/p.d', '{d}/o64.o', '{d}/o32.o'],
     open='nodev', setup=objects, inputs={'p.d': 'provider pm { probe x(); };\n'}, status=1,
     stdout='', stderr="dtrace: can't mix 32-bit and 64-bit object files\n")
case('link-model-mixed-32-then-64', ['-G', '-s', '{d}/p.d', '{d}/o32.o', '{d}/o64.o'],
     open='nodev', setup=objects, inputs={'p.d': 'provider pm { probe x(); };\n'}, status=1,
     stdout='', stderr="dtrace: can't mix 32-bit and 64-bit object files\n")
case('link-model-32-object', ['-G', '-x', 'syslibdir={drti}', '-s', '{d}/p.d', '{d}/o32.o'],
     open='nodev', setup=objects, inputs={'p.d': 'provider pm { probe x(); };\n'},
     status_in=[0, 1], stdout='', stderr_re='.*', log_has=['NODEV-OPEN flags 0x9'])
case('link-model-not-elf', ['-G', '-x', 'syslibdir={drti}', '-s', '{d}/p.d', '{d}/text.o'],
     open='nodev', setup=objects, inputs={'p.d': 'provider pm { probe x(); };\n'}, status=1,
     stdout='', stderr_re=r'(?s).*dtrace: failed to link script .*\n',
     log_has=['NODEV-OPEN flags 0x1\n'])
case('link-model-missing-object', ['-G', '-s', '{d}/p.d', '{d}/absent.o'], open='nodev',
     inputs={'p.d': 'provider pm { probe x(); };\n'}, status=1, stdout='',
     stderr_re=r'(?s).*dtrace: failed to link script .*\n', log_has=['NODEV-OPEN flags 0x1\n'])
case('link-model-non-elf-class', ['-G', '-s', '{d}/p.d', '{d}/odd.o'], open='nodev',
     inputs={'p.d': 'provider pm { probe x(); };\n',
             'odd.o': b'\x7fELF\x03\x01\x01' + bytes(57)}, status=1, stdout='',
     stderr_re=r'(?s).*dtrace: failed to link script .*\n', log_has=['NODEV-OPEN flags 0x1\n'])

# Host consumer: receipts, replays and reconnection retries.
host('receipt-deadline-expires', LOOP.replace('wait-log {d}/shim.log GO\n', '') +
     'frame-ack 16 0 0\nhold\n', during=guest_runner(), clock='file:{d}/signal-1:61000',
     signals=[('EXEC conn=', None)], stdout_re='.*',
     stderr_re=all_of(MATCHED3, 'dtrace: host execution receipt failed: Operation timed out\n'),
     timeout=90)
host('guest-response-ignored-without-probes', LOOP.replace('wait-log {d}/shim.log GO\n',
     'sleep 500\n') + STOP_OK + 'hold\n',
     during=guest_runner(args=(), stop_guest=False, expect_installed=False),
     stderr='Ignoring 0 probes from VMID 3\n', daemon_has=['STOP-REPLY result=1'])
host('guest-response-parse-fails', LOOP.replace('wait-log {d}/shim.log GO\n', 'sleep 300\n') +
     STOP_OK + 'hold\n', during=guest_runner(), api_faults='dtrace_elf_parse:3:4',
     stderr='ELF parsing failed: Internal libdtrace error: ', daemon_has=['STOP-REPLY result=1'])
host('pgplist-allocation-aborts', 'wait-elf 1\nsend-elf base\nhold\n', faults='malloc:3:12',
     status=134, allow_abort=True, log_has=['ABORT'],
     stderr='dtrace: malloc of newpgpl failed: Cannot allocate memory\n')
host('ack-send-fails-reconnects', GEN + 'hold\n', faults='send:1:32',
     stderr_re=all_of('dtrace: identified delivery ACK failed; reconnecting for replay\n',
                      RECONNECTING), timeout=30, signals=[('REGISTERED conn=3', signal.SIGINT)],
     stdout_re='.*')
host('reconnect-registration-retried', BASE + 'reg-nack 2\nclose\n' + STOP_OK + 'hold\n',
     stderr_re=all_of(MATCHED0, RECONNECTING + RECONNECTED),
     daemon_has=['REGISTERED conn=3', 'REGISTERED conn=4', 'STOP-REPLY result=1'])
# The refused READDATA connection consumes no step: the next ELFWRITE
# connection proceeds once the consumer's retry has connected.
host('reconnect-readdata-retried', BASE + 'drop-conn 4\nclose\nwait-conn 6\n' + STOP_OK +
     'hold\n',
     stderr_re=all_of(MATCHED0, RECONNECTING + RECONNECTED),
     daemon_has=['DROP conn=4', 'STOP-REPLY result=1'])
for label, faults, api, frame in (
        ('mkstemp', 'mkstemp:4:24', None, None),
        ('elf-create', None, 'dtrace_elf_create:3:2', None),
        ('fsync', 'fsync:4:5', None, None),
        ('lseek', 'lseek:3:5', None, None),
        ('send', None, None, 'frame-ack 1 3 0\n'),
        ('close', 'close:LATE:5', None, None),
        ('unlink', 'unlink:4:5', None, None)):
    if label == 'close':
        continue
    host('replay-' + label + '-fails', (frame or '') + GEN + IDENT + 'expect-ack\n' + STOP_OK +
         'hold\n', faults=faults, api_faults=api,
         # An injected unlink failure leaves its file by definition.
         unlink_fault=label == 'unlink',
         stderr_re='dtrace: failed to replay derived ELF: .+\n',
         daemon_has=['ACK delivery=5 vmid=3 epoch=9 outcome=0'])
host('join-receiver-fails', BASE + END_ON_SIGNAL, faults='pthread_join:1:3',
     signals=[('STEP wait-file', signal.SIGINT)], status=1, stdout_re='.*',
     stderr_re=all_of(MATCHED0, 'dtrace: failed to join g_dtracedtd: No such process\n'))
host('join-reporter-fails', BASE + END_ON_SIGNAL, faults='pthread_join:2:3',
     signals=[('STEP wait-file', signal.SIGINT)], status=1, stdout_re='.*',
     stderr_re=all_of(MATCHED0, 'dtrace: failed to join g_executiontd: No such process\n'))
host('join-worker-fails', BASE + END_ON_SIGNAL, faults='pthread_join:3:3',
     signals=[('STEP wait-file', signal.SIGINT)], stdout_re='.*', status=0,
     stderr_re=all_of(MATCHED0, 'failed to join g_worktd\n'))
host('stop-reaps-background-descendant', 'wait-elf 1\nsend-elf base\nwait-log {d}/shim.log GO\n'
     'sleep 300\n' + STOP_OK + 'hold\n',
     prog=['-w', '-n', 'BEGIN { system("/bin/sleep 0.5 &"); }'], script='go 0 dtrace:::BEGIN n:0',
     
     stdout_re='.*', stderr_re='(?s).*' + MATCHED0 + '.*',
     daemon_has=['STOP-REPLY result=1', 'COMMIT'])

# Envelope and delivery-identity validation (hypertrace_frame.h), each a
# receiver failure before any program executes.
ENV = 'send-elf base vmid=3 epoch=9 name=vm3 '
for label, extra in (('version', 'env_version=7'), ('vmid-zero', 'env_vmid=0'),
                     ('vmid-range', 'env_vmid=1024'), ('epoch-zero', 'env_epoch=0'),
                     ('name-empty', 'env_namelen=0'), ('name-too-long', 'env_namelen=4096'),
                     ('name-beyond-frame', 'env_namelen=900000'),
                     ('name-nul', 'name_nul=1'), ('elf-missing', 'elf_bad=1'),
                     ('frame-shorter-than-envelope', 'truncate=20'),
                     ('elf-too-short', 'env_namelen=6481')):
    host('envelope-' + label, 'wait-elf 1\n' + ENV + extra + '\nhold\n', status=1,
         stderr='dtrace: invalid dtraced VM/ELF envelope\n')
# A zero program or source identity is already rejected by the header decoder.
for label, extra in (('program-zero', 'delivery=5 program=zero'),
                     ('source-zero', 'delivery=5 source=zero')):
    host('delivery-' + label, 'wait-elf 1\n' + ENV + extra + '\nhold\n', status=1,
         stderr='dtrace: invalid dtraced ELF header: Protocol error\n')
for label, extra in (('vmid-mismatch', 'delivery=5 hvmid=4'),
                     ('epoch-mismatch', 'delivery=5 hepoch=8'),
                     ('identity-without-delivery', 'delivery=0 hvmid=3')):
    host('delivery-' + label, 'wait-elf 1\n' + ENV + extra + '\nhold\n', status=1,
         stderr='dtrace: dtraced delivery identity conflicts with VM envelope\n')
host('delivery-identity-unenveloped', 'wait-elf 1\nsend-elf base delivery=5 hvmid=3 hepoch=9\n'
     'hold\n', status=1, stderr='dtrace: dtraced delivery identity conflicts with VM envelope\n')

# Identifier handshake reader (dtrace_identifiers.h).
guest('identifiers-count-too-large', ['-N', '-Y', fx('derived.elf')],
      stdin=(1 << 40).to_bytes(8, 'little'), status=1, stdout='',
      stderr='dtrace: failed to read complete identifier handshake: Invalid argument\n')
guest('identifiers-allocation-fails', ['-N', '-Y', fx('derived.elf')],
      stdin=(1).to_bytes(8, 'little') + bytes(128), faults='malloc:1:12', status=1, stdout='',
      stderr='dtrace: failed to read complete identifier handshake: Cannot allocate memory\n')
guest('identifiers-body-short', ['-N', '-Y', fx('derived.elf')],
      stdin=(2).to_bytes(8, 'little') + bytes(130), status=1, stdout='',
      stderr='dtrace: failed to read complete identifier handshake: Broken pipe\n')
guest('identifiers-read-interrupted', ['-N', '-Y', fx('derived.elf')], stdin=idents_stdin(),
      faults='read:1:4', signals=[('ROUND 2', signal.SIGINT)], stdout_re='(?s).*',
      stderr_has=['prog_exec = 1\n', 'process_elf_hypertrace(): matched 1 probe\n'])
guest('identifiers-read-fails', ['-N', '-Y', fx('derived.elf')], stdin=idents_stdin(),
      faults='read:1:5', status=1, stdout='',
      stderr='dtrace: failed to read complete identifier handshake: Input/output error\n')
guest('identifiers-stdin-closed', ['-N', '-Y', fx('derived.elf')], stdin=None,
      env={'CLI_CLOSE_STDIN': '1'}, status=1, stdout='', stdin_closed=True,
      stderr_re='dtrace: failed to read complete identifier handshake: .+\n')
guest('launch-report-not-installed', ['-N', '-Y', fx('base.elf')], stdout_socket=True,
      stdin=lambda ctx: (1).to_bytes(8, 'little') + program_srcident(ctx, ctx.out/'fixtures'/
                                                                  'base.elf'),
      env={'HYPERTRACE_LAUNCH_REPORT': '1'}, stdout_re='(?s).*',
      stderr_re=r'(?s).*prog_exec = 0\ndtrace: send_elf\(.*\)\n',
      check=lambda d, out, *a: [] if (0x3154534e495448).to_bytes(8, 'little') + b'\x00'
      in out.encode('latin-1') else ['no not-installed launch report'])
guest('launch-report-deadline-fails', ['-N', '-Y', fx('base.elf')],
      stdin=lambda ctx: (1).to_bytes(8, 'little') + program_srcident(ctx, ctx.out/'fixtures'/
                                                                  'base.elf'),
      env={'HYPERTRACE_LAUNCH_REPORT': '1'}, faults='clock_gettime:4:22', status=1,
      stdout_re='(?s).*', stderr_re=r'(?s).*dtrace: failed to set guest report deadline: '
      'Invalid argument\n')
guest('launch-report-write-fails', ['-N', '-Y', fx('base.elf')], stdout_socket=True,
      stdin=lambda ctx: (1).to_bytes(8, 'little') + program_srcident(ctx, ctx.out/'fixtures'/
                                                                  'base.elf'),
      env={'HYPERTRACE_LAUNCH_REPORT': '1'}, faults='send:1:32', status=1, stdout_re='(?s).*',
      stderr_re=r'(?s).*dtrace: failed to report guest installation: Broken pipe\n')

# A host program exiting by itself stops the consumer without a signal.
host('program-exit-stops-consumer', 'wait-elf 1\nsend-elf base\nhold\n',
     prog=['-n', 'BEGIN { exit(0); }'], script='go 0 dtrace:::BEGIN n:0', stdout_re='.*',
     stderr_re=MATCHED0, timeout=60)
# A not-installed guest reply has no probes; SIGINT then revokes it with a
# warning because its process ID is 0.
host('guest-reply-without-pid-warns', LOOP.replace('wait-log {d}/shim.log GO\n',
     'sleep 500\n') + 'hold\n', during=guest_runner(args=(), stop_guest=False,
     expect_installed=False), signals=[('STEP hold', signal.SIGINT)], stdout_re='.*',
     stderr_re=all_of('Ignoring 0 probes from VMID 3\n',
                      'dtrace: WARN: vm3 program pid claims to be 0\n'), timeout=90)
# The output worker owns tracing while an earlier program's enabling is slow:
# a duplicate guest reply then meets a valid pending entry.
host('duplicate-reply-after-busy-program', 'wait-elf 1\nsend-elf base\nwait-log {d}/shim.log DELAY\n'
     + IDENT + 'expect-ack\nwait-elf 2\nsave-elf derived {d}/derived.elf\n'
     'wait-file {d}/response.elf\nsend-elf file:{d}/response.elf vmid=3 epoch=9 name=vm3\n'
     'sleep 200\nsend-elf file:{d}/response.elf vmid=3 epoch=9 name=vm3\nsleep 200\n'
     + STOP_OK + 'hold\n', model='delay=ENABLE:6000', during=guest_runner(),
     # With all handle use serialized, the receiver cannot re-parse while the
     # first program's enabling holds the handle: the guest program is
     # executed after it (augmenting), and the duplicate finds no pending entry.
     stderr_re=MATCHED0 + r'dtrace: augmented with probes from \([0-9a-f]+\) 3\n',
     timeout=90)
host('identified-replay-waits-for-processing', LOOP.replace('wait-log {d}/shim.log GO\n',
     'wait-log {d}/shim.log DELAY\n') + IDENT + 'expect-ack\nwait-log {d}/shim.log GO\n'
     'sleep 200\n' + STOP_OK + 'hold\n', model='delay=VPROBE_CREATE:2000',
     during=guest_runner(), stderr_re=MATCHED3,
     check=lambda d, out, err, slog, dlog: [] if dlog.count(
         'ACK delivery=5 vmid=3 epoch=9 outcome=2') == 2 else ['replay was not acknowledged'])
host('identified-delivery-skips-unidentified-entry', 'wait-elf 1\n'
     'send-elf base vmid=3 epoch=9 name=vm3\nwait-elf 2\n' + IDENT + 'expect-ack\n'
     + IDENT + 'expect-ack\n' + STOP_OK + 'hold\n', stderr='',
     check=lambda d, out, err, slog, dlog: [] if dlog.count('outcome=2') == 2
     else ['identified replay not acknowledged twice'])


def gpgp_ident_env(ctx, d):
    fx_elf = ctx.out/'fixtures'/'derived.elf'
    listing = subprocess.run(['/usr/bin/readelf', '-SW', str(fx_elf)], capture_output=True,
                             text=True, check=True).stdout
    row = next(l for l in listing.splitlines() if '.dtrace_prog ' in l)
    offset = int(row.split('.dtrace_prog')[1].split()[2], 16)
    return {'CLI_SRCIDENT_FILE': str(d/'derived.elf'),
            'CLI_SRCIDENT_OFFSET': str(offset + ctx.harness['srcident_offset'] -
                                       ctx.harness['identlen'])}


AGAIN = (GEN + 'save-elf derived {d}/derived.elf\n'
         'send-elf file:{d}/derived.elf vmid=3 epoch=9 name=vm3\n')
host('reparse-against-guest-program-fails', AGAIN + 'sleep 300\n' + STOP_OK + 'hold\n',
     env_fn=gpgp_ident_env, api_faults='dtrace_elf_parse:2:6,dtrace_get_srcident:1:0,'
     'dtrace_elf_parse:3:5', stderr='ELF parsing failed: Checksum error: ',
     daemon_has=['STOP-REPLY result=1'])
# Async publication queue: with the daemon slow to accept outbound programs,
# the 65th unidentified delivery cannot be queued.
host('async-queue-full', 'ack-delay 3000\nwait-elf 1\nrepeat 66 send-elf base vmid=3 epoch=9 '
     'name=vm3\nsleep 1500\n' + STOP_OK + 'hold\n',
     stderr_re='(?s).*failed to dtrace_send_elf\\(\\): No buffer space available\n.*',
     timeout=120)
host('stop-reply-lost-still-commits', BASE + STOP_OK + 'hold\n', faults='send:1:32',
     stderr_re=MATCHED0, daemon_has=['STOP-REPLY-FAILED', 'COMMIT conn=3 valid=1 result=1'])
host('drain-truncated-reconnects', BASE + f'drain token={TOKEN} len=10 noreply=1\nclose\n'
     + STOP_OK + 'hold\n', stderr_re=all_of(MATCHED0, RECONNECTING + RECONNECTED),
     daemon_has=['REGISTERED conn=3', 'STOP-REPLY result=1'])
# system() children are created after the collector became a reaper; a
# background child is reparented to it as a descendant.
DESC = 'wait-elf 1\nsend-elf base\nwait-log {d}/shim.log GO\nsleep 300\n'
# The background child signals its start through a file before the stop.
host('stop-quiesce-deadline-expires', DESC + 'wait-file {d}/started\n' + STOP_OK + 'hold\n',
     prog=['-w', '-n', 'BEGIN { system("/bin/sleep 8 & touch {d}/started"); }'],
     script='go 0 dtrace:::BEGIN n:0',
     clock='file:{d}/signal-1:46000', signals=[('STEP stop', None)], stdout_re='.*',
     stderr_re='(?s).*' + MATCHED0 + '.*', daemon_has=['STOP-REPLY result=0'])
host('stop-reap-wait-fails', DESC + 'sleep 500\n' + STOP_OK + 'hold\n',
     prog=['-w', '-n', 'BEGIN { system("/bin/sleep 0.2 &"); }'], script='go 0 dtrace:::BEGIN n:0',
     faults='waitpid:1:5', stdout_re='.*', stderr_re='(?s).*' + MATCHED0 + '.*',
     daemon_has=['STOP-REPLY result=0'])
host('stop-reaper-pid-query-fails', DESC + STOP_OK + 'hold\n',
     prog=['-w', '-n', 'BEGIN { system("/bin/sleep 2 &"); }'], script='go 0 dtrace:::BEGIN n:0',
     faults='procctl:4:5', stdout_re='.*', stderr_re='(?s).*' + MATCHED0 + '.*',
     daemon_has=['STOP-REPLY result=0'])
case('buffered-anonymous-aggregation', FAST + ['-B', '-n', 'BEGIN { @[1] = count(); @c = sum(2); '
                                               'exit(0); }'],
     script='go 0 dtrace:::BEGIN n:1 n:1 a:0:1 n:2 a:2:1 n:0', stderr=matched('BEGIN ', 1),
     stdout_has=['dtrace: >>> Called buffer handler:\n'])
case('args-allocation-fails-early', ['-V'], env={'CLI_ARM_EARLY': '1'}, faults='malloc:1:12',
     status=1, stdout='', stderr='dtrace: failed to allocate memory for arguments: '
     'Cannot allocate memory\n')


# Process control: notifications reach prochandler() only when the consumer
# loop sleeps (dtrace_sleep() returns before draining notifications once its
# earliest deadline has passed), so these cases use slow rates.
SLOW = ['-x', 'switchrate=500ms', '-x', 'statusrate=500ms', '-x', 'aggrate=500ms']
case('proc-victim-exits', SLOW + ['-c', '/bin/sleep 0.3', '-n', 'BEGIN {}'], stdout='\n',
     stderr_re=re.escape(matched('BEGIN ', 1)) + r'dtrace: pid \d+ has exited\n')
case('proc-victim-exit-status', SLOW + ['-c', '/usr/bin/false', '-n', 'BEGIN {}'], stdout='\n',
     stderr_re=re.escape(matched('BEGIN ', 1)) + r'dtrace: pid \d+ exited with status 1\n')
case('proc-victim-killed', SLOW + ['-c', '/bin/sh -c kill${IFS}-9${IFS}$$', '-n', 'BEGIN {}'],
     stdout='\n', stderr_re=re.escape(matched('BEGIN ', 1)) + r'dtrace: pid \d+ terminated by 9\n')
case('proc-victim-quiet', SLOW + ['-q', '-c', '/bin/sleep 0.3', '-n', 'BEGIN {}'], stdout='\n',
     stderr='')
case('proc-grab-running', SLOW + ['-p', '{pid}', '-n', 'BEGIN {}'], spawn=['/bin/sleep', '0.6'],
     stdout='\n', stderr_re=re.escape(matched('BEGIN ', 1)) + r'dtrace: pid \d+ has exited\n')

# Anonymous-enabling file pruning faults (dof_prune).
PRUNE = {'anon.dof': 'keep\ndof-data-0=old\nrest\n'}
for label, faults, message in (
        ('fstat', 'fstat:1:5', 'failed to fstat {d}/anon.dof: Input/output error'),
        ('allocation', 'malloc:1:12', 'failed to allocate memory for {d}/anon.dof: '
         'Cannot allocate memory'),
        ('read', 'read:1:5', 'failed to read {d}/anon.dof: Input/output error'),
        ('reopen', 'open:2:13', 'failed to open {d}/anon.dof for writing: Permission denied'),
        ('write-leading', 'write:1:5', 'failed to write to {d}/anon.dof: Input/output error'),
        ('write-trailing', 'write:2:5', 'failed to write to {d}/anon.dof: Input/output error')):
    case('anon-prune-' + label + '-fails', ['-A', '-o', '{d}/anon.dof'], inputs=dict(PRUNE),
         faults=faults, status=1, stdout='', stderr_re='(?s).*' + re.escape('dtrace: ' + message)
         .replace(re.escape('{d}'), '{d}') + '\n')
case('anon-nextboot-wait-fails', ['-A', '-o', '{d}/anon.dof', '-n', 'BEGIN {}'],
     faults='waitpid:1:5', status=1, stdout='',
     stderr='dtrace: saved anonymous enabling in {d}/anon.dof\n'
            'dtrace: waiting for nextboot: Input/output error\n')
case('resolvers-hostname-only', ['-e', '-x', 'resolvers=hostname', '-n', 'BEGIN { trace(1); }'],
     open='nodev', stdout='', stderr='')
case('resolvers-none', ['-e', '-x', 'resolvers=none', '-n', 'BEGIN { trace(1); }'],
     open='nodev', stdout='', stderr='')
host('receive-deadline-fails', 'wait-elf 1\nhold\n', faults='clock_gettime:1:22', status=1,
     stderr='dtrace: failed to set dtraced receive deadline: Invalid argument\n')


# Condition outcomes of identity, drain, stop and session checks.
for field in ('vmid', 'epoch', 'program', 'source'):
    host('ingress-installed-' + field + '-mismatch', 'wait-elf 1\n' + ENV +
         f'delivery=5 installed={field}\nhold\n', status=1,
         stderr='dtrace: dtraced ingress session is missing or mismatched\n')
for label, extra in (('program', 'program=' + '42' * 16), ('source', 'source=' + '43' * 16),
                     ('delivery', 'delivery=6'), ('session', '')):
    line = ('send-elf base vmid=3 epoch=9 name=vm3 delivery=5 ' + extra + '\n' if label !=
            'session' else IDENT)
    host('derived-parent-' + label + '-differs', GEN + line + 'expect-ack\nwait-elf 3\n' +
         STOP_OK + 'hold\n', stderr='',
         extra=(['-x', 'hypertrace_session_file={d}/session'] if label == 'session' else []),
         setup=(session_file() if label == 'session' else None),
         check=lambda d, out, err, slog, dlog: [] if dlog.count('outcome=2') == 2 and
         dlog.count('location=outbound') == 2 else ['expected a second derivation'])
host('drain-digest-mismatch', BASE + f'drain token={TOKEN} digest=bad\n' + STOP_OK + 'hold\n',
     extra=NOTEMPORAL, stderr_re=MATCHED0, daemon_has=['DRAIN-REPLY result=0'])
host('drain-buffered-output', BASE + f'drain token={TOKEN}\n' + STOP_OK + 'hold\n',
     extra=['-x', 'temporal=no', '-B'], stderr_re=MATCHED0, stdout_re='.*',
     daemon_has=['DRAIN-REPLY result=0'])
host('drain-fstat-fails', BASE + f'drain token={TOKEN}\n' + STOP_OK + 'hold\n',
     extra=NOTEMPORAL, faults='fstat:1:5', stderr_re=MATCHED0,
     daemon_has=['DRAIN-REPLY result=0'])
host('drain-fsync-fails', BASE + f'drain token={TOKEN}\n' + STOP_OK + 'hold\n',
     extra=NOTEMPORAL, faults='fsync:3:5', stderr_re=MATCHED0,
     daemon_has=['DRAIN-REPLY result=0'])
host('drain-after-interrupt', BASE + 'wait-file {d}/signal-1\n' + f'drain token={TOKEN}\n'
     'close\n', extra=NOTEMPORAL, signals=[('STEP wait-file', signal.SIGINT)], stdout_re='.*',
     stderr_re='(?s).*' + MATCHED0 + '.*', daemon_has=['DRAIN-REPLY result=0'])
host('stop-after-interrupt', BASE + 'wait-file {d}/signal-1\n' + STOP_OK + 'close\n',
     signals=[('STEP wait-file', signal.SIGINT)], stdout_re='.*',
     stderr_re='(?s).*' + MATCHED0 + '.*', daemon_has=['STOP-REPLY result=0'])
host('stop-before-any-program', 'wait-elf 1\n' + STOP_OK + 'hold\n', stderr='',
     daemon_has=['STOP-REPLY result=1', 'COMMIT'])
host('stop-while-receipt-retries', LOOP.replace('wait-log {d}/shim.log GO\n', '') +
     'frame-ack 16 0 0\nwait-log {d}/daemon.log EXEC conn=\n' + STOP_OK + 'hold\n',
     during=guest_runner(), stderr_re=MATCHED3, daemon_has=['STOP-REPLY result=1'])
host('session-file-read-interrupted', BASE + STOP_OK + 'hold\n', extra=SESSION,
     setup=session_file(), faults='pread:1:4', stderr_re=MATCHED0,
     daemon_has=['session=0102030405060708090a0b0c0d0e0f10'])
case('exec-siginfo-ignored', FAST + ['-n', ENTRY + ' { @c = count(); }'], ignore_siginfo=True,
     script=f'go 0 {ENTRY} n:1 a:0:1',
     signals=[('ROUND 2', signal.SIGINFO), ('ROUND 4', signal.SIGINT)],
     stdout='\n\n' + ' %16d\n' % 1, stderr=matched(ENTRY + ' ', 1))


# -x checkmodref.  Expected reports follow the documented modref rules
# (analysis-modref.py): stores are MOD and loads REF for global (x),
# thread-local (self->), clause-local (this->) variables; exit is an
# external-memory MOD, ustack an external REF+MOD, speculate an internal
# REF+MOD, and any subroutine call references every kind.  An action is
# reported when it references anything after an earlier action of the same
# program modified anything; the report lists the kinds it references.
def modref(where, *kinds):
    return f'dtrace: ref-after-mod in dtrace:::{where}:' + ''.join(' ' + k for k in kinds) + '\n'


CMR = ['-x', 'checkmodref']
for label, prog, expected in (
        ('global', 'dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }', modref('END', 'global')),
        ('thread', 'dtrace:::BEGIN { self->t = 1; } dtrace:::END { trace(self->t); }',
         modref('END', 'thread')),
        ('clause', 'dtrace:::BEGIN { this->c = 1; trace(this->c); }', modref('BEGIN', 'clause')),
        ('external', 'dtrace:::BEGIN { exit(0); ustack(); }', modref('BEGIN', 'external')),
        ('internal', 'dtrace:::BEGIN { x = 1; } dtrace:::END { speculate(1); trace(1); }',
         modref('END', 'internal')),
        ('subroutine-all-kinds', 'dtrace:::BEGIN { x = 1; trace(strlen("ab")); }',
         modref('BEGIN', 'global', 'thread', 'clause', 'external', 'internal')),
        ('two-reports', 'dtrace:::BEGIN { x = 1; self->t = 2; } '
         'dtrace:::END { trace(x); trace(self->t); }',
         modref('END', 'global') + modref('END', 'thread')),
        ('ref-before-mod', 'int x; dtrace:::BEGIN { trace(x); } dtrace:::END { x = 1; }', ''),
        ('mod-only', 'dtrace:::BEGIN { x = 1; self->t = 2; this->c = 3; }', ''),
        # walltimestamp is a global reference, ustack an external one with
        # its own MOD; nothing was modified before either.
        ('ref-without-mod', 'dtrace:::BEGIN { trace(walltimestamp); ustack(); }', '')):
    case('checkmodref-' + label, CMR + ['-e', '-n', prog], open='nodev', stdout='',
         stderr=expected)
case('checkmodref-off', ['-e', '-n', 'dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }'],
     open='nodev', stdout='', stderr='')
case('checkmodref-value-rejected', ['-x', 'checkmodref=yes', '-e', '-n', 'BEGIN {}'],
     open='nodev', status=1, stdout='', stderr='dtrace: -x checkmodref takes no value\n')
case('checkmodref-empty-value-rejected', ['-x', 'checkmodref=', '-e', '-n', 'BEGIN {}'],
     open='nodev', status=1, stdout='', stderr='dtrace: -x checkmodref takes no value\n')
for label, args in (('list', ['-l']), ('header', ['-h', '-s', '{d}/p.d', '-o', '{d}/p.h']),
                    ('link', ['-G', '-s', '{d}/p.d']), ('anon', ['-A', '-o', '{d}/a.dof'])):
    case('checkmodref-mode-' + label + '-rejected', CMR + args, open='nodev', status=1,
         inputs={'p.d': 'provider pm { probe x(); };\n'}, stdout='',
         stderr='dtrace: -x checkmodref is valid only when programs are compiled for '
                'execution\n')
case('checkmodref-executes-after-warning', FAST + CMR + ['-n', 'dtrace:::BEGIN { x = 1; } '
     'dtrace:::END { trace(x); }'], script='go 0 dtrace:::BEGIN n:0', signals=[('ROUND 2',
     signal.SIGINT)], stdout_re='.*',
     stderr=modref('END', 'global') + matched('dtrace:::BEGIN ', 2), log_has=['GO'])
host('checkmodref-received-program', BASE + STOP_OK + 'hold\n', extra=CMR,
     prog=['-n', 'dtrace:::BEGIN { exit(0); ustack(); }'],
     # Checked once, when the received program is executed, not when the
     # host consumer compiles it for dtraced.
     stderr_re=re.escape(modref('BEGIN', 'external')) +
     r'dtrace: matched 1 probe \([0-9a-f]+\) from 0\n',
     daemon_has=['STOP-REPLY result=1'])
guest('checkmodref-elf-program', CMR + ['-Y', fx('modref.elf')], stdout='',
      stderr_has=[modref('END', 'global'), 'dtrace: send_elf('])
# The ref-after-mod report is made at link time even for an ELF that is not
# marked for execution, which -y then refuses to run.
case('checkmodref-elf-run', FAST + CMR + ['-y', fx('modref.elf')], status=1, stdout_re='.*',
     stderr_has=[modref('END', 'global'),
                 'modref.elf: program is not marked for execution\n'])

# Regression cases for defects fixed in dtrace.c (see COVERAGE-cli.5BSD.md).
case('fix-define-symbol', ['-e', '-C', '-D', 'OFFLINE_DEF=1', '-s', '{d}/s.d'], open='nodev',
     inputs={'s.d': '#if OFFLINE_DEF\nBEGIN { trace(1); }\n#else\nBEGIN { not D }\n#endif\n'},
     stdout='', stderr='')
case('fix-graph-file', ['-e', '-g', '{d}/g.dot', '-n', 'BEGIN { trace(1); }'], open='nodev',
     stdout='', stderr='',
     check=lambda d, *a: [] if (d/'g.dot').exists() and 'digraph' in (d/'g.dot').read_text()
     else ['graph file missing or not a digraph'])
case('fix-graph-file-unwritable', ['-e', '-g', '{d}/absent/g.dot', '-n', 'BEGIN { trace(1); }'],
     open='nodev', stdout='', stderr='Failed to open {d}/absent/g.dot for writing\n')
case('fix-session-file-requires-host', ['-x', 'hypertrace_session_file=/nonexistent', '-e',
                                        '-n', 'BEGIN {}'], open='nodev', status=1, stdout='',
     stderr='dtrace: -x hypertrace_session_file requires a host HyperTrace consumer (-E)\n')
case('fix-session-file-relative', ['-x', 'hypertrace_session_file=relative', '-E', '-n',
                                   'BEGIN {}'], open='nodev', status=1, stdout='',
     stderr='dtrace: -x hypertrace_session_file needs an absolute path\n')
case('fix-session-file-missing-value', ['-x', 'hypertrace_session_file', '-E', '-n',
                                        'BEGIN {}'], open='nodev', status=1, stdout='',
     stderr='dtrace: -x hypertrace_session_file needs an absolute path\n')
case('fix-signal-thread-sigmask', FAST + ['-n', 'BEGIN { trace(1); }'],
     # The message is fixed; fatal() from the signal thread then closes the
     # handle while the consumer thread still uses it (open race, reported).
     script='go 0 dtrace:::BEGIN n:1', faults='pthread_sigmask:2:22', status=1,
     stdout_re='.*', stderr_has=[matched('BEGIN ', 1)],
     stderr_re=r".*dtrace: failed to apply sigmask to signal handler thread: "
               r"Invalid argument\n$")


# Regression for the fatal()/handle-close race: each case reaches fatal() on
# one thread while another thread uses the handle.  Before the fix 19 of 80
# repetitions crashed (cov-cli-race-before-20261021); every repetition must
# now exit with its documented status and leave a complete profile.
for _name in ('host-options-update-fails', 'guest-report-deadline-fails',
              'guest-report-write-fails', 'signal-wait-fails', 'host-join-receiver-fails',
              'host-join-reporter-fails', 'host-join-worker-fails', 'fix-signal-thread-sigmask'):
    _base = next(c for c in CASES if c['name'] == _name)
    for _i in range(6):
        CASES.append(dict(_base, name=f'fix-fatal-race-{_i}-{_name}'))
# Temporary files follow TMPDIR (absent set-id) so a private directory can be
# used; before the fix they were always created in /tmp.
case('fix-tmpdir-honoured', ['-E', '-e', '-n', 'BEGIN { trace(1); }'], open='nodev', stderr='',
     check=elf_path_check('honoured.elf'))

# Regression for the lost g_pgpcond wakeup: three threads wait on one
# condition variable, so a single pthread_cond_signal could wake the reporter
# instead of the execution loop (6/40 hung before the fix, 80/80 passed after).
_wakeup = next(c for c in CASES if c['name'] == 'host-stop-unidentified')
for _i in range(16):
    CASES.append(dict(_wakeup, name=f'fix-wakeup-{_i}'))

import os as _os
if _os.environ.get('CLI_STRESS'):
    for _name in _os.environ['CLI_STRESS'].split(','):
        base = next(c for c in CASES if c['name'] == _name)
        for i in range(int(_os.environ.get('CLI_STRESS_N', '30'))):
            CASES.append(dict(base, name=f"stress-{i}-{base['name']}"))


# ---------------------------------------------------------------------------
# Runner.

class Context:
    def __init__(self, out, binary, harness, env, objtop):
        self.out, self.binary, self.harness, self.env, self.objtop = \
            out, binary, harness, env, objtop
        self.sockdir = Path(tempfile.mkdtemp(prefix='cov-cli-', dir='/tmp'))


def wait_marker(paths, marker, deadline):
    while time.monotonic() < deadline:
        for path in paths:
            try:
                if marker in path.read_text(errors='replace'):
                    return True
            except OSError:
                pass
        time.sleep(0.01)
    return False


TMP_PREFIXES = ('dtrace-execprog.', 'dtrace-process-elf.', 'ddtrace-elf.', 'ddtrace-reemit.')


def leftover_tmp(tmpdir, who):
    left = [p.name for p in Path(tmpdir).glob('*') if p.name.startswith(TMP_PREFIXES)]
    return [f'{who} left temporary files {sorted(left)}'] if left else []


def run_case(ctx, index, c):
    d = ctx.out/'cases'/c['name']
    d.mkdir(parents=True)
    log = d/'shim.log'
    profiles = d/'profiles'
    profiles.mkdir()
    env = dict(ctx.env)
    (d/'tmp').mkdir()
    # CLI_NO_TMPDIR (evidence runs only) leaves dtrace on its /tmp default.
    tmpdir = '/tmp' if os.environ.get('CLI_NO_TMPDIR') else str(d/'tmp')
    env.update(LD_PRELOAD=str(ctx.harness['shim']), CLI_SHIM_LOG=str(log), TMPDIR=tmpdir,
               DTRACE_DOF_INIT_DISABLE='1', TZ='UTC', LC_ALL='C',
               CLI_OPEN=c.get('open', 'model'),
               LLVM_PROFILE_FILE=str(profiles/'%p-%m.profraw'))
    for key, var in (('script', 'CLI_SCRIPT'), ('model', 'CLI_MODEL'), ('faults', 'CLI_FAULTS'),
                     ('gate', 'CLI_GATE'), ('nextboot', 'CLI_NEXTBOOT'), ('clock', 'CLI_CLOCK'),
                     ('api_faults', 'CLI_API_FAULTS')):
        if c.get(key):
            env[var] = c[key].replace('{d}', str(d))
    env.update({k: v.replace('{d}', str(d)) for k, v in c.get('env', {}).items()})
    if 'env_fn' in c:
        env.update(c['env_fn'](ctx, d))
    for name, content in c.get('inputs', {}).items():
        target = d/name
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content.replace('{d}', str(d)))
        if name in c.get('modes', {}):
            target.chmod(c['modes'][name])
    if c.get('setup'):
        c['setup'](d)
    daemon = None
    dlog = d/'daemon.log'
    errors = []
    if c.get('daemon') is not None:
        sock = ctx.sockdir/f'{index}.sock'
        (d/'daemon.script').write_text(c['daemon'].replace('{d}', str(d))
                                       .replace('{fx}', str(ctx.out/'fixtures')))
        daemon = subprocess.Popen([str(ctx.harness['daemon']), str(sock), str(d/'daemon.script'),
                                   str(dlog)], stdout=subprocess.DEVNULL,
                                  stderr=open(d/'daemon.stderr', 'w'))
        if not wait_marker([dlog], 'LISTENING', time.monotonic() + 10):
            errors.append('fake daemon did not start')
        env['CLI_DTRACED_SOCK'] = str(sock)
    spawned = None
    if c.get('spawn'):
        spawned = subprocess.Popen(c['spawn'], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    args = [a.replace('{d}', str(d)).replace('{drti}', str(ctx.objtop/'cddl/lib/drti'))
            .replace('{fx}', str(ctx.out/'fixtures'))
            .replace('{pid}', str(spawned.pid if spawned else 0)) for a in c['args']]
    timeout = c.get('timeout', 60)
    start = time.monotonic()
    stdin = c.get('stdin')
    if callable(stdin):
        stdin = stdin(ctx)
    sock_reader = None
    if c.get('stdout_socket'):
        # dtraced launches guests with a socket as stdout; the launch report
        # is written with send(2).
        import socket
        import threading
        ours, theirs = socket.socketpair()
        captured = bytearray()

        def drain():
            while chunk := ours.recv(65536):
                captured.extend(chunk)
        sock_reader = threading.Thread(target=drain)
        sock_reader.start()
        stdout_arg = theirs.fileno()
    else:
        stdout_arg = subprocess.PIPE
    preexec = None
    if c.get('ignore_siginfo'):
        preexec = lambda: signal.signal(signal.SIGINFO, signal.SIG_IGN)
    proc = subprocess.Popen([str(ctx.binary), *args], cwd=d, env=env, preexec_fn=preexec,
                            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=stdout_arg, stderr=subprocess.PIPE)
    if sock_reader is not None:
        theirs.close()
    companion_errors = []
    companion = None
    if 'during' in c:
        import threading
        companion = threading.Thread(target=lambda: companion_errors.extend(
            c['during'](ctx, d, env, start + timeout) or []))
        companion.start()
    if stdin is not None:
        try:
            proc.stdin.write(stdin)
            if not c.get('stdin_keep_open'):
                proc.stdin.close()
                proc.stdin = None
        except BrokenPipeError:
            proc.stdin = None
    for number, (marker, sig) in enumerate(c.get('signals', []), 1):
        if not wait_marker([log, dlog], marker, start + timeout):
            errors.append(f'marker {marker!r} not seen')
            break
        if proc.poll() is None and sig is not None:
            proc.send_signal(sig)
        # The scripted daemon may wait for this file (wait-file).
        (d/f'signal-{number}').write_text(str(sig))
    try:
        stdout, stderr = proc.communicate(timeout=max(1, start + timeout - time.monotonic()))
    except subprocess.TimeoutExpired:
        # Record every thread's stack before killing a hung consumer.
        with open(d/'timeout-stacks.txt', 'w') as fp:
            subprocess.run(['/usr/bin/lldb', '--batch', '-p', str(proc.pid), '-o',
                            'thread backtrace all'], stdout=fp, stderr=subprocess.STDOUT,
                           timeout=120)
        proc.kill()
        stdout, stderr = proc.communicate()
        errors.append('timeout')
    if spawned is not None:
        try:
            spawned.wait(timeout=30)
        except subprocess.TimeoutExpired:
            spawned.kill()
            spawned.wait()
    if companion is not None:
        companion.join()
        errors.extend(companion_errors)
    if daemon is not None:
        daemon.terminate()
        daemon.wait()
    if sock_reader is not None:
        sock_reader.join()
        ours.close()
        stdout = bytes(captured)
    stdout = stdout.decode('latin-1') if c.get('stdout_socket') else \
        stdout.decode(errors='replace')
    stderr = stderr.decode(errors='replace')
    (d/'stdout.txt').write_text(stdout)
    (d/'stderr.txt').write_text(stderr)
    shimlog = log.read_text(errors='replace') if log.exists() else ''
    daemonlog = dlog.read_text(errors='replace') if dlog.exists() else ''
    want = c.get('status_in', [c.get('status', 0)])
    if proc.returncode not in want:
        errors.append(f'status {proc.returncode} not in {want}')
    for key, text in (('stdout', stdout), ('stderr', stderr)):
        if key in c and text != c[key].replace('{d}', str(d)).replace(
                '{fx}', str(ctx.out/'fixtures')):
            errors.append(f'{key} mismatch: expected {c[key]!r} got {text!r}')
        for frag in c.get(key + '_has', []):
            if frag.replace('{d}', str(d)).replace('{fx}', str(ctx.out/'fixtures')) not in text:
                errors.append(f'{key} lacks {frag!r}: {text[-800:]!r}')
        for frag in c.get(key + '_lacks', []):
            if frag in text:
                errors.append(f'{key} has {frag!r}')
        if key + '_re' in c and not re.fullmatch(c[key + '_re'].replace('{d}', re.escape(str(d))),
                                                 text, re.S):
            errors.append(f'{key} does not match {c[key + "_re"]!r}: {text!r}')
    for frag in c.get('log_has', []):
        if frag not in shimlog:
            errors.append(f'shim log lacks {frag!r}')
    for frag in c.get('log_lacks', []):
        if frag in shimlog:
            errors.append(f'shim log has {frag!r}')
    for frag in c.get('daemon_has', []):
        if frag not in daemonlog:
            errors.append(f'daemon log lacks {frag!r}')
    for frag in c.get('daemon_lacks', []):
        if frag in daemonlog:
            errors.append(f'daemon log has {frag!r}')
    if c.get('api_faults'):
        for spec in c['api_faults'].split(','):
            fname, nth, _ = spec.split(':')
            if f'API-FAULT {fname} #{nth} ' not in shimlog:
                errors.append(f'injected API fault {spec} did not fire')
    if c.get('faults'):
        for spec in c['faults'].split(','):
            fname, nth, _ = spec.split(':')
            if f'FAULT {fname} #{nth} ' not in shimlog:
                errors.append(f'injected fault {spec} did not fire')
    allowed = c.get('allow_refused', [])
    for line in shimlog.splitlines():
        if line.startswith('REFUSED') and not any(a in line for a in allowed) and \
                'open /dev/dtrace/helper' not in line:
            errors.append('unexpected boundary refusal: ' + line)
        if line.startswith('UNEXPECTED') and not c.get('allow_unexpected'):
            errors.append('unmodeled ioctl: ' + line)
        if line.startswith('ABORT') and not c.get('allow_abort'):
            errors.append('abort() called')
    # A forked child (system() actions) may fail to write its own profile;
    # only the measured process's profile writes must succeed.
    if re.search(rf'LLVM Profile Error: .*/{proc.pid}-', stderr) or \
            ('LLVM Profile Error' in stderr and not c.get('child_profiles')):
        errors.append('profile error')
    for name, content in c.get('files', {}).items():
        target = d/name
        if not target.exists():
            errors.append(f'missing output file {name}')
        elif content is not None and target.read_text(errors='replace') != \
                content.replace('{d}', str(d)):
            errors.append(f'file {name} mismatch: {target.read_text(errors="replace")!r}')
    if 'check' in c:
        errors.extend(c['check'](d, stdout, stderr, shimlog, daemonlog))
    # No failure path may leave a temporary file dtrace(1) created.
    if not c.get('unlink_fault'):
        errors.extend(leftover_tmp(d/'tmp', 'case'))
    prof = sorted(str(p) for p in profiles.rglob('*.profraw'))
    if not prof and proc.returncode >= 0:
        errors.append('no profile written')
    return {'name': c['name'], 'args': args, 'status': proc.returncode, 'passed': not errors,
            'errors': errors, 'profiles': prof, 'seconds': round(time.monotonic() - start, 2),
            'known_defect': c.get('known_defect')}


def safe_run(ctx, index, c):
    try:
        return run_case(ctx, index, c)
    except Exception as error:  # a harness error fails only this case
        return {'name': c['name'], 'args': c['args'], 'status': None, 'passed': False,
                'errors': [f'harness error: {error!r}'], 'profiles': [], 'seconds': 0,
                'known_defect': None}


def run_all(out, binary, harness, env, objtop, only=None):
    ctx = Context(out, binary, harness, env, objtop)
    selected = [c for c in CASES if only is None or re.search(only, c['name'])]
    names = [c['name'] for c in selected]
    if len(set(names)) != len(names):
        raise SystemExit('duplicate case names')
    fixtures = ctx.out/'fixtures'
    fixtures.mkdir()
    results = []
    for i, f in enumerate(FIXTURES):
        r = safe_run(ctx, 10000 + i, f)
        results.append(r)
        produced = ctx.out/'cases'/f['name']/f['output']
        if not r['passed'] or not produced.exists():
            raise SystemExit(f"fixture {f['name']} failed: {r['errors']}")
        shutil.copyfile(produced, fixtures/f['output'])
    try:
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
            results += list(pool.map(lambda ic: safe_run(ctx, *ic), enumerate(selected)))
    finally:
        shutil.rmtree(ctx.sockdir, ignore_errors=True)
    return results


# ---------------------------------------------------------------------------
# OpenTelemetry output (-x otel=...).  Exported files are checked with the
# independent validator from lib/libotelexport/tests (its own JSON parser and
# OTLP schema), never with library code.  The probe clock program is enabled
# before the script, so it owns the first BEGIN ECB (#0) and the script's
# BEGIN is #1.  The anchor printf takes walltimestamp and timestamp; a wall
# time of 1700000000 s with timestamp 0 puts every later record just after
# 2023-11-14T22:13:20Z, far from the consumer's clock.
ANCHOR = 'go 0 dtrace:::BEGIN n:1700000000000000000 n:0'
W0 = 1700000000 * 10**9


def otel_tool(d, name):
    return d.parent.parent/'harness'/name


def otlp_lines(d, path):
    """Validate an OTLP JSON Lines file; return its parsed requests."""
    import json
    proc = subprocess.run([str(otel_tool(d, 'otlp_validate')), str(path)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise ValueError(f'validator: {proc.stderr.strip()}')
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def otel_items(reqs, kind):
    """(resource attributes dict, item) for every log record/metric/span."""
    keys = {'logs': ('resourceLogs', 'scopeLogs', 'logRecords'),
            'metrics': ('resourceMetrics', 'scopeMetrics', 'metrics'),
            'spans': ('resourceSpans', 'scopeSpans', 'spans')}[kind]
    out = []
    for req in reqs:
        for rs in req.get(keys[0], []):
            res = {a['key']: list(a['value'].values())[0]
                   for a in rs['resource']['attributes']}
            for ss in rs[keys[1]]:
                for item in ss[keys[2]]:
                    out.append((res, ss['scope']['name'], item))
    return out


def attrs(item):
    return {a['key']: list(a['value'].values())[0] for a in item.get('attributes', [])}


def otel_check(fn):
    """Wrap a check so validator errors become case errors."""
    def check(d, stdout, stderr, shimlog, daemonlog):
        try:
            return fn(d, stdout) or []
        except (ValueError, KeyError, IndexError) as error:
            return [f'otel check: {error!r}']
    return check


def check_otlpjson_printf(d, stdout):
    reqs = otlp_lines(d, d/'out.jsonl')
    logs = otel_items(reqs, 'logs')
    errors = []
    if stdout != '':
        errors.append('stdout not empty')
    if [i['body']['stringValue'] for _, _, i in logs] != ['hello 42']:
        errors.append(f'log bodies {[i["body"] for _, _, i in logs]}')
    res, scope, rec = logs[0]
    t = int(rec['timeUnixNano'])
    if not W0 < t < W0 + 10**9:
        errors.append(f'timeUnixNano {t} is not the probe clock')
    if int(rec['observedTimeUnixNano']) < W0 + 10**16:
        errors.append('observedTimeUnixNano is not the consumer clock')
    if res.get('service.name') != 'dtrace' or scope != 'dtrace' or \
            not res.get('service.version', '').startswith('Sun D'):
        errors.append(f'resource/scope {res} {scope}')
    if attrs(rec).get('dtrace.probe') != 'dtrace:::BEGIN':
        errors.append(f'probe attribute {attrs(rec)}')
    if any(k.startswith('hypertrace.') for k in res):
        errors.append('host records carry a guest resource')
    return errors


case('otel-otlpjson-file', FAST + ['-q', '-x', 'otel=otlp-json', '-o', '{d}/out.jsonl', '-n',
                                   'BEGIN { printf("hello %d\\n", 42); exit(0); }'],
     script=ANCHOR + ' ; go 0 dtrace:::BEGIN#1 n:42 n:0', stdout='', stderr='',
     check=otel_check(check_otlpjson_printf))


def check_json_records(d, stdout):
    import json
    recs = [json.loads(line) for line in stdout.splitlines()]
    bodies = [(r['probe'], r['body']) for r in recs]
    want = [('test:kernel:alpha:entry', '7 8'), ('test:kernel:beta:entry',
                                                'test:kernel:beta:entry')]
    if bodies != want:
        return [f'records {bodies} != {want}']
    if not all(r['time'].startswith('2023-11-14T22:13:20.') for r in recs):
        return [f'times {[r["time"] for r in recs]}']
    if recs[0]['attributes'].get('cpu.logical_number') != 1:
        return [f'attributes {recs[0]["attributes"]}']
    return []


# Without -q, a firing's trace() records are one line and a firing that
# traces nothing is recorded by its probe, as dtrace(1) prints them.
case('otel-json-trace-records', FAST + ['-x', 'otel=json', '-n',
                                        'test:kernel:alpha:entry { trace(arg0); trace(arg1); } '
                                        'test:kernel:beta:entry { }'],
     script=ANCHOR + ' ; go 1 test:kernel:alpha:entry n:7 n:8 ; go 1 test:kernel:beta:entry',
     signals=[('ROUND 2', signal.SIGINT)],
     stderr=matched('test:kernel:alpha:entry ', 2), check=otel_check(check_json_records))


def check_otlpjson_metrics(d, stdout):
    reqs = otlp_lines(d, d/'agg.jsonl')
    mets = otel_items(reqs, 'metrics')
    names = sorted(m['name'] for _, _, m in mets)
    if names != ['dtrace.agg.c']:
        return [f'metric names {names}']
    dp = mets[0][2]['sum']['dataPoints'][0]
    if dp['asInt'] != '1' or attrs(dp) != {'syscall': 'alpha'}:
        return [f'data point {dp}']
    return []


case('otel-otlpjson-aggregation', FAST + ['-x', 'otel=otlp-json', '-o', '{d}/agg.jsonl', '-s',
                                          '{d}/agg.d'],
     inputs={'agg.d': 'test:kernel:alpha:entry { @c[probefunc] = count(); }\n'},
     script=ANCHOR + ' ; go 0 test:kernel:alpha:entry n:1 s:alpha a:0:3',
     signals=[('ROUND 2', signal.SIGINT)], stdout='',
     stderr_re=r"dtrace: script '.*/agg.d' matched 1 probe\n",
     check=otel_check(check_otlpjson_metrics))


def check_siginfo(d, stdout):
    reqs = otlp_lines(d, d/'s.jsonl')
    mets = otel_items(reqs, 'metrics')
    if len(mets) < 2:
        return [f'expected a SIGINFO snapshot and the final one, got {len(mets)}']
    return []


case('otel-siginfo-snapshot', FAST + ['-x', 'otel=otlp-json', '-o', '{d}/s.jsonl', '-n',
                                      'test:kernel:alpha:entry { @c = count(); }'],
     script=ANCHOR + ' ; go 0 test:kernel:alpha:entry n:1 a:0:1',
     signals=[('ROUND 3', signal.SIGINFO), ('ROUND 6', signal.SIGINT)], stdout='',
     stderr=matched('test:kernel:alpha:entry ', 1), check=otel_check(check_siginfo))


def collector_env(statuses=''):
    """Start the loopback collector; point OTEL_* at it."""
    def env_fn(ctx, d):
        coll = d/'coll'
        coll.mkdir()
        args = [str(ctx.harness['otlp_collector']), '-o', str(coll), '-t', '30', '-n', '2']
        if statuses:
            args += ['-r', statuses]
        subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=open(coll/'stderr', 'w'))
        deadline = time.monotonic() + 10
        while not (coll/'port').exists() or not (coll/'port').read_text().strip():
            if time.monotonic() > deadline:
                break
            time.sleep(0.02)
        port = (coll/'port').read_text().strip()
        return {'OTEL_EXPORTER_OTLP_ENDPOINT': f'http://127.0.0.1:{port}',
                'OTEL_EXPORTER_OTLP_COMPRESSION': 'none',
                'OTEL_RESOURCE_ATTRIBUTES': 'deployment.environment.name=lab'}
    return env_fn


def check_http(d, stdout):
    coll = d/'coll'
    deadline = time.monotonic() + 10
    while not (coll/'2.json').exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    paths = sorted((coll/f'{n}.path').read_text().strip() for n in (1, 2))
    if paths != ['/v1/logs', '/v1/metrics']:
        return [f'paths {paths}']
    reqs = otlp_lines(d, coll/'1.json') + otlp_lines(d, coll/'2.json')
    logs = otel_items(reqs, 'logs')
    if not logs or logs[0][0].get('deployment.environment.name') != 'lab':
        return [f'resource {logs[:1]}']
    return []


case('otel-otlp-http', FAST + ['-q', '-x', 'otel=otlp', '-n',
                               'test:kernel:alpha:entry { printf("x\\n"); @c = count(); }'],
     env_fn=collector_env(), script=ANCHOR + ' ; go 0 test:kernel:alpha:entry n:0 n:1 a:0:1',
     signals=[('ROUND 2', signal.SIGINT)], stdout='', stderr='',
     check=otel_check(check_http))


def check_spool(d, stdout):
    reqs = otlp_lines(d, d/'spool.jsonl')
    if len(otel_items(reqs, 'logs')) != 1:
        return ['spool lacks the log batch']
    return []


# Port 9 on loopback refuses: the batch is spooled after the retries.
case('otel-otlp-spool', FAST + ['-q', '-x', 'otel=otlp', '-x', 'otelendpoint=http://127.0.0.1:9',
                                '-x', 'otelspool={d}/spool.jsonl', '-x', 'otelspoolmax=1m', '-n',
                                'BEGIN { printf("x\\n"); exit(0); }'],
     script=ANCHOR + ' ; go 0 dtrace:::BEGIN#1 n:0 n:0', stdout='',
     stderr_has=['otlp: spooled /v1/logs batch to'], check=otel_check(check_spool))


def check_rotated(d, stdout):
    first = otlp_lines(d, d/'r.jsonl.1')
    second = otlp_lines(d, d/'r.jsonl')
    if not first or not second:
        return ['rotation produced no records']
    return []


case('otel-otlpjson-rotate', FAST + ['-q', '-x', 'otel=otlp-json', '-x', 'otelrotatesize=1k',
                                     '-x', 'otelrotatekeep=2', '-x', 'otelrotatetime=1h',
                                     '-o', '{d}/r.jsonl', '-n',
                                     'test:kernel:alpha:entry { printf("line %d\\n", arg0); }'],
     # Three records at GO, written by the first once-a-second flush;
     # the fourth comes later and its write rotates.
     script=ANCHOR + ' ; ' + ' ; '.join(f'go 0 test:kernel:alpha:entry n:{i}' for i in range(3))
     + ' ; snap:2400 0 test:kernel:alpha:entry n:3',
     signals=[('ROUND 900', signal.SIGINT)], stdout='', stderr='',
     env={'OTEL_RESOURCE_ATTRIBUTES': 'k=' + 'v' * 900},
     check=otel_check(check_rotated))

for name, args, msg in (
        ('format', ['-x', 'otel=xml'], '-x otel=xml: expected otlp, otlp-json or json'),
        ('no-format', ['-x', 'otel'], '-x otel needs a format: otlp, otlp-json or json'),
        ('no-value', ['-x', 'otelendpoint'], '-x otelendpoint needs a value'),
        ('unknown', ['-x', 'otelbogus=1'], 'unknown OpenTelemetry option -x otelbogus'),
        ('badsize', ['-x', 'otel=otlp', '-x', 'otelspoolmax=9q'],
         '-x otelspoolmax expects a positive number with an optional unit suffix'),
        ('badtime', ['-x', 'otel=json', '-o', 'f', '-x', 'otelrotatetime=0'],
         '-x otelrotatetime expects a positive number with an optional unit suffix'),
        ('badrotsize', ['-x', 'otel=json', '-o', 'f', '-x', 'otelrotatesize=x'],
         '-x otelrotatesize expects a positive number with an optional unit suffix'),
        ('badkeep', ['-x', 'otel=json', '-o', 'f', '-x', 'otelrotatekeep=1000'],
         '-x otelrotatekeep expects 1 to 999'),
        ('without-otel', ['-x', 'otelspool=s'], '-x otel* options need -x otel'),
        ('otlp-file', ['-x', 'otel=otlp', '-o', 'f'],
         '-x otel=otlp sends to the collector; use -x otel=otlp-json to write a file'),
        ('otlp-rotate', ['-x', 'otel=otlp', '-x', 'otelrotatekeep=2'],
         '-x otelrotate* options need a file (-o)'),
        ('spoolmax-alone', ['-x', 'otel=otlp', '-x', 'otelspoolmax=1k'],
         '-x otelspoolmax needs -x otelspool'),
        ('json-endpoint', ['-x', 'otel=json', '-x', 'otelendpoint=http://h'],
         '-x otelendpoint and -x otelspool apply to -x otel=otlp only'),
        ('stdout-rotate', ['-x', 'otel=json', '-x', 'otelrotatesize=1k'],
         '-x otelrotate* options need a file (-o)'),
        ('list-mode', ['-x', 'otel=json', '-l'],
         '-x otel applies to tracing (not -A, -e, -G, -h, -l, -y or -Y)'),
        ('compile-only', ['-x', 'otel=json', '-e'],
         '-x otel applies to tracing (not -A, -e, -G, -h, -l, -y or -Y)'),
        ('buffered', ['-x', 'otel=json', '-B'], '-x otel is not valid with -B'),
        ('libxo', ['--libxo', 'json', '-x', 'otel=json'], '-x otel is not valid with --libxo')):
    # libxo closes its empty document even on a fatal exit.
    case(f'otel-usage-{name}', args + ['-n', 'BEGIN { exit(0); }'], status=1,
         stdout='{ }\n' if name == 'libxo' else '', stderr=f'dtrace: {msg}\n')

case('otel-output-unwritable', ['-x', 'otel=otlp-json', '-o', '{d}/absent/o', '-n',
                                'BEGIN { exit(0); }'], status=1, stdout='',
     stderr_has=['otelexport: {d}/absent/o: open failed: No such file or directory\n',
                 'dtrace: cannot open the OpenTelemetry output\n'])
case('otel-buffered-handler-fails', ['-x', 'otel=json', '-n', 'BEGIN { exit(0); }'],
     api_faults='dtrace_handle_buffered:1:5', status=1, stdout='',
     stderr_has=['dtrace: cannot start the OpenTelemetry exporter\n'])
case('otel-clock-compile-fails', ['-x', 'otel=json', '-n', 'BEGIN { exit(0); }'],
     api_faults='dtrace_program_strcompile:2:5', status=1, stdout='',
     stderr_has=['dtrace: cannot compile the probe clock program',
                 'dtrace: failed to start OpenTelemetry output\n'])
case('otel-clock-enable-fails', ['-x', 'otel=json', '-n', 'BEGIN { exit(0); }'],
     api_faults='dtrace_program_exec:1:5', status=1, stdout='',
     stderr_has=['dtrace: cannot enable the probe clock program',
                 'dtrace: failed to start OpenTelemetry output\n'])
# A failing final snapshot is an export failure: exit status 1.
case('otel-final-snapshot-fails', FAST + ['-q', '-x', 'otel=json', '-n',
                                          'BEGIN { @c = count(); exit(0); }'],
     script=ANCHOR + ' ; go 0 dtrace:::BEGIN#1 n:1 a:0:1 n:0',
     api_faults='dtrace_aggregate_snap:1:5',
     status=1, stdout='', stderr_has=['failed to export OpenTelemetry data\n'])
case('otel-drops', ['-b', '64', '-x', 'otel=json', '-x', 'switchrate=10ms', '-n',
                    ENTRY + ' { trace(arg0); }'],
     script=ANCHOR + ' ; ' + ';'.join(f'go 0 {ENTRY} n:{i}' for i in range(1, 5)),
     signals=[('ROUND 2', signal.SIGINT)], stderr_has=['drops on CPU 0'],
     check=lambda d, out, err, slog, dlog: [] if out.count('"body"') >= 1 else ['no records'])


# HyperTrace host consumer: the guest's records form their own resource
# (VM name, id and epoch from the received program, hypertrace.host.name the
# hypervisor), distinct from the host's; the host's probe clock is local to
# the consumer and never shipped through dtraced.
def check_guest_resource(d, stdout):
    reqs = otlp_lines(d, d/'otel.jsonl')
    logs = otel_items(reqs, 'logs')
    guests = [(r, i) for r, _, i in logs if r.get('hypertrace.vm.name') == 'vm3']
    if not guests:
        return [f'no guest records: {logs}']
    res, rec = guests[0]
    want = {'hypertrace.vm.id': '3', 'hypertrace.vm.epoch': '9', 'host.name': 'vm3'}
    if any(res.get(k) != v for k, v in want.items()) or 'host.id' in res or \
            not res.get('hypertrace.host.name'):
        return [f'guest resource {res}']
    if rec['body']['stringValue'] != '5':
        return [f'guest record {rec["body"]}']
    return []


host('otel-guest-resource', LOOP + 'sleep 300\n' + STOP_OK + 'hold\n',
     during=guest_runner(), extra=['-x', 'otel=otlp-json', '-o', '{d}/otel.jsonl'],
     script=ANCHOR + ' ; go 0 dtrace:::BEGIN#1 n:5', stderr_re=MATCHED3,
     daemon_has=['ACK delivery=5 vmid=3 epoch=9 outcome=2', 'STOP-REPLY result=1'],
     log_has=['VPROBE_CREATE vmid 3 epoch 9', 'ENABLE-GUEST vmid 3 epoch 9'],
     check=otel_check(check_guest_resource))
# A drain certifies once the exporter has taken (and synced) the records.
host('otel-drain', BASE + f'drain token={TOKEN}\n' + STOP_OK + 'hold\n',
     extra=['-x', 'otel=otlp-json', '-o', '{d}/d.jsonl'], stderr_re=MATCHED0,
     script=ANCHOR + ' ; go 0 dtrace:::BEGIN#1 n:1',
     daemon_has=['DRAIN-REPLY result=1 echo=1', 'STOP-REPLY result=1'],
     check=otel_check(lambda d, out: [] if otel_items(otlp_lines(d, d/'d.jsonl'), 'logs')
                      else ['drained records missing']))
# Like any failure to enable a received program, the consumer stops.
host('otel-clock-fails-on-receive', BASE + 'hold\n', extra=['-x', 'otel=json'],
     api_faults='dtrace_program_strcompile:2:5',
     stderr_has=['dtrace: cannot compile the probe clock program'])
host('otel-drain-gate-released', BASE + f'drain token={TOKEN}\n' + STOP_OK + END_ON_SIGNAL,
     extra=['-x', 'otel=otlp-json', '-o', '{d}/d.jsonl'], gate=f'held:{TOKEN}:1',
     signals=[('STOP-REPLY', signal.SIGINT)], stdout='',
     stderr_re=all_of(MATCHED0, RECONNECTING),
     daemon_has=['DRAIN-REPLY result=0', 'STOP-REPLY result=0'])
# The rotation fails (the directory turns read-only during the run): the
# once-a-second flush reports it and the run exits 1.
def lock_dir_when_written(ctx, d, env, deadline):
    while not (d/'out'/'f.jsonl').exists() or (d/'out'/'f.jsonl').stat().st_size == 0:
        if time.monotonic() > deadline:
            return ['output never written']
        time.sleep(0.02)
    (d/'out').chmod(0o555)
    return []


case('otel-rotate-fails', FAST + ['-q', '-x', 'otel=otlp-json', '-x', 'otelrotatesize=1',
                                  '-o', '{d}/out/f.jsonl', '-n',
                                  'test:kernel:alpha:entry { printf("x\\n"); }'],
     setup=lambda d: (d/'out').mkdir(), during=lock_dir_when_written,
     # One record at GO, another after a second (pass 150): two
     # once-a-second writes, the second of which rotates.
     script=ANCHOR + ' ; go 0 test:kernel:alpha:entry n:0 ; snap:2400 0 '
     'test:kernel:alpha:entry n:1',
     signals=[('ROUND 900', signal.SIGINT)], status=1, stdout='',
     stderr_has=['f.jsonl: rotate failed: Permission denied\n',
                 'failed to export OpenTelemetry data\n'])
# The script text is read again for aggregation key names; if that fails
# the keys are numbered instead.
case('otel-script-reread-fails', FAST + ['-x', 'otel=json', '-s', '{d}/k.d'],
     inputs={'k.d': 'BEGIN { exit(0); }\n'}, faults='fopen:2:2',
     script=ANCHOR + ' ; go 0 dtrace:::BEGIN#1 n:0',
     stdout_has=['"profile":"k","probe":"dtrace:::BEGIN"'],
     stderr_re=r"dtrace: script '.*/k.d' matched 1 probe\n")
# A script name without a suffix names the records as it is.
case('otel-script-no-suffix', FAST + ['-q', '-x', 'otel=json', '-s', '{d}/plain'],
     inputs={'plain': 'BEGIN { printf("p\\n"); exit(0); }\n'},
     script=ANCHOR + ' ; go 0 dtrace:::BEGIN#1 n:0 n:0', stderr='',
     stdout_has=['"profile":"plain"'])
case('otel-no-program', ['-x', 'otel=json'], status=1, stdout='',
     stderr='dtrace: no probes specified\n')
case('otel-usage-guest', ['-x', 'otel=json', '-y', '{d}/none.elf'], status=1, stdout='',
     stderr_has=['dtrace: -x otel applies to tracing (not -A, -e, -G, -h, -l, -y or -Y)\n'])
case('otel-usage-guest-hypertrace', ['-x', 'otel=json', '-Y', '{d}/none.elf'], status=1,
     stdout='', stderr_has=['dtrace: -x otel applies to tracing (not -A, -e, -G, -h, -l, -y or -Y)\n'])
# A script whose name starts with its only dot keeps it.
case('otel-script-dotfile', FAST + ['-q', '-x', 'otel=json', '-s', '{d}/.hidden'],
     inputs={'.hidden': 'BEGIN { printf("h\\n"); exit(0); }\n'},
     script=ANCHOR + ' ; go 0 dtrace:::BEGIN#1 n:0 n:0', stderr='',
     stdout_has=['"profile":".hidden"'])
# Collecting the D text for key names runs out of memory: a clear error.
case('otel-source-alloc-fails', ['-x', 'otel=json', '-n', 'BEGIN { exit(0); }'],
     faults='realloc:1:12', status=1, stdout='',
     stderr_has=['dtrace: failed to allocate memory'])
case('exec-oformat-siginfo', FAST + ['--libxo', 'json', '-n',
                                     'test:kernel:alpha:entry { @c = count(); }'],
     script='go 0 test:kernel:alpha:entry n:1 a:0:1',
     signals=[('ROUND 3', signal.SIGINFO), ('ROUND 6', signal.SIGINT)],
     stderr=matched('test:kernel:alpha:entry ', 1), stdout_has=['"probes"'])
