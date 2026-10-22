#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Link a broad corpus of valid D programs through the HyperTrace linker.

Each case compiles with the actual libdtrace (NODEV; the host's kernel CTF is
read from disk, and its hash is recorded), runs hypertrace_link(), and
creates DOF.  A valid program must link with an empty message and yield
structurally valid DOF; dt_set_progerr() terminates the process on a typing
error, so each case runs in its own child and a crash or exit is a failure.
The 'no-kernel-ctf' cases use linker-offline.py's empty module inventory (a
kldnext() shim) so that no kernel type file exists, and check that this is
reported instead of dereferenced.  No tracing device, kernel module load or VM is used.
"""
from pathlib import Path
import ctypes as C
import hashlib
import json
import os
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dof_validation import validate_dof  # noqa: E402

B = 'BEGIN '
CASES = {
    # Arithmetic, logical and comparison operators.
    'ops-arith': B + '{ x = timestamp; trace(x * 3 + x / 7 - x % 5); }',
    'ops-bits': B + '{ x = timestamp; trace((x & 0xff) | (x ^ 3) << 2 >> 1); }',
    'ops-unary': B + '{ x = (int)timestamp; trace(-x); trace(~x); trace(!x); }',
    'ops-compare': B + '{ x = timestamp; trace(x < 1); trace(x <= 2); '
                   'trace(x > 3); trace(x >= 4); trace(x == 5); trace(x != 6); }',
    'ops-logical': B + '{ x = timestamp; trace(x && pid || tid ^^ 1); }',
    'ops-ternary': B + '{ x = timestamp; trace(x > 2 ? "big" : "small"); }',
    'ops-signed': B + '{ x = (int8_t)timestamp; y = (uint16_t)x; '
                  'trace((int64_t)y * -1); }',
    'ops-sizeof': B + '{ trace(sizeof (struct thread)); trace(sizeof (int)); }',
    'ops-offsetof': B + '{ trace(offsetof(struct proc, p_pid)); }',
    # Variables of every scope and kind.
    'var-global': B + '{ g = 1; g = g + 2; trace(g); }',
    'var-thread': B + '{ self->t = pid; self->t++; trace(self->t); self->t = 0; }',
    'var-clause': B + '{ this->c = timestamp; trace(this->c); }',
    'var-global-string': B + '{ gs = execname; trace(gs); }',
    'var-assoc-global': B + '{ a[pid, execname] = 3; trace(a[pid, execname]); }',
    'var-assoc-thread': B + '{ self->a[tid] = 4; trace(self->a[tid]); '
                        'self->a[tid] = 0; }',
    'var-assoc-string': B + '{ s[execname] = "v"; trace(s[execname]); }',
    'var-across-clauses': B + '{ shared = 5; } END { trace(shared); }',
    'var-struct-copy': 'struct pt { int x; int y; }; struct pt g; '
                       + B + '{ g.x = 1; g.y = g.x + 1; trace(g.y); }',
    'var-array': 'int arr[4]; ' + B + '{ arr[2] = 7; trace(arr[2]); }',
    'var-pointer-local': B + '{ this->p = curthread; trace(this->p->td_tid); }',
    # Built-in variables.
    'builtin-ids': B + '{ trace(pid); trace(ppid); trace(tid); trace(uid); '
                   'trace(gid); trace(cpu); }',
    'builtin-time': B + '{ trace(timestamp); trace(vtimestamp); '
                    'trace(walltimestamp); }',
    'builtin-strings': B + '{ trace(execname); trace(probeprov); '
                       'trace(probemod); trace(probefunc); trace(probename); }',
    'builtin-args': B + '{ trace(arg0 + arg1 + arg9); trace(epid); trace(id); }',
    'builtin-ipl': B + '{ trace(ipl); trace(stackdepth); trace(errno); }',
    'builtin-curthread': B + '{ trace(curthread->td_tid); '
                         'trace(curthread->td_proc->p_pid); }',
    'builtin-curpsinfo': B + '{ trace(curpsinfo->pr_pid); '
                         'trace(curpsinfo->pr_psargs); }',
    # Subroutines with kernel return types.
    'subr-strlen': B + '{ trace(strlen(execname)); }',
    'subr-strjoin': B + '{ trace(strjoin(execname, "-x")); }',
    'subr-substr': B + '{ trace(substr(execname, 1, 3)); }',
    'subr-index': B + '{ trace(index(execname, "a")); trace(rindex(execname, "a")); }',
    'subr-strchr': B + '{ trace(strchr(execname, 0x61)); trace(strrchr(execname, 0x61)); }',
    'subr-strstr': B + '{ trace(strstr(execname, "a")); }',
    'subr-strtok': B + '{ trace(strtok(execname, "/")); }',
    'subr-toupper': B + '{ trace(toupper(execname)); trace(tolower(execname)); }',
    'subr-basename': B + '{ trace(basename("/a/b")); trace(dirname("/a/b")); '
                     'trace(cleanpath("/a/../b")); }',
    'subr-lltostr': B + '{ trace(lltostr(timestamp)); trace(strtoll("12")); }',
    'subr-inet': B + '{ trace(inet_ntoa((in_addr_t *)arg0)); '
                 'trace(inet_ntoa6((struct in6_addr *)arg0)); }',
    'subr-ntoh': B + '{ trace(htons(1)); trace(htonl(1)); trace(htonll(1)); '
                 'trace(ntohs(1)); trace(ntohl(1)); trace(ntohll(1)); }',
    'subr-rand': B + '{ trace(rand()); trace(random()); }',
    'subr-copyin': B + '{ trace(*(int *)copyin(arg0, 4)); }',
    'subr-copyinstr': B + '{ trace(copyinstr(arg0)); trace(copyinstr(arg0, 8)); }',
    'subr-copyinto': B + '{ this->b = (int *)alloca(4); copyinto(arg0, 4, this->b); '
                     'trace(*this->b); }',
    'subr-alloca-bcopy': B + '{ this->p = (char *)alloca(8); '
                         'bcopy(execname, this->p, 4); trace(this->p[0]); }',
    'subr-speculation': B + '{ self->spec = speculation(); speculate(self->spec); '
                        'trace(1); } END { commit(self->spec); }',
    'subr-mutex': B + '{ trace(mutex_owned((struct mtx *)arg0)); }',
    'subr-progenyof': B + '{ trace(progenyof(1)); }',
    'subr-getmajor': B + '{ trace(strtoll("7", 8)); }',
    'subr-memref': B + '{ trace(memref(&`ticks, 4)); }',
    'subr-json': B + '{ trace(json("{\\"a\\":1}", "a")); }',
    # Actions and aggregations.
    'act-printf': B + '{ printf("%s %d %x\\n", execname, pid, tid); }',
    'act-aggregations': B + '{ @c[execname] = count(); @s[pid] = sum(arg0); '
                        '@mn = min(arg0); @mx = max(arg0); @a = avg(arg0); '
                        '@sd = stddev(arg0); }',
    'act-histograms': B + '{ @q = quantize(arg0); @l = lquantize(arg0, 0, 100, 10); '
                      '@ll = llquantize(arg0, 10, 0, 6, 20); }',
    'act-printa': B + '{ @c[execname] = count(); printa("%s %@d\\n", @c); '
                  'trunc(@c, 1); clear(@c); normalize(@c, 2); denormalize(@c); }',
    'act-stack': B + '{ stack(); stack(4); ustack(); ustack(2, 16); }',
    'act-syms': B + '{ sym(arg0); mod(arg0); usym(arg0); umod(arg0); uaddr(arg0); }',
    'act-tracemem': B + '{ tracemem(arg0, 16); }',
    'act-exit': B + '{ exit(0); }',
    'act-predicates': B + '/pid != 0 && execname != "x"/ { trace(1); }',
    'act-print': 'struct pf { int a; long b; }; '
                 + B + '{ print(*(struct pf *)arg0); }',
    'act-setopt': B + '{ setopt("quiet"); }',
    # Strings and casts.
    'cast-pointer': B + '{ trace((uintptr_t)curthread); trace((char *)arg0); }',
    'string-compare': B + '{ trace(execname == "init"); trace(execname < "z"); }',
    'string-literal-concat': B + '{ x = "abc"; y = strjoin(x, x); trace(y); }',
    'translator': B + '{ trace(xlate <psinfo_t *> '
                  '(curthread->td_proc)->pr_pid); }',
    # Control flow (D if/else).
    'flow-if': B + '{ if (pid > 1) { trace(1); } else { trace(2); } }',
    'flow-nested-if': B + '{ x = timestamp; if (x > 1) { if (x > 2) { trace(3); } } }',
}


def child(binary, name, nosys):
    lib = C.CDLL(str(binary))
    lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
    lib.dtrace_open.restype = C.c_void_p
    lib.dtrace_close.argtypes = [C.c_void_p]
    lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int,
                                              C.c_uint, C.c_int, C.c_void_p]
    lib.dtrace_program_strcompile.restype = C.c_void_p
    lib.hypertrace_link.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
    lib.hypertrace_link.restype = C.c_int
    lib.dtrace_dof_create.argtypes = [C.c_void_p, C.c_void_p, C.c_uint]
    lib.dtrace_dof_create.restype = C.c_void_p
    lib.dtrace_dof_destroy.argtypes = [C.c_void_p, C.c_void_p]
    lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]
    lib.dtrace_errmsg.restype = C.c_char_p
    lib.dtrace_errno.argtypes = [C.c_void_p]
    error = C.c_int()
    # NODEV, plus NOSYS for the missing-kernel-CTF cases.
    h = lib.dtrace_open(3, 3 if nosys else 1, C.byref(error))
    assert h, error.value
    prog = (CASES | NOSYS_CASES)[name]
    p = lib.dtrace_program_strcompile(h, prog.encode(), 4, 0x1004, 0, None)
    if not p:
        print('COMPILE-ERROR:', lib.dtrace_errmsg(h, lib.dtrace_errno(h)).decode())
        raise SystemExit(4)
    message = C.create_string_buffer(512)
    result = lib.hypertrace_link(h, p, message)
    print('LINK:', result, message.value.decode(errors='replace'), flush=True)
    if result != 0 or message.value:
        raise SystemExit(5)
    dof = lib.dtrace_dof_create(h, p, 1)
    assert dof
    size = struct.unpack_from('<Q', C.string_at(dof, 64), 48)[0]
    assert 64 <= size <= 64 * 1024 * 1024
    validate_dof(C.string_at(dof, size))
    lib.dtrace_dof_destroy(h, dof)
    lib.dtrace_close(h)
    print('PASS:', name)


# Without kernel CTF, a subroutine's return type cannot be resolved; the
# linker must return it as a program error (status 5 here: a failed link
# with the message) rather than crash or end the process.  A program
# without subroutines still links.
NOSYS_CASES = {
    'no-kernel-ctf-subr': B + '{ trace(strlen(execname)); }',
    'no-kernel-ctf-plain': B + '{ trace(1); }',
}
NOSYS_EXPECT = {
    'no-kernel-ctf-subr': (5, 'strlen(): kernel type information is unavailable'),
    'no-kernel-ctf-plain': (0, 'PASS: no-kernel-ctf-plain'),
}

if len(sys.argv) == 5 and sys.argv[1] == '--child':
    child(Path(sys.argv[2]), sys.argv[3], sys.argv[4] == 'nosys')
    raise SystemExit(0)
if len(sys.argv) != 3:
    raise SystemExit('usage: linker-corpus.py /usr/obj/output /usr/obj/matched-objtop')
out, world = (Path(x).resolve() for x in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, world)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and an existing object tree')
out.mkdir(parents=True)
binary = world / 'cddl/lib/libdtrace/libdtrace.so.2'
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(world / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
kernel = Path('/boot/kernel/kernel')
shim_source = out / 'no-modules.c'
shim_source.write_text('/* Test boundary: an empty host module inventory. */\n'
                       'int kldnext(int id) { (void)id; return 0; }\n')
shim = out / 'no-modules.so'
subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                str(shim_source), '-o', str(shim)], check=True)
nosys_env = env | {'LD_PRELOAD': str(shim)}
results = []
for name in list(CASES) + list(NOSYS_CASES):
    nosys = name in NOSYS_CASES
    try:
        r = subprocess.run([sys.executable, __file__, '--child', str(binary), name,
                            'nosys' if nosys else 'kernel'],
                           env=nosys_env if nosys else env,
                           capture_output=True, text=True, timeout=120)
        text = r.stdout + r.stderr
        status = r.returncode
    except subprocess.TimeoutExpired:
        text, status = 'timeout', 'timeout'
    (out / (name + '.log')).write_text(text)
    if nosys:
        want_status, want_text = NOSYS_EXPECT[name]
        passed = status == want_status and want_text in text
    else:
        passed = status == 0 and 'PASS: ' + name in text
    results.append({'case': name, 'status': status, 'passed': passed})
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({
    'sha256': {str(p): sha(p) for p in (binary, Path(__file__).resolve(), kernel)},
    'device_mode': 'NODEV (kernel CTF read from /boot/kernel); NODEV|NOSYS for '
                   'no-kernel-ctf cases', 'separate_process_per_case': True,
    'live': False}, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r))
if failed:
    raise SystemExit(1)
print(f'PASS: {len(results)} HyperTrace link cases')
