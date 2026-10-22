# SPDX-License-Identifier: BSD-2-Clause
"""Shared pieces of the frontend-codegen suites.

* build(): compiles frontend-codegen.c with libdtrace's own CFLAGS against the
  library under test (the C driver compiles D offline through dtrace_vopen()
  and a modeled dtrace(4) vector, then dumps each statement's DIF as JSON).
* compile_cases(): runs the driver over a list of cases.
* DIF: an independent DIF interpreter written from the DIF ISA comments in
  sys/dtrace.h and the kernel emulator (dtrace_dif_emulate) semantics: 64-bit
  registers with %r0 = 0, condition codes from CMP/SCMP/TST, branch
  conditions as in the kernel, sign/zero-extending loads, the tuple stack,
  global/thread-local/clause-local variables and associative arrays, scratch
  allocation, and the subset of subroutines the suites use, each implemented
  from its documented D semantics.  The 5BSD relocation pseudo-ops TYPECAST
  (a typing annotation the linker replaces with NOP) is a no-op; USETX and
  ULOAD/UULOAD are never expected in these programs (all types are D-local)
  and raise.
"""
from pathlib import Path
import hashlib
import json
import os
import struct
import subprocess

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parents[2]
M64 = (1 << 64) - 1

ACT = dict(DIFEXPR=1, EXIT=2, PRINTF=3, PRINTA=4, LIBACT=5, TRACEMEM=6,
           TRACEMEM_DYNSIZE=7, PRINTM=8, PRINTIMMSTACK=9, USTACK=0x101,
           JSTACK=0x102, USYM=0x103, UMOD=0x104, UADDR=0x105, STOP=0x201,
           RAISE=0x202, SYSTEM=0x203, FREOPEN=0x204, STACK=0x401, SYM=0x402,
           MOD=0x403, IMMSTACK=0x404, BREAKPOINT=0x501, PANIC=0x502,
           CHILL=0x503, SPECULATE=0x601, COMMIT=0x602, DISCARD=0x603)
AGG = dict(COUNT=0x701, MIN=0x702, MAX=0x703, AVG=0x704, SUM=0x705,
           STDDEV=0x706, QUANTIZE=0x707, LQUANTIZE=0x708, LLQUANTIZE=0x709)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def check_args(argv, kind):
    if len(argv) != 3:
        raise SystemExit(f'usage: {argv[0]} /usr/obj/new-output /usr/obj/.../amd64.amd64')
    out, obj = (Path(a).resolve() for a in argv[1:])
    if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
        raise SystemExit('Use a new /usr/obj output and an existing object tree')
    out.mkdir(parents=True)
    return out, obj


def build(out, obj, source='frontend-codegen.c', sanitize=True, extra=()):
    """Compile a C driver with libdtrace's CFLAGS; return its path."""
    lib = obj / 'cddl/lib/libdtrace'
    prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
    cflags = subprocess.run(
        ['make', '-C', str(ROOT / 'cddl/lib/libdtrace'), '-m', str(ROOT / 'share/mk'),
         'SRCTOP=' + str(ROOT), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
         '-V', 'CFLAGS'], env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)},
        capture_output=True, text=True, check=True).stdout.split()
    keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
    exe = out / Path(source).stem
    source = TESTS / source
    san = ['-fsanitize=address,undefined', '-fno-sanitize-recover=undefined'] if sanitize else []
    command = ['cc', *keep, '-g', '-O1', *san, '-Wall', '-Wno-unknown-pragmas', *extra,
               str(source), '-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace',
               '-lctf', '-lelf', '-o', str(exe)]
    b = subprocess.run(command, capture_output=True, text=True)
    (out / f'build-{exe.name}.log').write_text(' '.join(command) + '\n' + b.stdout + b.stderr)
    if b.returncode:
        raise SystemExit(f'driver compilation failed; inspect build-{exe.name}.log')
    return exe


FAKEMOD_SRC = r'''
struct kobj { int a; long b; unsigned char c; };
struct kobj fake_kobj = { 1, 2, 3 };
int fake_var[4] = { 1, 2, 3, 4 };
long fake_long = 0x1122334455667788L;
int fake_func(int x) { return x + fake_var[0]; }
'''


def build_fakemod(out):
    """A small ELF shared object whose symbol table backs the driver's
    offline kernel/user modules (fakek, fakel, fakeu)."""
    src = out / 'fakemod.c'
    src.write_text(FAKEMOD_SRC)
    so = out / 'fakemod.so'
    o = out / 'fakemod.o'
    # One compilation unit with CTF (ctfconvert, then ctfmerge into the
    # shared object) so the offline modules carry type information.
    subprocess.run(['cc', '-c', '-fPIC', '-g', '-O0', '-o', str(o), str(src)], check=True)
    subprocess.run(['ctfconvert', '-L', 'fakemod', str(o)], check=True)
    subprocess.run(['cc', '-shared', '-nostdlib', '-o', str(so), str(o)], check=True)
    subprocess.run(['ctfmerge', '-L', 'fakemod', '-o', str(so), str(o)], check=True)
    syms = {}
    for line in subprocess.run(['nm', '-S', str(so)], capture_output=True, text=True,
                               check=True).stdout.splitlines():
        f = line.split()
        if len(f) == 4 and f[3] in ('fake_var', 'fake_long', 'fake_func', 'fake_kobj'):
            syms[f[3]] = (int(f[0], 16), int(f[1], 16))
    os.environ['FRONTEND_FAKEMOD'] = str(so)
    return syms


def env_for(obj):
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
        ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
    env['ASAN_OPTIONS'] = 'detect_leaks=0'
    env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
    # libdtrace aborts on a register left allocated after code generation
    # (dt_regset_assert_free) when this is set: every compile is checked.
    env['DTRACE_DEBUG_REGSET'] = '1'
    return env


def compile_cases(exe, obj, out, cases, tag='cases'):
    """cases: list of dicts {name, prog, cflags=0, spec=4, opts=[]}.

    Returns {name: result dict}."""
    text = []
    for c in cases:
        opts = ','.join(c.get('opts', [])) or '-'
        assert ' ' not in opts and '\n' not in c['name']
        text.append(f"@@case {c['name']} {c.get('cflags', 0):x} {c.get('spec', 4)} {opts}\n{c['prog']}")
    src = out / f'{tag}.txt'
    src.write_text('\n'.join(text) + '\n')
    res = out / f'{tag}.jsonl'
    tmp = out / f'{tag}-tmp'
    tmp.mkdir(exist_ok=True)
    r = subprocess.run([str(exe), str(src), str(res), str(tmp)], env=env_for(obj),
                       capture_output=True, text=True, timeout=1800, cwd=out)
    (out / f'{tag}.log').write_text(r.stdout + r.stderr)
    if r.returncode:
        raise SystemExit(f'driver failed ({r.returncode}); inspect {tag}.log')
    got = {}
    for line in res.read_text().splitlines():
        d = json.loads(line)
        got[d['case']] = d
    missing = [c['name'] for c in cases if c['name'] not in got]
    if missing:
        raise SystemExit(f'driver produced no result for {missing[:5]}')
    return got


def finish(out, results, files, scope, label):
    (out / 'results.json').write_text(json.dumps(results, indent=1) + '\n')
    (out / 'provenance.json').write_text(json.dumps({
        'sha256': {str(p): sha(p) for p in files}, 'scope': scope}, indent=2) + '\n')
    failed = [r for r in results if not r['passed']]
    for r in failed[:60]:
        print('FAIL', json.dumps(r)[:600])
    if failed:
        raise SystemExit(f'{len(failed)} of {len(results)} {label} failed')
    print('PASS:', len(results), label)


# --------------------------------------------------------------------------
# DIF interpreter

OP = {n: i for i, n in enumerate(
    'NONE OR XOR AND SLL SRL SUB ADD MUL SDIV UDIV SREM UREM NOT MOV CMP TST '
    'BA BE BNE BG BGU BGE BGEU BL BLU BLE BLEU LDSB LDSH LDSW LDUB LDUH LDUW '
    'LDX RET NOP SETX SETS SCMP LDGA LDGS STGS LDTA LDTS STTS SRA CALL PUSHTR '
    'PUSHTV POPTS FLUSHTS LDGAA LDTAA STGAA STTAA LDLS STLS ALLOCS COPYS STB '
    'STH STW STX ULDSB ULDSH ULDSW ULDUB ULDUH ULDUW ULDX RLDSB RLDSH RLDSW '
    'RLDUB RLDUH RLDUW RLDX XLATE XLARG HYPERCALL USETX ULOAD UULOAD '
    'TYPECAST'.split())}
NAME = {v: k for k, v in OP.items()}
SUBR = {n: i for i, n in enumerate(
    'rand mutex_owned mutex_owner mutex_type_adaptive mutex_type_spin '
    'rw_read_held rw_write_held rw_iswriter copyin copyinstr speculation '
    'progenyof strlen copyout copyoutstr alloca bcopy copyinto msgdsize '
    'msgsize getmajor getminor ddi_pathname strjoin lltostr basename dirname '
    'cleanpath strchr strrchr strstr strtok substr index rindex htons htonl '
    'htonll ntohs ntohl ntohll inet_ntop inet_ntoa inet_ntoa6 toupper tolower '
    'memref sx_shared_held sx_exclusive_held sx_isexclusive memstr getf json '
    'strtoll random ptinfo'.split())}

BUILTIN = {0x101: 'timestamp', 0x102: 'vtimestamp', 0x103: 'ipl', 0x104: 'epid',
           0x105: 'id', 0x110: 'stackdepth', 0x111: 'caller', 0x112: 'probeprov',
           0x113: 'probemod', 0x114: 'probefunc', 0x115: 'probename', 0x116: 'pid',
           0x117: 'tid', 0x118: 'execname', 0x119: 'zonename', 0x11a: 'walltimestamp',
           0x11b: 'ustackdepth', 0x11c: 'ucaller', 0x11d: 'ppid', 0x11e: 'uid',
           0x11f: 'gid', 0x120: 'errno', 0x100: 'curthread', 0x14f: 'cpu'}
STRING_BUILTINS = {'probeprov', 'probemod', 'probefunc', 'probename', 'execname',
                   'zonename'}


class DIFError(Exception):
    pass


def s64(v):
    v &= M64
    return v - (1 << 64) if v >> 63 else v


def ext(v, size, signed):
    v &= (1 << (8 * size)) - 1
    if signed and v >> (8 * size - 1):
        v -= 1 << (8 * size)
    return v


class Machine:
    """State shared across DIFO executions of one probe firing (variables,
    memory).  'env' supplies argument values and built-in variables."""
    STR = 0x10000000
    SCRATCH = 0x20000000
    VARS = 0x30000000
    KMEM = 0x40000000

    def __init__(self, env=None, strsize=256):
        self.env = dict(env or {})
        self.mem = {}
        self.globals, self.tls, self.locals = {}, {}, {}
        self.assoc = {}
        self.scratch = self.SCRATCH
        self.varbrk = self.VARS
        self.strsize = strsize
        self.kbrk = self.KMEM
        self.spec = 0
        self.strcache = {}

    # memory -------------------------------------------------------------
    def write(self, addr, data):
        for i, b in enumerate(data):
            self.mem[addr + i] = b

    def read(self, addr, n):
        try:
            return bytes(self.mem[addr + i] for i in range(n))
        except KeyError:
            raise DIFError(f'load from unmapped address {addr:#x}')

    def load(self, addr, size, signed):
        return ext(int.from_bytes(self.read(addr, size), 'little'), size, signed) & M64

    def cstr(self, addr, limit=None):
        if addr == 0:
            raise DIFError('NULL string')
        limit = self.strsize if limit is None else limit
        out = bytearray()
        while len(out) < limit:
            b = self.mem.get(addr + len(out))
            if b is None:
                raise DIFError(f'string runs into unmapped memory at {addr + len(out):#x}')
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def alloc(self, n, data=None):
        p = (self.scratch + 7) & ~7
        self.scratch = p + max(n, 1)
        self.write(p, data if data is not None else bytes(n))
        return p

    def newstr(self, s):
        if isinstance(s, str):
            s = s.encode()
        s = s[:self.strsize - 1] if len(s) >= self.strsize else s
        # Strings live in buffers of the string size, as in scratch space.
        return self.alloc(self.strsize, s + b'\0' * (self.strsize - len(s)))

    def kobj(self, data):
        """Place 'kernel' data and return its address."""
        p = (self.kbrk + 15) & ~15
        self.kbrk = p + len(data) + 16
        self.write(p, data)
        return p

    def varstore(self, size):
        p = (self.varbrk + 7) & ~7
        self.varbrk = p + max(size, 8)
        self.write(p, bytes(max(size, 8)))
        return p


def run_difo(m, d, maxsteps=200000):
    """Execute one dumped DIFO on Machine m; return the raw 64-bit result."""
    buf = d['buf']
    inttab = [int(x) for x in d['int']]
    strtab = d['str'].encode('latin-1')
    key = ('strtab', id(d))
    if key not in m.strcache:
        base = m.alloc(len(strtab) + m.strsize, strtab + b'\0' * m.strsize)
        m.strcache[key] = base
    sbase = m.strcache[key]
    vartab = {}
    for name, vid, kind, scope, flags, t in d['var']:
        vartab[(vid, scope, kind)] = t
    regs = [0] * 8
    tup = []
    cc = dict(n=0, z=0, v=0, c=0)
    pc = 0
    steps = 0

    def vtype(vid, scope, kind):
        return vartab.get((vid, scope, kind), [0, 0, 0, 8])

    def keyof(t):
        return tuple(t)

    while pc < len(buf):
        steps += 1
        if steps > maxsteps:
            raise DIFError('step limit')
        ins = buf[pc]
        pc += 1
        op = (ins >> 24) & 0xff
        r1, r2, rd = (ins >> 16) & 0xff, (ins >> 8) & 0xff, ins & 0xff
        var = (ins >> 8) & 0xffff
        name = NAME.get(op)
        if name is None:
            raise DIFError(f'bad opcode {op}')
        R = lambda i: 0 if i == 0 else regs[i]

        def W(i, v):
            if i >= 8:
                raise DIFError('bad register')
            if i != 0:
                regs[i] = v & M64
        if name in ('OR', 'XOR', 'AND', 'SUB', 'ADD', 'MUL'):
            a, b = R(r1), R(r2)
            W(rd, {'OR': a | b, 'XOR': a ^ b, 'AND': a & b, 'SUB': a - b,
                   'ADD': a + b, 'MUL': a * b}[name])
        elif name == 'SLL':
            W(rd, R(r1) << (R(r2) & 63))
        elif name == 'SRL':
            W(rd, R(r1) >> (R(r2) & 63))
        elif name == 'SRA':
            W(rd, s64(R(r1)) >> (R(r2) & 63))
        elif name in ('SDIV', 'UDIV', 'SREM', 'UREM'):
            a, b = R(r1), R(r2)
            if b == 0:
                raise DIFError('divide by zero')
            if name[0] == 'S':
                sa, sb = s64(a), s64(b)
                q = abs(sa) // abs(sb) * (1 if (sa < 0) == (sb < 0) else -1)
                W(rd, q if name == 'SDIV' else sa - q * sb)
            else:
                W(rd, a // b if name == 'UDIV' else a % b)
        elif name == 'NOT':
            W(rd, ~R(r1))
        elif name == 'MOV':
            W(rd, R(r1))
        elif name == 'CMP':
            a, b = R(r1), R(r2)
            # Signed conditions use n ^ v of the 64-bit subtraction, with v
            # the two's complement overflow (DIF ISA: signed branches).
            r = s64(a - b)
            ov = int((s64(a) - s64(b)) != r)
            cc = dict(n=int(r < 0), z=int(r == 0), v=ov, c=int(a < b))
        elif name == 'SCMP':
            a, b = R(r1), R(r2)
            sa = m.cstr(a) if a else b''
            sb = m.cstr(b) if b else b''
            r = (sa > sb) - (sa < sb)
            cc = dict(n=int(r < 0), z=int(r == 0), v=0, c=0)
        elif name == 'TST':
            cc = dict(n=0, z=int(R(r1) == 0), v=0, c=0)
        elif name.startswith('B'):
            n, z, v, c = cc['n'], cc['z'], cc['v'], cc['c']
            take = {'BA': 1, 'BE': z, 'BNE': not z, 'BG': not (z | (n ^ v)),
                    'BGU': not (c | z), 'BGE': not (n ^ v), 'BGEU': not c,
                    'BL': n ^ v, 'BLU': c, 'BLE': z | (n ^ v), 'BLEU': c | z}[name]
            if take:
                pc = ins & 0xffffff
        elif name in ('LDSB', 'LDSH', 'LDSW', 'LDUB', 'LDUH', 'LDUW', 'LDX',
                      'ULDSB', 'ULDSH', 'ULDSW', 'ULDUB', 'ULDUH', 'ULDUW', 'ULDX',
                      'RLDSB', 'RLDSH', 'RLDSW', 'RLDUB', 'RLDUH', 'RLDUW', 'RLDX'):
            base = name[1:] if name[0] in 'UR' else name
            size = {'B': 1, 'H': 2, 'W': 4, 'X': 8}[base[-1]]
            signed = base[2] == 'S' if base != 'LDX' else False
            W(rd, m.load(R(r1), size, signed))
        elif name == 'RET':
            return R(rd)
        elif name in ('NOP', 'TYPECAST'):
            pass
        elif name == 'SETX':
            W(rd, inttab[var])
        elif name == 'SETS':
            W(rd, sbase + var)
        elif name == 'LDGA':
            if r1 not in (0, 1, 2):
                raise DIFError(f'LDGA of array {r1}')
            args = m.env.get(('args', 'regs', 'uregs')[r1], [])
            i = R(r2)
            W(rd, args[i] if i < len(args) else 0)
        elif name == 'LDGS':
            if var >= 0x500:
                t = vtype(var, 0, 1)
                if t[2] & 1:
                    W(rd, m.globals.setdefault(var, m.varstore(t[3] or m.strsize)))
                else:
                    W(rd, m.globals.get(var, 0))
            else:
                W(rd, builtin(m, var))
        elif name in ('STGS', 'STTS', 'STLS'):
            scope = {'STGS': 0, 'STTS': 1, 'STLS': 2}[name]
            store = {'STGS': m.globals, 'STTS': m.tls, 'STLS': m.locals}[name]
            t = vtype(var, scope, 1)
            if t[2] & 1:
                size = t[3] if t[0] != 1 else (t[3] or m.strsize)
                if R(rd) == 0:
                    store.pop(var, None)
                else:
                    dst = store.setdefault(var, m.varstore(size))
                    if t[0] == 1:
                        s = m.cstr(R(rd), size)
                        m.write(dst, s + b'\0')
                    else:
                        m.write(dst, m.read(R(rd), size))
            else:
                if name == 'STTS' and R(rd) == 0:
                    store.pop(var, None)
                else:
                    store[var] = R(rd)
        elif name in ('LDTS', 'LDLS'):
            store = m.tls if name == 'LDTS' else m.locals
            W(rd, store.get(var, 0))
        elif name == 'CALL':
            W(rd, subr(m, var, tup, vartab))
        elif name in ('PUSHTR', 'PUSHTV'):
            if len(tup) >= 8:
                raise DIFError('tuple overflow')
            if name == 'PUSHTR':
                if r1 == 1:  # DIF_TYPE_STRING
                    lim = R(r2) or m.strsize
                    tup.append(('s', m.cstr(R(rd), lim) if R(rd) else b''))
                else:
                    tup.append(('r', m.read(R(rd), R(r2))))
            else:
                tup.append(('v', R(rd)))
        elif name == 'POPTS':
            if tup:
                tup.pop()
        elif name == 'FLUSHTS':
            tup = []
        elif name in ('LDGAA', 'LDTAA', 'STGAA', 'STTAA'):
            scope = 1 if name in ('LDTAA', 'STTAA') else 0
            k = (scope, var, tuple(tup))
            t = vtype(var, scope, 0)
            if name.startswith('LD'):
                W(rd, m.assoc.get(k, 0))
            else:
                if R(rd) == 0:
                    m.assoc.pop(k, None)
                elif t[2] & 1:
                    size = t[3] or m.strsize
                    dst = m.varstore(size)
                    data = (m.cstr(R(rd), size) + b'\0') if t[0] == 1 else m.read(R(rd), size)
                    m.write(dst, data)
                    m.assoc[k] = dst
                else:
                    m.assoc[k] = R(rd)
        elif name == 'ALLOCS':
            W(rd, m.alloc(R(r1)))
        elif name == 'COPYS':
            m.write(R(rd), m.read(R(r1), R(r2)))
        elif name in ('STB', 'STH', 'STW', 'STX'):
            size = {'STB': 1, 'STH': 2, 'STW': 4, 'STX': 8}[name]
            m.write(R(rd), (R(r1) & ((1 << (8 * size)) - 1)).to_bytes(size, 'little'))
        elif name in ('XLATE', 'XLARG'):
            xl = d['xl'][var]
            sub = xl['difo']
            if name == 'XLATE':
                m.env['xlate_input'] = R(rd)
            else:
                m.env['xlate_input'] = m.env['args'][m.env.get('xlarg', 0)]
            W(rd, run_difo(m, sub))
        else:
            raise DIFError(f'unsupported opcode {name}')
    raise DIFError('fell off the end')


def builtin(m, var):
    name = BUILTIN.get(var)
    if 0x106 <= var <= 0x10f:
        args = m.env.get('args', [])
        i = var - 0x106
        return args[i] & M64 if i < len(args) else 0
    if name is None:
        raise DIFError(f'unknown builtin variable {var:#x}')
    v = m.env.get(name, 0)
    if name in STRING_BUILTINS:
        return m.newstr(v or '')
    return v & M64


def subr(m, sid, tup, vartab):
    name = next((k for k, v in SUBR.items() if v == sid), None)
    vals = [t[1] for t in tup]

    def s(i):
        t = tup[i]
        if t[0] == 's':
            return t[1]
        return m.cstr(t[1]) if t[0] == 'v' else t[1].split(b'\0')[0]

    def iv(i, signed=True):
        v = tup[i][1]
        return s64(v) if signed else v
    if name == 'strlen':
        return len(s(0))
    if name == 'strjoin':
        return m.newstr(s(0) + s(1))
    if name == 'substr':
        # substr(s, index[, length]): documented semantics, negative index
        # counts from the end; a negative length trims from the end.
        st = s(0)
        n = len(st)
        i = iv(1)
        if i < 0:
            i += n
            if i < 0:
                i = 0
        if len(tup) > 2:
            ln = iv(2)
            if ln < 0:
                ln = max(0, n - i + ln)
        else:
            ln = n
        return m.newstr(st[i:i + ln] if i < n else b'')
    if name in ('index', 'rindex'):
        h, n = s(0), s(1)
        if name == 'index':
            start = iv(2) if len(tup) > 2 else 0
            if start < 0:
                start = 0
            r = h.find(n, start)
        else:
            start = iv(2) if len(tup) > 2 else len(h)
            r = h.rfind(n, 0, start + len(n)) if start >= 0 else -1
        return r & M64
    if name in ('strchr', 'strrchr'):
        h, c = s(0), iv(1) & 0xff
        i = h.find(bytes([c])) if name == 'strchr' else h.rfind(bytes([c]))
        return 0 if i < 0 else m.newstr(h[i:])
    if name == 'strstr':
        h, n = s(0), s(1)
        i = h.find(n)
        return 0 if i < 0 else m.newstr(h[i:])
    if name in ('toupper', 'tolower'):
        st = s(0)
        return m.newstr(st.upper() if name == 'toupper' else st.lower())
    if name == 'lltostr':
        v = iv(0)
        if len(tup) > 1:
            base = iv(1)
            digits = '0123456789abcdefghijklmnopqrstuvwxyz'
            u = v & M64
            out = ''
            while True:
                out = digits[u % base] + out
                u //= base
                if not u:
                    break
            return m.newstr({16: '0x', 8: '0'}.get(base, '') + out)
        return m.newstr(str(v))
    if name in ('htons', 'ntohs'):
        return int.from_bytes((iv(0, False) & 0xffff).to_bytes(2, 'little'), 'big')
    if name in ('htonl', 'ntohl'):
        return int.from_bytes((iv(0, False) & 0xffffffff).to_bytes(4, 'little'), 'big')
    if name in ('htonll', 'ntohll'):
        return int.from_bytes((iv(0, False)).to_bytes(8, 'little'), 'big')
    if name == 'alloca':
        return m.alloc(iv(0, False))
    if name == 'bcopy':
        m.write(vals[1], m.read(vals[0], vals[2]))
        return 0
    if name == 'speculation':
        m.spec += 1
        return m.spec
    if name == 'rand' or name == 'random':
        return m.env.get('rand', 4)
    if name == 'strtoll':
        st = s(0).decode()
        base = iv(1) if len(tup) > 1 else 10
        try:
            return int(st, base) & M64
        except ValueError:
            return 0
    if name in ('basename', 'dirname'):
        import posixpath
        st = s(0).decode()
        return m.newstr(posixpath.basename(st.rstrip('/')) if name == 'basename'
                        else (posixpath.dirname(st.rstrip('/')) or '.'))
    if name == 'copyin':
        src, n = vals[0], vals[1]
        return m.alloc(n, m.read(src, n))
    if name == 'copyinstr':
        return m.newstr(m.cstr(vals[0]))
    if name == 'progenyof':
        return int(m.env.get('pid', 0) == vals[0])
    raise DIFError(f'unsupported subroutine {name} ({sid})')


def retval(m, d, raw):
    """Interpret a DIFO result according to its return type."""
    kind, ckind, flags, size = d['rtype']
    if kind == 1:  # string
        return m.cstr(raw).decode('latin-1') if raw else None
    if flags & 1:  # by reference: bytes
        return m.read(raw, size)
    return raw


def disasm(d):
    out = []
    for ins in d['buf']:
        op = (ins >> 24) & 0xff
        out.append((NAME.get(op, op), (ins >> 16) & 0xff, (ins >> 8) & 0xff, ins & 0xff))
    return out
