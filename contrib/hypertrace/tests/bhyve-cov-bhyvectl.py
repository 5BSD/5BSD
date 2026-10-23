#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""bhyvectl(8) and the actual libvmmapi against a user-space vmm(4) model.

usage: bhyve-cov-bhyvectl.py OUT BHYVECTL LIBVMMAPI_DIR BUILD [VENDOR]

The production bhyvectl (or a test build of the original sources) runs with
the coverage build's libvmmapi.so.7 and bhyve-cov-vmmfake.so preloaded.  The
model owns /dev/vmmctl, /dev/vmm/*, /dev/vmm.io/* and /dev/mem, refuses vmm
ioctls on any other descriptor and never calls kldload(2): no VM is created,
opened or run and no kernel memory is read.  An IPC controller built from
bhyve-cov-ipcserver.c answers the get-vm-pid, checkpoint and repair commands.

Oracles:
  * set/get round trips through distinct values for every settable register,
    descriptor, capability, x2APIC state, RTC byte and time;
  * every printed register/VMCB/VMCS value equals the model's reply to the
    request issued for it, and every named register line asks for the
    architecturally named register (vm_reg_name parsed from vmm.h);
  * MSR permission bitmaps decoded per the AMD APM 15.11 / Intel SDM 24.6.9
    layouts from a bitmap with known cleared bits;
  * statistics, CPU sets, topology, memory segments/maps, GPA PTEs, run exits
    and suspend requests match the model state exactly;
  * argument errors print the usage text and exit 1; injected failures of each
    request make bhyvectl report the error and stop where it should.
"""
from pathlib import Path
import calendar, json, os, re, subprocess, sys, time

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parents[2]


def compile_helpers(out, build):
    flags = ['-I%s' % (build / 'source-includes'), '-I%s' % (ROOT / 'lib/libvmmapi'),
             '-I%s' % (ROOT / 'sys'), '-DWITH_VMMAPI_SNAPSHOT', '-std=gnu17',
             '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-O1', '-g']
    shim = out / 'vmmfake.so'
    subprocess.run(['cc'] + flags + ['-fPIC', '-shared', '-o', str(shim),
                    str(TESTS / 'bhyve-cov-vmmfake.c')], check=True)
    server = out / 'ipcserver'
    subprocess.run(['cc', '-Wall', '-Werror', '-O1', '-o', str(server),
                    str(TESTS / 'bhyve-cov-ipcserver.c'), '-lnv'], check=True)
    return shim, server


def compile_vmmhelper(out, build, libdir):
    helper = out / 'vmmhelper'
    subprocess.run(['cc', '-I%s' % (build / 'source-includes'), '-I%s' % (ROOT / 'lib/libvmmapi'),
                    '-I%s' % (ROOT / 'sys'), '-std=gnu17', '-Wall', '-Werror', '-O1', '-o',
                    str(helper), str(TESTS / 'bhyve-cov-vmmhelper.c'), '-L%s' % libdir,
                    '-lvmmapi'], check=True)
    return helper


def reg_enum():
    text = (ROOT / 'sys/amd64/include/vmm.h').read_text()
    body = re.search(r'enum vm_reg_name \{(.*?)\};', text, re.S).group(1)
    names = [w.strip().rstrip(',') for w in body.split('\n') if w.strip()]
    return {n: i for i, n in enumerate(names)}


def vmcb_offsets():
    text = (ROOT / 'sys/amd64/vmm/amd/vmcb.h').read_text()
    offs = {}
    for name, kind, value in re.findall(
            r'#define\s+(VMCB_OFF_\w+)\s+VMCB_OFF_(CTRL|STATE)\((0x[0-9A-Fa-f]+)\)', text):
        offs[name] = int(value, 16) + (0x400 if kind == 'STATE' else 0)
    return offs


def vmcb_access(off, width):
    return 0x80000000 | ((width & 0xf) << 16) | (off & 0xfff)


def exitcodes():
    text = (ROOT / 'sys/amd64/include/vmm.h').read_text()
    body = re.search(r'enum vm_exitcode \{(.*?)\};', text, re.S).group(1)
    codes, value = {}, -1
    for item in body.split(','):
        item = re.sub(r'/\*.*?\*/', '', item, flags=re.S).strip()
        if not item:
            continue
        if '=' in item:
            name, expr = (x.strip() for x in item.split('='))
            value = int(expr, 0) if re.fullmatch(r'-?\w+', expr) and expr[0].isdigit() else codes[expr]
        else:
            name, value = item, value + 1
        codes[name] = value
    return codes


def default_register(cpu, reg):
    reg &= 0xffffffff
    return (0x1000 * (reg & 0xffffff) + cpu * 0x10 + 5 + ((reg >> 24) << 40)) & (2**64 - 1)


class Suite:
    def __init__(self, out, binary, libdir, build, vendor, base_env=None):
        self.out, self.binary, self.vendor = out, binary, vendor
        self.shim, self.server = compile_helpers(out, build)
        self.helper = compile_vmmhelper(out, build, libdir)
        self.state = out / 'vmm.state'
        self.log = out / 'vmm.log'
        self.rundir = out / 'run'
        self.rundir.mkdir()
        self.env = dict(base_env or os.environ, LD_PRELOAD=str(self.shim),
                        LD_LIBRARY_PATH=str(libdir), VMMFAKE_STATE=str(self.state),
                        VMMFAKE_LOG=str(self.log), BHYVECTL_TEST_VENDOR=vendor)
        self.results = []
        self.regs = reg_enum()
        self.vmcb = vmcb_offsets()
        # Labels whose request must name a specific VMCS field (vmcs.h).
        vmcs = dict((n, int(v, 16)) for n, v in re.findall(
            r'#define\s+(VMCS_\w+)\s+(0x[0-9A-Fa-f]+)\s*$',
            (ROOT / 'sys/amd64/vmm/intel/vmcs.h').read_text(), re.M))
        self.label_regs = {} if vendor != 'intel' else {
            'apic_access_addr': 0x80000000 | vmcs['VMCS_APIC_ACCESS'],
            'virtual_apic_addr': 0x80000000 | vmcs['VMCS_VIRTUAL_APIC'],
            'vmcs_pointer': 0x80000000 | vmcs['VMCS_LINK_POINTER'],
            'eptp': 0x80000000 | vmcs['VMCS_EPTP'],
            'tsc_offset': 0x80000000 | vmcs['VMCS_TSC_OFFSET']}

    # ------------------------------------------------------------ helpers
    def run(self, *args, env=None, expect=0, fds=()):
        if self.log.exists():
            self.log.unlink()
        environment = dict(self.env, **(env or {}))
        done = subprocess.run([str(self.binary)] + list(args), env=environment,
                              capture_output=True, text=True, timeout=60, pass_fds=fds)
        log = self.log.read_text().splitlines() if self.log.exists() else []
        if expect is not None and done.returncode != expect:
            self.check('exit status %s' % ' '.join(args), False,
                       status=done.returncode, expected=expect,
                       stdout=done.stdout[-2000:], stderr=done.stderr[-2000:])
        return done, log

    def check(self, name, passed, **detail):
        self.results.append(dict(case=name, passed=bool(passed), **detail))
        if not passed:
            print('FAIL', name, json.dumps(detail)[:3000])

    def replies(self, log, cmd):
        out = []
        for line in log:
            if line.startswith('ioctl %s ' % cmd) and 'error' not in line:
                out.append(dict(re.findall(r'(\w+)=([^ ]+)', line)))
        return out

    # ---------------------------------------------------- printed values
    REGLINE = re.compile(r'^([A-Za-z0-9_/ ]+?)\[(\d+)\]\t+(0x[0-9a-f]+|\d+)$')

    def check_printed_registers(self, name, stdout, log, cpu):
        """Every single-value register line printed equals the model reply
        to the corresponding VM_GET_REGISTER, in order, and named general
        registers ask for that register."""
        replies = self.replies(log, 'VM_GET_REGISTER')
        lines = [m.groups() for m in map(self.REGLINE.match, stdout.splitlines()) if m]
        lines = [l for l in lines if l[0] not in ('x2apic_state',)]
        # Two-value sysenter lines and run output are not register lines.
        index = 0
        skipped = 0
        mismatches = []
        for label, printed_cpu, value in lines:
            got = int(value, 16) if value.startswith('0x') else int(value)
            # A request without a printed line (the MSR bitmap address read
            # again before the bitmap dump) is skipped.
            while index < len(replies) and got not in (
                    int(replies[index]['val'], 16), int(replies[index]['val'], 16) & 0xffffffff):
                index += 1
                skipped += 1
            if index >= len(replies):
                mismatches.append(('no request for', label, hex(got)))
                break
            reply = replies[index]
            index += 1
            regname = 'VM_REG_GUEST_' + label.upper()
            if regname in self.regs and int(reply['reg'], 16) != self.regs[regname]:
                mismatches.append((label, 'asked', reply['reg']))
            if label in self.label_regs and int(reply['reg'], 16) != self.label_regs[label]:
                mismatches.append((label, 'asked', reply['reg']))
            if int(printed_cpu) != cpu or int(reply['cpu']) != cpu:
                mismatches.append((label, 'cpu', printed_cpu, reply['cpu']))
        self.check(name, not mismatches and skipped <= 1 and len(replies) - index <= 1,
                   mismatches=mismatches[:10], lines=len(lines), requests=len(replies),
                   skipped=skipped)

    # --------------------------------------------------------------- tests
    def test_usage(self):
        done, _ = self.run(expect=1)
        text = done.stderr
        self.check('usage lists every option', text.startswith('Usage: ') and
                   '[--set-rax=<RAX>]' in text and '[--cpu=<vcpu_number>]' in text and
                   '[--checkpoint=<filename>]' in text and '[--unassign-pptdev=<bus/slot.func>]' in text
                   and '[--get-all]' in text and '[--rundir=<path>]' in text and
                   '[--set-rtc-nvram=<val>]' in text, head=text[:400])
        vendor_opt = '--get-vmcs-link' if self.vendor == 'intel' else '--get-vmcb-intercepts'
        other_opt = '--get-vmcb-intercepts' if self.vendor == 'intel' else '--get-vmcs-link'
        self.check('vendor options offered', vendor_opt[2:] in text and other_opt[2:] not in text)
        for args in (['--vm=x', '--no-such-option'],
                     ['--vm=x', '--checkpoint=a', '--suspend=b'],
                     ['--vm=x', '--migrate-fd=3', '--migrate-fd=4'],
                     ['--vm=x', '--migrate-key-fd=3', '--migrate-key-fd=4'],
                     ['--vm=x', '--migrate-repair', '--get-all'],
                     ['--vm=x', '--migrate-repair', 'extra'],
                     ['--vm=x', '--migrate-recover-fd=3', '--get-all'],
                     ['--vm=x', '--migrate-recover-fd=3', 'extra'],
                     # merged: strict numeric options and capability names
                     ['--vm=x', '--cpu=x'], ['--vm=x', '--cpu=-1'], ['--vm=x', '--cpu=1x'],
                     ['--vm=x', '--cpu=2147483648'], ['--vm=x', '--cpu=99999999999999999999'],
                     ['--vm=x', '--set-mem=-1'], ['--vm=x', '--set-mem=0'],
                     ['--vm=x', '--set-mem=abc'], ['--vm=x', '--set-mem=4x'],
                     ['--vm=x', '--set-mem=99999999999999999999'],
                     ['--vm=x', '--set-mem=17592186044415'],
                     ['--vm=x', '--setcap=2', '--capname=hlt_exit'],
                     ['--vm=x', '--setcap=10', '--capname=hlt_exit'],
                     ['--vm=x', '--setcap=', '--capname=hlt_exit'],
                     ['--vm=x', '--setcap=1'],
                     ['--vm=x', '--getcap', '--capname=no_such_cap'],
                     # migrate_resolve: action and exactly its confirmation
                     ['--vm=x', '--migrate-source-retired'],
                     ['--vm=x', '--migrate-acknowledge-loss'],
                     ['--vm=x', '--migrate-resolve=resume'],
                     ['--vm=x', '--migrate-resolve=discard'],
                     ['--vm=x', '--migrate-resolve=resume', '--migrate-acknowledge-loss'],
                     ['--vm=x', '--migrate-resolve=discard', '--migrate-source-retired'],
                     ['--vm=x', '--migrate-resolve=resume', '--migrate-source-retired',
                      '--migrate-acknowledge-loss'],
                     ['--vm=x', '--migrate-resolve=keep', '--migrate-source-retired'],
                     ['--vm=x', '--migrate-resolve=resume', '--migrate-resolve=resume',
                      '--migrate-source-retired'],
                     ['--vm=x', '--migrate-resolve=resume', '--migrate-source-retired',
                      '--get-all'],
                     ['--vm=x', '--migrate-resolve=resume', '--migrate-source-retired', 'extra'],
                     # the plaintext opt-in belongs to a migration request
                     ['--vm=x', '--migrate-plaintext-unix'],
                     ['--vm=x', '--migrate-plaintext-unix', '--migrate-recover-fd=3']):
            done, _ = self.run(*args, expect=1)
            self.check('usage for %s' % ' '.join(args), 'Usage: ' in done.stderr)

    def test_numeric_refusals(self):
        # Merged: register, descriptor, RTC and LAPIC values are parsed
        # strictly with a per-option maximum; PCI addresses are bus/slot.func
        # or bus/slot/func within PCI limits.  Refusals exit 1 before any
        # request reaches the VM.
        bad_values = [('--set-efer', '-1'), ('--set-efer', ''), ('--set-efer', '1x'),
                      ('--set-efer', '0x10000000000000000'), ('--desc-limit', '0x100000000'),
                      ('--desc-access', '4294967296'), ('--set-x2apic-state', '7'),
                      ('--set-x2apic-state', '2'),
                      ('--set-rtc-nvram', '256'), ('--rtc-nvram-offset', '2147483648'),
                      ('--set-rtc-time', '9223372036854775808'), ('--assert-lapic-lvt', '-3'),
                      ('--get-gpa-pmap', 'x')]
        for option, value in bad_values:
            done, log = self.run('--vm=guest0', '%s=%s' % (option, value), expect=1)
            self.check('refused %s=%s' % (option, value),
                       'invalid numeric value' in done.stderr and
                       not any(l.startswith('ioctl VM_') for l in log), stderr=done.stderr[-300:])
        for value in ('1/2', '-1/2/3', '1/-2/3', '1/2/-3', '256/0/0', '0/32/0', '0/0/8',
                      'x/2/3', '1/x/3', '1/2/x', '1/2/3x', '1-2/3', '99999999999999999999/0/0',
                      '0/99999999999999999999/0', '0/0/99999999999999999999'):
            done, log = self.run('--vm=guest0', '--unassign-pptdev=%s' % value, expect=1)
            self.check('refused PCI address %s' % value,
                       'invalid PCI address' in done.stderr and
                       not any('VM_UNBIND_PPTDEV' in l for l in log), stderr=done.stderr[-300:])
        for value, bus, slot, func in (('4/5.6', 4, 5, 6), ('255/31/7', 255, 31, 7), ('0/0/0', 0, 0, 0)):
            done, log = self.run('--vm=guest0', '--unassign-pptdev=%s' % value)
            self.check('PCI address %s' % value,
                       'ioctl VM_UNBIND_PPTDEV bus=%d slot=%d func=%d' % (bus, slot, func) in log,
                       log=log[-3:])
        # Maximum values are admitted and reach the model unchanged.
        done, log = self.run('--vm=guest0', '--set-x2apic-state=1', '--get-x2apic-state')
        self.check('largest x2apic state', 'x2apic_state[0]\t1' in done.stdout, stdout=done.stdout)
        done, log = self.run('--vm=guest0', '--rtc-nvram-offset=17', '--set-rtc-nvram=255',
                             '--get-rtc-nvram')
        self.check('largest nvram value', 'rtc nvram[017]: 0xff' in done.stdout, stdout=done.stdout)
        # An odd memory size is rounded up to the 2 MiB granule.
        done, log = self.run('--vm=mem9', '--create', '--set-mem=3', '--get-memseg')
        allocs = self.replies(log, 'VM_ALLOC_MEMSEG')
        self.check('odd memory size rounded to 2 MiB', len(allocs) == 1 and
                   allocs[0]['len'] == str(4 << 20), allocs=allocs)

    def test_lifecycle(self):
        done, log = self.run('--vm=absent', expect=1)
        self.check('open of a missing VM fails', 'vm_open: absent could not be opened: '
                   'No such file or directory' in done.stderr and
                   not any('VMMCTL_VM_CREATE' in l for l in log))
        done, log = self.run('--vm=guest0', '--create')
        self.check('create issues VMMCTL_VM_CREATE', any('ioctl VMMCTL_VM_CREATE' in l for l in log))
        done, _ = self.run('--vm=guest0', '--create', '--destroy', expect=1)
        self.check('mutually exclusive actions', 'mutually exclusive actions specified' in done.stderr)
        done, _ = self.run('--vm=guest0', '--force-reset', '--force-poweroff', expect=1)
        self.check('reset and poweroff exclusive', 'mutually exclusive' in done.stderr)
        done, log = self.run('--vm=guest0', '--create', env={'VMMFAKE_FAIL': 'VMMCTL_VM_CREATE:1:28'})
        self.check('create of an existing VM opens it', done.returncode == 0)
        done, log = self.run('--vm=newvm', '--create', env={'VMMFAKE_FAIL': 'VMMCTL_VM_CREATE:1:28'},
                             expect=1)
        self.check('create failure reported', 'No space left on device' in done.stderr)
        done, log = self.run('--vm=guest0', env={'VMMFAKE_FAIL': '/dev/vmmctl:1:13'}, expect=1)
        self.check('control device failure reported', 'Permission denied' in done.stderr)

    def test_registers(self):
        sets = {'efer': 0xd01, 'cr0': 0x80050033, 'cr2': 0x7f001000, 'cr3': 0x1234000,
                'cr4': 0x3606f0, 'dr0': 0x11, 'dr1': 0x22, 'dr2': 0x33, 'dr3': 0x44,
                'dr6': 0xffff0ff0, 'dr7': 0x400, 'rsp': 0x7ffff000, 'rip': 0xffff0,
                'rax': 0xdeadbeefcafe, 'rflags': 0x246, 'cs': 0x8, 'ds': 0x10, 'es': 0x18,
                'fs': 0x20, 'gs': 0x28, 'ss': 0x30, 'tr': 0x38, 'ldtr': 0x40}
        for cpu in (0, 1):
            args = ['--vm=guest0', '--cpu=%d' % cpu] + \
                ['--set-%s=%#x' % (k, v + cpu) for k, v in sets.items()]
            done, log = self.run(*args)
            written = {int(r['reg'], 16): int(r['val'], 16) for r in self.replies(log, 'VM_SET_REGISTER')}
            wanted = {self.regs['VM_REG_GUEST_' + k.upper()]: v + cpu for k, v in sets.items()}
            self.check('set registers cpu %d' % cpu, written == wanted, written=len(written))
            args = ['--vm=guest0', '--cpu=%d' % cpu] + ['--get-%s' % k for k in sets] + \
                ['--get-rbx', '--get-rcx', '--get-rdx', '--get-rsi', '--get-rdi', '--get-rbp'] + \
                ['--get-r%d' % i for i in range(8, 16)]
            done, log = self.run(*args)
            printed = dict((m.group(1), int(m.group(3), 16)) for m in
                           map(self.REGLINE.match, done.stdout.splitlines()) if m)
            self.check('register round trip cpu %d' % cpu,
                       all(printed.get(k) == v + cpu for k, v in sets.items()) and
                       printed.get('rbx') == default_register(cpu, self.regs['VM_REG_GUEST_RBX']),
                       printed={k: hex(v) for k, v in printed.items()})
            self.check_printed_registers('register requests cpu %d' % cpu, done.stdout, log, cpu)

    def test_descriptors(self):
        segs = ['ds', 'es', 'ss', 'cs', 'fs', 'gs', 'tr', 'ldtr', 'gdtr', 'idtr']
        for n, seg in enumerate(segs):
            base, limit, access = 0x100000 * (n + 1), 0xfff + n, 0xc093 + n
            done, log = self.run('--vm=guest0', '--set-desc-%s' % seg, '--desc-base=%#x' % base,
                                 '--desc-limit=%#x' % limit, '--desc-access=%#x' % access)
            set_ = self.replies(log, 'VM_SET_SEGMENT_DESCRIPTOR')
            expect_access = 0 if seg in ('gdtr', 'idtr') else access
            self.check('set desc %s' % seg, len(set_) == 1 and
                       int(set_[0]['reg']) == self.regs['VM_REG_GUEST_' + seg.upper()] and
                       int(set_[0]['base'], 16) == base and int(set_[0]['limit'], 16) == limit and
                       int(set_[0]['access'], 16) == expect_access)
            done, log = self.run('--vm=guest0', '--get-desc-%s' % seg)
            if seg in ('gdtr', 'idtr'):
                want = '%s[0]\t\t0x%016x/0x%08x' % (seg, base, limit)
            else:
                want = '%s desc[0]\t0x%016x/0x%08x/0x%08x' % (seg, base, limit, access)
            self.check('get desc %s' % seg, want in done.stdout, stdout=done.stdout)

    def test_misc(self):
        done, log = self.run('--vm=guest0', '--set-x2apic-state=1')
        done, log = self.run('--vm=guest0', '--get-x2apic-state')
        self.check('x2apic round trip', 'x2apic_state[0]\t1' in done.stdout)
        # A machine-dependent request failure is reflected in the exit status
        # (regression: bhyvectl_md_main() used to return void, so bhyvectl
        # exited 0) and later requests are not attempted.
        # Merged: an out-of-range state is refused by the parser, so the
        # model's refusal is injected for a valid one.
        done, log = self.run('--vm=guest0', '--set-x2apic-state=1', '--getcap', expect=None,
                             env={'VMMFAKE_FAIL': 'VM_SET_X2APIC_STATE:1:22'})
        self.check('md request failure gives a failing exit status',
                   done.returncode == 255 and 'errno = 22' in done.stdout and
                   not any(l.startswith('ioctl VM_GET_CAPABILITY') for l in log),
                   status=done.returncode, stdout=done.stdout[-500:])
        done, log = self.run('--vm=guest0', '--get-intinfo', expect=None,
                             env={'VMMFAKE_FAIL': 'VM_GET_INTINFO:1:5'})
        self.check('md get failure gives a failing exit status',
                   done.returncode == 255 and 'errno = 5' in done.stdout and
                   'pending:' not in done.stdout, status=done.returncode)
        done, log = self.run('--vm=guest0', '--rtc-nvram-offset=17', '--set-rtc-nvram=0xa5',
                             '--get-rtc-nvram')
        self.check('rtc nvram round trip', 'rtc nvram[017]: 0xa5' in done.stdout, stdout=done.stdout)
        done, log = self.run('--vm=guest0', '--rtc-nvram-offset=33', '--get-rtc-nvram')
        self.check('rtc nvram default', 'rtc nvram[033]: 0x%02x' % (33 ^ 0x5a) in done.stdout)
        for secs in (0, 951782400, 1700000000, 4102444799):
            done, log = self.run('--vm=guest0', '--set-rtc-time=%d' % secs, '--get-rtc-time')
            t = time.gmtime(secs)
            want = 'rtc time %s: %s %s %02d %02d:%02d:%02d %d' % (
                '%#x' % secs if secs else '0', ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][t.tm_wday],
                calendar.month_abbr[t.tm_mon], t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, t.tm_year)
            self.check('rtc time %d' % secs, want in done.stdout, stdout=done.stdout, want=want)
        for gpa in (0x1000, 0x2001, 0x3003):
            done, _ = self.run('--vm=guest0', '--get-gpa-pmap=%#x' % gpa)
            ptes = ' '.join('%#x' % (gpa + 0x1000 * i + 0x67) for i in range((gpa & 3) + 1))
            self.check('gpa pmap %#x' % gpa, 'gpa %#x: %s' % (gpa, ptes) in done.stdout,
                       stdout=done.stdout)
        done, log = self.run('--vm=guest0', '--cpu=1', '--inject-nmi', '--assert-lapic-lvt=3',
                             '--unassign-pptdev=4/5/6')
        self.check('nmi lapic and pptdev requests',
                   any(l == 'ioctl VM_INJECT_NMI cpu=1' for l in log) and
                   any(l == 'ioctl VM_LAPIC_LOCAL_IRQ cpu=1 vector=3' for l in log) and
                   any(l == 'ioctl VM_UNBIND_PPTDEV bus=4 slot=5 func=6' for l in log), log=log[-8:])
        # Interrupt info decoding: pending from the model's set value,
        # current fixed as an external interrupt, vector 0x20.
        for info, text in ((0, 'n/a'),
                           ((1 << 31) | (3 << 8) | 14 | (1 << 11) | (0x55 << 32),
                            'exception vector 14 errcode 0x55'),
                           ((1 << 31) | (2 << 8) | 2, 'nmi vector 2'),
                           ((1 << 31) | (4 << 8) | 0x80, 'swint vector 128'),
                           ((1 << 31) | (0 << 8) | 0x30, 'extint vector 48')):
            self.set_intinfo(info)
            done, _ = self.run('--vm=guest0', '--get-intinfo')
            self.check('intinfo %#x' % info, 'pending:\t%s\n' % text in done.stdout and
                       'current:\textint vector 32' in done.stdout, stdout=done.stdout)

    def helper_run(self, *args, env=None):
        # Model state bhyvectl cannot create, made through libvmmapi.
        environment = dict(self.env, **(env or {}))
        environment.pop('VMMFAKE_LOG', None)
        subprocess.run([str(self.helper)] + [str(a) for a in args], env=environment, check=True)

    def set_intinfo(self, info):
        self.helper_run('intinfo', 'guest0', info)

    def test_memmap_flags(self):
        self.run('--vm=map0', '--create')
        self.helper_run('wired', 'map0', 8 << 20, env={'VMMFAKE_IOMMU': '1'})
        self.helper_run('devmem', 'map0', 'fbuf', 0x10000, 0xd0000000)
        done, _ = self.run('--vm=map0', '--get-memmap', '--get-memseg')
        lines = done.stdout.splitlines()
        self.check('memory map flags and names',
                   '0           %-12ssysmem      0           RWX   wired/iommu' %
                   self.humanize(8 << 20) in lines and
                   'D0000000    %-12sfbuf        0           RW-   ' %
                   self.humanize(0x10000) in lines and
                   any(re.fullmatch(r'\d+ +%s +fbuf' % re.escape(self.humanize(0x10000)), l)
                       for l in lines), stdout=done.stdout)

    def test_individual_options(self):
        done, _ = self.run(expect=1)
        options = re.findall(r'\[--(get-[a-z0-9-]+)\]', done.stderr)
        skip = {'get-all', 'get-vm-pid', 'get-memmap', 'get-memseg', 'get-stats',
                'get-msr-bitmap', 'get-active-cpus', 'get-debug-cpus', 'get-suspended-cpus',
                'get-cpu-topology', 'get-rtc-time', 'get-rtc-nvram', 'get-intinfo',
                'get-x2apic-state'}
        ran = 0
        for option in options:
            if option in skip or option.startswith('get-desc-'):
                continue
            done, log = self.run('--vm=guest0', '--cpu=2', '--' + option)
            self.check_printed_registers('single option %s' % option, done.stdout, log, 2)
            self.check('single option %s prints' % option, done.stdout.strip() != '')
            ran += 1
        self.check('individual options exercised', ran > 40, ran=ran)

    def test_capabilities(self):
        done, log = self.run('--vm=guest0', '--getcap')
        names = ['hlt_exit', 'mtrap_exit', 'pause_exit', 'unrestricted_guest', 'enable_invpcid',
                 'bpt_exit', 'rdpid', 'rdtscp', 'ipi_exit', 'mask_hwintr', 'rflags_tf', 'nested_vmx',
                 'nested_svm']
        expect = []
        for i, n in enumerate(names):
            if n in ('rdpid', 'nested_vmx'):
                expect.append('Capability "%s" is not available' % n)
            else:
                expect.append('Capability "%s" is %s on vcpu 0' % (n, 'set' if i & 1 else 'not set'))
        self.check('all capabilities', done.stdout.splitlines() == expect, stdout=done.stdout)
        done, log = self.run('--vm=guest0', '--capname=hlt_exit', '--setcap=1')
        done, log = self.run('--vm=guest0', '--getcap', '--capname=hlt_exit')
        self.check('capability round trip', done.stdout == 'Capability "hlt_exit" is set on vcpu 0\n',
                   stdout=done.stdout)
        done, log = self.run('--vm=guest0', '--capname=rdpid', '--setcap=1', expect=255)
        self.check('unavailable capability', 'Capability "rdpid" is not available' in done.stdout)
        # Merged: --setcap takes exactly 0 or 1; clearing reaches the model.
        done, log = self.run('--vm=guest0', '--capname=hlt_exit', '--setcap=0')
        done, log = self.run('--vm=guest0', '--getcap', '--capname=hlt_exit')
        self.check('capability cleared', 'Capability "hlt_exit" is not set on vcpu 0' in done.stdout,
                   stdout=done.stdout)
        # A set failure other than an unavailable capability prints nothing.
        done, log = self.run('--vm=guest0', '--capname=hlt_exit', '--setcap=1', expect=255,
                             env={'VMMFAKE_FAIL': 'VM_SET_CAPABILITY:1:5'})
        self.check('capability set failure', 'not available' not in done.stdout, stdout=done.stdout)
        done, log = self.run('--vm=guest0', '--getcap', env={'VMMFAKE_FAIL': 'VM_GET_CAPABILITY:3:5'},
                             expect=255)
        self.check('capability failure stops listing',
                   len(done.stdout.splitlines()) == 3 and 'errno = 5' in done.stdout,
                   stdout=done.stdout)

    def test_state_queries(self):
        done, _ = self.run('--vm=guest0', '--get-stats')
        lines = done.stdout.splitlines()
        want = ['vcpu0 stats:'] + ['%-40s\t%d' % ('statistic number %d' % i, i * 3) for i in range(70)]
        self.check('statistics across two requests', lines == want, got=lines[:3])
        done, _ = self.run('--vm=guest0', '--cpu=1', '--get-stats',
                           env={'VMMFAKE_FAIL': 'VM_STATS:1:5'})
        self.check('statistics failure prints nothing', done.stdout == '')
        done, _ = self.run('--vm=guest0', '--get-active-cpus', '--get-debug-cpus',
                           '--get-suspended-cpus', '--get-cpu-topology')
        self.check('cpu sets and topology', done.stdout.splitlines() == [
            'active cpus:\t 0, 1', 'debug cpus:\t (none)', 'suspended cpus:\t (none)',
            'cpu_topology:\tsockets=1, cores=2, threads=1, maxcpus=8'], stdout=done.stdout)
        for flag, cmd in (('--get-active-cpus', 'VM_GET_CPUS'), ('--get-debug-cpus', 'VM_GET_CPUS'),
                          ('--get-suspended-cpus', 'VM_GET_CPUS')):
            done, _ = self.run('--vm=guest0', flag, env={'VMMFAKE_FAIL': cmd + ':1:22'}, expect=255)
            self.check('cpu set failure %s' % flag, 'errno = 22' in done.stdout)

    @staticmethod
    def humanize(value):
        # libutil's humanize_number(3) as bhyvectl calls it (8-byte buffer,
        # HN_AUTOSCALE, HN_NOSPACE): an independent system implementation.
        import ctypes
        libutil = ctypes.CDLL('libutil.so.10')
        buf = ctypes.create_string_buffer(8)
        libutil.humanize_number(buf, ctypes.c_size_t(8), ctypes.c_int64(value), b'B',
                                ctypes.c_int(0x20), ctypes.c_int(0x02))
        return buf.value.decode()

    def test_memory(self):
        done, log = self.run('--vm=mem0', '--create', '--set-mem=64', '--get-memseg', '--get-memmap')
        h = self.humanize(64 << 20)
        self.check('memory setup and listing', done.stdout.splitlines() == [
            'ID  Length      Name', '0   %-12ssysmem' % h,
            'Address     Length      Segment     Offset      Prot  Flags',
            '0           %-12ssysmem      0           RWX   ' % h], stdout=done.stdout)
        allocs = self.replies(log, 'VM_ALLOC_MEMSEG')
        maps = self.replies(log, 'VM_MMAP_MEMSEG')
        self.check('memory setup requests', len(allocs) == 1 and allocs[0]['segid'] == '0' and
                   allocs[0]['len'] == str(64 << 20) and len(maps) == 1 and
                   maps[0]['gpa'] == '0' and maps[0]['prot'] == '7', allocs=allocs, maps=maps)
        done, log = self.run('--vm=mem0', '--set-mem=64', '--get-memmap')
        self.check('existing memory reused', not self.replies(log, 'VM_ALLOC_MEMSEG') and
                   not self.replies(log, 'VM_MMAP_MEMSEG'))
        done, log = self.run('--vm=mem1', '--create', '--set-mem=5000', '--get-all')
        lines = done.stdout.splitlines()
        low, high = 3 << 30, (5000 << 20) - (3 << 30)
        self.check('split memory listing', '0   %-12ssysmem' % self.humanize(5000 << 20) in lines and
                   '0           %-12ssysmem      0           RWX   ' % self.humanize(low) in lines and
                   '100000000   %-12ssysmem      C0000000    RWX   ' % self.humanize(high) in lines,
                   stdout=done.stdout[:800])
        done, log = self.run('--vm=mem1', '--get-memseg', env={'VMMFAKE_FAIL': 'VM_GET_MEMSEG:1:5'},
                             expect=255)
        self.check('memseg failure', 'errno = 5' in done.stdout)
        done, log = self.run('--vm=mem1', '--get-memmap', env={'VMMFAKE_FAIL': 'VM_GET_MEMSEG:1:5'},
                             expect=255)
        self.check('memmap segment lookup failure', 'errno = 5' in done.stdout)
        done, log = self.run('--vm=mem1', '--get-memmap', env={'VMMFAKE_FAIL': 'VM_MMAP_GETNEXT:2:5'},
                             expect=255)
        self.check('memmap walk failure', 'errno = 5' in done.stdout)
        done, log = self.run('--vm=mem2', '--create', '--set-mem=64',
                             env={'VMMFAKE_FAIL': 'VM_ALLOC_MEMSEG:1:12'}, expect=255)
        self.check('memory allocation failure', 'errno = 12' in done.stdout)

    def test_run_and_suspend(self):
        ec = exitcodes()
        for code, lines in ((ec['VM_EXITCODE_INOUT'], ['\treason\t\tINOUT', '\tdirection\tOUT', '\tbytes\t\t4',
                                 '\tflags\t\tSTRING REP ', '\tport\t\t0x03f8', '\teax\t\t0x00000041']),
                            (ec['VM_EXITCODE_VMX'], ['\treason\t\tVMX', '\tstatus\t\t1',
                                 '\texit_reason\t0x00000030 (48)',
                                 '\tqualification\t0x0000000000000181', '\tinst_type\t\t3',
                                 '\tinst_error\t\t7']),
                            (ec['VM_EXITCODE_SVM'], None),
                            (ec['VM_EXITCODE_MAX'] + 7,
                             ['*** unknown vm run exitcode %d' % (ec['VM_EXITCODE_MAX'] + 7)])):
            done, _ = self.run('--vm=run0', '--create', '--run', env={'VMMFAKE_EXITCODE': str(code)})
            out = done.stdout.splitlines()
            if lines is None:
                self.check('run exit %d' % code, out[3:] == [
                    '\treason\t\tSVM', '\texit_reason\t\t0x7b', '\texitinfo1\t\t0x10',
                    '\texitinfo2\t\t0x20'], stdout=done.stdout)
            else:
                self.check('run exit %d' % code, out[0] == 'vm exit[0]' and
                           out[1].startswith('\trip\t\t0x00000000000') and
                           out[2] == '\tinst_length\t2' and out[3:] == lines, stdout=done.stdout)
        # The model alternates OUT and IN between runs; a plain access has
        # no flags.
        seen = set()
        for _ in range(2):
            done, _ = self.run('--vm=run0', '--run',
                               env={'VMMFAKE_EXITCODE': str(ec['VM_EXITCODE_INOUT']),
                                    'VMMFAKE_INOUT_PLAIN': '1'})
            seen.update(d for d in ('IN', 'OUT') if '\tdirection\t%s\n' % d in done.stdout)
            self.check('run exit inout plain flags', '\tflags\t\t\n' in done.stdout,
                       stdout=done.stdout)
        self.check('run exit inout both directions', seen == {'IN', 'OUT'}, seen=sorted(seen))
        done, _ = self.run('--vm=run0', '--run', env={'VMMFAKE_FAIL': 'VM_RUN:1:4'}, expect=255)
        self.check('run failure', 'vm_run error -1' in done.stdout)
        done, log = self.run('--vm=run0', '--force-reset')
        self.check('force reset', 'ioctl VM_SUSPEND how=1' in log)
        done, log = self.run('--vm=run0', '--force-poweroff', expect=255)
        self.check('second suspend refused', 'errno = 37' in done.stdout)
        self.run('--vm=run1', '--create')
        done, log = self.run('--vm=run1', '--force-poweroff')
        self.check('force poweroff', 'ioctl VM_SUSPEND how=2' in log)
        done, log = self.run('--vm=run1', '--destroy')
        self.check('destroy', any('ioctl VMMCTL_VM_DESTROY' in l for l in log))
        done, log = self.run('--vm=run1', expect=1)
        self.check('destroyed VM is gone', 'could not be opened' in done.stderr)

    def test_get_all(self):
        done, log = self.run('--vm=all0', '--create', '--set-mem=8', '--cpu=1', '--get-all',
                             env={'VMMFAKE_MEM': '4=0xfe,2080=0xfd'})
        self.check_printed_registers('get-all register values', done.stdout, log, 1)
        descs = self.replies(log, 'VM_GET_SEGMENT_DESCRIPTOR')
        printed = re.findall(r'^(\w+) desc\[1\]\t(0x[0-9a-f]+)/(0x[0-9a-f]+)/(0x[0-9a-f]+)$',
                             done.stdout, re.M)
        self.check('get-all descriptors', len(printed) == 8 and all(
            int(p[1], 16) == int(d['base'], 16) and int(p[2], 16) == int(d['limit'], 16) and
            int(p[3], 16) == int(d['access'], 16) and
            int(d['reg']) == self.regs['VM_REG_GUEST_' + p[0].upper()]
            for p, d in zip(printed, descs)), printed=printed[:2])
        if self.vendor != 'intel':
            # VMCB requests carry offset and width per the vmcb.h layout.
            asked = {int(r['reg'], 16) for r in self.replies(log, 'VM_GET_REGISTER')}
            need = [vmcb_access(self.vmcb[n], w) for n, w in (
                ('VMCB_OFF_CR_INTERCEPT', 4), ('VMCB_OFF_TLB_CTRL', 4), ('VMCB_OFF_EXITINFO1', 8),
                ('VMCB_OFF_VIRQ', 8), ('VMCB_OFF_AVIC_BAR', 8), ('VMCB_OFF_AVIC_PT', 8),
                ('VMCB_OFF_NPT_BASE', 8), ('VMCB_OFF_ASID', 4), ('VMCB_OFF_GUEST_PAT', 8),
                ('VMCB_OFF_SYSENTER_EIP', 8), ('VMCB_OFF_EXIT_REASON', 8), ('VMCB_OFF_MSR_PERM', 8))]
            self.check('vmcb fields requested', all(a in asked for a in need))
            # AMD MSR permission map: byte 4 bits 0/1 = MSR 0x10 read/write;
            # byte 2048+32 bits 0/1 = MSR 0xC0000080 read/write.
            msr_lines = [l for l in done.stdout.splitlines() if l.startswith(('MSR', 'MSR_'))]
            self.check('amd msr bitmap', msr_lines == ['MSR_TSC             [1]\t\tR-',
                                                       'MSR_EFER            [1]\t\t-W'],
                       got=msr_lines[:6])
            address = re.search(r'^msr_bitmap\[1\]\t\t(0x[0-9a-f]+)$', done.stdout, re.M)
            self.check('amd msr bitmap mapped at the VMCB address', address is not None and
                       'mmap kind 4 len 8192 off %s' % address.group(1) in log)
        else:
            msr_lines = [l for l in done.stdout.splitlines() if l.startswith(('MSR', 'MSR_'))]
            # Intel: read map byte 2 bit 0 = MSR 0x10; write map 2048+byte.
            # VMMFAKE_MEM clears bit 0 of byte 4 (MSR 0x20 read) and bit 1
            # of byte 2080 (write map byte 32 bit 1 = MSR 0x101 write).
            want = [('%-20s' % ('MSR       %#08x' % 0x20)) + '[1]\t\tR-',
                    ('%-20s' % ('MSR       %#08x' % 0x101)) + '[1]\t\t-W']
            self.check('intel msr bitmap', msr_lines == want, got=msr_lines[:20])
            address = re.search(r'^msr_bitmap\[1\]\t\t(0x[0-9a-f]+)$', done.stdout, re.M)
            self.check('intel msr bitmap mapped at the VMCS address', address is not None and
                       'mmap kind 4 len 4096 off %s' % address.group(1) in log)
        for needed in ('x2apic_state[1]', 'exception_bitmap[1]', 'tsc_offset[1]',
                       'guest_sysenter_ip[1]', 'pending:', 'rtc time', 'cpu_topology:',
                       'vcpu1 stats:', 'Capability "hlt_exit"'):
            self.check('get-all prints %s' % needed, needed in done.stdout)

    def test_msr_names(self):
        """Every MSR that msr_name() names, passed through for reads only,
        is printed under its name (numbers from the Intel SDM / AMD APM)."""
        named = {0x10: 'MSR_TSC', 0x174: 'MSR_SYSENTER_CS_MSR', 0x175: 'MSR_SYSENTER_ESP_MSR',
                 0x176: 'MSR_SYSENTER_EIP_MSR', 0x277: 'MSR_PAT', 0xc0000080: 'MSR_EFER',
                 0xc0000081: 'MSR_STAR', 0xc0000082: 'MSR_LSTAR', 0xc0000083: 'MSR_CSTAR',
                 0xc0000084: 'MSR_SF_MASK', 0xc0000100: 'MSR_FSBASE', 0xc0000101: 'MSR_GSBASE',
                 0xc0000102: 'MSR_KGSBASE'}
        page = {}
        for msr in named:
            low, high = msr & 0x1fff, msr >= 0xc0000000
            if self.vendor == 'intel':
                byte, bit = (1024 if high else 0) + low // 8, low % 8
            else:
                byte, bit = (2048 if high else 0) + low // 4, (low % 4) * 2
            page[byte] = page.get(byte, 0xff) & ~(1 << bit) & 0xff
        spec = ','.join('%d=%#x' % kv for kv in sorted(page.items()))
        self.run('--vm=msr0', '--create')
        done, _ = self.run('--vm=msr0', '--get-msr-bitmap', env={'VMMFAKE_MEM': spec})
        got = [l for l in done.stdout.splitlines() if l.startswith('MSR')]
        order = sorted(named, key=lambda m: (m & 0x1fff, m >= 0xc0000000))
        want = ['%-20s[0]\t\tR-' % named[m] for m in order]
        self.check('msr names', got == want, got=got, want=want)

    def test_md_short_circuit(self):
        """Once a machine-dependent request fails, no later one is sent and
        bhyvectl exits with the failure."""
        sets = ['--set-%s=1' % r for r in ('efer', 'cr0', 'cr2', 'cr3', 'cr4', 'dr0', 'dr1',
                'dr2', 'dr3', 'dr6', 'dr7', 'rsp', 'rip', 'rax', 'rflags', 'cs', 'ds', 'es',
                'fs', 'gs', 'ss', 'tr', 'ldtr', 'x2apic-state')]
        sets += ['--set-desc-%s' % d for d in ('ds', 'es', 'ss', 'cs', 'fs', 'gs', 'tr', 'ldtr',
                                                'gdtr', 'idtr')]
        sets += ['--desc-base=0', '--desc-limit=0', '--desc-access=0', '--unassign-pptdev=1/2/3',
                 '--inject-nmi', '--assert-lapic-lvt=1', '--set-rtc-time=5',
                 '--rtc-nvram-offset=20', '--set-rtc-nvram=1', '--get-gpa-pmap=0x1000',
                 '--get-all']
        self.run('--vm=md0', '--create')
        done, log = self.run('--vm=md0', *sets, env={'VMMFAKE_FAIL': 'VM_SET_REGISTER:1:22'},
                             expect=None)
        sent = [l.split()[1] for l in log if l.startswith('ioctl ') and 'VM_GET_IDENTITY' not in l]
        md = [c for c in sent if c not in ('VM_GET_CAPABILITY',)]
        self.check('md failure stops later requests', done.returncode == 255 and
                   'errno = 22' in done.stdout and
                   sum(1 for c in sent if c == 'VM_SET_REGISTER') == 1 and
                   not any(c in sent for c in ('VM_SET_SEGMENT_DESCRIPTOR', 'VM_SET_X2APIC_STATE',
                                               'VM_UNBIND_PPTDEV', 'VM_INJECT_NMI',
                                               'VM_LAPIC_LOCAL_IRQ', 'VM_RTC_SETTIME',
                                               'VM_RTC_WRITE', 'VM_GET_GPA_PMAP',
                                               'VM_GET_REGISTER', 'VM_GET_CAPABILITY')),
                   status=done.returncode, sent=md[-12:])

    def test_rtc_unrepresentable(self):
        """An RTC value gmtime_r() cannot represent is reported as such
        (regression: the result was unchecked and an uninitialised struct tm
        was printed)."""
        self.run('--vm=rtc0', '--create')
        done, _ = self.run('--vm=rtc0', '--set-rtc-time=0x7fffffffffffffff', '--get-rtc-time')
        self.check('rtc time not representable',
                   'rtc time 0x7fffffffffffffff: not representable\n' in done.stdout,
                   stdout=done.stdout)

    def test_failures(self):
        """Fail each request of a full query in turn: the failing step's
        output is absent and either the error is reported or (machine
        dependent queries) the remaining common queries still run."""
        done, log = self.run('--vm=all0', '--get-all')
        sequence = []
        for line in log:
            if line.startswith('ioctl '):
                name = line.split()[1]
                sequence.append(name)
        counts = {}
        cases = 0
        for name in sequence:
            counts[name] = counts.get(name, 0) + 1
            spec = '%s:%d:5' % (name, counts[name])
            failed, flog = self.run('--vm=all0', '--get-all', env={'VMMFAKE_FAIL': spec},
                                    expect=None)
            cases += 1
            if not any('injected' in l for l in flog):
                self.check('fault %s fired' % spec, False)
                continue
            # The process ends normally; no line prints the failed value.
            self.check('fault %s handled' % spec, failed.returncode in (0, 255) and
                       'Segmentation' not in failed.stderr and
                       (failed.returncode == 0 or 'errno = 5' in failed.stdout),
                       status=failed.returncode)
        self.check('fault enumeration ran', cases > 50, cases=cases)

    def test_ipc(self):
        mode = self.out / 'ipc.mode'
        reqlog = self.out / 'ipc.log'
        server = subprocess.Popen([str(self.server), str(self.rundir), 'guest0', str(mode),
                                   str(reqlog)], stdout=subprocess.PIPE, text=True)
        try:
            server.stdout.readline()
            rundir = '--rundir=%s' % self.rundir
            mode.write_text('pid\n')
            done, _ = self.run('--vm=guest0', rundir, '--get-vm-pid')
            self.check('vm pid', 'vm pid:\t4242' in done.stdout)
            mode.write_text('ok\n')
            done, _ = self.run('--vm=guest0', rundir, '--get-vm-pid', expect=92)
            self.check('vm pid missing is EPROTO', 'errno = 92' in done.stdout)
            mode.write_text('error\n')
            done, _ = self.run('--vm=guest0', rundir, '--get-vm-pid', expect=45)
            self.check('vm pid refused is EOPNOTSUPP', 'IPC command failed: controller refused'
                       in done.stderr and 'errno = 45' in done.stdout)
            mode.write_text('close\n')
            done, _ = self.run('--vm=guest0', rundir, '--get-vm-pid', expect=None)
            self.check('vm pid dropped', 'nvlist_xfer() failed' in done.stderr and
                       done.returncode != 0)
            done, _ = self.run('--vm=guest0', '--rundir=%s/none' % self.out, '--get-vm-pid', expect=3)
            self.check('no controller is ESRCH', 'connect() failed' in done.stderr)
            long = '--rundir=' + '/x' * 60
            done, _ = self.run('--vm=guest0', long, '--get-vm-pid', expect=63)
            self.check('socket path too long', 'bhyve IPC socket path is too long' in done.stderr)
            ckdir = self.out / 'ckpt'
            ckdir.mkdir()
            mode.write_text('ok\n')
            for flag, suspend in (('--checkpoint', 0), ('--suspend', 1)):
                done, _ = self.run('--vm=guest0', rundir, '%s=%s/image.ckp' % (flag, ckdir))
                last = reqlog.read_text().splitlines()[-1]
                self.check('%s request' % flag, done.returncode == 0 and last ==
                           'cmd=checkpoint filename=image.ckp suspend=%d fddir-is-dir=1 mode=ok'
                           % suspend, last=last)
            done, _ = self.run('--vm=guest0', rundir, '--checkpoint=%s/missing/x.ckp' % self.out,
                               expect=2)
            self.check('checkpoint directory missing', 'errno = ' in done.stdout)
            for reply, status, text in (('repair-ok', 0, 'migration rollback repaired; source runnable'),
                                        ('repair-false', 1, 'migration rollback repair failed: '),
                                        ('repair-stuck', 1, 'migration rollback repair failed: '),
                                        ('error', 1, 'migration rollback repair failed\n')):
                mode.write_text(reply + '\n')
                done, _ = self.run('--vm=guest0', rundir, '--migrate-repair', expect=status)
                self.check('repair %s' % reply, text in done.stdout + done.stderr,
                           out=done.stdout + done.stderr)
        finally:
            server.kill()
            server.wait()

    def test_vendor_identity(self):
        # Test build only: the CPUID seam selects the vendor.
        done, _ = self.run('--vm=guest0', '--get-vmcb-asid', env={'BHYVECTL_TEST_VENDOR': 'hygon'},
                           expect=1)
        self.check('hygon uses the AMD options', 'vm_open: guest0 could not be opened' in done.stderr)
        done, _ = self.run('--vm=guest0', env={'BHYVECTL_TEST_VENDOR': 'other'}, expect=1)
        self.check('unknown vendor refused', 'Unknown cpu vendor "UnknownVendr"' in done.stderr,
                   stderr=done.stderr)

    def test_migration_cli(self):
        mode = self.out / 'ipc.mode'
        reqlog = self.out / 'ipc.log'
        server = subprocess.Popen([str(self.server), str(self.rundir), 'mig0', str(mode),
                                   str(reqlog)], stdout=subprocess.PIPE, text=True)
        creds = [os.open(str(self.out / ('cred%d' % i)), os.O_RDWR | os.O_CREAT, 0o600)
                 for i in range(4)]
        pin = '--migrate-peer-sha256=' + '04' * 32
        try:
            server.stdout.readline()
            rundir = '--rundir=%s' % self.rundir
            cred_args = ['--migrate-certificate-fd=%d' % creds[0], '--migrate-key-fd=%d' % creds[1],
                         '--migrate-trust-fd=%d' % creds[2], pin]
            for args, text in (
                    (['--migrate-key-fd=3'], 'migration recovery failed: Invalid argument'),
                    (['--migrate-fd=abc'] + cred_args, 'migration initiation failed: Invalid argument'),
                    (['--migrate-fd=%d' % creds[3]], 'migration initiation failed: Invalid argument'),
                    (['--migrate-fd=%d' % creds[3], '--migrate-key-fd=%d' % creds[1]],
                     'migration initiation failed: Invalid argument'),
                    (['--migrate-fd=%d' % creds[3]] + cred_args[:3] + ['--migrate-peer-sha256=zz'],
                     'migration initiation failed: Invalid argument')):
                done, _ = self.run('--vm=mig0', rundir, *args, expect=1, fds=creds)
                self.check('migration argument %s' % ' '.join(args), text in done.stderr,
                           stderr=done.stderr)
            for reply, ok in (('migrate-0-6-0', True), ('migrate-1-6-0', False),
                              ('migrate-x-6-0', False), ('migrate-0-5-0', False),
                              ('migrate-0-x-0', False), ('migrate-0-6-1', False),
                              ('migrate-0-6-x', False), ('error', None)):
                mode.write_text(reply + '\n')
                done, _ = self.run('--vm=mig0', rundir, '--migrate-fd=%d' % creds[3], *cred_args,
                                   expect=0 if ok else 1, fds=creds)
                want = ('migration completed; source remains retired' if ok else
                        'migration initiation failed: Protocol error' if ok is False else
                        'migration initiation failed\n')
                self.check('migration reply %s' % reply, want in done.stdout + done.stderr,
                           out=done.stdout + done.stderr)
                last = reqlog.read_text().splitlines()[-1]
                self.check('migration request %s' % reply, last.startswith('cmd=migrate mode='))
            for reply, ok in (('recover-0-1', True), ('recover-0-0', False), ('recover-0-x', False),
                              ('recover-1-1', False)):
                mode.write_text(reply + '\n')
                done, _ = self.run('--vm=mig0', rundir, '--migrate-recover-fd=%d' % creds[3],
                                   *cred_args, expect=0 if ok else 1, fds=creds)
                want = ('migration recovery confirmed; source remains retired' if ok else
                        'migration recovery failed: Protocol error')
                self.check('recovery reply %s' % reply, want in done.stdout + done.stderr,
                           out=done.stdout + done.stderr)
                self.check('recovery request %s' % reply,
                           reqlog.read_text().splitlines()[-1].startswith('cmd=migrate_recover'))
            # The plaintext opt-in: no credentials may accompany it.
            for args in (['--migrate-plaintext-unix'] + cred_args[:1],
                         ['--migrate-plaintext-unix', pin]):
                done, _ = self.run('--vm=mig0', rundir, '--migrate-fd=%d' % creds[3], *args,
                                   expect=1, fds=creds)
                self.check('plaintext with credentials %s' % args[1][:22],
                           'migration initiation failed: Invalid argument' in done.stderr,
                           stderr=done.stderr)
            mode.write_text('migrate-0-6-0\n')
            done, _ = self.run('--vm=mig0', rundir, '--migrate-fd=%d' % creds[3],
                               '--migrate-plaintext-unix', expect=0, fds=creds)
            last = reqlog.read_text().splitlines()[-1]
            self.check('plaintext migration request',
                       'migration completed' in done.stdout and last.startswith('cmd=migrate ')
                       and 'plaintext_unix=1' in last, last=last)
            # Operator resolution of a retained destination.
            for args, reply, status, text in (
                    (['--migrate-resolve=resume', '--migrate-source-retired'], 'resolve-1-0', 0,
                     'retained migration resumed; destination running'),
                    (['--migrate-resolve=discard', '--migrate-acknowledge-loss'], 'resolve-1-0', 0,
                     'retained migration discarded'),
                    (['--migrate-resolve=resume', '--migrate-source-retired'], 'resolve-0-1-16', 1,
                     'migration resolution failed: Device busy'),
                    (['--migrate-resolve=resume', '--migrate-source-retired'], 'resolve-1-1', 1,
                     'migration resolution failed: Protocol error'),
                    (['--migrate-resolve=resume', '--migrate-source-retired'], 'resolve-0-1', 1,
                     'migration resolution failed: Protocol error'),
                    (['--migrate-resolve=resume', '--migrate-source-retired'], 'resolve-0-1-0', 1,
                     'migration resolution failed: Protocol error'),
                    (['--migrate-resolve=resume', '--migrate-source-retired'], 'resolve-x-x', 1,
                     'migration resolution failed: Protocol error'),
                    (['--migrate-resolve=resume', '--migrate-source-retired'], 'resolve-1-x', 1,
                     'migration resolution failed: Protocol error'),
                    (['--migrate-resolve=resume', '--migrate-source-retired'], 'close', 1,
                     'migration resolution failed')):
                mode.write_text(reply + '\n')
                done, _ = self.run('--vm=mig0', rundir, *args, expect=status)
                self.check('resolve %s %s' % (args[0], reply), text in done.stdout + done.stderr,
                           out=done.stdout + done.stderr)
                last = reqlog.read_text().splitlines()[-1]
                action = args[0].split('=')[1]
                flag = 'source_retired=1' if action == 'resume' else 'acknowledge_loss=1'
                self.check('resolve request %s %s' % (action, reply),
                           last.startswith('cmd=migrate_resolve action=%s %s' % (action, flag)),
                           last=last)
            done, _ = self.run('--vm=guest0', rundir, '--get-vm-pid',
                               env={'VMMFAKE_FAIL': 'socket:1:24'}, expect=24)
            self.check('socket failure', 'Error creating bhyvectl socket' in done.stderr)
        finally:
            server.kill()
            server.wait()
            for fd in creds:
                os.close(fd)

    def finish(self):
        (self.out / 'results.json').write_text(json.dumps(self.results, indent=2) + '\n')
        passed = sum(r['passed'] for r in self.results)
        print('%d/%d bhyvectl checks passed (%s)' % (passed, len(self.results), self.vendor))
        return passed == len(self.results)


def run_suite(out, binary, libdir, build, vendor, base_env=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    suite = Suite(out, Path(binary), Path(libdir), Path(build), vendor, base_env)
    if vendor == 'intel':
        suite.test_vendor_identity()
    for test in (suite.test_usage, suite.test_lifecycle, suite.test_numeric_refusals,
                 suite.test_registers,
                 suite.test_descriptors, suite.test_misc, suite.test_capabilities,
                 suite.test_state_queries, suite.test_memory, suite.test_run_and_suspend,
                 suite.test_get_all, suite.test_failures, suite.test_ipc,
                 suite.test_memmap_flags, suite.test_individual_options,
                 suite.test_migration_cli, suite.test_msr_names, suite.test_md_short_circuit,
                 suite.test_rtc_unrepresentable):
        test()
    return suite.finish()


if __name__ == '__main__':
    out, binary, libdir, build = sys.argv[1:5]
    vendor = sys.argv[5] if len(sys.argv) > 5 else 'host'
    if not Path(out).resolve().is_relative_to('/usr/obj') or Path(out).exists():
        raise SystemExit('Use a new /usr/obj output directory')
    raise SystemExit(0 if run_suite(out, binary, libdir, build, vendor) else 1)
