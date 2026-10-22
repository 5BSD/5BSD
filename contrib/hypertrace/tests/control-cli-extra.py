#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Supplementary process cases for the actual dtracedctl executable.

Usage: control-cli-extra.py OUTPUT BINARY

Complements control-cli-offline.py with option-ordering, positional-list,
allocation, connect-progress and second-clock cases. An LD_PRELOAD shim
redirects only the daemon socket path to a private /tmp/htctl2-* listener
(any other connect fails), and injects exactly one named fault, reported on
stderr so each case can require that its fault fired. Oracles: exit status,
diagnostic text, the exact request frame the peer decodes, and stdout.
"""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading

out, binary = (Path(p).resolve() for p in sys.argv[1:3])
assert out.is_relative_to('/usr/obj') and binary.is_relative_to('/usr/obj')
out.mkdir(parents=True, exist_ok=True)
root = Path(__file__).resolve().parents[3]
shim = out / 'extra-shim.c'
shim.write_text(r'''
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dtraced.h>
static int fired, clock_calls, hello_sent, stalled;
static const char *mode(void) { const char *m = getenv("HTCTL_FAULT"); return m ? m : ""; }
static void hit(const char *name) {
	fired = 1;
	(void)write(2, "HTCTL_FAULT_HIT=", 16);
	(void)write(2, name, strlen(name));
	(void)write(2, "\n", 1);
}
void *calloc(size_t n, size_t size) {
	static void *(*real)(size_t, size_t);
	if (!real) real = dlsym(RTLD_NEXT, "calloc");
	/* parse_names allocates exactly one pointer per name */
	if (!fired && !strcmp(mode(), "calloc") && size == sizeof(char *) && n == 2) {
		hit("calloc"); errno = ENOMEM; return NULL;
	}
	return real(n, size);
}
ssize_t send(int fd, const void *b, size_t n, int flags) {
	ssize_t (*real)(int, const void *, size_t, int) = dlsym(RTLD_NEXT, "send");
	ssize_t r = real(fd, b, n, flags);
	if (r == 160)
		hello_sent = 1;	/* the client hello is complete */
	return r;
}
int clock_gettime(clockid_t id, struct timespec *ts) {
	int (*real)(clockid_t, struct timespec *) = dlsym(RTLD_NEXT, "clock_gettime");
	(void)clock_calls;
	if (id == CLOCK_MONOTONIC && !fired && hello_sent &&
	    !strcmp(mode(), "clock-after-hello")) {
		hit("clock-after-hello"); errno = EIO; return -1;
	}
	if (id == CLOCK_MONOTONIC && stalled) {
		errno = EIO;	/* the pending connect cannot be finished */
		return -1;
	}
	return real(id, ts);
}
int connect(int fd, const struct sockaddr *a, socklen_t l) {
	int (*real)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
	const char *path = getenv("HTCTL_SOCKET");
	struct sockaddr_un r = { .sun_family = AF_UNIX };
	if (!path || strncmp(path, "/tmp/htctl2-", 12) || a->sa_family != AF_UNIX ||
	    strcmp(((const struct sockaddr_un *)a)->sun_path, DTRACED_SOCKPATH)) {
		errno = EPERM; return -1;
	}
	strlcpy(r.sun_path, path, sizeof(r.sun_path));
	r.sun_len = SUN_LEN(&r);
	int rc = real(fd, (struct sockaddr *)&r, r.sun_len);
	if (rc == 0 && !fired && (!strcmp(mode(), "connect-inprogress") ||
	    !strcmp(mode(), "connect-interrupted") ||
	    !strcmp(mode(), "connect-already"))) {
		/* connected; report the pending states a slow connect returns */
		hit(mode());
		errno = !strcmp(mode(), "connect-inprogress") ? EINPROGRESS :
		    !strcmp(mode(), "connect-already") ? EALREADY : EINTR;
		return -1;
	}
	if (rc == 0 && !fired && !strcmp(mode(), "connect-stalled")) {
		/* still pending when the deadline clock fails */
		hit("connect-stalled");
		stalled = 1;
		errno = EINPROGRESS;
		return -1;
	}
	if (rc == 0 && !fired && !strcmp(mode(), "connect-refused")) {
		hit("connect-refused"); errno = ECONNREFUSED; return -1;
	}
	return rc;
}
''')
subprocess.run(['/usr/bin/cc', '-shared', '-fPIC', '-I' + str(root / 'usr.sbin/dtraced'),
                str(shim), '-o', str(out / 'extra-shim.so')], check=True)

VERSION, HELLO, HEADER = 67, 160, 520
cases = []


def add(name, args, status, peer=None, diagnostic='', fault='', names=None,
        kind=15, stdout=None):
    cases.append(dict(name=name, args=args, status=status, peer=peer,
                      diagnostic=diagnostic, fault=fault, names=names, kind=kind,
                      stdout=stdout))


STATS = (2, 3, 5, 7)
STATS_OUT = ''.join('%s: %d\n' % (k, v) for k, v in zip(
    ('forwarder channels', 'outbound deliveries', 'installed deliveries',
     'revoked deliveries'), STATS))
add('cleanup-then-stats', ['--cleanup-state', '--show-stats'], 64, diagnostic='Usage:')
add('stats-empty-positional', ['--show-stats', ''], 64, diagnostic='invalid VM names')
add('cleanup-bad-positional', ['--cleanup-state', 'a,,b'], 64, diagnostic='invalid VM names')
add('positional-after-inline', ['--show-stats=a', 'b'], 64, diagnostic='invalid VM names')
add('calloc-failure', ['--show-stats=a,b'], 64,
    diagnostic='invalid VM names: ' + os.strerror(12), fault='calloc')
add('connect-in-progress', ['--show-stats=first'], 0, peer='ok', fault='connect-inprogress',
    names=['first'], stdout=STATS_OUT)
add('connect-interrupted', ['--cleanup-state=first,second'], 0, peer='ok',
    fault='connect-interrupted', names=['first', 'second'], kind=3, stdout='')
add('connect-already', ['--show-stats=first'], 0, peer='ok', fault='connect-already',
    names=['first'], stdout=STATS_OUT)
add('connect-stalled', ['--show-stats'], 69, peer='accept-only',
    diagnostic='connection failed: ' + os.strerror(5), fault='connect-stalled')
add('connect-refused', ['--show-stats'], 69, peer='accept-only',
    diagnostic='connection failed: ' + os.strerror(61), fault='connect-refused')
add('request-clock-failure', ['--show-stats'], 74, peer='hello-only',
    diagnostic='statistics failed: ' + os.strerror(5), fault='clock-after-hello')
add('stats-positional-list', ['--show-stats', 'vm1,vm2,vm3'], 0, peer='ok',
    names=['vm1', 'vm2', 'vm3'], stdout=STATS_OUT)


def recv_exact(s, n):
    data = bytearray()
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise EOFError(len(data))
        data.extend(chunk)
    return bytes(data)


def serve(listener, case, observed, errors):
    try:
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(5)
            if case['peer'] == 'accept-only':
                return
            peer.sendall(struct.pack('<IIQ', 3, VERSION, 0) + bytes(144))
            client = recv_exact(peer, HELLO)
            assert struct.unpack_from('<IIQ', client) == (1, VERSION, 1)
            if case['peer'] == 'hello-only':
                assert peer.recv(1) == b''
                return
            size = struct.unpack('<Q', recv_exact(peer, 8))[0]
            frame = recv_exact(peer, size)
            assert struct.unpack_from('<Q', frame, 0)[0] == case['kind']
            count = struct.unpack_from('<Q', frame, 304)[0]
            off, names = HEADER, []
            for _ in range(count):
                n = struct.unpack_from('<Q', frame, off)[0]
                off += 8
                names.append(frame[off:off + n - 1].decode())
                assert frame[off + n - 1] == 0
                off += n
            assert off == size
            observed['names'] = names
            peer.sendall(b'\1')
            if case['kind'] == 15:
                peer.sendall(struct.pack('<4Q', *STATS))
    except Exception as exc:
        errors.append(repr(exc))


results = []
with tempfile.TemporaryDirectory(prefix='htctl2-', dir='/tmp') as tmp:
    path = os.path.join(tmp, 'peer.sock')
    for case in cases:
        listener = thread = None
        observed, errors = {}, []
        if case['peer']:
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(path)
            listener.listen(1)
            listener.settimeout(5)
            thread = threading.Thread(target=serve, args=(listener, case, observed, errors))
            thread.start()
        env = dict(os.environ, LD_PRELOAD=str(out / 'extra-shim.so'),
                   HTCTL_SOCKET=path, HTCTL_FAULT=case['fault'])
        try:
            run = subprocess.run([str(binary), *case['args']], env=env,
                                 capture_output=True, text=True, timeout=15)
        finally:
            if thread:
                thread.join(8)
            if listener:
                listener.close()
                os.unlink(path)
        ok = run.returncode == case['status'] and case['diagnostic'] in run.stderr
        ok = ok and not errors and (thread is None or not thread.is_alive())
        if case['fault']:
            ok = ok and run.stderr.count('HTCTL_FAULT_HIT=' + case['fault'] + '\n') == 1
        else:
            ok = ok and 'HTCTL_FAULT_HIT=' not in run.stderr
        if case['names'] is not None:
            ok = ok and observed.get('names') == case['names']
        if case['stdout'] is not None:
            ok = ok and run.stdout == case['stdout']
        results.append(dict(case=case['name'], status=run.returncode, passed=ok,
                            stderr=run.stderr[-400:], stdout=run.stdout,
                            observed=observed, errors=errors))
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r))
print('control-cli-extra:', len(results), 'cases;', len(failed), 'failures')
raise SystemExit(1 if failed else 0)
