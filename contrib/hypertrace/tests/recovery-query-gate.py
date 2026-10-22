#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check the production query-only gate without opening a tracing device."""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/hypertrace.c').read_text()
start = source.index('int\nhypertrace_session_recovery_open(')
end = source.index('static int\nht_session_gate_query', start)
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/capsicum.h>
#include <sys/hypertrace_wire.h>
static bool prepared;
static int session_gate_fd = -1, session_gate_error = ENXIO;
static int mode, opens, closes, rights_calls, limits, queries;
static int test_open(const char *path, int flags) {
 assert(strcmp(path, "/dev/dtrace/hypertrace") == 0);
 assert(flags == (O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
 opens++; if (mode == 1) { errno = ENOENT; return -1; } return 101;
}
static int test_close(int fd) { assert(fd == 101); closes++; return 0; }
static int test_rights(int fd, const cap_rights_t *rights) {
 assert(fd == 101 && cap_rights_is_set(rights, CAP_IOCTL)); rights_calls++;
 if (mode == 2) { errno = EPERM; return -1; } return 0;
}
static int test_limits(int fd, const unsigned long *commands, size_t count) {
 assert(fd == 101 && count == 1 && commands[0] == HYPERTRACE_IOC_EPOCH_QUERY);
 limits++; if (mode == 3) { errno = ENOTCAPABLE; return -1; } return 0;
}
static int test_ioctl(int fd, unsigned long command, void *data) {
 struct hypertrace_epoch_query *q = data;
 assert(fd == 101 && command == HYPERTRACE_IOC_EPOCH_QUERY);
 assert(q->vmid == 7 && q->epoch == 9); queries++;
 if (mode == 4) { errno = EIO; return -1; }
 if (mode == 5) q->live = 1;
 if (mode == 6) q->reserved2 = 1;
 return 0;
}
#define open test_open
#define close test_close
#define caph_rights_limit test_rights
#define cap_ioctls_limit test_limits
#define ioctl test_ioctl
'''
fixture += source[start:end]
fixture += r'''
int main(void) {
 for (mode = 1; mode <= 3; mode++) {
  assert(hypertrace_session_recovery_open() == (mode == 1 ? ENOENT : mode == 2 ? EPERM : ENOTCAPABLE));
  assert(session_gate_fd == -1 && !prepared);
 }
 assert(opens == 3 && closes == 2 && rights_calls == 2 && limits == 1);
 mode = 0; prepared = true;
 assert(hypertrace_session_recovery_open() == EBUSY && opens == 3);
 prepared = false;
 assert(hypertrace_session_recovery_open() == 0 && !prepared);
 assert(hypertrace_session_recovery_open() == EBUSY && opens == 4);
 assert(hypertrace_session_retired(7, 9) == 0 && queries == 1);
 for (mode = 4; mode <= 6; mode++) {
  assert(hypertrace_session_retired(7, 9) == -1);
  assert(errno == (mode == 4 ? EIO : mode == 5 ? EBUSY : EPROTO));
 }
 hypertrace_session_recovery_close();
 assert(session_gate_fd == -1 && closes == 3);
 hypertrace_session_recovery_close(); assert(closes == 3);
 assert(hypertrace_session_retired(7, 9) == -1 && errno == ENXIO);
 assert(queries == 4);
 mode = 0; assert(hypertrace_session_recovery_open() == 0);
 hypertrace_session_recovery_close(); assert(closes == 4);
 return 0;
}
'''
(out / 'gate.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), str(out / 'gate.c'), '-o', str(out / 'gate')], check=True)
subprocess.run([str(out / 'gate')], check=True, timeout=30)
print('PASS: query-only rights, setup failures, lifecycle isolation, retirement results and cleanup; no device opened')
