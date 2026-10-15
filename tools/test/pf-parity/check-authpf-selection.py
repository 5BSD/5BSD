#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production authpf selection function without host PF or privileges.

Compile the actual change_filter body with injected NSS, privilege and exec
boundaries. File lookup, allocation, fork and wait use the real implementation.
This is a focused component check, not SSH/session or firewall qualification.
"""
import argparse
from pathlib import Path
import re
import resource
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', type=Path, default=Path('/usr/src/contrib/openbsd-pf/usr.sbin/authpf/authpf.c'))
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if not str(a.output.resolve()).startswith('/usr/obj/5BSD-pf-parity/'):
    p.error('output must be within the PF parity object directory')
a.output.mkdir(parents=True, exist_ok=True)
source_text = a.source.read_text()
match = re.search(r'static int\nchange_filter\([^\n]+\)\n\{.*?\n\}', source_text, re.S)
if not match:
    p.error('production change_filter function not found')
preamble = r'''
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <grp.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#define PATH_USER_DIR "users"
#define PATH_GROUP_DIR "groups"
#define PATH_PFRULES "default.rules"
#define PATH_PFCTL "/test-only/pfctl"
static void *pfh __attribute__((unused));
static int dev __attribute__((unused)) = 42;
static int user_ip = 1, missing_group;
static char anchorname[] = "authpf", rulesetname[] = "test";
static struct timeval Tstart, Tend;
static const char *expected;
static int pfctl_fd(void *p) { (void)p; return 42; }
static void remove_stale_rulesets(void) { abort(); }
static struct group *test_getgrgid(gid_t gid) {
    static struct group gr = { .gr_name = "primary", .gr_gid = 4242 };
    assert(gid == 4242);
    return missing_group ? NULL : &gr;
}
static gid_t test_getgid(void) { return 4242; }
static int test_setregid(gid_t a, gid_t b) {
    assert(a == 4242 && b == 4242); return 0;
}
static int test_setresgid(gid_t a, gid_t b, gid_t c) {
    assert(a == 4242 && b == 4242 && c == 4242); return 0;
}
static void test_syslog(int priority, const char *fmt, ...) {
    (void)priority; (void)fmt;
}
static int test_execvp(const char *path, char *const argv[]) {
    assert(strcmp(path, PATH_PFCTL) == 0);
    assert(strcmp(argv[2], "/dev/fd/42") == 0);
    assert(strcmp(argv[5], "authpf/test") == 0);
    assert(strcmp(argv[7], "user_id=alice") == 0);
    assert(strcmp(argv[user_ip ? 10 : 8], "-f") == 0);
    assert(strcmp(argv[user_ip ? 11 : 9], expected) == 0);
    assert(argv[user_ip ? 12 : 10] == NULL);
    if (user_ip) assert(strcmp(argv[9], "user_ip=192.0.2.1") == 0);
    _exit(0);
}
#define getgrgid test_getgrgid
#define getgid test_getgid
#define setregid test_setregid
#define setresgid test_setresgid
#define syslog test_syslog
#define execvp test_execvp
#define execv test_execvp
'''
driver = r'''
int main(int argc, char **argv) {
    assert(argc == 4);
    expected = argv[1];
    user_ip = atoi(argv[2]);
    missing_group = atoi(argv[3]);
    int result = change_filter(1, "alice", "192.0.2.1");
    assert(result == (missing_group ? -1 : 0));
    return 0;
}
'''
cfile = a.output/'authpf-selection.c'
timing = re.search(r'struct (timeval|timespec)\s+Tstart, Tend;', source_text)
if not timing:
    p.error('production session timestamp declaration not found')
preamble = preamble.replace('struct timeval Tstart, Tend;', timing.group())
cfile.write_text(preamble + match.group() + '\n' + driver)
binary = (a.output/'authpf-selection').resolve()
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-O2', str(cfile), '-o', str(binary)], check=True)
for label, files, expected, noip, missing in [
    ('user_precedes_group_and_default', ['users/alice/authpf.rules','groups/primary/authpf.rules','default.rules'], 'users/alice/authpf.rules', False, False),
    ('primary_group_precedes_default', ['groups/primary/authpf.rules','default.rules'], 'groups/primary/authpf.rules', False, False),
    ('global_default', ['default.rules'], 'default.rules', False, False),
    ('supplementary_group_not_selected', ['groups/other/authpf.rules','default.rules'], 'default.rules', False, False),
    ('group_noip', ['groups/primary/authpf.rules','default.rules'], 'groups/primary/authpf.rules', True, False),
    ('missing_primary_group_fails', ['users/alice/authpf.rules','default.rules'], 'unused', False, True),
]:
    with tempfile.TemporaryDirectory(dir=a.output) as work:
        for name in files:
            target = Path(work)/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('# fixture\n')
        subprocess.run([str(binary), expected, str(int(not noip)), str(int(missing))], cwd=work, check=True)
    print('AUTHPF_SELECTION_CASE', label, 'passed', flush=True)
