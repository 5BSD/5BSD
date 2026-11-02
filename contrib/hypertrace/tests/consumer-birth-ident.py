#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile the production process-incarnation identifier generator."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_subr.c').read_text()
start = source.index('static int\ndtraced_self_procdesc(')
end = source.index('\nint\nopen_dtraced_session(', start)
producer = source[start:end]
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#define DTRACED_FDIDENTLEN 128
PRODUCER
static void *worker(void *ptr) {
    char ident[DTRACED_FDIDENTLEN] = { 0 };
    assert(dtraced_birth_ident(ident) == 0);
    assert(strcmp(ident, (char *)ptr) == 0);
    return NULL;
}
static void run(void) {
    for (birth_mock_error = 1; birth_mock_error <= 5; birth_mock_error++) {
        char failed[DTRACED_FDIDENTLEN], original[DTRACED_FDIDENTLEN];
        memset(failed, 0x5a, sizeof(failed)); memcpy(original, failed, sizeof(failed));
        assert(dtraced_birth_ident(failed) == -1);
        assert(errno == (birth_mock_error == 1 ? ENOTTY : birth_mock_error == 2 ? ESRCH : EPROTO));
        assert(memcmp(failed, original, sizeof(failed)) == 0);
    }
    birth_mock_error = 0;
    char first[DTRACED_FDIDENTLEN] = { 0 };
    char second[DTRACED_FDIDENTLEN] = { 0 };
    assert(dtraced_birth_ident(first) == 0);
    assert(dtraced_birth_ident(second) == 0);
    assert(strcmp(first, second) == 0);
    char prefix[32];
    assert(snprintf(prefix, sizeof(prefix), "dtrace-%u-",
        (unsigned)getpid()) > 0);
    assert(strncmp(first, prefix, strlen(prefix)) == 0 &&
        strlen(first) == strlen(prefix) + 32);
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(pipefd[0]);
        char inherited[DTRACED_FDIDENTLEN] = { 0 };
        assert(dtraced_birth_ident(inherited) == 0);
        assert(write(pipefd[1], inherited, sizeof(inherited)) ==
            sizeof(inherited));
        _exit(0);
    }
    close(pipefd[1]);
    char inherited[DTRACED_FDIDENTLEN] = { 0 };
    assert(read(pipefd[0], inherited, sizeof(inherited)) ==
        sizeof(inherited));
    close(pipefd[0]);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    assert(strcmp(inherited, first) != 0);
    pthread_t threads[8];
    for (unsigned i = 0; i < 8; i++)
        assert(pthread_create(&threads[i], NULL, worker, first) == 0);
    for (unsigned i = 0; i < 8; i++)
        assert(pthread_join(threads[i], NULL) == 0);
    printf("PASS (%s): consumer incarnation is stable per process and fork-distinct\n",
        birth_mock_capmode ? "capability mode, pdself" : "ambient, pdopenpid");
}
int main() {
    /* Ambient first: dtrace(1) from a shell (pdself would be ENOTCAPABLE). */
    for (birth_mock_capmode = 0; birth_mock_capmode <= 1; birth_mock_capmode++)
        run();
    /* A kernel without Capsicum: cap_getmode(2) is ENOSYS, the caller is
     * ambient and names itself with pdopenpid(2). */
    birth_mock_capmode = 0;
    birth_mock_capmode_errno = ENOSYS;
    run();
    /* Any other cap_getmode(2) failure gives no identity. */
    birth_mock_capmode_errno = EFAULT;
    birth_mock_error = 0;
    char ident[DTRACED_FDIDENTLEN];
    errno = 0;
    assert(dtraced_birth_ident(ident) == -1 && errno == EFAULT);
    puts("PASS: cap_getmode ENOSYS is ambient; another failure is refused");
}
'''.replace('PRODUCER', producer)
cfile = out / 'consumer-birth-ident.c'
cfile.write_text(fixture)
binary = out / 'consumer-birth-ident'
subprocess.run(['cc', '-std=c11', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra',
    '-Werror', '-UNDEBUG', '-pthread', '-fsanitize=address,undefined', '-include', str(root / 'contrib/hypertrace/tests/consumer-birth-mock.h'),
    '-I' + str(root / 'sys'), str(cfile), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
