#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile the production consumer-session loader against real local files."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
start = source.index('static int\ndtrace_consumer_session_load(')
brace = source.index('{', start)
depth = 1
end = brace + 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
loader = source[start:end]
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static int g_hypertrace_session_fd = -1;
LOADER
static void record(const char *path, uint8_t id, int corrupt) {
    uint8_t wire[52] = { 'H','C','S','1' };
    wire[4] = id;
    assert(SHA256(wire, 20, wire + 20) != NULL);
    if (corrupt) wire[20]++;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    assert(fchmod(fd, 0600) == 0);
    assert(write(fd, wire, sizeof(wire)) == sizeof(wire));
    assert(fsync(fd) == 0);
    assert(close(fd) == 0);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    char path[1024], linkpath[1024];
    assert(snprintf(path, sizeof(path), "%s/session", argv[1]) > 0);
    assert(snprintf(linkpath, sizeof(linkpath), "%s/link", argv[1]) > 0);
    uint8_t session[16] = { 0 };
    record(path, 0x71, 0);
    assert(dtrace_consumer_session_load(path, session) == 0);
    assert(session[0] == 0x71 && g_hypertrace_session_fd >= 0);
    assert(dtrace_consumer_session_load(path, session) == -1 && errno == EINVAL);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(g_hypertrace_session_fd);
        g_hypertrace_session_fd = -1;
        uint8_t other[16] = { 0 };
        _exit(dtrace_consumer_session_load(path, other) == -1 &&
            (errno == EWOULDBLOCK || errno == EAGAIN) ? 0 : 1);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    close(g_hypertrace_session_fd);
    g_hypertrace_session_fd = -1;
    assert(dtrace_consumer_session_load("relative", session) == -1 &&
        errno == EINVAL);
    unlink(linkpath);
    assert(symlink(path, linkpath) == 0);
    assert(dtrace_consumer_session_load(linkpath, session) == -1);
    unlink(linkpath);
    record(path, 0x71, 1);
    assert(dtrace_consumer_session_load(path, session) == -1 &&
        errno == EPROTO);
    record(path, 0, 0);
    assert(dtrace_consumer_session_load(path, session) == -1 &&
        errno == EPROTO);
    record(path, 0x71, 0);
    assert(chmod(path, 0644) == 0);
    assert(dtrace_consumer_session_load(path, session) == -1 &&
        errno == EPROTO);
    assert(chmod(path, 0600) == 0);
    assert(link(path, linkpath) == 0);
    assert(dtrace_consumer_session_load(path, session) == -1 &&
        errno == EPROTO);
    assert(unlink(linkpath) == 0);
    assert(truncate(path, 20) == 0);
    assert(dtrace_consumer_session_load(path, session) == -1 &&
        errno == EPROTO);
    unlink(path);
    puts("PASS: consumer session file binds one owner and rejects bad records");
    return 0;
}
'''.replace('LOADER', loader)
cfile = out / 'consumer-session-file.c'
cfile.write_text(fixture)
binary = out / 'consumer-session-file'
subprocess.run(['cc', '-std=c11', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra',
    '-Werror', '-fsanitize=address,undefined', str(cfile), '-lcrypto', '-o',
    str(binary)], check=True)
subprocess.run([str(binary), str(out)], check=True, timeout=30)
