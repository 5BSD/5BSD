#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual gdb.c migration fence and connection admission, with real sockets.

Extracts the breakpoint/vCPU-state definitions, new_connection() and the
migration fence functions from usr.sbin/bhyve/gdb.c. VM suspension and mevent
registration are substituted. No VM, debugger or device is used.
"""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root / 'usr.sbin/bhyve/gdb.c').read_text()
def between(start, end):
    a = s.index(start)
    return s[a:s.index(end, a)]
structs = between('struct breakpoint {', '/*\n * When a vCPU stops') + \
    between('struct vcpu_state {', 'static struct io_buffer cur_comm')
connection = between('static void\nnew_connection(', '/*\n * Debugger ownership during migration.')
fence = between('/*\n * Debugger ownership during migration.', '#ifndef WITHOUT_CAPSICUM\nstatic void\nlimit_gdb_socket')
for required in ('gdb_migration_fenced', 'gdb_migration_retired'):
    if required not in s[:s.index('struct gdb_reg {')]:
        raise SystemExit('fence state is not declared with the gdb.c statics')
fixture = r'''
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define GDB_BP_SIZE 1
enum ev_type { EVF_READ, EVF_WRITE };
struct mevent { int fd; };
struct vmctx { int unused; };
''' + structs + r'''
static struct vmctx vm, *ctx = &vm;
static int cur_fd = -1, cur_vcpu, stopped_vcpu = -1, guest_ncpus = 4;
static bool gdb_active, first_stop, report_next_stop;
static bool gdb_migration_fenced, gdb_migration_retired;
static TAILQ_HEAD(, breakpoint) breakpoints = TAILQ_HEAD_INITIALIZER(breakpoints);
static struct vcpu_state vcpu_state[4];
static cpuset_t vcpus_active, vcpus_suspended, vcpus_waiting;
static pthread_mutex_t gdb_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mevent *read_event, *write_event, events[2];
static atomic_int suspends, installs;
static struct mevent *mevent_add(int fd, enum ev_type type, void (*f)(int, enum ev_type, void *), void *arg) {
	(void)f; (void)arg; events[type].fd = fd; atomic_fetch_add(&installs, 1); return (&events[type]);
}
static void mevent_delete_close(struct mevent *e) { close(e->fd); }
static void gdb_readable(int fd, enum ev_type e, void *a) { (void)fd; (void)e; (void)a; }
static void gdb_writable(int fd, enum ev_type e, void *a) { (void)fd; (void)e; (void)a; }
static void gdb_suspend_vcpus(void) {
	/* The real function issues vm_suspend_all_cpus(ctx); a NULL ctx after
	 * retirement would be a use of the retired alias. */
	assert(ctx != NULL); atomic_fetch_add(&suspends, 1);
	vcpus_suspended = vcpus_active;
}
''' + connection + fence + r'''
static char path[104];
static int listener;
static int client(void) {
	int fd = socket(AF_UNIX, SOCK_STREAM, 0); assert(fd >= 0);
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	strlcpy(a.sun_path, path, sizeof(a.sun_path));
	assert(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
	return (fd);
}
/* Returns true if the server kept the connection. */
static bool attach(void) {
	int fd = client(), before = atomic_load(&installs);
	new_connection(listener, EVF_READ, NULL);
	char byte;
	bool kept = atomic_load(&installs) != before;
	if (!kept) assert(read(fd, &byte, 1) == 0); /* refused: closed by server */
	close(fd);
	return (kept);
}
static void detach(void) {
	/* Mirrors close_connection_locked's observable result. */
	pthread_mutex_lock(&gdb_lock);
	close(cur_fd); cur_fd = -1; read_event = write_event = NULL;
	CPU_ZERO(&vcpus_suspended);
	pthread_mutex_unlock(&gdb_lock);
}
static atomic_bool stop;
static atomic_int refused_in_window, accepted_in_window;
/* Fenced-window generation: odd while a fenced window is open.  An attach is
 * in a window only if the same odd generation is seen before and after it. */
static atomic_uint window;
static void *attacher(void *unused) {
	(void)unused;
	while (!atomic_load(&stop)) {
		unsigned gen = atomic_load(&window);
		bool kept = attach();
		bool in_window = (gen & 1) != 0 && atomic_load(&window) == gen;
		if (kept) {
			/* A kept connection is never installed while fenced. */
			pthread_mutex_lock(&gdb_lock);
			assert(!gdb_migration_fenced);
			pthread_mutex_unlock(&gdb_lock);
			if (in_window) atomic_fetch_add(&accepted_in_window, 1);
			detach();
		} else if (in_window)
			atomic_fetch_add(&refused_in_window, 1);
	}
	return (NULL);
}
int main(void) {
	const char *reason;
	char dir[] = "gdbfence.XXXXXX"; assert(mkdtemp(dir));
	snprintf(path, sizeof(path), "%s/s", dir);
	listener = socket(AF_UNIX, SOCK_STREAM, 0); assert(listener >= 0);
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	strlcpy(a.sun_path, path, sizeof(a.sun_path));
	assert(bind(listener, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(listener, 64) == 0);
	for (int i = 0; i < guest_ncpus; i++) CPU_SET(i, &vcpus_active);
	unsigned checks = 0;
	/* No debug server: nothing to coordinate. */
	assert(gdb_migration_fence(&reason) == 0 && reason == NULL && !gdb_migration_fenced);
	gdb_migration_unfence(); gdb_migration_retire();
	assert(!gdb_migration_retired && ctx == &vm);
	gdb_active = true; checks++;
	/* gdb.wait before any debugger attached: vCPU 0 is held. */
	CPU_SET(0, &vcpus_suspended); stopped_vcpu = 0;
	assert(gdb_migration_fence(&reason) == EBUSY && strstr(reason, "vCPU is held"));
	CPU_ZERO(&vcpus_suspended); stopped_vcpu = -1;
	CPU_SET(2, &vcpus_waiting);
	assert(gdb_migration_fence(&reason) == EBUSY && strstr(reason, "vCPU is held"));
	CPU_ZERO(&vcpus_waiting); checks += 2;
	/* An attached client owns the guest. */
	assert(attach() && cur_fd >= 0 && atomic_load(&suspends) == 1);
	assert(gdb_migration_fence(&reason) == EBUSY && strstr(reason, "client is attached"));
	assert(!gdb_migration_fenced);
	detach(); checks++;
	/* Breakpoints in guest memory and pending step state also refuse. */
	struct breakpoint bp = { .gpa = 0x1000 };
	TAILQ_INSERT_TAIL(&breakpoints, &bp, link);
	assert(gdb_migration_fence(&reason) == EBUSY && strstr(reason, "breakpoints"));
	TAILQ_REMOVE(&breakpoints, &bp, link);
	for (int field = 0; field < 3; field++) {
		struct vcpu_state *v = &vcpu_state[3];
		if (field == 0) v->stepping = true;
		if (field == 1) v->stepped = true;
		if (field == 2) v->hit_swbreak = true;
		assert(gdb_migration_fence(&reason) == EBUSY && strstr(reason, "pending"));
		memset(v, 0, sizeof(*v));
	}
	checks += 4;
	/* Idle server: fence, refuse attach, refuse a second fence, rollback. */
	assert(gdb_migration_fence(&reason) == 0 && gdb_migration_fenced);
	assert(gdb_migration_fence(&reason) == EBUSY && strstr(reason, "already fenced"));
	int before = atomic_load(&suspends);
	for (int i = 0; i < 8; i++) assert(!attach());
	assert(cur_fd == -1 && atomic_load(&suspends) == before);
	gdb_migration_unfence();
	assert(!gdb_migration_fenced && attach() && cur_fd >= 0);
	detach(); checks += 3;
	/* Concurrent attach attempts never land inside a fenced window. */
	pthread_t thread;
	assert(pthread_create(&thread, NULL, attacher, NULL) == 0);
	for (int cycle = 0; cycle < 200; cycle++) {
		while (gdb_migration_fence(&reason) != 0) {
			/* A connection raced in; wait for the attacher to detach it. */
			assert(strstr(reason, "client is attached") || strstr(reason, "vCPU is held"));
			usleep(100);
		}
		atomic_fetch_add(&window, 1);	/* open: odd */
		for (int spin = 0; spin < 50; spin++) {
			pthread_mutex_lock(&gdb_lock);
			assert(cur_fd == -1);
			pthread_mutex_unlock(&gdb_lock);
			usleep(20);
		}
		atomic_fetch_add(&window, 1);	/* closed: even */
		usleep(50);
		gdb_migration_unfence();
		usleep(200);
	}
	atomic_store(&stop, true);
	assert(pthread_join(thread, NULL) == 0);
	assert(atomic_load(&accepted_in_window) == 0);
	printf("concurrency: %d attaches refused inside fenced windows\n",
	    atomic_load(&refused_in_window));
	assert(atomic_load(&refused_in_window) > 0);
	checks++;
	/* Retirement makes the fence permanent and drops the vmctx alias. */
	assert(gdb_migration_fence(&reason) == 0);
	gdb_migration_retire();
	gdb_migration_unfence();
	assert(gdb_migration_fenced && gdb_migration_retired && ctx == NULL);
	for (int i = 0; i < 4; i++) assert(!attach());
	assert(gdb_migration_fence(&reason) == EBUSY && strstr(reason, "already fenced"));
	checks++;
	close(listener); unlink(path); rmdir(dir);
	printf("PASS: %u gdb migration fence checks; actual new_connection refused while fenced\n", checks);
	return (0);
}
'''
(out / 'gdbfence.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-pthread',
    '-fsanitize=address,undefined', str(out / 'gdbfence.c'),
    '-o', str(out / 'gdbfence')], check=True)
subprocess.run([str(out / 'gdbfence')], cwd=out, check=True, timeout=60)
