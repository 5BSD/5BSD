/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable, otherwise idle VM only: malloc counters are system-wide. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <memstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sigio_cleanup_test.h"

static uint64_t
registrations(void)
{
	struct memory_type_list *list;
	struct memory_type *type;
	uint64_t count;

	list = memstat_mtl_alloc();
	if (list == NULL)
		return (UINT64_MAX);
	if (memstat_sysctl_malloc(list, 0) != 0) {
		memstat_mtl_free(list);
		fprintf(stderr, "Cannot obtain malloc statistics\n");
		return (UINT64_MAX);
	}
	type = memstat_mtl_find(list, ALLOCATOR_MALLOC, "sigio");
	if (type == NULL) {
		memstat_mtl_free(list);
		fprintf(stderr, "Missing SIGIO allocator statistics\n");
		return (UINT64_MAX);
	}
	count = memstat_get_count(type);
	memstat_mtl_free(list);
	return (count);
}

int
sigio_cleanup_test(void)
{
	uint64_t before, after, registered;
	int sockets[2], maxpid, failed = 0, result = 2, status;
	int ready[2] = {-1, -1}, gate[2] = {-1, -1};
	pid_t child = -1;
	char byte;
	size_t length = sizeof(maxpid);

	if (sysctlbyname("kern.pid_max", &maxpid, &length, NULL, 0) != 0 ||
	    length != sizeof(maxpid) || maxpid >= INT_MAX || maxpid <= 0)
		return (2);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
		return (2);
	before = registrations();
	if (before == UINT64_MAX)
		goto out;
	/* Positive control: the counter must observe a live registration. */
	if (fcntl(sockets[0], F_SETOWN, getpid()) != 0)
		goto out;
	registered = registrations();
	if (fcntl(sockets[0], F_SETOWN, 0) != 0)
		goto out;
	after = registrations();
	if (registered == UINT64_MAX || registered != before + 1 ||
	    after != before) {
		fprintf(stderr, "Counter unavailable or VM not quiescent\n");
		goto out;
	}
	/* A live process in another session covers the EPERM paths. */
	if (pipe(ready) != 0 || pipe(gate) != 0)
		goto out;
	child = fork();
	if (child < 0)
		goto out;
	if (child == 0) {
		close(ready[0]);
		close(gate[1]);
		close(sockets[0]);
		close(sockets[1]);
		if (setsid() == -1 || write(ready[1], "r", 1) != 1)
			_exit(1);
		close(ready[1]);
		_exit(read(gate[0], &byte, 1) == 0 ? 0 : 1);
	}
	close(ready[1]);
	ready[1] = -1;
	close(gate[0]);
	gate[0] = -1;
	if (read(ready[0], &byte, 1) != 1 || byte != 'r')
		goto out;
	for (int scenario = 0; scenario != 4; scenario++) {
		int group = scenario & 1;
		int target = scenario < 2 ? INT_MAX : child;
		int expected = scenario < 2 ? ESRCH : EPERM;
		before = registrations();
		if (before == UINT64_MAX)
			goto out;
		for (int i = 0; i < 128; i++) {
			if (fcntl(sockets[0], F_SETOWN,
			    group ? -target : target) != -1 || errno != expected)
				goto out;
		}
		after = registrations();
		printf("SIGIO_CLEANUP target=%s rejection=%s before=%" PRIu64
		    " after=%" PRIu64 "\n", group ? "group" : "process",
		    scenario < 2 ? "missing" : "session", before, after);
		if (after == UINT64_MAX || after != before)
			failed = 1;
	}
	result = failed ? 1 : 0;
out:
	for (int i = 0; i != 2; i++) {
		if (ready[i] != -1)
			close(ready[i]);
		if (gate[i] != -1)
			close(gate[i]);
	}
	if (child > 0) {
		pid_t waited;

		do {
			waited = waitpid(child, &status, 0);
		} while (waited == -1 && errno == EINTR);
		if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			result = 2;
	}
	close(sockets[0]);
	close(sockets[1]);
	if (result == 0)
		puts("SIGIO_CLEANUP_PASS");
	else
		fprintf(stderr, "SIGIO_CLEANUP_FAIL result=%d\n", result);
	return (result);
}
