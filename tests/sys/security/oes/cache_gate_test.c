/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A client's first decision-cache entry makes the hooks whose events drop
 * cached decisions live (oes_gate_client_update()).  Every OES_IOC_CACHE_ADD
 * of the client must return only once they are, including a second add that
 * races the first: otherwise a change made in the window does not drop the
 * entry.
 *
 * The test kernel's hold point debug.mac_capability.test_issuer_oes_gate_hold
 * parks the first add's gate update after it has taken sc_gate_sx and before
 * it publishes.  A second add from another thread of the same client then
 * either waits for the gate, releasing the parked update as it does (the
 * hold point's rule), or returns at once.  When it returns, it reads whether
 * VNODE_CHECK_WRITE, an invalidating hook, is live.  Nothing is timed: the
 * order is fixed by the hold point.  The case needs a test kernel and says
 * so elsewhere.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define	GATE_HOLD	"debug.mac_capability.test_issuer_oes_gate_hold"

static int
gate_hold(int v)
{

	return (sysctlbyname(GATE_HOLD, NULL, NULL, &v, sizeof(v)));
}

/* Is the hook named live?  -1 if security.oes.gate.hooks has no such line. */
static int
hook_live(const char *name)
{
	char *buf, *line, *p;
	size_t len;
	int live;

	len = 0;
	if (sysctlbyname("security.oes.gate.hooks", NULL, &len, NULL, 0) != 0)
		return (-1);
	buf = malloc(len + 1);
	if (buf == NULL ||
	    sysctlbyname("security.oes.gate.hooks", buf, &len, NULL, 0) != 0) {
		free(buf);
		return (-1);
	}
	buf[len] = '\0';
	live = -1;
	for (line = strtok(buf, "\n"); line != NULL; line = strtok(NULL, "\n")) {
		p = strchr(line, ' ');
		if (p == NULL || strncmp(p + 1, name, strlen(name)) != 0 ||
		    p[1 + strlen(name)] != ' ')
			continue;
		p = strstr(line, " live ");
		if (p != NULL)
			live = atoi(p + 6);
		break;
	}
	free(buf);
	return (live);
}

struct adder {
	int		fd;
	oes_cache_entry_t entry;
	int		error;
	int		write_live;	/* VNODE_CHECK_WRITE when the add returned */
};

static void *
add_entry(void *arg)
{
	struct adder *a = arg;

	a->error = ioctl(a->fd, OES_IOC_CACHE_ADD, &a->entry) == 0 ? 0 : errno;
	a->write_live = hook_live("VNODE_CHECK_WRITE");
	return (NULL);
}

/*
 * An AUTH_OPEN of a descendant, answered, gives the keys of a valid cache
 * entry for this client.
 */
static void
make_entry(int fd, const char *path, oes_cache_entry_t *e)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	oes_response_t resp;
	test_msg_buf buf;
	pid_t pid;
	int status, f;

	ATF_REQUIRE(test_set_descendants_scope(fd) == 0);
	ATF_REQUIRE(test_set_mode(fd, OES_MODE_AUTH) == 0);
	ATF_REQUIRE(test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		f = open(path, O_RDONLY);
		_exit(f >= 0 ? 0 : 1);
	}
	for (;;) {
		ATF_REQUIRE(test_wait_event(fd, &buf.msg, INFTIM) == 0);
		if (buf.msg.em_action != OES_ACTION_AUTH)
			continue;
		memset(&resp, 0, sizeof(resp));
		resp.er_id = buf.msg.em_id;
		resp.er_result = OES_AUTH_ALLOW;
		ATF_REQUIRE(write(fd, &resp, sizeof(resp)) ==
		    (ssize_t)sizeof(resp));
		if (buf.msg.em_event == OES_EVENT_AUTH_OPEN &&
		    buf.msg.em_process.ep_pid == pid)
			break;
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	memset(e, 0, sizeof(*e));
	e->ece_key.eck_event = OES_EVENT_AUTH_OPEN;
	e->ece_key.eck_flags = OES_CACHE_KEY_PROCESS | OES_CACHE_KEY_FILE;
	e->ece_key.eck_op_flags = buf.msg.em_event_data.open.access;
	e->ece_key.eck_process = buf.msg.em_process.ep_token;
	e->ece_key.eck_exec_id = buf.msg.em_process.ep_exec_id;
	e->ece_key.eck_file = buf.msg.em_event_data.open.file.ef_token;
	e->ece_result = OES_AUTH_ALLOW;
	e->ece_ttl_ms = OES_MAX_CACHE_TTL_MS;
}

ATF_TC(second_add_waits_for_gate);
ATF_TC_HEAD(second_add_waits_for_gate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A cache add racing the client's first one returns only once the "
	    "invalidating hooks are live");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(second_add_waits_for_gate, tc)
{
	struct adder a, b;
	pthread_t ta, tb;
	char path[] = "cache_gate.XXXXXX";
	int fd, f, v;
	size_t len;

	len = sizeof(v);
	if (sysctlbyname(GATE_HOLD, &v, &len, NULL, 0) != 0)
		atf_tc_skip("DEFERRED_STACK_TIER: no %s: %s (test kernels only)",
		    GATE_HOLD, strerror(errno));
	if (hook_live("VNODE_CHECK_WRITE") != 0)
		atf_tc_fail("VNODE_CHECK_WRITE is already live (%d): another "
		    "client uses the cache, so the window cannot be shown",
		    hook_live("VNODE_CHECK_WRITE"));
	f = mkstemp(path);
	ATF_REQUIRE(f >= 0);
	close(f);
	fd = test_open_oes();
	ATF_REQUIRE(fd >= 0);
	make_entry(fd, path, &a.entry);

	a.fd = b.fd = fd;
	b.entry = a.entry;
	ATF_REQUIRE_MSG(gate_hold(1) == 0, "%s: %s", GATE_HOLD,
	    strerror(errno));
	ATF_REQUIRE(pthread_create(&ta, NULL, add_entry, &a) == 0);
	/* Returns once the first add's gate update has parked. */
	ATF_REQUIRE_MSG(gate_hold(2) == 0, "waiting for the park: %s",
	    strerror(errno));
	ATF_REQUIRE(pthread_create(&tb, NULL, add_entry, &b) == 0);
	ATF_REQUIRE(pthread_join(tb, NULL) == 0);
	/* A second add that did not wait left the first one parked. */
	ATF_REQUIRE(gate_hold(0) == 0);
	ATF_REQUIRE(pthread_join(ta, NULL) == 0);

	ATF_CHECK_EQ_MSG(a.error, 0, "first add: %s", strerror(a.error));
	ATF_CHECK_EQ_MSG(b.error, 0, "second add: %s", strerror(b.error));
	ATF_CHECK_EQ_MSG(b.write_live, 1, "the second add returned while "
	    "VNODE_CHECK_WRITE was not live (%d)", b.write_live);
	ATF_CHECK_EQ(a.write_live, 1);
	close(fd);
	(void)unlink(path);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, second_add_waits_for_gate);
	return (atf_no_error());
}
