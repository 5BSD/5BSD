/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Verify composable descendants scopes.  A nested client inherits the outer
 * scope marker and adds its own: the outer client sees the two generations
 * below its opener, while the nested client sees only its child.  Neither
 * sees the process that opened it (oes(4), "A client's own processes").
 */
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <liboes.h>

static int
touch_path(const char *path)
{
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	return (fd < 0 ? -1 : close(fd));
}

static int
configure(oes_client_t **clientp)
{
	oes_event_type_t event;
	oes_client_t *client;

	client = oes_client_create_descendants();
	if (client == NULL || oes_set_mode(client, OES_MODE_NOTIFY, 0, 0) < 0)
		return (-1);
	event = OES_EVENT_NOTIFY_OPEN;
	if (oes_subscribe(client, &event, 1, OES_SUB_REPLACE) < 0 ||
	    oes_unmute_all_processes(client) < 0 ||
	    oes_unmute_all_paths(client) < 0 ||
	    oes_unmute_all_target_paths(client) < 0) {
		oes_client_destroy(client);
		return (-1);
	}
	*clientp = client;
	return (0);
}

static void
drain_events(oes_client_t *client)
{
	const oes_message_t *msg;

	while (oes_read_event(client, &msg, false) == 0)
		;
}

/*
 * Read client until every process of want[] has an OPEN event, each with
 * EP_FLAG_OES_CLIENT as flags[] says; fail if a process of forbid[] has
 * one first.  The forbidden opens are made before the wanted ones, so the
 * wanted events fence them.
 */
static int
observe(oes_client_t *client, const pid_t *want, const bool *flags,
    int nwant, const pid_t *forbid, int nforbid)
{
	const oes_message_t *msg;
	struct pollfd pfd;
	bool saw[4] = { false, false, false, false };
	int i, k, nsaw = 0;

	pfd.fd = oes_client_fd(client);
	pfd.events = POLLIN;
	for (i = 0; i < 300 && nsaw < nwant; i++) {
		if (poll(&pfd, 1, 10) <= 0)
			continue;
		while (oes_read_event(client, &msg, false) == 0) {
			bool is_client;

			if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
				continue;
			is_client = (msg->em_process.ep_flags &
			    EP_FLAG_OES_CLIENT) != 0;
			for (k = 0; k < nforbid; k++) {
				if (msg->em_process.ep_pid == forbid[k]) {
					fprintf(stderr, "forbidden pid %d seen\n",
					    (int)forbid[k]);
					return (1);
				}
			}
			for (k = 0; k < nwant; k++) {
				if (msg->em_process.ep_pid != want[k])
					continue;
				if (is_client != flags[k]) {
					fprintf(stderr, "pid %d client flag "
					    "mismatch\n", (int)want[k]);
					return (1);
				}
				if (!saw[k]) {
					saw[k] = true;
					nsaw++;
				}
			}
		}
		if (errno != EAGAIN)
			return (1);
	}
	if (nsaw < nwant)
		fprintf(stderr, "scope result: %d of %d processes seen\n",
		    nsaw, nwant);
	return (nsaw < nwant);
}

static int
nested_process(int ready_fd, int go_fd, int pid_fd, const char *nested_path,
    const char *grand_path)
{
	oes_client_t *client;
	pid_t grandchild;
	char byte;
	int status;

	if (configure(&client) != 0)
		return (10);
	if (write(ready_fd, "R", 1) != 1 || read(go_fd, &byte, 1) != 1)
		return (11);
	if (touch_path(nested_path) != 0)
		return (12);
	grandchild = fork();
	if (grandchild < 0)
		return (13);
	if (grandchild == 0)
		_exit(touch_path(grand_path) == 0 ? 0 : 1);
	if (write(pid_fd, &grandchild, sizeof(grandchild)) !=
	    (ssize_t)sizeof(grandchild))
		return (14);
	if (waitpid(grandchild, &status, 0) != grandchild ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (15);
	{
		/*
		 * Its child, not its parent, and not itself: it opened the
		 * client, and a client never receives the events of the
		 * processes that act as it (oes(4)).
		 */
		pid_t want[] = { grandchild };
		bool flags[] = { false };
		pid_t forbid[] = { getppid(), getpid() };

		status = observe(client, want, flags, 1, forbid, 2);
	}
	oes_client_destroy(client);
	return (status == 0 ? 0 : 16);
}

int
main(void)
{
	oes_client_t *outer;
	char outer_path[] = "/tmp/oes-nested-outer.XXXXXX";
	char nested_path[] = "/tmp/oes-nested-client.XXXXXX";
	char grand_path[] = "/tmp/oes-nested-grand.XXXXXX";
	int ready[2], go[2], grandpid[2], fd, status, result;
	pid_t nested, grandchild;
	char byte;

	fd = mkstemp(outer_path);
	if (fd < 0)
		return (1);
	close(fd);
	fd = mkstemp(nested_path);
	if (fd < 0)
		return (1);
	close(fd);
	fd = mkstemp(grand_path);
	if (fd < 0)
		return (1);
	close(fd);
	if (pipe(ready) != 0 || pipe(go) != 0 || pipe(grandpid) != 0 ||
	    configure(&outer) != 0)
		return (1);

	nested = fork();
	if (nested < 0)
		return (1);
	if (nested == 0) {
		close(ready[0]);
		close(go[1]);
		close(grandpid[0]);
		_exit(nested_process(ready[1], go[0], grandpid[1], nested_path,
		    grand_path));
	}
	close(ready[1]);
	close(go[0]);
	close(grandpid[1]);
	result = 1;
	if (read(ready[0], &byte, 1) != 1)
		goto out;
	/* Discard opens performed while the nested client was being created. */
	drain_events(outer);
	if (touch_path(outer_path) != 0 ||
	    write(go[1], "G", 1) != 1 ||
	    read(grandpid[0], &grandchild, sizeof(grandchild)) !=
	    (ssize_t)sizeof(grandchild))
		goto out;
	if (waitpid(nested, &status, 0) != nested || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		fprintf(stderr, "nested client failed: %d\n",
		    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		goto out;
	}
	/*
	 * The nested client's process (a reader of its own client, so
	 * flagged) and the grandchild; not this process, which opened outer.
	 */
	{
		pid_t want[] = { nested, grandchild };
		bool flags[] = { true, false };
		pid_t forbid[] = { getpid() };

		status = observe(outer, want, flags, 2, forbid, 1);
	}
	if (status != 0) {
		fprintf(stderr, "outer descendants scope missed nested events\n");
		goto out;
	}
	result = 0;
out:
	oes_client_destroy(outer);
	unlink(outer_path);
	unlink(nested_path);
	unlink(grand_path);
	if (result == 0)
		printf("nested descendants clients: ok\n");
	return (result);
}
