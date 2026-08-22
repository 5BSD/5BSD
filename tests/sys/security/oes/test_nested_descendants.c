/*
 * Verify composable descendants scopes.  A nested client inherits the outer
 * scope marker and adds its own: the outer client sees all three generations,
 * while the nested client sees only itself and its child.
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

static int
observe(oes_client_t *client, pid_t first, pid_t second, pid_t third,
    pid_t forbidden, bool require_first_client, bool require_second_client,
    bool require_third_client)
{
	const oes_message_t *msg;
	struct pollfd pfd;
	bool saw_first, saw_second, saw_third, saw_forbidden;
	int i;

	saw_first = saw_second = saw_forbidden = false;
	saw_third = third <= 0;
	pfd.fd = oes_client_fd(client);
	pfd.events = POLLIN;
	for (i = 0; i < 300 && (!saw_first || !saw_second || !saw_third); i++) {
		if (poll(&pfd, 1, 10) <= 0)
			continue;
		while (oes_read_event(client, &msg, false) == 0) {
			bool is_client;

			if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
				continue;
			is_client = (msg->em_process.ep_flags &
			    EP_FLAG_OES_CLIENT) != 0;
			if (msg->em_process.ep_pid == first) {
				if (is_client != require_first_client) {
					fprintf(stderr, "first client flag mismatch\n");
					return (1);
				}
				saw_first = true;
			} else if (msg->em_process.ep_pid == second) {
				if (is_client != require_second_client) {
					fprintf(stderr, "second client flag mismatch\n");
					return (1);
				}
				saw_second = true;
			} else if (msg->em_process.ep_pid == third) {
				if (is_client != require_third_client) {
					fprintf(stderr, "third client flag mismatch\n");
					return (1);
				}
				saw_third = true;
			} else if (msg->em_process.ep_pid == forbidden) {
				saw_forbidden = true;
			}
		}
		if (errno != EAGAIN)
			return (1);
	}
	if (!saw_first || !saw_second || !saw_third || saw_forbidden)
		fprintf(stderr, "scope result first=%d second=%d third=%d forbidden=%d\n",
		    saw_first, saw_second, saw_third, saw_forbidden);
	return (!saw_first || !saw_second || !saw_third || saw_forbidden);
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
	status = observe(client, getpid(), grandchild, 0, getppid(), true,
	    false, false);
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
	if (observe(outer, getpid(), nested, grandchild, -1, true, true,
	    false) != 0) {
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
