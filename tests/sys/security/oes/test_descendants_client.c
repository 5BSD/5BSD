/*
 * Descendants-scoped client integration test.
 *
 * The monitor is a sibling of the outside actor.  It must receive OPEN
 * notifications from itself and its child, but never from its parent.
 */
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <liboes.h>

static int
touch_path(const char *path)
{
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	return (close(fd));
}

static int
monitor_subtree(int ready_fd, int go_fd, const char *root_path,
	const char *child_path)
{
	oes_client_t *client;
	const oes_message_t *msg;
	oes_event_type_t event;
	struct pollfd pfd;
	pid_t child;
	char byte;
	bool saw_root, saw_child, saw_outside;
	int i, status;

	client = oes_client_create_descendants();
	if (client == NULL)
		return (10);
	if (oes_set_mode(client, OES_MODE_NOTIFY, 0, 0) < 0)
		return (11);
	event = OES_EVENT_NOTIFY_OPEN;
	if (oes_subscribe(client, &event, 1, OES_SUB_REPLACE) < 0)
		return (12);
	if (oes_unmute_all_processes(client) < 0 ||
	    oes_unmute_all_paths(client) < 0)
		return (13);

	if (write(ready_fd, "R", 1) != 1)
		return (14);
	if (read(go_fd, &byte, 1) != 1)
		return (15);

	if (touch_path(root_path) != 0)
		return (16);
	child = fork();
	if (child < 0)
		return (17);
	if (child == 0) {
		/* Preserve the PID but replace the image: scope must survive exec. */
		execl("/bin/sh", "sh", "-c", "exec 3<\"$1\"", "sh",
		    child_path, (char *)NULL);
		_exit(127);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return (18);

	saw_root = saw_child = saw_outside = false;
	pfd.fd = oes_client_fd(client);
	pfd.events = POLLIN;
	for (i = 0; i < 200 && (!saw_root || !saw_child); i++) {
		if (poll(&pfd, 1, 10) <= 0)
			continue;
		while (oes_read_event(client, &msg, false) == 0) {
			const char *path;

			if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
				continue;
			path = oes_msg_string(msg,
			    msg->em_event_data.open.file.ef_path_off);
			fprintf(stderr, "descendants event: pid=%d flags=0x%x path=%s\n",
			    msg->em_process.ep_pid, msg->em_process.ep_flags, path);
			if (msg->em_process.ep_pid == getpid()) {
				if ((msg->em_process.ep_flags &
				    EP_FLAG_OES_CLIENT) == 0)
					return (21);
				saw_root = true;
			} else if (msg->em_process.ep_pid == child) {
				if ((msg->em_process.ep_flags &
				    EP_FLAG_OES_CLIENT) != 0)
					return (22);
				saw_child = true;
			} else if (msg->em_process.ep_pid == getppid())
				saw_outside = true;
		}
		if (errno != EAGAIN)
			return (19);
	}
	oes_client_destroy(client);
	if (!saw_root || !saw_child || saw_outside) {
		fprintf(stderr,
		    "descendants visibility: root=%d child=%d outside=%d\n",
		    saw_root, saw_child, saw_outside);
		return (20);
	}
	return (0);
}

int
main(void)
{
	char root_path[] = "/tmp/oes-desc-root.XXXXXX";
	char child_path[] = "/tmp/oes-desc-child.XXXXXX";
	char outside_path[] = "/tmp/oes-desc-outside.XXXXXX";
	int ready[2], go[2], fd, status;
	pid_t monitor;
	char byte;

	fd = mkstemp(root_path);
	if (fd < 0)
		return (1);
	close(fd);
	fd = mkstemp(child_path);
	if (fd < 0)
		return (1);
	close(fd);
	fd = mkstemp(outside_path);
	if (fd < 0)
		return (1);
	close(fd);
	if (pipe(ready) != 0 || pipe(go) != 0)
		return (1);

	monitor = fork();
	if (monitor < 0)
		return (1);
	if (monitor == 0) {
		close(ready[0]);
		close(go[1]);
		_exit(monitor_subtree(ready[1], go[0], root_path, child_path));
	}
	close(ready[1]);
	close(go[0]);
	if (read(ready[0], &byte, 1) != 1)
		return (1);
	/* The parent is outside the monitor's subtree. */
	if (touch_path(outside_path) != 0 || write(go[1], "G", 1) != 1)
		return (1);
	if (waitpid(monitor, &status, 0) != monitor)
		return (1);

	unlink(root_path);
	unlink(child_path);
	unlink(outside_path);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "descendants client: FAIL (%d)\n",
		    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		return (1);
	}
	printf("descendants client: ok\n");
	return (0);
}
