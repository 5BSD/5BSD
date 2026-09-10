/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Process-descriptor guardian for capability daemon integration tests.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	CONTROL_BACKLOG	4
#define	COMMAND_SIZE	64

static const char *socket_path;

static void
cleanup_socket(void)
{

	if (socket_path != NULL)
		(void)unlink(socket_path);
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: capd_test_guardian run -l lease -s socket -- command ...\n"
	    "       capd_test_guardian ctl -s socket status|kill\n");
	exit(64);
}

static int
make_listener(const char *path)
{
	struct sockaddr_un sun;
	int fd;

	if (strlen(path) >= sizeof(sun.sun_path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		return (-1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	(void)unlink(path);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1 ||
	    chmod(path, 0600) == -1 || listen(fd, CONTROL_BACKLOG) == -1) {
		int saved_errno;

		saved_errno = errno;
		close(fd);
		(void)unlink(path);
		errno = saved_errno;
		return (-1);
	}
	return (fd);
}

static bool
handle_control(int listen_fd, int pd, pid_t child)
{
	struct timeval timeout;
	char command[COMMAND_SIZE];
	ssize_t n;
	int client;

	client = accept(listen_fd, NULL, NULL);
	if (client == -1)
		return (false);
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	(void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
	    sizeof(timeout));
	n = read(client, command, sizeof(command) - 1);
	if (n <= 0) {
		close(client);
		return (false);
	}
	command[n] = '\0';
	if (strcmp(command, "status\n") == 0) {
		char reply[COMMAND_SIZE];

		(void)snprintf(reply, sizeof(reply), "running pid=%jd\n",
		    (intmax_t)child);
		(void)write(client, reply, strlen(reply));
		close(client);
		return (false);
	}
	if (strcmp(command, "kill\n") == 0) {
		(void)write(client, "terminating\n", 12);
		close(client);
		if (pdkill(pd, SIGKILL) == -1 && errno != ESRCH)
			warn("pdkill");
		return (true);
	}
	(void)write(client, "error unknown-command\n", 22);
	close(client);
	return (false);
}

static int
run_guardian(const char *lease_path, const char *control_path, char **argv)
{
	struct kevent changes[6], events[6];
	int kq, lease_fd, listen_fd, n, pd, status;
	pid_t child;
	bool terminating;

	socket_path = control_path;
	if (atexit(cleanup_socket) != 0)
		err(1, "atexit");
	listen_fd = make_listener(control_path);
	if (listen_fd == -1)
		err(1, "control socket %s", control_path);
	lease_fd = open(lease_path, O_RDONLY);
	if (lease_fd == -1)
		err(1, "lease %s", lease_path);
	kq = kqueue();
	if (kq == -1)
		err(1, "kqueue");

	child = pdfork(&pd, PD_CLOEXEC);
	if (child == -1)
		err(1, "pdfork");
	if (child == 0) {
		close(lease_fd);
		close(listen_fd);
		execvp(argv[0], argv);
		err(127, "exec %s", argv[0]);
	}
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	n = 0;
	EV_SET(&changes[n++], lease_fd, EVFILT_READ, EV_ADD | EV_CLEAR,
	    0, 0, NULL);
	EV_SET(&changes[n++], listen_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&changes[n++], pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
	EV_SET(&changes[n++], SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&changes[n++], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&changes[n++], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	if (kevent(kq, changes, n, NULL, 0, NULL) == -1) {
		int saved_errno;

		saved_errno = errno;
		(void)pdkill(pd, SIGKILL);
		(void)waitpid(child, NULL, 0);
		close(pd);
		close(kq);
		close(lease_fd);
		close(listen_fd);
		errno = saved_errno;
		err(1, "kevent register");
	}

	terminating = false;
	for (;;) {
		n = kevent(kq, NULL, 0, events, nitems(events), NULL);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent wait");
		}
		for (int i = 0; i < n; i++) {
			if (events[i].filter == EVFILT_PROCDESC &&
			    (events[i].fflags & NOTE_EXIT) != 0)
				goto exited;
			if (events[i].filter == EVFILT_READ &&
			    (int)events[i].ident == listen_fd) {
				if (handle_control(listen_fd, pd, child))
					terminating = true;
				continue;
			}
			if ((events[i].filter == EVFILT_READ &&
			    (int)events[i].ident == lease_fd &&
			    (events[i].flags & EV_EOF) != 0) ||
			    events[i].filter == EVFILT_SIGNAL) {
				if (!terminating && pdkill(pd, SIGKILL) == -1 &&
				    errno != ESRCH)
					warn("pdkill after lease/signal loss");
				terminating = true;
			}
		}
	}

exited:
	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid");
	close(pd);
	close(kq);
	close(lease_fd);
	close(listen_fd);
	if (WIFEXITED(status))
		return (WEXITSTATUS(status));
	if (WIFSIGNALED(status))
		return (128 + WTERMSIG(status));
	return (1);
}

static int
control_guardian(const char *path, const char *command)
{
	struct sockaddr_un sun;
	char request[COMMAND_SIZE], reply[COMMAND_SIZE];
	ssize_t n;
	int fd;

	if (strlen(path) >= sizeof(sun.sun_path))
		errx(64, "control socket path is too long");
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		err(1, "socket");
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect %s", path);
	(void)snprintf(request, sizeof(request), "%s\n", command);
	if (write(fd, request, strlen(request)) != (ssize_t)strlen(request))
		err(1, "write command");
	n = read(fd, reply, sizeof(reply) - 1);
	if (n == -1)
		err(1, "read reply");
	reply[n] = '\0';
	fputs(reply, stdout);
	close(fd);
	return (strncmp(reply, "error ", 6) == 0 ? 1 : 0);
}

int
main(int argc, char **argv)
{
	const char *lease, *path;
	int ch;

	if (argc < 2)
		usage();
	lease = NULL;
	path = NULL;
	if (strcmp(argv[1], "run") == 0) {
		optind = 2;
		while ((ch = getopt(argc, argv, "l:s:")) != -1) {
			switch (ch) {
			case 'l': lease = optarg; break;
			case 's': path = optarg; break;
			default: usage();
			}
		}
		if (lease == NULL || path == NULL || optind >= argc)
			usage();
		return (run_guardian(lease, path, &argv[optind]));
	}
	if (strcmp(argv[1], "ctl") == 0) {
		optind = 2;
		while ((ch = getopt(argc, argv, "s:")) != -1) {
			if (ch == 's')
				path = optarg;
			else
				usage();
		}
		if (path == NULL || optind + 1 != argc ||
		    (strcmp(argv[optind], "status") != 0 &&
		    strcmp(argv[optind], "kill") != 0))
			usage();
		return (control_guardian(path, argv[optind]));
	}
	usage();
}
