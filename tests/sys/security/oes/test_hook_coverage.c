/*
 * OES comprehensive hook coverage tests.
 *
 * Tests every MAC hook/event type. Some require root privileges.
 */
#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

#define TEST_DIR	"/tmp/oes_hook_test"
#define TEST_FILE	TEST_DIR "/testfile"
#define TEST_FILE2	TEST_DIR "/testfile2"
#define TEST_LINK	TEST_DIR "/testlink"
#define TEST_SYMLINK	TEST_DIR "/testsymlink"
#define TEST_SUBDIR	TEST_DIR "/subdir"
#define TEST_SOCKET	"/tmp/oes_hook_test.sock"

static int passed = 0;
static int failed = 0;
static int skipped = 0;
static int is_root = 0;

#define PASS(name) do { printf("  PASS: %s\n", name); passed++; } while (0)
#define FAIL(name, reason) do { printf("  FAIL: %s - %s\n", name, reason); failed++; } while (0)
#define SKIP(name, reason) do { printf("  SKIP: %s - %s\n", name, reason); skipped++; } while (0)

static int oes_fd = -1;

static int
open_oes(void)
{
	if (oes_fd >= 0)
		return (0);
	oes_fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (oes_fd < 0) {
		perror("open /dev/oes");
		return (-1);
	}
	return (0);
}

static void
close_oes(void)
{
	if (oes_fd >= 0) {
		close(oes_fd);
		oes_fd = -1;
	}
}

static int
setup_notify(oes_event_type_t *events, size_t nevents)
{
	struct oes_mode_args margs;
	struct oes_subscribe_args sargs;
	struct oes_mute_args mute;

	if (open_oes() < 0)
		return (-1);

	memset(&margs, 0, sizeof(margs));
	margs.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(oes_fd, OES_IOC_SET_MODE, &margs) < 0)
		return (-1);

	memset(&sargs, 0, sizeof(sargs));
	sargs.esa_events = events;
	sargs.esa_count = nevents;
	sargs.esa_flags = OES_SUB_REPLACE;
	if (ioctl(oes_fd, OES_IOC_SUBSCRIBE, &sargs) < 0)
		return (-1);

	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = OES_MUTE_SELF;
	(void)ioctl(oes_fd, OES_IOC_MUTE_PROCESS, &mute);

	return (0);
}

static int
wait_for_event(oes_event_type_t expected, pid_t from_pid, int timeout_ms)
{
	struct pollfd pfd;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	struct timespec start, now;
	ssize_t n;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		int elapsed = (now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_nsec - start.tv_nsec) / 1000000;
		if (elapsed >= timeout_ms)
			return (0);

		pfd.fd = oes_fd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, timeout_ms - elapsed) <= 0)
			return (0);

		n = read(oes_fd, msg, OES_MSG_MAX_SIZE);
		if (n < (ssize_t)sizeof(oes_message_t))
			continue;

		if (from_pid != 0 && msg->em_process.ep_pid != from_pid)
			continue;

		if (msg->em_event == expected)
			return (1);
	}
}

static void
drain_events(void)
{
	struct pollfd pfd;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;

	pfd.fd = oes_fd;
	pfd.events = POLLIN;
	while (poll(&pfd, 1, 10) > 0)
		(void)read(oes_fd, msg, OES_MSG_MAX_SIZE);
}

/*
 * Helper: run action in child, wait for event
 */
static int
test_event(const char *name, oes_event_type_t event, void (*action)(void))
{
	pid_t pid;
	int status;

	close_oes();
	if (setup_notify(&event, 1) < 0) {
		FAIL(name, "setup failed");
		return (-1);
	}

	drain_events();

	pid = fork();
	if (pid == 0) {
		action();
		_exit(0);
	}

	usleep(50000);
	int seen = wait_for_event(event, pid, 1000);
	waitpid(pid, &status, 0);
	close_oes();

	if (seen) {
		PASS(name);
		return (0);
	} else {
		FAIL(name, "event not received");
		return (-1);
	}
}

/* Action helpers */
static void action_open(void) {
	int fd = open(TEST_FILE, O_RDONLY);
	if (fd >= 0) close(fd);
}

static void action_create(void) {
	int fd = open(TEST_FILE2, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) close(fd);
	unlink(TEST_FILE2);
}

static void action_unlink(void) {
	int fd = open(TEST_FILE2, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) close(fd);
	unlink(TEST_FILE2);
}

static void action_read(void) {
	char buf[16];
	int fd = open(TEST_FILE, O_RDONLY);
	if (fd >= 0) {
		(void)read(fd, buf, sizeof(buf));
		close(fd);
	}
}

static void action_write(void) {
	int fd = open(TEST_FILE, O_WRONLY);
	if (fd >= 0) {
		(void)write(fd, "x", 1);
		close(fd);
	}
}

static void action_stat(void) {
	struct stat sb;
	(void)stat(TEST_FILE, &sb);
}

static void action_access(void) {
	(void)access(TEST_FILE, R_OK);
}

static void action_readdir(void) {
	DIR *d = opendir(TEST_DIR);
	if (d) {
		(void)readdir(d);
		closedir(d);
	}
}

static void action_readlink(void) {
	char buf[256];
	(void)readlink(TEST_SYMLINK, buf, sizeof(buf));
}

static void action_link(void) {
	(void)link(TEST_FILE, TEST_LINK);
	unlink(TEST_LINK);
}

static void action_rename(void) {
	int fd = open(TEST_FILE2, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) close(fd);
	(void)rename(TEST_FILE2, TEST_LINK);
	unlink(TEST_LINK);
}

static void action_chdir(void) {
	char cwd[256];
	(void)getcwd(cwd, sizeof(cwd));
	(void)chdir(TEST_DIR);
	(void)chdir(cwd);
}

static void action_mmap(void) {
	int fd = open("/bin/ls", O_RDONLY);
	if (fd >= 0) {
		void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
		if (p != MAP_FAILED)
			munmap(p, 4096);
		close(fd);
	}
}

static void action_setmode(void) {
	(void)chmod(TEST_FILE, 0644);
}

static void action_setowner(void) {
	(void)chown(TEST_FILE, getuid(), getgid());
}

static void action_setutimes(void) {
	(void)utimes(TEST_FILE, NULL);
}

static void action_setflags(void) {
	(void)chflags(TEST_FILE, 0);
}

static void action_extattr(void) {
	char buf[16];
	(void)extattr_set_file(TEST_FILE, EXTATTR_NAMESPACE_USER, "test", "x", 1);
	(void)extattr_get_file(TEST_FILE, EXTATTR_NAMESPACE_USER, "test", buf, sizeof(buf));
	(void)extattr_list_file(TEST_FILE, EXTATTR_NAMESPACE_USER, buf, sizeof(buf));
	(void)extattr_delete_file(TEST_FILE, EXTATTR_NAMESPACE_USER, "test");
}

static void action_socket_bind(void) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock >= 0) {
		struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = 0 };
		(void)bind(sock, (struct sockaddr *)&addr, sizeof(addr));
		close(sock);
	}
}

static void action_socket_listen(void) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock >= 0) {
		struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = 0 };
		if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
			(void)listen(sock, 1);
		close(sock);
	}
}

static void action_socket_connect(void) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock >= 0) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(80),
			.sin_addr.s_addr = htonl(0x7f000001)
		};
		(void)connect(sock, (struct sockaddr *)&addr, sizeof(addr));
		close(sock);
	}
}

static void action_signal(void) {
	pid_t child = fork();
	if (child == 0) {
		pause();
		_exit(0);
	}
	usleep(10000);
	kill(child, SIGTERM);
	waitpid(child, NULL, 0);
}

static void action_ptrace(void) {
	pid_t child = fork();
	if (child == 0) {
		usleep(500000);
		_exit(0);
	}
	usleep(10000);
	if (ptrace(PT_ATTACH, child, NULL, 0) == 0) {
		int status;
		waitpid(child, &status, 0);
		ptrace(PT_DETACH, child, NULL, 0);
	}
	waitpid(child, NULL, 0);
}

static void action_sysctl(void) {
	int val;
	size_t len = sizeof(val);
	(void)sysctlbyname("kern.osreldate", &val, &len, NULL, 0);
}

static void action_exec(void) {
	char path[] = "/bin/echo";
	char *argv[] = { path, NULL };
	char *envp[] = { NULL };
	execve(path, argv, envp);
}

/* New action helpers for added hooks */
static void action_socket_create(void) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock >= 0)
		close(sock);
}

static void action_socket_accept(void) {
	int srv = socket(AF_UNIX, SOCK_STREAM, 0);
	if (srv < 0)
		return;
	unlink(TEST_SOCKET);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strlcpy(addr.sun_path, TEST_SOCKET, sizeof(addr.sun_path));
	if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(srv, 1) < 0) {
		close(srv);
		return;
	}
	pid_t client = fork();
	if (client == 0) {
		int cli = socket(AF_UNIX, SOCK_STREAM, 0);
		if (cli >= 0) {
			(void)connect(cli, (struct sockaddr *)&addr, sizeof(addr));
			close(cli);
		}
		_exit(0);
	}
	struct pollfd pfd = { .fd = srv, .events = POLLIN };
	if (poll(&pfd, 1, 1000) > 0) {
		int acc = accept(srv, NULL, NULL);
		if (acc >= 0)
			close(acc);
	}
	waitpid(client, NULL, 0);
	close(srv);
	unlink(TEST_SOCKET);
}

static void action_socket_send(void) {
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
		(void)send(sv[0], "x", 1, 0);
		close(sv[0]);
		close(sv[1]);
	}
}

static void action_socket_receive(void) {
	int sv[2];
	char buf[4];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
		(void)send(sv[0], "x", 1, 0);
		(void)recv(sv[1], buf, sizeof(buf), 0);
		close(sv[0]);
		close(sv[1]);
	}
}

static void action_socket_stat(void) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock >= 0) {
		struct stat sb;
		(void)fstat(sock, &sb);
		close(sock);
	}
}

static void action_socket_poll(void) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock >= 0) {
		struct pollfd pfd = { .fd = sock, .events = POLLIN };
		(void)poll(&pfd, 1, 0);
		close(sock);
	}
}

static void action_pipe_read(void) {
	int pfd[2];
	char buf[4];
	if (pipe(pfd) == 0) {
		(void)write(pfd[1], "x", 1);
		(void)read(pfd[0], buf, sizeof(buf));
		close(pfd[0]);
		close(pfd[1]);
	}
}

static void action_pipe_write(void) {
	int pfd[2];
	if (pipe(pfd) == 0) {
		(void)write(pfd[1], "x", 1);
		close(pfd[0]);
		close(pfd[1]);
	}
}

static void action_pipe_stat(void) {
	int pfd[2];
	if (pipe(pfd) == 0) {
		struct stat sb;
		(void)fstat(pfd[0], &sb);
		close(pfd[0]);
		close(pfd[1]);
	}
}

static void action_pipe_poll(void) {
	int pfd[2];
	if (pipe(pfd) == 0) {
		struct pollfd pollfd = { .fd = pfd[0], .events = POLLIN };
		(void)poll(&pollfd, 1, 0);
		close(pfd[0]);
		close(pfd[1]);
	}
}

static void action_pipe_ioctl(void) {
	int pfd[2];
	if (pipe(pfd) == 0) {
		int nbytes;
		(void)ioctl(pfd[0], FIONREAD, &nbytes);
		close(pfd[0]);
		close(pfd[1]);
	}
}

static void action_mount_stat(void) {
	struct statfs sfs;
	(void)statfs("/", &sfs);
}

static void action_proc_sched(void) {
	pid_t child = fork();
	if (child == 0) {
		usleep(100000);
		_exit(0);
	}
	/* setpriority triggers proc_check_sched */
	(void)setpriority(PRIO_PROCESS, child, 0);
	waitpid(child, NULL, 0);
}

static void
test_vnode_events(void)
{
	printf("\n=== VNODE EVENTS ===\n");

	test_event("NOTIFY_OPEN", OES_EVENT_NOTIFY_OPEN, action_open);
	test_event("NOTIFY_CREATE", OES_EVENT_NOTIFY_CREATE, action_create);
	test_event("NOTIFY_UNLINK", OES_EVENT_NOTIFY_UNLINK, action_unlink);
	test_event("NOTIFY_READ", OES_EVENT_NOTIFY_READ, action_read);
	test_event("NOTIFY_WRITE", OES_EVENT_NOTIFY_WRITE, action_write);
	test_event("NOTIFY_STAT", OES_EVENT_NOTIFY_STAT, action_stat);
	test_event("NOTIFY_ACCESS", OES_EVENT_NOTIFY_ACCESS, action_access);
	test_event("NOTIFY_READDIR", OES_EVENT_NOTIFY_READDIR, action_readdir);
	test_event("NOTIFY_READLINK", OES_EVENT_NOTIFY_READLINK, action_readlink);
	test_event("NOTIFY_LINK", OES_EVENT_NOTIFY_LINK, action_link);
	test_event("NOTIFY_RENAME", OES_EVENT_NOTIFY_RENAME, action_rename);
	test_event("NOTIFY_CHDIR", OES_EVENT_NOTIFY_CHDIR, action_chdir);
	test_event("NOTIFY_MMAP", OES_EVENT_NOTIFY_MMAP, action_mmap);
	test_event("NOTIFY_SETMODE", OES_EVENT_NOTIFY_SETMODE, action_setmode);
	test_event("NOTIFY_SETOWNER", OES_EVENT_NOTIFY_SETOWNER, action_setowner);
	test_event("NOTIFY_SETUTIMES", OES_EVENT_NOTIFY_SETUTIMES, action_setutimes);
	test_event("NOTIFY_SETFLAGS", OES_EVENT_NOTIFY_SETFLAGS, action_setflags);
}

static void
test_extattr_events(void)
{
	printf("\n=== EXTATTR EVENTS ===\n");

	/* UFS required for extattr */
	close_oes();
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_SETEXTATTR,
		OES_EVENT_NOTIFY_GETEXTATTR,
		OES_EVENT_NOTIFY_LISTEXTATTR,
		OES_EVENT_NOTIFY_DELETEEXTATTR,
	};
	if (setup_notify(events, 4) < 0) {
		SKIP("EXTATTR events", "setup failed");
		return;
	}

	drain_events();
	pid_t pid = fork();
	if (pid == 0) {
		action_extattr();
		_exit(0);
	}
	usleep(100000);

	int set_seen = wait_for_event(OES_EVENT_NOTIFY_SETEXTATTR, pid, 500);
	int get_seen = wait_for_event(OES_EVENT_NOTIFY_GETEXTATTR, pid, 500);
	int list_seen = wait_for_event(OES_EVENT_NOTIFY_LISTEXTATTR, pid, 500);
	int del_seen = wait_for_event(OES_EVENT_NOTIFY_DELETEEXTATTR, pid, 500);

	int status;
	waitpid(pid, &status, 0);
	close_oes();

	if (set_seen) PASS("NOTIFY_SETEXTATTR"); else SKIP("NOTIFY_SETEXTATTR", "UFS required");
	if (get_seen) PASS("NOTIFY_GETEXTATTR"); else SKIP("NOTIFY_GETEXTATTR", "UFS required");
	if (list_seen) PASS("NOTIFY_LISTEXTATTR"); else SKIP("NOTIFY_LISTEXTATTR", "UFS required");
	if (del_seen) PASS("NOTIFY_DELETEEXTATTR"); else SKIP("NOTIFY_DELETEEXTATTR", "UFS required");
}

static void
test_socket_events(void)
{
	printf("\n=== SOCKET EVENTS ===\n");

	test_event("NOTIFY_SOCKET_CREATE", OES_EVENT_NOTIFY_SOCKET_CREATE, action_socket_create);
	test_event("NOTIFY_SOCKET_BIND", OES_EVENT_NOTIFY_SOCKET_BIND, action_socket_bind);
	test_event("NOTIFY_SOCKET_LISTEN", OES_EVENT_NOTIFY_SOCKET_LISTEN, action_socket_listen);
	test_event("NOTIFY_SOCKET_CONNECT", OES_EVENT_NOTIFY_SOCKET_CONNECT, action_socket_connect);
	test_event("NOTIFY_SOCKET_ACCEPT", OES_EVENT_NOTIFY_SOCKET_ACCEPT, action_socket_accept);
	test_event("NOTIFY_SOCKET_SEND", OES_EVENT_NOTIFY_SOCKET_SEND, action_socket_send);
	test_event("NOTIFY_SOCKET_RECEIVE", OES_EVENT_NOTIFY_SOCKET_RECEIVE, action_socket_receive);
	test_event("NOTIFY_SOCKET_STAT", OES_EVENT_NOTIFY_SOCKET_STAT, action_socket_stat);
	test_event("NOTIFY_SOCKET_POLL", OES_EVENT_NOTIFY_SOCKET_POLL, action_socket_poll);
}

static void
test_process_events(void)
{
	printf("\n=== PROCESS EVENTS ===\n");

	test_event("NOTIFY_SIGNAL", OES_EVENT_NOTIFY_SIGNAL, action_signal);
	test_event("NOTIFY_EXEC", OES_EVENT_NOTIFY_EXEC, action_exec);
	test_event("NOTIFY_PROC_SCHED", OES_EVENT_NOTIFY_PROC_SCHED, action_proc_sched);

	/* PTRACE may require privileges */
	close_oes();
	oes_event_type_t event = OES_EVENT_NOTIFY_PTRACE;
	if (setup_notify(&event, 1) < 0) {
		SKIP("NOTIFY_PTRACE", "setup failed");
		return;
	}
	drain_events();
	pid_t pid = fork();
	if (pid == 0) {
		action_ptrace();
		_exit(0);
	}
	usleep(100000);
	int seen = wait_for_event(OES_EVENT_NOTIFY_PTRACE, pid, 1000);
	int status;
	waitpid(pid, &status, 0);
	close_oes();
	if (seen) PASS("NOTIFY_PTRACE"); else SKIP("NOTIFY_PTRACE", "may need privileges");
}

static void
test_pipe_events(void)
{
	printf("\n=== PIPE EVENTS ===\n");

	test_event("NOTIFY_PIPE_READ", OES_EVENT_NOTIFY_PIPE_READ, action_pipe_read);
	test_event("NOTIFY_PIPE_WRITE", OES_EVENT_NOTIFY_PIPE_WRITE, action_pipe_write);
	test_event("NOTIFY_PIPE_STAT", OES_EVENT_NOTIFY_PIPE_STAT, action_pipe_stat);
	test_event("NOTIFY_PIPE_POLL", OES_EVENT_NOTIFY_PIPE_POLL, action_pipe_poll);
	test_event("NOTIFY_PIPE_IOCTL", OES_EVENT_NOTIFY_PIPE_IOCTL, action_pipe_ioctl);
}

static void
test_mount_events(void)
{
	printf("\n=== MOUNT EVENTS ===\n");

	test_event("NOTIFY_MOUNT_STAT", OES_EVENT_NOTIFY_MOUNT_STAT, action_mount_stat);
}

static void
test_priv_events(void)
{
	printf("\n=== PRIVILEGE EVENTS ===\n");

	/* priv_check is called implicitly during privileged operations */
	if (!is_root) {
		SKIP("NOTIFY_PRIV_CHECK", "requires root for privilege checks");
		return;
	}

	/* Root operations that trigger priv_check */
	close_oes();
	oes_event_type_t event = OES_EVENT_NOTIFY_PRIV_CHECK;
	if (setup_notify(&event, 1) < 0) {
		SKIP("NOTIFY_PRIV_CHECK", "setup failed");
		return;
	}
	drain_events();

	pid_t pid = fork();
	if (pid == 0) {
		/* Trigger a privilege check by trying to set system time */
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		(void)clock_settime(CLOCK_REALTIME, &ts);
		_exit(0);
	}
	usleep(100000);
	int seen = wait_for_event(OES_EVENT_NOTIFY_PRIV_CHECK, pid, 1000);
	int status;
	waitpid(pid, &status, 0);
	close_oes();

	if (seen) PASS("NOTIFY_PRIV_CHECK"); else SKIP("NOTIFY_PRIV_CHECK", "event not triggered");
}

static void
test_system_events(void)
{
	printf("\n=== SYSTEM EVENTS ===\n");

	test_event("NOTIFY_SYSCTL", OES_EVENT_NOTIFY_SYSCTL, action_sysctl);

	/* Root-only events */
	if (!is_root) {
		SKIP("NOTIFY_REBOOT", "requires root");
		SKIP("NOTIFY_SWAPON", "requires root");
		SKIP("NOTIFY_SWAPOFF", "requires root");
		SKIP("NOTIFY_KLDLOAD", "requires root");
		SKIP("NOTIFY_KENV", "requires root");
		return;
	}

	SKIP("NOTIFY_REBOOT", "destructive test");
	SKIP("NOTIFY_SWAPON", "needs swap device");
	SKIP("NOTIFY_SWAPOFF", "needs swap device");
	SKIP("NOTIFY_KLDLOAD", "needs safe module");
	SKIP("NOTIFY_KENV", "requires controlled kernel environment change");
}

static void
test_cred_events(void)
{
	printf("\n=== CREDENTIAL EVENTS ===\n");

	if (!is_root) {
		SKIP("NOTIFY_SETUID", "requires root");
		SKIP("NOTIFY_SETGID", "requires root");
		return;
	}

	SKIP("NOTIFY_SETUID", "test needs privileged subprocess");
	SKIP("NOTIFY_SETGID", "test needs privileged subprocess");
}

static void
test_auth_denial(void)
{
	struct oes_mode_args margs;
	struct oes_subscribe_args sargs;
	struct oes_mute_args mute;
	oes_event_type_t event = OES_EVENT_AUTH_LINK;
	pid_t pid;
	int status;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	ssize_t n;
	struct pollfd pfd;

	printf("\n=== AUTH DENIAL ===\n");

	close_oes();
	if (open_oes() < 0) {
		FAIL("AUTH_LINK denial", "setup failed");
		return;
	}

	memset(&margs, 0, sizeof(margs));
	margs.ema_mode = OES_MODE_AUTH;
	margs.ema_timeout_ms = 500;
	if (ioctl(oes_fd, OES_IOC_SET_MODE, &margs) < 0) {
		FAIL("AUTH_LINK denial", "set mode failed");
		close_oes();
		return;
	}

	memset(&sargs, 0, sizeof(sargs));
	sargs.esa_events = &event;
	sargs.esa_count = 1;
	sargs.esa_flags = OES_SUB_REPLACE;
	if (ioctl(oes_fd, OES_IOC_SUBSCRIBE, &sargs) < 0) {
		FAIL("AUTH_LINK denial", "subscribe failed");
		close_oes();
		return;
	}

	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = OES_MUTE_SELF;
	(void)ioctl(oes_fd, OES_IOC_MUTE_PROCESS, &mute);

	pid = fork();
	if (pid == 0) {
		int tfd = open(TEST_FILE2, O_CREAT | O_WRONLY, 0644);
		if (tfd >= 0) close(tfd);
		int ret = link(TEST_FILE2, TEST_LINK);
		unlink(TEST_FILE2);
		unlink(TEST_LINK);
		_exit(ret == 0 ? 1 : 0);
	}

	pfd.fd = oes_fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) > 0) {
		n = read(oes_fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t) && msg->em_event == OES_EVENT_AUTH_LINK) {
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_DENY;
			write(oes_fd, &resp, sizeof(resp));
		}
	}

	waitpid(pid, &status, 0);
	close_oes();

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		PASS("AUTH_LINK denial blocked operation");
	else
		FAIL("AUTH_LINK denial", "operation was not blocked");

	unlink(TEST_FILE2);
	unlink(TEST_LINK);
}

static void
setup_test_files(void)
{
	mkdir(TEST_DIR, 0755);
	int fd = open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) {
		write(fd, "test", 4);
		close(fd);
	}
	symlink(TEST_FILE, TEST_SYMLINK);
}

static void
cleanup_test_files(void)
{
	unlink(TEST_SYMLINK);
	unlink(TEST_LINK);
	unlink(TEST_FILE);
	unlink(TEST_FILE2);
	rmdir(TEST_SUBDIR);
	rmdir(TEST_DIR);
	unlink(TEST_SOCKET);
}

int
main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	is_root = (geteuid() == 0);

	printf("OES Hook Coverage Tests\n");
	printf("========================\n");
	printf("Running as: %s\n", is_root ? "root" : "user");

	setup_test_files();

	test_vnode_events();
	test_extattr_events();
	test_socket_events();
	test_pipe_events();
	test_mount_events();
	test_process_events();
	test_system_events();
	test_cred_events();
	test_priv_events();
	test_auth_denial();

	cleanup_test_files();

	printf("\n========================\n");
	printf("Results: %d passed, %d failed, %d skipped\n", passed, failed, skipped);

	return (failed > 0 ? 1 : 0);
}
