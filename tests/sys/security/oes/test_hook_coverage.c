/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * OES comprehensive hook coverage tests.
 *
 * Tests every MAC hook/event type. Some require root privileges.
 */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/extattr.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/linker.h>
#include <sys/mdioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <dev/dq/dq.h>
#include <libdq.h>
#include <security/oes/oes.h>
#include "test_common.h"

#define TEST_DIR	"/tmp/oes_hook_test"
#define TEST_FILE	TEST_DIR "/testfile"
#define TEST_FILE2	TEST_DIR "/testfile2"
#define TEST_LINK	TEST_DIR "/testlink"
#define TEST_SYMLINK	TEST_DIR "/testsymlink"
#define TEST_SUBDIR	TEST_DIR "/subdir"
#define TEST_SOCKET	"/tmp/oes_hook_test.sock"
#define TEST_KLD	TEST_DIR "/notamodule.ko"
#define TEST_KENV	"oes.hook_coverage_test"
#define TEST_UNPRIV_ID	65534		/* nobody */

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
	/* The number may be reused: forget what was batched for the old one. */
	test_forget_event_reader(oes_fd);
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

/*
 * Count of NOSLEEP notifications the kernel discarded because the deferred
 * delivery queue was full.  Read on its own descriptor so it works with
 * oes_fd closed, and reported as 0 when unavailable: a stats read that fails
 * must not turn into a claim that events were dropped.
 */
static uint64_t
nosleep_drops(void)
{
	struct oes_stats stats;
	uint64_t drops = 0;
	int fd;

	fd = open(OES_DEVICE_PATH, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return (0);
	memset(&stats, 0, sizeof(stats));
	if (ioctl(fd, OES_IOC_GET_STATS, &stats) == 0)
		drops = stats.es_nosleep_drops;
	close(fd);
	return (drops);
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

/*
 * Wait for one event of the given type from the given process (0: any).
 *
 * A read of a NOTIFY client returns as many events as fit in the buffer, so
 * every message of every read is examined: the event waited for is usually
 * not the first of its batch when other processes generate the same type.
 * test_wait_event() keeps the unread rest of a batch for the next call.
 */
static int
wait_for_event(oes_event_type_t expected, pid_t from_pid, int timeout_ms)
{
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	struct timespec start, now;
	int elapsed;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed = (now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_nsec - start.tv_nsec) / 1000000;
		if (elapsed >= timeout_ms)
			return (0);

		if (test_wait_event(oes_fd, msg, timeout_ms - elapsed) != 0)
			continue;

		if (from_pid != 0 && msg->em_process.ep_pid != from_pid)
			continue;

		if (msg->em_event == expected)
			return (1);
	}
}

/*
 * Wait until one event of each listed type has arrived from the process, in
 * whatever order they were delivered.  seen[i] is set for events[i].
 */
static void
wait_for_events(const oes_event_type_t *events, int *seen, size_t nevents,
    pid_t from_pid, int timeout_ms)
{
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	struct timespec start, now;
	size_t i, nseen;
	int elapsed;

	memset(seen, 0, nevents * sizeof(*seen));
	nseen = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);

	while (nseen < nevents) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed = (now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_nsec - start.tv_nsec) / 1000000;
		if (elapsed >= timeout_ms)
			return;

		if (test_wait_event(oes_fd, msg, timeout_ms - elapsed) != 0)
			continue;
		if (msg->em_process.ep_pid != from_pid)
			continue;
		for (i = 0; i < nevents; i++) {
			if (msg->em_event == events[i] && !seen[i]) {
				seen[i] = 1;
				nseen++;
			}
		}
	}
}

static void
drain_events(void)
{
	struct pollfd pfd;
	test_msg_buf _msg_buf;

	pfd.fd = oes_fd;
	pfd.events = POLLIN;
	while (poll(&pfd, 1, 10) > 0)
		(void)read(oes_fd, _msg_buf.raw, sizeof(_msg_buf.raw));
	test_forget_event_reader(oes_fd);
}

/*
 * Helper: run action in child, wait for event
 */
static int
test_event(const char *name, oes_event_type_t event, void (*action)(void))
{
	uint64_t drops_before, drops_after;
	pid_t pid;
	int attempt, seen, status;

	/*
	 * Hooks that run with VFS locks held are delivered NOSLEEP: the event
	 * is handed to a deferred task and is dropped outright once that queue
	 * reaches OES_DEFER_MAX, which the kernel counts in es_nosleep_drops.
	 * An absent event with the counter moving is that bounded-queue drop
	 * under load, not a hook that failed to fire, so the action is tried
	 * again; an event absent with no drop counted is a failure.
	 */
	for (attempt = 0; attempt < 3; attempt++) {
		close_oes();
		if (setup_notify(&event, 1) < 0) {
			FAIL(name, "setup failed");
			return (-1);
		}

		drain_events();
		drops_before = nosleep_drops();

		pid = fork();
		if (pid == 0) {
			action();
			_exit(0);
		}

		usleep(50000);
		seen = wait_for_event(event, pid, 1000);
		waitpid(pid, &status, 0);
		drops_after = nosleep_drops();
		close_oes();

		if (seen) {
			PASS(name);
			return (0);
		}
		if (drops_after == drops_before) {
			FAIL(name, "event not received");
			return (-1);
		}
	}
	SKIP(name, "NOSLEEP event dropped in three attempts: the deferred "
	    "queue overflowed (es_nosleep_drops advanced), so delivery was "
	    "best-effort here rather than missing");
	return (0);
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

/*
 * reboot(2) by a process that may not reboot.  The MAC check, where the
 * event is generated, comes before the privilege check; the privilege is
 * then refused twice over, to an unprivileged user and to any process in a
 * jail, so the system keeps running.  The jail is not persistent and goes
 * away with the process.
 */
static void action_reboot(void) {
	struct iovec iov[4];
	char name[32];

	snprintf(name, sizeof(name), "oes_hook_%d", (int)getpid());
	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = name;
	iov[1].iov_len = strlen(name) + 1;
	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, "/");
	iov[3].iov_len = sizeof("/");
	if (jail_set(iov, 4, JAIL_CREATE | JAIL_ATTACH) < 0)
		_exit(1);
	if (setgid(TEST_UNPRIV_ID) != 0 || setuid(TEST_UNPRIV_ID) != 0)
		_exit(1);
	(void)reboot(RB_NOSYNC);
}

/*
 * kldload(2) of a file that is not a module: the linker opens the file,
 * makes the MAC check and only then finds no ELF header in it.
 */
static void action_kldload(void) {
	char junk[512];
	int fd;

	memset(junk, 'k', sizeof(junk));
	(void)unlink(TEST_KLD);
	fd = open(TEST_KLD, O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY, 0644);
	if (fd >= 0) {
		(void)write(fd, junk, sizeof(junk));
		close(fd);
	}
	(void)kldload(TEST_KLD);
	unlink(TEST_KLD);
}

static void action_kenv(void) {
	(void)kenv(KENV_SET, TEST_KENV, __DECONST(char *, "1"), 2);
	(void)kenv(KENV_UNSET, TEST_KENV, NULL, 0);
}

static void action_setuid(void) {
	(void)setuid(TEST_UNPRIV_ID);
}

static void action_setgid(void) {
	(void)setgid(TEST_UNPRIV_ID);
}

/* A small memory disk to turn swapping on and off again. */
static int md_ctl = -1;
static unsigned md_unit;
static char md_path[32];

static int
md_attach(void)
{
	struct md_ioctl mdio;

	md_ctl = open("/dev/" MDCTL_NAME, O_RDWR | O_CLOEXEC);
	if (md_ctl < 0)
		return (-1);
	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_type = MD_MALLOC;
	mdio.md_mediasize = 8 * 1024 * 1024;
	mdio.md_sectorsize = 512;
	mdio.md_options = MD_AUTOUNIT;
	if (ioctl(md_ctl, MDIOCATTACH, &mdio) != 0) {
		int error = errno;

		close(md_ctl);
		md_ctl = -1;
		errno = error;
		return (-1);
	}
	md_unit = mdio.md_unit;
	snprintf(md_path, sizeof(md_path), "/dev/%s%u", MD_NAME, md_unit);
	return (0);
}

static void
md_detach(void)
{
	struct md_ioctl mdio;

	if (md_ctl < 0)
		return;
	(void)swapoff(md_path, 0);
	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_unit = md_unit;
	(void)ioctl(md_ctl, MDIOCDETACH, &mdio);
	close(md_ctl);
	md_ctl = -1;
}

static void action_swap(void) {
	if (swapon(md_path) == 0)
		(void)swapoff(md_path, 0);
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

	close_oes();
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_SETEXTATTR,
		OES_EVENT_NOTIFY_GETEXTATTR,
		OES_EVENT_NOTIFY_LISTEXTATTR,
		OES_EVENT_NOTIFY_DELETEEXTATTR,
	};
	if (setup_notify(events, 4) < 0) {
		FAIL("EXTATTR events", "setup failed");
		return;
	}

	drain_events();
	pid_t pid = fork();
	if (pid == 0) {
		action_extattr();
		_exit(0);
	}
	usleep(100000);

	int seen[4];
	wait_for_events(events, seen, 4, pid, 2000);

	int status;
	waitpid(pid, &status, 0);
	close_oes();

	/*
	 * The MAC checks run before the filesystem is asked, so all four
	 * events are generated on any filesystem, tmpfs included, whether or
	 * not the operation is supported there.
	 */
	static const char *names[4] = {
		"NOTIFY_SETEXTATTR", "NOTIFY_GETEXTATTR",
		"NOTIFY_LISTEXTATTR", "NOTIFY_DELETEEXTATTR",
	};
	for (int i = 0; i < 4; i++) {
		if (seen[i])
			PASS(names[i]);
		else
			FAIL(names[i], "event not received");
	}
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
		FAIL("NOTIFY_PTRACE", "setup failed");
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
	if (seen)
		PASS("NOTIFY_PTRACE");
	else if (is_root)
		FAIL("NOTIFY_PTRACE", "event not received");
	else
		SKIP("NOTIFY_PTRACE", "may need privileges");
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
		FAIL("NOTIFY_PRIV_CHECK", "setup failed");
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

	if (seen)
		PASS("NOTIFY_PRIV_CHECK");
	else
		FAIL("NOTIFY_PRIV_CHECK", "event not received");
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

	/*
	 * Each of these events is generated by the MAC check of the system
	 * call, so none needs the operation itself to succeed, and those that
	 * would change the system are made to fail after the check.
	 */
	test_event("NOTIFY_REBOOT", OES_EVENT_NOTIFY_REBOOT, action_reboot);
	test_event("NOTIFY_KLDLOAD", OES_EVENT_NOTIFY_KLDLOAD, action_kldload);
	test_event("NOTIFY_KENV", OES_EVENT_NOTIFY_KENV, action_kenv);

	/* The swap checks are made on a device that is about to be used. */
	if (md_attach() != 0) {
		char reason[96];

		snprintf(reason, sizeof(reason),
		    "no memory disk to swap on: %s", strerror(errno));
		SKIP("NOTIFY_SWAPON", reason);
		SKIP("NOTIFY_SWAPOFF", reason);
		return;
	}
	test_event("NOTIFY_SWAPON", OES_EVENT_NOTIFY_SWAPON, action_swap);
	if (swapon(md_path) != 0) {
		/* The device was refused after the check: nothing to turn off. */
		char reason[96];

		snprintf(reason, sizeof(reason),
		    "swapon(%s) is refused here: %s", md_path,
		    strerror(errno));
		SKIP("NOTIFY_SWAPOFF", reason);
	} else {
		(void)swapoff(md_path, 0);
		test_event("NOTIFY_SWAPOFF", OES_EVENT_NOTIFY_SWAPOFF,
		    action_swap);
	}
	md_detach();
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

	test_event("NOTIFY_SETUID", OES_EVENT_NOTIFY_SETUID, action_setuid);
	test_event("NOTIFY_SETGID", OES_EVENT_NOTIFY_SETGID, action_setgid);
}

/*
 * Served descriptors (dq(4)): every mpo_file_* hook OES implements.  The
 * child is the controller: it mints one writable object presenting a real
 * backing file and answers every event with libdq's dq_serve_file(), while
 * a grandchild, the requester, runs each operation once; the controller
 * then fstats and closes its own copy.  The queue is O_CLOFORK (dq_open), so
 * the grandchild does not hold it.  Requester and controller are different
 * processes, so events are matched by type alone; nothing but a dq
 * descriptor can produce them.
 */
#define	DQ_BACKING	TEST_DIR "/dqbacking"

struct dq_serve_ctx {
	int			 backing;
	struct dq_serve_opts	 opts;
};

static int
dq_serve_cb(int q, const struct dq_event *ev, const void *body,
    size_t bodylen, void *arg)
{
	struct dq_serve_ctx *ctx = arg;

	(void)dq_serve_file(q, ev, body, bodylen, ctx->backing, &ctx->opts);
	return (0);
}

/* Every operation with a served-descriptor event, once. */
static void
dq_requester_ops(int fd)
{
	struct flock fl;
	struct stat sb;
	char buf[16];
	void *p;
	int n;

	(void)read(fd, buf, sizeof(buf));
	(void)fstat(fd, &sb);
	(void)pwrite(fd, "w", 1, 0);
	(void)fchmod(fd, 0640);
	(void)fsync(fd);
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_len = 1;
	if (fcntl(fd, F_SETLK, &fl) == 0) {
		fl.l_type = F_UNLCK;
		(void)fcntl(fd, F_SETLK, &fl);
	}
	(void)ioctl(fd, FIONREAD, &n);
	p = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
	if (p != MAP_FAILED)
		(void)munmap(p, getpagesize());
}

/*
 * Exit status: 0 ok, 2 open /dev/dq, 3 backing file, 4 mint (errno in the
 * pipe is not worth it: dm_reason is reported as 64 + reason on EINVAL).
 */
static void action_dq_session(void) {
	struct dq_ident_file ident;
	struct dq_policy pol;
	struct dq_serve_ctx ctx;
	struct pollfd pfd;
	struct statfs sfs;
	struct stat st;
	char path[PATH_MAX], fill[8192];
	uint64_t object;
	pid_t reader;
	int fd, q, reason, i;

	q = dq_open();
	if (q < 0)
		_exit(2);
	memset(fill, 'b', sizeof(fill));
	ctx.backing = open(DQ_BACKING, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (ctx.backing < 0 ||
	    write(ctx.backing, fill, sizeof(fill)) != sizeof(fill) ||
	    realpath(DQ_BACKING, path) == NULL ||
	    fstat(ctx.backing, &st) != 0 || fstatfs(ctx.backing, &sfs) != 0 ||
	    dq_ident_from_stat(&ident, path, &st, &sfs, ctx.backing) != 0)
		_exit(3);
	dq_policy_default(&pol);
	pol.dp_write = DQ_EVENT;
	pol.dp_ioctl = DQ_EVENT;
	pol.dp_mmap_shared_write = DQ_ALLOW;
	reason = 0;
	if (dq_mint_file_flags(q, &ident, &pol, DQ_MINT_F_WRITE, &object, &fd,
	    &reason) != 0)
		_exit(errno == EINVAL ? 64 + reason : 4);

	memset(&ctx.opts, 0, sizeof(ctx.opts));
	ctx.opts.so_state = dq_serve_state_create();
	ctx.opts.so_ident = &ident;

	reader = fork();
	if (reader == 0) {
		dq_requester_ops(fd);
		_exit(0);
	}
	/* Serve until the requester is done; bounded so a hang is a FAIL. */
	for (i = 0; reader > 0 && i < 100; i++) {
		if (waitpid(reader, NULL, WNOHANG) == reader)
			break;
		pfd.fd = q;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 50) > 0)
			(void)dq_dispatch(q, dq_serve_cb, &ctx);
	}
	(void)fstat(fd, &st);
	close(fd);
	if (ctx.opts.so_state != NULL)
		dq_serve_state_destroy(ctx.opts.so_state);
	close(q);
	close(ctx.backing);
	unlink(DQ_BACKING);
}

/*
 * Like test_event() but accepts the event from any process: the controller
 * (child) and the requester (grandchild) are both children of this test.
 */
static int
test_dq_event(const char *name, oes_event_type_t event)
{
	pid_t pid;
	int status, seen;

	close_oes();
	if (setup_notify(&event, 1) < 0) {
		FAIL(name, "setup failed");
		return (-1);
	}
	drain_events();

	pid = fork();
	if (pid == 0) {
		action_dq_session();
		_exit(0);
	}

	seen = wait_for_event(event, 0, 3000);
	waitpid(pid, &status, 0);
	close_oes();

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		char reason[64];
		int code = WEXITSTATUS(status);

		if (code >= 64)
			snprintf(reason, sizeof(reason),
			    "DQ_IOC_MINT: EINVAL, dm_reason %d", code - 64);
		else
			snprintf(reason, sizeof(reason), "controller child: %s",
			    code == 2 ? "open /dev/dq failed" :
			    code == 3 ? "backing file setup failed" :
			    "DQ_IOC_MINT failed");
		FAIL(name, reason);
		return (-1);
	}
	if (seen) {
		PASS(name);
		return (0);
	}
	FAIL(name, "event not received");
	return (-1);
}

static void
test_dq_events(void)
{
	static const struct {
		const char *name;
		oes_event_type_t event;
	} events[] = {
		{ "NOTIFY_FILE_STAT", OES_EVENT_NOTIFY_FILE_STAT },
		{ "NOTIFY_FILE_READ", OES_EVENT_NOTIFY_FILE_READ },
		{ "NOTIFY_DQ_REPLY", OES_EVENT_NOTIFY_DQ_REPLY },
		{ "NOTIFY_FILE_CLOSE", OES_EVENT_NOTIFY_FILE_CLOSE },
		{ "NOTIFY_FILE_WRITE", OES_EVENT_NOTIFY_FILE_WRITE },
		{ "NOTIFY_FILE_SETATTR", OES_EVENT_NOTIFY_FILE_SETATTR },
		{ "NOTIFY_FILE_FSYNC", OES_EVENT_NOTIFY_FILE_FSYNC },
		{ "NOTIFY_FILE_LOCK", OES_EVENT_NOTIFY_FILE_LOCK },
		{ "NOTIFY_FILE_IOCTL", OES_EVENT_NOTIFY_FILE_IOCTL },
		{ "NOTIFY_FILE_MMAP", OES_EVENT_NOTIFY_FILE_MMAP },
	};
	size_t i;
	int qfd;

	printf("\n=== SERVED DESCRIPTOR EVENTS (dq) ===\n");

	/* The device admits PRIV_DRIVER only and may be absent from the kernel. */
	qfd = open("/dev/dq", O_RDWR | O_CLOEXEC);
	if (qfd < 0) {
		char reason[64];

		snprintf(reason, sizeof(reason), "open /dev/dq: %s",
		    strerror(errno));
		for (i = 0; i < sizeof(events) / sizeof(events[0]); i++)
			SKIP(events[i].name, reason);
		return;
	}
	close(qfd);

	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++)
		test_dq_event(events[i].name, events[i].event);
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
	/* The first AUTH_LINK read is denied: only this test's child may send it. */
	if (open_oes() < 0 || test_set_descendants_scope(oes_fd) < 0) {
		FAIL("AUTH_LINK denial", "setup failed");
		close_oes();
		return;
	}

	memset(&margs, 0, sizeof(margs));
	margs.ema_mode = OES_MODE_AUTH;
	margs.ema_default_deadline_ms = 500;
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
	unlink(TEST_KLD);
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
	test_dq_events();
	test_auth_denial();

	cleanup_test_files();

	printf("\n========================\n");
	printf("Results: %d passed, %d failed, %d skipped\n", passed, failed, skipped);

	return (failed > 0 ? 1 : 0);
}
