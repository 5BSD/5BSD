/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

static int
new_envfd(const char *name, uint32_t flags, uint64_t max_size)
{
	struct envfd_create_options options =
	    ENVFD_CREATE_OPTIONS_INITIALIZER(max_size);

	options.eco_flags = flags;
	return (envfd_create(name, &options));
}

static void
send_fd(int sock, int fd)
{
	char control[CMSG_SPACE(sizeof(fd))], byte;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	byte = 0;
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	ATF_REQUIRE_EQ((ssize_t)sizeof(byte), sendmsg(sock, &msg, 0));
}

static int
try_send_fd(int sock, int fd)
{
	char control[CMSG_SPACE(sizeof(fd))], byte;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	byte = 0;
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	if (sendmsg(sock, &msg, 0) == -1)
		return (errno);
	return (0);
}

static int
recv_fd(int sock)
{
	char control[CMSG_SPACE(sizeof(int))], byte;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	int fd;

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	ATF_REQUIRE_EQ((ssize_t)sizeof(byte), recvmsg(sock, &msg, 0));
	ATF_REQUIRE((msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) == 0);
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL);
	ATF_REQUIRE_EQ(SOL_SOCKET, cmsg->cmsg_level);
	ATF_REQUIRE_EQ(SCM_RIGHTS, cmsg->cmsg_type);
	ATF_REQUIRE(cmsg->cmsg_len >= CMSG_LEN(sizeof(fd)));
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return (fd);
}

static int
exec_shell_fd_status(int fd, bool second_exec)
{
	char command[128];
	int status;
	pid_t pid;

	if (second_exec) {
		ATF_REQUIRE(snprintf(command, sizeof(command),
		    "exec /bin/sh -c ': <&%d'", fd) < (int)sizeof(command));
	} else {
		ATF_REQUIRE(snprintf(command, sizeof(command), ": <&%d", fd) <
		    (int)sizeof(command));
	}
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", command, (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

ATF_TC_WITHOUT_HEAD(basic_value_semantics);
ATF_TC_BODY(basic_value_semantics, tc)
{
	static const unsigned char value[] = { 0x00, 0x41, 0xff, 0x00 };
	struct envfd_info info;
	struct stat sb;
	unsigned char buf[sizeof(value) + 1];
	int fd;

	fd = new_envfd("service.token", 0, 32);
	ATF_REQUIRE(fd >= 0);

	/* Generic zero-length reads do not consult the EnvFD object state. */
	ATF_REQUIRE_EQ(0, read(fd, NULL, 0));
	errno = 0;
	ATF_REQUIRE_ERRNO(ENOATTR, read(fd, buf, sizeof(buf)) == -1);
	memset(&info, 0xa5, sizeof(info));
	ATF_REQUIRE_EQ(0, ioctl(fd, ENVFD_GETINFO, &info));
	ATF_CHECK_EQ(sizeof(info), info.ei_size);
	ATF_CHECK_EQ(ENVFD_STATE_UNWRITTEN, info.ei_state);
	ATF_CHECK_EQ(0, info.ei_value_size);
	ATF_CHECK_EQ(0, info.ei_generation);
	ATF_CHECK_STREQ("service.token", info.ei_name);

	ATF_REQUIRE_EQ((ssize_t)sizeof(value),
	    write(fd, value, sizeof(value)));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ((off_t)sizeof(value), sb.st_size);
	errno = 0;
	ATF_REQUIRE_ERRNO(EFAULT,
	    write(fd, (const void *)(uintptr_t)-1, 1) == -1);
	ATF_REQUIRE_EQ(0, ioctl(fd, ENVFD_GETINFO, &info));
	ATF_CHECK_EQ(1, info.ei_generation);
	ATF_CHECK_EQ(sizeof(value), info.ei_value_size);

	memset(buf, 0xa5, sizeof(buf));
	ATF_REQUIRE_EQ((ssize_t)sizeof(value), read(fd, buf, sizeof(buf)));
	ATF_CHECK(memcmp(buf, value, sizeof(value)) == 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(value), read(fd, buf, sizeof(buf)));
	ATF_REQUIRE_EQ(0, read(fd, NULL, 0));

	errno = 0;
	ATF_REQUIRE_ERRNO(EMSGSIZE,
	    read(fd, buf, sizeof(value) - 1) == -1);
	ATF_REQUIRE_EQ((ssize_t)sizeof(value), read(fd, buf, sizeof(buf)));

	/* Empty is a published value and is distinct from unwritten. */
	ATF_REQUIRE_EQ(0, write(fd, NULL, 0));
	ATF_REQUIRE_EQ(0, ioctl(fd, ENVFD_GETINFO, &info));
	ATF_CHECK_EQ(ENVFD_STATE_READY, info.ei_state);
	ATF_CHECK_EQ(0, info.ei_value_size);
	ATF_CHECK_EQ(2, info.ei_generation);
	ATF_REQUIRE_EQ(0, read(fd, NULL, 0));

	ATF_REQUIRE_EQ(0, close(fd));
}

ATF_TC_WITHOUT_HEAD(validation_and_access);
ATF_TC_BODY(validation_and_access, tc)
{
	struct envfd_create_options options =
	    ENVFD_CREATE_OPTIONS_INITIALIZER(8);
	char max_name[ENVFD_NAME_MAX];
	char long_name[ENVFD_NAME_MAX + 1];
	int fd;

	ATF_REQUIRE_ERRNO(EINVAL, envfd_create(NULL, &options) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("null-options", NULL) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("", &options) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("bad=name", &options) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("bad/name", &options) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("bad name", &options) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("bad\nname", &options) == -1);
	memset(long_name, 'x', sizeof(long_name));
	long_name[sizeof(long_name) - 1] = '\0';
	ATF_REQUIRE_ERRNO(ENAMETOOLONG,
	    envfd_create(long_name, &options) == -1);
	memset(max_name, 'x', sizeof(max_name) - 1);
	max_name[sizeof(max_name) - 1] = '\0';
	fd = envfd_create(max_name, &options);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, close(fd));

	options.eco_reserved[1] = 1;
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("reserved", &options) == -1);
	options.eco_reserved[1] = 0;
	options.eco_reserved0 = 1;
	ATF_REQUIRE_ERRNO(EINVAL,
	    envfd_create("reserved0", &options) == -1);
	options.eco_reserved0 = 0;
	options.eco_flags = UINT32_MAX;
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("flags", &options) == -1);
	options.eco_flags = 0;
	options.eco_access = O_ACCMODE;
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("access", &options) == -1);
	options.eco_access = O_RDWR;
	options.eco_size--;
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("size", &options) == -1);
	options.eco_size = sizeof(options);
	options.eco_fdflags = O_CLOEXEC;
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("fdflags", &options) == -1);
	options.eco_fdflags = 0;
	options.eco_xfer_state = CAP_XFER_NONE + 1;
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("xfer-state", &options) == -1);
	options.eco_xfer_state = CAP_XFER_UNLIMITED;
	options.eco_cloexec_state = 3;
	ATF_REQUIRE_ERRNO(EINVAL,
	    envfd_create("exec-state", &options) == -1);
	options.eco_cloexec_state = CAP_CLOEXEC_UNLOCKED;
	options.eco_clofork_state = 3;
	ATF_REQUIRE_ERRNO(EINVAL,
	    envfd_create("fork-state", &options) == -1);
	options.eco_clofork_state = CAP_CLOFORK_UNLOCKED;
	options.eco_max_value_size = UINT64_MAX;
	ATF_REQUIRE_ERRNO(EFBIG,
	    envfd_create("system-maximum", &options) == -1);

	options = (struct envfd_create_options)
	    ENVFD_CREATE_OPTIONS_INITIALIZER(1);
	options.eco_access = O_RDONLY;
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("readonly", &options) == -1);
	options.eco_access = O_WRONLY;
	ATF_REQUIRE_ERRNO(EINVAL, envfd_create("writeonly", &options) == -1);

	fd = new_envfd("bounded", 0, 1);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EFBIG, write(fd, "xx", 2) == -1);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(vectored_io);
ATF_TC_BODY(vectored_io, tc)
{
	static const unsigned char value[] =
	    { 'a', 'b', 'c', 0, 'd', 'e', 'f' };
	struct envfd_info info;
	struct iovec iov[2];
	unsigned char first[2], second[sizeof(value) - sizeof(first)];
	unsigned char whole[sizeof(value)];
	int fd;

	fd = new_envfd("vectored", 0, 16);
	ATF_REQUIRE(fd >= 0);
	iov[0].iov_base = __DECONST(unsigned char *, value);
	iov[0].iov_len = 3;
	iov[1].iov_base = __DECONST(unsigned char *, value + 3);
	iov[1].iov_len = sizeof(value) - 3;
	ATF_REQUIRE_EQ((ssize_t)sizeof(value), writev(fd, iov, 2));

	memset(first, 0xa5, sizeof(first));
	memset(second, 0xa5, sizeof(second));
	iov[0].iov_base = first;
	iov[0].iov_len = sizeof(first);
	iov[1].iov_base = second;
	iov[1].iov_len = sizeof(second);
	ATF_REQUIRE_EQ((ssize_t)sizeof(value), readv(fd, iov, 2));
	memcpy(whole, first, sizeof(first));
	memcpy(whole + sizeof(first), second, sizeof(second));
	ATF_CHECK(memcmp(whole, value, sizeof(value)) == 0);

	/* An undersized vector must not receive a partial snapshot. */
	memset(first, 0xa5, sizeof(first));
	memset(second, 0xa5, sizeof(second));
	iov[1].iov_len--;
	ATF_REQUIRE_ERRNO(EMSGSIZE, readv(fd, iov, 2) == -1);
	ATF_CHECK(first[0] == 0xa5 && first[1] == 0xa5);
	ATF_CHECK(second[0] == 0xa5);

	/* A fault after one valid iovec must not publish a partial value. */
	iov[0].iov_base = __DECONST(char *, "new");
	iov[0].iov_len = 3;
	iov[1].iov_base = (void *)(uintptr_t)-1;
	iov[1].iov_len = 1;
	ATF_REQUIRE_ERRNO(EFAULT, writev(fd, iov, 2) == -1);
	ATF_REQUIRE_EQ(0, ioctl(fd, ENVFD_GETINFO, &info));
	ATF_CHECK_EQ(1, info.ei_generation);
	ATF_CHECK_EQ(sizeof(value), info.ei_value_size);
	ATF_REQUIRE_EQ((ssize_t)sizeof(value),
	    read(fd, whole, sizeof(whole)));
	ATF_CHECK(memcmp(whole, value, sizeof(value)) == 0);
	ATF_REQUIRE_EQ(0, close(fd));
}

struct writer_arg {
	pthread_barrier_t *barrier;
	int fd;
	unsigned char value;
	ssize_t result;
	int error;
};

static void *
writer(void *cookie)
{
	struct writer_arg *arg;
	int error;

	arg = cookie;
	error = pthread_barrier_wait(arg->barrier);
	if (error != 0 && error != PTHREAD_BARRIER_SERIAL_THREAD) {
		arg->result = -1;
		arg->error = error;
		return (NULL);
	}
	arg->result = write(arg->fd, &arg->value, sizeof(arg->value));
	arg->error = arg->result == -1 ? errno : 0;
	return (NULL);
}

#define	SNAPSHOT_SIZE		4096
#define	SNAPSHOT_WRITES		512

struct snapshot_arg {
	pthread_barrier_t	barrier;
	atomic_bool		done;
	atomic_int		failure;
	int			fd;
};

static void *
snapshot_writer(void *cookie)
{
	struct snapshot_arg *arg;
	unsigned char values[2][SNAPSHOT_SIZE];
	ssize_t n;
	int error, i;

	arg = cookie;
	memset(values[0], 0x55, sizeof(values[0]));
	memset(values[1], 0xaa, sizeof(values[1]));
	error = pthread_barrier_wait(&arg->barrier);
	if (error != 0 && error != PTHREAD_BARRIER_SERIAL_THREAD) {
		atomic_store(&arg->failure, error);
		atomic_store(&arg->done, true);
		return (NULL);
	}
	for (i = 0; i < SNAPSHOT_WRITES; i++) {
		n = write(arg->fd, values[i & 1], SNAPSHOT_SIZE);
		if (n != SNAPSHOT_SIZE) {
			atomic_store(&arg->failure, n == -1 ? errno : EIO);
			break;
		}
	}
	atomic_store(&arg->done, true);
	return (NULL);
}

static void *
snapshot_reader(void *cookie)
{
	struct snapshot_arg *arg;
	unsigned char value[SNAPSHOT_SIZE], expected;
	ssize_t n;
	int error, i;

	arg = cookie;
	error = pthread_barrier_wait(&arg->barrier);
	if (error != 0 && error != PTHREAD_BARRIER_SERIAL_THREAD) {
		atomic_store(&arg->failure, error);
		return (NULL);
	}
	do {
		n = read(arg->fd, value, sizeof(value));
		if (n != sizeof(value)) {
			atomic_store(&arg->failure, n == -1 ? errno : EIO);
			break;
		}
		expected = value[0];
		if (expected != 0x55 && expected != 0xaa) {
			atomic_store(&arg->failure, EILSEQ);
			break;
		}
		for (i = 1; i < SNAPSHOT_SIZE; i++) {
			if (value[i] != expected) {
				atomic_store(&arg->failure, EILSEQ);
				return (NULL);
			}
		}
	} while (!atomic_load(&arg->done));
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(concurrent_snapshots);
ATF_TC_BODY(concurrent_snapshots, tc)
{
	struct snapshot_arg arg;
	struct envfd_info info;
	unsigned char initial[SNAPSHOT_SIZE];
	pthread_t reader, writer_thread;

	arg.fd = new_envfd("snapshot-race", 0, SNAPSHOT_SIZE);
	ATF_REQUIRE(arg.fd >= 0);
	memset(initial, 0x55, sizeof(initial));
	ATF_REQUIRE_EQ((ssize_t)sizeof(initial),
	    write(arg.fd, initial, sizeof(initial)));
	atomic_init(&arg.done, false);
	atomic_init(&arg.failure, 0);
	ATF_REQUIRE_EQ(0, pthread_barrier_init(&arg.barrier, NULL, 2));
	ATF_REQUIRE_EQ(0, pthread_create(&reader, NULL, snapshot_reader,
	    &arg));
	ATF_REQUIRE_EQ(0, pthread_create(&writer_thread, NULL,
	    snapshot_writer, &arg));
	ATF_REQUIRE_EQ(0, pthread_join(writer_thread, NULL));
	ATF_REQUIRE_EQ(0, pthread_join(reader, NULL));
	ATF_CHECK_EQ(0, atomic_load(&arg.failure));
	ATF_REQUIRE_EQ(0, ioctl(arg.fd, ENVFD_GETINFO, &info));
	ATF_CHECK_EQ(SNAPSHOT_WRITES + 1, info.ei_generation);
	ATF_REQUIRE_EQ(0, pthread_barrier_destroy(&arg.barrier));
	ATF_REQUIRE_EQ(0, close(arg.fd));
}

ATF_TC_WITHOUT_HEAD(write_once_shared_and_atomic);
ATF_TC_BODY(write_once_shared_and_atomic, tc)
{
	enum { NWRITERS = 8 };
	struct writer_arg args[NWRITERS];
	pthread_barrier_t barrier;
	pthread_t threads[NWRITERS];
	struct envfd_info info;
	unsigned char value;
	int fd, fd2, i, successes;

	fd = new_envfd("write-once-race", ENVFD_WRITE_ONCE, 1);
	ATF_REQUIRE(fd >= 0);
	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);
	ATF_REQUIRE_ERRNO(EFAULT,
	    write(fd, (const void *)(uintptr_t)-1, 1) == -1);
	ATF_REQUIRE_ERRNO(EFBIG, write(fd2, "too large", 9) == -1);
	ATF_REQUIRE_EQ(0, ioctl(fd, ENVFD_GETINFO, &info));
	ATF_CHECK_EQ(ENVFD_STATE_UNWRITTEN, info.ei_state);
	ATF_CHECK_EQ(0, info.ei_generation);
	ATF_REQUIRE_EQ(0, pthread_barrier_init(&barrier, NULL, NWRITERS));
	for (i = 0; i < NWRITERS; i++) {
		args[i].barrier = &barrier;
		args[i].fd = i % 2 == 0 ? fd : fd2;
		args[i].value = (unsigned char)i;
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, writer,
		    &args[i]));
	}
	successes = 0;
	for (i = 0; i < NWRITERS; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		if (args[i].result == 1)
			successes++;
		else {
			ATF_CHECK_EQ(-1, args[i].result);
			ATF_CHECK_EQ(EROFS, args[i].error);
		}
	}
	ATF_CHECK_EQ(1, successes);
	ATF_REQUIRE_EQ(0, pthread_barrier_destroy(&barrier));
	ATF_REQUIRE_EQ(1, read(fd, &value, 1));
	ATF_REQUIRE_EQ(0, ioctl(fd, ENVFD_GETINFO, &info));
	ATF_CHECK_EQ(ENVFD_STATE_SEALED, info.ei_state);
	ATF_CHECK_EQ(1, info.ei_generation);
	ATF_REQUIRE_ERRNO(EROFS, write(fd2, &value, 1) == -1);
	ATF_REQUIRE_ERRNO(EROFS, write(fd2, "too large", 9) == -1);
	close(fd2);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(write_once_pass_and_fork);
ATF_TC_BODY(write_once_pass_and_fork, tc)
{
	int fd, received, status, sv[2];
	pid_t pid;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	fd = new_envfd("write-once-shared", ENVFD_WRITE_ONCE, 8);
	ATF_REQUIRE(fd >= 0);
	send_fd(sv[0], fd);
	received = recv_fd(sv[1]);

	ATF_REQUIRE_EQ(6, write(fd, "parent", 6));
	ATF_REQUIRE_ERRNO(EROFS, write(received, "again", 5) == -1);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(write(received, "child", 5) == -1 && errno == EROFS ?
		    0 : 1);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));

	close(received);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(orphaned_scm_rights_close);
ATF_TC_BODY(orphaned_scm_rights_close, tc)
{
	int fd, sv[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	fd = new_envfd("orphaned-passfd", ENVFD_WRITE_ONCE, 8);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(5, write(fd, "value", 5));
	send_fd(sv[0], fd);
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE_EQ(0, close(sv[0]));
	/* unp_dispose() closes the unread EnvFD through closef_nothread(). */
	ATF_REQUIRE_EQ(0, close(sv[1]));
}

static void
get_event(int kq, struct kevent *event, int expected)
{
	struct timespec timeout;
	int n;

	timeout.tv_sec = expected ? 1 : 0;
	timeout.tv_nsec = 0;
	n = kevent(kq, NULL, 0, event, 1, &timeout);
	ATF_REQUIRE_MSG(n == expected, "kevent returned %d: %s", n,
	    n == -1 ? strerror(errno) : "unexpected event count");
}

ATF_TC_WITHOUT_HEAD(kqueue_notifications);
ATF_TC_BODY(kqueue_notifications, tc)
{
	struct kevent change, event;
	char value[8];
	int fd, kq, kq2;

	fd = new_envfd("events", 0, 8);
	ATF_REQUIRE(fd >= 0);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&change, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_ERRNO(EINVAL,
	    kevent(kq, &change, 1, NULL, 0, NULL) == -1);
	EV_SET(&change, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_ERRNO(EINVAL,
	    kevent(kq, &change, 1, NULL, 0, NULL) == -1);
	EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_ERRNO(EINVAL,
	    kevent(kq, &change, 1, NULL, 0, NULL) == -1);
	EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD, 0x4, 0, NULL);
	ATF_REQUIRE_ERRNO(EINVAL,
	    kevent(kq, &change, 1, NULL, 0, NULL) == -1);
	EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD,
	    NOTE_ENVFD_WRITE | NOTE_ENVFD_SEALED, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &change, 1, NULL, 0, NULL));

	ATF_REQUIRE_ERRNO(EFBIG, write(fd, "too-large", 9) == -1);
	get_event(kq, &event, 0);
	ATF_REQUIRE_EQ(3, write(fd, "one", 3));
	get_event(kq, &event, 1);
	ATF_CHECK_EQ((uintptr_t)fd, event.ident);
	ATF_CHECK_EQ(EVFILT_ENVFD, event.filter);
	ATF_CHECK_EQ(NOTE_ENVFD_WRITE, event.fflags);
	ATF_CHECK_EQ(1, event.data);
	ATF_CHECK_EQ(3, event.ext[0]);
	ATF_REQUIRE_EQ(3, read(fd, value, sizeof(value)));
	get_event(kq, &event, 0);

	/* EV_CLEAR delivery reports the latest generation and size. */
	ATF_REQUIRE_EQ(3, write(fd, "two", 3));
	ATF_REQUIRE_EQ(5, write(fd, "three", 5));
	get_event(kq, &event, 1);
	ATF_CHECK_EQ(NOTE_ENVFD_WRITE, event.fflags);
	ATF_CHECK_EQ(3, event.data);
	ATF_CHECK_EQ(5, event.ext[0]);
	get_event(kq, &event, 0);
	close(kq);

	/* Registration observes future writes, not already-published ones. */
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD, NOTE_ENVFD_WRITE, 0,
	    NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &change, 1, NULL, 0, NULL));
	get_event(kq, &event, 0);
	ATF_REQUIRE_EQ(4, write(fd, "four", 4));
	get_event(kq, &event, 1);
	ATF_CHECK_EQ(NOTE_ENVFD_WRITE, event.fflags);
	ATF_CHECK_EQ(4, event.data);

	EV_SET(&change, fd, EVFILT_ENVFD, EV_DELETE, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &change, 1, NULL, 0, NULL));
	ATF_REQUIRE_EQ(4, write(fd, "five", 4));
	get_event(kq, &event, 0);
	close(kq);
	close(fd);

	fd = new_envfd("seal-event", ENVFD_WRITE_ONCE, 1);
	ATF_REQUIRE(fd >= 0);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	kq2 = kqueue();
	ATF_REQUIRE(kq2 >= 0);
	EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD,
	    NOTE_ENVFD_WRITE | NOTE_ENVFD_SEALED, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &change, 1, NULL, 0, NULL));
	EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD, NOTE_ENVFD_SEALED, 0,
	    NULL);
	ATF_REQUIRE_EQ(0, kevent(kq2, &change, 1, NULL, 0, NULL));
	ATF_REQUIRE_EQ(0, write(fd, NULL, 0));
	get_event(kq, &event, 1);
	ATF_CHECK_EQ(NOTE_ENVFD_WRITE | NOTE_ENVFD_SEALED, event.fflags);
	ATF_CHECK_EQ(1, event.data);
	ATF_CHECK_EQ(0, event.ext[0]);
	get_event(kq2, &event, 1);
	ATF_CHECK_EQ(NOTE_ENVFD_SEALED, event.fflags);
	ATF_CHECK_EQ(1, event.data);
	ATF_REQUIRE_ERRNO(EROFS, write(fd, "x", 1) == -1);
	get_event(kq, &event, 0);
	get_event(kq2, &event, 0);
	close(kq2);
	close(kq);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(capsicum_rights);
ATF_TC_BODY(capsicum_rights, tc)
{
	cap_rights_t rights;
	struct envfd_info info;
	struct kevent change;
	unsigned long cmd;
	char byte;
	int fd, kq;

	fd = new_envfd("rights-read", 0, 1);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, write(fd, "r", 1));
	cap_rights_init(&rights, CAP_READ);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(1, read(fd, &byte, 1));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, write(fd, "w", 1) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    ioctl(fd, ENVFD_GETINFO, &info) == -1);
	close(fd);

	fd = new_envfd("rights-info", 0, 1);
	ATF_REQUIRE(fd >= 0);
	cap_rights_init(&rights, CAP_IOCTL, CAP_EVENT);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	cmd = ENVFD_GETINFO;
	ATF_REQUIRE_EQ(0, cap_ioctls_limit(fd, &cmd, 1));
	ATF_REQUIRE_EQ(0, ioctl(fd, ENVFD_GETINFO, &info));
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD, NOTE_ENVFD_WRITE, 0,
	    NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &change, 1, NULL, 0, NULL));
	close(kq);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(capmode_only);
ATF_TC_BODY(capmode_only, tc)
{
	struct envfd_info info;
	struct kevent change, event;
	struct stat sb;
	struct timespec timeout;
	char value[8];
	int fd, kq, status;
	pid_t pid;

	fd = new_envfd("sandbox-token", ENVFD_CAPMODE_ONLY, 8);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(ECAPMODE, write(fd, "outside", 7) == -1);
	ATF_REQUIRE_ERRNO(ECAPMODE,
	    ioctl(fd, ENVFD_GETINFO, &info) == -1);
	ATF_REQUIRE_ERRNO(ECAPMODE, fstat(fd, &sb) == -1);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD, NOTE_ENVFD_WRITE, 0,
	    NULL);
	ATF_REQUIRE_ERRNO(ECAPMODE,
	    kevent(kq, &change, 1, NULL, 0, NULL) == -1);
	close(kq);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (cap_enter() == -1)
			_exit(1);
		kq = kqueue();
		if (kq == -1)
			_exit(2);
		EV_SET(&change, fd, EVFILT_ENVFD, EV_ADD, NOTE_ENVFD_WRITE, 0,
		    NULL);
		if (kevent(kq, &change, 1, NULL, 0, NULL) == -1)
			_exit(3);
		if (write(fd, "inside", 6) != 6)
			_exit(4);
		timeout.tv_sec = 1;
		timeout.tv_nsec = 0;
		if (kevent(kq, NULL, 0, &event, 1, &timeout) != 1 ||
		    event.data != 1)
			_exit(5);
		if (ioctl(fd, ENVFD_GETINFO, &info) == -1 ||
		    info.ei_generation != 1)
			_exit(6);
		if (fstat(fd, &sb) == -1 || sb.st_size != 6)
			_exit(7);
		if (read(fd, value, sizeof(value)) != 6 ||
		    memcmp(value, "inside", 6) != 0)
			_exit(8);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_REQUIRE_ERRNO(ECAPMODE, read(fd, &status, sizeof(status)) == -1);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(create_in_capmode);
ATF_TC_BODY(create_in_capmode, tc)
{
	struct envfd_info info;
	char value[8];
	int fd, status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (cap_enter() == -1)
			_exit(1);
		fd = new_envfd("created-in-capmode", ENVFD_CAPMODE_ONLY,
		    sizeof(value));
		if (fd == -1)
			_exit(2);
		if (write(fd, "inside", 6) != 6)
			_exit(3);
		if (read(fd, value, sizeof(value)) != 6 ||
		    memcmp(value, "inside", 6) != 0)
			_exit(4);
		if (ioctl(fd, ENVFD_GETINFO, &info) == -1 ||
		    info.ei_generation != 1 ||
		    info.ei_state != ENVFD_STATE_READY ||
		    strcmp(info.ei_name, "created-in-capmode") != 0)
			_exit(5);
		if (close(fd) == -1)
			_exit(6);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

ATF_TC_WITHOUT_HEAD(initial_descriptor_confinement);
ATF_TC_BODY(initial_descriptor_confinement, tc)
{
	struct envfd_create_options options =
	    ENVFD_CREATE_OPTIONS_INITIALIZER(1);
	int fd, received, status, sv[2];
	pid_t grandchild, pid;

	options.eco_fdflags = FD_CLOEXEC | FD_CLOFORK;
	options.eco_xfer_state = CAP_XFER_NONE;
	options.eco_cloexec_state = CAP_CLOEXEC_ONCE;
	options.eco_clofork_state = CAP_CLOFORK_LOCKED;
	fd = envfd_create("confined", &options);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(FD_CLOEXEC | FD_CLOFORK,
	    fcntl(fd, F_GETFD) & (FD_CLOEXEC | FD_CLOFORK));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(fd, CAP_XFER_UNLIMITED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(fd, CAP_CLOEXEC_UNLOCKED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	ATF_CHECK_EQ(ENOTCAPABLE, try_send_fd(sv[0], fd));
	close(sv[0]);
	close(sv[1]);

	/* The initial locked fork state performs the operation it promises. */
	ATF_REQUIRE_EQ(0, fcntl(fd, F_SETFD, 0));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 1);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	close(fd);

	/* A one-shot transfer succeeds exactly once. */
	options = (struct envfd_create_options)
	    ENVFD_CREATE_OPTIONS_INITIALIZER(1);
	options.eco_xfer_state = CAP_XFER_ONCE;
	fd = envfd_create("xfer-once", &options);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	send_fd(sv[0], fd);
	received = recv_fd(sv[1]);
	ATF_CHECK_EQ(ENOTCAPABLE, try_send_fd(sv[0], fd));
	ATF_CHECK_EQ(ENOTCAPABLE, try_send_fd(sv[1], received));
	close(received);
	close(sv[0]);
	close(sv[1]);
	close(fd);

	/*
	 * A one-shot fork permits the first child, then locks both the
	 * parent's entry and the inherited child's entry against later forks.
	 */
	options = (struct envfd_create_options)
	    ENVFD_CREATE_OPTIONS_INITIALIZER(1);
	options.eco_clofork_state = CAP_CLOFORK_ONCE;
	fd = envfd_create("fork-once", &options);
	ATF_REQUIRE(fd >= 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (fcntl(fd, F_GETFD) == -1)
			_exit(1);
		grandchild = fork();
		if (grandchild == -1)
			_exit(2);
		if (grandchild == 0)
			_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ?
			    0 : 3);
		if (waitpid(grandchild, &status, 0) != grandchild ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			_exit(4);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 1);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	close(fd);

	/*
	 * A one-shot exec survives the first image replacement and is forced
	 * closed by the second.  A locked descriptor closes on the first.
	 */
	options = (struct envfd_create_options)
	    ENVFD_CREATE_OPTIONS_INITIALIZER(1);
	options.eco_cloexec_state = CAP_CLOEXEC_ONCE;
	fd = envfd_create("exec-once", &options);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(0, exec_shell_fd_status(fd, false));
	ATF_CHECK(exec_shell_fd_status(fd, true) != 0);
	close(fd);

	options.eco_cloexec_state = CAP_CLOEXEC_LOCKED;
	fd = envfd_create("exec-locked", &options);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(exec_shell_fd_status(fd, false) != 0);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(unsupported_operations);
ATF_TC_BODY(unsupported_operations, tc)
{
	struct aiocb cb;
	struct pollfd pfd;
	char byte;
	int fd;

	fd = new_envfd("not-a-file", ENVFD_WRITE_ONCE, 8);
	ATF_REQUIRE(fd >= 0);
	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 0));
	ATF_CHECK_EQ(POLLIN | POLLOUT,
	    pfd.revents & (POLLIN | POLLOUT));
	ATF_REQUIRE_ERRNO(ESPIPE, lseek(fd, 0, SEEK_SET) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, ftruncate(fd, 0) == -1);
	ATF_REQUIRE_ERRNO(ENODEV,
	    mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	cb.aio_buf = &byte;
	cb.aio_nbytes = sizeof(byte);
	ATF_REQUIRE_ERRNO(EOPNOTSUPP, aio_write(&cb) == -1);
	ATF_REQUIRE_ERRNO(EOPNOTSUPP, aio_read(&cb) == -1);
	byte = 1;
	ATF_REQUIRE_EQ(1, write(fd, &byte, 1));
	pfd.revents = 0;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 0));
	ATF_CHECK_EQ(POLLIN | POLLOUT,
	    pfd.revents & (POLLIN | POLLOUT));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(kinfo_metadata);
ATF_TC_BODY(kinfo_metadata, tc)
{
	struct kinfo_file *files, *kif;
	size_t length, offset;
	int fd, found, mib[4];

	fd = new_envfd("inspectable", ENVFD_WRITE_ONCE, 32);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(5, write(fd, "value", 5));
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_FILEDESC;
	mib[3] = getpid();
	length = 0;
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), NULL, &length, NULL, 0));
	files = malloc(length);
	ATF_REQUIRE(files != NULL);
	ATF_REQUIRE_EQ(0,
	    sysctl(mib, nitems(mib), files, &length, NULL, 0));

	found = 0;
	for (offset = 0; offset < length; offset += kif->kf_structsize) {
		kif = (struct kinfo_file *)((char *)files + offset);
		ATF_REQUIRE(kif->kf_structsize != 0);
		ATF_REQUIRE(offset + kif->kf_structsize <= length);
		if (kif->kf_fd != fd)
			continue;
		found = 1;
		ATF_CHECK_EQ(KF_TYPE_ENVFD, kif->kf_type);
		ATF_CHECK((kif->kf_status & KF_ATTR_VALID) != 0);
		ATF_CHECK_STREQ("envfd:inspectable", kif->kf_path);
		ATF_CHECK_EQ(5, kif->kf_un.kf_envfd.kf_envfd_value_size);
		ATF_CHECK_EQ(32, kif->kf_un.kf_envfd.kf_envfd_max_size);
		ATF_CHECK_EQ(1, kif->kf_un.kf_envfd.kf_envfd_generation);
		ATF_CHECK_EQ(ENVFD_WRITE_ONCE,
		    kif->kf_un.kf_envfd.kf_envfd_flags);
		ATF_CHECK_EQ(ENVFD_STATE_SEALED,
		    kif->kf_un.kf_envfd.kf_envfd_state);
		ATF_CHECK_EQ(0, kif->kf_un.kf_envfd.kf_envfd_addr);
	}
	ATF_CHECK_EQ(1, found);
	free(files);
	ATF_REQUIRE_EQ(0, close(fd));
}

static u_long
envfd_counter(const char *name)
{
	u_long value;
	size_t size;

	size = sizeof(value);
	ATF_REQUIRE_EQ(0, sysctlbyname(name, &value, &size, NULL, 0));
	ATF_REQUIRE_EQ(sizeof(value), size);
	return (value);
}

struct envfd_saved_limits {
	u_long	max_objects;
	u_long	max_bytes;
};

static void
envfd_set_limit(const char *name, u_long value)
{

	ATF_REQUIRE_EQ(0,
	    sysctlbyname(name, NULL, NULL, &value, sizeof(value)));
}

ATF_TC_WITH_CLEANUP(accounting_limits);
ATF_TC_HEAD(accounting_limits, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.config", "allow_sysctl_side_effects");
}

ATF_TC_BODY(accounting_limits, tc)
{
	static const char state_file[] = "envfd-limits.save";
	struct envfd_saved_limits saved;
	FILE *fp;
	u_long bytes0, objects0;
	int fd;

	objects0 = envfd_counter("kern.envfd.objects");
	bytes0 = envfd_counter("kern.envfd.bytes");
	ATF_REQUIRE(objects0 < ULONG_MAX);
	ATF_REQUIRE(bytes0 < ULONG_MAX);
	saved.max_objects = envfd_counter("kern.envfd.max_objects");
	saved.max_bytes = envfd_counter("kern.envfd.max_bytes");
	fp = fopen(state_file, "wb");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE_EQ(1, fwrite(&saved, sizeof(saved), 1, fp));
	ATF_REQUIRE_EQ(0, fclose(fp));

	envfd_set_limit("kern.envfd.max_objects", objects0 + 1);
	fd = new_envfd("object-limit-first", 0, 1);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(ENFILE,
	    new_envfd("object-limit-second", 0, 1) == -1);
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_CHECK_EQ(objects0, envfd_counter("kern.envfd.objects"));
	ATF_CHECK_EQ(bytes0, envfd_counter("kern.envfd.bytes"));

	envfd_set_limit("kern.envfd.max_bytes", bytes0 + 1);
	ATF_REQUIRE_ERRNO(ENOMEM,
	    new_envfd("byte-limit", 0, 1) == -1);
	ATF_CHECK_EQ(objects0, envfd_counter("kern.envfd.objects"));
	ATF_CHECK_EQ(bytes0, envfd_counter("kern.envfd.bytes"));
}

ATF_TC_CLEANUP(accounting_limits, tc)
{
	static const char state_file[] = "envfd-limits.save";
	struct envfd_saved_limits saved;
	FILE *fp;

	fp = fopen(state_file, "rb");
	if (fp == NULL)
		return;
	ATF_REQUIRE_EQ(1, fread(&saved, sizeof(saved), 1, fp));
	ATF_REQUIRE_EQ(0, fclose(fp));
	envfd_set_limit("kern.envfd.max_bytes", saved.max_bytes);
	envfd_set_limit("kern.envfd.max_objects", saved.max_objects);
}

ATF_TC_WITHOUT_HEAD(accounting_lifecycle);
ATF_TC_BODY(accounting_lifecycle, tc)
{
	u_long bytes0, bytes1, bytes2, objects0;
	int fd, fd2;

	objects0 = envfd_counter("kern.envfd.objects");
	bytes0 = envfd_counter("kern.envfd.bytes");
	fd = new_envfd("accounted", 0, 16);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(objects0 + 1,
	    envfd_counter("kern.envfd.objects"));
	bytes1 = envfd_counter("kern.envfd.bytes");
	ATF_CHECK(bytes1 > bytes0);

	ATF_REQUIRE_EQ(5, write(fd, "first", 5));
	bytes2 = envfd_counter("kern.envfd.bytes");
	ATF_CHECK(bytes2 > bytes1);
	ATF_REQUIRE_EQ(5, write(fd, "again", 5));
	ATF_CHECK_EQ(bytes2, envfd_counter("kern.envfd.bytes"));

	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_CHECK_EQ(objects0 + 1,
	    envfd_counter("kern.envfd.objects"));
	ATF_CHECK_EQ(bytes2, envfd_counter("kern.envfd.bytes"));
	ATF_REQUIRE_EQ(0, close(fd2));
	ATF_CHECK_EQ(objects0, envfd_counter("kern.envfd.objects"));
	ATF_CHECK_EQ(bytes0, envfd_counter("kern.envfd.bytes"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, basic_value_semantics);
	ATF_TP_ADD_TC(tp, validation_and_access);
	ATF_TP_ADD_TC(tp, vectored_io);
	ATF_TP_ADD_TC(tp, concurrent_snapshots);
	ATF_TP_ADD_TC(tp, write_once_shared_and_atomic);
	ATF_TP_ADD_TC(tp, write_once_pass_and_fork);
	ATF_TP_ADD_TC(tp, orphaned_scm_rights_close);
	ATF_TP_ADD_TC(tp, kqueue_notifications);
	ATF_TP_ADD_TC(tp, capsicum_rights);
	ATF_TP_ADD_TC(tp, capmode_only);
	ATF_TP_ADD_TC(tp, create_in_capmode);
	ATF_TP_ADD_TC(tp, initial_descriptor_confinement);
	ATF_TP_ADD_TC(tp, unsupported_operations);
	ATF_TP_ADD_TC(tp, kinfo_metadata);
	ATF_TP_ADD_TC(tp, accounting_limits);
	ATF_TP_ADD_TC(tp, accounting_lifecycle);
	return (atf_no_error());
}
