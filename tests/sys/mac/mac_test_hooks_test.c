/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/extattr.h>
#include <sys/linker.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>

#include <sys/acl.h>
#include <sys/resource.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <paths.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *deny_hooks[] = {
	"proc_check_fork",
	"proc_check_mmap_anon",
	"proc_check_mprotect",
	"file_check_dup",
	"file_check_receive",
	"file_check_ioctl",
	"file_check_mmap",
	"vnode_check_truncate",
	"vnode_check_uipc_bind",
	"vnode_check_uipc_connect",
	"socket_check_setsockopt",
	"kld_check_unload",
	"pts_check_open",
	"mount_check_mount",
	"mount_check_remount",
	"mount_check_umount",
	"system_check_kas_info",
};

static void
sysctl_name(char *buf, size_t buflen, const char *kind, const char *hook)
{

	snprintf(buf, buflen, "security.mac.test_hooks.%s.%s", kind, hook);
}

static int
read_hook_value(const char *kind, const char *hook)
{
	char name[128];
	int value;
	size_t len;

	sysctl_name(name, sizeof(name), kind, hook);
	len = sizeof(value);
	ATF_REQUIRE_MSG(sysctlbyname(name, &value, &len, NULL, 0) == 0,
	    "sysctlbyname(%s) failed: %s", name, strerror(errno));
	return (value);
}

static void
write_deny_value(const char *hook, int value)
{
	char name[128];

	sysctl_name(name, sizeof(name), "deny", hook);
	ATF_REQUIRE_MSG(sysctlbyname(name, NULL, NULL, &value, sizeof(value)) == 0,
	    "sysctlbyname(%s) failed: %s", name, strerror(errno));
}

static void
reset_denies(void)
{
	size_t i;

	for (i = 0; i < nitems(deny_hooks); i++) {
		int value = 0;
		char name[128];

		sysctl_name(name, sizeof(name), "deny", deny_hooks[i]);
		(void)sysctlbyname(name, NULL, NULL, &value, sizeof(value));
	}
}

static int
counter(const char *hook)
{

	return (read_hook_value("counter", hook));
}

static void
require_counter_bump(const char *hook, int before)
{
	int after;

	after = counter(hook);
	ATF_REQUIRE_MSG(after > before, "%s counter did not increase: %d -> %d",
	    hook, before, after);
}

static char *
make_tempdir(void)
{
	char *dir;

	dir = strdup("/tmp/mac_test_hooks.XXXXXX");
	ATF_REQUIRE(dir != NULL);
	ATF_REQUIRE_MSG(mkdtemp(dir) != NULL, "mkdtemp failed: %s",
	    strerror(errno));
	return (dir);
}

static void
path_join(char *buf, size_t buflen, const char *dir, const char *leaf)
{

	snprintf(buf, buflen, "%s/%s", dir, leaf);
}

static void
create_file_with_data(const char *path)
{
	int fd;

	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, "data", 4) == 4);
	ATF_REQUIRE(close(fd) == 0);
}

static void
send_fd(int sock, int fd)
{
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char ch;

	memset(&msg, 0, sizeof(msg));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	ch = 'x';
	iov.iov_base = &ch;
	iov.iov_len = sizeof(ch);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	ATF_REQUIRE(sendmsg(sock, &msg, 0) == 1);
}

static int
recv_fd(int sock)
{
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char ch;
	int fd;

	memset(&msg, 0, sizeof(msg));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	iov.iov_base = &ch;
	iov.iov_len = sizeof(ch);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	if (recvmsg(sock, &msg, 0) < 0)
		return (-1);
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL);
	ATF_REQUIRE_EQ(cmsg->cmsg_level, SOL_SOCKET);
	ATF_REQUIRE_EQ(cmsg->cmsg_type, SCM_RIGHTS);
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return (fd);
}

static bool
fd_is_open_after_exec(int fd)
{
	char cmd[64];
	int status;
	pid_t pid;

	snprintf(cmd, sizeof(cmd),
	    "exec 2>/dev/null; : <&%d && exit 0; exit 1", fd);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(_PATH_BSHELL, "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) != 127,
	    "fd probe shell failed to exec");
	return (WEXITSTATUS(status) == 0);
}

static void
add_iov(struct iovec *iov, int *iovlen, const char *name, const void *val,
    size_t len)
{

	iov[*iovlen].iov_base = __DECONST(char *, name);
	iov[*iovlen].iov_len = strlen(name) + 1;
	*iovlen += 1;
	iov[*iovlen].iov_base = __DECONST(void *, val);
	iov[*iovlen].iov_len = len;
	*iovlen += 1;
}

static int
mount_tmpfs(const char *path, int flags)
{
	struct iovec iov[8];
	int iovlen;
	static const char from[] = "tmpfs";
	static const char fstype[] = "tmpfs";
	static const char sizeopt[] = "4m";

	iovlen = 0;
	add_iov(iov, &iovlen, "fstype", fstype, sizeof(fstype));
	add_iov(iov, &iovlen, "fspath", path, strlen(path) + 1);
	add_iov(iov, &iovlen, "from", from, sizeof(from));
	add_iov(iov, &iovlen, "size", sizeopt, sizeof(sizeopt));
	return (nmount(iov, iovlen, flags));
}

ATF_TC_WITH_CLEANUP(proc_checks);
ATF_TC_HEAD(proc_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise process check hooks");
}
ATF_TC_BODY(proc_checks, tc)
{
	void *p;
	int before;
	pid_t pid;
	int status;

	reset_denies();

	before = counter("proc_check_mmap_anon");
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE(p != MAP_FAILED);
	ATF_REQUIRE(munmap(p, PAGE_SIZE) == 0);
	require_counter_bump("proc_check_mmap_anon", before);

	before = counter("proc_check_mmap_anon");
	write_deny_value("proc_check_mmap_anon", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0) == MAP_FAILED);
	require_counter_bump("proc_check_mmap_anon", before);
	write_deny_value("proc_check_mmap_anon", 0);

	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE(p != MAP_FAILED);
	before = counter("proc_check_mprotect");
	ATF_REQUIRE(mprotect(p, PAGE_SIZE, PROT_READ) == 0);
	require_counter_bump("proc_check_mprotect", before);
	before = counter("proc_check_mprotect");
	write_deny_value("proc_check_mprotect", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, mprotect(p, PAGE_SIZE, PROT_READ | PROT_WRITE) ==
	    -1);
	require_counter_bump("proc_check_mprotect", before);
	write_deny_value("proc_check_mprotect", 0);
	ATF_REQUIRE(munmap(p, PAGE_SIZE) == 0);

	before = counter("proc_check_fork");
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	require_counter_bump("proc_check_fork", before);

	before = counter("proc_check_fork");
	write_deny_value("proc_check_fork", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, fork() == -1);
	require_counter_bump("proc_check_fork", before);
	write_deny_value("proc_check_fork", 0);

	before = counter("proc_check_syscall");
	(void)getpid();
	require_counter_bump("proc_check_syscall", before);

	/* proc_check_core: send SIGQUIT to a child. */
	before = counter("proc_check_core");
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
		(void)setrlimit(RLIMIT_CORE, &rl);
		raise(SIGQUIT);
		_exit(1);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	require_counter_bump("proc_check_core", before);
}
ATF_TC_CLEANUP(proc_checks, tc)
{
	reset_denies();
}

ATF_TC_WITH_CLEANUP(proc_notifications);
ATF_TC_HEAD(proc_notifications, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise process notify hooks");
}
ATF_TC_BODY(proc_notifications, tc)
{
	int before;
	pid_t pid;
	int status;

	reset_denies();

	before = counter("proc_notify_exit");
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	require_counter_bump("proc_notify_exit", before);

	before = counter("proc_notify_exec_complete");
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(_PATH_BSHELL, "sh", "-c", "exit 0", (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	require_counter_bump("proc_notify_exec_complete", before);
}
ATF_TC_CLEANUP(proc_notifications, tc)
{
	reset_denies();
}

ATF_TC_WITH_CLEANUP(file_checks);
ATF_TC_HEAD(file_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise file-layer hooks");
}
ATF_TC_BODY(file_checks, tc)
{
	char filepath[PATH_MAX];
	char *dir;
	int before, fd, fd2, socks[2], one;
	void *p;

	reset_denies();
	dir = make_tempdir();
	path_join(filepath, sizeof(filepath), dir, "mapped");
	create_file_with_data(filepath);

	before = counter("file_check_dup");
	fd = dup(STDOUT_FILENO);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(close(fd) == 0);
	require_counter_bump("file_check_dup", before);
	before = counter("file_check_dup");
	write_deny_value("file_check_dup", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, dup(STDOUT_FILENO) == -1);
	require_counter_bump("file_check_dup", before);
	write_deny_value("file_check_dup", 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, socks) == 0);
	fd = open(filepath, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	before = counter("file_check_receive");
	send_fd(socks[0], fd);
	fd2 = recv_fd(socks[1]);
	ATF_REQUIRE(fd2 >= 0);
	ATF_REQUIRE(close(fd2) == 0);
	require_counter_bump("file_check_receive", before);
	before = counter("file_check_receive");
	write_deny_value("file_check_receive", EPERM);
	send_fd(socks[0], fd);
	ATF_REQUIRE_ERRNO(EPERM, recv_fd(socks[1]) == -1);
	require_counter_bump("file_check_receive", before);
	write_deny_value("file_check_receive", 0);
	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(close(socks[0]) == 0);
	ATF_REQUIRE(close(socks[1]) == 0);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	before = counter("file_check_ioctl");
	one = 1;
	ATF_REQUIRE(ioctl(fd, FIONBIO, &one) == 0);
	require_counter_bump("file_check_ioctl", before);
	before = counter("file_check_ioctl");
	write_deny_value("file_check_ioctl", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, ioctl(fd, FIONBIO, &one) == -1);
	require_counter_bump("file_check_ioctl", before);
	write_deny_value("file_check_ioctl", 0);
	ATF_REQUIRE(close(fd) == 0);

	fd = open(filepath, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	before = counter("file_check_mmap");
	p = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	ATF_REQUIRE(p != MAP_FAILED);
	ATF_REQUIRE(munmap(p, PAGE_SIZE) == 0);
	require_counter_bump("file_check_mmap", before);
	before = counter("file_check_mmap");
	write_deny_value("file_check_mmap", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE,
	    fd, 0) == MAP_FAILED);
	require_counter_bump("file_check_mmap", before);
	write_deny_value("file_check_mmap", 0);
	ATF_REQUIRE(close(fd) == 0);

	before = counter("file_notify_close");
	fd = open(filepath, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(close(fd) == 0);
	require_counter_bump("file_notify_close", before);

	/* file_check_inherit: fork+exec with a non-CLOEXEC fd */
	fd = open(filepath, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	before = counter("file_check_inherit");
	ATF_REQUIRE_MSG(fd_is_open_after_exec(fd),
	    "fd %d did not survive exec on allow path", fd);
	require_counter_bump("file_check_inherit", before);

	/*
	 * Deny path: the fd should be force-closed during exec when
	 * the policy denies inheritance.  Verify by having the child
	 * exec a shell command that tests whether the fd is still open.
	 */
	before = counter("file_check_inherit");
	write_deny_value("file_check_inherit", EPERM);
	ATF_REQUIRE_MSG(!fd_is_open_after_exec(fd),
	    "fd %d survived exec despite MAC deny", fd);
	require_counter_bump("file_check_inherit", before);
	write_deny_value("file_check_inherit", 0);
	ATF_REQUIRE(close(fd) == 0);

	ATF_REQUIRE(unlink(filepath) == 0);
	ATF_REQUIRE(rmdir(dir) == 0);
	free(dir);
}
ATF_TC_CLEANUP(file_checks, tc)
{
	reset_denies();
}

ATF_TC_WITH_CLEANUP(vnode_socket_checks);
ATF_TC_HEAD(vnode_socket_checks, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise vnode and socket check hooks");
}
ATF_TC_BODY(vnode_socket_checks, tc)
{
	char filepath[PATH_MAX], sockpath[PATH_MAX];
	char *dir;
	int before, client, server, one;
	struct sockaddr_un sun;

	reset_denies();
	dir = make_tempdir();
	path_join(filepath, sizeof(filepath), dir, "file");
	create_file_with_data(filepath);
	path_join(sockpath, sizeof(sockpath), dir, "sock");

	server = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(server >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, sockpath, sizeof(sun.sun_path));

	before = counter("vnode_check_uipc_bind");
	ATF_REQUIRE(bind(server, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	require_counter_bump("vnode_check_uipc_bind", before);
	ATF_REQUIRE(listen(server, 1) == 0);

	client = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(client >= 0);
	before = counter("vnode_check_uipc_connect");
	ATF_REQUIRE(connect(client, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	require_counter_bump("vnode_check_uipc_connect", before);
	ATF_REQUIRE(close(client) == 0);

	before = counter("vnode_check_uipc_connect");
	write_deny_value("vnode_check_uipc_connect", EPERM);
	client = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(client >= 0);
	ATF_REQUIRE_ERRNO(EPERM, connect(client, (struct sockaddr *)&sun,
	    sizeof(sun)) == -1);
	require_counter_bump("vnode_check_uipc_connect", before);
	ATF_REQUIRE(close(client) == 0);
	write_deny_value("vnode_check_uipc_connect", 0);

	before = counter("socket_check_setsockopt");
	one = 1;
	ATF_REQUIRE(setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one,
	    sizeof(one)) == 0);
	require_counter_bump("socket_check_setsockopt", before);
	before = counter("socket_check_setsockopt");
	write_deny_value("socket_check_setsockopt", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, setsockopt(server, SOL_SOCKET, SO_REUSEADDR,
	    &one, sizeof(one)) == -1);
	require_counter_bump("socket_check_setsockopt", before);
	write_deny_value("socket_check_setsockopt", 0);

	before = counter("vnode_check_truncate");
	ATF_REQUIRE(truncate(filepath, 0) == 0);
	require_counter_bump("vnode_check_truncate", before);
	before = counter("vnode_check_truncate");
	write_deny_value("vnode_check_truncate", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, truncate(filepath, 0) == -1);
	require_counter_bump("vnode_check_truncate", before);
	write_deny_value("vnode_check_truncate", 0);

	ATF_REQUIRE(close(server) == 0);
	ATF_REQUIRE(unlink(sockpath) == 0);
	ATF_REQUIRE(unlink(filepath) == 0);
	ATF_REQUIRE(rmdir(dir) == 0);
	free(dir);
}
ATF_TC_CLEANUP(vnode_socket_checks, tc)
{
	reset_denies();
}

ATF_TC_WITH_CLEANUP(vnode_notifications);
ATF_TC_HEAD(vnode_notifications, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise vnode notify hooks");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(vnode_notifications, tc)
{
	char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX];
	char *dir;
	int before, fd;
	struct timeval tv[2];

	reset_denies();
	dir = make_tempdir();
	path_join(a, sizeof(a), dir, "a");
	path_join(b, sizeof(b), dir, "b");
	path_join(c, sizeof(c), dir, "c");

	before = counter("vnode_notify_create");
	fd = open(a, O_CREAT | O_RDWR | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, "payload", 7) == 7);
	ATF_REQUIRE(close(fd) == 0);
	require_counter_bump("vnode_notify_create", before);

	before = counter("vnode_notify_open");
	fd = open(a, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(close(fd) == 0);
	require_counter_bump("vnode_notify_open", before);

	before = counter("vnode_notify_link");
	ATF_REQUIRE(link(a, b) == 0);
	require_counter_bump("vnode_notify_link", before);

	before = counter("vnode_notify_rename");
	ATF_REQUIRE(rename(b, c) == 0);
	require_counter_bump("vnode_notify_rename", before);

	before = counter("vnode_notify_truncate");
	ATF_REQUIRE(truncate(a, 0) == 0);
	require_counter_bump("vnode_notify_truncate", before);

	before = counter("vnode_notify_setmode");
	ATF_REQUIRE(chmod(a, 0600) == 0);
	require_counter_bump("vnode_notify_setmode", before);

	tv[0].tv_sec = 1;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = 1;
	tv[1].tv_usec = 0;
	before = counter("vnode_notify_setutimes");
	ATF_REQUIRE(utimes(a, tv) == 0);
	require_counter_bump("vnode_notify_setutimes", before);

	before = counter("vnode_notify_setowner");
	ATF_REQUIRE(chown(a, 0, 0) == 0);
	require_counter_bump("vnode_notify_setowner", before);

	before = counter("vnode_notify_setflags");
	ATF_REQUIRE(chflags(a, UF_NODUMP) == 0);
	require_counter_bump("vnode_notify_setflags", before);
	ATF_REQUIRE(chflags(a, 0) == 0);

	before = counter("vnode_notify_setextattr");
	if (extattr_set_file(a, EXTATTR_NAMESPACE_USER, "test",
	    "val", 3) >= 0)
		require_counter_bump("vnode_notify_setextattr", before);

	before = counter("vnode_notify_deleteextattr");
	if (extattr_delete_file(a, EXTATTR_NAMESPACE_USER, "test") == 0)
		require_counter_bump("vnode_notify_deleteextattr", before);

	before = counter("vnode_notify_setacl");
	{
		acl_t acl = acl_get_file(a, ACL_TYPE_ACCESS);
		if (acl != NULL) {
			if (acl_set_file(a, ACL_TYPE_ACCESS, acl) == 0)
				require_counter_bump("vnode_notify_setacl",
				    before);
			acl_free(acl);
		}
	}

	before = counter("vnode_notify_unlink");
	ATF_REQUIRE(unlink(c) == 0);
	require_counter_bump("vnode_notify_unlink", before);
	ATF_REQUIRE(unlink(a) == 0);
	ATF_REQUIRE(rmdir(dir) == 0);
	free(dir);
}
ATF_TC_CLEANUP(vnode_notifications, tc)
{
	reset_denies();
}

ATF_TC_WITH_CLEANUP(mount_and_kas_info);
ATF_TC_HEAD(mount_and_kas_info, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise mount and kas-info hooks");
}
ATF_TC_BODY(mount_and_kas_info, tc)
{
	char *dir;
	int before;
	int mib[4];
	struct kinfo_proc kp;
	size_t len;

	reset_denies();
	dir = make_tempdir();

	before = counter("mount_check_mount");
	if (mount_tmpfs(dir, 0) != 0) {
		if (errno == ENODEV || errno == EOPNOTSUPP) {
			free(dir);
			atf_tc_skip("tmpfs mount unavailable");
		}
		atf_tc_fail("tmpfs mount failed: %s", strerror(errno));
	}
	require_counter_bump("mount_check_mount", before);

	before = counter("mount_check_remount");
	ATF_REQUIRE(mount_tmpfs(dir, MNT_UPDATE) == 0);
	require_counter_bump("mount_check_remount", before);

	before = counter("mount_check_umount");
	ATF_REQUIRE(unmount(dir, 0) == 0);
	require_counter_bump("mount_check_umount", before);

	before = counter("mount_check_mount");
	write_deny_value("mount_check_mount", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, mount_tmpfs(dir, 0) == -1);
	require_counter_bump("mount_check_mount", before);
	write_deny_value("mount_check_mount", 0);

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = getpid();
	len = sizeof(kp);
	/* Allow path: kernel pointers should be populated. */
	before = counter("system_check_kas_info");
	ATF_REQUIRE(sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == 0);
	require_counter_bump("system_check_kas_info", before);
	ATF_REQUIRE_MSG(kp.ki_paddr != NULL,
	    "ki_paddr should be non-NULL when hook allows");

	/*
	 * Deny path: sysctl still succeeds but kernel pointer fields
	 * are zeroed (ki_paddr, ki_fd, ki_pd, ki_vmspace).
	 */
	before = counter("system_check_kas_info");
	write_deny_value("system_check_kas_info", EPERM);
	len = sizeof(kp);
	ATF_REQUIRE(sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == 0);
	require_counter_bump("system_check_kas_info", before);
	ATF_REQUIRE_MSG(kp.ki_paddr == NULL,
	    "ki_paddr should be NULL when hook denies");
	ATF_REQUIRE_MSG(kp.ki_fd == NULL,
	    "ki_fd should be NULL when hook denies");
	write_deny_value("system_check_kas_info", 0);

	ATF_REQUIRE(rmdir(dir) == 0);
	free(dir);
}
ATF_TC_CLEANUP(mount_and_kas_info, tc)
{
	reset_denies();
}

ATF_TC_WITH_CLEANUP(pts_check);
ATF_TC_HEAD(pts_check, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise pts_check_open hook");
}
ATF_TC_BODY(pts_check, tc)
{
	int before, fd;

	reset_denies();

	/* Allow path: posix_openpt should succeed and bump counter. */
	before = counter("pts_check_open");
	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	require_counter_bump("pts_check_open", before);
	ATF_REQUIRE(close(fd) == 0);

	/* Deny path: posix_openpt should fail with EPERM. */
	before = counter("pts_check_open");
	write_deny_value("pts_check_open", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, posix_openpt(O_RDWR | O_NOCTTY) == -1);
	require_counter_bump("pts_check_open", before);
	write_deny_value("pts_check_open", 0);
}
ATF_TC_CLEANUP(pts_check, tc)
{
	reset_denies();
}

ATF_TC_WITH_CLEANUP(kld_check);
ATF_TC_HEAD(kld_check, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise kld_check_unload hook");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kld_check, tc)
{
	int before, modid, saved_errno;

	reset_denies();

	/*
	 * Load a small safe module so we can test unload.
	 * If loading fails, skip rather than fail.
	 */
	if (kldload("accf_http") == -1 && errno != EEXIST) {
		atf_tc_skip("cannot load accf_http for unload test");
	}

	modid = kldfind("accf_http");
	ATF_REQUIRE(modid != -1);

	/* Deny path: unload should fail with EPERM. */
	before = counter("kld_check_unload");
	write_deny_value("kld_check_unload", EPERM);
	ATF_REQUIRE_ERRNO(EPERM, kldunload(modid) == -1);
	require_counter_bump("kld_check_unload", before);
	write_deny_value("kld_check_unload", 0);

	/* Allow path: unload should succeed. */
	before = counter("kld_check_unload");
	if (kldunload(modid) == -1) {
		saved_errno = errno;
		atf_tc_skip("loaded module cannot be unloaded in this environment: %s",
		    strerror(saved_errno));
	}
	require_counter_bump("kld_check_unload", before);
}
ATF_TC_CLEANUP(kld_check, tc)
{
	reset_denies();
}

ATF_TC(vmm_check);
ATF_TC_HEAD(vmm_check, tc)
{
	atf_tc_set_md_var(tc, "descr", "Exercise vmm_check_create hook");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(vmm_check, tc)
{

	atf_tc_skip("Requires vmm(4) loaded and bhyve support");
}

ATF_TC(zfs_snapshot_checks);
ATF_TC_HEAD(zfs_snapshot_checks, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Exercise mount_check_snapshot_{create,delete,revert} hooks");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(zfs_snapshot_checks, tc)
{

	atf_tc_skip("Requires a ZFS pool");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, proc_checks);
	ATF_TP_ADD_TC(tp, proc_notifications);
	ATF_TP_ADD_TC(tp, file_checks);
	ATF_TP_ADD_TC(tp, vnode_socket_checks);
	ATF_TP_ADD_TC(tp, vnode_notifications);
	ATF_TP_ADD_TC(tp, mount_and_kas_info);
	ATF_TP_ADD_TC(tp, pts_check);
	ATF_TP_ADD_TC(tp, kld_check);
	ATF_TP_ADD_TC(tp, vmm_check);
	ATF_TP_ADD_TC(tp, zfs_snapshot_checks);
	return (atf_no_error());
}
