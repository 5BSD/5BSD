/* SPDX-License-Identifier: BSD-2-Clause
 * Linux64 differential tests; run only in a disposable guest.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
/* Stable Linux UAPI layout, kept local for the musl-only cross sysroot. */
struct sockaddr_nl {
	uint16_t nl_family, pad;
	uint32_t pid, groups;
};
struct nlmsghdr {
	uint32_t nlmsg_len;
	uint16_t nlmsg_type, nlmsg_flags;
	uint32_t nlmsg_seq, nlmsg_pid;
};
struct ifinfomsg {
	uint8_t ifi_family, pad;
	uint16_t ifi_type;
	int32_t ifi_index;
	uint32_t ifi_flags, ifi_change;
};
struct rtattr {
	uint16_t rta_len, rta_type;
};
#define NETLINK_ROUTE 0
#define RTM_NEWLINK 16
#define RTM_GETLINK 18
#define NLM_F_REQUEST 1
#define NLM_F_DUMP 0x300
#define NLMSG_DONE 3
#define IFLA_IFNAME 3
#define IFLA_CARRIER 33
#define ALIGN4(n) (((n) + 3) & ~3U)
#define NLMSG_LENGTH(n) (sizeof(struct nlmsghdr) + (n))
#define NLMSG_DATA(h) ((void*)((h) + 1))
#define NLMSG_OK(h, n)                                                         \
	((n) >= (int)sizeof(*(h)) && (h)->nlmsg_len >= sizeof(*(h))            \
	    && (h)->nlmsg_len <= (unsigned)(n))
#define NLMSG_NEXT(h, n)                                                       \
	((n) -= ALIGN4((h)->nlmsg_len),                                        \
	    (void*)((char*)(h) + ALIGN4((h)->nlmsg_len)))
#define IFLA_PAYLOAD(h)                                                        \
	((h)->nlmsg_len - sizeof(*(h)) - sizeof(struct ifinfomsg))
#define IFLA_RTA(i) ((struct rtattr*)((i) + 1))
#define RTA_OK(a, n)                                                           \
	((n) >= (int)sizeof(*(a)) && (a)->rta_len >= sizeof(*(a))              \
	    && (a)->rta_len <= (unsigned)(n))
#define RTA_NEXT(a, n)                                                         \
	((n) -= ALIGN4((a)->rta_len),                                          \
	    (void*)((char*)(a) + ALIGN4((a)->rta_len)))
#define RTA_DATA(a) ((void*)((a) + 1))
#define RTA_PAYLOAD(a) ((a)->rta_len - sizeof(*(a)))
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x)                                                               \
	do {                                                                   \
		if (!(x)) {                                                    \
			fprintf(stderr, "line %d: %s: %s\n", __LINE__, #x,     \
			    strerror(errno));                                  \
			exit(1);                                               \
		}                                                              \
	} while (0)
static void put(const char* p)
{
	int f = open(p, O_CREAT | O_RDWR, 0600);
	CHECK(f >= 0);
	CHECK(write(f, "abc", 3) == 3);
	CHECK(close(f) == 0);
}
static int notifications(void)
{
	char d[] = "/tmp/inotify-next-XXXXXX", a[256], b[256], buf[65536];
	CHECK(mkdtemp(d));
	snprintf(a, sizeof(a), "%s/a", d);
	snprintf(b, sizeof(b), "%s/b", d);
	int f = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	CHECK(f >= 0);
	int w = inotify_add_watch(
	    f, d, IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE);
	CHECK(w >= 0);
	CHECK(inotify_add_watch(f, d, IN_CREATE | IN_MASK_CREATE) == -1
	    && errno == EEXIST);
	CHECK(inotify_add_watch(f, d, IN_ATTRIB | IN_MASK_ADD) == w);
	put(a);
	CHECK(rename(a, b) == 0);
	CHECK(unlink(b) == 0);
	int bytes = 0;
	CHECK(ioctl(f, FIONREAD, &bytes) == 0 && bytes > 0);
	CHECK(read(f, buf, 1) == -1 && errno == EINVAL);
	int n = read(f, buf, sizeof(buf));
	CHECK(n == bytes);
	unsigned from = 0, to = 0, seen = 0;
	for (int off = 0; off < n;) {
		struct inotify_event* e = (void*)(buf + off);
		CHECK(off + (int)sizeof(*e) + (int)e->len <= n);
		CHECK(e->wd == w);
		if (e->mask & IN_CREATE)
			seen |= 1;
		if (e->mask & IN_DELETE)
			seen |= 2;
		if (e->mask & IN_MOVED_FROM)
			from = e->cookie;
		if (e->mask & IN_MOVED_TO)
			to = e->cookie;
		off += sizeof(*e) + e->len;
	}
	fprintf(stderr, "notify seen=%u from=%u to=%u\n", seen, from, to);
	CHECK(seen == 3 && from != 0 && from == to);
	CHECK(ioctl(f, FIONREAD, &bytes) == 0 && bytes == 0);
	CHECK(inotify_add_watch(f, d, IN_CREATE | IN_ONESHOT) == w);
	put(a);
	put(b);
	n = read(f, buf, sizeof(buf));
	CHECK(n > 0);
	int create = 0, ignored = 0;
	for (int off = 0; off < n;) {
		struct inotify_event* e = (void*)(buf + off);
		if (e->mask & IN_CREATE)
			create++;
		if (e->mask & IN_IGNORED)
			ignored++;
		off += sizeof(*e) + e->len;
	}
	CHECK(create == 1 && ignored == 1);
	CHECK(inotify_rm_watch(f, w) == -1 && errno == EINVAL);
	unlink(a);
	unlink(b);
	close(f);
	rmdir(d);
	return 0;
}
static int notifyrace(void)
{
	char d[] = "/tmp/inotify-race-XXXXXX", a[256], buf[65536];
	CHECK(mkdtemp(d));
	snprintf(a, sizeof(a), "%s/a", d);
	int f = inotify_init1(IN_NONBLOCK);
	CHECK(f >= 0);
	CHECK(inotify_add_watch(f, d, IN_CREATE) >= 0);
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		for (int i = 0; i < 4000; i++) {
			put(a);
			CHECK(unlink(a) == 0);
		}
		_exit(0);
	}
	for (int i = 0; i < 8000; i++) {
		CHECK(inotify_add_watch(
			  f, d, IN_CREATE | ((i & 1) ? IN_DELETE : IN_ATTRIB))
		    >= 0);
		int n;
		CHECK(ioctl(f, FIONREAD, &n) == 0 && n >= 0);
		ssize_t r = read(f, buf, sizeof(buf));
		CHECK(r >= 0 || errno == EAGAIN);
	}
	int st;
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	close(f);
	rmdir(d);
	return 0;
}
static int number(const char* name, const char* field)
{
	char p[256], buf[256];
	snprintf(p, sizeof(p), "/sys/class/net/%s/%s", name, field);
	int f = open(p, O_RDONLY);
	CHECK(f >= 0);
	int n = read(f, buf, sizeof(buf) - 1);
	CHECK(n > 0);
	buf[n] = 0;
	close(f);
	return atoi(buf);
}
static int discovery(void)
{
	int f = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	CHECK(f >= 0);
	struct timeval timeout = { 5, 0 };
	CHECK(setsockopt(f, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
	    == 0);
	struct sockaddr_nl local = { .nl_family = AF_NETLINK },
			   kernel = { .nl_family = AF_NETLINK };
	CHECK(bind(f, (void*)&local, sizeof(local)) == 0);
	struct {
		struct nlmsghdr h;
		struct ifinfomsg i;
	} req = { .h = { .nlmsg_len = sizeof(req),
		      .nlmsg_type = RTM_GETLINK,
		      .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		      .nlmsg_seq = 42 },
		.i = { .ifi_family = AF_UNSPEC } };
	CHECK(sendto(f, &req, sizeof(req), 0, (void*)&kernel, sizeof(kernel))
	    == sizeof(req));
	char buf[32768];
	int done = 0, lo = 0, count = 0;
	while (!done) {
		int n = recv(f, buf, sizeof(buf), 0);
		CHECK(n > 0);
		for (struct nlmsghdr* h = (void*)buf; NLMSG_OK(h, n);
		    h = NLMSG_NEXT(h, n)) {
			CHECK(h->nlmsg_seq == 42);
			if (h->nlmsg_type == NLMSG_DONE) {
				done = 1;
				break;
			}
			CHECK(h->nlmsg_type == RTM_NEWLINK);
			CHECK(h->nlmsg_len
			    >= NLMSG_LENGTH(sizeof(struct ifinfomsg)));
			struct ifinfomsg* i = NLMSG_DATA(h);
			int len = IFLA_PAYLOAD(h), carrier = -1;
			char name[128] = { 0 };
			for (struct rtattr* a = IFLA_RTA(i); RTA_OK(a, len);
			    a = RTA_NEXT(a, len)) {
				if (a->rta_type == IFLA_IFNAME) {
					CHECK(RTA_PAYLOAD(a) < sizeof(name));
					memcpy(
					    name, RTA_DATA(a), RTA_PAYLOAD(a));
				}
				if (a->rta_type == IFLA_CARRIER) {
					CHECK(RTA_PAYLOAD(a) == 1);
					carrier = *(unsigned char*)RTA_DATA(a);
				}
			}
			CHECK(name[0]);
			fprintf(stderr,
			    "link %s sysfs=%d netlink=%d type=%u flags=%x "
			    "carrier=%d\n",
			    name, number(name, "ifindex"), i->ifi_index,
			    i->ifi_type, i->ifi_flags, carrier);
			CHECK(number(name, "ifindex") == i->ifi_index);
			CHECK(number(name, "type") == i->ifi_type);
			if (carrier >= 0)
				CHECK(!!(i->ifi_flags & 0x10000) ==
			    (!!carrier && !!(i->ifi_flags & 1)));
			char path[256], text[256], expect[256];
			snprintf(path, sizeof(path), "/sys/class/net/%s/uevent",
			    name);
			int fd = open(path, O_RDONLY);
			CHECK(fd >= 0);
			int r = read(fd, text, sizeof(text) - 1);
			CHECK(r >= 0);
			text[r] = 0;
			close(fd);
			snprintf(expect, sizeof(expect),
			    "INTERFACE=%s\nIFINDEX=%d\n", name, i->ifi_index);
			CHECK(!strcmp(text, expect));
			if (!strcmp(name, "lo")) {
				CHECK(i->ifi_type == 772);
				lo++;
			}
			count++;
		}
	}
	CHECK(lo == 1 && count >= 1);
	close(f);
	return 0;
}
static void xattredges_at(const char *path)
{
	char name[256], buf[258];
	int f = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
	CHECK(f >= 0);
	CHECK(listxattr(path, NULL, 8) == 0);
	memset(name, 'x', 255);
	memcpy(name, "user.", 5);
	name[255] = 0;
	CHECK(fsetxattr(f, name, "v", 1, 0) == 0);
	CHECK(fgetxattr(f, name, buf, sizeof(buf)) == 1 && buf[0] == 'v');
	CHECK(listxattr(path, NULL, 0) == 256);
	CHECK(listxattr(path, NULL, 256) == -1 && errno == EFAULT);
	CHECK(flistxattr(f, NULL, 256) == -1 && errno == EFAULT);
	CHECK(llistxattr(path, (void *)(uintptr_t)1, 256) == -1 && errno == EFAULT);
	CHECK(listxattr(path, buf, 255) == -1 && errno == ERANGE);
	memset(buf, 0xa5, sizeof(buf));
	CHECK(flistxattr(f, buf, 256) == 256);
	CHECK(!memcmp(buf, name, 256) && (unsigned char)buf[256] == 0xa5);
	CHECK(fremovexattr(f, name) == 0);
	CHECK(flistxattr(f, NULL, 0) == 0);
	CHECK(close(f) == 0);
	CHECK(unlink(path) == 0);
}
static int xattredges(void)
{
	char path[128];
	snprintf(path, sizeof(path), "/tmp/xattr-edge-%d", getpid());
	xattredges_at(path);
	return 0;
}
static int notifydelete(void)
{
	char path[] = "/tmp/notify-delete-XXXXXX", buf[4096];
	int file = mkstemp(path);
	CHECK(file >= 0);
	CHECK(close(file) == 0);
	int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	CHECK(fd >= 0);
	int wd = inotify_add_watch(fd, path, IN_ATTRIB);
	CHECK(wd >= 0);
	CHECK(unlink(path) == 0);
	int n = read(fd, buf, sizeof(buf)), ignored = 0;
	CHECK(n > 0);
	for (int off = 0; off < n;) {
		struct inotify_event *ev = (void *)(buf + off);
		CHECK(ev->wd == wd && !(ev->mask & IN_DELETE_SELF));
		if (ev->mask & IN_IGNORED)
			ignored++;
		off += sizeof(*ev) + ev->len;
	}
	CHECK(ignored == 1);
	CHECK(inotify_rm_watch(fd, wd) == -1 && errno == EINVAL);
	CHECK(close(fd) == 0);
	return 0;
}
static int abstractlife(void)
{
	struct sockaddr_un names[192], peer;
	int fd[192], duplicate;
	for (int i = 0; i < 192; i++) {
		memset(&names[i], 0, sizeof(names[i]));
		names[i].sun_family = AF_UNIX;
		/* Long names, including embedded NULs, remain live together. */
		memset(names[i].sun_path + 1, 'z', sizeof(names[i].sun_path) - 1);
		memcpy(names[i].sun_path + 1, &i, sizeof(i));
		pid_t pid = getpid();
		memcpy(names[i].sun_path + 8, &pid, sizeof(pid));
		fd[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
		CHECK(fd[i] >= 0);
		CHECK(bind(fd[i], (void *)&names[i], sizeof(names[i])) == 0);
	}
	for (int i = 191; i >= 0; i--) {
		duplicate = socket(AF_UNIX, SOCK_DGRAM, 0);
		CHECK(duplicate >= 0);
		CHECK(connect(duplicate, (void *)&names[i], sizeof(names[i])) == 0);
		CHECK(write(duplicate, "x", 1) == 1);
		char value;
		CHECK(read(fd[i], &value, 1) == 1 && value == 'x');
		CHECK(close(fd[i]) == 0);
		CHECK(close(duplicate) == 0);
	}
	int listener = socket(AF_UNIX, SOCK_STREAM, 0);
	int client = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0 && client >= 0);
	CHECK(bind(listener, (void *)&names[0], sizeof(names[0])) == 0);
	CHECK(listen(listener, 4) == 0);
	CHECK(connect(client, (void *)&names[0], sizeof(names[0])) == 0);
	int accepted = accept(listener, NULL, NULL);
	CHECK(accepted >= 0);
	CHECK(close(listener) == 0);
	/* An accepted endpoint keeps its address, not the listening name. */
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (void *)&names[0], sizeof(names[0])) == 0);
	socklen_t len = sizeof(peer);
	CHECK(getsockname(accepted, (void *)&peer, &len) == 0);
	CHECK(len == sizeof(names[0]) && !memcmp(&peer, &names[0], len));
	CHECK(write(client, "s", 1) == 1);
	char value;
	CHECK(read(accepted, &value, 1) == 1 && value == 's');
	close(accepted);close(client);close(listener);
	return 0;
}
static int fusefiles(const char* dir)
{
	CHECK(chdir(dir) == 0);
	CHECK(mkdir("work", 0777) == 0);
	CHECK(chdir("work") == 0);
	int f = open("a", O_CREAT | O_RDWR | O_EXCL, 0640);
	CHECK(f >= 0);
	CHECK(write(f, "hello", 5) == 5);
	CHECK(fsync(f) == 0);
	CHECK(pwrite(f, "X", 1, 8192) == 1);
	struct stat st;
	CHECK(fstat(f, &st) == 0 && st.st_size == 8193);
	char buf[8193];
	memset(buf, 1, sizeof(buf));
	CHECK(pread(f, buf, sizeof(buf), 0) == sizeof(buf));
	CHECK(!memcmp(buf, "hello", 5) && buf[8192] == 'X');
	for (int i = 5; i < 8192; i++)
		CHECK(buf[i] == 0);
	CHECK(ftruncate(f, 4096) == 0);
	char* m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
	CHECK(m != MAP_FAILED);
	memcpy(m + 32, "mapped", 6);
	CHECK(msync(m, 4096, MS_SYNC) == 0);
	CHECK(munmap(m, 4096) == 0);
	CHECK(pread(f, buf, 6, 32) == 6 && !memcmp(buf, "mapped", 6));
	CHECK(rename("a", "b") == 0);
	CHECK(link("b", "hard") == 0);
	CHECK(symlink("b", "sym") == 0);
	CHECK(readlink("sym", buf, sizeof(buf)) == 1 && buf[0] == 'b');
	CHECK(stat("b", &st) == 0 && st.st_nlink == 2);
	CHECK(chmod("b", 0600) == 0);
	CHECK(stat("b", &st) == 0 && (st.st_mode & 0777) == 0600);
	CHECK(setxattr("b", "user.gate", "value", 5, 0) == 0);
	CHECK(getxattr("b", "user.gate", buf, sizeof(buf)) == 5
	    && !memcmp(buf, "value", 5));
	CHECK(listxattr("b", NULL, 0) == 10);
	CHECK(listxattr("b", buf, 1) == -1 && errno == ERANGE);
	CHECK(listxattr("b", buf, sizeof(buf)) == 10);
	CHECK(removexattr("b", "user.gate") == 0);
	xattredges_at("xattr-edge");
	CHECK(getxattr("b", "user.gate", buf, sizeof(buf)) == -1
	    && errno == ENODATA);
	struct flock lk
	    = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1 };
	CHECK(fcntl(f, F_SETLK, &lk) == 0);
	pid_t p = fork();
	CHECK(p >= 0);
	if (!p) {
		int g = open("b", O_RDWR);
		CHECK(g >= 0);
		CHECK(fcntl(g, F_SETLK, &lk) == -1
		    && (errno == EAGAIN || errno == EACCES));
		close(g);
		_exit(0);
	}
	int status;
	CHECK(waitpid(p, &status, 0) == p && status == 0);
	lk.l_type = F_UNLCK;
	CHECK(fcntl(f, F_SETLK, &lk) == 0);
	CHECK(unlink("b") == 0);
	CHECK(unlink("hard") == 0);
	CHECK(pread(f, buf, 5, 0) == 5 && !memcmp(buf, "hello", 5));
	CHECK(pwrite(f, "!", 1, 0) == 1);
	CHECK(fsync(f) == 0);
	CHECK(close(f) == 0);
	CHECK(unlink("sym") == 0);
	for (int i = 0; i < 300; i++) {
		char name[32];
		snprintf(name, sizeof(name), "file-%03d", i);
		put(name);
	}
	DIR* d = opendir(".");
	CHECK(d);
	int n = 0;
	struct dirent* e;
	while ((e = readdir(d)))
		if (!strncmp(e->d_name, "file-", 5))
			n++;
	CHECK(n == 300);
	rewinddir(d);
	n = 0;
	while ((e = readdir(d)))
		if (!strncmp(e->d_name, "file-", 5))
			n++;
	CHECK(n == 300);
	closedir(d);
	for (int i = 0; i < 300; i++) {
		char name[32];
		snprintf(name, sizeof(name), "file-%03d", i);
		CHECK(unlink(name) == 0);
	}
	CHECK(chdir("..") == 0);
	CHECK(rmdir("work") == 0);
	return 0;
}
static socklen_t abstractname(struct sockaddr_un* a, const char* tag)
{
	memset(a, 0, sizeof(*a));
	a->sun_family = AF_UNIX;
	snprintf(
	    a->sun_path + 1, sizeof(a->sun_path) - 1, "compat-next-%s", tag);
	return 2 + 1 + strlen(a->sun_path + 1);
}
static int abstractextra(void)
{
	struct sockaddr_un a, b;
	char tag[32];
	snprintf(tag, sizeof(tag), "%d", getpid());
	socklen_t len = abstractname(&a, tag);
	int server = socket(AF_UNIX, SOCK_DGRAM, 0),
	    client = socket(AF_UNIX, SOCK_DGRAM, 0), one = 1;
	CHECK(server >= 0 && client >= 0);
	CHECK(bind(server, (void*)&a, len) == 0);
	CHECK(setsockopt(server, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one))
	    == 0);
	CHECK(setsockopt(client, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one))
	    == 0);
	int pipefd[2];
	CHECK(pipe(pipefd) == 0);
	char ch = 'q';
	struct iovec iov = { &ch, 1 };
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(int))
		    + CMSG_SPACE(sizeof(struct ucred))];
	} control;
	memset(&control, 0, sizeof(control));
	struct msghdr msg = { .msg_name = &a,
		.msg_namelen = len,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.data,
		.msg_controllen = CMSG_SPACE(sizeof(int)) };
	struct cmsghdr* c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &pipefd[1], sizeof(int));
	CHECK(sendmsg(client, &msg, 0) == 1);
	socklen_t n = sizeof(b);
	CHECK(getsockname(client, (void*)&b, &n) == 0 && n == 8
	    && b.sun_path[0] == 0);
	msg.msg_name = &a;
	msg.msg_namelen = sizeof(a);
	msg.msg_controllen = sizeof(control);
	memset(&control, 0, sizeof(control));
	CHECK(recvmsg(server, &msg, 0) == 1);
	CHECK(msg.msg_namelen == n && !memcmp(&a, &b, n));
	int fd = -1, creds = 0;
	for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
		if (c->cmsg_type == SCM_RIGHTS)
			memcpy(&fd, CMSG_DATA(c), sizeof(int));
		if (c->cmsg_type == SCM_CREDENTIALS) {
			struct ucred cr;
			memcpy(&cr, CMSG_DATA(c), sizeof(cr));
			CHECK(cr.pid == getpid() && cr.uid == getuid());
			creds++;
		}
	}
	CHECK(fd >= 0 && creds == 1);
	CHECK(write(fd, "R", 1) == 1);
	CHECK(read(pipefd[0], &ch, 1) == 1 && ch == 'R');
	close(fd);
	close(pipefd[0]);
	close(pipefd[1]);
	close(server);
	close(client);
	pid_t kids[4];
	for (int j = 0; j < 4; j++) {
		kids[j] = fork();
		CHECK(kids[j] >= 0);
		if (!kids[j]) {
			for (int i = 0; i < 400; i++) {
				int f = socket(AF_UNIX, SOCK_DGRAM, 0);
				CHECK(f >= 0);
				socklen_t size = abstractname(&a, tag);
				int rc = bind(f, (void*)&a, size);
				CHECK(rc == 0 || errno == EADDRINUSE);
				close(f);
			}
			_exit(0);
		}
	}
	for (int j = 0; j < 4; j++) {
		int st;
		CHECK(waitpid(kids[j], &st, 0) == kids[j] && st == 0);
	}
	return 0;
}
static int isolated(const char* mode, const char* tag)
{
	struct sockaddr_un a;
	socklen_t n = abstractname(&a, tag);
	int f = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK(f >= 0);
	CHECK(connect(f, (void*)&a, n) == -1);
	if (!strcmp(mode, "cap")) {
		CHECK(errno == EPERM);
		CHECK(bind(f, (void*)&a, n) == -1 && errno == EPERM);
	} else {
		CHECK(errno == ECONNREFUSED);
		CHECK(bind(f, (void*)&a, n) == 0);
	}
	close(f);
	return 0;
}
static int isolation(const char* mode)
{
	struct sockaddr_un a;
	char tag[32];
	snprintf(tag, sizeof(tag), "%d", getpid());
	socklen_t n = abstractname(&a, tag);
	int f = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK(f >= 0);
	CHECK(bind(f, (void*)&a, n) == 0);
	pid_t p = fork();
	CHECK(p >= 0);
	if (!p) {
		execl("/root/abstract-native", "abstract-native", mode, tag,
		    (char*)0);
		_exit(99);
	}
	int st;
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(st == 0);
	close(f);
	return 0;
}
static int fusefailure(const char* dir)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/uncached-after-daemon-exit", dir);
	struct stat st;
	CHECK(stat(path, &st) == -1);
	CHECK(errno == ENOTCONN || errno == ENXIO || errno == EIO);
	return 0;
}
int main(int argc, char** argv)
{
	CHECK(argc >= 2);
	alarm(120);
	if (argc > 2 && !strcmp(argv[argc - 1], "unprivileged")) {
		CHECK(setgid(65534) == 0);
		CHECK(setuid(65534) == 0);
	}
	if (!strcmp(argv[1], "xattredges"))
		return xattredges();
	if (!strcmp(argv[1], "notifydelete"))
		return notifydelete();
	if (!strcmp(argv[1], "abstractlife"))
		return abstractlife();
	if (!strcmp(argv[1], "caps")) {
		int f = socket(AF_UNIX, SOCK_DGRAM, 0);
		CHECK(f >= 0);
		CHECK(dup2(f, 3) == 3);
		execl("/root/abstract-caps", "abstract-caps",
		    "/root/abstract-caps-probe", (char*)0);
		return 2;
	}
	if (!strcmp(argv[1], "abstractextra"))
		return abstractextra();
	if (!strcmp(argv[1], "isolate"))
		return isolation(argv[2]);
	if (!strcmp(argv[1], "isolated"))
		return isolated(argv[2], argv[3]);
	if (!strcmp(argv[1], "notify"))
		return notifications();
	if (!strcmp(argv[1], "notifyrace"))
		return notifyrace();
	if (!strcmp(argv[1], "discovery"))
		return discovery();
	if (!strcmp(argv[1], "fusefailure"))
		return fusefailure(argv[2]);
	if (!strcmp(argv[1], "fuse")) {
		CHECK(argc >= 3);
		return fusefiles(argv[2]);
	}
	return 2;
}
