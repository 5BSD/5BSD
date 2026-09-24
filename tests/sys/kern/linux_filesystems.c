/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding amd64 Linux filesystem ABI checks; run only in a guest. */
#include "linux_test.h"

static char data[65536];
static const char target[] = "/tmp/fs space\ttab\nline\\slash";
static const char escaped[] = "/tmp/fs\\040space\\011tab\\012line\\134slash";
static const char source[] = "fs source\ttab\nline\\slash";

static int
contains(const char *s, const char *part)
{
	for (; *s; s++) {
		const char *a = s, *b = part;
		while (*b && *a == *b)
			a++, b++;
		if (!*b)
			return 1;
	}
	return 0;
}

static long
readfile(const char *path)
{
	long fd = sys3(SYS_open, path, 0, 0), n, total = 0;
	if (fd < 0)
		return fd;
	while (total < (long)sizeof(data) - 1) {
		n = sys3(SYS_read, fd, data + total, sizeof(data) - 1 - total);
		if (n < 0) {
			sys1(SYS_close, fd);
			return n;
		}
		if (!n)
			break;
		total += n;
	}
	data[total] = 0;
	sys1(SYS_close, fd);
	return total;
}

static int
mount_test(int invalid)
{
	static const char *bad[] = { "mode=888", "uid=-1", "gid=4294967295",
		"size=garbage", "mode=700oops", "unknown=1", "uid=12junk",
		"size=1%%", "size=1%junk", "nr_blocks=1%",
		"nr_blocks=-1", "nr_blocks=32junk" };
	unsigned char st[144];
	long r;
	sys2(SYS_mkdir, target, 0700);
	if (invalid) {
		for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			r = sys5(SYS_mount, source, target, "tmpfs", 0, bad[i]);
			if (r == 0) {
				sys2(166, target, 0);
				return 10 + i;
			}
			if (r != -EINVAL)
				return 20 + i;
		}
		return 0;
	}
	r = sys5(SYS_mount, source, target, "tmpfs", 0,
	    "size=2M,mode=0700,mode=0710,uid=123,gid=456,nr_inodes=128");
	if (r)
		return 1;
	if (sys2(SYS_stat, target, st))
		return 2;
	if ((*(unsigned int *)(st + 24) & 07777) != 0710 ||
	    *(unsigned int *)(st + 28) != 123 ||
	    *(unsigned int *)(st + 32) != 456)
		return 3;
	if (readfile("/proc/self/mounts") < 0 || !contains(data, escaped))
		return 4;
	if (readfile("/proc/self/mountinfo") < 0 || !contains(data, escaped))
		return 5;
	if (sys2(166, target, 0))
		return 6;
	/* Linux defaults do not inherit the covered directory's mode. */
	if (sys5(SYS_mount, "tmpfs", target, "tmpfs", 0, 0))
		return 7;
	if (sys2(SYS_stat, target, st) ||
	    (*(unsigned int *)(st + 24) & 07777) != 01777)
		return 8;
	if (sys2(166, target, 0))
		return 9;
	return 0;
}

static int
limits_test(void)
{
	static char block[65536];
	long fd, r, total = 0;
	sys2(SYS_mkdir, "/tmp/fs-limit", 0700);
	if (sys5(SYS_mount, "tmpfs", "/tmp/fs-limit", "tmpfs", 0,
		"size=1M,nr_inodes=128"))
		return 1;
	fd = sys3(SYS_open, "/tmp/fs-limit/data", 0102, 0600);
	if (fd < 0)
		return 2;
	for (int i = 0; i < 64; i++) {
		r = sys3(SYS_write, fd, block, sizeof(block));
		if (r == -ENOSPC)
			break;
		if (r <= 0)
			return 3;
		total += r;
	}
	if (total <= 0 || total > 1024 * 1024)
		return 4;
	sys1(SYS_close, fd);
	if (sys2(166, "/tmp/fs-limit", 0))
		return 5;
	/* Failed option parsing must not install a mount. */
	if (sys5(SYS_mount, "tmpfs", "/tmp/fs-limit", "tmpfs", 0, (void *)1) !=
	    -EFAULT)
		return 6;
	return 0;
}

static int
sysfs_mount(void)
{
	sys2(SYS_mkdir, "/tmp/fs-sys", 0700);
	if (sys5(SYS_mount, "sysfs", "/tmp/fs-sys", "sysfs", 0, 0))
		return 1;
	if (readfile("/tmp/fs-sys/devices/system/cpu/online") <= 0)
		return 2;
	if (sys2(166, "/tmp/fs-sys", 0))
		return 3;
	return 0;
}

static int
cpu_test(void)
{
	char list[4096], path[128];
	static unsigned char seen[4096];
	long n = readfile("/sys/devices/system/cpu/online");
	if (n <= 0 || n >= (long)sizeof(list))
		return 1;
	for (long i = 0; i <= n; i++)
		list[i] = data[i];
	const char *p = list;
	unsigned count = 0;
	while (*p && *p != '\n') {
		unsigned first = 0, last;
		if (*p < '0' || *p > '9')
			return 2;
		while (*p >= '0' && *p <= '9')
			first = first * 10 + *p++ - '0';
		last = first;
		if (*p == '-') {
			p++;
			last = 0;
			if (*p < '0' || *p > '9')
				return 3;
			while (*p >= '0' && *p <= '9')
				last = last * 10 + *p++ - '0';
		}
		if (last < first || last >= sizeof(seen))
			return 4;
		for (unsigned i = first; i <= last; i++) {
			if (seen[i])
				return 5;
			seen[i] = 1;
			count++;
			char digits[16];
			unsigned x = i, k = 0, off = 0;
			const char *base = "/sys/devices/system/cpu/cpu";
			while (*base)
				path[off++] = *base++;
			do {
				digits[k++] = '0' + x % 10;
				x /= 10;
			} while (x);
			while (k)
				path[off++] = digits[--k];
			path[off] = 0;
			long fd = sys3(SYS_open, path, 0x10000, 0);
			if (fd < 0)
				return 6;
			sys1(SYS_close, fd);
		}
		if (*p == ',')
			p++;
		else if (*p != '\n' && *p)
			return 7;
	}
	return count ? 0 : 8;
}

static unsigned long
counter(const char *path)
{
	unsigned long v = 0;
	if (readfile(path) <= 0)
		return ~0UL;
	for (char *p = data; *p != '\n'; p++) {
		if (*p < '0' || *p > '9')
			return ~0UL;
		v = v * 10 + *p - '0';
	}
	return v;
}

static int
network_test(void)
{
	const char *rx = "/sys/class/net/lo/statistics/rx_bytes";
	unsigned long before = counter(rx), after;
	struct {
		unsigned short family, port;
		unsigned int addr;
		char pad[8];
	} addr = { 2, 0x3930, 0x0100007f, { 0 } };
	if (before == ~0UL)
		return 1;
	if (readfile("/sys/class/net/lo/carrier") <= 0 || !xstreq(data, "1\n"))
		return 2;
	if (readfile("/sys/class/net/lo/operstate") <= 0 ||
	    (!xstreq(data, "unknown\n") && !xstreq(data, "up\n")))
		return 3;
	long fd = sys3(SYS_socket, 2, 2, 0);
	if (fd < 0)
		return 4;
	for (int i = 0; i < 16; i++)
		if (sys6(SYS_sendto, fd, "abc", 3, 0, &addr, sizeof(addr)) != 3)
			return 5;
	sys1(SYS_close, fd);
	after = counter(rx);
	if (after == ~0UL || after <= before)
		return 6;
	return 0;
}

static const char work[] = "/tmp/fs-coverage";

static void
filename(char *path, const char *base, unsigned n)
{
	char digits[16];
	unsigned i = 0;
	while (*base)
		*path++ = *base++;
	do {
		digits[i++] = '0' + n % 10;
		n /= 10;
	} while (n);
	while (i)
		*path++ = digits[--i];
	*path = 0;
}

/* Linux x86-64 statfs starts with type, block size, and block count. */
static int
sizing_test(void)
{
	static const struct {
		const char *option;
		unsigned long bytes;
	} cases[] = {
		{ "nr_blocks=32", 131072 },
		{ "nr_blocks=0x20", 131072 },
		{ "nr_blocks=040", 131072 },
		{ "nr_blocks=1k", 4194304 },
		{ "size=1M,nr_blocks=32", 131072 },
		{ "nr_blocks=32,size=256k", 262144 },
		{ "size=1", 4096 },
		{ "size=1%", 0 },
		{ "size=50%", 0 },
		{ "size=100%", 0 },
	};
	unsigned long st[32], memory = 0;
	if (readfile("/proc/meminfo") <= 0)
		return 1;
	char *p = data;
	if (!contains(p, "MemTotal:"))
		return 2;
	while (*p && (*p < '0' || *p > '9'))
		p++;
	while (*p >= '0' && *p <= '9')
		memory = memory * 10 + *p++ - '0';
	memory *= 1024;
	if (!memory)
		return 3;
	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, cases[i].option))
			return 10 + i;
		if (sys2(137, work, st))
			return 30 + i;
		unsigned long expected = cases[i].bytes;
		if (!expected)
			expected = (memory * (i == 7 ? 1 : i == 8 ? 50 : 100) / 100 +
			    4095) & ~4095UL;
		if (st[0] != 0x01021994 || st[1] != 4096 || st[2] * st[1] != expected)
			return 50 + i;
		if (sys2(166, work, 0))
			return 70 + i;
	}
	return 0;
}

static int
options_test(void)
{
	static const char *opts[] = { "size=131072", "size=128k", "size=128K",
		"size=0x20000", "size=0400000", ",,size=1m,,size=128k,",
		"size=0", "mode=0000", "mode=07777", "uid=0,gid=0",
		"nr_inodes=16" };
	unsigned char st[144];
	sys2(SYS_mkdir, work, 0700);
	for (unsigned i = 0; i < sizeof(opts) / sizeof(opts[0]); i++) {
		if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, opts[i]))
			return 10 + i;
		if (sys2(SYS_stat, work, st))
			return 30 + i;
		unsigned mode = *(unsigned *)(st + 24) & 07777;
		if (mode != (i == 7 ? 0U : i == 8 ? 07777U : 01777U))
			return 50 + i;
		if (sys2(166, work, 0))
			return 70 + i;
	}
	return sizing_test();
}

static int
inode_test(void)
{
	char path[128];
	unsigned made = 0;
	long fd;
	sys2(SYS_mkdir, work, 0700);
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, "size=2M,nr_inodes=16"))
		return 1;
	for (unsigned i = 0; i < 32; i++) {
		filename(path, "/tmp/fs-coverage/f", i);
		fd = sys3(SYS_open, path, 0102, 0600);
		if (fd == -ENOSPC)
			break;
		if (fd < 0)
			return 2;
		made++;
		sys1(SYS_close, fd);
	}
	if (made != 15)
		return 3;
	if (sys1(SYS_unlink, "/tmp/fs-coverage/f0"))
		return 4;
	fd = sys3(SYS_open, "/tmp/fs-coverage/reused", 0102, 0600);
	if (fd < 0)
		return 5;
	sys1(SYS_close, fd);
	return sys2(166, work, 0) ? 6 : 0;
}

static int
readonly_test(void)
{
	long fd;
	sys2(SYS_mkdir, work, 0700);
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 1, "size=2M"))
		return 1;
	if (sys3(SYS_open, "/tmp/fs-coverage/a", 0102, 0600) != -EROFS)
		return 2;
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 32, 0))
		return 3;
	fd = sys3(SYS_open, "/tmp/fs-coverage/a", 0102, 0600);
	if (fd < 0)
		return 4;
	if (sys3(SYS_write, fd, "ok", 2) != 2)
		return 5;
	sys1(SYS_close, fd);
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 33, 0))
		return 6;
	if (sys3(SYS_open, "/tmp/fs-coverage/b", 0102, 0600) != -EROFS)
		return 7;
	return sys2(166, work, 0) ? 8 : 0;
}

static int
bind_test(void)
{
	long fd;
	sys2(SYS_mkdir, work, 0700);
	sys2(SYS_mkdir, "/tmp/fs-bind", 0700);
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, "size=1M"))
		return 1;
	fd = sys3(SYS_open, "/tmp/fs-coverage/a", 0102, 0600);
	if (fd < 0)
		return 2;
	sys3(SYS_write, fd, "bound", 5);
	sys1(SYS_close, fd);
	/* Linux copies options, then ignores their contents for bind mounts. */
	if (sys5(SYS_mount, work, "/tmp/fs-bind", "tmpfs", 4096, (void *)1) !=
	    -EFAULT)
		return 9;
	if (sys5(SYS_mount, work, "/tmp/fs-bind", "tmpfs", 4096, "unknown=1"))
		return 3;
	if (readfile("/tmp/fs-bind/a") != 5 || !xstreq(data, "bound"))
		return 4;
	if (sys2(166, "/tmp/fs-bind", 0))
		return 5;
	return sys2(166, work, 0) ? 6 : 0;
}

static int
faults_test(void)
{
	char *p = (char *)sys6(SYS_mmap, 0, 8192, 3, 0x22, -1, 0);
	if ((long)p < 0)
		return 1;
	if (sys3(SYS_mprotect, p + 4096, 4096, 0))
		return 2;
	p[4092] = 's';
	p[4093] = 'i';
	p[4094] = 'z';
	p[4095] = 'e';
	sys2(SYS_mkdir, work, 0700);
	for (int i = 0; i < 32; i++) {
		if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, p + 4092) !=
		    -EINVAL)
			return 3;
		if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, "uid=invalid") !=
		    -EINVAL)
			return 4;
	}
	if (sys2(166, work, 0) != -EINVAL)
		return 5;
	/* A complete option before a fault is parsed as a terminated prefix. */
	const char *opt = "mode=0700";
	for (int i = 0; i < 9; i++)
		p[4087 + i] = opt[i];
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, p + 4087))
		return 6;
	unsigned char st[144];
	if (sys2(SYS_stat, work, st) ||
	    (*(unsigned *)(st + 24) & 07777) != 0700)
		return 7;
	if (sys2(166, work, 0))
		return 8;
	/* Linux terminates an option buffer at the page boundary. */
	for (int i = 0; i < 4096; i++)
		p[i] = ',';
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, p))
		return 9;
	if (sys2(166, work, 0))
		return 10;
	sys2(SYS_munmap, p, 8192);
	return 0;
}

static int
permissions_child(void *arg)
{
	(void)arg;
	if (sys2(116, 0, 0) || sys1(106, 456) || sys1(105, 456))
		return 1;
	if (sys3(SYS_open, "/tmp/fs-coverage/a", 0102, 0600) != -EACCES)
		return 2;
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0, 0) != -EPERM)
		return 3;
	long fd = sys3(SYS_open, "/sys/devices/system/cpu/online", 1, 0);
	if (fd >= 0) {
		sys1(SYS_close, fd);
		return 4;
	}
	return 0;
}

static int
permissions_test(void)
{
	int rc;
	sys2(SYS_mkdir, work, 0700);
	if (sys5(SYS_mount, "tmpfs", work, "tmpfs", 0,
		"uid=123,gid=123,mode=0700"))
		return 1;
	rc = run_child(permissions_child, 0);
	if (sys2(166, work, 0))
		return 2;
	return rc ? 10 + rc : 0;
}

static int
stream_test(void)
{
	static const char *paths[] = { "/sys/devices/system/cpu/online",
		"/sys/class/net/lo/address", "/proc/self/mounts",
		"/proc/self/mountinfo" };
	static char expected[65536], small[65536];
	for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		long n = readfile(paths[i]);
		if (n <= 0 || n > 60000)
			return 1;
		for (long k = 0; k < n; k++)
			expected[k] = data[k];
		long fd = sys3(SYS_open, paths[i], 0, 0), off = 0, r;
		if (fd < 0)
			return 2;
		while ((r = sys3(SYS_read, fd, small + off, 1)) == 1 && off < n)
			off++;
		if (r || off != n) {
			msg(paths[i]);
			msgnum(" read result ", r);
			msgnum(" offset ", off);
			return 3;
		}
		for (long k = 0; k < n; k++)
			if (small[k] != expected[k])
				return 4;
		if (sys3(SYS_lseek, fd, 0, 0))
			return 5;
		if (sys3(SYS_read, fd, small, 7) != (n < 7 ? n : 7))
			return 6;
		if (sys4(SYS_pread64, fd, small, 1, n - 1) != 1 ||
		    small[0] != expected[n - 1])
			return 7;
		if (sys3(SYS_lseek, fd, 0, 1) != (n < 7 ? n : 7))
			return 8;
		sys1(SYS_close, fd);
	}
	return 0;
}

static int
counters_test(void)
{
	static const char *names[] = { "rx_bytes", "tx_bytes", "rx_packets",
		"tx_packets", "rx_errors", "tx_errors", "rx_dropped",
		"tx_dropped", "multicast", "collisions" };
	char path[128];
	for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		char *p = path;
		const char *s = "/sys/class/net/lo/statistics/";
		while (*s)
			*p++ = *s++;
		s = names[i];
		while (*s)
			*p++ = *s++;
		*p = 0;
		if (counter(path) == ~0UL)
			return 10 + i;
	}
	return 0;
}

static int
link_test(const char *name, int state)
{
	char path[128];
	char *p = path;
	const char *s = "/sys/class/net/";
	while (*s)
		*p++ = *s++;
	while (*name)
		*p++ = *name++;
	char *suffix = p;
	s = "/carrier";
	while (*s)
		*p++ = *s++;
	*p = 0;
	long n = readfile(path);
	if (state < 0)
		return n == -ENOENT ? 0 : 1;
	if (!state) {
		if (n != -EINVAL)
			return 2;
	} else if (n <= 0 || !xstreq(data, "1\n"))
		return 3;
	p = suffix;
	s = "/operstate";
	while (*s)
		*p++ = *s++;
	*p = 0;
	if (readfile(path) <= 0)
		return 4;
	if (!state)
		return xstreq(data, "down\n") ? 0 : 5;
	return xstreq(data, "up\n") || xstreq(data, "unknown\n") ? 0 : 6;
}

static int
many_test(void)
{
	enum { MANY_MOUNTS = 96 };
	char path[128], escapedpath[128];
	for (unsigned i = 0; i < MANY_MOUNTS; i++) {
		filename(path, "/tmp/fs many ", i);
		sys2(SYS_mkdir, path, 0700);
		if (sys5(SYS_mount, "tmpfs", path, "tmpfs", 0,
			"size=64k,nr_inodes=16"))
			return 1;
	}
	if (readfile("/proc/self/mountinfo") <= 4096)
		return 2;
	for (unsigned i = 0; i < MANY_MOUNTS; i++) {
		filename(escapedpath, "/tmp/fs\\040many\\040", i);
		unsigned len = xstrlen(escapedpath);
		escapedpath[len] = ' ';
		escapedpath[len + 1] = 0;
		if (!contains(data, escapedpath))
			return 3;
	}
	for (unsigned i = MANY_MOUNTS; i > 0; i--) {
		filename(path, "/tmp/fs many ", i - 1);
		if (sys2(166, path, 0))
			return 4;
	}
	return 0;
}

static int
mount_reader(void *arg)
{
	int *ready = arg;
	char go;
	sys1(SYS_close, ready[1]);
	if (sys3(SYS_read, ready[0], &go, 1) != 1)
		return 1;
	for (int i = 0; i < 128; i++) {
		if (readfile("/proc/self/mountinfo") <= 0)
			return 2;
		if (contains(data, "fs race"))
			return 3;
	}
	return 0;
}

static int
race_test(void)
{
	int ready[2], status = 0;
	long child;
	if (sys1(SYS_pipe, ready))
		return 1;
	sys2(SYS_mkdir, "/tmp/fs race", 0700);
	child = fork_process();
	if (child < 0)
		return 2;
	if (!child)
		sys1(SYS_exit_group, mount_reader(ready));
	sys1(SYS_close, ready[0]);
	if (sys3(SYS_write, ready[1], "x", 1) != 1)
		return 3;
	sys1(SYS_close, ready[1]);
	for (int i = 0; i < 64; i++) {
		if (sys5(SYS_mount, "tmpfs", "/tmp/fs race", "tmpfs", 0,
			"size=64k"))
			return 4;
		if (sys2(166, "/tmp/fs race", 0))
			return 5;
	}
	if (sys4(SYS_wait4, child, &status, 0, 0) != child || status)
		return 6;
	return 0;
}

static int
churn_test(void)
{
	unsigned present = 0, absent = 0;
	struct timespec pause = { 0, 1000000 };
	for (int i = 0; i < 8192; i++) {
		if ((i % 64) == 0)
			sys2(SYS_nanosleep, &pause, 0);
		long r = readfile("/sys/class/net/lo1/statistics/rx_bytes");
		/* Linux kernfs may lose the active node after a successful
		 * open. */
		if (r != -ENOENT && r != -ENODEV && r != -EINVAL && r <= 0) {
			msgnum("CHURN_READ_ERROR ", r);
			return 1;
		}
		if (r == -ENOENT || r == -ENODEV || r == -EINVAL)
			absent++;
		if (r > 0) {
			present++;
			for (long k = 0; k < r - 1; k++)
				if (data[k] < '0' || data[k] > '9')
					return 2;
			if (data[r - 1] != '\n')
				return 3;
		}
	}
	msgnum("CHURN_PRESENT ", present);
	msgnum("CHURN_ABSENT ", absent);
	return present && absent ? 0 : 4;
}

static int
test(int argc, char **argv, char **envp)
{
	(void)envp;
	if (argc < 2)
		return 99;
	if (argc > 2 && xstreq(argv[2], "unprivileged")) {
		if (sys1(106, 65534) || sys1(105, 65534))
			return 98;
	}
	if (xstreq(argv[1], "options"))
		return options_test();
	if (xstreq(argv[1], "inode"))
		return inode_test();
	if (xstreq(argv[1], "readonly"))
		return readonly_test();
	if (xstreq(argv[1], "bind"))
		return bind_test();
	if (xstreq(argv[1], "faults"))
		return faults_test();
	if (xstreq(argv[1], "permissions"))
		return permissions_test();
	if (xstreq(argv[1], "stream"))
		return stream_test();
	if (xstreq(argv[1], "counters"))
		return counters_test();
	if (xstreq(argv[1], "many"))
		return many_test();
	if (argc > 2 && xstreq(argv[1], "link_up"))
		return link_test(argv[2], 1);
	if (argc > 2 && xstreq(argv[1], "link_down"))
		return link_test(argv[2], 0);
	if (argc > 2 && xstreq(argv[1], "link_absent"))
		return link_test(argv[2], -1);
	if (xstreq(argv[1], "race"))
		return race_test();
	if (xstreq(argv[1], "churn"))
		return churn_test();
	if (xstreq(argv[1], "limits"))
		return limits_test();
	if (xstreq(argv[1], "mount"))
		return mount_test(0);
	if (xstreq(argv[1], "invalid"))
		return mount_test(1);
	if (xstreq(argv[1], "sysfs_mount"))
		return sysfs_mount();
	if (xstreq(argv[1], "cpu"))
		return cpu_test();
	if (xstreq(argv[1], "network"))
		return network_test();
	return 97;
}
