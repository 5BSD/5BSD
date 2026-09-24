/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux amd64 remap_file_pages reference and VM gate. */
typedef unsigned long u64;
static const char path[] = "remap-file-pages.tmp";
static const u64 page = 4096;
static long
call(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d, r8 __asm__("r8") = e,
	    r9 __asm__("r9") = f;
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (ret);
}
static long
remap(u64 start, u64 size, u64 prot, u64 pgoff, u64 flags)
{
	return (call(216, start, size, prot, pgoff, flags, 0));
}
static int
test(void)
{
	char *map, *priv;
	char value;
	long fd;
	int i;

	fd = call(257, -100, (long)path, 0x242, 0600, 0, 0);
	if (fd < 0 || call(77, fd, 4 * page, 0, 0, 0, 0) != 0)
		return (1);
	for (i = 0; i < 4; i++) {
		value = 'A' + i;
		if (call(18, fd, (long)&value, 1, i * page, 0, 0) != 1)
			return (2);
	}
	map = (char *)call(9, 0, 4 * page, 3, 1, fd, 0);
	if ((long)map < 0)
		return (3);
	if (call(3, fd, 0, 0, 0, 0, 0) != 0)
		return (4);
	if (map[0] != 'A' || map[page] != 'B' ||
	    map[2 * page] != 'C' || map[3 * page] != 'D')
		return (5);
	if (remap((u64)(map + page), page, 0, 0, 0) != 0 ||
	    map[page] != 'A')
		return (6);
	map[page] = 'Z';
	if (map[0] != 'Z')
		return (7);
	if (remap((u64)(map + 2 * page), page, 0, 3, 0) != 0 ||
	    map[2 * page] != 'D')
		return (8);
	fd = call(257, -100, (long)path, 2, 0, 0, 0);
	if (fd < 0 || call(17, fd, (long)&value, 1, page, 0, 0) != 1 ||
	    value != 'B')
		return (9);
	if (remap((u64)(map + 3 * page + 17), page + 7, 0, 1,
	    0x80000000UL) != 0 || map[3 * page] != 'B')
		return (10);
	if (remap((u64)map, page, 1, 0, 0) != -22 ||
	    remap((u64)map, 0, 0, 0, 0) != -22 ||
	    remap(0x4000, page, 0, 0, 0) != -22 ||
	    remap((u64)(map + 3 * page), 2 * page, 0, 0, 0) != -22 ||
	    remap((u64)map, page, 0, ~(u64)0, 0) != -22)
		return (11);
	if (map[0] != 'Z' || map[page] != 'Z' ||
	    map[2 * page] != 'D' || map[3 * page] != 'B')
		return (12);
	priv = (char *)call(9, 0, page, 1, 2, fd, 0);
	if ((long)priv < 0 || remap((u64)priv, page, 0, 1, 0) != -22 ||
	    priv[0] != 'Z')
		return (13);
	if (remap((u64)(map + 3 * page), page, 0, 1, 0x10000) != 0 ||
	    map[3 * page] != 'B')
		return (15);
	if (call(11, (long)priv, page, 0, 0, 0, 0) != 0 ||
	    call(11, (long)map, 4 * page, 0, 0, 0, 0) != 0 ||
	    call(3, fd, 0, 0, 0, 0, 0) != 0 ||
	    call(87, (long)path, 0, 0, 0, 0, 0) != 0)
		return (14);
	return (0);
}

/* Adjacent mappings, fork inheritance and protection changes. */
static int
test_edges(void)
{
	char *map;
	char value;
	long fd, pid;
	int i, status;

	fd = call(257, -100, (long)path, 0x242, 0600, 0, 0);
	if (fd < 0 || call(77, fd, 4 * page, 0, 0, 0, 0) != 0)
		return (16);
	for (i = 0; i < 4; i++) {
		value = 'A' + i;
		if (call(18, fd, (long)&value, 1, i * page, 0, 0) != 1)
			return (17);
	}
	map = (char *)call(9, 0, 2 * page, 3, 1, fd, 0);
	if ((long)map < 0 ||
	    call(9, (long)(map + page), page, 3, 0x11, fd,
	    3 * page) != (long)(map + page) ||
	    map[0] != 'A' || map[page] != 'D')
		return (18);
	if (remap((u64)map, 2 * page, 0, 1, 0) != 0 ||
	    map[0] != 'B' || map[page] != 'C')
		return (19);
	pid = call(57, 0, 0, 0, 0, 0, 0);
	if (pid < 0)
		return (20);
	if (pid == 0) {
		call(60, map[0] == 'B' && map[page] == 'C' ? 0 : 1,
		    0, 0, 0, 0, 0);
		__builtin_unreachable();
	}
	if (call(61, pid, (long)&status, 0, 0, 0, 0) != pid || status != 0)
		return (21);
	if (call(10, (long)map, page, 1, 0, 0, 0) != 0 ||
	    remap((u64)map, page, 0, 0, 0) != 0 || map[0] != 'A' ||
	    call(10, (long)map, page, 3, 0, 0, 0) != 0)
		return (22);
	map[0] = 'Q';
	if (call(9, (long)(map + page), page, 3, 0x31, -1,
	    0) != (long)(map + page) || map[page] != 0 ||
	    remap((u64)map, 2 * page, 0, 0, 0) != -22 ||
	    map[0] != 'Q' || map[page] != 0)
		return (23);
	if (call(11, (long)map, 2 * page, 0, 0, 0, 0) != 0 ||
	    call(3, fd, 0, 0, 0, 0, 0) != 0 ||
	    call(87, (long)path, 0, 0, 0, 0, 0) != 0)
		return (24);
	return (0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	int rc;

	rc = test();
	if (rc == 0)
		rc = test_edges();
	call(60, rc, 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
