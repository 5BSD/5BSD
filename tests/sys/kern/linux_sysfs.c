/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux amd64 sysfs(2) enumeration and error-order regression. */
typedef unsigned long word;
#define SYS_SYSFS 139
static long
raw(long n, word a, word b, word c)
{
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c) : "rcx", "r11", "memory");
	return (ret);
}
static long
sysfs(long op, word a, word b)
{
	return (raw(SYS_SYSFS, op, a, b));
}
static int
same(const char *a, const char *b)
{
	while (*a == *b && *a != 0) {
		a++;
		b++;
	}
	return (*a == *b);
}
static char long_name[4096];
static int
test(void)
{
	const char *required[] = { "zfs", "tmpfs" };
	char name[64];
	long n, index;
	int i, j;

	n = sysfs(3, 1, 1);
	if (n < 2 || n > 64 || sysfs(3, 0, 0) != n)
		return (1);
	for (i = 0; i < 2; i++) {
		index = sysfs(1, (word)required[i], 1);
		if (index < 0 || index >= n ||
		    sysfs(2, index, (word)name) != 0 ||
		    !same(name, required[i]))
			return (2 + i);
	}
	for (i = 0; i < n; i++) {
		for (j = 0; j < (int)sizeof(name); j++)
			name[j] = (char)0xa5;
		if (sysfs(2, i, (word)name) != 0)
			return (4);
		for (j = 0; j < (int)sizeof(name) && name[j] != 0; j++)
			;
		if (j == (int)sizeof(name) || sysfs(1, (word)name, 0) != i)
			return (5);
	}
	if (sysfs(0, 1, 1) != -22 || sysfs(4, 1, 1) != -22 ||
	    sysfs(-1, 1, 1) != -22)
		return (6);
	if (sysfs(1, (word)"no_such_fs", 0) != -22 ||
	    sysfs(1, (word)"", 0) != -22)
		return (7);
	if (sysfs(1, 1, 0) != -14 || sysfs(1, 0, 0) != -14)
		return (8);
	if (sysfs(2, n, (word)name) != -22 ||
	    sysfs(2, (word)-1, (word)name) != -22 ||
	    sysfs(2, n, 1) != -22)
		return (9);
	if (sysfs(2, 0, 1) != -14 || sysfs(2, 0, 0) != -14)
		return (10);
	for (i = 0; i < (int)sizeof(long_name); i++)
		long_name[i] = 'x';
	if (sysfs(1, (word)long_name, 0) != -36)
		return (11);
	return (0);
}
__attribute__((force_align_arg_pointer)) void _start(void)
{
	int result = test();
	raw(60, result, 0, 0);
	__builtin_unreachable();
}
