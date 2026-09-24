/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 binary UNIX-domain names. Disposable VM only. */
#include "linux_test.h"
#define EADDRINUSE 98
struct address {
	unsigned short family;
	unsigned char name[108];
};
static int same(const void* a, const void* b, unsigned n)
{
	const unsigned char *x = a, *y = b;
	for (unsigned i = 0; i < n; i++)
		if (x[i] != y[i])
			return 0;
	return 1;
}
static void name(struct address* a, unsigned tag)
{
	xmemset(a, 0, sizeof(*a));
	a->family = 1;
	unsigned long pid = sys0(SYS_getpid);
	for (unsigned i = 1; i < 108; i++)
		a->name[i] = (unsigned char)(i * 17 + tag);
	for (unsigned i = 0; i < 4; i++)
		a->name[i + 1] = pid >> (i * 8);
	a->name[5] = tag;
	a->name[6] = 0;
	a->name[7] = 0;
}
static int endpoint(int type, unsigned size)
{
	struct address a, b, c;
	name(&a, type + size);
	long server = sys3(SYS_socket, 1, type, 0),
	     other = sys3(SYS_socket, 1, type, 0);
	if (server < 0 || other < 0)
		return 1;
	if (sys3(SYS_bind, server, &a, size))
		return 2;
	if (sys3(SYS_bind, other, &a, size) != -EADDRINUSE)
		return 3;
	unsigned n = sizeof(b);
	if (sys3(SYS_getsockname, server, &b, &n) || n != size
	    || !same(&a, &b, size))
		return 4;
	n = 0;
	if (sys3(SYS_getsockname, server, 0, &n) || n != size)
		return 5;
	n = 1;
	b.family = 0xffff;
	if (sys3(SYS_getsockname, server, &b, &n) || n != size
	    || ((unsigned char*)&b)[0] != 1 || ((unsigned char*)&b)[1] != 255)
		return 6;
	if (type != 2 && sys2(SYS_listen, server, 4))
		return 7;
	if (sys3(SYS_connect, other, &a, size))
		return 8;
	long peer = type == 2 ? server : sys3(SYS_accept, server, 0, 0);
	if (peer < 0)
		return 9;
	n = sizeof(c);
	if (sys3(SYS_getpeername, other, &c, &n) || n != size
	    || !same(&a, &c, size))
		return 10;
	char value = 'x', got = 0;
	if (sys3(SYS_write, other, &value, 1) != 1
	    || sys3(SYS_read, peer, &got, 1) != 1 || got != value)
		return 11;
	if (type != 2)
		sys1(SYS_close, peer);
	sys1(SYS_close, other);
	long held = sys1(SYS_dup, server);
	if (held < 0)
		return 12;
	sys1(SYS_close, server);
	other = sys3(SYS_socket, 1, type, 0);
	if (sys3(SYS_bind, other, &a, size) != -EADDRINUSE)
		return 13;
	sys1(SYS_close, held);
	if (sys3(SYS_bind, other, &a, size))
		return 14;
	sys1(SYS_close, other);
	return 0;
}
static int binary(void)
{
	struct address a, b;
	name(&a, 91);
	b = a;
	b.name[7] = 1;
	long first = sys3(SYS_socket, 1, 2, 0),
	     second = sys3(SYS_socket, 1, 2, 0);
	if (first < 0 || second < 0 || sys3(SYS_bind, first, &a, 10)
	    || sys3(SYS_bind, second, &b, 10))
		return 1;
	sys1(SYS_close, second);
	second = sys3(SYS_socket, 1, 2, 0);
	if (sys3(SYS_bind, second, &a, 11))
		return 2;
	sys1(SYS_close, first);
	sys1(SYS_close, second);
	return 0;
}
static int autobind(void)
{
	struct address a, b;
	name(&a, 88);
	long s = sys3(SYS_socket, 1, 2, 0), t = sys3(SYS_socket, 1, 2, 0);
	if (s < 0 || t < 0 || sys3(SYS_bind, s, &a, 2)
	    || sys3(SYS_bind, t, &a, 2))
		return 1;
	unsigned n = sizeof(a), m = sizeof(b);
	if (sys3(SYS_getsockname, s, &a, &n) || sys3(SYS_getsockname, t, &b, &m)
	    || n != 8 || m != 8 || a.name[0] || b.name[0] || same(&a, &b, n))
		return 2;
	if (sys3(SYS_connect, t, &a, n))
		return 3;
	char c = 'q', r = 0;
	if (sys3(SYS_write, t, &c, 1) != 1 || sys3(SYS_read, s, &r, 1) != 1
	    || r != c)
		return 4;
	sys1(SYS_close, s);
	sys1(SYS_close, t);
	return 0;
}
static int test(int argc, char** argv, char** envp)
{
	if (argc > 2 && xstreq(argv[2], "unprivileged")) {
		if (sys1(106, 65534) || sys1(105, 65534))
			return 99;
		char* next[] = { argv[0], argv[1], "unprivileged-exec", 0 };
		sys3(SYS_execve, argv[0], next, envp);
		return 98;
	}
	if (argc < 2)
		return 97;
	if (xstreq(argv[1], "binary"))
		return binary();
	if (xstreq(argv[1], "autobind"))
		return autobind();
	int type = xstreq(argv[1], "stream") ? 1
	    : xstreq(argv[1], "dgram")	     ? 2
	    : xstreq(argv[1], "seqpacket")   ? 5
					     : 0;
	if (!type)
		return 96;
	unsigned sizes[] = { 8, 16, 106, 110 };
	for (unsigned i = 0; i < 4; i++) {
		int r = endpoint(type, sizes[i]);
		if (r)
			return r + i * 20;
	}
	return 0;
}
