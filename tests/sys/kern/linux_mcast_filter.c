/* SPDX-License-Identifier: BSD-2-Clause */
/* Source-filter ABI and delivery probe: disposable Linux/FreeBSD guests only.
 */
#include "linux_test.h"
struct ipfilter {
	u32 group, interface, mode, count, source[8];
};
struct groupfilter {
	u32 index, pad;
	u8 group[128];
	u32 mode, count;
	u8 source[8][128];
};
union filter {
	struct ipfilter ip;
	struct groupfilter group;
	u8 bytes[2048];
};
static union filter f;
static int form, fd, index, level, option, head, elem;
static u32 loop = 0x0100007f, group = 0x090009ef;
static const char *ifname;
static void
number(long n)
{
	char b[32];
	int i = 0;
	if (n < 0) {
		wr1("-");
		n = -n;
	}
	do {
		b[i++] = '0' + n % 10;
		n /= 10;
	} while (n);
	while (i)
		sys3(SYS_write, 1, &b[--i], 1);
}
static void
address(u8 *p, int family, int source)
{
	xmemset(p, 0, 128);
	*(u16 *)p = family;
	if (family == 2)
		*(u32 *)(p + 4) = source ? loop + (source - 1) * 0x01000000U :
					   group;
	else if (source) {
		p[8] = 0xfd;
		p[23] = source;
	} else {
		p[8] = 0xff;
		p[9] = 5;
		p[22] = 0x12;
		p[23] = 0x34;
	}
}
static void
init(u32 mode, u32 count)
{
	xmemset(&f, 0, sizeof(f));
	if (form == 0) {
		f.ip.group = group;
		f.ip.interface = loop;
		f.ip.mode = mode;
		f.ip.count = count;
		for (int i = 0; i < 8; i++)
			f.ip.source[i] = loop + i * 0x01000000U;
	} else {
		f.group.index = index;
		address(f.group.group, form == 2 ? 10 : 2, 0);
		f.group.mode = mode;
		f.group.count = count;
		for (int i = 0; i < 8; i++)
			address(f.group.source[i], form == 2 ? 10 : 2, i + 1);
	}
}
static u32
count(void)
{
	return form ? f.group.count : f.ip.count;
}
static u32
mode(void)
{
	return form ? f.group.mode : f.ip.mode;
}
static long
set(void *v, int len)
{
	return sys5(SYS_setsockopt, fd, level, option, v, len);
}
static long
get(void *v, int *len)
{
	return sys5(SYS_getsockopt, fd, level, option, v, len);
}
static int
join(void)
{
	if (form == 2) {
		u8 req[20] = { 0 };
		u8 a[128];
		address(a, 10, 0);
		xmemcpy(req, a + 8, 16);
		*(u32 *)(req + 16) = index;
		return sys5(SYS_setsockopt, fd, 41, 20, req, 20);
	}
	u32 req[3] = { group, loop, (u32)index };
	return sys5(SYS_setsockopt, fd, 0, 35, req, 12);
}
static int
openfd(void)
{
	fd = sys3(SYS_socket, form == 2 ? 10 : 2, 2, 0);
	if (fd < 0)
		return 90;
	char req[40] = { 0 };
	for (int i = 0; ifname[i] && i < 15; i++)
		req[i] = ifname[i];
	if (sys3(SYS_ioctl, fd, 0x8933, req))
		return 91;
	index = *(int *)(req + 16);
	level = form == 2 ? 41 : 0;
	option = form ? 48 : 41;
	head = form ? 144 : 16;
	elem = form ? 128 : 4;
	return 0;
}
#define C(x, n)                            \
	do {                               \
		long result = (x);         \
		if (!result) {             \
			wr1("FAIL form="); \
			number(form);      \
			wr1(" check=");    \
			number(n);         \
			wr1("\n");         \
			return n;          \
		}                          \
	} while (0)
static long delta(int, int, int);
static int
delivery(int transition)
{
	u8 bindaddr[128] = { 0 }, dst[128], src[128];
	int af = form == 2 ? 10 : 2, alen = form == 2 ? 28 : 16;
	*(u16 *)bindaddr = af;
	*(u16 *)(bindaddr + 2) = 0x7856;
	C(sys3(SYS_bind, fd, bindaddr, alen) == 0, 80);
	address(dst, af, 0);
	*(u16 *)(dst + 2) = 0x7856;
	if (form == 2)
		*(u32 *)(dst + 24) = index;
	int tx = sys3(SYS_socket, af, 2, 0);
	C(tx >= 0, 81);
	address(src, af, 1);
	C(sys3(SYS_bind, tx, src, alen) == 0, 82);
	if (form == 2)
		C(sys5(SYS_setsockopt, tx, 41, 17, &index, 4) == 0, 83);
	else
		C(sys5(SYS_setsockopt, tx, 0, 32, &loop, 4) == 0, 84);
	for (int step = 0; step < 5; step++) {
		init(step < 2 ? 1 : 0, step == 4 ? 0 : 1);
		if (step == 1 || step == 3) {
			if (form)
				address(f.group.source[0], af, 2);
			else
				f.ip.source[0] = loop + 0x01000000U;
		}
		if (transition && step < 2) {
			/* Change from a full empty EXCLUDE to a source INCLUDE. */
			init(0, 0);
			C(set(&f, head) == 0, 172);
			C(delta(1, 1, step + 1) == 0, 173);
		} else
		C(set(&f, head + (step == 4 ? 0 : elem)) == 0, 85);
		char payload = 'a' + step, out = 0;
		C(sys6(SYS_sendto, tx, &payload, 1, 0, dst, alen) == 1, 86);
		struct {
			int fd;
			short events, revents;
		} pollfd = { fd, 1, 0 };
		long ready = sys3(SYS_poll, &pollfd, 1, 250);
		int allow = (step == 0 || step == 3 || step == 4);
		if (allow) {
			C(ready == 1, 87);
			C(sys6(SYS_recvfrom, fd, &out, 1, 0, 0, 0) == 1 &&
				out == payload,
			    88);
		} else
			C(ready == 0, 89);
	}
	sys1(SYS_close, tx);
	return 0;
}
/* Source add/remove, through the legacy and RFC 3678 entry points. */
static long
delta(int add, int include, int source)
{
	if (!form) {
		u32 req[3] = { group, loop, loop + (source - 1) * 0x01000000U };
		int opt = include ? (add ? 39 : 40) : (add ? 38 : 37);
		return sys5(SYS_setsockopt, fd, 0, opt, req, sizeof(req));
	}
	struct { u32 index, pad; u8 group[128], source[128]; } req;
	xmemset(&req, 0, sizeof(req));
	req.index = index;
	address(req.group, form == 2 ? 10 : 2, 0);
	address(req.source, form == 2 ? 10 : 2, source);
	int opt = include ? (add ? 46 : 47) : (add ? 43 : 44);
	return sys5(SYS_setsockopt, fd, level, opt, &req, sizeof(req));
}
static int
transitions(void)
{
	for (int round = 0; round < 32; round++) {
		/* Full empty replacement releases the old source-list identity. */
		init(0, 0);
		C(set(&f, head) == 0, 160);
		C(delta(1, 1, 1) == 0, 161);
		init(99, 8); int len = sizeof(f);
		C(get(&f, &len) == 0 && mode() == 1 && count() == 1, 162);
		C(delta(1, 0, 2) == -EINVAL, 163);
		C(delta(1, 1, 1) == -99, 164);
		C(delta(0, 1, 1) == 0, 165);
		C(join() == 0, 166); /* Removing the last INCLUDE source left. */
		C(delta(1, 0, 1) == 0, 167);
		C(delta(1, 1, 2) == -EINVAL, 168);
		C(delta(0, 0, 1) == 0, 169);
		/* An allocated but empty delta list still prohibits a mode change. */
		C(delta(1, 1, 2) == -EINVAL, 170);
		init(99, 8);len = sizeof(f);
		C(get(&f, &len) == 0 && mode() == 0 && count() == 0, 171);
	}
	return 0;
}
static int
mixed(void)
{
	for (int include = 0; include < 2; include++) {
		/* Unsorted full-state input, including a repeated source. */
		init(include, 3);
		if (form) {
			address(f.group.source[0], form == 2 ? 10 : 2, 2);
			address(f.group.source[1], form == 2 ? 10 : 2, 1);
			address(f.group.source[2], form == 2 ? 10 : 2, 2);
		} else {
			f.ip.source[0] = f.ip.source[2] = loop + 0x01000000U;
			f.ip.source[1] = loop;
		}
		C(set(&f, head + 3 * elem) == 0, 130);
		C(delta(1, include, 3) == 0, 131);
		C(delta(1, include, 3) == -99, 132);
		C(delta(0, include, 4) == -99, 133);
		for (int step = 0; step < 3; step++) {
			if (step)
				C(delta(0, include, 2) == 0, 134);
			init(99, 8);
			int len = sizeof(f);
			C(get(&f, &len) == 0 && count() == (u32)(4 - step) &&
			    mode() == (u32)include, 135);
			int values[3][4] = { {2, 1, 2, 3}, {1, 2, 3}, {1, 3} };
			for (int j = 0; j < 4 - step; j++) {
				u8 expected[128];
				if (form)
					address(expected, form == 2 ? 10 : 2, values[step][j]);
				else
					*(u32 *)expected = loop + (values[step][j] - 1) * 0x01000000U;
				C(xmemcmp(f.bytes + head + j * elem, expected, elem) == 0, 136);
			}
		}
		C(delta(0, include, 2) == -99, 137);
	}
	return 0;
}
static int
mixed_delivery(void)
{
	u8 bindaddr[128] = {0}, dst[128], src[128];
	int af = form == 2 ? 10 : 2, alen = form == 2 ? 28 : 16;
	*(u16 *)bindaddr = af;
	*(u16 *)(bindaddr + 2) = 0x7956;
	C(sys3(SYS_bind, fd, bindaddr, alen) == 0, 140);
	address(dst, af, 0);
	*(u16 *)(dst + 2) = 0x7956;
	if (form == 2) *(u32 *)(dst + 24) = index;
	int tx = sys3(SYS_socket, af, 2, 0);
	C(tx >= 0, 141);
	address(src, af, 1);
	C(sys3(SYS_bind, tx, src, alen) == 0, 142);
	C(sys5(SYS_setsockopt, tx, form == 2 ? 41 : 0,
	    form == 2 ? 17 : 32, form == 2 ? (void *)&index : (void *)&loop, 4) == 0, 143);
	for (int include = 0; include < 2; include++) {
		init(include, 2);
		xmemcpy(f.bytes + head + elem, f.bytes + head, elem);
		C(set(&f, head + 2 * elem) == 0, 144);
		for (int step = 0; step < 3; step++) {
			if (step) C(delta(0, include, 1) == 0, 145);
			char payload = 'a' + step, out;
			C(sys6(SYS_sendto, tx, &payload, 1, 0, dst, alen) == 1, 146);
			struct { int fd; short events, revents; } pollfd = { fd, 1, 0 };
			long ready = sys3(SYS_poll, &pollfd, 1, 250);
			int allow = include ? step != 2 : step == 2;
			C(ready == allow, 147);
			if (allow) C(sys6(SYS_recvfrom, fd, &out, 1, 0, 0, 0) == 1 && out == payload, 148);
		}
	}
	init(99, 8); int len = sizeof(f);
	C(get(&f, &len) == -99, 149);
	C(join() == 0, 150);
	sys1(SYS_close, tx);
	return 0;
}
static int
mixed_churn(void)
{
	init(0, 2);
	xmemcpy(f.bytes + head + elem, f.bytes + head, elem);
	C(set(&f, head + 2 * elem) == 0, 151);
	long pid = fork_process();
	C(pid >= 0, 152);
	for (int i = 0; i < 200; i++) {
		C(delta(1, 0, pid ? 3 : 4) == 0, 153);
		init(99, 8); int len = sizeof(f);
		C(get(&f, &len) == 0 && mode() == 0 && count() >= 3 && count() <= 4, 154);
		C(delta(0, 0, pid ? 3 : 4) == 0, 155);
	}
	if (!pid) sys1(SYS_exit, 0);
	int st;
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0, 156);
	init(99, 8); int len = sizeof(f);
	C(get(&f, &len) == 0 && count() == 2, 157);
	return 0;
}
static int
run(const char *name)
{
	int len, st;
	C(join() == 0, 1);
	init(1, 2);
	C(set(&f, head + 2 * elem) == 0, 2);
	if (xstreq(name, "transition_delivery"))
		return delivery(1);
	if (xstreq(name, "transitions"))
		return transitions();
	if (xstreq(name, "mixed_delivery"))
		return mixed_delivery();
	if (xstreq(name, "mixed_churn"))
		return mixed_churn();
	if (xstreq(name, "mixed"))
		return mixed();
	if (xstreq(name, "delivery"))
		return delivery(0);
	if (xstreq(name, "roundtrip") || xstreq(name, "dualstack")) {
		init(99, 8);
		len = sizeof(f);
		C(get(&f, &len) == 0, 3);
		C(count() == 2 && mode() == 1 && len == head + 2 * elem, 4);
		if (!form)
			C(f.ip.source[0] == loop &&
				f.ip.source[1] == loop + 0x01000000U,
			    5);
		else {
			u8 a[128];
			address(a, form == 2 ? 10 : 2, 1);
			C(xmemcmp(f.group.source[0], a, 128) == 0, 6);
			address(a, form == 2 ? 10 : 2, 2);
			C(xmemcmp(f.group.source[1], a, 128) == 0, 7);
		}
	} else if (xstreq(name, "replace")) {
		init(0, 0);
		C(set(&f, head) == 0, 10);
		init(99, 8);
		len = sizeof(f);
		C(get(&f, &len) == 0 && count() == 0 && mode() == 0, 11);
		init(0, 1);
		C(set(&f, head + elem) == 0, 12);
		init(99, 8);
		len = sizeof(f);
		C(get(&f, &len) == 0 && count() == 1 && mode() == 0, 13);
		init(1, 2);
		C(set(&f, head + 2 * elem) == 0, 14);
	} else if (xstreq(name, "leave")) {
		init(1, 0);
		C(set(&f, head) == 0, 20);
		init(99, 1);
		len = sizeof(f);
		C(get(&f, &len) == -99, 21);
		init(0, 0);
		C(set(&f, head) == -22, 22);
		C(join() == 0, 23);
	} else if (xstreq(name, "lengths")) {
		init(99, 0);
		len = head;
		C(get(&f, &len) == 0 && len == head && count() == 2, 30);
		init(99, 1);
		len = head;
		C(get(&f, &len) == 0 && len == head + elem && count() == 2, 31);
		init(99, 8);
		xmemset(f.bytes + head + 2 * elem, 0x5a,
		    sizeof(f) - head - 2 * elem);
		len = sizeof(f);
		C(get(&f, &len) == 0 && len == head + 2 * elem, 32);
		C(f.bytes[len] == 0x5a, 33);
		init(1, 2);
		C(set(&f, head + elem) == -22, 34);
		C(set(&f, head - 1) == -22, 35);
		len = head - 1;
		C(get(&f, &len) == -22, 36);
		len = -1;
		C(get(&f, &len) == -22, 37);
	} else if (xstreq(name, "invalid")) {
		init(2, 0);
		C(set(&f, head) == -22, 40);
		init(0, 0);
		if (form)
			f.group.group[form == 2 ? 8 : 4] = 1;
		else
			f.ip.group = loop;
		C(set(&f, head) == -22, 41);
		init(0, 0);
		if (form)
			f.group.index = 0x7fffffff;
		else
			f.ip.interface = 0xdeadbeef;
		C(set(&f, head) == -19, 42);
		init(0, 0);
		if (form)
			f.group.count = 0xffffffff;
		else
			f.ip.count = 0xffffffff;
		C(set(&f, head) == -105, 43);
		init(99, 8);
		len = sizeof(f);
		C(get(&f, &len) == 0 && count() == 2 && mode() == 1, 44);
	} else if (xstreq(name, "faults")) {
		C(set(0, head) == -14, 50);
		init(99, 1);
		C(get(&f, 0) == -14, 51);
		len = head;
		C(get(0, &len) == -14, 52);
		char *p = (char *)sys6(SYS_mmap, 0, 8192, 3, 0x22, -1, 0);
		C((long)p > 0, 53);
		init(0, 2);
		xmemcpy(p + 4096 - head, &f, head);
		C(sys3(SYS_mprotect, p + 4096, 4096, 0) == 0, 54);
		C(set(p + 4096 - head, head + 2 * elem) == -14, 55);
		init(99, 8);
		len = sizeof(f);
		C(get(&f, &len) == 0 && count() == 2 && mode() == 1, 56);
		init(0, 0);
		xmemcpy(p + 4096 - head, &f, head);
		C(set(p + 4096 - head, head + 1) == -14, 57);
		init(99, 1);
		xmemcpy(p + 4096 - head, &f, head);
		len = head;
		C(get(p + 4096 - head, &len) == -14, 58);
		C(len == (form ? head : head + elem), 59);
		sys2(SYS_munmap, p, 8192);
	} else if (xstreq(name, "lifetime")) {
		int d = sys1(SYS_dup, fd);
		C(d >= 0, 60);
		sys1(SYS_close, fd);
		fd = d;
		long child = fork_process();
		C(child >= 0, 61);
		if (!child) {
			init(0, 1);
			sys1(SYS_exit, set(&f, head + elem) ? 1 : 0);
		}
		C(sys4(SYS_wait4, child, &st, 0, 0) == child && st == 0, 62);
		init(99, 8);
		len = sizeof(f);
		C(get(&f, &len) == 0 && count() == 1 && mode() == 0, 63);
	} else if (xstreq(name, "duplicates")) {
		init(1, 2);
		if (form)
			xmemcpy(f.group.source[1], f.group.source[0], 128);
		else
			f.ip.source[1] = f.ip.source[0];
		C(set(&f, head + 2 * elem) == 0, 70);
		init(99, 8);
		len = sizeof(f);
		C(get(&f, &len) == 0 && count() == 2 && len == head + 2 * elem,
		    71);
		C(xmemcmp(f.bytes + head, f.bytes + head + elem, elem) == 0,
		    72);
		init(1, 2);
		u8 tmp[128];
		xmemcpy(tmp, f.bytes + head, elem);
		xmemcpy(f.bytes + head, f.bytes + head + elem, elem);
		xmemcpy(f.bytes + head + elem, tmp, elem);
		C(set(&f, head + 2 * elem) == 0, 73);
		union filter expected;
		xmemcpy(&expected, &f, sizeof(f));
		init(99, 8);
		len = sizeof(f);
		C(get(&f, &len) == 0 && count() == 2, 74);
		C(xmemcmp(f.bytes + head, expected.bytes + head, 2 * elem) == 0,
		    75);
	} else if (xstreq(name, "churn")) {
		long pid = fork_process();
		C(pid >= 0, 120);
		for (int i = 0; i < 200; i++) {
			init(i % 2, i % 3 + 1);
			C(set(&f, head + (i % 3 + 1) * elem) == 0, 121);
			init(99, 8);
			len = sizeof(f);
			C(get(&f, &len) == 0 && count() >= 1 && count() <= 3 &&
				mode() <= 1,
			    122);
		}
		if (!pid)
			sys1(SYS_exit, 0);
		C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0, 123);
	} else if (xstreq(name, "interfaces")) {
		init(0, 1);
		if (form)
			f.group.index = 0;
		else
			f.ip.interface = 0;
		C(set(&f, head + elem) == (form == 2 ? -22 : 0), 110);
		init(99, 8);
		if (form)
			f.group.index = 0;
		else
			f.ip.interface = 0;
		len = sizeof(f);
		C(get(&f, &len) == (form ? -99 : 0), 111);
		if (form == 2) {
			init(1, 0);
			f.group.index = 0;
			C(set(&f, head) == 0, 112);
		}
	} else
		return 88;
	return 0;
}
static int
test(int argc, char **argv, char **envp)
{
	(void)envp;
	if (argc == 3 && xstreq(argv[1], "caps")) {
		int m = argv[2][0] - '0';
		fd = 3;
		form = 0;
		head = 16;
		elem = 4;
		level = 0;
		option = 41;
		loop = 0x0f02000a;
		init(1, 2);
		long setrc = set(&f, 24);
		int len = sizeof(f);
		init(99, 8);
		long getrc = get(&f, &len);
		long rc = (setrc != (m == 1 || m == 3 ? -1 : 0) ||
		    getrc != (m == 2 || m == 3 ? -1 : 0));
		__asm__ volatile("int3" : "+a"(rc)::"memory");
		return 0;
	}
	if (argc < 3)
		return 89;
	ifname = argv[2];
	if (!xstreq(ifname, "lo") && !xstreq(ifname, "lo0"))
		loop = 0x0f02000a;
	if (argc > 3 && xstreq(argv[3], "unprivileged")) {
		if (sys1(106, 60001) || sys1(105, 60001))
			return 87;
	}
	for (form = 0; form < 3; form++) {
		int r = openfd();
		if (!r && xstreq(argv[1], "dualstack") && form < 2) {
			sys1(SYS_close, fd);
			fd = sys3(SYS_socket, 10, 2, 0);
			if (fd < 0)
				r = 93;
		}
		if (!r)
			r = run(argv[1]);
		sys1(SYS_close, fd);
		if (r)
			return r;
	}
	return 0;
}
