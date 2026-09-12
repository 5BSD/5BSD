/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for the socket option translation:
 * no Linux libc or sysroot required.  Exit status identifies the failed
 * check.  Every option is named by its Linux number.
 */
typedef unsigned long size_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef long int64_t;

struct iovec { void *base; size_t len; };
struct msghdr {
	void *name; int namelen; int pad0;
	struct iovec *iov; size_t iovlen;
	void *control; size_t controllen;
	int flags; int pad1;
};
struct cmsghdr { size_t len; int level; int type; };
struct sockaddr_in { uint16_t family; uint16_t port; uint32_t addr;
	uint8_t zero[8]; };
struct sockaddr_in6 { uint16_t family; uint16_t port; uint32_t flowinfo;
	uint8_t addr[16]; uint32_t scope; };
/* Linux struct sockaddr_storage: 16-bit family, 8-byte aligned. */
struct sockaddr_storage { uint16_t family; char data[126]; }
    __attribute__((aligned(8)));
/* 4 bytes of padding follow gr_interface on x86_64: 136 bytes total. */
struct group_req { uint32_t gr_interface; struct sockaddr_storage gr_group; };
/* Linux struct ip_mreq_source: multiaddr, INTERFACE, sourceaddr. */
struct ip_mreq_source { uint32_t multiaddr; uint32_t interface;
	uint32_t sourceaddr; };
struct in_pktinfo { int ifindex; uint32_t spec_dst; uint32_t addr; };
struct sock_timeval { int64_t sec; int64_t usec; };
struct ifreq { char name[16]; union { int ifindex; char pad[24]; } u; };

/* Linux constants. */
#define	AF_UNIX		1
#define	AF_INET		2
#define	AF_INET6	10
#define	SOCK_STREAM	1
#define	SOCK_DGRAM	2
#define	SOL_SOCKET	1
#define	SOL_IP		0
#define	SOL_TCP		6
#define	SOL_IPV6	41
#define	EPERM		1
#define	ENOENT		2
#define	EBADF		9
#define	EINVAL		22
#define	EDOM		33
#define	ENOPROTOOPT	92
#define	EADDRNOTAVAIL	99

#define	SYS_read	0
#define	SYS_write	1
#define	SYS_close	3
#define	SYS_ioctl	16
#define	SYS_pipe	22
#define	SYS_socket	41
#define	SYS_connect	42
#define	SYS_sendto	44
#define	SYS_recvfrom	45
#define	SYS_sendmsg	46
#define	SYS_recvmsg	47
#define	SYS_bind	49
#define	SYS_listen	50
#define	SYS_getsockname	51
#define	SYS_socketpair	53
#define	SYS_setsockopt	54
#define	SYS_getsockopt	55
#define	SYS_exit	60
#define	SYS_getuid	102
#define	SYS_accept4	288

#define	SIOCGIFINDEX	0x8933

static long
call(long nr, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (result);
}

static long
setopt(int s, int level, int name, const void *val, int len)
{
	return (call(SYS_setsockopt, s, level, name, (long)val, len, 0));
}

static long
getopt(int s, int level, int name, void *val, int *len)
{
	return (call(SYS_getsockopt, s, level, name, (long)val, (long)len, 0));
}

static long
setint(int s, int level, int name, int val)
{
	return (setopt(s, level, name, &val, sizeof(val)));
}

/* Returns the value, or -errno; -1000 - len if the reported len is odd. */
static long
getint(int s, int level, int name)
{
	int val = -1, len = sizeof(val);
	long r;

	r = getopt(s, level, name, &val, &len);
	if (r < 0)
		return (r);
	if (len != sizeof(val))
		return (-1000 - len);
	return (val);
}

static uint32_t
htonl(uint32_t v)
{
	return (__builtin_bswap32(v));
}

static void
mkzero(void *p, size_t n)
{
	char *c = p;

	while (n-- > 0)
		*c++ = 0;
}

static int
lo_ifindex(void)
{
	struct ifreq ifr;
	long s;
	int idx = -1;

	s = call(SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
	if (s < 0)
		return (-1);
	mkzero(&ifr, sizeof(ifr));
	__builtin_memcpy(ifr.name, "lo0", 4);
	if (call(SYS_ioctl, s, SIOCGIFINDEX, (long)&ifr, 0, 0, 0) == 0)
		idx = ifr.u.ifindex;
	else {
		__builtin_memcpy(ifr.name, "lo", 3);
		if (call(SYS_ioctl, s, SIOCGIFINDEX, (long)&ifr, 0, 0, 0) == 0)
			idx = ifr.u.ifindex;
	}
	(void)call(SYS_close, s, 0, 0, 0, 0, 0);
	return (idx);
}

/* Bind s to 127.0.0.1:0 and fill in the address it got. */
static int
bind_lo(int s, struct sockaddr_in *sin)
{
	int len = sizeof(*sin);

	mkzero(sin, sizeof(*sin));
	sin->family = AF_INET;
	sin->addr = htonl(0x7f000001);
	if (call(SYS_bind, s, (long)sin, sizeof(*sin), 0, 0, 0) != 0)
		return (-1);
	if (call(SYS_getsockname, s, (long)sin, (long)&len, 0, 0, 0) != 0)
		return (-1);
	return (0);
}

/*
 * Send one byte from s to itself with the given control message (may be
 * NULL) and receive it back with a control buffer; returns the number of
 * bytes of control data received or -errno.
 */
static long
udp_roundtrip(int s, const struct sockaddr_in *sin, const void *scmsg,
    size_t scmsglen, char *cbuf, size_t cbuflen)
{
	struct msghdr mh;
	struct iovec iov;
	char b = 'x';
	long r;

	iov.base = &b;
	iov.len = 1;
	mkzero(&mh, sizeof(mh));
	mh.name = (void *)sin;
	mh.namelen = sizeof(*sin);
	mh.iov = &iov;
	mh.iovlen = 1;
	mh.control = (void *)scmsg;
	mh.controllen = scmsglen;
	r = call(SYS_sendmsg, s, (long)&mh, 0, 0, 0, 0);
	if (r != 1)
		return (r < 0 ? r : -1);
	mkzero(&mh, sizeof(mh));
	mh.iov = &iov;
	mh.iovlen = 1;
	mh.control = cbuf;
	mh.controllen = cbuflen;
	r = call(SYS_recvmsg, s, (long)&mh, 0, 0, 0, 0);
	if (r != 1)
		return (r < 0 ? r : -1);
	return (mh.controllen);
}

static int
test_udp(void)
{
	struct sockaddr_in sin;
	struct sock_timeval stv;
	struct group_req gr;
	struct ip_mreq_source ims;
	struct cmsghdr *cm;
	struct in_pktinfo *pki;
	char cbuf[128], scbuf[32];
	long u, r;
	int len, lo, v;

	u = call(SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
	if (u < 0) return (1);
	lo = lo_ifindex();
	if (lo <= 0) return (2);

	/* IP_MINTTL(21): set 10, read back 10. */
	if (setint(u, SOL_IP, 21, 10) != 0) return (3);
	if (getint(u, SOL_IP, 21) != 10) return (4);
	/* IP_TTL(2): set 77, read back 77. */
	if (setint(u, SOL_IP, 2, 77) != 0) return (5);
	if (getint(u, SOL_IP, 2) != 77) return (6);
	/* SO_TYPE(3) is SOCK_DGRAM, SO_ERROR(4) is 0 on a fresh socket. */
	if (getint(u, SOL_SOCKET, 3) != SOCK_DGRAM) return (7);
	if (getint(u, SOL_SOCKET, 4) != 0) return (8);
	/* SO_RCVBUF(8): Linux reports at least what was set. */
	if (setint(u, SOL_SOCKET, 8, 65536) != 0) return (9);
	if (getint(u, SOL_SOCKET, 8) < 65536) return (10);
	/* IP_PROTOCOL(52), getsockopt only: IPPROTO_UDP. */
	if (getint(u, SOL_IP, 52) != 17) return (11);
	/* IP_PROTOCOL cannot be set: ENOPROTOOPT. */
	if (setint(u, SOL_IP, 52, 17) != -ENOPROTOOPT) return (12);

	/* SO_RCVTIMEO_NEW(66): 64-bit tv_sec/tv_usec round trip. */
	stv.sec = 1;
	stv.usec = 500000;
	if (setopt(u, SOL_SOCKET, 66, &stv, sizeof(stv)) != 0) return (13);
	mkzero(&stv, sizeof(stv));
	len = sizeof(stv);
	if (getopt(u, SOL_SOCKET, 66, &stv, &len) != 0) return (14);
	if (len != 16 || stv.sec != 1 || stv.usec != 500000) return (15);
	/* tv_usec out of range is EDOM. */
	stv.usec = 1000000;
	if (setopt(u, SOL_SOCKET, 66, &stv, sizeof(stv)) != -EDOM)
		return (16);
	/* A short optlen is EINVAL. */
	stv.usec = 0;
	if (setopt(u, SOL_SOCKET, 66, &stv, 8) != -EINVAL) return (17);
	/* getsockopt copies min(optlen, 16) and reports what it copied. */
	stv.sec = stv.usec = -1;
	len = 8;
	if (getopt(u, SOL_SOCKET, 66, &stv, &len) != 0) return (18);
	if (len != 8 || stv.sec != 1 || stv.usec != -1) return (19);
	/* SO_SNDTIMEO_NEW(67): a negative tv_sec means "no timeout". */
	stv.sec = -1;
	stv.usec = 0;
	if (setopt(u, SOL_SOCKET, 67, &stv, sizeof(stv)) != 0) return (20);
	len = sizeof(stv);
	if (getopt(u, SOL_SOCKET, 67, &stv, &len) != 0) return (21);
	if (stv.sec != 0 || stv.usec != 0) return (22);

	/* MCAST_JOIN_GROUP(42) with the Linux group_req layout (136 bytes). */
	mkzero(&gr, sizeof(gr));
	gr.gr_interface = lo;
	sin.family = AF_INET;
	sin.port = 0;
	sin.addr = htonl(0xe00000fb);		/* 224.0.0.251 */
	__builtin_memcpy(&gr.gr_group, &sin, sizeof(sin));
	if (sizeof(gr) != 136) return (23);
	if (setopt(u, SOL_IP, 42, &gr, sizeof(gr)) != 0) return (24);
	/* MCAST_LEAVE_GROUP(45). */
	if (setopt(u, SOL_IP, 45, &gr, sizeof(gr)) != 0) return (25);
	/* Leaving a group not joined is EADDRNOTAVAIL. */
	if (setopt(u, SOL_IP, 45, &gr, sizeof(gr)) != -EADDRNOTAVAIL)
		return (26);
	/* A short group_req is EINVAL. */
	if (setopt(u, SOL_IP, 42, &gr, 100) != -EINVAL) return (27);

	/*
	 * IP_ADD_SOURCE_MEMBERSHIP(39) with the Linux member order: the
	 * interface (127.0.0.1) is the second member.  Passing the struct
	 * through in FreeBSD order would select 10.1.2.3 as the interface
	 * and fail with EADDRNOTAVAIL.
	 */
	ims.multiaddr = htonl(0xe8010101);	/* 232.1.1.1 */
	ims.interface = htonl(0x7f000001);
	ims.sourceaddr = htonl(0x0a010203);
	if (setopt(u, SOL_IP, 39, &ims, sizeof(ims)) != 0) return (28);
	/* IP_DROP_SOURCE_MEMBERSHIP(40). */
	if (setopt(u, SOL_IP, 40, &ims, sizeof(ims)) != 0) return (29);
	if (setopt(u, SOL_IP, 40, &ims, sizeof(ims)) != -EADDRNOTAVAIL)
		return (30);

	/* IP_MTU_DISCOVER(10): DO(2) sets DF and reads back as DO. */
	if (setint(u, SOL_IP, 10, 2) != 0) return (31);
	if (getint(u, SOL_IP, 10) != 2) return (32);
	/* DONT(0) clears it. */
	if (setint(u, SOL_IP, 10, 0) != 0) return (33);
	if (getint(u, SOL_IP, 10) != 0) return (34);
	/* OMIT(5) and INTERFACE(4) cannot be honoured: EINVAL. */
	if (setint(u, SOL_IP, 10, 5) != -EINVAL) return (35);
	if (setint(u, SOL_IP, 10, 4) != -EINVAL) return (36);
	/* Out of range is EINVAL on Linux as well. */
	if (setint(u, SOL_IP, 10, 99) != -EINVAL) return (37);

	/* IP_MULTICAST_ALL(49): only the FreeBSD behaviour (0) is accepted. */
	if (setint(u, SOL_IP, 49, 0) != 0) return (38);
	if (setint(u, SOL_IP, 49, 1) != -EINVAL) return (39);
	if (getint(u, SOL_IP, 49) != 0) return (40);
	/* IP_RECVOPTS(6) / IP_RETOPTS(7): never delivered, ENOPROTOOPT. */
	if (setint(u, SOL_IP, 6, 1) != -ENOPROTOOPT) return (41);
	if (setint(u, SOL_IP, 7, 1) != -ENOPROTOOPT) return (42);
	/* IP_ROUTER_ALERT(5), IP_NODEFRAG(22): no facility, ENOPROTOOPT. */
	if (setint(u, SOL_IP, 5, 1) != -ENOPROTOOPT) return (43);
	if (setint(u, SOL_IP, 22, 1) != -ENOPROTOOPT) return (44);
	/* IP_FREEBIND(15): root only here (IP_BINDANY); EPERM otherwise. */
	r = setint(u, SOL_IP, 15, 1);
	if (call(SYS_getuid, 0, 0, 0, 0, 0, 0) == 0) {
		if (r != 0) return (45);
	} else if (r != -EPERM)
		return (46);

	/* SO_NO_CHECK(11): checksums cannot be disabled; 0 ok, 1 EINVAL. */
	if (setint(u, SOL_SOCKET, 11, 0) != 0) return (47);
	if (setint(u, SOL_SOCKET, 11, 1) != -EINVAL) return (48);
	if (getint(u, SOL_SOCKET, 11) != 0) return (49);
	/* SO_BSDCOMPAT(14): obsolete no-op on Linux too. */
	if (setint(u, SOL_SOCKET, 14, 1) != 0) return (50);
	if (getint(u, SOL_SOCKET, 14) != 0) return (51);
	/* SO_PASSRIGHTS(83): SCM_RIGHTS cannot be turned off. */
	if (setint(u, SOL_SOCKET, 83, 1) != 0) return (52);
	if (setint(u, SOL_SOCKET, 83, 0) != -EINVAL) return (53);
	if (getint(u, SOL_SOCKET, 83) != 1) return (54);
	/* SO_PRIORITY(12), SO_BINDTODEVICE(25): ENOPROTOOPT. */
	if (setint(u, SOL_SOCKET, 12, 3) != -ENOPROTOOPT) return (55);
	if (setopt(u, SOL_SOCKET, 25, "lo0", 4) != -ENOPROTOOPT) return (56);
	/* An unknown option number is ENOPROTOOPT for set and get. */
	if (setint(u, SOL_SOCKET, 9999, 1) != -ENOPROTOOPT) return (57);
	if (getint(u, SOL_SOCKET, 9999) != -ENOPROTOOPT) return (58);
	/* EBADF beats everything. */
	if (setint(-1, SOL_IP, 2, 1) != -EBADF) return (59);

	/*
	 * IP_RECVTTL(12): a datagram sent to ourselves arrives with an
	 * IP_TTL(2) control message carrying the TTL set above as an int.
	 */
	if (bind_lo(u, &sin) != 0) return (60);
	if (setint(u, SOL_IP, 12, 1) != 0) return (61);
	r = udp_roundtrip(u, &sin, 0, 0, cbuf, sizeof(cbuf));
	if (r != 24) return (62);
	cm = (struct cmsghdr *)cbuf;
	if (cm->len != 20 || cm->level != SOL_IP || cm->type != 2)
		return (63);
	if (*(int *)(cm + 1) != 77) return (64);
	if (setint(u, SOL_IP, 12, 0) != 0) return (65);

	/*
	 * IP_PKTINFO(8): set, read back 1, and receive a struct in_pktinfo
	 * with the loopback interface index and the destination address.
	 */
	if (setint(u, SOL_IP, 8, 1) != 0) return (66);
	if (getint(u, SOL_IP, 8) != 1) return (67);
	r = udp_roundtrip(u, &sin, 0, 0, cbuf, sizeof(cbuf));
	if (r != 32) return (68);
	if (cm->len != 28 || cm->level != SOL_IP || cm->type != 8) return (69);
	pki = (struct in_pktinfo *)(cm + 1);
	if (pki->ifindex != lo) return (70);
	if (pki->addr != htonl(0x7f000001)) return (71);
	if (pki->spec_dst != htonl(0x7f000001)) return (72);
	if (setint(u, SOL_IP, 8, 0) != 0) return (73);
	if (getint(u, SOL_IP, 8) != 0) return (74);

	/*
	 * Per-datagram IP_TOS(1) via sendmsg(): with IP_RECVTOS(13) on, the
	 * datagram comes back with an IP_TOS control message (one byte).
	 */
	if (setint(u, SOL_IP, 13, 1) != 0) return (75);
	mkzero(scbuf, sizeof(scbuf));
	cm = (struct cmsghdr *)scbuf;
	cm->len = 20;
	cm->level = SOL_IP;
	cm->type = 1;
	*(int *)(cm + 1) = 0x10;
	r = udp_roundtrip(u, &sin, scbuf, 24, cbuf, sizeof(cbuf));
	if (r != 24) return (76);
	cm = (struct cmsghdr *)cbuf;
	if (cm->len != 17 || cm->level != SOL_IP || cm->type != 1) return (77);
	if (*(uint8_t *)(cm + 1) != 0x10) return (78);
	/* A TOS outside 0..255 is EINVAL. */
	cm = (struct cmsghdr *)scbuf;
	*(int *)(cm + 1) = 256;
	if (udp_roundtrip(u, &sin, scbuf, 24, cbuf, sizeof(cbuf)) != -EINVAL)
		return (79);
	/* IP_PKTINFO(8) on send: an interface cannot be forced, EINVAL. */
	cm->len = 28;
	cm->type = 8;
	pki = (struct in_pktinfo *)(cm + 1);
	pki->ifindex = lo;
	pki->spec_dst = pki->addr = 0;
	if (udp_roundtrip(u, &sin, scbuf, 32, cbuf, sizeof(cbuf)) != -EINVAL)
		return (80);
	/* ipi_spec_dst naming the bound address (127.0.0.1) is accepted. */
	pki->ifindex = 0;
	pki->spec_dst = htonl(0x7f000001);
	if (udp_roundtrip(u, &sin, scbuf, 32, cbuf, sizeof(cbuf)) != 24)
		return (81);
	/* An unknown IP-level control message type is EINVAL. */
	cm->len = 20;
	cm->type = 99;
	if (udp_roundtrip(u, &sin, scbuf, 24, cbuf, sizeof(cbuf)) != -EINVAL)
		return (82);
	/*
	 * On a socket bound to INADDR_ANY, ipi_spec_dst selects the
	 * source address of the datagram (IP_SENDSRCADDR underneath).
	 */
	v = call(SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
	if (v < 0) return (83);
	mkzero(&sin, sizeof(sin));
	sin.family = AF_INET;
	if (call(SYS_bind, v, (long)&sin, sizeof(sin), 0, 0, 0) != 0)
		return (84);
	len = sizeof(sin);
	if (call(SYS_getsockname, v, (long)&sin, (long)&len, 0, 0, 0) != 0)
		return (85);
	sin.addr = htonl(0x7f000001);
	if (setint(v, SOL_IP, 8, 1) != 0) return (86);
	cm->len = 28;
	cm->type = 8;
	if (udp_roundtrip(v, &sin, scbuf, 32, cbuf, sizeof(cbuf)) != 32)
		return (87);
	cm = (struct cmsghdr *)cbuf;
	pki = (struct in_pktinfo *)(cm + 1);
	if (cm->type != 8 || pki->addr != htonl(0x7f000001)) return (88);
	(void)call(SYS_close, v, 0, 0, 0, 0, 0);

	(void)call(SYS_close, u, 0, 0, 0, 0, 0);
	return (0);
}

/* Linux struct tcp_info, first bytes only. */
struct tcp_info_head { uint8_t state; uint8_t ca_state; uint8_t rest[246]; };

static int
test_tcp(void)
{
	struct sockaddr_in sin;
	struct tcp_info_head ti;
	char name[16], cur[16];
	long t, c, a, r;
	int len;

	t = call(SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
	if (t < 0) return (100);
	/* SO_REUSEADDR(2), SO_KEEPALIVE(9), TCP_NODELAY(1): set 1, get 1. */
	if (setint(t, SOL_SOCKET, 2, 1) != 0) return (101);
	if (getint(t, SOL_SOCKET, 2) != 1) return (102);
	if (setint(t, SOL_SOCKET, 9, 1) != 0) return (103);
	if (getint(t, SOL_SOCKET, 9) != 1) return (104);
	if (setint(t, SOL_TCP, 1, 1) != 0) return (105);
	if (getint(t, SOL_TCP, 1) != 1) return (106);
	if (bind_lo(t, &sin) != 0) return (107);
	if (call(SYS_listen, t, 1, 0, 0, 0, 0) != 0) return (108);
	c = call(SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
	if (c < 0) return (109);
	if (call(SYS_connect, c, (long)&sin, sizeof(sin), 0, 0, 0) != 0)
		return (110);
	a = call(SYS_accept4, t, 0, 0, 0, 0, 0);
	if (a < 0) return (111);

	/* TCP_INFO(11): 248 bytes, tcpi_state TCP_ESTABLISHED(1). */
	if (sizeof(ti) != 248) return (112);
	len = sizeof(ti);
	mkzero(&ti, sizeof(ti));
	if (getopt(c, SOL_TCP, 11, &ti, &len) != 0) return (113);
	if (len != 248) return (114);
	if (ti.state != 1) return (115);
	/* The listener is TCP_LISTEN(10). */
	len = sizeof(ti);
	if (getopt(t, SOL_TCP, 11, &ti, &len) != 0) return (116);
	if (ti.state != 10) return (117);
	/* A short buffer gets a truncated copy and the truncated length. */
	len = 8;
	ti.state = 0;
	if (getopt(c, SOL_TCP, 11, &ti, &len) != 0) return (118);
	if (len != 8 || ti.state != 1) return (119);
	/* TCP_INFO is read-only: setsockopt is ENOPROTOOPT. */
	if (setopt(c, SOL_TCP, 11, &ti, sizeof(ti)) != -ENOPROTOOPT)
		return (120);

	/* TCP_CONGESTION(13): a non-empty algorithm name, 16 bytes max. */
	mkzero(name, sizeof(name));
	len = sizeof(name);
	if (getopt(c, SOL_TCP, 13, name, &len) != 0) return (121);
	if (len != 16 || name[0] < 'a' || name[0] > 'z' || name[15] != 0)
		return (122);
	/* Setting the current algorithm by name works and reads back. */
	__builtin_memcpy(cur, name, sizeof(cur));
	if (setopt(c, SOL_TCP, 13, cur, 16) != 0) return (123);
	/* Only the first optlen bytes count: "cubicXXX" with optlen 5 ok. */
	__builtin_memcpy(name, cur, sizeof(name));
	for (len = 0; len < 15 && name[len] != 0; len++)
		;
	name[len] = 'X';
	if (setopt(c, SOL_TCP, 13, name, len) != 0) return (124);
	/*
	 * Linux calls NewReno "reno".  If newreno is loaded the name is
	 * translated both ways; if not, the failure is Linux's ENOENT.
	 */
	r = setopt(c, SOL_TCP, 13, "reno", 4);
	if (r != 0 && r != -ENOENT) return (125);
	if (r == 0) {
		mkzero(name, sizeof(name));
		len = sizeof(name);
		if (getopt(c, SOL_TCP, 13, name, &len) != 0) return (126);
		if (name[0] != 'r' || name[1] != 'e' || name[2] != 'n' ||
		    name[3] != 'o' || name[4] != 0) return (127);
		if (setopt(c, SOL_TCP, 13, cur, 16) != 0) return (128);
	}
	/* An unknown algorithm is ENOENT. */
	if (setopt(c, SOL_TCP, 13, "nosuchcc", 8) != -ENOENT) return (129);
	/* optlen 0 is EINVAL. */
	if (setopt(c, SOL_TCP, 13, "reno", 0) != -EINVAL) return (130);
	/* getsockopt with a 2-byte buffer copies 2 bytes, no terminator. */
	name[0] = name[1] = name[2] = 'Z';
	len = 2;
	if (getopt(c, SOL_TCP, 13, name, &len) != 0) return (131);
	if (len != 2 || name[0] != cur[0] || name[1] != cur[1] ||
	    name[2] != 'Z') return (132);

	/* TCP_USER_TIMEOUT(18): milliseconds, rounded up to whole seconds. */
	if (setint(c, SOL_TCP, 18, 2500) != 0) return (133);
	if (getint(c, SOL_TCP, 18) != 3000) return (134);
	if (setint(c, SOL_TCP, 18, 0) != 0) return (135);
	if (getint(c, SOL_TCP, 18) != 0) return (136);

	/* TCP_QUICKACK(12), TCP_NOTSENT_LOWAT(25), TCP_INQ(36): ENOPROTOOPT. */
	if (setint(c, SOL_TCP, 12, 1) != -ENOPROTOOPT) return (137);
	if (setint(c, SOL_TCP, 25, 1) != -ENOPROTOOPT) return (138);
	if (setint(c, SOL_TCP, 36, 1) != -ENOPROTOOPT) return (139);
	if (getint(c, SOL_TCP, 12) != -ENOPROTOOPT) return (140);
	/* TCP_DEFER_ACCEPT(9): ENOPROTOOPT (logged as unimplemented). */
	if (setint(t, SOL_TCP, 9, 1) != -ENOPROTOOPT) return (141);
	/* TCP_CORK(3): set 1, get 1 (not the FreeBSD TF_NOPUSH bit). */
	if (setint(c, SOL_TCP, 3, 1) != 0) return (142);
	if (getint(c, SOL_TCP, 3) != 1) return (143);
	if (setint(c, SOL_TCP, 3, 0) != 0) return (144);
	if (getint(c, SOL_TCP, 3) != 0) return (145);

	(void)call(SYS_close, a, 0, 0, 0, 0, 0);
	(void)call(SYS_close, c, 0, 0, 0, 0, 0);
	(void)call(SYS_close, t, 0, 0, 0, 0, 0);
	return (0);
}

static int
test_ipv6(void)
{
	long s;

	s = call(SYS_socket, AF_INET6, SOCK_DGRAM, 0, 0, 0, 0);
	if (s < 0) return (0);	/* no IPv6: nothing to check */
	/* IPV6_V6ONLY(26): set 1, get 1. */
	if (setint(s, SOL_IPV6, 26, 1) != 0) return (150);
	if (getint(s, SOL_IPV6, 26) != 1) return (151);
	/* IPV6_UNICAST_HOPS(16): set 33, get 33. */
	if (setint(s, SOL_IPV6, 16, 33) != 0) return (152);
	if (getint(s, SOL_IPV6, 16) != 33) return (153);
	/* IPV6_RECVPKTINFO(49), IPV6_RECVHOPLIMIT(51), IPV6_RECVTCLASS(66). */
	if (setint(s, SOL_IPV6, 49, 1) != 0) return (154);
	if (getint(s, SOL_IPV6, 49) != 1) return (155);
	if (setint(s, SOL_IPV6, 51, 1) != 0) return (156);
	if (setint(s, SOL_IPV6, 66, 1) != 0) return (157);
	if (getint(s, SOL_IPV6, 66) != 1) return (158);
	/* IPV6_TCLASS(67): set 0x20, get 0x20. */
	if (setint(s, SOL_IPV6, 67, 0x20) != 0) return (159);
	if (getint(s, SOL_IPV6, 67) != 0x20) return (160);
	/*
	 * The RFC 2292 options (IPV6_2292PKTINFO(2), IPV6_2292HOPOPTS(3),
	 * IPV6_2292DSTOPTS(4), IPV6_2292RTHDR(5), IPV6_2292PKTOPTIONS(6),
	 * IPV6_2292HOPLIMIT(8)) are rejected with ENOPROTOOPT.
	 */
	if (setint(s, SOL_IPV6, 2, 1) != -ENOPROTOOPT) return (161);
	if (setint(s, SOL_IPV6, 3, 1) != -ENOPROTOOPT) return (162);
	if (setint(s, SOL_IPV6, 4, 1) != -ENOPROTOOPT) return (163);
	if (setint(s, SOL_IPV6, 5, 1) != -ENOPROTOOPT) return (164);
	if (setint(s, SOL_IPV6, 6, 1) != -ENOPROTOOPT) return (165);
	if (setint(s, SOL_IPV6, 8, 1) != -ENOPROTOOPT) return (166);
	if (getint(s, SOL_IPV6, 2) != -ENOPROTOOPT) return (167);
	/* IPV6_MTU_DISCOVER(23): DO(2) round trip, default is WANT(1). */
	if (getint(s, SOL_IPV6, 23) != 1) return (168);
	if (setint(s, SOL_IPV6, 23, 2) != 0) return (169);
	if (getint(s, SOL_IPV6, 23) != 2) return (170);
	if (setint(s, SOL_IPV6, 23, 5) != -EINVAL) return (171);
	/* IPV6_MULTICAST_ALL(29): as IP_MULTICAST_ALL. */
	if (setint(s, SOL_IPV6, 29, 1) != -EINVAL) return (172);
	if (setint(s, SOL_IPV6, 29, 0) != 0) return (173);
	/* IPV6_ADDR_PREFERENCES(72): TMP(1) round trip; COA(4) is EINVAL. */
	if (setint(s, SOL_IPV6, 72, 0x0001) != 0) return (174);
	if (getint(s, SOL_IPV6, 72) != 0x0001) return (175);
	if (setint(s, SOL_IPV6, 72, 0x0002) != 0) return (176);
	if (getint(s, SOL_IPV6, 72) != 0x0002) return (177);
	/* Two source preferences at once is EINVAL on Linux. */
	if (setint(s, SOL_IPV6, 72, 0x0003) != -EINVAL) return (178);
	if (setint(s, SOL_IPV6, 72, 0x0004) != -EINVAL) return (179);
	/* IPV6_MTU(24) needs a connected socket: ENOTCONN(107). */
	if (getint(s, SOL_IPV6, 24) != -107) return (180);
	/* IPV6_ADDRFORM(1), IPV6_JOIN_ANYCAST(27): ENOPROTOOPT. */
	if (setint(s, SOL_IPV6, 1, 2) != -ENOPROTOOPT) return (181);
	if (setint(s, SOL_IPV6, 27, 1) != -ENOPROTOOPT) return (182);
	(void)call(SYS_close, s, 0, 0, 0, 0, 0);
	return (0);
}

/* SCM_RIGHTS over a socketpair must keep working (hot path). */
static int
test_unix(void)
{
	struct msghdr mh;
	struct iovec iov;
	struct cmsghdr *cm;
	char cbuf[32], b;
	int sv[2], pp[2], fd;
	long r;

	if (call(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (200);
	if (call(SYS_pipe, (long)pp, 0, 0, 0, 0, 0) != 0) return (201);
	mkzero(cbuf, sizeof(cbuf));
	cm = (struct cmsghdr *)cbuf;
	cm->len = 20;
	cm->level = SOL_SOCKET;
	cm->type = 1;	/* SCM_RIGHTS */
	*(int *)(cm + 1) = pp[1];
	b = 'y';
	iov.base = &b;
	iov.len = 1;
	mkzero(&mh, sizeof(mh));
	mh.iov = &iov;
	mh.iovlen = 1;
	mh.control = cbuf;
	mh.controllen = 24;
	if (call(SYS_sendmsg, sv[0], (long)&mh, 0, 0, 0, 0) != 1) return (202);
	mkzero(cbuf, sizeof(cbuf));
	mkzero(&mh, sizeof(mh));
	mh.iov = &iov;
	mh.iovlen = 1;
	mh.control = cbuf;
	mh.controllen = sizeof(cbuf);
	r = call(SYS_recvmsg, sv[1], (long)&mh, 0, 0, 0, 0);
	if (r != 1) return (203);
	if (mh.controllen != 24 || cm->len != 20 || cm->level != SOL_SOCKET ||
	    cm->type != 1) return (204);
	fd = *(int *)(cm + 1);
	if (call(SYS_write, fd, (long)"z", 1, 0, 0, 0) != 1) return (205);
	if (call(SYS_read, pp[0], (long)&b, 1, 0, 0, 0) != 1 || b != 'z')
		return (206);
	return (0);
}

static int
test(void)
{
	int r;

	if ((r = test_udp()) != 0) return (r);
	if ((r = test_tcp()) != 0) return (r);
	if ((r = test_ipv6()) != 0) return (r);
	if ((r = test_unix()) != 0) return (r);
	return (0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
