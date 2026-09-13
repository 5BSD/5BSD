/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * AF_VSOCK (Linux family 40) through the emulator: stream loopback via
 * VMADDR_CID_LOCAL, datagram, getsockname/getpeername translation,
 * SO_VM_SOCKETS_* options at both SOL_VSOCK (287) and AF_VSOCK (40)
 * levels, IOCTL_VM_SOCKETS_GET_LOCAL_CID, and address validation.  Exit
 * status = failed check number; skips if the kernel has no vsock.
 */
#include "linux_test.h"

#define	AF_VSOCK		40
#define	SOCK_STREAM		1
#define	SOCK_DGRAM		2
#define	SOCK_SEQPACKET		5
#define	SOL_VSOCK		287
#define	VMADDR_CID_ANY		0xffffffffU
#define	VMADDR_CID_LOCAL	1
#define	VMADDR_PORT_ANY		0xffffffffU
#define	SO_VM_SOCKETS_BUFFER_SIZE	0
#define	SO_VM_SOCKETS_BUFFER_MIN_SIZE	1
#define	SO_VM_SOCKETS_BUFFER_MAX_SIZE	2
#define	SO_VM_SOCKETS_PEER_HOST_VM_ID	3
#define	SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW 8
#define	IOCTL_VM_SOCKETS_GET_LOCAL_CID	0x7b9
#define	EADDRNOTAVAIL		99
#define	ECONNREFUSED		111
#define	ECONNRESET_		104
#define	ENOPROTOOPT		92
#define	SYS_accept_		43
#define	EPROTONOSUPPORT_	93
#define	ESOCKTNOSUPPORT_	94

struct sockaddr_vm { u16 family; u16 reserved1; u32 port; u32 cid; u8 flags;
    u8 zero[3]; };

static int
test(int argc, char **argv, char **envp)
{
	struct sockaddr_vm sa, peer;
	long l, c, a, r, i, fd;
	unsigned int len, cid;
	unsigned long v64;
	char buf[8192];

	(void)argc; (void)argv; (void)envp;

	l = sys3(SYS_socket, AF_VSOCK, SOCK_STREAM, 0);
	if (l == -EAFNOSUPPORT)
		skip("AF_VSOCK not available in this kernel\n");
	if (l < 0) return (1);
	/* 2: the local CID ioctl works on a vsock socket (any value). */
	fd = sys3(SYS_open, "/dev/null", O_RDONLY, 0);
	cid = 0xdeadbeef;
	if (sys3(SYS_ioctl, l, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) != 0)
		return (2);
	if (cid == 0xdeadbeef) return (2);
	/* on a non-vsock fd it is ENOTTY */
	if (sys3(SYS_ioctl, fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) != -ENOTTY)
		return (2);
	(void)sys1(SYS_close, fd);
	/* 3: bind to CID_ANY, an ephemeral port; getsockname shows family 40. */
	xmemset(&sa, 0, sizeof(sa));
	sa.family = AF_VSOCK; sa.cid = VMADDR_CID_ANY; sa.port = VMADDR_PORT_ANY;
	if (sys3(SYS_bind, l, &sa, sizeof(sa)) != 0) return (3);
	len = sizeof(sa);
	if (sys3(SYS_getsockname, l, &sa, &len) != 0) return (3);
	if (len != sizeof(sa) || sa.family != AF_VSOCK || sa.port == VMADDR_PORT_ANY)
		return (3);
	if (sys2(SYS_listen, l, 4) != 0) return (3);
	/* 4-6: connect over loopback, transfer 8 KiB each way. */
	c = sys3(SYS_socket, AF_VSOCK, SOCK_STREAM, 0);
	if (c < 0) return (4);
	peer = sa; peer.cid = VMADDR_CID_LOCAL;
	if (sys3(SYS_connect, c, &peer, sizeof(peer)) != 0) return (4);
	len = sizeof(peer);
	a = sys3(SYS_accept_, l, &peer, &len);
	if (a < 0) return (5);
	if (peer.family != AF_VSOCK || len != sizeof(peer)) return (5);
	xmemset(buf, 'v', sizeof(buf));
	for (i = 0; i < 8192;) {
		r = sys3(SYS_write, c, buf + i, 8192 - i);
		if (r <= 0) return (5);
		i += r;
	}
	for (i = 0; i < 8192;) {
		r = sys3(SYS_read, a, buf, sizeof(buf));
		if (r <= 0) return (6);
		i += r;
	}
	if (sys3(SYS_write, a, "back", 4) != 4) return (6);
	if (sys3(SYS_read, c, buf, 4) != 4 || buf[0] != 'b') return (6);
	/* getpeername on the accepted side reports the connecting port */
	len = sizeof(peer);
	if (sys3(SYS_getpeername, a, &peer, &len) != 0) return (6);
	if (peer.family != AF_VSOCK) return (6);
	/* 7-9: options at both levels. */
	len = 8;
	if (sys5(SYS_getsockopt, c, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &v64,
	    &len) != 0) return (7);
	if (v64 == 0) return (7);
	if (sys5(SYS_getsockopt, c, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &v64,
	    &len) != 0) return (7);
	v64 = 262144;
	if (sys5(SYS_setsockopt, c, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &v64, 8)
	    != 0) return (8);
	len = 8; v64 = 0;
	if (sys5(SYS_getsockopt, c, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &v64,
	    &len) != 0 || v64 != 262144) return (8);
	len = 8;
	if (sys5(SYS_getsockopt, a, SOL_VSOCK, SO_VM_SOCKETS_PEER_HOST_VM_ID, &v64,
	    &len) != 0) return (8);
	/* an unknown option is ENOPROTOOPT, a short optlen EINVAL */
	r = sys5(SYS_setsockopt, c, SOL_VSOCK, 77, &v64, 8);
	if (r != -ENOPROTOOPT) { msgnum("unknown vsock option ", r); return (9); }
	r = sys5(SYS_setsockopt, c, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &v64, 2);
	if (r != -EINVAL) { msgnum("short vsock optlen ", r); return (9); }
	(void)sys1(SYS_close, a); (void)sys1(SYS_close, c);
	/* 10: connect to an unbound port is ECONNREFUSED. */
	c = sys3(SYS_socket, AF_VSOCK, SOCK_STREAM, 0);
	peer.family = AF_VSOCK; peer.cid = VMADDR_CID_LOCAL; peer.port = 65000;
	peer.reserved1 = 0; peer.flags = 0;
	r = sys3(SYS_connect, c, &peer, sizeof(peer));
	/* virtio-vsock answers a RST: Linux reports ECONNRESET for that too. */
	if (r != -ECONNREFUSED && r != -ETIMEDOUT && r != -ECONNRESET_) {
		msgnum("connect ", r);
		return (10);
	}
	/* 11: address validation: short address EINVAL, wrong family. */
	if (sys3(SYS_connect, c, &peer, 8) != -EINVAL) return (11);
	peer.family = 2;
	r = sys3(SYS_connect, c, &peer, sizeof(peer));
	if (r != -EAFNOSUPPORT && r != -EINVAL) return (11);
	(void)sys1(SYS_close, c);
	/* 12: datagram sockets bind, or are refused with a defined errno. */
	c = sys3(SYS_socket, AF_VSOCK, SOCK_DGRAM, 0);
	if (c >= 0) {
		sa.family = AF_VSOCK; sa.cid = VMADDR_CID_ANY; sa.port = VMADDR_PORT_ANY;
		r = sys3(SYS_bind, c, &sa, sizeof(sa));
		if (r != 0 && r != -EOPNOTSUPP && r != -EADDRNOTAVAIL) {
			msgnum("vsock dgram bind ", r);
			return (12);
		}
		(void)sys1(SYS_close, c);
	} else if (c != -EPROTONOSUPPORT_ && c != -ESOCKTNOSUPPORT_)
		{ msgnum("vsock dgram socket ", c); return (12); }
	(void)sys1(SYS_close, l);
	return (0);
}
