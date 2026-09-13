/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1995 Søren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/domain.h>
#include <sys/filedesc.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/vsock.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>
#include <sys/un.h>
#include <sys/unistd.h>

#include <security/audit/audit.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#ifdef INET6
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif

#ifdef COMPAT_LINUX32
#include <compat/freebsd32/freebsd32_util.h>
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif
#include <compat/linux/linux_common.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_file.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_pidfd.h>
#include <compat/linux/linux_socket.h>
#include <compat/linux/linux_time.h>
#include <compat/linux/linux_util.h>

_Static_assert(offsetof(struct l_ifreq, ifr_ifru) ==
    offsetof(struct ifreq, ifr_ifru),
    "Linux ifreq members names should be equal to FreeeBSD");
_Static_assert(offsetof(struct l_ifreq, ifr_index) ==
    offsetof(struct ifreq, ifr_index),
    "Linux ifreq members names should be equal to FreeeBSD");
_Static_assert(offsetof(struct l_ifreq, ifr_name) ==
    offsetof(struct ifreq, ifr_name),
    "Linux ifreq members names should be equal to FreeeBSD");

#define	SECURITY_CONTEXT_STRING	"unconfined"

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
CTASSERT(sizeof(struct l_group_req) == 132);
CTASSERT(sizeof(struct l_group_source_req) == 260);
#else
CTASSERT(sizeof(struct l_group_req) == 136);
CTASSERT(sizeof(struct l_group_source_req) == 264);
#endif
CTASSERT(sizeof(struct l_ip_mreq_source) == 12);
CTASSERT(sizeof(struct l_in_pktinfo) == 12);
CTASSERT(sizeof(struct l_sockaddr_in6) == 28);
CTASSERT(sizeof(struct l_ip6_mtuinfo) == 32);
CTASSERT(sizeof(struct l_sock_timeval) == 16);
CTASSERT(sizeof(struct l_tcp_info) == 248);

static int linux_sendmsg_common(struct thread *, l_int, struct l_msghdr *,
					l_uint);
static int linux_recvmsg_common(struct thread *, l_int, struct l_msghdr *,
					l_uint, struct msghdr *);
static int linux_set_socket_flags(int, int *);
static int linux_sockopt_copyout(struct thread *, void *, socklen_t,
					struct linux_getsockopt_args *);
static int linux_sockopt_copyout_trunc(struct thread *, void *, socklen_t,
					struct linux_getsockopt_args *);

#define	SOL_NETLINK	270

static int
linux_to_bsd_sockopt_level(int level)
{

	if (level == LINUX_SOL_SOCKET)
		return (SOL_SOCKET);
	/* Linux uses its AF_VSOCK number as the level too; native takes both. */
	if (level == LINUX_AF_VSOCK)
		return (SOL_VSOCK);
	/* Remaining values are RFC-defined protocol numbers. */
	return (level);
}

static int
bsd_to_linux_sockopt_level(int level)
{

	if (level == SOL_SOCKET)
		return (LINUX_SOL_SOCKET);
	return (level);
}

/*
 * Socket option translation.
 *
 * Return values:
 *   >= 0  the FreeBSD option name;
 *   -1    unknown option, logged by the caller;
 *   -2    known option that cannot be honoured exactly on FreeBSD; it is
 *         rejected with ENOPROTOOPT.  Options that could be implemented
 *         with more work are logged (rate limited) so they can be
 *         enumerated; options with no kernel facility behind them are
 *         rejected quietly.
 *
 * Options that need value or structure translation are intercepted by
 * Linux name in linux_setsockopt()/linux_getsockopt() before these
 * tables are consulted.
 */
static int
linux_to_bsd_ip_sockopt(int opt)
{

	switch (opt) {
	/* known and translated sockopts */
	case LINUX_IP_TOS:
		return (IP_TOS);
	case LINUX_IP_TTL:
		return (IP_TTL);
	case LINUX_IP_HDRINCL:
		return (IP_HDRINCL);
	case LINUX_IP_OPTIONS:
		return (IP_OPTIONS);
	case LINUX_IP_RECVTTL:
		return (IP_RECVTTL);
	case LINUX_IP_RECVTOS:
		return (IP_RECVTOS);
	case LINUX_IP_FREEBIND:
		/*
		 * IP_BINDANY needs PRIV_NETINET_BINDANY on FreeBSD while
		 * IP_FREEBIND is unprivileged on Linux; the EPERM an
		 * unprivileged caller gets is honest.
		 */
		return (IP_BINDANY);
	case LINUX_IP_TRANSPARENT:
		/*
		 * The socket-visible part of IP_TRANSPARENT is the ability
		 * to bind to non-local addresses; interception itself is a
		 * firewall (ipfw fwd / pf rdr) matter on both systems.
		 * Both require privilege.
		 */
		return (IP_BINDANY);
	case LINUX_IP_IPSEC_POLICY:
		/* we have this option, but not documented in ip(4) manpage */
		return (IP_IPSEC_POLICY);
	case LINUX_IP_MINTTL:
		return (IP_MINTTL);
	case LINUX_IP_MULTICAST_IF:
		return (IP_MULTICAST_IF);
	case LINUX_IP_MULTICAST_TTL:
		return (IP_MULTICAST_TTL);
	case LINUX_IP_MULTICAST_LOOP:
		return (IP_MULTICAST_LOOP);
	case LINUX_IP_ADD_MEMBERSHIP:
		return (IP_ADD_MEMBERSHIP);
	case LINUX_IP_DROP_MEMBERSHIP:
		return (IP_DROP_MEMBERSHIP);
	/* struct ip_mreq_source is reordered in linux_setsockopt(). */
	case LINUX_IP_UNBLOCK_SOURCE:
		return (IP_UNBLOCK_SOURCE);
	case LINUX_IP_BLOCK_SOURCE:
		return (IP_BLOCK_SOURCE);
	case LINUX_IP_ADD_SOURCE_MEMBERSHIP:
		return (IP_ADD_SOURCE_MEMBERSHIP);
	case LINUX_IP_DROP_SOURCE_MEMBERSHIP:
		return (IP_DROP_SOURCE_MEMBERSHIP);
	/* struct group_req / group_source_req are translated. */
	case LINUX_MCAST_JOIN_GROUP:
		return (MCAST_JOIN_GROUP);
	case LINUX_MCAST_LEAVE_GROUP:
		return (MCAST_LEAVE_GROUP);
	case LINUX_MCAST_JOIN_SOURCE_GROUP:
		return (MCAST_JOIN_SOURCE_GROUP);
	case LINUX_MCAST_LEAVE_SOURCE_GROUP:
		return (MCAST_LEAVE_SOURCE_GROUP);
	case LINUX_MCAST_BLOCK_SOURCE:
		return (MCAST_BLOCK_SOURCE);
	case LINUX_MCAST_UNBLOCK_SOURCE:
		return (MCAST_UNBLOCK_SOURCE);
	case LINUX_IP_RECVORIGDSTADDR:
		return (IP_RECVORIGDSTADDR);

	/*
	 * Handled by Linux name in linux_setsockopt()/linux_getsockopt():
	 * IP_PKTINFO, IP_MTU_DISCOVER, IP_MULTICAST_ALL, IP_PROTOCOL,
	 * IP_RECVERR.  Reaching here means the other direction
	 * (e.g. setsockopt(IP_PROTOCOL)) which Linux rejects too.
	 */
	case LINUX_IP_PKTINFO:
	case LINUX_IP_MTU_DISCOVER:
	case LINUX_IP_MULTICAST_ALL:
	case LINUX_IP_PROTOCOL:
		return (-2);

	/* known but not implemented sockopts, could be done with more work */
	case LINUX_IP_RECVERR:
		/* needed by steam and glibc's resolver */
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported IPv4 socket option IP_RECVERR (%d), you can not get extended reliability info in linux programs",
		    opt);
		return (-2);
	case LINUX_IP_MTU:
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported IPv4 socket option IP_MTU (%d), your linux program can not read the path MTU of this socket",
		    opt);
		return (-2);
	case LINUX_IP_RECVOPTS:
	case LINUX_IP_RETOPTS:
		/*
		 * ip_savecontrol() never emits IP_RECVOPTS / IP_RECVRETOPTS
		 * ("notyet"), so accepting the option would silently
		 * deliver nothing.
		 */
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported IPv4 socket option IP_RECVOPTS/IP_RETOPTS (%d), received IP options are not delivered",
		    opt);
		return (-2);
	case LINUX_IP_MSFILTER:
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported IPv4 socket option IP_MSFILTER (%d)",
		    opt);
		return (-2);
	case LINUX_MCAST_MSFILTER:
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported IPv4 socket option MCAST_MSFILTER (%d)",
		    opt);
		return (-2);

	/*
	 * Known options with no FreeBSD facility behind them; rejected
	 * quietly with ENOPROTOOPT.
	 */
	case LINUX_IP_ROUTER_ALERT:
	case LINUX_IP_PKTOPTIONS:
	case LINUX_IP_XFRM_POLICY:
	case LINUX_IP_PASSSEC:
	case LINUX_IP_NODEFRAG:
	case LINUX_IP_CHECKSUM:
	case LINUX_IP_BIND_ADDRESS_NO_PORT:
	case LINUX_IP_RECVFRAGSIZE:
	case LINUX_IP_UNICAST_IF:
	case LINUX_IP_LOCAL_PORT_RANGE:
		return (-2);

	/* unknown sockopts */
	default:
		return (-1);
	}
}

static int
linux_to_bsd_ip6_sockopt(int opt)
{

	switch (opt) {
	/* known and translated sockopts */
	case LINUX_IPV6_CHECKSUM:
		return (IPV6_CHECKSUM);
	case LINUX_IPV6_NEXTHOP:
		return (IPV6_NEXTHOP);
	case LINUX_IPV6_UNICAST_HOPS:
		return (IPV6_UNICAST_HOPS);
	case LINUX_IPV6_MULTICAST_IF:
		return (IPV6_MULTICAST_IF);
	case LINUX_IPV6_MULTICAST_HOPS:
		return (IPV6_MULTICAST_HOPS);
	case LINUX_IPV6_MULTICAST_LOOP:
		return (IPV6_MULTICAST_LOOP);
	case LINUX_IPV6_ADD_MEMBERSHIP:
		return (IPV6_JOIN_GROUP);
	case LINUX_IPV6_DROP_MEMBERSHIP:
		return (IPV6_LEAVE_GROUP);
	case LINUX_IPV6_V6ONLY:
		return (IPV6_V6ONLY);
	case LINUX_IPV6_IPSEC_POLICY:
		/* we have this option, but not documented in ip6(4) manpage */
		return (IPV6_IPSEC_POLICY);
	/*
	 * Protocol-independent multicast API; the group_req /
	 * group_source_req argument is translated in linux_setsockopt().
	 */
	case LINUX_MCAST_JOIN_GROUP:
		return (MCAST_JOIN_GROUP);
	case LINUX_MCAST_LEAVE_GROUP:
		return (MCAST_LEAVE_GROUP);
	case LINUX_MCAST_JOIN_SOURCE_GROUP:
		return (MCAST_JOIN_SOURCE_GROUP);
	case LINUX_MCAST_LEAVE_SOURCE_GROUP:
		return (MCAST_LEAVE_SOURCE_GROUP);
	case LINUX_MCAST_BLOCK_SOURCE:
		return (MCAST_BLOCK_SOURCE);
	case LINUX_MCAST_UNBLOCK_SOURCE:
		return (MCAST_UNBLOCK_SOURCE);
	case LINUX_IPV6_RECVPKTINFO:
		return (IPV6_RECVPKTINFO);
	case LINUX_IPV6_PKTINFO:
		return (IPV6_PKTINFO);
	case LINUX_IPV6_RECVHOPLIMIT:
		return (IPV6_RECVHOPLIMIT);
	case LINUX_IPV6_HOPLIMIT:
		return (IPV6_HOPLIMIT);
	case LINUX_IPV6_RECVHOPOPTS:
		return (IPV6_RECVHOPOPTS);
	case LINUX_IPV6_HOPOPTS:
		return (IPV6_HOPOPTS);
	case LINUX_IPV6_RTHDRDSTOPTS:
		return (IPV6_RTHDRDSTOPTS);
	case LINUX_IPV6_RECVRTHDR:
		return (IPV6_RECVRTHDR);
	case LINUX_IPV6_RTHDR:
		return (IPV6_RTHDR);
	case LINUX_IPV6_RECVDSTOPTS:
		return (IPV6_RECVDSTOPTS);
	case LINUX_IPV6_DSTOPTS:
		return (IPV6_DSTOPTS);
	case LINUX_IPV6_RECVPATHMTU:
		return (IPV6_RECVPATHMTU);
	case LINUX_IPV6_PATHMTU:
		/* struct ip6_mtuinfo is translated in linux_getsockopt(). */
		return (IPV6_PATHMTU);
	case LINUX_IPV6_DONTFRAG:
		return (IPV6_DONTFRAG);
	case LINUX_IPV6_RECVTCLASS:
		return (IPV6_RECVTCLASS);
	case LINUX_IPV6_TCLASS:
		return (IPV6_TCLASS);
	case LINUX_IPV6_AUTOFLOWLABEL:
		return (IPV6_AUTOFLOWLABEL);
	case LINUX_IPV6_ORIGDSTADDR:
		return (IPV6_ORIGDSTADDR);
	case LINUX_IPV6_FREEBIND:
		/* Privileged on FreeBSD, see IP_FREEBIND. */
		return (IPV6_BINDANY);
	case LINUX_IPV6_TRANSPARENT:
		/* See IP_TRANSPARENT. */
		return (IPV6_BINDANY);

	/*
	 * Handled by Linux name in linux_setsockopt()/linux_getsockopt():
	 * IPV6_MTU_DISCOVER, IPV6_MTU (get), IPV6_MULTICAST_ALL,
	 * IPV6_ADDR_PREFERENCES, IPV6_RECVERR.
	 */
	case LINUX_IPV6_MTU_DISCOVER:
	case LINUX_IPV6_MULTICAST_ALL:
	case LINUX_IPV6_ADDR_PREFERENCES:
		return (-2);

	/* known but not implemented sockopts, could be done with more work */
	case LINUX_IPV6_MTU:
		/* getsockopt is served via IPV6_PATHMTU, setsockopt is not. */
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported IPv6 socket option IPV6_MTU (%d), your linux program can not set the MTU on this socket",
		    opt);
		return (-2);
	case LINUX_IPV6_RECVERR:
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported IPv6 socket option IPV6_RECVERR (%d), you can not get extended reliability info in linux programs",
		    opt);
		return (-2);
	case LINUX_MCAST_MSFILTER:
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported IPv6 socket option MCAST_MSFILTER (%d), your linux program can not manipulate the multicast source filter",
		    opt);
		return (-2);

	/*
	 * The RFC 2292 options.  FreeBSD implements them, but setting one
	 * switches the socket into an exclusive RFC 2292 mode in which the
	 * RFC 3542 options are refused with EINVAL; Linux lets both
	 * families coexist.  Rejected rather than mapped to a different
	 * behaviour.
	 */
	case LINUX_IPV6_2292PKTINFO:
	case LINUX_IPV6_2292HOPOPTS:
	case LINUX_IPV6_2292DSTOPTS:
	case LINUX_IPV6_2292RTHDR:
	case LINUX_IPV6_2292PKTOPTIONS:
	case LINUX_IPV6_2292HOPLIMIT:
		return (-2);

	/*
	 * Known options with no FreeBSD facility behind them; rejected
	 * quietly with ENOPROTOOPT.
	 */
	case LINUX_IPV6_ADDRFORM:
	case LINUX_IPV6_AUTHHDR:
	case LINUX_IPV6_FLOWINFO:
	case LINUX_IPV6_ROUTER_ALERT:
	case LINUX_IPV6_JOIN_ANYCAST:
	case LINUX_IPV6_LEAVE_ANYCAST:
	case LINUX_IPV6_ROUTER_ALERT_ISOLATE:
	case LINUX_IPV6_FLOWLABEL_MGR:
	case LINUX_IPV6_FLOWINFO_SEND:
	case LINUX_IPV6_XFRM_POLICY:
	case LINUX_IPV6_HDRINCL:
	case LINUX_IPV6_MINHOPCOUNT:
	case LINUX_IPV6_UNICAST_IF:
	case LINUX_IPV6_RECVFRAGSIZE:
		return (-2);

	/* unknown sockopts */
	default:
		return (-1);
	}
}

static int
linux_to_bsd_so_sockopt(int opt)
{

	switch (opt) {
	case LINUX_SO_DEBUG:
		return (SO_DEBUG);
	case LINUX_SO_REUSEADDR:
		return (SO_REUSEADDR);
	case LINUX_SO_TYPE:
		return (SO_TYPE);
	case LINUX_SO_ERROR:
		return (SO_ERROR);
	case LINUX_SO_DONTROUTE:
		return (SO_DONTROUTE);
	case LINUX_SO_BROADCAST:
		return (SO_BROADCAST);
	case LINUX_SO_SNDBUF:
	case LINUX_SO_SNDBUFFORCE:
		return (SO_SNDBUF);
	case LINUX_SO_RCVBUF:
	case LINUX_SO_RCVBUFFORCE:
		return (SO_RCVBUF);
	case LINUX_SO_KEEPALIVE:
		return (SO_KEEPALIVE);
	case LINUX_SO_OOBINLINE:
		return (SO_OOBINLINE);
	case LINUX_SO_LINGER:
		return (SO_LINGER);
	case LINUX_SO_REUSEPORT:
		/*
		 * Linux SO_REUSEPORT load-balances incoming connections
		 * and datagrams across the sockets sharing the port, which
		 * is SO_REUSEPORT_LB here; plain SO_REUSEPORT only permits
		 * the duplicate bind.
		 */
		return (SO_REUSEPORT_LB);
	case LINUX_SO_PASSCRED:
		return (LOCAL_CREDS_PERSISTENT);
	case LINUX_SO_PEERCRED:
		return (LOCAL_PEERCRED);
	case LINUX_SO_RCVLOWAT:
		return (SO_RCVLOWAT);
	case LINUX_SO_SNDLOWAT:
		return (SO_SNDLOWAT);
	case LINUX_SO_RCVTIMEO:
	case LINUX_SO_RCVTIMEO_NEW:
		return (SO_RCVTIMEO);
	case LINUX_SO_SNDTIMEO:
	case LINUX_SO_SNDTIMEO_NEW:
		return (SO_SNDTIMEO);
	case LINUX_SO_TIMESTAMPO:
	case LINUX_SO_TIMESTAMPN:
		return (SO_TIMESTAMP);
	case LINUX_SO_TIMESTAMPNSO:
	case LINUX_SO_TIMESTAMPNSN:
		return (SO_BINTIME);
	case LINUX_SO_ACCEPTCONN:
		return (SO_ACCEPTCONN);
	case LINUX_SO_PROTOCOL:
		return (SO_PROTOCOL);
	case LINUX_SO_DOMAIN:
		return (SO_DOMAIN);
	case LINUX_SO_MARK:
		/*
		 * Both are 32-bit socket tags consumed by the packet
		 * filter (ipfw sockarg / dummynet here, fwmark there).
		 * FreeBSD does not require privilege to set it and has no
		 * getsockopt for it.
		 */
		return (SO_USER_COOKIE);
	case LINUX_SO_MAX_PACING_RATE:
		/* Both 32-bit bytes per second. */
		return (SO_MAX_PACING_RATE);

	/*
	 * Handled by Linux name in linux_setsockopt()/linux_getsockopt():
	 * SO_NO_CHECK, SO_BSDCOMPAT, SO_PASSRIGHTS, SO_PEERGROUPS,
	 * SO_PEERSEC.
	 */
	case LINUX_SO_NO_CHECK:
	case LINUX_SO_BSDCOMPAT:
	case LINUX_SO_PASSRIGHTS:
	case LINUX_SO_PEERPIDFD:
		return (-2);

	/* known but not implemented sockopts, could be done with more work */
	case LINUX_SO_TIMESTAMPINGO:
	case LINUX_SO_TIMESTAMPINGN:
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported socket option SO_TIMESTAMPING (%d)", opt);
		return (-2);

	/*
	 * Known options with no FreeBSD facility behind them; rejected
	 * quietly with ENOPROTOOPT.
	 */
	case LINUX_SO_PRIORITY:
	case LINUX_SO_SECURITY_AUTHENTICATION:
	case LINUX_SO_SECURITY_ENCRYPTION_TRANSPORT:
	case LINUX_SO_SECURITY_ENCRYPTION_NETWORK:
	case LINUX_SO_BINDTODEVICE:
	case LINUX_SO_ATTACH_FILTER:
	case LINUX_SO_DETACH_FILTER:
	case LINUX_SO_PEERNAME:
	case LINUX_SO_PASSSEC:
	case LINUX_SO_RXQ_OVFL:
	case LINUX_SO_WIFI_STATUS:
	case LINUX_SO_PEEK_OFF:
	case LINUX_SO_NOFCS:
	case LINUX_SO_LOCK_FILTER:
	case LINUX_SO_SELECT_ERR_QUEUE:
	case LINUX_SO_BUSY_POLL:
	case LINUX_SO_BPF_EXTENSIONS:
	case LINUX_SO_INCOMING_CPU:
	case LINUX_SO_ATTACH_BPF:
	case LINUX_SO_ATTACH_REUSEPORT_CBPF:
	case LINUX_SO_ATTACH_REUSEPORT_EBPF:
	case LINUX_SO_CNX_ADVICE:
	case LINUX_SO_MEMINFO:
	case LINUX_SO_INCOMING_NAPI_ID:
	case LINUX_SO_COOKIE:
	case LINUX_SO_ZEROCOPY:
	case LINUX_SO_TXTIME:
	case LINUX_SO_BINDTOIFINDEX:
	case LINUX_SO_DETACH_REUSEPORT_BPF:
	case LINUX_SO_PREFER_BUSY_POLL:
	case LINUX_SO_BUSY_POLL_BUDGET:
	case LINUX_SO_NETNS_COOKIE:
	case LINUX_SO_BUF_LOCK:
	case LINUX_SO_RESERVE_MEM:
	case LINUX_SO_TXREHASH:
	case LINUX_SO_RCVMARK:
	case LINUX_SO_PASSPIDFD:
	case LINUX_SO_DEVMEM_LINEAR:
	case LINUX_SO_DEVMEM_DMABUF:
	case LINUX_SO_DEVMEM_DONTNEED:
	case LINUX_SO_RCVPRIORITY:
	case LINUX_SO_INQ:
		return (-2);
	}
	return (-1);
}

/*
 * SOL_UDP: none of the Linux UDP options (corking, GSO/GRO segmentation,
 * ESP/L2TP encapsulation, IPv6 zero-checksum control) has a socket-level
 * equivalent here.  Known numbers are ENOPROTOOPT without a log entry.
 */
static int
linux_to_bsd_udp_sockopt(int opt)
{

	switch (opt) {
	case LINUX_UDP_CORK:
	case LINUX_UDP_ENCAP:
	case LINUX_UDP_NO_CHECK6_TX:
	case LINUX_UDP_NO_CHECK6_RX:
	case LINUX_UDP_SEGMENT:
	case LINUX_UDP_GRO:
		return (-2);
	}
	return (-1);
}

static int
linux_to_bsd_tcp_sockopt(int opt)
{

	switch (opt) {
	case LINUX_TCP_NODELAY:
		return (TCP_NODELAY);
	case LINUX_TCP_MAXSEG:
		return (TCP_MAXSEG);
	case LINUX_TCP_CORK:
		return (TCP_NOPUSH);
	case LINUX_TCP_KEEPIDLE:
		return (TCP_KEEPIDLE);
	case LINUX_TCP_KEEPINTVL:
		return (TCP_KEEPINTVL);
	case LINUX_TCP_KEEPCNT:
		return (TCP_KEEPCNT);
	case LINUX_TCP_INFO:
		/* struct tcp_info is translated in linux_getsockopt(). */
		return (TCP_INFO);
	case LINUX_TCP_CONGESTION:
		/* Names are translated in linux_{get,set}sockopt(). */
		return (TCP_CONGESTION);
	case LINUX_TCP_MD5SIG:
		return (TCP_MD5SIG);
	case LINUX_TCP_USER_TIMEOUT:
		return (TCP_MAXUNACKTIME);
	case LINUX_TCP_FASTOPEN:
		/*
		 * Linux takes a queue length, FreeBSD a boolean; both mean
		 * "enable TFO on this listener" for any non-zero value.
		 */
		return (TCP_FASTOPEN);

	/* known but not implemented sockopts, could be done with more work */
	case LINUX_TCP_DEFER_ACCEPT:
		/* accf_data(9) has the wait but not the timeout. */
		LINUX_RATELIMIT_MSG_OPT1(
		    "unsupported TCP socket option TCP_DEFER_ACCEPT (%d)", opt);
		return (-2);

	/*
	 * Known options with no FreeBSD facility behind them (or, for
	 * TCP_QUICKACK, only in the RACK stack); rejected quietly.
	 */
	case LINUX_TCP_SYNCNT:
	case LINUX_TCP_LINGER2:
	case LINUX_TCP_WINDOW_CLAMP:
	case LINUX_TCP_QUICKACK:
	case LINUX_TCP_THIN_LINEAR_TIMEOUTS:
	case LINUX_TCP_THIN_DUPACK:
	case LINUX_TCP_REPAIR:
	case LINUX_TCP_REPAIR_QUEUE:
	case LINUX_TCP_QUEUE_SEQ:
	case LINUX_TCP_REPAIR_OPTIONS:
	case LINUX_TCP_TIMESTAMP:
	case LINUX_TCP_NOTSENT_LOWAT:
	case LINUX_TCP_CC_INFO:
	case LINUX_TCP_SAVE_SYN:
	case LINUX_TCP_SAVED_SYN:
	case LINUX_TCP_REPAIR_WINDOW:
	case LINUX_TCP_FASTOPEN_CONNECT:
	case LINUX_TCP_ULP:
	case LINUX_TCP_MD5SIG_EXT:
	case LINUX_TCP_FASTOPEN_KEY:
	case LINUX_TCP_FASTOPEN_NO_COOKIE:
	case LINUX_TCP_ZEROCOPY_RECEIVE:
	case LINUX_TCP_INQ:
	case LINUX_TCP_TX_DELAY:
		return (-2);
	}
	return (-1);
}

static u_int
linux_to_bsd_tcp_user_timeout(l_uint linux_timeout)
{

	/*
	 * Linux exposes TCP_USER_TIMEOUT in milliseconds while
	 * TCP_MAXUNACKTIME uses whole seconds. Round up partial
	 * seconds so a non-zero Linux timeout never becomes zero.
	 */
	return (howmany(linux_timeout, 1000U));
}

static l_uint
bsd_to_linux_tcp_user_timeout(u_int bsd_timeout)
{

	if (bsd_timeout > UINT_MAX / 1000U)
		return (UINT_MAX);

	return (bsd_timeout * 1000U);
}

/*
 * TCP_CONGESTION: Linux calls NewReno "reno"; every other algorithm name
 * we share (cubic, htcp, vegas, dctcp, cdg) is spelled the same.
 */
static int
linux_setsockopt_tcp_congestion(struct thread *td,
    struct linux_setsockopt_args *args)
{
	char name[LINUX_TCP_CA_NAME_MAX];
	const char *uname;
	size_t i, len;
	int c, error;

	if (args->optlen <= 0)
		return (EINVAL);
	/*
	 * Linux: strncpy_from_user(name, optval, min(TCP_CA_NAME_MAX - 1,
	 * optlen)); stop at the NUL, never read past it.
	 */
	len = MIN(args->optlen, LINUX_TCP_CA_NAME_MAX - 1);
	uname = PTRIN(args->optval);
	for (i = 0; i < len; i++) {
		c = fubyte(uname + i);
		if (c == -1)
			return (EFAULT);
		if (c == 0)
			break;
		name[i] = c;
	}
	name[i] = '\0';
	if (strcmp(name, "reno") == 0)
		strlcpy(name, "newreno", sizeof(name));
	error = kern_setsockopt(td, args->s, IPPROTO_TCP, TCP_CONGESTION,
	    name, UIO_SYSSPACE, strlen(name) + 1);
	/* tcp_set_cc_mod() says ESRCH for an unknown name; Linux ENOENT. */
	return (error == ESRCH ? ENOENT : error);
}

static int
linux_getsockopt_tcp_congestion(struct thread *td,
    struct linux_getsockopt_args *args)
{
	char name[TCP_CA_NAME_MAX];
	socklen_t len, ulen;
	int error;

	error = copyin(PTRIN(args->optlen), &ulen, sizeof(ulen));
	if (error != 0)
		return (error);
	len = sizeof(name);
	error = kern_getsockopt(td, args->s, IPPROTO_TCP, TCP_CONGESTION,
	    name, UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	name[sizeof(name) - 1] = '\0';
	if (strcmp(name, "newreno") == 0)
		strlcpy(name, "reno", sizeof(name));
	/* Linux copies min(optlen, TCP_CA_NAME_MAX) bytes, unterminated. */
	len = MIN(ulen, LINUX_TCP_CA_NAME_MAX);
	return (linux_sockopt_copyout(td, name, len, args));
}

static uint8_t
bsd_to_linux_tcp_state(uint8_t state)
{

	switch (state) {
	case TCPS_CLOSED:
		return (LINUX_TCP_CLOSE);
	case TCPS_LISTEN:
		return (LINUX_TCP_LISTEN);
	case TCPS_SYN_SENT:
		return (LINUX_TCP_SYN_SENT);
	case TCPS_SYN_RECEIVED:
		return (LINUX_TCP_SYN_RECV);
	case TCPS_ESTABLISHED:
		return (LINUX_TCP_ESTABLISHED);
	case TCPS_CLOSE_WAIT:
		return (LINUX_TCP_CLOSE_WAIT);
	case TCPS_FIN_WAIT_1:
		return (LINUX_TCP_FIN_WAIT1);
	case TCPS_CLOSING:
		return (LINUX_TCP_CLOSING);
	case TCPS_LAST_ACK:
		return (LINUX_TCP_LAST_ACK);
	case TCPS_FIN_WAIT_2:
		return (LINUX_TCP_FIN_WAIT2);
	case TCPS_TIME_WAIT:
		return (LINUX_TCP_TIME_WAIT);
	}
	return (LINUX_TCP_CLOSE);
}

/*
 * TCP_INFO: the FreeBSD struct tcp_info was modelled on the Linux one, but
 * the state numbering, the option bits and several units (bytes vs.
 * segments, usec vs. msec) differ.  Fields FreeBSD does not track are left
 * zero, as Linux does for fields it cannot fill.
 */
static int
linux_getsockopt_tcp_info(struct thread *td,
    struct linux_getsockopt_args *args)
{
	struct l_tcp_info lti;
	struct tcp_info ti;
	socklen_t len, ulen;
	uint32_t mss;
	int error;

	error = copyin(PTRIN(args->optlen), &ulen, sizeof(ulen));
	if (error != 0)
		return (error);
	len = sizeof(ti);
	error = kern_getsockopt(td, args->s, IPPROTO_TCP, TCP_INFO,
	    &ti, UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);

	memset(&lti, 0, sizeof(lti));
	lti.tcpi_state = bsd_to_linux_tcp_state(ti.tcpi_state);
	if (ti.tcpi_options & TCPI_OPT_TIMESTAMPS)
		lti.tcpi_options |= LINUX_TCPI_OPT_TIMESTAMPS;
	if (ti.tcpi_options & TCPI_OPT_SACK)
		lti.tcpi_options |= LINUX_TCPI_OPT_SACK;
	if (ti.tcpi_options & TCPI_OPT_WSCALE)
		lti.tcpi_options |= LINUX_TCPI_OPT_WSCALE;
	if (ti.tcpi_options & TCPI_OPT_ECN)
		lti.tcpi_options |= LINUX_TCPI_OPT_ECN;
	if (ti.tcpi_options & TCPI_OPT_TFO)
		lti.tcpi_options |= LINUX_TCPI_OPT_SYN_DATA;
	lti.tcpi_snd_wscale = ti.tcpi_snd_wscale;
	lti.tcpi_rcv_wscale = ti.tcpi_rcv_wscale;
	lti.tcpi_rto = ti.tcpi_rto;
	lti.tcpi_snd_mss = ti.tcpi_snd_mss;
	lti.tcpi_rcv_mss = ti.tcpi_rcv_mss;
	/* FreeBSD reports usec here, Linux jiffies_to_msecs(). */
	lti.tcpi_last_data_recv = ti.tcpi_last_data_recv / 1000;
	lti.tcpi_rtt = ti.tcpi_rtt;
	lti.tcpi_rttvar = ti.tcpi_rttvar;
	/*
	 * Linux keeps snd_cwnd, snd_ssthresh and the segment counters in
	 * segments, FreeBSD in bytes.
	 */
	mss = ti.tcpi_snd_mss != 0 ? ti.tcpi_snd_mss : 1;
	lti.tcpi_snd_ssthresh = howmany(ti.tcpi_snd_ssthresh, mss);
	lti.tcpi_snd_cwnd = howmany(ti.tcpi_snd_cwnd, mss);
	lti.tcpi_unacked = (ti.tcpi_snd_max - ti.tcpi_snd_una) / mss;
	/* tcpi_rcv_space is rcv_wnd on FreeBSD. */
	lti.tcpi_rcv_wnd = ti.tcpi_rcv_space;
	lti.tcpi_rcv_space = ti.tcpi_rcv_space;
	lti.tcpi_snd_wnd = ti.tcpi_snd_wnd;
	lti.tcpi_total_retrans = ti.tcpi_snd_rexmitpack;
	lti.tcpi_delivered_ce = ti.tcpi_delivered_ce;
	lti.tcpi_rcv_ooopack = ti.tcpi_rcv_ooopack;
	/* tcpi_rttmin is in stack-specific units (ticks or usec); skip. */

	/* Linux copies min(optlen, sizeof) and reports what it copied. */
	len = MIN(ulen, sizeof(lti));
	return (linux_sockopt_copyout(td, &lti, len, args));
}

/*
 * IP_MTU_DISCOVER / IPV6_MTU_DISCOVER onto IP_DONTFRAG / IPV6_DONTFRAG.
 * IP_PMTUDISC_DO and _PROBE set DF and fail oversized sends with
 * EMSGSIZE, which is what the *_DONTFRAG options do.  _DONT is the
 * FreeBSD default; _WANT (the Linux default) is accepted as "use the
 * default".  _INTERFACE and _OMIT have no equivalent and get EINVAL.
 */
static int
linux_setsockopt_mtu_discover(struct thread *td,
    struct linux_setsockopt_args *args, int level, int name)
{
	int error, val;

	if (args->optlen < sizeof(val))
		return (EINVAL);
	error = copyin(PTRIN(args->optval), &val, sizeof(val));
	if (error != 0)
		return (error);
	switch (val) {
	case LINUX_IP_PMTUDISC_DONT:
	case LINUX_IP_PMTUDISC_WANT:
		val = 0;
		break;
	case LINUX_IP_PMTUDISC_DO:
	case LINUX_IP_PMTUDISC_PROBE:
		val = 1;
		break;
	default:
		return (EINVAL);
	}
	return (kern_setsockopt(td, args->s, level, name, &val,
	    UIO_SYSSPACE, sizeof(val)));
}

static int
linux_getsockopt_mtu_discover(struct thread *td,
    struct linux_getsockopt_args *args, int level, int name, int off)
{
	socklen_t len;
	int error, val;

	len = sizeof(val);
	error = kern_getsockopt(td, args->s, level, name, &val,
	    UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	val = (val != 0) ? LINUX_IP_PMTUDISC_DO : off;
	return (linux_sockopt_copyout_trunc(td, &val, sizeof(val), args));
}

/*
 * Boolean options whose FreeBSD behaviour is fixed: only the value that
 * matches what FreeBSD does is accepted; anything else is EINVAL.
 */
static int
linux_setsockopt_fixed_bool(struct thread *td,
    struct linux_setsockopt_args *args, int fixed)
{
	int error, val;

	if (args->optlen < sizeof(val))
		return (EINVAL);
	error = copyin(PTRIN(args->optval), &val, sizeof(val));
	if (error != 0)
		return (error);
	return (((val != 0) == (fixed != 0)) ? 0 : EINVAL);
}

static int
linux_getsockopt_fixed_int(struct thread *td,
    struct linux_getsockopt_args *args, int fixed)
{

	return (linux_sockopt_copyout_trunc(td, &fixed, sizeof(fixed), args));
}

/*
 * IP_PKTINFO is IP_RECVIF + IP_RECVDSTADDR; the two control messages are
 * folded into one struct in_pktinfo in linux_recvmsg_common().
 */
static int
linux_setsockopt_ip_pktinfo(struct thread *td,
    struct linux_setsockopt_args *args)
{
	int error, val, undo;

	if (args->optlen < sizeof(val))
		return (EINVAL);
	error = copyin(PTRIN(args->optval), &val, sizeof(val));
	if (error != 0)
		return (error);
	val = (val != 0);
	error = kern_setsockopt(td, args->s, IPPROTO_IP, IP_RECVDSTADDR,
	    &val, UIO_SYSSPACE, sizeof(val));
	if (error != 0)
		return (error);
	error = kern_setsockopt(td, args->s, IPPROTO_IP, IP_RECVIF,
	    &val, UIO_SYSSPACE, sizeof(val));
	if (error != 0) {
		undo = !val;
		(void)kern_setsockopt(td, args->s, IPPROTO_IP, IP_RECVDSTADDR,
		    &undo, UIO_SYSSPACE, sizeof(undo));
	}
	return (error);
}

static int
linux_getsockopt_ip_pktinfo(struct thread *td,
    struct linux_getsockopt_args *args)
{
	socklen_t len;
	int error, recvif, recvdst;

	len = sizeof(recvif);
	error = kern_getsockopt(td, args->s, IPPROTO_IP, IP_RECVIF,
	    &recvif, UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	len = sizeof(recvdst);
	error = kern_getsockopt(td, args->s, IPPROTO_IP, IP_RECVDSTADDR,
	    &recvdst, UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	recvif = (recvif != 0 && recvdst != 0);
	return (linux_sockopt_copyout_trunc(td, &recvif, sizeof(recvif),
	    args));
}

/*
 * IPV6_ADDR_PREFERENCES onto IPV6_PREFER_TEMPADDR.  Only the
 * temporary/public source preference exists here.  The mobility and CGA
 * flags that name the default state (HOME, NONCGA) are accepted as such;
 * COA and CGA cannot be honoured and get EINVAL, as Linux does for
 * contradictory flag sets.
 */
static int
linux_setsockopt_ip6_addr_preferences(struct thread *td,
    struct linux_setsockopt_args *args)
{
	int error, val;

	if (args->optlen < sizeof(val))
		return (EINVAL);
	error = copyin(PTRIN(args->optval), &val, sizeof(val));
	if (error != 0)
		return (error);
	if ((val & ~(LINUX_IPV6_PREFER_SRC_TMP | LINUX_IPV6_PREFER_SRC_PUBLIC |
	    LINUX_IPV6_PREFER_SRC_PUBTMP_DEFAULT | LINUX_IPV6_PREFER_SRC_HOME |
	    LINUX_IPV6_PREFER_SRC_NONCGA)) != 0)
		return (EINVAL);
	switch (val & (LINUX_IPV6_PREFER_SRC_TMP |
	    LINUX_IPV6_PREFER_SRC_PUBLIC | LINUX_IPV6_PREFER_SRC_PUBTMP_DEFAULT)) {
	case 0:
	case LINUX_IPV6_PREFER_SRC_PUBTMP_DEFAULT:
	case LINUX_IPV6_PREFER_SRC_PUBLIC:
		val = 0;
		break;
	case LINUX_IPV6_PREFER_SRC_TMP:
		val = 1;
		break;
	default:
		/* Linux: more than one source preference is EINVAL. */
		return (EINVAL);
	}
	return (kern_setsockopt(td, args->s, IPPROTO_IPV6,
	    IPV6_PREFER_TEMPADDR, &val, UIO_SYSSPACE, sizeof(val)));
}

static int
linux_getsockopt_ip6_addr_preferences(struct thread *td,
    struct linux_getsockopt_args *args)
{
	socklen_t len;
	int error, val;

	len = sizeof(val);
	error = kern_getsockopt(td, args->s, IPPROTO_IPV6,
	    IPV6_PREFER_TEMPADDR, &val, UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	val = (val != 0) ? LINUX_IPV6_PREFER_SRC_TMP :
	    LINUX_IPV6_PREFER_SRC_PUBLIC;
	return (linux_sockopt_copyout_trunc(td, &val, sizeof(val), args));
}

static void
bsd_to_linux_sockaddr_in6(const struct sockaddr_in6 *sin6,
    struct l_sockaddr_in6 *lsin6)
{

	memset(lsin6, 0, sizeof(*lsin6));
	lsin6->sin6_family = LINUX_AF_INET6;
	lsin6->sin6_port = sin6->sin6_port;
	lsin6->sin6_flowinfo = sin6->sin6_flowinfo;
	memcpy(lsin6->sin6_addr, &sin6->sin6_addr, sizeof(lsin6->sin6_addr));
	lsin6->sin6_scope_id = sin6->sin6_scope_id;
}

static void
bsd_to_linux_ip6_mtuinfo(const struct ip6_mtuinfo *mi,
    struct l_ip6_mtuinfo *lmi)
{

	bsd_to_linux_sockaddr_in6(&mi->ip6m_addr, &lmi->ip6m_addr);
	lmi->ip6m_mtu = mi->ip6m_mtu;
}

/* IPV6_PATHMTU (struct ip6_mtuinfo) and IPV6_MTU (int) getsockopt. */
static int
linux_getsockopt_ip6_pathmtu(struct thread *td,
    struct linux_getsockopt_args *args, bool as_int)
{
	struct l_ip6_mtuinfo lmi;
	struct ip6_mtuinfo mi;
	socklen_t len, ulen;
	int error, mtu;

	error = copyin(PTRIN(args->optlen), &ulen, sizeof(ulen));
	if (error != 0)
		return (error);
	len = sizeof(mi);
	error = kern_getsockopt(td, args->s, IPPROTO_IPV6, IPV6_PATHMTU,
	    &mi, UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	if (as_int) {
		mtu = mi.ip6m_mtu;
		return (linux_sockopt_copyout(td, &mtu, MIN(ulen, sizeof(mtu)),
		    args));
	}
	if (ulen < sizeof(lmi))
		return (EINVAL);
	bsd_to_linux_ip6_mtuinfo(&mi, &lmi);
	return (linux_sockopt_copyout(td, &lmi, sizeof(lmi), args));
}

/*
 * Convert a Linux sockaddr_storage (as embedded in group_req and friends)
 * into a FreeBSD one.
 */
static int
linux_to_bsd_sockaddr_storage(const struct l_sockaddr_storage *lss,
    struct sockaddr_storage *ss)
{
	socklen_t len;

	memcpy(ss, lss, sizeof(*ss));
	len = sizeof(*ss);
	return (linux_to_bsd_sockaddr((struct l_sockaddr *)ss, NULL, &len));
}

/*
 * MCAST_JOIN_GROUP & co.  struct group_req and struct group_source_req
 * differ in the sockaddr_storage layout (and, on 32-bit Linux, in the
 * offset of the group member), so they are rebuilt member by member.
 */
static int
linux_setsockopt_group_req(struct thread *td,
    struct linux_setsockopt_args *args, int level, int name)
{
	struct l_group_source_req lreq;
	struct group_source_req req;
	size_t lsize, size;
	int error;

	if (name == MCAST_JOIN_GROUP || name == MCAST_LEAVE_GROUP) {
		lsize = sizeof(struct l_group_req);
		size = sizeof(struct group_req);
	} else {
		lsize = sizeof(struct l_group_source_req);
		size = sizeof(struct group_source_req);
	}
	if (args->optlen < lsize)
		return (EINVAL);
	error = copyin(PTRIN(args->optval), &lreq, lsize);
	if (error != 0)
		return (error);

	memset(&req, 0, sizeof(req));
	req.gsr_interface = lreq.gsr_interface;
	error = linux_to_bsd_sockaddr_storage(&lreq.gsr_group,
	    &req.gsr_group);
	if (error != 0)
		return (error);
	if (size == sizeof(struct group_source_req)) {
		error = linux_to_bsd_sockaddr_storage(&lreq.gsr_source,
		    &req.gsr_source);
		if (error != 0)
			return (error);
	}
	return (kern_setsockopt(td, args->s, level, name, &req,
	    UIO_SYSSPACE, size));
}

/* IP_ADD_SOURCE_MEMBERSHIP & co.: reorder struct ip_mreq_source. */
static int
linux_setsockopt_ip_mreq_source(struct thread *td,
    struct linux_setsockopt_args *args, int name)
{
	struct l_ip_mreq_source lmreq;
	struct ip_mreq_source mreq;
	int error;

	if (args->optlen < sizeof(lmreq))
		return (EINVAL);
	error = copyin(PTRIN(args->optval), &lmreq, sizeof(lmreq));
	if (error != 0)
		return (error);
	mreq.imr_multiaddr.s_addr = lmreq.imr_multiaddr;
	mreq.imr_sourceaddr.s_addr = lmreq.imr_sourceaddr;
	mreq.imr_interface.s_addr = lmreq.imr_interface;
	return (kern_setsockopt(td, args->s, IPPROTO_IP, name, &mreq,
	    UIO_SYSSPACE, sizeof(mreq)));
}

/* SO_RCVTIMEO_NEW / SO_SNDTIMEO_NEW carry 64-bit fields on every ABI. */
static int
linux_setsockopt_sock_timeval(struct thread *td,
    struct linux_setsockopt_args *args, int name)
{
	struct l_sock_timeval ltv;
	struct timeval tv;
	int error;

	if (args->optlen < sizeof(ltv))
		return (EINVAL);
	error = copyin(PTRIN(args->optval), &ltv, sizeof(ltv));
	if (error != 0)
		return (error);
	if (ltv.tv_usec < 0 || ltv.tv_usec >= 1000000)
		return (EDOM);
	/* sock_set_timeout(): a negative tv_sec means "no timeout". */
	if (ltv.tv_sec < 0)
		ltv.tv_sec = ltv.tv_usec = 0;
	/* sosetopt() clamps anything above INT32_MAX seconds to SBT_MAX. */
	tv.tv_sec = MIN(ltv.tv_sec, INT32_MAX);
	tv.tv_usec = ltv.tv_usec;
	return (kern_setsockopt(td, args->s, SOL_SOCKET, name, &tv,
	    UIO_SYSSPACE, sizeof(tv)));
}

static int
linux_getsockopt_sock_timeval(struct thread *td,
    struct linux_getsockopt_args *args, int name)
{
	struct l_sock_timeval ltv;
	struct timeval tv;
	socklen_t len;
	int error;

	len = sizeof(tv);
	error = kern_getsockopt(td, args->s, SOL_SOCKET, name, &tv,
	    UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	ltv.tv_sec = tv.tv_sec;
	ltv.tv_usec = tv.tv_usec;
	return (linux_sockopt_copyout_trunc(td, &ltv, sizeof(ltv), args));
}

#ifdef INET6
static int
linux_to_bsd_icmp6_sockopt(int opt)
{

	switch (opt) {
	case LINUX_ICMP6_FILTER:
		return (ICMP6_FILTER);
	}
	return (-1);
}
#endif

static int
linux_to_bsd_msg_flags(int flags)
{
	int ret_flags = 0;

	if (flags & LINUX_MSG_OOB)
		ret_flags |= MSG_OOB;
	if (flags & LINUX_MSG_PEEK)
		ret_flags |= MSG_PEEK;
	if (flags & LINUX_MSG_DONTROUTE)
		ret_flags |= MSG_DONTROUTE;
	if (flags & LINUX_MSG_CTRUNC)
		ret_flags |= MSG_CTRUNC;
	if (flags & LINUX_MSG_TRUNC)
		ret_flags |= MSG_TRUNC;
	if (flags & LINUX_MSG_DONTWAIT)
		ret_flags |= MSG_DONTWAIT;
	if (flags & LINUX_MSG_EOR)
		ret_flags |= MSG_EOR;
	if (flags & LINUX_MSG_WAITALL)
		ret_flags |= MSG_WAITALL;
	if (flags & LINUX_MSG_NOSIGNAL)
		ret_flags |= MSG_NOSIGNAL;
	if (flags & LINUX_MSG_PROXY)
		LINUX_RATELIMIT_MSG_OPT1("socket message flag MSG_PROXY (%d) not handled",
		    LINUX_MSG_PROXY);
	if (flags & LINUX_MSG_FIN)
		LINUX_RATELIMIT_MSG_OPT1("socket message flag MSG_FIN (%d) not handled",
		    LINUX_MSG_FIN);
	if (flags & LINUX_MSG_SYN)
		LINUX_RATELIMIT_MSG_OPT1("socket message flag MSG_SYN (%d) not handled",
		    LINUX_MSG_SYN);
	if (flags & LINUX_MSG_CONFIRM)
		LINUX_RATELIMIT_MSG_OPT1("socket message flag MSG_CONFIRM (%d) not handled",
		    LINUX_MSG_CONFIRM);
	if (flags & LINUX_MSG_RST)
		LINUX_RATELIMIT_MSG_OPT1("socket message flag MSG_RST (%d) not handled",
		    LINUX_MSG_RST);
	if (flags & LINUX_MSG_ERRQUEUE)
		LINUX_RATELIMIT_MSG_OPT1("socket message flag MSG_ERRQUEUE (%d) not handled",
		    LINUX_MSG_ERRQUEUE);
	return (ret_flags);
}

static int
linux_to_bsd_cmsg_type(int cmsg_type)
{

	switch (cmsg_type) {
	case LINUX_SCM_RIGHTS:
		return (SCM_RIGHTS);
	case LINUX_SCM_CREDENTIALS:
		return (SCM_CREDS);
	}
	return (-1);
}

static int
bsd_to_linux_ip_cmsg_type(int cmsg_type)
{

	switch (cmsg_type) {
	case IP_RECVORIGDSTADDR:
		return (LINUX_IP_RECVORIGDSTADDR);
	case IP_RECVTOS:
		return (LINUX_IP_TOS);
	case IP_RECVTTL:
		return (LINUX_IP_TTL);
	case IP_RECVIF:
		/* Folded together with IP_RECVDSTADDR, see recvmsg. */
		return (LINUX_IP_PKTINFO);
	}
	return (-1);
}

#ifdef INET6
static int
bsd_to_linux_ip6_cmsg_type(int cmsg_type)
{
	switch (cmsg_type) {
	case IPV6_2292HOPLIMIT:
		return (LINUX_IPV6_2292HOPLIMIT);
	case IPV6_HOPLIMIT:
		return (LINUX_IPV6_HOPLIMIT);
	case IPV6_PKTINFO:
		return (LINUX_IPV6_PKTINFO);
	case IPV6_HOPOPTS:
		return (LINUX_IPV6_HOPOPTS);
	case IPV6_DSTOPTS:
		return (LINUX_IPV6_DSTOPTS);
	case IPV6_RTHDR:
		return (LINUX_IPV6_RTHDR);
	case IPV6_RTHDRDSTOPTS:
		return (LINUX_IPV6_RTHDRDSTOPTS);
	case IPV6_TCLASS:
		return (LINUX_IPV6_TCLASS);
	case IPV6_PATHMTU:
		return (LINUX_IPV6_PATHMTU);
	case IPV6_ORIGDSTADDR:
		return (LINUX_IPV6_ORIGDSTADDR);
	}
	return (-1);
}
#endif

static int
bsd_to_linux_cmsg_type(struct proc *p, int cmsg_type, int cmsg_level)
{
	struct linux_pemuldata *pem;

	if (cmsg_level == IPPROTO_IP)
		return (bsd_to_linux_ip_cmsg_type(cmsg_type));
#ifdef INET6
	if (cmsg_level == IPPROTO_IPV6)
		return (bsd_to_linux_ip6_cmsg_type(cmsg_type));
#endif
	if (cmsg_level != SOL_SOCKET)
		return (-1);

	pem = pem_find(p);

	switch (cmsg_type) {
	case SCM_RIGHTS:
		return (LINUX_SCM_RIGHTS);
	case SCM_CREDS:
		return (LINUX_SCM_CREDENTIALS);
	case SCM_CREDS2:
		return (LINUX_SCM_CREDENTIALS);
	case SCM_TIMESTAMP:
		return (pem->so_timestamp);
	case SCM_BINTIME:
		return (pem->so_timestampns);
	}
	return (-1);
}

static int
linux_to_bsd_msghdr(struct msghdr *bhdr, const struct l_msghdr *lhdr)
{
	if (lhdr->msg_controllen > INT_MAX)
		return (ENOBUFS);

	bhdr->msg_name		= PTRIN(lhdr->msg_name);
	bhdr->msg_namelen	= lhdr->msg_namelen;
	bhdr->msg_iov		= PTRIN(lhdr->msg_iov);
	bhdr->msg_iovlen	= lhdr->msg_iovlen;
	bhdr->msg_control	= PTRIN(lhdr->msg_control);

	/*
	 * msg_controllen is skipped since BSD and LINUX control messages
	 * are potentially different sizes (e.g. the cred structure used
	 * by SCM_CREDS is different between the two operating system).
	 *
	 * The caller can set it (if necessary) after converting all the
	 * control messages.
	 */

	bhdr->msg_flags		= linux_to_bsd_msg_flags(lhdr->msg_flags);
	return (0);
}

static int
bsd_to_linux_msghdr(const struct msghdr *bhdr, struct l_msghdr *lhdr)
{
	lhdr->msg_name		= PTROUT(bhdr->msg_name);
	lhdr->msg_namelen	= bhdr->msg_namelen;
	lhdr->msg_iov		= PTROUT(bhdr->msg_iov);
	lhdr->msg_iovlen	= bhdr->msg_iovlen;
	lhdr->msg_control	= PTROUT(bhdr->msg_control);

	/*
	 * msg_controllen is skipped since BSD and LINUX control messages
	 * are potentially different sizes (e.g. the cred structure used
	 * by SCM_CREDS is different between the two operating system).
	 *
	 * The caller can set it (if necessary) after converting all the
	 * control messages.
	 */

	/* msg_flags skipped */
	return (0);
}

static int
linux_set_socket_flags(int lflags, int *flags)
{

	if (lflags & ~(LINUX_SOCK_CLOEXEC | LINUX_SOCK_NONBLOCK))
		return (EINVAL);
	if (lflags & LINUX_SOCK_NONBLOCK)
		*flags |= SOCK_NONBLOCK;
	if (lflags & LINUX_SOCK_CLOEXEC)
		*flags |= SOCK_CLOEXEC;
	return (0);
}

static int
linux_copyout_sockaddr(const struct sockaddr *sa, void *uaddr, size_t len)
{
	struct l_sockaddr *lsa;
	int error;

	error = bsd_to_linux_sockaddr(sa, &lsa, len);
	if (error != 0)
		return (error);

	error = copyout(lsa, uaddr, len);
	free(lsa, M_LINUX);

	return (error);
}

static int
linux_sendit(struct thread *td, int s, struct msghdr *mp, int flags,
    struct mbuf *control, enum uio_seg segflg)
{
	struct sockaddr *to;
	int error, len;

	if (mp->msg_name != NULL) {
		len = mp->msg_namelen;
		error = linux_to_bsd_sockaddr(mp->msg_name, &to, &len);
		if (error != 0)
			return (error);
		mp->msg_name = to;
	} else
		to = NULL;

	error = kern_sendit(td, s, mp, linux_to_bsd_msg_flags(flags), control,
	    segflg);

	if (to)
		free(to, M_SONAME);
	return (error);
}

/* Return 0 if IP_HDRINCL is set for the given socket. */
static int
linux_check_hdrincl(struct thread *td, int s)
{
	int error, optval;
	socklen_t size_val;

	size_val = sizeof(optval);
	error = kern_getsockopt(td, s, IPPROTO_IP, IP_HDRINCL,
	    &optval, UIO_SYSSPACE, &size_val);
	if (error != 0)
		return (error);

	return (optval == 0);
}

/*
 * Updated sendto() when IP_HDRINCL is set:
 * tweak endian-dependent fields in the IP packet.
 */
static int
linux_sendto_hdrincl(struct thread *td, struct linux_sendto_args *linux_args)
{
/*
 * linux_ip_copysize defines how many bytes we should copy
 * from the beginning of the IP packet before we customize it for BSD.
 * It should include all the fields we modify (ip_len and ip_off).
 */
#define linux_ip_copysize	8

	struct ip *packet;
	struct msghdr msg;
	struct iovec aiov[1];
	int error;

	/* Check that the packet isn't too big or too small. */
	if (linux_args->len < linux_ip_copysize ||
	    linux_args->len > IP_MAXPACKET)
		return (EINVAL);

	packet = (struct ip *)malloc(linux_args->len, M_LINUX, M_WAITOK);

	/* Make kernel copy of the packet to be sent */
	if ((error = copyin(PTRIN(linux_args->msg), packet,
	    linux_args->len)))
		goto goout;

	/* Convert fields from Linux to BSD raw IP socket format */
	packet->ip_len = linux_args->len;
	packet->ip_off = ntohs(packet->ip_off);

	/* Prepare the msghdr and iovec structures describing the new packet */
	msg.msg_name = PTRIN(linux_args->to);
	msg.msg_namelen = linux_args->tolen;
	msg.msg_iov = aiov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_flags = 0;
	aiov[0].iov_base = (char *)packet;
	aiov[0].iov_len = linux_args->len;
	error = linux_sendit(td, linux_args->s, &msg, linux_args->flags,
	    NULL, UIO_SYSSPACE);
goout:
	free(packet, M_LINUX);
	return (error);
}

static const char *linux_netlink_names[] = {
	[LINUX_NETLINK_ROUTE] = "ROUTE",
	[LINUX_NETLINK_SOCK_DIAG] = "SOCK_DIAG",
	[LINUX_NETLINK_NFLOG] = "NFLOG",
	[LINUX_NETLINK_SELINUX] = "SELINUX",
	[LINUX_NETLINK_AUDIT] = "AUDIT",
	[LINUX_NETLINK_FIB_LOOKUP] = "FIB_LOOKUP",
	[LINUX_NETLINK_NETFILTER] = "NETFILTER",
	[LINUX_NETLINK_KOBJECT_UEVENT] = "KOBJECT_UEVENT",
};

int
linux_socket(struct thread *td, struct linux_socket_args *args)
{
	int retval_socket, type;
	sa_family_t domain;

	type = args->type & LINUX_SOCK_TYPE_MASK;
	if (type < 0 || type > LINUX_SOCK_MAX)
		return (EINVAL);
	retval_socket = linux_set_socket_flags(args->type & ~LINUX_SOCK_TYPE_MASK,
		&type);
	if (retval_socket != 0)
		return (retval_socket);
	domain = linux_to_bsd_domain(args->domain);
	if (domain == AF_UNKNOWN) {
		/* Mask off SOCK_NONBLOCK / CLOEXEC for error messages. */
		type = args->type & LINUX_SOCK_TYPE_MASK;
		if (args->domain == LINUX_AF_NETLINK &&
		    args->protocol == LINUX_NETLINK_AUDIT) {
			; /* Do nothing, quietly. */
		} else if (args->domain == LINUX_AF_NETLINK) {
			const char *nl_name;

			if (args->protocol >= 0 &&
			    args->protocol < nitems(linux_netlink_names))
				nl_name = linux_netlink_names[args->protocol];
			else
				nl_name = NULL;
			if (nl_name != NULL)
				linux_msg(curthread,
				    "unsupported socket(AF_NETLINK, %d, "
				    "NETLINK_%s)", type, nl_name);
			else
				linux_msg(curthread,
				    "unsupported socket(AF_NETLINK, %d, %d)",
				    type, args->protocol);
		} else {
			linux_msg(curthread, "unsupported socket domain %d, "
			    "type %d, protocol %d", args->domain, type,
			    args->protocol);
		}
		return (EAFNOSUPPORT);
	}

	retval_socket = kern_socket(td, domain, type, args->protocol);
	/* Linux: an AF_VSOCK type the transport lacks is ESOCKTNOSUPPORT. */
	if (retval_socket == EPROTOTYPE && domain == AF_VSOCK)
		retval_socket = ESOCKTNOSUPPORT;
	if (retval_socket)
		return (retval_socket);

	if (type == SOCK_RAW
	    && (args->protocol == IPPROTO_RAW || args->protocol == 0)
	    && domain == PF_INET) {
		/* It's a raw IP socket: set the IP_HDRINCL option. */
		int hdrincl;

		hdrincl = 1;
		/* We ignore any error returned by kern_setsockopt() */
		kern_setsockopt(td, td->td_retval[0], IPPROTO_IP, IP_HDRINCL,
		    &hdrincl, UIO_SYSSPACE, sizeof(hdrincl));
	}
#ifdef INET6
	/*
	 * Linux AF_INET6 socket has IPV6_V6ONLY setsockopt set to 0 by default
	 * and some apps depend on this. So, set V6ONLY to 0 for Linux apps.
	 * For simplicity we do this unconditionally of the net.inet6.ip6.v6only
	 * sysctl value.
	 */
	if (domain == PF_INET6) {
		int v6only;

		v6only = 0;
		/* We ignore any error returned by setsockopt() */
		kern_setsockopt(td, td->td_retval[0], IPPROTO_IPV6, IPV6_V6ONLY,
		    &v6only, UIO_SYSSPACE, sizeof(v6only));
	}
#endif

	return (retval_socket);
}

int
linux_bind(struct thread *td, struct linux_bind_args *args)
{
	struct sockaddr *sa;
	int error;

	error = linux_to_bsd_sockaddr(PTRIN(args->name), &sa,
	    &args->namelen);
	if (error != 0)
		return (error);

	error = kern_bindat(td, AT_FDCWD, args->s, sa);
	free(sa, M_SONAME);

	/* XXX */
	if (error == EADDRNOTAVAIL && args->namelen != sizeof(struct sockaddr_in))
		return (EINVAL);
	return (error);
}

int
linux_connect(struct thread *td, struct linux_connect_args *args)
{
	struct socket *so;
	struct sockaddr *sa;
	struct file *fp;
	int error;

	error = linux_to_bsd_sockaddr(PTRIN(args->name), &sa,
	    &args->namelen);
	if (error != 0)
		return (error);

	error = kern_connectat(td, AT_FDCWD, args->s, sa);
	free(sa, M_SONAME);
	if (error != EISCONN)
		return (error);

	/*
	 * Linux doesn't return EISCONN the first time it occurs,
	 * when on a non-blocking socket. Instead it returns the
	 * error getsockopt(SOL_SOCKET, SO_ERROR) would return on BSD.
	 */
	error = getsock(td, args->s, &cap_connect_rights, &fp);
	if (error != 0)
		return (error);

	error = EISCONN;
	so = fp->f_data;
	if (atomic_load_int(&fp->f_flag) & FNONBLOCK) {
		SOCK_LOCK(so);
		if (so->so_emuldata == 0)
			error = so->so_error;
		so->so_emuldata = (void *)1;
		SOCK_UNLOCK(so);
	}
	fdrop(fp, td);

	return (error);
}

int
linux_listen(struct thread *td, struct linux_listen_args *args)
{

	return (kern_listen(td, args->s, args->backlog));
}

static int
linux_accept_common(struct thread *td, int s, l_uintptr_t addr,
    l_uintptr_t namelen, int flags)
{
	struct sockaddr_storage ss = { .ss_len = sizeof(ss) };
	struct file *fp, *fp1;
	struct socket *so;
	socklen_t len;
	int bflags, error, error1;

	bflags = 0;
	fp = NULL;

	error = linux_set_socket_flags(flags, &bflags);
	if (error != 0)
		return (error);

	if (PTRIN(addr) != NULL) {
		error = copyin(PTRIN(namelen), &len, sizeof(len));
		if (error != 0)
			return (error);
		if (len < 0)
			return (EINVAL);
	} else
		len = 0;

	error = kern_accept4(td, s, (struct sockaddr *)&ss, bflags, &fp);

	/*
	 * Translate errno values into ones used by Linux.
	 */
	if (error != 0) {
		/*
		 * XXX. This is wrong, different sockaddr structures
		 * have different sizes.
		 */
		switch (error) {
		case EFAULT:
			if (namelen != sizeof(struct sockaddr_in))
				error = EINVAL;
			break;
		case EINVAL:
			error1 = getsock(td, s, &cap_accept_rights, &fp1);
			if (error1 != 0) {
				error = error1;
				break;
			}
			so = fp1->f_data;
			if (so->so_type == SOCK_DGRAM)
				error = EOPNOTSUPP;
			fdrop(fp1, td);
			break;
		}
		return (error);
	}

	if (PTRIN(addr) != NULL) {
		len = min(ss.ss_len, len);
		error = linux_copyout_sockaddr((struct sockaddr *)&ss,
		    PTRIN(addr), len);
		if (error == 0) {
			len = ss.ss_len;
			error = copyout(&len, PTRIN(namelen), sizeof(len));
		}
		if (error != 0) {
			fdclose(td, fp, td->td_retval[0]);
			td->td_retval[0] = 0;
		}
	}
	if (fp != NULL)
		fdrop(fp, td);
	return (error);
}

int
linux_accept(struct thread *td, struct linux_accept_args *args)
{

	return (linux_accept_common(td, args->s, args->addr,
	    args->namelen, 0));
}

int
linux_accept4(struct thread *td, struct linux_accept4_args *args)
{

	return (linux_accept_common(td, args->s, args->addr,
	    args->namelen, args->flags));
}

int
linux_getsockname(struct thread *td, struct linux_getsockname_args *args)
{
	struct sockaddr_storage ss = { .ss_len = sizeof(ss) };
	socklen_t len;
	int error;

	error = copyin(PTRIN(args->namelen), &len, sizeof(len));
	if (error != 0)
		return (error);

	error = kern_getsockname(td, args->s, (struct sockaddr *)&ss);
	if (error != 0)
		return (error);

	len = min(ss.ss_len, len);
	error = linux_copyout_sockaddr((struct sockaddr *)&ss,
	    PTRIN(args->addr), len);
	if (error == 0) {
		len = ss.ss_len;
		error = copyout(&len, PTRIN(args->namelen), sizeof(len));
	}
	return (error);
}

int
linux_getpeername(struct thread *td, struct linux_getpeername_args *args)
{
	struct sockaddr_storage ss = { .ss_len = sizeof(ss) };
	socklen_t len;
	int error;

	error = copyin(PTRIN(args->namelen), &len, sizeof(len));
	if (error != 0)
		return (error);

	error = kern_getpeername(td, args->s, (struct sockaddr *)&ss);
	if (error != 0)
		return (error);

	len = min(ss.ss_len, len);
	error = linux_copyout_sockaddr((struct sockaddr *)&ss,
	    PTRIN(args->addr), len);
	if (error == 0) {
		len = ss.ss_len;
		error = copyout(&len, PTRIN(args->namelen), sizeof(len));
	}
	return (error);
}

int
linux_socketpair(struct thread *td, struct linux_socketpair_args *args)
{
	int domain, error, sv[2], type;

	domain = linux_to_bsd_domain(args->domain);
	if (domain != PF_LOCAL)
		return (EAFNOSUPPORT);
	type = args->type & LINUX_SOCK_TYPE_MASK;
	if (type < 0 || type > LINUX_SOCK_MAX)
		return (EINVAL);
	error = linux_set_socket_flags(args->type & ~LINUX_SOCK_TYPE_MASK,
	    &type);
	if (error != 0)
		return (error);
	if (args->protocol != 0 && args->protocol != PF_UNIX) {
		/*
		 * Use of PF_UNIX as protocol argument is not right,
		 * but Linux does it.
		 * Do not map PF_UNIX as its Linux value is identical
		 * to FreeBSD one.
		 */
		return (EPROTONOSUPPORT);
	}
	error = kern_socketpair(td, domain, type, 0, sv);
	if (error != 0)
                return (error);
        error = copyout(sv, PTRIN(args->rsv), 2 * sizeof(int));
        if (error != 0) {
                (void)kern_close(td, sv[0]);
                (void)kern_close(td, sv[1]);
        }
	return (error);
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
struct linux_send_args {
	register_t s;
	register_t msg;
	register_t len;
	register_t flags;
};

static int
linux_send(struct thread *td, struct linux_send_args *args)
{
	struct sendto_args /* {
		int s;
		caddr_t buf;
		int len;
		int flags;
		caddr_t to;
		int tolen;
	} */ bsd_args;
	struct file *fp;
	int error;

	bsd_args.s = args->s;
	bsd_args.buf = (caddr_t)PTRIN(args->msg);
	bsd_args.len = args->len;
	bsd_args.flags = linux_to_bsd_msg_flags(args->flags);
	bsd_args.to = NULL;
	bsd_args.tolen = 0;
	error = sys_sendto(td, &bsd_args);
	if (error == ENOTCONN) {
		/*
		 * Linux doesn't return ENOTCONN for non-blocking sockets.
		 * Instead it returns the EAGAIN.
		 */
		error = getsock(td, args->s, &cap_send_rights, &fp);
		if (error == 0) {
			if (atomic_load_int(&fp->f_flag) & FNONBLOCK)
				error = EAGAIN;
			fdrop(fp, td);
		}
	}
	return (error);
}

struct linux_recv_args {
	register_t s;
	register_t msg;
	register_t len;
	register_t flags;
};

static int
linux_recv(struct thread *td, struct linux_recv_args *args)
{
	struct recvfrom_args /* {
		int s;
		caddr_t buf;
		int len;
		int flags;
		struct sockaddr *from;
		socklen_t fromlenaddr;
	} */ bsd_args;

	bsd_args.s = args->s;
	bsd_args.buf = (caddr_t)PTRIN(args->msg);
	bsd_args.len = args->len;
	bsd_args.flags = linux_to_bsd_msg_flags(args->flags);
	bsd_args.from = NULL;
	bsd_args.fromlenaddr = 0;
	return (sys_recvfrom(td, &bsd_args));
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

int
linux_sendto(struct thread *td, struct linux_sendto_args *args)
{
	struct msghdr msg;
	struct iovec aiov;
	struct socket *so;
	struct file *fp;
	int error;

	if (linux_check_hdrincl(td, args->s) == 0)
		/* IP_HDRINCL set, tweak the packet before sending */
		return (linux_sendto_hdrincl(td, args));

	bzero(&msg, sizeof(msg));
	error = getsock(td, args->s, &cap_send_connect_rights, &fp);
	if (error != 0)
		return (error);
	so = fp->f_data;
	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0) {
		msg.msg_name = PTRIN(args->to);
		msg.msg_namelen = args->tolen;
	}
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = PTRIN(args->msg);
	aiov.iov_len = args->len;
	fdrop(fp, td);
	return (linux_sendit(td, args->s, &msg, args->flags, NULL,
	    UIO_USERSPACE));
}

int
linux_recvfrom(struct thread *td, struct linux_recvfrom_args *args)
{
	struct sockaddr *sa;
	struct msghdr msg;
	struct iovec aiov;
	int error, fromlen;

	if (PTRIN(args->fromlen) != NULL) {
		error = copyin(PTRIN(args->fromlen), &fromlen,
		    sizeof(fromlen));
		if (error != 0)
			return (error);
		if (fromlen < 0)
			return (EINVAL);
		fromlen = min(fromlen, SOCK_MAXADDRLEN);
		sa = malloc(fromlen, M_SONAME, M_WAITOK);
	} else {
		fromlen = 0;
		sa = NULL;
	}

	msg.msg_name = sa;
	msg.msg_namelen = fromlen;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = PTRIN(args->buf);
	aiov.iov_len = args->len;
	msg.msg_control = 0;
	msg.msg_flags = linux_to_bsd_msg_flags(args->flags);

	error = kern_recvit(td, args->s, &msg, UIO_SYSSPACE, NULL);
	if (error != 0)
		goto out;

	/*
	 * XXX. Seems that FreeBSD is different from Linux here. Linux
	 * fill source address if underlying protocol provides it, while
	 * FreeBSD fill it if underlying protocol is not connection-oriented.
	 * So, kern_recvit() set msg.msg_namelen to 0 if protocol pr_flags
	 * does not contains PR_ADDR flag.
	 */
	if (PTRIN(args->from) != NULL && msg.msg_namelen != 0)
		error = linux_copyout_sockaddr(sa, PTRIN(args->from),
		    msg.msg_namelen);

	if (error == 0 && PTRIN(args->fromlen) != NULL)
		error = copyout(&msg.msg_namelen, PTRIN(args->fromlen),
		    sizeof(msg.msg_namelen));
out:
	free(sa, M_SONAME);
	return (error);
}

/* Ancillary data accepted by sendmsg() at IPPROTO_IP. */
static int
linux_to_bsd_ip_scmsg_type(int cmsg_type)
{

	switch (cmsg_type) {
	case LINUX_IP_PKTINFO:
		return (IP_SENDSRCADDR);
	case LINUX_IP_TOS:
		return (IP_TOS);
	}
	/* IP_TTL, IP_RETOPTS: no per-datagram support in udp_output(). */
	return (-1);
}

#ifdef INET6
/* Ancillary data accepted by sendmsg() at IPPROTO_IPV6. */
static int
linux_to_bsd_ip6_scmsg_type(int cmsg_type)
{

	switch (cmsg_type) {
	case LINUX_IPV6_PKTINFO:
		return (IPV6_PKTINFO);
	case LINUX_IPV6_2292PKTINFO:
		return (IPV6_2292PKTINFO);
	case LINUX_IPV6_HOPLIMIT:
		return (IPV6_HOPLIMIT);
	case LINUX_IPV6_2292HOPLIMIT:
		return (IPV6_2292HOPLIMIT);
	case LINUX_IPV6_TCLASS:
		return (IPV6_TCLASS);
	case LINUX_IPV6_DONTFRAG:
		return (IPV6_DONTFRAG);
	case LINUX_IPV6_HOPOPTS:
		return (IPV6_HOPOPTS);
	case LINUX_IPV6_2292HOPOPTS:
		return (IPV6_2292HOPOPTS);
	case LINUX_IPV6_DSTOPTS:
		return (IPV6_DSTOPTS);
	case LINUX_IPV6_2292DSTOPTS:
		return (IPV6_2292DSTOPTS);
	case LINUX_IPV6_RTHDRDSTOPTS:
		return (IPV6_RTHDRDSTOPTS);
	case LINUX_IPV6_RTHDR:
		return (IPV6_RTHDR);
	case LINUX_IPV6_2292RTHDR:
		return (IPV6_2292RTHDR);
	}
	return (-1);
}
#endif

/*
 * Copy in and translate the payload of an IPPROTO_IP / IPPROTO_IPV6
 * control message.  On return *lenp is the FreeBSD payload length, or 0
 * when the message carries nothing FreeBSD needs to see.
 */
static int
linux_sendmsg_ip_cmsg(const struct l_cmsghdr *lcmsg,
    struct l_cmsghdr *ucmsg, struct cmsghdr *cmsg, size_t avail,
    const struct sockaddr_storage *local, l_size_t *lenp)
{
	struct l_in_pktinfo pki;
	const struct sockaddr_in *lsin;
	l_size_t len;
	u_char tos;
	int error, ival;

	len = lcmsg->cmsg_len - L_CMSG_HDRSZ;
	*lenp = 0;
	/* Translated payloads are never longer than the Linux ones. */
	if (len > avail || CMSG_SPACE(len) > avail)
		return (EINVAL);
	if (cmsg->cmsg_level == IPPROTO_IP &&
	    cmsg->cmsg_type == IP_SENDSRCADDR) {
		if (len != sizeof(pki))
			return (EINVAL);
		error = copyin(LINUX_CMSG_DATA(ucmsg), &pki, sizeof(pki));
		if (error != 0)
			return (error);
		/* An output interface can not be forced per datagram. */
		if (pki.ipi_ifindex != 0)
			return (EINVAL);
		if (pki.ipi_spec_dst == INADDR_ANY)
			return (0);
		/*
		 * udp_output() refuses IP_SENDSRCADDR on a socket bound to
		 * a specific address; naming that same address is a no-op.
		 */
		lsin = (const struct sockaddr_in *)local;
		if (local->ss_family == AF_INET &&
		    lsin->sin_addr.s_addr == pki.ipi_spec_dst)
			return (0);
		memcpy(CMSG_DATA(cmsg), &pki.ipi_spec_dst,
		    sizeof(pki.ipi_spec_dst));
		*lenp = sizeof(pki.ipi_spec_dst);
		return (0);
	}
	if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) {
		/* Linux accepts an int or a u8; udp_output() wants u_char. */
		if (len == sizeof(ival)) {
			error = copyin(LINUX_CMSG_DATA(ucmsg), &ival,
			    sizeof(ival));
			if (error != 0)
				return (error);
			if (ival < 0 || ival > 255)
				return (EINVAL);
			tos = ival;
		} else if (len == sizeof(tos)) {
			error = copyin(LINUX_CMSG_DATA(ucmsg), &tos,
			    sizeof(tos));
			if (error != 0)
				return (error);
		} else
			return (EINVAL);
		*(u_char *)CMSG_DATA(cmsg) = tos;
		*lenp = sizeof(tos);
		return (0);
	}
	/*
	 * IPv6: struct in6_pktinfo, the ints and the raw extension
	 * headers share their layout with Linux.
	 */
	error = copyin(LINUX_CMSG_DATA(ucmsg), CMSG_DATA(cmsg), len);
	if (error != 0)
		return (error);
	*lenp = len;
	return (0);
}

static int
linux_sendmsg_common(struct thread *td, l_int s, struct l_msghdr *msghdr,
    l_uint flags)
{
	struct sockaddr_storage ss = { .ss_len = sizeof(ss) };
	struct cmsghdr *cmsg;
	struct mbuf *control;
	struct msghdr msg;
	struct l_cmsghdr linux_cmsg;
	struct l_cmsghdr *ptr_cmsg;
	struct l_msghdr linux_msghdr;
	struct iovec *iov;
	socklen_t datalen;
	struct socket *so;
	sa_family_t sa_family;
	struct file *fp;
	void *data;
	l_size_t len;
	l_size_t clen;
	int error;

	error = copyin(msghdr, &linux_msghdr, sizeof(linux_msghdr));
	if (error != 0)
		return (error);

	/*
	 * Some Linux applications (ping) define a non-NULL control data
	 * pointer, but a msg_controllen of 0, which is not allowed in the
	 * FreeBSD system call interface.  NULL the msg_control pointer in
	 * order to handle this case.  This should be checked, but allows the
	 * Linux ping to work.
	 */
	if (PTRIN(linux_msghdr.msg_control) != NULL &&
	    linux_msghdr.msg_controllen == 0)
		linux_msghdr.msg_control = PTROUT(NULL);

	error = linux_to_bsd_msghdr(&msg, &linux_msghdr);
	if (error != 0)
		return (error);

#ifdef COMPAT_LINUX32
	error = freebsd32_copyiniov(PTRIN(msg.msg_iov), msg.msg_iovlen,
	    &iov, EMSGSIZE);
#else
	error = copyiniov(msg.msg_iov, msg.msg_iovlen, &iov, EMSGSIZE);
#endif
	if (error != 0)
		return (error);

	control = NULL;

	error = kern_getsockname(td, s, (struct sockaddr *)&ss);
	if (error != 0)
		goto bad;
	sa_family = ss.ss_family;

	if (flags & LINUX_MSG_OOB) {
		error = EOPNOTSUPP;
		if (sa_family == AF_UNIX)
			goto bad;

		error = getsock(td, s, &cap_send_rights, &fp);
		if (error != 0)
			goto bad;
		so = fp->f_data;
		if (so->so_type != SOCK_STREAM)
			error = EOPNOTSUPP;
		fdrop(fp, td);
		if (error != 0)
			goto bad;
	}

	if (linux_msghdr.msg_controllen >= sizeof(struct l_cmsghdr)) {
		error = ENOBUFS;
		control = m_get(M_WAITOK, MT_CONTROL);
		MCLGET(control, M_WAITOK);
		data = mtod(control, void *);
		datalen = 0;

		ptr_cmsg = PTRIN(linux_msghdr.msg_control);
		clen = linux_msghdr.msg_controllen;
		do {
			error = copyin(ptr_cmsg, &linux_cmsg,
			    sizeof(struct l_cmsghdr));
			if (error != 0)
				goto bad;

			error = EINVAL;
			if (linux_cmsg.cmsg_len < sizeof(struct l_cmsghdr) ||
			    linux_cmsg.cmsg_len > clen)
				goto bad;

			if (datalen + CMSG_HDRSZ > MCLBYTES)
				goto bad;

			cmsg = data;
			cmsg->cmsg_level =
			    linux_to_bsd_sockopt_level(linux_cmsg.cmsg_level);
			switch (cmsg->cmsg_level) {
			case SOL_SOCKET:
				cmsg->cmsg_type = linux_to_bsd_cmsg_type(
				    linux_cmsg.cmsg_type);
				break;
			case IPPROTO_IP:
				cmsg->cmsg_type = linux_to_bsd_ip_scmsg_type(
				    linux_cmsg.cmsg_type);
				break;
#ifdef INET6
			case IPPROTO_IPV6:
				cmsg->cmsg_type = linux_to_bsd_ip6_scmsg_type(
				    linux_cmsg.cmsg_type);
				break;
#endif
			default:
				cmsg->cmsg_type = -1;
				break;
			}
			if (cmsg->cmsg_type == -1) {
				linux_msg(curthread,
				    "unsupported sendmsg cmsg level %d type %d",
				    linux_cmsg.cmsg_level, linux_cmsg.cmsg_type);
				goto bad;
			}

			if (cmsg->cmsg_level != SOL_SOCKET) {
				/*
				 * Linux ignores IP-level ancillary data on
				 * sockets of other families.
				 */
				if (sa_family != AF_INET &&
				    sa_family != AF_INET6)
					goto next;
				error = linux_sendmsg_ip_cmsg(&linux_cmsg,
				    ptr_cmsg, cmsg, MCLBYTES - datalen, &ss,
				    &len);
				if (error != 0)
					goto bad;
				if (len == 0)
					goto next;
				cmsg->cmsg_len = CMSG_LEN(len);
				data = (char *)data + CMSG_SPACE(len);
				datalen += CMSG_SPACE(len);
				goto next;
			}

			/*
			 * Some applications (e.g. pulseaudio) attempt to
			 * send ancillary data even if the underlying protocol
			 * doesn't support it which is not allowed in the
			 * FreeBSD system call interface.
			 */
			if (sa_family != AF_UNIX)
				goto next;

			if (cmsg->cmsg_type == SCM_CREDS) {
				len = sizeof(struct cmsgcred);
				if (datalen + CMSG_SPACE(len) > MCLBYTES)
					goto bad;

				/*
				 * The lower levels will fill in the structure
				 */
				memset(CMSG_DATA(data), 0, len);
			} else {
				len = linux_cmsg.cmsg_len - L_CMSG_HDRSZ;
				if (datalen + CMSG_SPACE(len) < datalen ||
				    datalen + CMSG_SPACE(len) > MCLBYTES)
					goto bad;

				error = copyin(LINUX_CMSG_DATA(ptr_cmsg),
				    CMSG_DATA(data), len);
				if (error != 0)
					goto bad;
			}

			cmsg->cmsg_len = CMSG_LEN(len);
			data = (char *)data + CMSG_SPACE(len);
			datalen += CMSG_SPACE(len);

next:
			if (clen <= LINUX_CMSG_ALIGN(linux_cmsg.cmsg_len))
				break;

			clen -= LINUX_CMSG_ALIGN(linux_cmsg.cmsg_len);
			ptr_cmsg = (struct l_cmsghdr *)((char *)ptr_cmsg +
			    LINUX_CMSG_ALIGN(linux_cmsg.cmsg_len));
		} while(clen >= sizeof(struct l_cmsghdr));

		control->m_len = datalen;
		if (datalen == 0) {
			m_freem(control);
			control = NULL;
		}
	}

	msg.msg_iov = iov;
	msg.msg_flags = 0;
	error = linux_sendit(td, s, &msg, flags, control, UIO_USERSPACE);
	control = NULL;

bad:
	m_freem(control);
	free(iov, M_IOV);
	return (error);
}

int
linux_sendmsg(struct thread *td, struct linux_sendmsg_args *args)
{

	return (linux_sendmsg_common(td, args->s, PTRIN(args->msg),
	    args->flags));
}

int
linux_sendmmsg(struct thread *td, struct linux_sendmmsg_args *args)
{
	struct l_mmsghdr *msg;
	l_uint retval;
	int error, datagrams;

	if (args->vlen > UIO_MAXIOV)
		args->vlen = UIO_MAXIOV;

	msg = PTRIN(args->msg);
	datagrams = 0;
	while (datagrams < args->vlen) {
		error = linux_sendmsg_common(td, args->s, &msg->msg_hdr,
		    args->flags);
		if (error != 0)
			break;

		retval = td->td_retval[0];
		error = copyout(&retval, &msg->msg_len, sizeof(msg->msg_len));
		if (error != 0)
			break;
		++msg;
		++datagrams;
	}
	if (error == 0)
		td->td_retval[0] = datagrams;
	return (error);
}

static int
recvmsg_scm_rights(struct thread *td, l_uint flags, socklen_t *datalen,
    void **data, void **udata)
{
	int i, fd, fds, *fdp;

	if (flags & LINUX_MSG_CMSG_CLOEXEC) {
		fds = *datalen / sizeof(int);
		fdp = *data;
		for (i = 0; i < fds; i++) {
			fd = *fdp++;
			(void)kern_fcntl(td, fd, F_SETFD, FD_CLOEXEC);
		}
	}
	return (0);
}


static int
recvmsg_scm_creds(socklen_t *datalen, void **data, void **udata)
{
	struct cmsgcred *cmcred;
	struct l_ucred lu;

	cmcred = *data;
	lu.pid = cmcred->cmcred_pid;
	lu.uid = cmcred->cmcred_uid;
	lu.gid = cmcred->cmcred_gid;
	memmove(*data, &lu, sizeof(lu));
	*datalen = sizeof(lu);
	return (0);
}
_Static_assert(sizeof(struct cmsgcred) >= sizeof(struct l_ucred),
    "scm_creds sizeof l_ucred");

static int
recvmsg_scm_creds2(socklen_t *datalen, void **data, void **udata)
{
	struct sockcred2 *scred;
	struct l_ucred lu;

	scred = *data;
	lu.pid = scred->sc_pid;
	lu.uid = scred->sc_uid;
	lu.gid = scred->sc_gid;
	memmove(*data, &lu, sizeof(lu));
	*datalen = sizeof(lu);
	return (0);
}
_Static_assert(sizeof(struct sockcred2) >= sizeof(struct l_ucred),
    "scm_creds2 sizeof l_ucred");

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
static int
recvmsg_scm_timestamp(l_int msg_type, socklen_t *datalen, void **data,
    void **udata)
{
	l_sock_timeval ltv64;
	l_timeval ltv;
	struct timeval *tv;
	socklen_t len;
	void *buf;

	if (*datalen != sizeof(struct timeval))
		return (EMSGSIZE);

	tv = *data;
#if defined(COMPAT_LINUX32)
	if (msg_type == LINUX_SCM_TIMESTAMPO &&
	    (tv->tv_sec > INT_MAX || tv->tv_sec < INT_MIN))
		return (EOVERFLOW);
#endif
	if (msg_type == LINUX_SCM_TIMESTAMPN)
		len = sizeof(ltv64);
	else
		len = sizeof(ltv);

	buf = malloc(len, M_LINUX, M_WAITOK);
	if (msg_type == LINUX_SCM_TIMESTAMPN) {
		ltv64.tv_sec = tv->tv_sec;
		ltv64.tv_usec = tv->tv_usec;
		memmove(buf, &ltv64, len);
	} else {
		ltv.tv_sec = tv->tv_sec;
		ltv.tv_usec = tv->tv_usec;
		memmove(buf, &ltv, len);
	}
	*data = *udata = buf;
	*datalen = len;
	return (0);
}
#else
_Static_assert(sizeof(struct timeval) == sizeof(l_timeval),
    "scm_timestamp sizeof l_timeval");
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
static int
recvmsg_scm_timestampns(l_int msg_type, socklen_t *datalen, void **data,
    void **udata)
{
	struct l_timespec64 ts64;
	struct l_timespec ts32;
	struct timespec ts;
	socklen_t len;
	void *buf;

	if (msg_type == LINUX_SCM_TIMESTAMPNSO)
		len = sizeof(ts32);
	else
		len = sizeof(ts64);

	buf = malloc(len, M_LINUX, M_WAITOK);
	bintime2timespec(*data, &ts);
	if (msg_type == LINUX_SCM_TIMESTAMPNSO) {
		ts32.tv_sec = ts.tv_sec;
		ts32.tv_nsec = ts.tv_nsec;
		memmove(buf, &ts32, len);
	} else {
		ts64.tv_sec = ts.tv_sec;
		ts64.tv_nsec = ts.tv_nsec;
		memmove(buf, &ts64, len);
	}
	*data = *udata = buf;
	*datalen = len;
	return (0);
}
#else
static int
recvmsg_scm_timestampns(l_int msg_type, socklen_t *datalen, void **data,
    void **udata)
{
	struct timespec ts;

	bintime2timespec(*data, &ts);
	memmove(*data, &ts, sizeof(struct timespec));
	*datalen = sizeof(struct timespec);
	return (0);
}
_Static_assert(sizeof(struct bintime) >= sizeof(struct timespec),
    "scm_timestampns sizeof timespec");
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

static int
recvmsg_scm_sol_socket(struct thread *td, l_int msg_type, l_int lmsg_type,
    l_uint flags, socklen_t *datalen, void **data, void **udata)
{
	int error;

	error = 0;
	switch (msg_type) {
	case SCM_RIGHTS:
		error = recvmsg_scm_rights(td, flags, datalen,
		    data, udata);
		break;
	case SCM_CREDS:
		error = recvmsg_scm_creds(datalen, data, udata);
		break;
	case SCM_CREDS2:
		error = recvmsg_scm_creds2(datalen, data, udata);
		break;
	case SCM_TIMESTAMP:
#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
		error = recvmsg_scm_timestamp(lmsg_type, datalen,
		    data, udata);
#endif
		break;
	case SCM_BINTIME:
		error = recvmsg_scm_timestampns(lmsg_type, datalen,
		    data, udata);
		break;
	}

	return (error);
}

static int
recvmsg_scm_ip_origdstaddr(socklen_t *datalen, void **data, void **udata)
{
	struct l_sockaddr *lsa;
	int error;

	error = bsd_to_linux_sockaddr(*data, &lsa, *datalen);
	if (error == 0) {
		*data = *udata = lsa;
		*datalen = sizeof(*lsa);
	}
	return (error);
}

/* Linux delivers the TTL as an int; FreeBSD as a u_char. */
static int
recvmsg_scm_ip_ttl(socklen_t *datalen, void **data, void **udata)
{
	int *ttl;

	if (*datalen < sizeof(u_char))
		return (EINVAL);
	ttl = malloc(sizeof(*ttl), M_LINUX, M_WAITOK);
	*ttl = *(u_char *)*data;
	*data = *udata = ttl;
	*datalen = sizeof(*ttl);
	return (0);
}

/*
 * IP_RECVIF (a sockaddr_dl) closes the IP_PKTINFO pair opened by
 * IP_RECVDSTADDR; build the struct in_pktinfo.  FreeBSD has no
 * "specific destination", so ipi_spec_dst repeats the header address.
 */
static int
recvmsg_scm_ip_pktinfo(struct l_in_pktinfo *pki, socklen_t *datalen,
    void **data, void **udata)
{
	struct l_in_pktinfo *lpki;
	struct sockaddr_dl *sdl;

	if (*datalen < offsetof(struct sockaddr_dl, sdl_data))
		return (EINVAL);
	sdl = *data;
	lpki = malloc(sizeof(*lpki), M_LINUX, M_WAITOK);
	lpki->ipi_ifindex = sdl->sdl_index;
	lpki->ipi_addr = pki->ipi_addr;
	lpki->ipi_spec_dst = pki->ipi_addr;
	*data = *udata = lpki;
	*datalen = sizeof(*lpki);
	return (0);
}

static int
recvmsg_scm_ipproto_ip(l_int msg_type, l_int lmsg_type, socklen_t *datalen,
    void **data, void **udata, struct l_in_pktinfo *pki)
{
	int error;

	error = 0;
	switch (msg_type) {
	case IP_ORIGDSTADDR:
		error = recvmsg_scm_ip_origdstaddr(datalen, data,
		    udata);
		break;
	case IP_RECVTTL:
		error = recvmsg_scm_ip_ttl(datalen, data, udata);
		break;
	case IP_RECVIF:
		error = recvmsg_scm_ip_pktinfo(pki, datalen, data, udata);
		break;
	}

	return (error);
}

#ifdef INET6
static int
recvmsg_scm_ip6_sockaddr(socklen_t *datalen, void **data, void **udata)
{
	struct l_sockaddr_in6 *lsin6;

	if (*datalen < sizeof(struct sockaddr_in6))
		return (EINVAL);
	lsin6 = malloc(sizeof(*lsin6), M_LINUX, M_WAITOK);
	bsd_to_linux_sockaddr_in6(*data, lsin6);
	*data = *udata = lsin6;
	*datalen = sizeof(*lsin6);
	return (0);
}

static int
recvmsg_scm_ip6_mtuinfo(socklen_t *datalen, void **data, void **udata)
{
	struct l_ip6_mtuinfo *lmi;

	if (*datalen < sizeof(struct ip6_mtuinfo))
		return (EINVAL);
	lmi = malloc(sizeof(*lmi), M_LINUX, M_WAITOK);
	bsd_to_linux_ip6_mtuinfo(*data, lmi);
	*data = *udata = lmi;
	*datalen = sizeof(*lmi);
	return (0);
}

static int
recvmsg_scm_ipproto_ipv6(l_int msg_type, socklen_t *datalen, void **data,
    void **udata)
{
	int error;

	error = 0;
	switch (msg_type) {
	case IPV6_ORIGDSTADDR:
		error = recvmsg_scm_ip6_sockaddr(datalen, data, udata);
		break;
	case IPV6_PATHMTU:
		error = recvmsg_scm_ip6_mtuinfo(datalen, data, udata);
		break;
	}

	return (error);
}
#endif

static int
linux_recvmsg_common(struct thread *td, l_int s, struct l_msghdr *msghdr,
    l_uint flags, struct msghdr *msg)
{
	struct proc *p = td->td_proc;
	struct cmsghdr *cm;
	struct l_cmsghdr *lcm = NULL;
	socklen_t datalen, maxlen, outlen;
	struct l_msghdr l_msghdr;
	struct iovec *iov, *uiov;
	struct mbuf *m, *control = NULL;
	struct mbuf **controlp;
	struct sockaddr *sa;
	struct l_in_pktinfo pki;
	caddr_t outbuf;
	void *data, *udata;
	int error, skiped;

	memset(&pki, 0, sizeof(pki));
	error = copyin(msghdr, &l_msghdr, sizeof(l_msghdr));
	if (error != 0)
		return (error);

	/*
	 * Pass user-supplied recvmsg() flags in msg_flags field,
	 * following sys_recvmsg() convention.
	*/
	l_msghdr.msg_flags = flags;

	error = linux_to_bsd_msghdr(msg, &l_msghdr);
	if (error != 0)
		return (error);

#ifdef COMPAT_LINUX32
	error = freebsd32_copyiniov(PTRIN(msg->msg_iov), msg->msg_iovlen,
	    &iov, EMSGSIZE);
#else
	error = copyiniov(msg->msg_iov, msg->msg_iovlen, &iov, EMSGSIZE);
#endif
	if (error != 0)
		return (error);

	if (msg->msg_name != NULL && msg->msg_namelen > 0) {
		msg->msg_namelen = min(msg->msg_namelen, SOCK_MAXADDRLEN);
		sa = malloc(msg->msg_namelen, M_SONAME, M_WAITOK);
		msg->msg_name = sa;
	} else {
		sa = NULL;
		msg->msg_name = NULL;
	}

	uiov = msg->msg_iov;
	msg->msg_iov = iov;
	controlp = (msg->msg_control != NULL) ? &control : NULL;
	error = kern_recvit(td, s, msg, UIO_SYSSPACE, controlp);
	msg->msg_iov = uiov;
	if (error != 0)
		goto bad;

	/*
	 * Note that kern_recvit() updates msg->msg_namelen.
	 */
	if (msg->msg_name != NULL && msg->msg_namelen > 0) {
		msg->msg_name = PTRIN(l_msghdr.msg_name);
		error = linux_copyout_sockaddr(sa, msg->msg_name,
		    msg->msg_namelen);
		if (error != 0)
			goto bad;
	}

	error = bsd_to_linux_msghdr(msg, &l_msghdr);
	if (error != 0)
		goto bad;

	skiped = outlen = 0;
	maxlen = l_msghdr.msg_controllen;
	if (control == NULL)
		goto out;

	lcm = malloc(L_CMSG_HDRSZ, M_LINUX, M_WAITOK | M_ZERO);
	msg->msg_control = mtod(control, struct cmsghdr *);
	msg->msg_controllen = control->m_len;
	outbuf = PTRIN(l_msghdr.msg_control);
	for (m = control; m != NULL; m = m->m_next) {
		cm = mtod(m, struct cmsghdr *);
		if (cm->cmsg_level == IPPROTO_IP &&
		    cm->cmsg_type == IP_RECVDSTADDR) {
			/*
			 * First half of IP_PKTINFO; ip_savecontrol()
			 * emits IP_RECVIF after it.
			 */
			if ((caddr_t)cm + cm->cmsg_len - (caddr_t)CMSG_DATA(cm)
			    >= sizeof(struct in_addr))
				memcpy(&pki.ipi_addr, CMSG_DATA(cm),
				    sizeof(pki.ipi_addr));
			continue;
		}
		lcm->cmsg_type = bsd_to_linux_cmsg_type(p, cm->cmsg_type,
		    cm->cmsg_level);
		lcm->cmsg_level = bsd_to_linux_sockopt_level(cm->cmsg_level);

		if (lcm->cmsg_type == -1 ||
		    lcm->cmsg_level == -1) {
			LINUX_RATELIMIT_MSG_OPT2(
			    "unsupported recvmsg cmsg level %d type %d",
			    cm->cmsg_level, cm->cmsg_type);
			/* Skip unsupported messages */
			skiped++;
			continue;
		}
		data = CMSG_DATA(cm);
		datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;
		udata = NULL;
		error = 0;

		switch (cm->cmsg_level) {
		case IPPROTO_IP:
			error = recvmsg_scm_ipproto_ip(cm->cmsg_type,
			    lcm->cmsg_type, &datalen, &data, &udata, &pki);
 			break;
#ifdef INET6
		case IPPROTO_IPV6:
			error = recvmsg_scm_ipproto_ipv6(cm->cmsg_type,
			    &datalen, &data, &udata);
			break;
#endif
		case SOL_SOCKET:
			error = recvmsg_scm_sol_socket(td, cm->cmsg_type,
			    lcm->cmsg_type, flags, &datalen, &data, &udata);
 			break;
 		}

		/* The recvmsg_scm_ is responsible to free udata on error. */
		if (error != 0)
			goto bad;

		if (outlen + LINUX_CMSG_LEN(datalen) > maxlen) {
			if (outlen == 0) {
				error = EMSGSIZE;
				goto err;
			} else {
				l_msghdr.msg_flags |= LINUX_MSG_CTRUNC;
				m_dispose_extcontrolm(control);
				free(udata, M_LINUX);
				goto out;
			}
		}

		lcm->cmsg_len = LINUX_CMSG_LEN(datalen);
		error = copyout(lcm, outbuf, L_CMSG_HDRSZ);
		if (error == 0) {
			error = copyout(data, LINUX_CMSG_DATA(outbuf), datalen);
			if (error == 0) {
				outbuf += LINUX_CMSG_SPACE(datalen);
				outlen += LINUX_CMSG_SPACE(datalen);
			}
		}
err:
		free(udata, M_LINUX);
		if (error != 0)
			goto bad;
	}
	if (outlen == 0 && skiped > 0) {
		error = EINVAL;
		goto bad;
	}

out:
	l_msghdr.msg_controllen = outlen;
	error = copyout(&l_msghdr, msghdr, sizeof(l_msghdr));

bad:
	if (control != NULL) {
		if (error != 0)
			m_dispose_extcontrolm(control);
		m_freem(control);
	}
	free(iov, M_IOV);
	free(lcm, M_LINUX);
	free(sa, M_SONAME);

	return (error);
}

int
linux_recvmsg(struct thread *td, struct linux_recvmsg_args *args)
{
	struct msghdr bsd_msg;
	struct file *fp;
	int error;

	error = getsock(td, args->s, &cap_recv_rights, &fp);
	if (error != 0)
		return (error);
	fdrop(fp, td);
	return (linux_recvmsg_common(td, args->s, PTRIN(args->msg),
	    args->flags, &bsd_msg));
}

static int
linux_recvmmsg_common(struct thread *td, l_int s, struct l_mmsghdr *msg,
    l_uint vlen, l_uint flags, struct timespec *tts)
{
	struct msghdr bsd_msg;
	struct timespec ts;
	struct file *fp;
	l_uint retval;
	int error, datagrams;

	error = getsock(td, s, &cap_recv_rights, &fp);
	if (error != 0)
		return (error);
	datagrams = 0;
	while (datagrams < vlen) {
		error = linux_recvmsg_common(td, s, &msg->msg_hdr,
		    flags & ~LINUX_MSG_WAITFORONE, &bsd_msg);
		if (error != 0)
			break;

		retval = td->td_retval[0];
		error = copyout(&retval, &msg->msg_len, sizeof(msg->msg_len));
		if (error != 0)
			break;
		++msg;
		++datagrams;

		/*
		 * MSG_WAITFORONE turns on MSG_DONTWAIT after one packet.
		 */
		if (flags & LINUX_MSG_WAITFORONE)
			flags |= LINUX_MSG_DONTWAIT;

		/*
		 * See BUGS section of recvmmsg(2).
		 */
		if (tts) {
			getnanotime(&ts);
			timespecsub(&ts, tts, &ts);
			if (!timespecisset(&ts) || ts.tv_sec > 0)
				break;
		}
		/* Out of band data, return right away. */
		if (bsd_msg.msg_flags & MSG_OOB)
			break;
	}
	if (error == 0)
		td->td_retval[0] = datagrams;
	fdrop(fp, td);
	return (error);
}

int
linux_recvmmsg(struct thread *td, struct linux_recvmmsg_args *args)
{
	struct timespec ts, tts, *ptts;
	int error;

	if (args->timeout) {
		error = linux_get_timespec(&ts, args->timeout);
		if (error != 0)
			return (error);
		getnanotime(&tts);
		timespecadd(&tts, &ts, &tts);
		ptts = &tts;
	}
		else ptts = NULL;

	return (linux_recvmmsg_common(td, args->s, PTRIN(args->msg),
	    args->vlen, args->flags, ptts));
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_recvmmsg_time64(struct thread *td, struct linux_recvmmsg_time64_args *args)
{
	struct timespec ts, tts, *ptts;
	int error;

	if (args->timeout) {
		error = linux_get_timespec64(&ts, args->timeout);
		if (error != 0)
			return (error);
		getnanotime(&tts);
		timespecadd(&tts, &ts, &tts);
		ptts = &tts;
	}
		else ptts = NULL;

	return (linux_recvmmsg_common(td, args->s, PTRIN(args->msg),
	    args->vlen, args->flags, ptts));
}
#endif

int
linux_shutdown(struct thread *td, struct linux_shutdown_args *args)
{

	return (kern_shutdown(td, args->s, args->how));
}

int
linux_setsockopt(struct thread *td, struct linux_setsockopt_args *args)
{
	struct proc *p = td->td_proc;
	struct linux_pemuldata *pem;
	l_timeval linux_tv;
	l_uint linux_timeout;
	struct sockaddr *sa;
	struct timeval tv;
	u_int bsd_timeout;
	socklen_t len;
	int error, level, name, val;

	level = linux_to_bsd_sockopt_level(args->level);
	switch (level) {
	case SOL_SOCKET:
		switch (args->optname) {
		case LINUX_SO_RCVTIMEO_NEW:
			return (linux_setsockopt_sock_timeval(td, args,
			    SO_RCVTIMEO));
		case LINUX_SO_SNDTIMEO_NEW:
			return (linux_setsockopt_sock_timeval(td, args,
			    SO_SNDTIMEO));
		case LINUX_SO_NO_CHECK:
			/* UDP checksums are always sent here. */
			return (linux_setsockopt_fixed_bool(td, args, 0));
		case LINUX_SO_PASSRIGHTS:
			/* SCM_RIGHTS can not be turned off here. */
			return (linux_setsockopt_fixed_bool(td, args, 1));
		case LINUX_SO_BSDCOMPAT:
			/* Obsolete; a no-op on Linux as well (any value). */
			if (args->optlen < sizeof(val))
				return (EINVAL);
			return (copyin(PTRIN(args->optval), &val, sizeof(val)));
		default:
			break;
		}
		name = linux_to_bsd_so_sockopt(args->optname);
		switch (name) {
		case LOCAL_CREDS_PERSISTENT:
			level = SOL_LOCAL;
			break;
		case SO_RCVTIMEO:
			/* FALLTHROUGH */
		case SO_SNDTIMEO:
			error = copyin(PTRIN(args->optval), &linux_tv,
			    sizeof(linux_tv));
			if (error != 0)
				return (error);
			tv.tv_sec = linux_tv.tv_sec;
			tv.tv_usec = linux_tv.tv_usec;
			return (kern_setsockopt(td, args->s, level,
			    name, &tv, UIO_SYSSPACE, sizeof(tv)));
			/* NOTREACHED */
		case SO_TIMESTAMP:
			/* overwrite SO_BINTIME */
			val = 0;
			error = kern_setsockopt(td, args->s, level,
			    SO_BINTIME, &val, UIO_SYSSPACE, sizeof(val));
			if (error != 0)
				return (error);
			pem = pem_find(p);
			pem->so_timestamp = args->optname;
			break;
		case SO_BINTIME:
			/* overwrite SO_TIMESTAMP */
			val = 0;
			error = kern_setsockopt(td, args->s, level,
			    SO_TIMESTAMP, &val, UIO_SYSSPACE, sizeof(val));
			if (error != 0)
				return (error);
			pem = pem_find(p);
			pem->so_timestampns = args->optname;
			break;
		default:
			break;
		}
		break;
	case IPPROTO_IP:
		switch (args->optname) {
		case LINUX_IP_RECVERR:
			if (linux_ignore_ip_recverr) {
				/*
				 * XXX: This is a hack to unbreak DNS
				 *	resolution with glibc 2.30 and above.
				 */
				return (0);
			}
			break;
		case LINUX_IP_PKTINFO:
			return (linux_setsockopt_ip_pktinfo(td, args));
		case LINUX_IP_MTU_DISCOVER:
			return (linux_setsockopt_mtu_discover(td, args,
			    IPPROTO_IP, IP_DONTFRAG));
		case LINUX_IP_MULTICAST_ALL:
			/*
			 * FreeBSD only delivers multicast datagrams for
			 * groups joined on the receiving socket, which is
			 * IP_MULTICAST_ALL == 0.
			 */
			return (linux_setsockopt_fixed_bool(td, args, 0));
		default:
			break;
		}
		name = linux_to_bsd_ip_sockopt(args->optname);
		break;
	case IPPROTO_IPV6:
		switch (args->optname) {
		case LINUX_IPV6_RECVERR:
			if (linux_ignore_ip_recverr) {
				/*
				 * XXX: This is a hack to unbreak DNS
				 *	resolution with glibc 2.30 and above.
				 */
				return (0);
			}
			break;
		case LINUX_IPV6_MTU_DISCOVER:
			return (linux_setsockopt_mtu_discover(td, args,
			    IPPROTO_IPV6, IPV6_DONTFRAG));
		case LINUX_IPV6_MULTICAST_ALL:
			/* See IP_MULTICAST_ALL. */
			return (linux_setsockopt_fixed_bool(td, args, 0));
		case LINUX_IPV6_ADDR_PREFERENCES:
			return (linux_setsockopt_ip6_addr_preferences(td,
			    args));
		default:
			break;
		}
		name = linux_to_bsd_ip6_sockopt(args->optname);
		break;
	case IPPROTO_TCP:
		name = linux_to_bsd_tcp_sockopt(args->optname);
		switch (name) {
		case TCP_CONGESTION:
			return (linux_setsockopt_tcp_congestion(td, args));
		case TCP_INFO:
			/* Read-only on Linux too. */
			return (ENOPROTOOPT);
		case TCP_MAXUNACKTIME:
			if (args->optlen < sizeof(linux_timeout))
				return (EINVAL);

			error = copyin(PTRIN(args->optval), &linux_timeout,
			    sizeof(linux_timeout));
			if (error != 0)
				return (error);

			bsd_timeout = linux_to_bsd_tcp_user_timeout(
			    linux_timeout);
			return (kern_setsockopt(td, args->s, level, name,
			    &bsd_timeout, UIO_SYSSPACE,
			    sizeof(bsd_timeout)));
		default:
			break;
		}
		break;
#ifdef INET6
	case IPPROTO_RAW: {
		struct file *fp;
		struct socket *so;
		int family;

		error = getsock(td, args->s, &cap_setsockopt_rights, &fp);
		if (error != 0)
			return (error);
		so = fp->f_data;
		family = so->so_proto->pr_domain->dom_family;
		fdrop(fp, td);

		name = -1;
		if (family == AF_INET6) {
			name = linux_to_bsd_ip6_sockopt(args->optname);
			if (name >= 0)
				level = IPPROTO_IPV6;
		}
		break;
	}
	case IPPROTO_ICMPV6: {
		struct icmp6_filter f;
		int i;

		name = linux_to_bsd_icmp6_sockopt(args->optname);
		if (name != ICMP6_FILTER)
			break;

		if (args->optlen != sizeof(f))
			return (EINVAL);

		error = copyin(PTRIN(args->optval), &f, sizeof(f));
		if (error)
			return (error);

		/* Linux uses opposite values for pass/block in ICMPv6 */
		for (i = 0; i < nitems(f.icmp6_filt); i++)
			f.icmp6_filt[i] = ~f.icmp6_filt[i];
		return (kern_setsockopt(td, args->s, IPPROTO_ICMPV6,
		    ICMP6_FILTER, &f, UIO_SYSSPACE, sizeof(f)));
	}
#endif
	case SOL_NETLINK:
		name = args->optname;
		break;
	case IPPROTO_UDP:
		name = linux_to_bsd_udp_sockopt(args->optname);
		break;
	case SOL_VSOCK:
		/* Same option numbers and struct timeval layout. */
		name = args->optname;
		error = kern_setsockopt(td, args->s, level, name,
		    PTRIN(args->optval), UIO_USERSPACE, args->optlen);
		/* Native answers EOPNOTSUPP for an unknown option. */
		return (error == EOPNOTSUPP ? ENOPROTOOPT : error);
	default:
		name = -1;
		break;
	}
	if (name < 0) {
		if (name == -1)
			linux_msg(curthread,
			    "unsupported setsockopt level %d optname %d",
			    args->level, args->optname);
		return (ENOPROTOOPT);
	}

	switch (name) {
	case IPV6_NEXTHOP: {
		len = args->optlen;
		error = linux_to_bsd_sockaddr(PTRIN(args->optval), &sa, &len);
		if (error != 0)
			return (error);

		error = kern_setsockopt(td, args->s, level,
		    name, sa, UIO_SYSSPACE, len);
		free(sa, M_SONAME);
		break;
	}
	case MCAST_JOIN_GROUP:
	case MCAST_LEAVE_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		/* Same numbers at IPPROTO_IP and IPPROTO_IPV6. */
		error = linux_setsockopt_group_req(td, args, level, name);
		break;
	case IP_ADD_SOURCE_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE:
		if (level != IPPROTO_IP) {
			error = kern_setsockopt(td, args->s, level, name,
			    PTRIN(args->optval), UIO_USERSPACE, args->optlen);
			break;
		}
		error = linux_setsockopt_ip_mreq_source(td, args, name);
		break;
	default:
		error = kern_setsockopt(td, args->s, level,
		    name, PTRIN(args->optval), UIO_USERSPACE, args->optlen);
	}

	return (error);
}

static int
linux_sockopt_copyout(struct thread *td, void *val, socklen_t len,
    struct linux_getsockopt_args *args)
{
	int error;

	error = copyout(val, PTRIN(args->optval), len);
	if (error == 0)
		error = copyout(&len, PTRIN(args->optlen), sizeof(len));
	return (error);
}

/*
 * Like linux_sockopt_copyout(), but copy at most the caller's *optlen
 * bytes and report the amount copied, which is what sk_getsockopt() /
 * ip_getsockopt() do for the fixed-size options.
 */
static int
linux_sockopt_copyout_trunc(struct thread *td, void *val, socklen_t len,
    struct linux_getsockopt_args *args)
{
	socklen_t ulen;
	int error;

	error = copyin(PTRIN(args->optlen), &ulen, sizeof(ulen));
	if (error != 0)
		return (error);
	if ((int)ulen < 0)
		return (EINVAL);
	return (linux_sockopt_copyout(td, val, MIN(ulen, len), args));
}

static int
linux_getsockopt_so_peergroups(struct thread *td,
    struct linux_getsockopt_args *args)
{
	l_gid_t *out = PTRIN(args->optval);
	struct xucred xu;
	socklen_t xulen, len;
	int error, i;

	xulen = sizeof(xu);
	error = kern_getsockopt(td, args->s, 0,
	    LOCAL_PEERCRED, &xu, UIO_SYSSPACE, &xulen);
	if (error != 0)
		return (error);

	len = xu.cr_ngroups * sizeof(l_gid_t);
	if (args->optlen < len) {
		error = copyout(&len, PTRIN(args->optlen), sizeof(len));
		if (error == 0)
			error = ERANGE;
		return (error);
	}

	/* "- 1" to skip the primary group. */
	for (i = 0; i < xu.cr_ngroups - 1; i++) {
		/* Copy to cope with a possible type discrepancy. */
		const l_gid_t g = xu.cr_groups[i + 1];

		error = copyout(&g, out + i, sizeof(l_gid_t));
		if (error != 0)
			return (error);
	}

	error = copyout(&len, PTRIN(args->optlen), sizeof(len));
	return (error);
}

/*
 * SO_PEERPIDFD (Linux 6.5): a pidfd for the peer of a connected unix
 * socket, from the same credentials LOCAL_PEERCRED records at connect.
 * ENODATA when the peer's pid is unknown, ESRCH when it is gone.
 */
static int
linux_getsockopt_so_peerpidfd(struct thread *td,
    struct linux_getsockopt_args *args)
{
	struct xucred xu;
	socklen_t xulen, len;
	int error, fd;

	error = copyin(PTRIN(args->optlen), &len, sizeof(len));
	if (error != 0)
		return (error);
	if (len < sizeof(int))
		return (EINVAL);
	xulen = sizeof(xu);
	error = kern_getsockopt(td, args->s, 0, LOCAL_PEERCRED, &xu,
	    UIO_SYSSPACE, &xulen);
	if (error != 0)
		return (error);
	if (xu.cr_pid <= 0)
		return (ENOATTR);	/* translated to Linux ENODATA */
	error = linux_pidfd_create(td, xu.cr_pid, false, &fd);
	if (error != 0)
		return (error);
	len = sizeof(int);
	error = copyout(&fd, PTRIN(args->optval), sizeof(fd));
	if (error == 0)
		error = copyout(&len, PTRIN(args->optlen), sizeof(len));
	if (error != 0)
		(void)kern_close(td, fd);
	return (error);
}

static int
linux_getsockopt_so_peersec(struct thread *td,
    struct linux_getsockopt_args *args)
{
	socklen_t len;
	int error;

	len = sizeof(SECURITY_CONTEXT_STRING);
	if (args->optlen < len) {
		error = copyout(&len, PTRIN(args->optlen), sizeof(len));
		if (error == 0)
			error = ERANGE;
		return (error);
	}

	return (linux_sockopt_copyout(td, SECURITY_CONTEXT_STRING,
	    len, args));
}

/* sogetopt() returns the so_options bit; Linux returns 0 or 1. */
static int
linux_getsockopt_so_bool(struct thread *td,
    struct linux_getsockopt_args *args, int name)
{
	socklen_t len;
	int error, val;

	len = sizeof(val);
	error = kern_getsockopt(td, args->s, SOL_SOCKET, name, &val,
	    UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	val = (val != 0);
	return (linux_sockopt_copyout_trunc(td, &val, sizeof(val), args));
}

static int
linux_getsockopt_so_linger(struct thread *td,
    struct linux_getsockopt_args *args)
{
	struct linger ling;
	socklen_t len;
	int error;

	len = sizeof(ling);
	error = kern_getsockopt(td, args->s, SOL_SOCKET,
	    SO_LINGER, &ling, UIO_SYSSPACE, &len);
	if (error != 0)
		return (error);
	ling.l_onoff = ((ling.l_onoff & SO_LINGER) != 0);
	return (linux_sockopt_copyout(td, &ling, len, args));
}

int
linux_getsockopt(struct thread *td, struct linux_getsockopt_args *args)
{
	l_uint linux_timeout;
	l_timeval linux_tv;
	struct timeval tv;
	socklen_t tv_len, xulen, len;
	struct sockaddr *sa;
	u_int bsd_timeout;
	struct xucred xu;
	struct l_ucred lxu;
	int error, level, name, newval;

	level = linux_to_bsd_sockopt_level(args->level);
	switch (level) {
	case SOL_SOCKET:
		switch (args->optname) {
		case LINUX_SO_PEERGROUPS:
			return (linux_getsockopt_so_peergroups(td, args));
		case LINUX_SO_PEERSEC:
			return (linux_getsockopt_so_peersec(td, args));
		case LINUX_SO_PEERPIDFD:
			return (linux_getsockopt_so_peerpidfd(td, args));
		case LINUX_SO_RCVTIMEO_NEW:
			return (linux_getsockopt_sock_timeval(td, args,
			    SO_RCVTIMEO));
		case LINUX_SO_SNDTIMEO_NEW:
			return (linux_getsockopt_sock_timeval(td, args,
			    SO_SNDTIMEO));
		case LINUX_SO_NO_CHECK:
		case LINUX_SO_BSDCOMPAT:
			return (linux_getsockopt_fixed_int(td, args, 0));
		case LINUX_SO_PASSRIGHTS:
			return (linux_getsockopt_fixed_int(td, args, 1));
		case LINUX_SO_DEBUG:
		case LINUX_SO_REUSEADDR:
		case LINUX_SO_KEEPALIVE:
		case LINUX_SO_DONTROUTE:
		case LINUX_SO_BROADCAST:
		case LINUX_SO_OOBINLINE:
		case LINUX_SO_REUSEPORT:
		case LINUX_SO_ACCEPTCONN:
		case LINUX_SO_TIMESTAMPO:
		case LINUX_SO_TIMESTAMPN:
		case LINUX_SO_TIMESTAMPNSO:
		case LINUX_SO_TIMESTAMPNSN:
			/*
			 * Dispatched by Linux name: SO_DEBUG shares its
			 * number with LOCAL_PEERCRED below.
			 */
			return (linux_getsockopt_so_bool(td, args,
			    linux_to_bsd_so_sockopt(args->optname)));
		default:
			break;
		}

		name = linux_to_bsd_so_sockopt(args->optname);
		switch (name) {
		case LOCAL_CREDS_PERSISTENT:
			level = SOL_LOCAL;
			break;
		case SO_RCVTIMEO:
			/* FALLTHROUGH */
		case SO_SNDTIMEO:
			tv_len = sizeof(tv);
			error = kern_getsockopt(td, args->s, level,
			    name, &tv, UIO_SYSSPACE, &tv_len);
			if (error != 0)
				return (error);
			linux_tv.tv_sec = tv.tv_sec;
			linux_tv.tv_usec = tv.tv_usec;
			return (linux_sockopt_copyout(td, &linux_tv,
			    sizeof(linux_tv), args));
			/* NOTREACHED */
		case LOCAL_PEERCRED:
			if (args->optlen < sizeof(lxu))
				return (EINVAL);
			/*
			 * LOCAL_PEERCRED is not served at the SOL_SOCKET level,
			 * but by the Unix socket's level 0.
			 */
			level = 0;
			xulen = sizeof(xu);
			error = kern_getsockopt(td, args->s, level,
			    name, &xu, UIO_SYSSPACE, &xulen);
			if (error != 0)
				return (error);
			lxu.pid = xu.cr_pid;
			lxu.uid = xu.cr_uid;
			lxu.gid = xu.cr_gid;
			return (linux_sockopt_copyout(td, &lxu,
			    sizeof(lxu), args));
			/* NOTREACHED */
		case SO_ERROR:
			len = sizeof(newval);
			error = kern_getsockopt(td, args->s, level,
			    name, &newval, UIO_SYSSPACE, &len);
			if (error != 0)
				return (error);
			newval = -bsd_to_linux_errno(newval);
			return (linux_sockopt_copyout(td, &newval,
			    len, args));
			/* NOTREACHED */
		case SO_DOMAIN:
			len = sizeof(newval);
			error = kern_getsockopt(td, args->s, level,
			    name, &newval, UIO_SYSSPACE, &len);
			if (error != 0)
				return (error);
			newval = bsd_to_linux_domain((sa_family_t)newval);
			if (newval == AF_UNKNOWN)
				return (ENOPROTOOPT);
			return (linux_sockopt_copyout(td, &newval,
			    len, args));
			/* NOTREACHED */
		case SO_LINGER:
			return (linux_getsockopt_so_linger(td, args));
			/* NOTREACHED */
		default:
			break;
		}
		break;
	case IPPROTO_IP:
		switch (args->optname) {
		case LINUX_IP_PKTINFO:
			return (linux_getsockopt_ip_pktinfo(td, args));
		case LINUX_IP_MTU_DISCOVER:
			return (linux_getsockopt_mtu_discover(td, args,
			    IPPROTO_IP, IP_DONTFRAG, LINUX_IP_PMTUDISC_DONT));
		case LINUX_IP_MULTICAST_ALL:
			return (linux_getsockopt_fixed_int(td, args, 0));
		case LINUX_IP_PROTOCOL:
			/* Same as SO_PROTOCOL. */
			level = SOL_SOCKET;
			name = SO_PROTOCOL;
			goto generic;
		default:
			break;
		}
		name = linux_to_bsd_ip_sockopt(args->optname);
		break;
	case IPPROTO_IPV6:
		switch (args->optname) {
		case LINUX_IPV6_MTU_DISCOVER:
			/*
			 * IPv6 fragments at the source to the path MTU
			 * unless IPV6_DONTFRAG is set, which is exactly
			 * IPV6_PMTUDISC_WANT.
			 */
			return (linux_getsockopt_mtu_discover(td, args,
			    IPPROTO_IPV6, IPV6_DONTFRAG,
			    LINUX_IP_PMTUDISC_WANT));
		case LINUX_IPV6_MTU:
			return (linux_getsockopt_ip6_pathmtu(td, args, true));
		case LINUX_IPV6_PATHMTU:
			return (linux_getsockopt_ip6_pathmtu(td, args, false));
		case LINUX_IPV6_MULTICAST_ALL:
			return (linux_getsockopt_fixed_int(td, args, 0));
		case LINUX_IPV6_ADDR_PREFERENCES:
			return (linux_getsockopt_ip6_addr_preferences(td,
			    args));
		default:
			break;
		}
		name = linux_to_bsd_ip6_sockopt(args->optname);
		break;
	case IPPROTO_TCP:
		name = linux_to_bsd_tcp_sockopt(args->optname);
		switch (name) {
		case TCP_INFO:
			return (linux_getsockopt_tcp_info(td, args));
		case TCP_CONGESTION:
			return (linux_getsockopt_tcp_congestion(td, args));
		case TCP_NODELAY:
		case TCP_NOPUSH:
		case TCP_FASTOPEN:
			/* FreeBSD returns the t_flags bit; Linux 0 or 1. */
			len = sizeof(newval);
			error = kern_getsockopt(td, args->s, level, name,
			    &newval, UIO_SYSSPACE, &len);
			if (error != 0)
				return (error);
			newval = (newval != 0);
			return (linux_sockopt_copyout_trunc(td, &newval,
			    sizeof(newval), args));
		case TCP_MAXUNACKTIME:
			len = sizeof(bsd_timeout);
			error = kern_getsockopt(td, args->s, level, name,
			    &bsd_timeout, UIO_SYSSPACE, &len);
			if (error != 0)
				return (error);

			linux_timeout = bsd_to_linux_tcp_user_timeout(
			    bsd_timeout);
			return (linux_sockopt_copyout(td, &linux_timeout,
			    sizeof(linux_timeout), args));
		default:
			break;
		}
		break;
#ifdef INET6
	case IPPROTO_RAW: {
		struct file *fp;
		struct socket *so;
		int family;

		error = getsock(td, args->s, &cap_getsockopt_rights, &fp);
		if (error != 0)
			return (error);
		so = fp->f_data;
		family = so->so_proto->pr_domain->dom_family;
		fdrop(fp, td);

		name = -1;
		if (family == AF_INET6) {
			name = linux_to_bsd_ip6_sockopt(args->optname);
			if (name >= 0)
				level = IPPROTO_IPV6;
		}
		break;
	}
	case IPPROTO_ICMPV6: {
		struct icmp6_filter f;
		int i;

		name = linux_to_bsd_icmp6_sockopt(args->optname);
		if (name != ICMP6_FILTER)
			break;

		error = copyin(PTRIN(args->optlen), &len, sizeof(len));
		if (error)
			return (error);
		if (len != sizeof(f))
			return (EINVAL);

		error = kern_getsockopt(td, args->s, IPPROTO_ICMPV6,
		    ICMP6_FILTER, &f, UIO_SYSSPACE, &len);
		if (error)
			return (error);

		/* Linux uses opposite values for pass/block in ICMPv6 */
		for (i = 0; i < nitems(f.icmp6_filt); i++)
			f.icmp6_filt[i] = ~f.icmp6_filt[i];
		error = copyout(&f, PTRIN(args->optval), len);
		if (error)
			return (error);

		return (copyout(&len, PTRIN(args->optlen), sizeof(socklen_t)));
	}
#endif
	case IPPROTO_UDP:
		name = linux_to_bsd_udp_sockopt(args->optname);
		break;
	case SOL_VSOCK:
		name = args->optname;
		error = copyin(PTRIN(args->optlen), &len, sizeof(len));
		if (error != 0)
			return (error);
		error = kern_getsockopt(td, args->s, level, name,
		    PTRIN(args->optval), UIO_USERSPACE, &len);
		if (error == 0)
			error = copyout(&len, PTRIN(args->optlen), sizeof(len));
		return (error == EOPNOTSUPP ? ENOPROTOOPT : error);
	default:
		name = -1;
		break;
	}
	if (name < 0) {
		if (name == -1)
			linux_msg(curthread,
			    "unsupported getsockopt level %d optname %d",
			    args->level, args->optname);
		return (ENOPROTOOPT);
	}

generic:
	if (name == IPV6_NEXTHOP) {
		error = copyin(PTRIN(args->optlen), &len, sizeof(len));
                if (error != 0)
                        return (error);
		sa = malloc(len, M_SONAME, M_WAITOK);

		error = kern_getsockopt(td, args->s, level,
		    name, sa, UIO_SYSSPACE, &len);
		if (error != 0)
			goto out;

		error = linux_copyout_sockaddr(sa, PTRIN(args->optval), len);
		if (error == 0)
			error = copyout(&len, PTRIN(args->optlen),
			    sizeof(len));
out:
		free(sa, M_SONAME);
	} else {
		if (args->optval) {
			error = copyin(PTRIN(args->optlen), &len, sizeof(len));
			if (error != 0)
				return (error);
		}
		error = kern_getsockopt(td, args->s, level,
		    name, PTRIN(args->optval), UIO_USERSPACE, &len);
		if (error == 0)
			error = copyout(&len, PTRIN(args->optlen),
			    sizeof(len));
	}

	return (error);
}

/*
 * Based on sendfile_getsock from kern_sendfile.c
 * Determines whether an fd is a stream socket that can be used
 * with FreeBSD sendfile.
 */
static bool
is_sendfile(struct file *fp, struct file *ofp)
{
	struct socket *so;

	/*
	 * FreeBSD sendfile() system call sends a regular file or
	 * shared memory object out a stream socket.
	 */
	if ((fp->f_type != DTYPE_SHM && fp->f_type != DTYPE_VNODE) ||
	    (fp->f_type == DTYPE_VNODE &&
	    (fp->f_vnode == NULL || fp->f_vnode->v_type != VREG)))
		return (false);
	/*
	 * The socket must be a stream socket and connected.
	 */
	if (ofp->f_type != DTYPE_SOCKET)
		return (false);
	so = ofp->f_data;
	if (so->so_type != SOCK_STREAM)
		return (false);
	/*
	 * SCTP one-to-one style sockets currently don't work with
	 * sendfile().
	 */
	if (so->so_proto->pr_protocol == IPPROTO_SCTP)
		return (false);
	return (!SOLISTENING(so));
}

static bool
is_regular_file(struct file *fp)
{

	return (fp->f_type == DTYPE_VNODE && fp->f_vnode != NULL &&
	    fp->f_vnode->v_type == VREG);
}

static int
sendfile_fallback(struct thread *td, struct file *fp, l_int out,
    off_t *offset, l_size_t count, off_t *sbytes)
{
	off_t current_offset, out_offset, to_send;
	l_size_t bytes_sent, n_read;
	struct file *ofp;
	struct iovec aiov;
	struct uio auio;
	bool seekable;
	size_t bufsz;
	void *buf;
	int flags, error;

	if (offset == NULL) {
		if ((error = fo_seek(fp, 0, SEEK_CUR, td)) != 0)
			return (error);
		current_offset = td->td_uretoff.tdu_off;
	} else {
		if ((fp->f_ops->fo_flags & DFLAG_SEEKABLE) == 0)
			return (ESPIPE);
		current_offset = *offset;
	}
	error = fget_write(td, out, &cap_pwrite_rights, &ofp);
	if (error != 0)
		return (error);
	seekable = (ofp->f_ops->fo_flags & DFLAG_SEEKABLE) != 0;
	if (seekable) {
		if ((error = fo_seek(ofp, 0, SEEK_CUR, td)) != 0)
			goto drop;
		out_offset = td->td_uretoff.tdu_off;
	} else
		out_offset = 0;

	flags = FOF_OFFSET | FOF_NOUPDATE;
	bufsz = min(count, maxphys);
	buf = malloc(bufsz, M_LINUX, M_WAITOK);
	bytes_sent = 0;
	while (bytes_sent < count) {
		to_send = min(count - bytes_sent, bufsz);
		aiov.iov_base = buf;
		aiov.iov_len = bufsz;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_td = td;
		auio.uio_rw = UIO_READ;
		auio.uio_offset = current_offset;
		auio.uio_resid = to_send;
		error = fo_read(fp, &auio, fp->f_cred, flags, td);
		if (error != 0)
			break;
		n_read = to_send - auio.uio_resid;
		if (n_read == 0)
			break;
		aiov.iov_base = buf;
		aiov.iov_len = bufsz;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_td = td;
		auio.uio_rw = UIO_WRITE;
		auio.uio_offset = (seekable) ? out_offset : 0;
		auio.uio_resid = n_read;
		error = fo_write(ofp, &auio, ofp->f_cred, flags, td);
		if (error != 0)
			break;
		bytes_sent += n_read;
		current_offset += n_read;
		out_offset += n_read;
	}
	free(buf, M_LINUX);

	if (error == 0) {
		*sbytes = bytes_sent;
		if (offset != NULL)
			*offset = current_offset;
		else
			error = fo_seek(fp, current_offset, SEEK_SET, td);
	}
	if (error == 0 && seekable)
		error = fo_seek(ofp, out_offset, SEEK_SET, td);

drop:
	fdrop(ofp, td);
	return (error);
}

static int
sendfile_sendfile(struct thread *td, struct file *fp, l_int out,
    off_t *offset, l_size_t count, off_t *sbytes)
{
	off_t current_offset;
	int error;

	if (offset == NULL) {
		if ((fp->f_ops->fo_flags & DFLAG_SEEKABLE) == 0)
			return (ESPIPE);
		if ((error = fo_seek(fp, 0, SEEK_CUR, td)) != 0)
			return (error);
		current_offset = td->td_uretoff.tdu_off;
	} else
		current_offset = *offset;
	error = fo_sendfile(fp, out, NULL, NULL, current_offset, count,
	    sbytes, 0, td);
	if (error == EAGAIN && *sbytes > 0) {
		/*
		 * The socket is non-blocking and we didn't finish sending.
		 * Squash the error, since that's what Linux does.
		 */
		error = 0;
	}
	if (error == 0) {
		current_offset += *sbytes;
		if (offset != NULL)
			*offset = current_offset;
		else
			error = fo_seek(fp, current_offset, SEEK_SET, td);
	}
	return (error);
}

static int
linux_sendfile_common(struct thread *td, l_int out, l_int in,
    off_t *offset, l_size_t count)
{
	struct file *fp, *ofp;
	off_t sbytes;
	int error;

	/* Linux cannot have 0 count. */
	if (count <= 0 || (offset != NULL && *offset < 0))
		return (EINVAL);

	AUDIT_ARG_FD(in);
	error = fget_read(td, in, &cap_pread_rights, &fp);
	if (error != 0)
		return (error);
	if ((fp->f_type != DTYPE_SHM && fp->f_type != DTYPE_VNODE) ||
	    (fp->f_type == DTYPE_VNODE &&
	    (fp->f_vnode == NULL || fp->f_vnode->v_type != VREG))) {
		error = EINVAL;
		goto drop;
	}
	error = fget_unlocked(td, out, &cap_no_rights, &ofp);
	if (error != 0)
		goto drop;

	if (is_regular_file(fp) && is_regular_file(ofp)) {
		error = kern_copy_file_range(td, in, offset, out, NULL, count,
		    0);
	} else {
		sbytes = 0;
		if (is_sendfile(fp, ofp))
			error = sendfile_sendfile(td, fp, out, offset, count,
			    &sbytes);
		else
			error = sendfile_fallback(td, fp, out, offset, count,
			    &sbytes);
		if (error == ENOBUFS && (ofp->f_flag & FNONBLOCK) != 0)
			error = EAGAIN;
		if (error == 0)
			td->td_retval[0] = sbytes;
	}
	fdrop(ofp, td);

drop:
	fdrop(fp, td);
	return (error);
}

int
linux_sendfile(struct thread *td, struct linux_sendfile_args *arg)
{
	/*
	 * Differences between FreeBSD and Linux sendfile:
	 * - Linux doesn't send anything when count is 0 (FreeBSD uses 0 to
	 *   mean send the whole file).
	 * - Linux can send to any fd whereas FreeBSD only supports sockets.
	 *   We therefore use FreeBSD sendfile where possible for performance,
	 *   but fall back on a manual copy (sendfile_fallback).
	 * - Linux doesn't have an equivalent for FreeBSD's flags and sf_hdtr.
	 * - Linux takes an offset pointer and updates it to the read location.
	 *   FreeBSD takes in an offset and a 'bytes read' parameter which is
	 *   only filled if it isn't NULL.  We use this parameter to update the
	 *   offset pointer if it exists.
	 * - Linux sendfile returns bytes read on success while FreeBSD
	 *   returns 0.  We use the 'bytes read' parameter to get this value.
	 */

	off_t offset64;
	l_off_t offset;
	int error;

	if (arg->offset != NULL) {
		error = copyin(arg->offset, &offset, sizeof(offset));
		if (error != 0)
			return (error);
		offset64 = offset;
	}

	error = linux_sendfile_common(td, arg->out, arg->in,
	    arg->offset != NULL ? &offset64 : NULL, arg->count);

	if (error == 0 && arg->offset != NULL) {
#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
		if (offset64 > INT32_MAX)
			return (EOVERFLOW);
#endif
		offset = (l_off_t)offset64;
		error = copyout(&offset, arg->offset, sizeof(offset));
	}

	return (error);
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_sendfile64(struct thread *td, struct linux_sendfile64_args *arg)
{
	off_t offset;
	int error;

	if (arg->offset != NULL) {
		error = copyin(arg->offset, &offset, sizeof(offset));
		if (error != 0)
			return (error);
	}

	error = linux_sendfile_common(td, arg->out, arg->in,
		arg->offset != NULL ? &offset : NULL, arg->count);

	if (error == 0 && arg->offset != NULL)
		error = copyout(&offset, arg->offset, sizeof(offset));

	return (error);
}

/* Argument list sizes for linux_socketcall */
static const unsigned char lxs_args_cnt[] = {
	0 /* unused*/,		3 /* socket */,
	3 /* bind */,		3 /* connect */,
	2 /* listen */,		3 /* accept */,
	3 /* getsockname */,	3 /* getpeername */,
	4 /* socketpair */,	4 /* send */,
	4 /* recv */,		6 /* sendto */,
	6 /* recvfrom */,	2 /* shutdown */,
	5 /* setsockopt */,	5 /* getsockopt */,
	3 /* sendmsg */,	3 /* recvmsg */,
	4 /* accept4 */,	5 /* recvmmsg */,
	4 /* sendmmsg */,	4 /* sendfile */
};
#define	LINUX_ARGS_CNT		(nitems(lxs_args_cnt) - 1)
#define	LINUX_ARG_SIZE(x)	(lxs_args_cnt[x] * sizeof(l_ulong))

int
linux_socketcall(struct thread *td, struct linux_socketcall_args *args)
{
	l_ulong a[6];
#if defined(__amd64__) && defined(COMPAT_LINUX32)
	register_t l_args[6];
#endif
	void *arg;
	int error;

	if (args->what < LINUX_SOCKET || args->what > LINUX_ARGS_CNT)
		return (EINVAL);
	error = copyin(PTRIN(args->args), a, LINUX_ARG_SIZE(args->what));
	if (error != 0)
		return (error);

#if defined(__amd64__) && defined(COMPAT_LINUX32)
	for (int i = 0; i < lxs_args_cnt[args->what]; ++i)
		l_args[i] = a[i];
	arg = l_args;
#else
	arg = a;
#endif
	switch (args->what) {
	case LINUX_SOCKET:
		return (linux_socket(td, arg));
	case LINUX_BIND:
		return (linux_bind(td, arg));
	case LINUX_CONNECT:
		return (linux_connect(td, arg));
	case LINUX_LISTEN:
		return (linux_listen(td, arg));
	case LINUX_ACCEPT:
		return (linux_accept(td, arg));
	case LINUX_GETSOCKNAME:
		return (linux_getsockname(td, arg));
	case LINUX_GETPEERNAME:
		return (linux_getpeername(td, arg));
	case LINUX_SOCKETPAIR:
		return (linux_socketpair(td, arg));
	case LINUX_SEND:
		return (linux_send(td, arg));
	case LINUX_RECV:
		return (linux_recv(td, arg));
	case LINUX_SENDTO:
		return (linux_sendto(td, arg));
	case LINUX_RECVFROM:
		return (linux_recvfrom(td, arg));
	case LINUX_SHUTDOWN:
		return (linux_shutdown(td, arg));
	case LINUX_SETSOCKOPT:
		return (linux_setsockopt(td, arg));
	case LINUX_GETSOCKOPT:
		return (linux_getsockopt(td, arg));
	case LINUX_SENDMSG:
		return (linux_sendmsg(td, arg));
	case LINUX_RECVMSG:
		return (linux_recvmsg(td, arg));
	case LINUX_ACCEPT4:
		return (linux_accept4(td, arg));
	case LINUX_RECVMMSG:
		return (linux_recvmmsg(td, arg));
	case LINUX_SENDMMSG:
		return (linux_sendmmsg(td, arg));
	case LINUX_SENDFILE:
		return (linux_sendfile(td, arg));
	}

	linux_msg(td, "socket type %d not implemented", args->what);
	return (ENOSYS);
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */
