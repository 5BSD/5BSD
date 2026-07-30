LWIPDIR=	${SRCTOP}/contrib/lwip/src

PACKAGE=	networkcmp
LIB=		lwipcmp
PRIVATELIB=	true

.PATH:		${LWIPDIR}/core \
		${LWIPDIR}/core/ipv4 \
		${LWIPDIR}/core/ipv6 \
		${LWIPDIR}/netif

SRCS=		init.c def.c dns.c inet_chksum.c ip.c mem.c memp.c netif.c \
		pbuf.c raw.c stats.c sys.c altcp.c altcp_alloc.c altcp_tcp.c \
		tcp.c tcp_in.c tcp_out.c timeouts.c udp.c \
		acd.c autoip.c dhcp.c etharp.c icmp.c igmp.c ip4_frag.c ip4.c \
		ip4_addr.c \
		dhcp6.c ethip6.c icmp6.c inet6.c ip6.c ip6_addr.c ip6_frag.c \
		mld6.c nd6.c \
		ethernet.c \
		lwipcmp_port.c

CFLAGS+=	-I${.CURDIR} -I${LWIPDIR}/include
CFLAGS+=	-Wno-cast-qual -Wno-missing-prototypes -Wno-sign-compare
WARNS?=		3

.include <bsd.lib.mk>
