# tcpdump(8) from OpenBSD (contrib/openbsd-pf/usr.sbin/tcpdump), built
# for 5BSD on the base libpcap.  The packet printers and output format are
# OpenBSD's; 5BSD glue: openbsd_compat.h (force-included), include/ (shadow
# headers for OpenBSD-only headers) and privsep_5bsd.c (the privileged
# operations of privsep.h on the public libpcap API).

.include <src.opts.mk>

TCPDUMP_DISTDIR?= ${SRCTOP}/contrib/openbsd-pf/usr.sbin/tcpdump
.PATH: ${TCPDUMP_DISTDIR}

PROG=	tcpdump
MAN=	tcpdump.8

SRCS=	tcpdump.c addrtoname.c \
	print-ether.c print-ip.c print-arp.c print-tcp.c print-udp.c \
	print-atalk.c print-domain.c print-tftp.c print-bootp.c print-nfs.c \
	print-icmp.c print-sl.c print-ppp.c print-rip.c print-timed.c \
	print-snmp.c print-ntp.c print-null.c print-ospf.c print-gtp.c \
	print-fddi.c print-llc.c print-sunrpc.c print-hsrp.c print-vqp.c \
	print-vrrp.c print-wb.c print-decnet.c print-isoclns.c print-ipx.c \
	print-atm.c print-dvmrp.c print-krb.c print-pim.c print-netbios.c \
	util.c parsenfsfh.c version.c print-igrp.c \
	print-gre.c print-nsh.c print-radius.c print-enc.c print-cnfp.c \
	print-ipsec.c print-ike.c print-raw.c print-l2tp.c print-mobile.c \
	print-ip6.c print-ip6opts.c print-icmp6.c print-dhcp6.c print-frag6.c \
	print-bgp.c print-ospf6.c print-ripng.c print-rt6.c print-stp.c \
	print-etherip.c print-lwres.c print-lldp.c print-cdp.c \
	print-ofp.c ofp_map.c \
	print-udpencap.c print-carp.c print-nhrp.c print-wg.c \
	print-802_11.c print-iapp.c print-mpls.c print-slow.c print-usbpcap.c \
	gmt2local.c savestr.c setsignal.c in_cksum.c
# 5BSD glue replaces privsep.c, privsep_fdpass.c and privsep_pcap.c.
SRCS+=	bpf_dump.c
.PATH: ${.CURDIR}
SRCS+=	privsep_5bsd.c

# pflog(4)/pfsync(4) printers and TCP OS fingerprinting (-o, pf.os(5))
SRCS+=	print-pflog.c print-pfsync.c pf_print_state.c
.PATH: ${SRCTOP}/contrib/openbsd-pf/sys/net ${SRCTOP}/contrib/openbsd-pf/sbin/pfctl
SRCS+=	pf_osfp.c pfctl_osfp.c
CFLAGS+= -DFAKE_PF_KERNEL

CFLAGS+= -I${.CURDIR}/include -I${TCPDUMP_DISTDIR}
CFLAGS+= -I${SRCTOP}/contrib/openbsd-pf/sbin/pfctl
CFLAGS+= -I${SRCTOP}/sys/netpfil/openbsd-pf/user
# for pcap-int.h (pcap_t's link type)
CFLAGS+= -include ${SRCTOP}/lib/libpcap/config.h -I${SRCTOP}/contrib/libpcap
CFLAGS+= -include ${.CURDIR}/openbsd_compat.h
CFLAGS+= -DCSLIP -DPPP -DHAVE_FDDI -DETHER_SERVICE -DHAVE_ETHER_NTOHOST
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
.endif

WARNS?=	1
NO_WFORMAT=
# Vendor code: warnings are reported, not fatal.
MK_WERROR=	no
CWARNFLAGS+= -Wno-pointer-sign -Wno-sign-compare \
	-Wno-incompatible-pointer-types-discards-qualifiers \
	-Wno-address-of-packed-member -Wno-unused-but-set-variable \
	-Wno-deprecated-declarations

LIBADD=	pcap crypto

.include <bsd.prog.mk>
