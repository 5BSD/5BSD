/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * OpenBSD tcpdump(8) (contrib/openbsd-pf/usr.sbin/tcpdump) on 5BSD:
 * force-included before every source file.  It adds the OpenBSD names the
 * vendor code uses on top of the pfctl(8) userland compatibility header.
 */
#ifndef _TCPDUMP_OPENBSD_COMPAT_H_
#define	_TCPDUMP_OPENBSD_COMPAT_H_

#include "../../../sys/netpfil/openbsd-pf/user/openbsd_compat.h"

#include <sys/param.h>
#include <sys/signal.h>
#include <limits.h>
#include <net/ethernet.h>

/* limits.h / sys/signal.h */
#ifndef HOST_NAME_MAX
#define	HOST_NAME_MAX		MAXHOSTNAMELEN
#endif
#ifndef _NSIG
#define	_NSIG			_SIG_MAXSIG
#endif

/* OpenBSD struct ether_addr member name */
#define	ether_addr_octet	octet

/* OpenBSD bpf.h: pcap_pkthdr.ts is a struct bpf_timeval there. */
#define	bpf_timeval		timeval

/* OpenBSD bpf.h direction filter (-D) and filter drop (-B) settings. */
#define	BPF_DIRECTION_IN	(1 << 0)
#define	BPF_DIRECTION_OUT	(1 << 1)
#define	BPF_FILDROP_PASS	0
#define	BPF_FILDROP_CAPTURE	1
#define	BPF_FILDROP_DROP	2

/* OpenBSD net/ethertypes.h names missing from net/ethernet.h */
#ifndef ETHERTYPE_NHRP
#define	ETHERTYPE_NHRP		0x2001
#endif
#ifndef ETHERTYPE_EAPOL
#define	ETHERTYPE_EAPOL		0x888E
#endif
#ifndef ETHERTYPE_NSH
#define	ETHERTYPE_NSH		0x894F
#endif

/* OpenBSD sys/mbuf.h flags in struct enchdr (enc(4)) */
#define	M_CONF			0x0400
#define	M_AUTH			0x0800

/*
 * tcpdump has its own nameser.h; 5BSD's <resolv.h> would otherwise pull
 * in <arpa/nameser_compat.h> and its conflicting HEADER.
 */
#define	_ARPA_NAMESER_COMPAT_

/* OpenBSD sys/socket.h: MPLS address family (loopback/null DLT headers). */
#ifndef AF_MPLS
#define	AF_MPLS			33
#endif

/*
 * tcpdump has its own bpf_dump() (bpf_dump.c) with an OpenBSD prototype that
 * differs from libpcap's; declare libpcap's first, then rename tcpdump's.
 */
#include <pcap.h>
#define	bpf_dump		obsd_bpf_dump

/* OpenBSD sys/endian.h swap32() usable in case labels */
#undef	swap32
#define	swap32(x)		((uint32_t)(((uint32_t)(x) >> 24) | \
				 (((uint32_t)(x) >> 8) & 0xff00) | \
				 (((uint32_t)(x) & 0xff00) << 8) | \
				 ((uint32_t)(x) << 24)))

/* OpenBSD sys/endian.h little-endian conversions */
#ifndef letoh16
#define	letoh16(x)		le16toh(x)
#define	letoh32(x)		le32toh(x)
#define	letoh64(x)		le64toh(x)
#endif

/* arpa/nameser_compat.h (not used, see above) */
#define	NAMESERVER_PORT		53

/* OpenBSD's getexecpath(3)-style helper used to re-exec the privileged part. */
int	getexecpath(char *, size_t);

#endif /* !_TCPDUMP_OPENBSD_COMPAT_H_ */
