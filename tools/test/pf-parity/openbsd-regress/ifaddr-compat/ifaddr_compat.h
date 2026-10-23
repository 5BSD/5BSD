/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Build glue for OpenBSD's regress/sbin/ifconfig/ifaddr.c on 5BSD.
 * Force-included by regress.py (CFLAGS); plumbing only, the test source
 * is unchanged.
 *
 * ifaddr.c is a cut-down OpenBSD ifconfig.  The cases use only the
 * address ioctls (SIOCSIFADDR, SIOCSIFNETMASK, SIOCSIFBRDADDR,
 * SIOCAIFADDR, SIOCDIFADDR, SIOCGIF*) and getifaddrs(3), which 5BSD
 * provides with the OpenBSD semantics.  The program also references
 * OpenBSD-only requests and structures in code the cases do not depend
 * on (status decoration, tunnels, rtlabel, rdomain-of-tunnel, ...).
 * Those requests are given the value 0, which ioctl(2) rejects with
 * ENOTTY before any driver sees it, and ifaddr.c already treats their
 * failure as "not available".  SIOCGIFDESCR is included because
 * OpenBSD passes the buffer in ifr_data while 5BSD uses ifr_buffer.
 */
#ifndef _IFADDR_COMPAT_H_
#define	_IFADDR_COMPAT_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_types.h>
#include <limits.h>

#define	__dead			__dead2
#define	unveil(path, permissions)	0

#ifndef letoh16
#define	letoh16(x)		le16toh(x)
#endif
#ifndef HOST_NAME_MAX
#define	HOST_NAME_MAX		255
#endif
#ifndef RT_TABLEID_MAX
#define	RT_TABLEID_MAX		255
#endif
#ifndef IFT_CARP
#define	IFT_CARP		0xf8
#endif
#ifndef IFDESCRSIZE
#define	IFDESCRSIZE		64
#endif

/* Requests without a 5BSD equivalent: ioctl(2) returns ENOTTY. */
#define	IFADDR_COMPAT_NOTSUP	((unsigned long)0)
#undef	SIOCGIFDESCR
#define	SIOCGIFDESCR		IFADDR_COMPAT_NOTSUP
#define	SIOCGIFXFLAGS		IFADDR_COMPAT_NOTSUP
#define	SIOCGIFLLPRIO		IFADDR_COMPAT_NOTSUP
#define	SIOCGIFPRIORITY		IFADDR_COMPAT_NOTSUP
#define	SIOCGIFHARDMTU		IFADDR_COMPAT_NOTSUP
#define	SIOCSIFRTLABEL		IFADDR_COMPAT_NOTSUP
#define	SIOCIFAFATTACH		IFADDR_COMPAT_NOTSUP
#define	SIOCIFAFDETACH		IFADDR_COMPAT_NOTSUP
#define	SIOCGLIFPHYADDR		IFADDR_COMPAT_NOTSUP
#define	SIOCSLIFPHYADDR		IFADDR_COMPAT_NOTSUP
#define	SIOCGLIFPHYTTL		IFADDR_COMPAT_NOTSUP
#define	SIOCSLIFPHYTTL		IFADDR_COMPAT_NOTSUP
#define	SIOCGLIFPHYDF		IFADDR_COMPAT_NOTSUP
#define	SIOCGLIFPHYECN		IFADDR_COMPAT_NOTSUP
#define	SIOCGLIFPHYRTABLE	IFADDR_COMPAT_NOTSUP
#define	SIOCSLIFPHYRTABLE	IFADDR_COMPAT_NOTSUP
#ifndef SIOCGIFRDOMAIN
#define	SIOCGIFRDOMAIN		IFADDR_COMPAT_NOTSUP
#define	SIOCSIFRDOMAIN		IFADDR_COMPAT_NOTSUP
#define	ifr_rdomainid		ifr_ifru.ifru_fib
#endif

/* struct ifreq members of those requests; never filled on 5BSD. */
#define	ifr_llprio		ifr_ifru.ifru_metric
#define	ifr_ttl			ifr_ifru.ifru_metric
#define	ifr_df			ifr_ifru.ifru_metric
#define	ifr_hardmtu		ifr_ifru.ifru_mtu
#define	ifi_capabilities	ifi_hwassist

struct if_afreq {
	char		ifar_name[IFNAMSIZ];
	sa_family_t	ifar_af;
};

struct if_laddrreq {
	char		iflr_name[IFNAMSIZ];
	unsigned int	flags;
	unsigned int	prefixlen;
	struct sockaddr_storage addr;
	struct sockaddr_storage dstaddr;
};

/* Link state names, as OpenBSD's ifconfig prints them. */
struct if_status_description {
	u_char		ifs_type;
	u_char		ifs_state;
	const char	*ifs_string;
};

#define	LINK_STATE_DESC_MATCH(_ifs, _t, _s)				\
	(((_ifs)->ifs_type == (_t) || (_ifs)->ifs_type == 0) &&		\
	    (_ifs)->ifs_state == (_s))

#define	LINK_STATE_DESCRIPTIONS {					\
	{ IFT_ETHER, LINK_STATE_DOWN, "no carrier" },			\
	{ 0, LINK_STATE_DOWN, "down" },					\
	{ 0, LINK_STATE_UP, "active" },					\
	{ 0, LINK_STATE_UNKNOWN, "unknown" },				\
	{ 0, 0, NULL }							\
}

#endif /* !_IFADDR_COMPAT_H_ */
