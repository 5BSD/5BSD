/*
 * 5BSD: carp
 *
 * OpenBSD's <netinet/ip_carp.h> as far as pfsync(4) uses it.  The 5BSD
 * implementation (sys/netpfil/openbsd-pf/pf_pfsync.c) applies the
 * pfsync demotion to net.inet.carp.demotion through carp_demote_adj_p.
 */
#ifndef _OPENBSD_PF_NETINET_IP_CARP_H_
#define	_OPENBSD_PF_NETINET_IP_CARP_H_

struct ifnet;

void	carp_group_demote_adj(struct ifnet *, int, char *);

#endif /* _OPENBSD_PF_NETINET_IP_CARP_H_ */
