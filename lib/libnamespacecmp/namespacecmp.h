/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _NAMESPACECMP_H_
#define _NAMESPACECMP_H_

/* The system.Namespace client (formerly part of libservice). */
#include <libservice.h>

__BEGIN_DECLS
/*
 * Confine this process to a jail via bsdnamespace (system.Namespace).  Consumer self-
 * service: libservice resolves bsdnamespace by name, has it create a jail rooted at
 * `path` (scoped by this process's channel label), and jail_attach_jd(2)s the
 * process to the returned descriptor — whose root credential authorizes the
 * attach, so a non-root caller may confine itself.  hostname/ip4_addr may be
 * NULL.  switchboard is not involved.
 *
 * `flags` is 0 for a persistent jail (reused by label across restarts) or
 * SERVICE_NS_EPHEMERAL for a jail whose lifetime is bound to this process (torn
 * down when the process exits).  Returns 0, or -1 with errno.
 */
#define	SERVICE_NS_EPHEMERAL	0x1u	/* jail lifetime bound to the caller */
#define	SERVICE_NS_VNET		0x2u	/* jail gets its own vnet (needs VIMAGE) */
int	service_enter_namespace(struct service_context *, const char *path,
	    const char *hostname, const char *ip4_addr, unsigned flags);
/*
 * As service_enter_namespace(3) but with an IPv6 address (ip6_addr; "" or NULL =
 * none) and the full SERVICE_NS_* flag set, including SERVICE_NS_VNET for a
 * jail with its own virtual network stack.  service_enter_namespace is this with
 * ip6_addr="".  Returns 0, or -1 with errno.
 */
int	service_enter_namespace_ex(struct service_context *, const char *path,
	    const char *hostname, const char *ip4_addr, const char *ip6_addr,
	    unsigned flags);
/*
 * Destroy the caller's namespace (jail), scoped to the caller's own label so it
 * can never name another's.  Returns 0, or -1 with errno (ENOENT if none).
 */
int	service_destroy_namespace(struct service_context *);

/*
 * The caller's namespace (jail) as reported by service_namespace_info(3).  A
 * label owns at most one jail: present==1 with the fields filled, or present==0.
 * An address field is empty ("") when the jail has no address of that family.
 *
 * `flags` carries the SERVICE_NS_* bits describing the jail, so a consumer that
 * lists after a restart can pass them straight back to service_enter_namespace_ex
 * to reconstruct a matching request: SERVICE_NS_VNET when the jail has its own
 * virtual network stack, SERVICE_NS_EPHEMERAL when this process's own connection
 * is anchoring the jail's lifetime (a persistent jail reused across a restart
 * reports it clear).
 */
struct service_namespace_info {
	int		present;	/* 1 = the caller has a jail, 0 = none */
	int		jid;		/* jail id when present */
	unsigned	flags;		/* SERVICE_NS_* describing the jail */
	char		path[PATH_MAX];	/* jail root path */
	char		hostname[64];	/* host.hostname */
	char		ip4_addr[64];	/* ip4.addr (empty if none) */
	char		ip6_addr[64];	/* ip6.addr (empty if none) */
};
/*
 * Report the caller's namespace (jail) into *out.  present==0 (no jail) is still
 * a success (returns 0).  Owner-scoped.  Returns -1 with errno on real failure.
 */
int	service_namespace_info(struct service_context *,
	    struct service_namespace_info *out);

__END_DECLS

#endif
