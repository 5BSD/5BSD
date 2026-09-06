/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYSCTLCMP_H_
#define	_SYSCTLCMP_H_

#include <sys/types.h>

#include <stddef.h>

#include "sysctlcmp_protocol.h"

struct sysctlcmp_client;

__BEGIN_DECLS
/* Acquire the system.Sysctl capability over the lookup channel. */
int	sysctlcmp_client_open(struct sysctlcmp_client **);
void	sysctlcmp_client_close(struct sysctlcmp_client *);

/*
 * Read a sysctl by name into buf; *lenp is the buffer size on entry and the
 * value length on return.  As with sysctlbyname(3), passing buf==NULL and
 * *lenp==0 queries the size.  If the value does not fit the buffer the call
 * fails with ENOMEM and *lenp holds the needed size, EXCEPT that a value larger
 * than SYSCTLCMP_MAX_VALUE (the transport cap) cannot be carried at all: it
 * fails with ENOMEM and *lenp is left unchanged.  Values are opaque bytes, as
 * from sysctl(3); the caller interprets the type.  Enumeration (name-to-next)
 * is provided separately by sysctlcmp_next().
 */
int	sysctlcmp_get(struct sysctlcmp_client *, const char *name,
	    void *buf, size_t *lenp);

/*
 * Write a sysctl by name (raw value bytes, as sysctl(3) expects for the
 * variable's type), subject to the provider's per-label write policy; a
 * variable not permitted for the caller's label fails with EPERM.
 */
int	sysctlcmp_set(struct sysctlcmp_client *, const char *name,
	    const void *value, size_t len);

/*
 * Type/format of a variable: *kindp receives the sysctl(9) kind (CTLTYPE in
 * the low bits, CTLFLAG_* in the high bits), and fmt the printf-style format
 * string (*fmtlenp is the buffer size in, the string length incl. NUL out;
 * ENOMEM with the needed size if too small).  Read-policy gated.
 */
int	sysctlcmp_oidfmt(struct sysctlcmp_client *, const char *name,
	    unsigned int *kindp, char *fmt, size_t *fmtlenp);

/* Description of a variable (sysctl -d).  Read-policy gated. */
int	sysctlcmp_describe(struct sysctlcmp_client *, const char *name,
	    char *buf, size_t *lenp);

/*
 * Enumeration: given a name (or "" / NULL to start), return the next variable
 * the caller is permitted to read.  Fails with ENOENT past the last permitted
 * variable.  Enumeration never reveals names outside the caller's read policy.
 */
int	sysctlcmp_next(struct sysctlcmp_client *, const char *name,
	    char *buf, size_t *lenp);

__END_DECLS

#endif
