/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * OpenBSD <sys/refcnt.h> for userland: the type embedded in <net/pfvar.h>
 * structures.  The kernel's definition is in sys/netpfil/openbsd-pf.
 * Installed as /usr/include/sys/refcnt.h.
 */
#ifndef _SYS_REFCNT_H_
#define	_SYS_REFCNT_H_

#ifdef _KERNEL
#error "kernel code gets struct refcnt from sys/netpfil/openbsd-pf"
#endif

struct refcnt {
	unsigned int	r_refs;
};

#endif /* !_SYS_REFCNT_H_ */
