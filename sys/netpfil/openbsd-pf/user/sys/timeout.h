/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * OpenBSD <sys/timeout.h> for userland: struct timeout is embedded in
 * kernel-only <net/pfvar.h> structures; userland sees an opaque object.
 * The kernel's timeout(9) is in sys/netpfil/openbsd-pf.
 * Installed as /usr/include/sys/timeout.h.
 */
#ifndef _SYS_TIMEOUT_H_
#define	_SYS_TIMEOUT_H_

#ifdef _KERNEL
#error "kernel code gets timeout(9) from sys/netpfil/openbsd-pf"
#endif

struct timeout {
	void	*to_opaque[8];
};

#endif /* !_SYS_TIMEOUT_H_ */
