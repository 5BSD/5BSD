/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Scriptable stand-ins for the libdtrace entry points libdtotel uses.
 */

#ifndef _DTRACE_STUB_H_
#define	_DTRACE_STUB_H_

#include <dtrace.h>

struct stub_state {
	dtrace_handle_buffered_f *bufhandler;
	void		*bufarg;
	int		 fail_handle_buffered;
	int		 fail_snap;
	int		 fail_walk;
	const dtrace_aggdata_t **aggs;
	size_t		 naggs;
	int		 jail_lookups;
};

char	*jail_getname(int);

extern struct stub_state stub;

/* Symbols: [0x1000, 0x2000) resolve to kernel`fn<N> with N = pc >> 8. */
#define	STUB_SYM_LO	0x1000
#define	STUB_SYM_HI	0x2000

#endif /* !_DTRACE_STUB_H_ */
