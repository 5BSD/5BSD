/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef LIB_LIBCAPSULERT_DIAGNOSTICS_H
#define LIB_LIBCAPSULERT_DIAGNOSTICS_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define CAPSULECLAIMS_TRACE_RIGHTS_PARSED(a0, a1, a2) \
	DTRACE_PROBE3(capsuleclaims, rights__parsed, (a0), (a1), (a2))
#else
#define CAPSULECLAIMS_TRACE_RIGHTS_PARSED(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#endif
