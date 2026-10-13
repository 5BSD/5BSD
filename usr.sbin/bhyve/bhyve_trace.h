/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef BHYVE_TRACE_H
#define BHYVE_TRACE_H
#ifdef WITH_DTRACE
#include <errno.h>
#include "vsock_provider.h"
/* Probe helpers must not change syscall-style error reporting. */
#define BHYVE_TRACE(name, ...) do { \
	if (BHYVE_##name##_ENABLED()) { \
		int trace_saved_errno = errno; \
		BHYVE_##name(__VA_ARGS__); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define BHYVE_TRACE(name, ...) ((void)0)
#endif
#define BHYVE_PHASE_START(op, phase) \
	BHYVE_TRACE(CHECKPOINT_PHASE_START, __DECONST(char *, op), \
	    __DECONST(char *, phase))
#define BHYVE_PHASE_DONE(op, phase, result, saved_errno) \
	BHYVE_TRACE(CHECKPOINT_PHASE_DONE, __DECONST(char *, op), \
	    __DECONST(char *, phase), result, saved_errno)
#endif
