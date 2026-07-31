/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifdef WITH_DTRACE
#include "logcmp_provider.h"
#define	LOGCMPD_PROBE_SESSION(label, instance, result) \
	LOGCMP_PROVIDER_SESSION_START(__DECONST(char *, label), instance, result)
#define	LOGCMPD_PROBE_RECORD(label, severity, length, result) \
	LOGCMP_PROVIDER_RECORD_WRITE(__DECONST(char *, label), severity, length, \
	    result)
#define	LOGCMPD_PROBE_DROP(label, sequence, error) \
	LOGCMP_PROVIDER_RECORD_DROP(__DECONST(char *, label), sequence, error)
#else
#define	LOGCMPD_PROBE_SESSION(label, instance, result)	((void)0)
#define	LOGCMPD_PROBE_RECORD(label, severity, length, result)	((void)0)
#define	LOGCMPD_PROBE_DROP(label, sequence, error)	((void)0)
#endif
