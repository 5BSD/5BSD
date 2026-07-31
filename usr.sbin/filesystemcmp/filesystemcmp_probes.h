/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _FILESYSTEMCMP_PROVIDER_PROBES_H_
#define	_FILESYSTEMCMP_PROVIDER_PROBES_H_

#ifdef WITH_DTRACE
#include "filesystemcmp_provider.h"
#define	FILESYSTEMCMPD_PROBE_SESSION(label, instance, result) \
	FILESYSTEMCMP_PROVIDER_SESSION_START(__DECONST(char *, label), instance, \
	    result)
#define	FILESYSTEMCMPD_PROBE_REQUEST(label, opcode, result) \
	FILESYSTEMCMP_PROVIDER_REQUEST_DONE(__DECONST(char *, label), opcode, \
	    result)
#else
#define	FILESYSTEMCMPD_PROBE_SESSION(label, instance, result)	((void)0)
#define	FILESYSTEMCMPD_PROBE_REQUEST(label, opcode, result)	((void)0)
#endif

#endif
