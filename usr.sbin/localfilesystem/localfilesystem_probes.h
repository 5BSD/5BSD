/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LOCALFILESYSTEM_PROBES_H_
#define	_LOCALFILESYSTEM_PROBES_H_

#ifdef WITH_DTRACE
#include "localfilesystem_provider.h"
#define	LOCALFILESYSTEM_PROBE_SESSION(label, instance, result) \
	LOCALFILESYSTEM_SESSION_START(__DECONST(char *, label), instance, \
	    result)
#define	LOCALFILESYSTEM_PROBE_SESSION_END(label, result) \
	LOCALFILESYSTEM_SESSION_END(__DECONST(char *, label), result)
#define	LOCALFILESYSTEM_PROBE_REQUEST(label, opcode, result) \
	LOCALFILESYSTEM_REQUEST_DONE(__DECONST(char *, label), opcode, \
	    result)
#else
#define	LOCALFILESYSTEM_PROBE_SESSION(label, instance, result)	((void)0)
#define	LOCALFILESYSTEM_PROBE_SESSION_END(label, result)	((void)0)
#define	LOCALFILESYSTEM_PROBE_REQUEST(label, opcode, result)	((void)0)
#endif

#endif
