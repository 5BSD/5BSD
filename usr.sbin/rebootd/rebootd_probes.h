#ifndef _REBOOTD_PROBES_H_
#define	_REBOOTD_PROBES_H_
#ifdef WITH_DTRACE
#include "rebootd_provider.h"
#define	REBOOTD_PROBE_SESSION_START(label)				\
	REBOOTD_SESSION_START((label))
#define	REBOOTD_PROBE_SESSION_END(label, result)			\
	REBOOTD_SESSION_END((label), (result))
#define	REBOOTD_PROBE_REQUEST(label, opcode, result)			\
	REBOOTD_REQUEST((label), (opcode), (result))
#define	REBOOTD_PROBE_MALFORMED(label, result)				\
	REBOOTD_MALFORMED((label), (result))
#else
#define	REBOOTD_PROBE_SESSION_START(label)	((void)0)
#define	REBOOTD_PROBE_SESSION_END(label, result)	((void)0)
#define	REBOOTD_PROBE_REQUEST(label, opcode, result)	((void)0)
#define	REBOOTD_PROBE_MALFORMED(label, result)	((void)0)
#endif
#endif
