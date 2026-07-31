#ifndef _KLDMGRD_PROBES_H_
#define	_KLDMGRD_PROBES_H_
#ifdef WITH_DTRACE
#include "kldmgrd_provider.h"
#define	KLDMGRD_PROBE_SESSION_START(label)				\
	KLDMGRD_SESSION_START((label))
#define	KLDMGRD_PROBE_SESSION_END(label, result)			\
	KLDMGRD_SESSION_END((label), (result))
#define	KLDMGRD_PROBE_REQUEST(label, opcode, result)			\
	KLDMGRD_REQUEST((label), (opcode), (result))
#define	KLDMGRD_PROBE_MALFORMED(label, result)				\
	KLDMGRD_MALFORMED((label), (result))
#else
#define	KLDMGRD_PROBE_SESSION_START(label)	((void)0)
#define	KLDMGRD_PROBE_SESSION_END(label, result)	((void)0)
#define	KLDMGRD_PROBE_REQUEST(label, opcode, result)	((void)0)
#define	KLDMGRD_PROBE_MALFORMED(label, result)	((void)0)
#endif
#endif
