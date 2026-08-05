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
#define	REBOOTD_PROBE_SCHEDULE(label, id, at, howto)			\
	REBOOTD_SCHEDULE_CREATE((label), (id), (at), (howto))
#define	REBOOTD_PROBE_IMMINENT(id, remaining)			\
	REBOOTD_SCHEDULE_IMMINENT((id), (remaining))
#define	REBOOTD_PROBE_CANCEL(id, error)				\
	REBOOTD_SCHEDULE_CANCEL((id), (error))
#define	REBOOTD_PROBE_EXECUTE(id, howto, result)			\
	REBOOTD_SCHEDULE_EXECUTE((id), (howto), (result))
#else
#define	REBOOTD_PROBE_SESSION_START(label)	((void)0)
#define	REBOOTD_PROBE_SESSION_END(label, result)	((void)0)
#define	REBOOTD_PROBE_REQUEST(label, opcode, result)	((void)0)
#define	REBOOTD_PROBE_MALFORMED(label, result)	((void)0)
#define	REBOOTD_PROBE_SCHEDULE(label, id, at, howto)	((void)0)
#define	REBOOTD_PROBE_IMMINENT(id, remaining)	((void)0)
#define	REBOOTD_PROBE_CANCEL(id, error)	((void)0)
#define	REBOOTD_PROBE_EXECUTE(id, howto, result)	((void)0)
#endif
#endif
