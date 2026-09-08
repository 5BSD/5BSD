/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _LOCALSYSCTL_PROBES_H_
#define	_LOCALSYSCTL_PROBES_H_

#ifdef WITH_DTRACE
#include "localsysctl_provider.h"
#define	LOCALSYSCTL_PROBE_REQUEST_START(client, opcode) \
	LOCALSYSCTL_REQUEST_START(__DECONST(char *, client), opcode)
#define	LOCALSYSCTL_PROBE_REQUEST_DONE(client, opcode, bytes, status, error) \
	LOCALSYSCTL_REQUEST_DONE(__DECONST(char *, client), opcode, bytes, \
	    status, error)
#else
#define	LOCALSYSCTL_PROBE_REQUEST_START(client, opcode) \
	do { (void)(client); (void)(opcode); } while (0)
#define	LOCALSYSCTL_PROBE_REQUEST_DONE(client, opcode, bytes, status, error) \
	do { (void)(client); (void)(opcode); (void)(bytes); (void)(status); \
	    (void)(error); } while (0)
#endif

#endif /* !_LOCALSYSCTL_PROBES_H_ */
