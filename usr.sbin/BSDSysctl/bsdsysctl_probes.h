/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _BSDSYSCTL_PROBES_H_
#define	_BSDSYSCTL_PROBES_H_

#ifdef WITH_DTRACE
#include "bsdsysctl_provider.h"
#define	BSDSYSCTL_PROBE_REQUEST_START(client, opcode) \
	BSDSYSCTL_REQUEST_START(__DECONST(char *, client), opcode)
#define	BSDSYSCTL_PROBE_REQUEST_DONE(client, opcode, bytes, status, error) \
	BSDSYSCTL_REQUEST_DONE(__DECONST(char *, client), opcode, bytes, \
	    status, error)
#else
#define	BSDSYSCTL_PROBE_REQUEST_START(client, opcode) \
	do { (void)(client); (void)(opcode); } while (0)
#define	BSDSYSCTL_PROBE_REQUEST_DONE(client, opcode, bytes, status, error) \
	do { (void)(client); (void)(opcode); (void)(bytes); (void)(status); \
	    (void)(error); } while (0)
#endif

#endif /* !_BSDSYSCTL_PROBES_H_ */
