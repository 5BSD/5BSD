/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BSDNETWORK_PF_SESSION_H_
#define _BSDNETWORK_PF_SESSION_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

#include <libservice.h>

/*
 * system.Network.PF (bsd.network.v1 NetworkPf, lib/libnetworkcmp/
 * networkcmp.fidl).  Beyond SwitchBoard's system.network.pf.read
 * anointment, a session must carry this read right.
 */
#define	NETWORK_PF_RIGHT_READ	((service_rights_t)1)
/* A worker serves one descriptor and lives this long at most. */
#define	NETWORK_PF_SESSION_MS	5000

struct service_context;
bool network_pf_admit(service_rights_t rights);
int network_pf_open(struct service_context *context);
int network_pf_serve(int session_fd, int pf_fd, int open_error);

#endif
