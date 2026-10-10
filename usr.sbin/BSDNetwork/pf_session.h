/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BSDNETWORK_PF_SESSION_H_
#define _BSDNETWORK_PF_SESSION_H_

struct service_context;
int network_pf_open(struct service_context *context);
int network_pf_serve(int session_fd, int pf_fd, int open_error);

#endif
