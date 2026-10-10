/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDNETWORK_STATE_H_
#define _BSDNETWORK_STATE_H_
#include <sys/event.h>
struct network_state_server;
int network_state_server_create(int, struct network_state_server **);
void network_state_server_destroy(struct network_state_server *);
/* Admission consumes fd on success and failure. */
int network_state_server_add(struct network_state_server *, int, const char *);
/* 1 handled, 0 belongs to another event source. */
int network_state_server_event(struct network_state_server *,
    const struct kevent *);
#endif
