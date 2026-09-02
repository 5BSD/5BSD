/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef AUTHORITYD_H
#define AUTHORITYD_H

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libutil.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "config.h"

/*
 * Daemon state.
 *
 * Set by main() during initialization, read by all modules.
 * Shutdown is coordinated through the 'running' flag and the
 * teardown functions.
 *
 * Module-private state (mac_capability fds, control socket fd) is kept
 * in static variables within each module.
 */
struct authorityd_state {
	struct pidfh		*pidfh;
	struct authorityd_config	 cfg;
	char			 conffile[PATH_MAX];
	bool			 foreground;
	bool			 test_mode;
	bool			 running;
	bool			 shutting_down;
};

extern struct authorityd_state od;

/* mac_capability.c — MAC capability lifecycle */
int	mac_capability_setup(void);
void	mac_capability_teardown(void);
int	mac_capability_mint_file_token(const char *path, uint64_t actions);
int	mac_capability_mint_net_token(const struct ort_net_claim *nc);
int	mac_capability_mint_vsock_token(const struct ort_vsock_claim *vc);
int	mac_capability_mint_system_token(uint32_t gates);
int	mac_capability_create_channel(int *authority_end, int *child_end);
int	mac_capability_create_coalition(void);
int	mac_capability_mint_instance(int instance_fd);
int	mac_capability_connect_for_delegate(const char *name);
int	mac_capability_coalition_enlist(int coalition_fd, int member_fd);
int	mac_capability_coalition_set_leader(int coalition_fd, int leader_fd);
int	mac_capability_coalition_set_deadline(int coalition_fd, int timeout_ms,
	    int sig, int grace_ms);
int	mac_capability_coalition_terminate(int coalition_fd);
int	mac_capability_coalition_recv_event(int coalition_fd, uint32_t *flagsp);
int	mac_capability_reload_claims(const struct authorityd_config *newcfg);
void	mac_capability_format_status(char *buf, size_t bufsz, size_t *offp);

/* control.c — control socket lifecycle.
 *
 * ctl_conn_event() returns an action bitmask.  For CTL_ACTION_LIFECYCLE
 * the requesting connection's opcode is carried in bits 8+ (see
 * CTL_ACTION_OP) so the transition is applied from the exact request
 * that set it — never through shared state that concurrent connections
 * could race on. */
#define	CTL_ACTION_NONE		0
#define	CTL_ACTION_SHUTDOWN	0x01
#define	CTL_ACTION_LIFECYCLE	0x02	/* PID 1 lifecycle request */
#define	CTL_ACTION_OP_SHIFT	8
#define	CTL_ACTION_OP(a)	(((a) >> CTL_ACTION_OP_SHIFT) & 0xff)

int	ctl_setup(void);
void	ctl_teardown(void);
int	ctl_fd(void);
int	ctl_accept(void);
int	ctl_conn_event(struct kevent *kev);
bool	ctl_is_conn_event(struct kevent *kev);

/* event.c — main event loop */
extern int event_kq;
void	event_loop(void);

/* bootstrap.c — serviced lifecycle */
int	bootstrap_start(int kq);
void	bootstrap_handle_exit(struct kevent *kev, int kq);
void	bootstrap_handle_channel_eof(void);
void	bootstrap_handle_timer(int kq);
void	bootstrap_signal(int sig);
void	bootstrap_stop(void);
bool	bootstrap_is_stopped(void);
bool	bootstrap_has_given_up(void);
bool	bootstrap_is_procdesc(struct kevent *kev);
bool	bootstrap_is_channel(struct kevent *kev);
bool	bootstrap_is_timer(struct kevent *kev);
pid_t	bootstrap_pid(void);

/* authority_proto.c — channel protocol handler */
void	authority_proto_init(int channel_fd);
int	authority_proto_dispatch(void);
void	authority_proto_reset(void);
bool	authority_proto_is_ready(void);
int	authority_proto_fd(void);

/* proc.c — process management */
void	reap_children(void);
void	kill_subtree(void);
int	apply_procctl_self_policy(void);

#endif /* AUTHORITYD_H */
