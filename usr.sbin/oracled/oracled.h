/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef ORACLED_H
#define ORACLED_H

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libutil.h>
#include <stdbool.h>
#include <time.h>

#include "config.h"

/*
 * Daemon state.
 *
 * Set by main() during initialization, read by all modules.
 * Shutdown is coordinated through the 'running' flag and the
 * teardown functions.
 *
 * Module-private state (cap_rt fds, control socket fd) is kept
 * in static variables within each module.
 */
struct oracled_state {
	struct pidfh		*pidfh;
	struct oracled_config	 cfg;
	char			 conffile[PATH_MAX];
	bool			 foreground;
	bool			 test_mode;
	bool			 running;
	bool			 shutting_down;
};

extern struct oracled_state od;

/* cap_rt.c — capability runtime lifecycle */
int	cap_rt_setup(void);
void	cap_rt_teardown(void);
int	cap_rt_mint_path_token(const char *path);
int	cap_rt_mint_net_token(const struct oracled_net_claim *nc);
int	cap_rt_mint_system_token(uint32_t gates);
int	cap_rt_create_pair(int *oracle_end, int *child_end);
int	cap_rt_create_coalition(void);
int	cap_rt_mint_instance(int instance_fd);
int	cap_rt_connect_for_delegate(const char *name);
int	cap_rt_coalition_enlist(int coalition_fd, int member_fd);
int	cap_rt_coalition_set_leader(int coalition_fd, int leader_fd);
int	cap_rt_coalition_set_deadline(int coalition_fd, int timeout_ms,
	    int sig, int grace_ms);
int	cap_rt_coalition_terminate(int coalition_fd);
int	cap_rt_coalition_recv_event(int coalition_fd, uint32_t *flagsp);
int	cap_rt_reload_claims(const struct oracled_config *newcfg);
void	cap_rt_format_status(char *buf, size_t bufsz, size_t *offp);

/* control.c — control socket lifecycle */
#define	CTL_ACTION_NONE		0
#define	CTL_ACTION_SHUTDOWN	0x01
#define	CTL_ACTION_REBOOT	0x02
#define	CTL_ACTION_RELOAD	0x04

int	ctl_setup(void);
void	ctl_teardown(void);
int	ctl_fd(void);
int	ctl_accept(void);
int	ctl_conn_event(struct kevent *kev, int *reboot_howto);
bool	ctl_is_conn_event(struct kevent *kev);

/* event.c — main event loop */
extern int event_kq;
void	event_loop(void);

/* bootstrap.c — serviced lifecycle */
int	bootstrap_start(int kq);
void	bootstrap_handle_exit(struct kevent *kev, int kq);
void	bootstrap_handle_timer(struct kevent *kev, int kq);
void	bootstrap_signal(int sig);
void	bootstrap_stop(void);
bool	bootstrap_is_stopped(void);
bool	bootstrap_is_procdesc(struct kevent *kev);
bool	bootstrap_is_pair(struct kevent *kev);
bool	bootstrap_is_timer(struct kevent *kev);
pid_t	bootstrap_pid(void);

/* oracle_proto.c — pair channel protocol handler */
void	oracle_proto_init(int pair_fd);
int	oracle_proto_dispatch(struct kevent *kev);
void	oracle_proto_reset(void);
bool	oracle_proto_is_ready(void);
int	oracle_proto_fd(void);

/* proc.c — process management */
void	reap_children(void);
void	kill_subtree(void);
void	apply_procctl_self_policy(void);

/*
 * Formatting helpers for cap_rt status display.
 */
static inline const char *
net_direction_name(int dir)
{

	switch (dir) {
	case ORACLED_NET_DIR_BIND:
		return ("bind");
	case ORACLED_NET_DIR_CONNECT:
		return ("connect");
	default:
		return ("any");
	}
}

static inline const char *
net_protocol_name(int proto)
{

	switch (proto) {
	case IPPROTO_TCP:
		return ("tcp");
	case IPPROTO_UDP:
		return ("udp");
	default:
		return ("any");
	}
}

/*
 * Safe snprintf accumulator.  Appends formatted text to buf at
 * offset *offp, clamping to prevent overflow.  Caller must
 * declare: size_t off = 0;
 *
 * Usage: BUF_APPEND(buf, sizeof(buf), &off, "fmt", ...);
 */
#define	BUF_APPEND(buf, bufsz, offp, ...)	do {			\
	size_t _rem = (*(offp) < (bufsz)) ? (bufsz) - *(offp) : 0;	\
	int _n = snprintf((buf) + *(offp), _rem, __VA_ARGS__);		\
	if (_n > 0) *(offp) += (size_t)_n;				\
	if (*(offp) >= (bufsz)) *(offp) = (bufsz) - 1;			\
} while (0)

#endif /* ORACLED_H */
