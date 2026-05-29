/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef ORACLED_H
#define ORACLED_H

#include <sys/types.h>
#include <sys/event.h>

#include <libutil.h>
#include <stdbool.h>
#include <time.h>

#include "config.h"

/*
 * Service launcher constants.
 */
#define	ORACLED_MAX_SERVICES		64
#define	ORACLED_MAX_PROVIDES		8
#define	ORACLED_MAX_REQUIRES		8
#define	ORACLED_MAX_CAP_PATHS		16
#define	ORACLED_MAX_CAP_NET		16
#define	ORACLED_LABEL_MAX		64

/* Restart policy */
#define	SVC_RESTART_NEVER		0
#define	SVC_RESTART_ALWAYS		1
#define	SVC_RESTART_ON_FAILURE		2

/* Service runtime state */
#define	SVC_STATE_STOPPED		0
#define	SVC_STATE_STARTING		1	/* pdfork'd, awaiting NOTE_EXEC */
#define	SVC_STATE_RUNNING		2	/* NOTE_EXEC received */
#define	SVC_STATE_STOPPING		3	/* graceful shutdown in progress */

/*
 * Parsed service manifest from /etc/oracled.d/ (UCL format).
 *
 * Immutable after manifest_load_dir().
 */
struct svc_manifest {
	char		label[ORACLED_LABEL_MAX];
	char		description[256];
	char		program[PATH_MAX];
	char		user[64];
	char		group[64];
	char		jail[ORACLED_LABEL_MAX];	/* jail name, empty = jid0 */

	/* Dependency graph edges */
	char		provides[ORACLED_MAX_PROVIDES][ORACLED_LABEL_MAX];
	unsigned	nprovides;
	char		requires[ORACLED_MAX_REQUIRES][ORACLED_LABEL_MAX];
	unsigned	nrequires;

	/* Capabilities to delegate */
	char		cap_paths[ORACLED_MAX_CAP_PATHS][PATH_MAX];
	unsigned	ncap_paths;
	struct oracled_net_claim cap_net[ORACLED_MAX_CAP_NET];
	unsigned	ncap_net;
	uint32_t	cap_system;	/* SYS_GATE_* bitmask */

	int		restart;	/* SVC_RESTART_* */
};

/*
 * Runtime state for a launched service.
 *
 * Wraps svc_manifest with process state, fds, and restart tracking.
 * The pd_fd, pair_fd, and coalition_fd are registered on the main
 * kqueue with 'this' as udata for event dispatch.
 */
struct svc_runtime {
	struct svc_manifest	manifest;

	/* Process state */
	int		state;		/* SVC_STATE_* */
	pid_t		pid;
	int		pd_fd;		/* process descriptor (parent holds) */
	int		pair_fd;	/* oracle's end of pair channel */
	int		coalition_fd;	/* coalition service instance */

	/* Restart tracking */
	unsigned	restart_count;
	bool		restart_pending;	/* timer scheduled */
	uintptr_t	timer_ident;		/* unique kevent ident */
	struct timespec	last_start;
	struct timespec	last_exit;
	int		last_exit_status;
};

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
	bool			 foreground;
	bool			 test_mode;
	bool			 running;

	/* Service launcher */
	struct svc_runtime	*services;
	unsigned		 nservices;
};

extern struct oracled_state od;

/* cap_rt.c — capability runtime lifecycle */
int	cap_rt_setup(void);
void	cap_rt_teardown(void);
int	cap_rt_mint_path_token(const char *path);
int	cap_rt_mint_net_token(void);
int	cap_rt_mint_system_token(uint32_t gates);
int	cap_rt_create_pair(int *oracle_end, int *child_end);
int	cap_rt_create_coalition(void);
int	cap_rt_coalition_enlist(int coalition_fd, int member_fd);
int	cap_rt_coalition_set_leader(int coalition_fd, int leader_fd);
int	cap_rt_coalition_graceful(int coalition_fd, int sig, int timeout_ms);
int	cap_rt_coalition_terminate(int coalition_fd);

/* control.c — control socket lifecycle */
#define	CTL_ACTION_NONE		0
#define	CTL_ACTION_SHUTDOWN	0x01
#define	CTL_ACTION_REBOOT	0x02
#define	CTL_ACTION_RELOAD	0x04

int	ctl_setup(void);
void	ctl_teardown(void);
int	ctl_fd(void);
int	ctl_handle(int *reboot_howto);

/* event.c — main event loop */
extern int event_kq;
void	event_loop(void);

/* proc.c — process management */
void	reap_children(void);
void	kill_subtree(void);
void	apply_procctl_self_policy(void);

/* manifest.c — service manifest parsing */
int	manifest_load_file(const char *path, struct svc_manifest *m);
int	manifest_load_dir(const char *dirpath,
	    struct svc_manifest *out, unsigned maxsvc, unsigned *nsvc);
void	manifest_log(const struct svc_manifest *m);
int	manifest_validate(const struct svc_manifest *m,
	    char *errbuf, size_t errlen);
int	manifest_format_summary(const struct svc_manifest *m,
	    char *buf, size_t len);

/* depgraph.c — dependency graph */
int	depgraph_sort(struct svc_runtime *svcs, unsigned nsvc);

/* execute.c — service fork/exec */
int	svc_exec(struct svc_runtime *svc, int kq);

/* supervisor.c — service lifecycle orchestration */
int	supervisor_start(int kq);
void	supervisor_handle_procdesc(struct kevent *kev);
void	supervisor_handle_pair(struct kevent *kev);
void	supervisor_stop(int kq);
int	supervisor_reload(int kq, char *summary, size_t sumlen);
int	supervisor_load_manifest(const char *path, int kq,
	    char *summary, size_t sumlen);
int	supervisor_check_manifest(const char *path,
	    char *summary, size_t sumlen);

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
