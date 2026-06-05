/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced — service manager daemon internals.
 */

#ifndef SERVICED_H
#define SERVICED_H

#include <sys/types.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

/*
 * Service launcher constants.
 */
#define	SERVICED_MAX_SERVICES		64
#define	SERVICED_MAX_PROVIDES		8
#define	SERVICED_MAX_REQUIRES		8
#define	SERVICED_MAX_CAP_PATHS		16
#define	SERVICED_MAX_CAP_NET		16
#define	SERVICED_MAX_CAP_JAIL		16
#define	SERVICED_LABEL_MAX		64

/* Restart policy */
#define	SVC_RESTART_NEVER		0
#define	SVC_RESTART_ALWAYS		1
#define	SVC_RESTART_ON_FAILURE		2

/* Service runtime state */
#define	SVC_STATE_STOPPED		0
#define	SVC_STATE_STARTING		1	/* pdfork'd, awaiting NOTE_EXEC */
#define	SVC_STATE_RUNNING		2	/* NOTE_EXEC received */
#define	SVC_STATE_STOPPING		3	/* graceful shutdown in progress */

/* Network claim direction flags (match cap_rt_isolation_proto.h). */
#define	SERVICED_NET_DIR_BIND		0x01
#define	SERVICED_NET_DIR_CONNECT	0x02
#define	SERVICED_NET_DIR_ANY		0x03

struct serviced_net_claim {
	int		domain;		/* AF_INET, AF_INET6, 0=any */
	int		protocol;	/* IPPROTO_TCP, IPPROTO_UDP, 0=any */
	uint16_t	port_min;	/* host byte order */
	uint16_t	port_max;	/* host byte order */
	uint8_t		direction;	/* SERVICED_NET_DIR_* */
};

struct serviced_jail_claim {
	int32_t		jid;		/* 0=not specified */
	uint32_t	actions;	/* FI_JAIL_* mask */
	char		name[64];	/* empty=not specified */
};

/*
 * Parsed service manifest from the manifest directory (UCL format).
 *
 * Immutable after manifest_load_dir().
 */
struct svc_manifest {
	char		label[SERVICED_LABEL_MAX];
	char		description[256];
	char		program[PATH_MAX];
	char		user[64];
	char		group[64];

	/* Dependency graph edges */
	char		provides[SERVICED_MAX_PROVIDES][SERVICED_LABEL_MAX];
	unsigned	nprovides;
	char		requires[SERVICED_MAX_REQUIRES][SERVICED_LABEL_MAX];
	unsigned	nrequires;

	/* Capabilities to delegate */
	char		cap_paths[SERVICED_MAX_CAP_PATHS][PATH_MAX];
	unsigned	ncap_paths;
	struct serviced_net_claim cap_net[SERVICED_MAX_CAP_NET];
	unsigned	ncap_net;
	struct serviced_jail_claim cap_jail[SERVICED_MAX_CAP_JAIL];
	unsigned	ncap_jail;
	uint32_t	cap_system;	/* SYS_GATE_* bitmask */

	/* Jail to create and attach child into (optional). */
	bool		has_jail;
	char		jail_name[64];
	char		jail_path[PATH_MAX];
	char		jail_hostname[64];
	char		jail_ip4_addr[64];

	int		restart;	/* SVC_RESTART_* */
	int		stop_timeout;	/* seconds before SIGKILL (default 5) */
	unsigned	max_failures;	/* circuit breaker threshold (default 10) */
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
	int		jail_fd;	/* jail descriptor (-1 if no jail) */

	/* Restart tracking */
	unsigned	restart_count;
	bool		restart_pending;	/* timer scheduled */
	uintptr_t	timer_ident;		/* unique kevent ident */
	bool		stop_kill_pending;	/* SIGKILL timer scheduled */
	uintptr_t	stop_timer_ident;
	bool		remove_pending;		/* remove after NOTE_EXIT */
	bool		reload_pending;		/* swap manifest after NOTE_EXIT */
	struct svc_manifest pending_manifest;
	struct timespec	last_start;
};

/*
 * Daemon state.
 */
struct serviced_state {
	int		oracle_pair_fd;		/* pair to oracled (fd 3) */
	int		pair_svc_fd;		/* pair service instance (fd 4) */
	int		coalition_svc_fd;	/* coalition service instance (fd 5) */
	int		capprotect_fd;		/* capprotect service instance (fd 6) */
	char		manifest_dir[PATH_MAX];
	bool		running;
	bool		shutting_down;

	/* Service launcher */
	struct svc_runtime	*services;
	unsigned		 nservices;
};

extern struct serviced_state sd;
extern int serviced_kq;

/* sctl.c — control socket */
int	sctl_setup(void);
void	sctl_teardown(void);
int	sctl_fd(void);
void	sctl_accept(void);
void	sctl_conn_event(struct kevent *kev);
bool	sctl_is_conn_event(struct kevent *kev);

/* caprt_direct.c — direct cap_rt operations using delegated fd */
int	caprt_create_pair(int *our_end, int *child_end);
int	caprt_create_coalition(void);
int	caprt_coalition_enlist(int coalition_fd, int member_fd);
int	caprt_coalition_set_leader(int coalition_fd, int leader_fd);

/* oracle_client.c — pair protocol client to oracled */
int	oracle_mint_path(int pair_fd, const char *path);
int	oracle_mint_file(int pair_fd, const char *path, uint64_t actions);
int	oracle_mint_net(int pair_fd, const struct serviced_net_claim *nc);
int	oracle_mint_jail(int pair_fd, const struct serviced_jail_claim *jc);
int	oracle_mint_system(int pair_fd, uint32_t gates);
int	oracle_create_jail(int pair_fd, const char *name, const char *path,
	    const char *hostname, const char *ip4_addr);
int	oracle_create_pair(int pair_fd, int *our_end, int *child_end);
int	oracle_create_coalition(int pair_fd);
int	oracle_send_ready(int pair_fd);
int	oracle_ping(int pair_fd);

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
void	supervisor_handle_timer(struct kevent *kev);
void	supervisor_stop(int kq);
bool	supervisor_is_stopped(void);
void	supervisor_teardown_state(void);
void	svc_graceful_stop(struct svc_runtime *svc, int kq);
void	schedule_restart(struct svc_runtime *svc, int kq);

/* svc_proto.c — service pair protocol dispatch */
void	supervisor_handle_pair(struct kevent *kev);

/* reload.c — hot reload logic */
int	supervisor_reload(int kq, char *summary, size_t sumlen);
int	supervisor_load_manifest(const char *path, int kq,
	    char *summary, size_t sumlen);
int	supervisor_check_manifest(const char *path,
	    char *summary, size_t sumlen);
void	svc_remove(unsigned idx);
void	svc_reregister_kevents(int kq);

/* naming.c — reverse-domain-name service registry */
int	naming_register(const char *name, struct svc_runtime *owner);
int	naming_unregister(const char *name, struct svc_runtime *owner);
void	naming_remove_owner(struct svc_runtime *owner);
int	naming_lookup(const char *name, struct svc_runtime *requester,
	    int *errp);

/*
 * Formatting helpers for human-readable names.
 * Used by manifest.c and supervisor.c.
 */
static inline const char *
restart_policy_name(int policy)
{

	switch (policy) {
	case SVC_RESTART_ALWAYS:
		return ("always");
	case SVC_RESTART_ON_FAILURE:
		return ("on-failure");
	default:
		return ("never");
	}
}

static inline const char *
net_direction_name(int dir)
{

	switch (dir) {
	case SERVICED_NET_DIR_BIND:
		return ("bind");
	case SERVICED_NET_DIR_CONNECT:
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

#endif /* SERVICED_H */
