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
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <time.h>

#include "serviced_manifest.h"
#include "oracled_svc_proto.h"

/* Timeout for mac_capability channel RPC calls (oracle and direct). */
#define	SERVICED_RPC_TIMEOUT_MS		100

/* Service runtime state */
#define	SVC_STATE_STOPPED		0
#define	SVC_STATE_STARTING		1	/* pdfork'd, awaiting NOTE_EXEC */
#define	SVC_STATE_RUNNING		2	/* SVC_OP_READY received */
#define	SVC_STATE_STOPPING		3	/* graceful shutdown in progress */

/*
 * Runtime state for a launched service.
 *
 * Wraps svc_manifest with process state, fds, and restart tracking.
 * The pd_fd, channel_fd, and coalition_fd are registered on the main
 * kqueue with 'this' as udata for event dispatch.
 */
struct svc_runtime {
	struct svc_manifest	manifest;

	/* Process state */
	int		state;		/* SVC_STATE_* */
	pid_t		pid;
	int		pd_fd;		/* process descriptor (parent holds) */
	int		channel_fd;	/* oracle's end of channel */
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

	/* Attribution */
	char		launched_by[SERVICED_LABEL_MAX]; /* who triggered launch */
	struct timespec	launch_time;
	unsigned	connection_count;	/* client connections brokered via lookup (cumulative) */

	/* Bundle origin */
	unsigned	bundle_idx;		/* index in bundle registry */
	unsigned	bundle_svc_idx;		/* service index within bundle */
};

/*
 * Daemon state.
 */
#define	SERVICED_BUNDLE_DIR_SYSTEM_DEFAULT	"/Capabilities/System"
#define	SERVICED_BUNDLE_DIR_USER_DEFAULT		"/Capabilities"

extern const char *serviced_bundle_dir_system;
extern const char *serviced_bundle_dir_user;

struct serviced_state {
	int		oracle_channel_fd;	/* channel to oracled (fd 3) */
	int		channel_svc_fd;		/* channel service instance (fd 4) */
	int		coalition_svc_fd;	/* coalition service instance (fd 5) */
	int		capprotect_fd;		/* capprotect service instance (fd 6) */
	int		identity_fd;		/* mac_capability_identity service instance */
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

/* mac_capability_direct.c — direct mac_capability operations using delegated fd */
int	mac_cap_create_channel(int *our_end, int *child_end);
int	mac_cap_create_coalition(void);
int	mac_cap_coalition_enlist(int coalition_fd, int member_fd);
int	mac_cap_coalition_set_leader(int coalition_fd, int leader_fd);
int	mac_cap_coalition_graceful(int coalition_fd, int sig, unsigned timeout_ms);
int	mac_cap_coalition_terminate(int coalition_fd);
int	mac_cap_mint_capprotect(void);

/* oracle_client.c — channel protocol client to oracled */
int	oracle_mint_path(int channel_fd, const char *path);
int	oracle_mint_file(int channel_fd, const char *path, uint64_t actions);
int	oracle_mint_net(int channel_fd, const struct ort_net_claim *nc);
int	oracle_mint_jail(int channel_fd, const struct serviced_jail_claim *jc);
int	oracle_mint_vsock(int channel_fd, const struct ort_vsock_claim *vc);
int	oracle_mint_system(int channel_fd, uint32_t gates);
int	oracle_create_jail(int channel_fd, const char *name, const char *path,
	    const char *hostname, const char *ip4_addr);
int	oracle_create_channel(int channel_fd, int *our_end, int *child_end);
int	oracle_create_coalition(int channel_fd);
int	oracle_ensure_kmod(int channel_fd, const char *name);
int	oracle_delegate_service(int channel_fd, const char *name);
int	oracle_send_ready(int channel_fd);
int	oracle_claim_path(int channel_fd, const char *path);
int	oracle_claim_net(int channel_fd, const struct ort_net_claim *nc);
int	oracle_claim_jail(int channel_fd, const struct serviced_jail_claim *jc);
int	oracle_claim_system(int channel_fd, uint32_t gates);
int	oracle_release_path(int channel_fd, const char *path);
int	oracle_release_net(int channel_fd, const struct ort_net_claim *nc);
int	oracle_release_jail(int channel_fd, const struct serviced_jail_claim *jc);
int	oracle_release_system(int channel_fd, uint32_t gates);
int	oracle_release_manifest(int channel_fd, const struct svc_manifest *m);

/* kldmgr_client.c — kernel module loading */
int	kldmgr_ensure_loaded(const struct svc_manifest *m, bool system_bundle,
	    int kq);

/* depgraph.c — dependency graph */
int	depgraph_sort(struct svc_runtime *svcs, unsigned nsvc);

/* execute.c — service fork/exec */
int	svc_exec(struct svc_runtime *svc, int kq);

/* supervisor.c — service lifecycle orchestration */
void	supervisor_handle_procdesc(struct kevent *kev);
void	supervisor_handle_timer(struct kevent *kev);
void	supervisor_stop(int kq);
bool	supervisor_is_stopped(void);
void	supervisor_teardown_state(void);
void	svc_graceful_stop(struct svc_runtime *svc, int kq);
void	schedule_restart(struct svc_runtime *svc, int kq);

/* svc_proto.c — service channel protocol dispatch */
void	supervisor_handle_channel(struct kevent *kev);

/* reload.c — hot reload logic */
int	supervisor_reload(int kq, char *summary, size_t sumlen);
struct svc_runtime *svc_by_label(const char *label);
void	svc_remove(unsigned idx);
void	svc_reregister_kevents(int kq);

/* bundle_registry.c — .cap bundle scanning and provides lookup */
struct capbundle;
int	bundle_registry_init(void);
int	bundle_registry_lookup(const char *name, unsigned *bundle_idx,
	    unsigned *service_idx);
struct capbundle *bundle_registry_get(unsigned idx);
bool	bundle_registry_is_system(unsigned idx);
unsigned bundle_registry_count(void);
void	bundle_registry_teardown(void);

/* startup.c — tier-based parallel service launch */
int	startup_launch_system(int kq);

/* on_demand.c — on-demand service launch for user bundles */
int	on_demand_launch(const char *name, struct svc_runtime *requester,
	    uint64_t reply_token, int kq);
void	on_demand_check_ready(struct svc_runtime *svc, int kq);
void	on_demand_timeout(uintptr_t ident, int kq);
bool	on_demand_is_timer(uintptr_t ident);
void	on_demand_teardown(int kq);

/* naming.c — reverse-domain-name service registry */
int	naming_register(const char *name, struct svc_runtime *owner);
int	naming_unregister(const char *name, struct svc_runtime *owner);
void	naming_remove_owner(struct svc_runtime *owner);
void	naming_rebind_owner(struct svc_runtime *old_owner,
	    struct svc_runtime *new_owner);
int	naming_lookup(const char *name, struct svc_runtime *requester,
	    int *errp);

/*
 * DJB2 hash function, shared between naming.c and bundle_registry.c.
 */
static inline unsigned
serviced_hash_djb2(const char *s)
{
	unsigned long h;

	h = 5381;
	while (*s != '\0')
		h = h * 33 + (unsigned char)*s++;
	return ((unsigned)h);
}

/*
 * Initialize the fd fields of an svc_runtime to -1.
 * Used in startup.c, on_demand.c, and reload.c to avoid
 * repeating the same 4-line pattern.
 */
static inline void
svc_runtime_init_fds(struct svc_runtime *svc)
{

	svc->pd_fd = -1;
	svc->channel_fd = -1;
	svc->coalition_fd = -1;
	svc->jail_fd = -1;
}

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

#endif /* SERVICED_H */
