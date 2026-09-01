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
#include <string.h>
#include <time.h>

#include "serviced_manifest.h"
#include "authorityd_svc_proto.h"

struct channel;
struct channel_message;

/* Timeout for mac_capability channel RPC calls (authority and direct). */
#define	SERVICED_RPC_TIMEOUT_MS		100

/*
 * Unit kind.  serviced manages a heterogeneous graph of units; the kind
 * selects the launch method, the readiness contract, and the default
 * restart policy.  NATIVE == 0 so a calloc'd svc_runtime defaults to the
 * current capability-service behavior and every existing code path is
 * unchanged until a unit is explicitly given another kind.
 *
 * The unit's stable identity is its manifest.label: runtime state is keyed
 * by label, so a unit may migrate between kinds (an rc service rewritten as
 * a .cap bundle: RC -> NATIVE) without changing its identity or disturbing
 * consumers.  Units carry no startup ordering; they launch in parallel and
 * satisfy inter-service needs on demand via IPC activation.  bundle_idx is
 * merely origin and is only meaningful for bundle-sourced units.
 *
 * SVC_KIND_RC provides rc(8) compatibility — serviced can run existing
 * rc.d services via service(8) so the base boots and migrates one service
 * at a time.  (This is unrelated to daemon version compatibility, which we
 * do not support: serviced and authorityd are always built and run together.)
 */
enum svc_kind {
	SVC_KIND_NATIVE = 0,	/* .cap bundle: cap mode + minted tokens */
	SVC_KIND_RC,		/* rc.d service via service(8); unconfined */
	SVC_KIND_ONESHOT,	/* runs once to completion; no restart */
	SVC_KIND_TARGET,	/* synthetic sync point; no process */
	SVC_KIND_TIMER,		/* schedule that activates another unit */
};

/* Service runtime state */
#define	SVC_STATE_STOPPED		0
#define	SVC_STATE_STARTING		1	/* pdfork'd, awaiting readiness */
#define	SVC_STATE_RUNNING		2	/* ready (see svc_kind readiness) */
#define	SVC_STATE_STOPPING		3	/* graceful shutdown in progress */
#define	SVC_STATE_DONE			4	/* oneshot completed successfully */

#define	SVC_NAME_UNCLAIMED		0
#define	SVC_NAME_INACTIVE		1
#define	SVC_NAME_ACTIVATING		2
#define	SVC_NAME_READY			3

/*
 * Lookup domain — a scope over the naming layer (§22).  A domain does not add
 * a namespace; it narrows *which* registered names a lookup channel may
 * resolve, layered on top of the existing per-name authorization.  Domains
 * only ever NARROW: SYSTEM (the default, value 0) resolves every registered
 * name, while USER resolves only an explicit allow-list of system names (plus
 * future user-scoped services).  A minted user-domain channel can therefore
 * never see more than the system channel that minted it, only less.
 *
 * uid is meaningful only for SVC_DOMAIN_USER; a SYSTEM domain ignores it.
 * Because SVC_DOMAIN_SYSTEM == 0, a calloc'd svc_runtime (and any zero-filled
 * requester state) defaults to the system domain and every existing lookup
 * path keeps its current behavior.
 */
enum svc_domain_kind {
	SVC_DOMAIN_SYSTEM = 0,	/* root scope: all registered SYSTEM names */
	SVC_DOMAIN_USER,	/* per-uid scope: allow-list + user services */
	SVC_DOMAIN_CONTROL,	/* admin scope: resolves ONLY control names,
				 * and control names resolve ONLY here */
};

struct svc_domain {
	enum svc_domain_kind	kind;
	uid_t			uid;	/* meaningful only for SVC_DOMAIN_USER */
};

/*
 * Runtime state for a launched service.
 *
 * Wraps svc_manifest with process state, fds, and restart tracking.
 * The pd_fd, channel_fd, and coalition_fd are registered on the main
 * kqueue with 'this' as udata for event dispatch.
 */
struct svc_launch;	/* opaque async-launch context, defined in execute.c */

struct svc_runtime {
	struct svc_manifest	manifest;
	enum svc_kind	kind;		/* launch method + readiness contract */

	/*
	 * Lookup domain for SVC_OP_LOOKUP arriving on this unit's control
	 * channel.  Zero-initialized to SVC_DOMAIN_SYSTEM: serviced-launched
	 * system units resolve every registered name, exactly as before.
	 */
	struct svc_domain	domain;

	/* Process state */
	int		state;		/* SVC_STATE_* */
	pid_t		pid;
	uint64_t	launch_id;	/* unique for each exec attempt */
	int		pd_fd;		/* process descriptor (parent holds) */
	int		channel_fd;	/* authority's end of channel */
	struct channel	*control_channel; /* owns channel_fd */
	int		coalition_fd;	/* coalition service instance */
	struct svc_launch *launch;	/* non-NULL while a launch is in progress */
	bool		protocol_ready;	/* SVC_OP_READY advisory received */
	bool		lookup_activated; /* launched to satisfy a named lookup */
	bool		want_console;	/* stdio on /dev/console (rc bootstrap) */
	uint8_t		name_state[SERVICED_MAX_PROVIDES];
	/*
	 * Per-provides transfer policy the provider set at claim time (its own
	 * protocol contract, not manifest policy): true leaves each delivered
	 * session CAP_XFER_UNLIMITED (the consumer may forward it), false (the
	 * default) attenuates it to CAP_XFER_NONE.
	 */
	bool		name_sendable[SERVICED_MAX_PROVIDES];

	/* Restart tracking */
	unsigned	restart_count;
	bool		restart_pending;	/* timer scheduled */
	uintptr_t	timer_ident;		/* unique kevent ident */
	bool		stop_kill_pending;	/* SIGKILL timer scheduled */
	bool		quiesce_pending;	/* awaiting SVC_OP_QUIESCE_RESULT */
	uintptr_t	stop_timer_ident;
	bool		remove_pending;		/* remove after NOTE_EXIT */
	bool		reload_pending;		/* swap manifest after NOTE_EXIT */
	bool		rc_stopping;		/* RC unit running "service <label> onestop" */
	struct svc_manifest pending_manifest;
	struct timespec	last_start;

	/* Provider-driven idle shutdown (SVC_OP_IDLE) */
	unsigned	idle_timeout_sec;	/* 0 = idle shutdown not requested */
	uintptr_t	idle_timer_ident;	/* 0 = no idle timer armed */
	bool		idle_stop_pending;	/* idle timer fired; keep slot for relaunch */

	/*
	 * Activation sources (Phase 5).  These outlive the unit's own
	 * start/stop cycles: the timer keeps firing and the vnode watch keeps
	 * reporting while the activated unit is stopped, each fire creating
	 * fresh demand.  activation_timer_ident carries the ACTIVATION_TIMER_BIT
	 * tag and is matched per-unit; activation_path_fd is the watched vnode
	 * descriptor (its value is the EVFILT_VNODE ident).
	 */
	uintptr_t	activation_timer_ident;	/* 0 = no periodic timer armed */
	int		activation_path_fd;	/* -1 = no path watch open */
	int		activation_queue_fd;	/* -1 = no queue-dir watch open */
	uintptr_t	activation_mount_ident;	/* 0 = no EVFILT_FS mount watch */
	/*
	 * Manager-owned socket activation listeners (Phase 4).  serviced binds
	 * and holds each listening socket declared by the unit; the first inbound
	 * connection creates demand.  These outlive the unit's start/stop cycles
	 * and, crucially, are NOT closed on provider stop/restart (only on unit
	 * removal via activation_source_teardown), so a queued connection is never
	 * dropped across a restart.  Each entry is -1 when unarmed; entry i
	 * corresponds to manifest.activation_sockets[i].
	 */
	int		activation_listen_fds[SERVICED_MAX_ACTIVATION_SOCKETS];
	unsigned	nactivation_listen;

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

/*
 * Operator disable list: bundle identities (one per line, '#' comments) that
 * serviced skips at scan time even though their bundles are installed.  This
 * is the persistent enablement toggle behind servicectl enable/disable and the
 * installer's capability-selection step.  It lives under /Capabilities with the
 * bundle registry it governs, not in a UNIX state directory.
 */
#define	SERVICED_DISABLED_PATH			"/Capabilities/Config/serviced/disabled"

extern const char *serviced_bundle_dir_system;
extern const char *serviced_bundle_dir_user;

struct serviced_state {
	int		authority_channel_fd;	/* channel to authorityd (fd 3) */
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

/*
 * serviced's retained client end of the SYSTEM ambient lookup channel (§21),
 * or -1 if none was installed.  Held open for the life of the daemon so every
 * process serviced forks for the rc world (and everything rc launches)
 * inherits it; svc_exec_command spares it from the child's closefrom(2).
 * Installed once in startup.c before /etc/rc runs.
 */
extern int serviced_ambient_lookup_fd;

/* sctl.c — capability control plane (system.serviced / system.lifecycle) */
void	sctl_teardown(void);
void	sctl_conn_event(struct kevent *kev);
bool	sctl_is_conn_event(struct kevent *kev);
/*
 * Adopt a freshly minted provider endpoint as an in-process capability control
 * connection (P3): serviced services SERVICED_CONTROL_NAME itself, gating
 * privileged ops on SVC_RIGHTS_ADMIN present in rights rather than a peer euid.
 * Takes ownership of provider_fd (closes it on failure).
 */
int	sctl_adopt_channel(int provider_fd, uint64_t rights, bool authority_relay);

/* mac_capability_direct.c — direct mac_capability operations using delegated fd */
int	mac_cap_create_channel(int *our_end, int *child_end);
int	mac_cap_create_coalition(void);
int	mac_cap_coalition_enlist(int coalition_fd, int member_fd);
int	mac_cap_coalition_set_leader(int coalition_fd, int leader_fd);
int	mac_cap_coalition_graceful(int coalition_fd, int sig, unsigned timeout_ms);
int	mac_cap_coalition_terminate(int coalition_fd);
int	mac_cap_mint_capprotect(void);
int	mac_cap_protect(int capprotect_fd, int pd_fd, uint32_t flags);

/* authority_client.c — channel protocol client to authorityd */
int	authority_mint_path(int channel_fd, const char *path);
int	authority_mint_file(int channel_fd, const char *path, uint64_t actions);
int	authority_mint_net(int channel_fd, const struct ort_net_claim *nc);
int	authority_mint_system(int channel_fd, uint32_t gates);
int	authority_create_channel(int channel_fd, int *our_end, int *child_end);
int	authority_create_coalition(int channel_fd);
int	authority_send_ready(int channel_fd);
int	authority_set_ambient_lookup(int channel_fd, int lookup_fd);
/*
 * Relay a system lifecycle op (a CTL_OP_* lifecycle opcode) to authorityd
 * (docs/lifecycle-capability-design.md, P4b).  Returns the authority's status
 * (0 = accepted), or -1 on a channel/transport failure.
 */
int	authority_lifecycle(int channel_fd, uint32_t lifecycle_op);
/* Relay an authority config reload to authorityd (P4b).  0 = ok, -1 = error. */
int	authority_reload(int channel_fd);
int	authority_release_manifest(int channel_fd, const struct svc_manifest *m);


/* execute.c — service fork/exec */
int	svc_exec(struct svc_runtime *svc, int kq);
int	svc_exec_rc_stop(struct svc_runtime *svc, int kq);
int	svc_launch_or_await(struct svc_runtime *svc, int kq);

/* supervisor.c — service lifecycle orchestration */
void	supervisor_handle_procdesc(struct kevent *kev);
void	supervisor_handle_timer(struct kevent *kev);
void	supervisor_stop(int kq);
bool	supervisor_is_stopped(void);
void	supervisor_teardown_state(void);
void	svc_graceful_stop(struct svc_runtime *svc, int kq);
void	svc_cancel_restart(struct svc_runtime *svc, int kq);
void	arm_idle_timer(struct svc_runtime *svc, int kq);
void	cancel_idle_timer(struct svc_runtime *svc, int kq);
void	svc_quiesce_complete(struct svc_runtime *, int status, int kq);
void	schedule_restart(struct svc_runtime *svc, int kq);

/* svc_proto.c — service channel protocol dispatch */
void	supervisor_handle_channel(struct kevent *kev);
/*
 * Native-launch machinery (execute.c).  svc_exec mints synchronously and forks
 * straight through; svc_launch_cancel aborts an in-progress launch context.
 */
void	svc_launch_cancel(struct svc_runtime *svc, int kq);
int	svc_channel_attach(struct svc_runtime *, int);
int	svc_channel_rebind(struct svc_runtime *);
void	svc_channel_close(struct svc_runtime *);
void	svc_channel_sync_events(struct svc_runtime *, int);
int	svc_channel_send_event(struct svc_runtime *, const void *, size_t,
	    const int *, size_t, int);

/* reload.c — hot reload logic */
int	supervisor_reload(int kq, char *summary, size_t sumlen);
struct svc_runtime *svc_by_label(const char *label);
void	svc_remove(unsigned idx);
void	svc_reregister_kevents(int kq);

/* bundle_registry.c — .cap bundle scanning and provides lookup */
struct capbundle;
struct capbundle_service;
int	bundle_registry_init(void);
int	bundle_registry_lookup(const char *name, unsigned *bundle_idx,
	    unsigned *service_idx);
struct capbundle *bundle_registry_get(unsigned idx);
bool	bundle_registry_is_system(unsigned idx);
unsigned bundle_registry_count(void);
void	bundle_registry_teardown(void);

/* startup.c — tier-based parallel service launch */
int	startup_launch_system(int kq);

/* activation.c — timer and path activation sources (Phase 5) */
int	activation_register_all(int kq);
void	activation_source_arm(struct svc_runtime *svc, int kq);
void	activation_source_teardown(struct svc_runtime *svc, int kq);
bool	activation_timer_owns(uintptr_t ident);
void	activation_timer_fire(uintptr_t ident, int kq);
void	activation_path_event(struct kevent *kev, int kq);
void	activation_mount_event(struct kevent *kev, int kq);
void	svc_run_container_remove(const char *label);
void	svc_run_container_sweep(void);
bool	activation_socket_owns(int fd);
void	activation_socket_event(struct kevent *kev, int kq);

/*
 * A serviced-held lookup channel (defined in domain.c).  on_demand.c only ever
 * holds it as an opaque handle for an ambient (login-session) requester.
 */
struct svc_lookup_channel;

/* on_demand.c — on-demand service launch for user bundles */
int	on_demand_launch(const char *name, struct svc_runtime *requester,
	    struct channel_message *request, int kq);
int	on_demand_launch_ambient(const char *name,
	    struct svc_lookup_channel *lc, const struct svc_domain *domain,
	    struct channel_message *request, int kq);
void	on_demand_lookup_channel_gone(struct svc_lookup_channel *lc, int kq);
void	on_demand_check_ready(struct svc_runtime *svc, int kq);
bool	on_demand_name_activating(struct svc_runtime *, const char *);
int	on_demand_name_claim(struct svc_runtime *, const char *, bool sendable);
bool	on_demand_name_sendable(const struct svc_runtime *, const char *);
bool	on_demand_all_names_claimed(const struct svc_runtime *);
int	on_demand_name_withdraw(struct svc_runtime *, const char *, int);
void	on_demand_name_ready(struct svc_runtime *, const char *, int);
void	on_demand_name_failed(struct svc_runtime *, const char *, int, int);
void	on_demand_provider_failed(struct svc_runtime *svc, int error, int kq);
void	on_demand_requester_gone(struct svc_runtime *svc, int kq);
void	on_demand_timeout(uintptr_t ident, int kq);
bool	on_demand_is_timer(uintptr_t ident);
void	on_demand_teardown(int kq);

/* naming.c — reverse-domain-name service registry */
bool	naming_exists(const char *name);
int	naming_register(const char *name, struct svc_runtime *owner,
	    bool sendable);
int	naming_unregister(const char *name, struct svc_runtime *owner);
void	naming_remove_owner(struct svc_runtime *owner);
void	naming_rebind_owner(struct svc_runtime *old_owner,
	    struct svc_runtime *new_owner);
int	naming_lookup(const char *name, struct svc_runtime *requester,
	    const struct svc_domain *domain, int *errp, bool *sendablep);

/* domain.c — lookup-domain scoping and minted user-domain channels (§21/§22) */
bool	lookup_channel_is_live(const struct svc_lookup_channel *lc);
void	lookup_channel_sync_events(struct svc_lookup_channel *lc, int kq);
bool	svc_domain_resolves(const struct svc_domain *domain, const char *name);
bool	name_is_control(const char *name);
bool	svc_domain_permits(const struct svc_domain *chan,
	    enum svc_domain_kind name_domain, const char *name);
bool	svc_domain_may_mint(const struct svc_domain *domain);
int	svc_fd_make_ambient(int fd);
int	domain_mint_user_channel(uid_t uid, int *out_fd, int kq);
int	domain_mint_system_channel(int *out_fd, int kq);
int	domain_mint_session_channel(enum svc_domain_kind kind, uid_t uid,
	    int *out_fd, int kq);
int	svc_mint_domain_kind(const struct svc_domain *requester,
	    uint32_t wire_domain, enum svc_domain_kind *kind);
bool	domain_channel_owns_event(uintptr_t ident);
void	domain_channel_event(struct kevent *kev, int kq);
void	domain_channel_teardown(void);

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
	svc->control_channel = NULL;
	svc->coalition_fd = -1;
	svc->activation_path_fd = -1;
	svc->activation_queue_fd = -1;
	svc->activation_mount_ident = 0;
	for (unsigned aidx = 0; aidx < SERVICED_MAX_ACTIVATION_SOCKETS; aidx++)
		svc->activation_listen_fds[aidx] = -1;
	svc->nactivation_listen = 0;
	svc->protocol_ready = false;
	memset(svc->name_state, SVC_NAME_UNCLAIMED,
	    sizeof(svc->name_state));
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
