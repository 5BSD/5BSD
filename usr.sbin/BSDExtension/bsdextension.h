/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal interface for bsdextension(8) — the system-extension broker.
 *
 * The allow-list configuration type and the pure-logic entry points live here
 * so the daemon translation unit and its unit tests share one definition.  In a
 * normal build the pure-logic functions stay file-static (SYSEXT_STATIC ==
 * static) and nothing beyond this type escapes.  Under -DBSDEXTENSION_TESTING the
 * daemon's main() is compiled out, the pure-logic functions gain external
 * linkage, and a test-only serve entry point (sysext_test_serve) is exposed so a
 * test can drive the real request handler over a real channel.  There is no
 * behavioural difference between the two builds — only linkage and the presence
 * of main().
 */

#ifndef _BSDEXTENSION_H_
#define _BSDEXTENSION_H_

#include <sys/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <libservice.h>

#include "sysext_proto.h"	/* SYSEXT_NAME_MAX */

#define	SYSEXT_MAX_ALLOW	256	/* allow-list capacity */
#define	SYSEXT_MAX_DRIVER_CLIENTS 8	/* driver_clients capacity */
#define	SYSEXT_CLIENT_MAX	64	/* switchboard label bound */
#define	SYSEXT_DEFAULT_CONF	"/Capabilities/Config/bsdextension.ucl"
/*
 * Bundle-relative config filename, opened via the switchboard-delivered Config
 * descriptor (service_config_open) since a born-in-capmode broker has no global
 * namespace access.
 */
#define	SYSEXT_CONFIG_NAME	"bsdextension.ucl"
#define SYSEXT_POLICY_DIR "/etc/bsdextension"

/* Internal parser shared by base and override policy; caller owns the fd. */
struct ucl_object_s;
struct ucl_object_s *sysext_config_object_fd(int, mode_t);

struct sysext_config {
	char	allow[SYSEXT_MAX_ALLOW][SYSEXT_NAME_MAX];
	size_t	nallow;
	/*
	 * device_drivers: also permit a module the delivered kernel directory's
	 * linker.hints records with plug-and-play match data (a hardware
	 * driver devmatch(8) selects), unless an administrator denied it.
	 */
	bool	device_drivers;
	/*
	 * driver_clients: switchboard client labels (service_identity
	 * client_label) admitted for the hardware-driver class only.  Such a
	 * client never loads an allowed_extensions entry; with device_drivers
	 * false it loads nothing.  devd's lasting grant (switchboard
	 * service-authority.ucl) is the intended member.
	 */
	char	driver_clients[SYSEXT_MAX_DRIVER_CLIENTS][SYSEXT_CLIENT_MAX];
	size_t	ndriver_clients;
};

struct sysext_policy;
struct sysext_policy *sysext_policy_create(const struct sysext_config *);
void sysext_policy_destroy(struct sysext_policy *);
int sysext_policy_snapshot(struct sysext_policy *, struct sysext_config *);
int sysext_policy_reload(struct sysext_policy *, const char *, service_rights_t);
/* Reload from an already-open config descriptor (capmode-safe; borrows fd). */
int sysext_policy_reload_fd(struct sysext_policy *, int fd, service_rights_t);
int sysext_config_reload(struct sysext_config *, const char *);
int sysext_config_reload_fd(struct sysext_config *, int);
/* Parse the allow-list from an already-open descriptor (capmode-safe reload). */
int sysext_config_load_fd(struct sysext_config *cfg, int fd);

/* Administrator configuration is independent of the filesystem provider.
 * The manifest supplies this private root-filesystem directory by descriptor;
 * attaching before serving makes overrides effective even for bootstrap loads. */
int sysext_policy_attach(struct sysext_policy *, int);
int sysext_policy_change(struct sysext_policy *, uint32_t, const char *,
    service_rights_t);
int sysext_policy_info(struct sysext_policy *, const char *, bool,
    struct sysext_info_reply *);
int sysext_policy_enabled(struct sysext_policy *, struct sysext_config *);
/* True when an administrator override explicitly denies name. */
bool sysext_policy_denied(struct sysext_policy *, const char *);

/*
 * Hardware-driver class.  The manifest delivers the kernel directory
 * (/boot/kernel) by descriptor; sysext_driver_module() reads its linker.hints
 * and reports whether name (with or without .ko) is a module file that
 * carries MDT_PNP_INFO records.  sysext_hints_pnp_module() is the bounded
 * parser over an in-memory hints image.
 */
#define	SYSEXT_KERNEL_DIR	"/boot/kernel"
#define	SYSEXT_HINTS_MAX	(16 * 1024 * 1024)
extern int sysext_driver_dirfd;
bool sysext_hints_pnp_module(const void *, size_t, const char *);
bool sysext_driver_module(int, const char *);

/*
 * Recent load decisions (Ensure and Restore), kept in memory for the read-only
 * status view (system.SystemExtension.Status): a ring of SYSEXT_DECISIONS_MAX
 * entries, the oldest dropped first, lost when the broker restarts.  Each
 * entry carries the requester's switchboard label, never payload data.
 */
struct sysext_decision {
	uint64_t sequence;		/* 1, 2, ... per broker start */
	int64_t	time;			/* CLOCK_REALTIME seconds */
	char	module[SYSEXT_NAME_MAX];
	char	client[SYSEXT_CLIENT_MAX];
	uint32_t operation;		/* SYSEXT_OP_ENSURE or SYSEXT_OP_RESTORE */
	uint32_t result;		/* SYSEXT_DECISION_* */
	uint32_t error;			/* errno of a failed load, else 0 */
};
void	sysext_decision_record(const char *module, const char *client,
	    uint32_t operation, uint32_t result, int error);
/* The oldest retained decision with a sequence above after: 0, or ENOENT. */
int	sysext_decision_next(uint64_t after, struct sysext_decision *);

/*
 * The held SYS_GATE_KLDLOAD/KLDUNLOAD "system" token (defined in
 * bsdextension.c), or -1.  bsdextension.c loads and reclaim.c unloads THROUGH
 * it when born in capability mode.
 */
extern int sysext_kld_token;

#ifdef BSDEXTENSION_TESTING
void sysext_test_policy_abandon(struct sysext_policy *);
void sysext_test_policy_commit_abandon(struct sysext_policy *);
#define	SYSEXT_STATIC		/* external linkage: reachable from tests */

/* Pure-logic entry points, unit-tested directly (see allowlist_test.c). */
bool	valid_module_name(const char *name);
void	sysext_config_defaults(struct sysext_config *cfg);
bool	extension_allowed(const struct sysext_config *cfg, const char *name);
bool	sysext_driver_client(const struct sysext_config *cfg, const char *client);
int	sysext_config_load(struct sysext_config *cfg, const char *path);
int	sysext_config_load_fd(struct sysext_config *cfg, int fd);

/*
 * Test-only serve entry point.  Installs cfg as the resolved allow-list and
 * runs the real per-client worker (sysext_worker -> sysext_request) on fd until
 * the client closes, exactly as a pdfork'd worker would in production.  Returns
 * the worker exit status (0 on clean close).  Used by provider_test.c.
 */
int	sysext_test_serve(int fd, const char *client,
	    const struct sysext_config *cfg);
/*
 * The same over the read-only status view: the worker binds the
 * SystemExtensionStatus handlers a system.SystemExtension.Status session gets.
 */
int	sysext_test_serve_status(int fd, const char *client,
	    const struct sysext_config *cfg);
/* Drop every recorded decision and restart the sequence at 1. */
void	sysext_test_decisions_reset(void);
#else
#define	SYSEXT_STATIC	static
#endif /* BSDEXTENSION_TESTING */

#endif /* _BSDEXTENSION_H_ */
