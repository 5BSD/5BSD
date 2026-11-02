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
#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <libservice.h>

#include "sysext_proto.h"	/* SYSEXT_NAME_MAX */

#define	SYSEXT_MAX_ALLOW	256	/* allow-list capacity */
#define	SYSEXT_MAX_DRIVER_CLIENTS 8	/* driver_clients capacity */
#define	SYSEXT_CLIENT_MAX	64	/* switchboard label bound */
#define	SYSEXT_REPOSITORY_MAX	64	/* root_load_repository bound */
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
	/*
	 * root_load_repository: the pkg repository name (the "repository"
	 * annotation pkg records at install) whose base packages a UID 0 login
	 * session may load kernel modules from (system.SystemExtension.RootLoad).
	 * Empty: root loads are refused.
	 */
	char	root_load_repository[SYSEXT_REPOSITORY_MAX];
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
 * The running kernel's module directory (kerneldir.c).  The manifest delivers
 * /boot by descriptor.  The directory is the one the loader booted the kernel
 * from: the pathname of kernel file id 1 (kldstat(2)), /boot/kernel/kernel or
 * for example /boot/kernel.old/kernel, which no one can change after boot.
 * It is opened beneath /boot (one component, no symbolic link) and used only
 * while its "kernel" file carries the running kernel's build-id
 * (kern.build_id).  sysext_kernel_dir_check() reopens it by name before and
 * after every use that leads to a load: a directory replaced since (the
 * installkernel rename to kernel.old) is adopted only when it holds the
 * running kernel; otherwise, and when the kernel file was replaced in place
 * (a kernel package upgrade before the reboot), driver and root loads are
 * refused until the next boot.
 *
 * The manifest also delivers "/", limited to fstatat(2) at startup
 * (sysext_root_dir_limit()): the kernel resolves the absolute path a load
 * names from the root, not through the held /boot, so the check also
 * requires boot beneath "/" to be the delivered /boot (a mount over /boot or
 * a /boot renamed and replaced is refused until the next boot), and root
 * loads compare each module path, resolved from "/", with the checked file
 * before and after the load.
 */
#define	SYSEXT_ROOT_DIR		"/"
#define	SYSEXT_BOOT_DIR		"/boot"
#define	SYSEXT_KERNEL_DIR	"/boot/kernel"	/* the usual kernel directory */
#define	SYSEXT_BUILD_ID_MAX	129		/* hex of a 64-byte note, NUL */
extern int sysext_boot_dirfd;
extern int sysext_root_dirfd;		/* "/", fstatat(2) only, or -1 */
extern int sysext_driver_dirfd;		/* the kernel directory, or -1 */
extern char sysext_kernel_dir[];	/* its path, e.g. /boot/kernel */
int	sysext_kernel_dir_open(void);
int	sysext_kernel_dir_check(char *detail, size_t detaillen);
int	sysext_root_dir_limit(int fd);
/* Hex GNU build-id of an ELF file (the kernel), 0 or an errno. */
int	sysext_elf_build_id(int fd, char *out, size_t outlen);
/* The kernel file's name in the kernel directory (normally "kernel"). */
const char *sysext_kernel_file_name(void);

/*
 * Hardware-driver class.  sysext_driver_module() reads the kernel directory's
 * linker.hints (cached while its identity, size and times are unchanged) and
 * reports whether name (with or without .ko) is a module file that carries
 * MDT_PNP_INFO records.  sysext_hints_pnp_module() is the bounded parser over
 * an in-memory hints image; sysext_hints_version_file() resolves a module
 * dependency exactly as the kernel linker does (linker_hints_lookup): the
 * MDT_VERSION record with the preferred version, else the highest in range,
 * else NAME.ko.
 */
#define	SYSEXT_HINTS_MAX	(16 * 1024 * 1024)
bool sysext_hints_pnp_module(const void *, size_t, const char *);
bool sysext_driver_module(int, const char *);
bool sysext_hints_version_file(const void *, size_t, const char *modname,
	    int minimum, int preferred, int maximum, char *file, size_t filelen);
/* The same over the kernel directory's linker.hints (or NAME.ko without). */
void sysext_kernel_dir_dependency(const char *modname, int minimum,
	    int preferred, int maximum, char *file, size_t filelen);

/*
 * Root loads (rootload.c), served on system.SystemExtension.RootLoad.  The
 * manifest delivers /var/db/pkg by descriptor; the package database is parsed
 * in a forked child that holds only that directory and a reply pipe (never
 * the kldload token).  A file qualifies when the database records
 * KERNELDIR/FILE in a package whose origin is base/... and whose repository
 * annotation is the configured root_load_repository, the file's BLAKE2b
 * checksum (pkg's "2$" format) matches the recorded one, no administrator
 * override denies it and it is not protected (sysext_root_protected).  The
 * module's MODULE_DEPEND closure is resolved before anything is loaded, from
 * the files' module metadata (read in a forked child as well) and the kernel
 * directory's linker.hints; every file of it must qualify, and the files are
 * loaded by absolute path, dependencies first.
 */
#define	SYSEXT_PKGDB_DIR	"/var/db/pkg"
#define	SYSEXT_PKGDB_FILE	"local.sqlite"
#define	SYSEXT_PKGDB_MAX	(1024L * 1024 * 1024)	/* database size bound */
#define	SYSEXT_MODULE_FILE_MAX	(512L * 1024 * 1024)	/* module size bound */
#define	SYSEXT_PKG_CHECKSUM_MAX	160
#define	SYSEXT_ROOT_LOADED_MAX	64	/* tracked root loads (for unload) */
#define	SYSEXT_ROOT_FILES_MAX	16	/* files one root load may load */
extern int sysext_pkgdb_dirfd;

struct sysext_pkg_record {
	char	checksum[SYSEXT_PKG_CHECKSUM_MAX];
	char	package[128];
	char	origin[160];
	char	repository[SYSEXT_REPOSITORY_MAX];
	bool	symlink;
	bool	found;		/* false: no package records the path */
};
/* 0 with *rec filled (rec->found false when no package records path), or an
 * errno when the database cannot be read. */
int	sysext_pkgdb_lookup(int dirfd, const char *path,
	    struct sysext_pkg_record *rec);
/* pkg's file checksum ("2$" + z-base-32 BLAKE2b-512) of an open file. */
int	sysext_pkg_checksum_fd(int fd, char *out, size_t outlen);
void	sysext_pkg_base32(const unsigned char *in, size_t inlen, char *out,
	    size_t outlen);

/* A module file's linker metadata: its MODULE_VERSION and MODULE_DEPEND. */
#define	SYSEXT_KLD_META_MAX	32
#define	SYSEXT_MODNAME_MAX	32	/* MAXMODNAME */
struct sysext_kld_meta {
	unsigned nversion;
	unsigned ndepend;
	struct {
		char	name[SYSEXT_MODNAME_MAX];
		int	version;
	} version[SYSEXT_KLD_META_MAX];
	struct {
		char	name[SYSEXT_MODNAME_MAX];
		int	minimum, preferred, maximum;
	} depend[SYSEXT_KLD_META_MAX];
};
/* Read the metadata of an open module file in a forked child: 0 or errno. */
int	sysext_kld_metadata(int fd, struct sysext_kld_meta *meta);
/* kldstat(2) name and pathname of a loaded file id: 0 or an errno. */
int	sysext_kld_stat(int fileid, char *name, size_t namelen, char *path,
	    size_t pathlen);

/*
 * Decide a root Load or Unload: returns SYSEXT_DECISION_*; *errorp is the
 * errno of a failed load or unload; detail receives a reason for the log.
 * The caller has already checked the name, the policy (enabled, the module
 * not denied by an administrator) and that the module is not loaded.
 */
uint32_t sysext_root_load(const char *repository, const char *name,
	    int *errorp, char *detail, size_t detaillen);
uint32_t sysext_root_unload(const char *name, int *errorp, char *detail,
	    size_t detaillen);
/* Another client asked for name while loaded: a root unload is refused. */
void	sysext_root_note_shared(const char *name);
/*
 * Security policies, tracing, storage, the packet filters and the hypervisor:
 * a root session may neither load nor unload them (or load a module that
 * needs one loaded).  Same list for both directions.
 */
bool	sysext_root_protected(const char *name);
/* True when an administrator override denies name (bsdextension.c). */
bool	sysext_admin_denied(const char *name);
/* Serialises the broker's own kernel loads (rootload.c checks new files). */
extern pthread_mutex_t sysext_load_lock;

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
/*
 * The same over the root-load endpoint (SystemExtensionRootLoad).  The boot
 * and package directories are the test's; sysext_test_kld_* and
 * sysext_test_mod_find replace the kernel linker calls (NULL: the real
 * kldload/kldunload/kldstat/kldnext/modfind), sysext_test_build_id the
 * running kernel's kern.build_id.
 */
int	sysext_test_serve_rootload(int fd, const char *client,
	    const struct sysext_config *cfg, int rootdir, int bootdir,
	    int pkgdir, const char *deny);
extern int (*sysext_test_kld_load)(const char *path, int *fileid);
extern int (*sysext_test_kld_unload)(int fileid);
/* Fill the name and pathname of a loaded file id; an errno when none. */
extern int (*sysext_test_kld_stat)(int fileid, char *name, size_t namelen,
	    char *path, size_t pathlen);
/* The first loaded file id after fileid, or 0 at the end. */
extern int (*sysext_test_kld_next)(int fileid);
/* 0 when a loaded file provides the module (version) name, else an errno. */
extern int (*sysext_test_mod_find)(const char *name);
extern const char *sysext_test_build_id;
void	sysext_test_root_reset(void);
/* Package database children forked (one per root load's plan). */
extern int sysext_test_pkgdb_children;
#else
#define	SYSEXT_STATIC	static
#endif /* BSDEXTENSION_TESTING */

#endif /* _BSDEXTENSION_H_ */
