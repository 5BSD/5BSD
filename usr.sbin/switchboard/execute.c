/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service fork/exec for switchboard.
 *
 * Creates a channel, mints capability tokens, pdfork()s a
 * child, scrubs its environment and fds, sets credentials, and
 * exec()s the program from the manifest.  Registers the process
 * descriptor and channel on the kqueue for supervision.
 *
 * Unlike capsule, switchboard does not hold /dev/mac_capability directly.
 * Channel and coalition creation use the delegated mac_capability fd
 * (mac_cap_direct.c).  Token minting goes through Capsule
 * channel (capsule_client.c).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_system_proto.h>	/* SYS_GATE_* */
#include <service_bootstrap.h>
#include <channel.h>


#include "switchboard.h"
#include "ambient_hygiene.h"
#include "launch_limits.h"
#include "rc_adopt.h"
#include "fd_budget.h"
#include "switchboard_audit.h"
#include "switchboard_probes.h"

/*
 * Diagnostic log sink for launched capability units.  A born-in-capmode daemon
 * cannot reach syslogd (capsicum) and boots before the Log capability, so
 * switchboard -- root, before the child's cap_enter(2) -- opens this file and
 * hands it to the child as stdout/stderr; LOG_PERROR output (ident[pid]: msg)
 * lands here persistently with no runtime path or Log-capability dependency.
 */
#define	SWITCHBOARD_CAP_DIAG_LOG	"/var/log/capability.log"

#define	SVC_CHANNEL_FD	3	/* well-known fd for the channel */
#define	SVC_CAPPROTECT_FD	4	/* capprotect service instance */

/*
 * Main-loop-owned process incarnation counter.  A PID and service label are
 * not sufficient identity because a restarted process can eventually reuse
 * both.  Zero is reserved for a runtime that has not been launched.
 */
static uint64_t svc_launch_sequence;

/*
 * switchboard's retained client end of the SYSTEM ambient lookup channel (§21).
 * -1 until startup.c installs it before running /etc/rc.  Every rc/oneshot
 * child inherits it across pdfork (it is CAP_CLOFORK_UNLOCKED) and svc_exec_command
 * spares it from the child's closefrom(2), so rc and everything it launches —
 * getty, login, su — carries system service discovery.
 */
int switchboard_ambient_lookup_fd = -1;

#define	SVC_TOKEN_BASE	6	/* after the typed bootstrap descriptor */
#define	SVC_MAX_TOKENS	SVC_LAUNCH_MAX_TOKENS
#define	SVC_INTERNAL_ENV	10	/* PATH, bootstrap, selectors, USER/HOME, NULL */
#define	SVC_MAX_ENV	(SVC_INTERNAL_ENV + SWITCHBOARD_MAX_ENVIRONMENT)
_Static_assert(SVC_CHANNEL_FD < SERVICE_BOOTSTRAP_FD,
    "service channel overlaps bootstrap descriptor");
_Static_assert(SVC_CAPPROTECT_FD < SERVICE_BOOTSTRAP_FD,
    "capprotect overlaps bootstrap descriptor");
_Static_assert(SVC_TOKEN_BASE == SERVICE_BOOTSTRAP_FD + 1,
    "token layout must follow bootstrap descriptor");
_Static_assert(SVC_MAX_TOKENS <= SERVICE_BOOTSTRAP_TOKEN_MAX,
    "bootstrap token table is too small");
_Static_assert(SWITCHBOARD_LABEL_MAX <= SERVICE_BOOTSTRAP_LABEL_MAX,
    "bootstrap label is too small");


/*
 * Marshal a manifest's per-OID sysctl isolation list into a packed
 * sys_sysctl_oidset (docs/capability-sysctl-isolation.md, Phase 2).  Each
 * `isolate` name is resolved to a MIB via sysctlnametomib(3); an unresolved
 * name is skipped with a warning (a single bad OID never fails the whole set)
 * and the set is capped at SYS_SYSCTL_MAXOIDS.  Writes the packed oidset into
 * buf, sets *outlen to its byte length, and returns the number of OIDs marshalled
 * (0 if none resolved — the caller then refuses rather than delegate coarsely).
 * buf must be at least CAPSULE_MINT_SYSTEM_PAYLOAD_MAX bytes.
 */
static unsigned
svc_marshal_sysctl_oidset(const struct svc_manifest *m, void *buf, size_t bufsz,
    size_t *outlen)
{
	struct sys_sysctl_oidset *oset = buf;
	unsigned i, n;

	*outlen = 0;
	if (bufsz < CAPSULE_MINT_SYSTEM_PAYLOAD_MAX)
		return (0);
	n = 0;
	for (i = 0; i < m->n_sysctl_isolate && n < SYS_SYSCTL_MAXOIDS; i++) {
		int mib[SYS_OID_MAXDEPTH];
		size_t depth = nitems(mib);
		size_t d;

		if (sysctlnametomib(m->sysctl_isolate[i], mib, &depth) == -1) {
			syslog(LOG_WARNING, "svc_exec %s: sysctl isolate OID "
			    "'%s' unresolved: %m; skipping", m->label,
			    m->sysctl_isolate[i]);
			continue;
		}
		oset->oids[n].depth = (uint32_t)depth;
		memset(oset->oids[n].mib, 0, sizeof(oset->oids[n].mib));
		for (d = 0; d < depth && d < SYS_OID_MAXDEPTH; d++)
			oset->oids[n].mib[d] = mib[d];
		n++;
	}
	if (n == 0)
		return (0);
	oset->noids = n;
	*outlen = sizeof(uint32_t) + (size_t)n * sizeof(struct sys_sysctl_oid);
	return (n);
}

/*
 * Fold a unit label into a single path component: '/' and '.' become '_'.
 * The per-instance runtime container is named for the unit, like a bundle.
 */
static void
svc_run_container_leaf(const char *label, char *buf, size_t len)
{
	size_t i, n;

	for (i = 0, n = 0; label[i] != '\0' && n + 1 < len; i++)
		buf[n++] = (label[i] == '/' || label[i] == '.') ? '_' : label[i];
	buf[n] = '\0';
}

static void
svc_run_container_path(const char *label, char *buf, size_t len)
{
	char leaf[NAME_MAX + 1];

	svc_run_container_leaf(label, leaf, sizeof(leaf));
	(void)snprintf(buf, len, "%s/%s", switchboard_run_dir, leaf);
}

/*
 * Create (or reuse) a unit's per-instance runtime container under
 * /Capabilities/Run, owned by the launched service, and return an O_DIRECTORY
 * descriptor.  The container is the unit's read-write scratch/home (macOS-style
 * app container): created before exec, delivered as the "container" capability,
 * and removed on stop.  Confinement is by capabilities and the jail rooted here,
 * not by the name.
 */
static int
svc_run_container_open(const char *label, uid_t uid, gid_t gid)
{
	char path[PATH_MAX];
	cap_rights_t rights;
	int fd, saved;

	(void)mkdir(switchboard_run_dir, 0700);
	svc_run_container_path(label, path, sizeof(path));
	if (mkdir(path, 0700) == -1 && errno != EEXIST)
		return (-1);
	fd = open(path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	/*
	 * Deliver with exactly the rights libservice's directory-descriptor
	 * validation expects (a read-write scratch dir whose openat(2)ed files
	 * keep GETFL|SETFL for O_APPEND), matching the former storage-directory
	 * delivery so a plain open()'s ambient rights do not fail validation.
	 */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_PREAD, CAP_PWRITE,
	    CAP_SEEK, CAP_FCNTL, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FTRUNCATE, CAP_FSYNC, CAP_CREATE, CAP_MKDIRAT, CAP_UNLINKAT,
	    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET);
	if (fchown(fd, uid, gid) == -1 || fchmod(fd, 0700) == -1 ||
	    cap_rights_limit(fd, &rights) == -1 ||
	    cap_fcntls_limit(fd, CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	return (fd);
}

/* Best-effort recursive removal of a directory tree by descriptor. */
static void
svc_rmtree_at(int parent, const char *name)
{
	int fd;
	DIR *dir;
	struct dirent *de;

	fd = openat(parent, name, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1) {
		(void)unlinkat(parent, name, 0);
		return;
	}
	dir = fdopendir(fd);
	if (dir == NULL) {
		(void)close(fd);
		return;
	}
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
		    (de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;
		if (de->d_type == DT_DIR)
			svc_rmtree_at(fd, de->d_name);
		else
			(void)unlinkat(fd, de->d_name, 0);
	}
	(void)closedir(dir);
	(void)unlinkat(parent, name, AT_REMOVEDIR);
}

/*
 * Sweep every leftover runtime container at startup.  On a clean stop switchboard
 * removes a unit's container itself; this reclaims containers stranded by a
 * crash or panic (the belt-and-suspenders behind putting /Capabilities/Run on
 * a volatile filesystem, which wipes the tree on reboot regardless).
 */
void
svc_run_container_sweep(void)
{
	int base;
	DIR *dir;
	struct dirent *de;

	base = open(switchboard_run_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (base == -1)
		return;
	dir = fdopendir(base);
	if (dir == NULL) {
		(void)close(base);
		return;
	}
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
		    (de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;
		svc_rmtree_at(base, de->d_name);
	}
	(void)closedir(dir);
}

/* Remove a unit's runtime container and its contents (best effort). */
void
svc_run_container_remove(const char *label)
{
	char leaf[NAME_MAX + 1];
	int base;

	base = open(switchboard_run_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (base == -1)
		return;
	svc_run_container_leaf(label, leaf, sizeof(leaf));
	svc_rmtree_at(base, leaf);
	(void)close(base);
}

/* Build the immutable descriptor bootstrap consumed by libservice. */
static int
create_service_bootstrap(const struct svc_manifest *m, unsigned ntokens,
    unsigned nservices,
    char names[][SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX],
    char types[][SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX], bool have_capprotect)
{
	struct envfd_create_options options =
	    ENVFD_CREATE_OPTIONS_INITIALIZER(sizeof(struct service_bootstrap));
	struct service_bootstrap bootstrap;
	cap_rights_t rights;
	ssize_t written;
	int fd, error;
	unsigned i;

	options.eco_flags = ENVFD_WRITE_ONCE;
	options.eco_access = O_RDWR;
	options.eco_fdflags = FD_CLOEXEC;
	options.eco_xfer_state = CAP_XFER_NONE;
	options.eco_clofork_state = CAP_CLOFORK_ONCE;
	options.eco_cloexec_state = CAP_CLOEXEC_ONCE;
	fd = envfd_create(SERVICE_BOOTSTRAP_ENVFD_NAME, &options);
	if (fd == -1)
		return (-1);
	memset(&bootstrap, 0, sizeof(bootstrap));
	bootstrap.magic = SERVICE_BOOTSTRAP_MAGIC;
	bootstrap.version = SERVICE_BOOTSTRAP_VERSION;
	bootstrap.header_size = offsetof(struct service_bootstrap, label);
	bootstrap.total_size = sizeof(bootstrap);
	bootstrap.flags = have_capprotect ?
	    SERVICE_BOOTSTRAP_F_CAPPROTECT : 0;
	bootstrap.channel_fd = SVC_CHANNEL_FD;
	bootstrap.capprotect_fd = have_capprotect ?
	    SVC_CAPPROTECT_FD : -1;
	bootstrap.ntokens = ntokens;
	bootstrap.ncapabilities = nservices;
	strlcpy(bootstrap.label, m->label, sizeof(bootstrap.label));
	for (i = 0; i < ntokens; i++)
		bootstrap.token_fds[i] = SVC_TOKEN_BASE + i;
	for (i = 0; i < nservices; i++) {
		bootstrap.capabilities[i].fd = SVC_TOKEN_BASE + ntokens + i;
		strlcpy(bootstrap.capabilities[i].name, names[i],
		    sizeof(bootstrap.capabilities[i].name));
		strlcpy(bootstrap.capabilities[i].type, types[i],
		    sizeof(bootstrap.capabilities[i].type));
	}
	written = write(fd, &bootstrap, sizeof(bootstrap));
	explicit_bzero(&bootstrap, sizeof(bootstrap));
	if (written != (ssize_t)sizeof(bootstrap)) {
		if (written >= 0)
			errno = EIO;
		goto fail;
	}
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_limit(fd, &rights) == -1 ||
	    cap_ioctls_limit(fd, (const unsigned long[]){ ENVFD_GETINFO },
	    1) == -1)
		goto fail;
	return (fd);

fail:
	error = errno;
	close(fd);
	errno = error;
	return (-1);
}

/*
 * Permit exactly the supervised fork and exec.  Both resulting descriptor
 * entries become locked, so neither the parent nor the new image can widen
 * propagation for a later child or program image.
 */
static int
prepare_child_descriptor(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == -1 ? -1 : 0);
}

/*
 * Confine a descriptor for the launched program but leave it fork-inheritable
 * (CAP_CLOFORK_UNLOCKED).  Used for the capprotect shield instance: a provider
 * must be able to pass it across the pdfork(2) it does per session so each
 * worker can apply its own protection policy.  CLOFORK_ONCE would survive only
 * the launch fork and then latch to LOCKED, dropping the descriptor in every
 * subsequent worker.  Transfer and exec are still confined.
 */
static int
prepare_child_descriptor_forkable(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == -1 ? -1 : 0);
}

static bool
manifest_has_env(const struct svc_manifest *m, const char *name)
{
	size_t n = strlen(name);
	unsigned i;
	for (i = 0; i < m->nenvironment; i++)
		if (strncmp(m->environment[i], name, n) == 0 &&
		    m->environment[i][n] == '=')
			return (true);
	return (false);
}

/*
 * Child process setup and exec.  Does not return on success.
 * All functions called here must be async-signal-safe or safe
 * in a post-fork child (no malloc, no syslog).
 */
static void __dead2
child_exec(struct svc_manifest *m, int child_channel_fd,
    int capprotect_fd, int bootstrap_fd, int *token_fds, unsigned ntokens,
    int *service_fds, unsigned nservices,
    uid_t uid, gid_t gid, bool have_creds, const char *homedir,
    gid_t *groups, int ngroups)
{
	char user_env[128], home_env[PATH_MAX + 8];
	char unit_dir[PATH_MAX], unit_dir_env[PATH_MAX + 32];
	char libdir_path[PATH_MAX], libdir_fds_env[64];
	char config_dir_path[PATH_MAX], config_fd_env[48];
	char dir_fds_env[1024];
	char bootstrap_env[32];
	char *env[SVC_MAX_ENV];
	char *argv[SWITCHBOARD_MAX_ARGUMENTS + 2];
	int nullfd, logfd, fd, ldfd, tgtfd;
	bool have_capprotect;
	unsigned i, envc;

	ldfd = -1;
	tgtfd = -1;

	/*
	 * stdin from /dev/null; stdout+stderr to the capability diagnostic log.
	 * A born-in-capmode daemon cannot reach the syslogd socket (capsicum) and
	 * boots before the Log capability, so its LOG_PERROR/printf diagnostics
	 * would otherwise be lost to /dev/null.  switchboard is root here, before
	 * the child's cap_enter(2), so it opens the sink and hands it over as the
	 * child's stdout/stderr -- captured, persistent, and needing no global path
	 * or Log-capability dependency at runtime.  Fall back to /dev/null if the
	 * log cannot be opened; never fail the launch over diagnostics.  The fd (at
	 * 1/2) is inherited across fexecve and is a held descriptor the daemon can
	 * write in capability mode.
	 */
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd == -1)
		_exit(126);
	logfd = open(SWITCHBOARD_CAP_DIAG_LOG,
	    O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (logfd == -1)
		logfd = nullfd;
	if (dup2(nullfd, STDIN_FILENO) == -1 ||
	    dup2(logfd, STDOUT_FILENO) == -1 ||
	    dup2(logfd, STDERR_FILENO) == -1)
		_exit(126);
	if (logfd != nullfd && logfd > STDERR_FILENO)
		(void)close(logfd);
	if (nullfd > STDERR_FILENO)
		(void)close(nullfd);

	/*
	 * Remap fds into their well-known positions.  First move all
	 * source fds above the reserved range to avoid clobbering a
	 * source fd that occupies a target slot (e.g., child_channel_fd
	 * could be 5 which is SVC_TOKEN_BASE, or token_fds[0] could
	 * be 3 which is SVC_CHANNEL_FD).
	 */
	{
		int safe_base;

		safe_base = SVC_TOKEN_BASE + (int)ntokens + (int)nservices + 1;
		if (child_channel_fd < safe_base) {
			fd = fcntl(child_channel_fd, F_DUPFD, safe_base);
			if (fd == -1)
				_exit(126);
			(void)close(child_channel_fd);
			child_channel_fd = fd;
		}
		if (bootstrap_fd < safe_base) {
			fd = fcntl(bootstrap_fd, F_DUPFD, safe_base);
			if (fd == -1)
				_exit(126);
			(void)close(bootstrap_fd);
			bootstrap_fd = fd;
		}
		for (i = 0; i < ntokens; i++) {
			if (token_fds[i] < safe_base) {
				fd = fcntl(token_fds[i], F_DUPFD, safe_base);
				if (fd == -1)
					_exit(126);
				(void)close(token_fds[i]);
				token_fds[i] = fd;
			}
		}
		for (i = 0; i < nservices; i++) {
			if (service_fds[i] < safe_base) {
				fd = fcntl(service_fds[i], F_DUPFD, safe_base);
				if (fd == -1)
					_exit(126);
				(void)close(service_fds[i]);
				service_fds[i] = fd;
			}
		}
		if (capprotect_fd >= 0 && capprotect_fd < safe_base) {
			fd = fcntl(capprotect_fd, F_DUPFD, safe_base);
			if (fd == -1)
				_exit(126);
			(void)close(capprotect_fd);
			capprotect_fd = fd;
		}
	}

	/* Now safe to map into final positions. */
	if (dup2(child_channel_fd, SVC_CHANNEL_FD) == -1)
		_exit(126);
	(void)close(child_channel_fd);
	have_capprotect = capprotect_fd >= 0;
	if (capprotect_fd >= 0) {
		if (dup2(capprotect_fd, SVC_CAPPROTECT_FD) == -1)
			_exit(126);
		(void)close(capprotect_fd);
	} else {
		/*
		 * No capprotect instance for this service.  closefrom() below
		 * starts at the first token slot, so nothing else scrubs the
		 * reserved capprotect slot — close it explicitly so no fd the
		 * child happened to inherit at fd 4 survives into execve().
		 */
		(void)close(SVC_CAPPROTECT_FD);
	}
	if (dup2(bootstrap_fd, SERVICE_BOOTSTRAP_FD) == -1)
		_exit(126);
	(void)close(bootstrap_fd);

	for (i = 0; i < ntokens; i++) {
		fd = (int)(SVC_TOKEN_BASE + i);
		if (dup2(token_fds[i], fd) == -1)
			_exit(126);
		(void)close(token_fds[i]);
	}
	for (i = 0; i < nservices; i++) {
		fd = SVC_TOKEN_BASE + (int)ntokens + (int)i;
		if (dup2(service_fds[i], fd) == -1)
			_exit(126);
		(void)close(service_fds[i]);
	}

	closefrom(SVC_TOKEN_BASE + (int)ntokens + (int)nservices);

	if (fcntl(SVC_CHANNEL_FD, F_SETFD, 0) == -1)
		_exit(126);
	if (have_capprotect && fcntl(SVC_CAPPROTECT_FD, F_SETFD, 0) == -1)
		_exit(126);
	if (fcntl(SERVICE_BOOTSTRAP_FD, F_SETFD, 0) == -1)
		_exit(126);
	for (i = 0; i < ntokens; i++) {
		if (fcntl(SVC_TOKEN_BASE + (int)i, F_SETFD, 0) == -1)
			_exit(126);
	}
	for (i = 0; i < nservices; i++) {
		if (fcntl(SVC_TOKEN_BASE + (int)ntokens + (int)i,
		    F_SETFD, 0) == -1)
			_exit(126);
	}

	/* Build minimal environment. */
	envc = 0;
	for (i = 0; i < m->nenvironment; i++)
		env[envc++] = m->environment[i];
	if (!manifest_has_env(m, "PATH"))
		env[envc++] = __DECONST(char *,
		    "PATH=/sbin:/bin:/usr/sbin:/usr/bin");
	if (manifest_has_env(m, SERVICE_BOOTSTRAP_ENV))
		_exit(126);
	(void)snprintf(bootstrap_env, sizeof(bootstrap_env),
	    "%s=%d", SERVICE_BOOTSTRAP_ENV, SERVICE_BOOTSTRAP_FD);
	env[envc++] = bootstrap_env;
	if (strlcpy(unit_dir, m->program, sizeof(unit_dir)) >=
	    sizeof(unit_dir))
		_exit(126);
	{
		char *cursor, *marker;

		marker = NULL;
		for (cursor = unit_dir;
		    (cursor = strstr(cursor, "/bin/")) != NULL; cursor += 5)
			marker = cursor;
		if (marker == NULL || marker[5] == '\0')
			_exit(126);
		*marker = '\0';
	}
	if (manifest_has_env(m, SERVICE_UNIT_DIR_ENV) ||
	    snprintf(unit_dir_env, sizeof(unit_dir_env), "%s=%s",
	    SERVICE_UNIT_DIR_ENV, unit_dir) >= (int)sizeof(unit_dir_env))
		_exit(126);
	env[envc++] = unit_dir_env;

	/*
	 * If the bundle ships its own shared libraries in <unit>/lib, deliver
	 * that directory as a descriptor via LD_LIBRARY_PATH_FDS.  rtld(1)
	 * consults it (openat, capability-mode-safe) ahead of the hint file and
	 * the /lib defaults, so a bundle program resolves its NEEDED libraries
	 * -- and any dlopen(3) after cap_enter(2) -- from its own bundle rather
	 * than the global namespace.  Opt-in by the mere presence of the
	 * directory; a unit without a lib/ is launched exactly as before.  The
	 * descriptor is opened here, after closefrom(2), without O_CLOEXEC so it
	 * survives execve(2); it is a read-only directory capability.  (rtld
	 * honors LD_LIBRARY_PATH_FDS only for trusted, non-issetugid launches.)
	 */
	if (!manifest_has_env(m, "LD_LIBRARY_PATH_FDS")) {
		int libfd, usrlibfd, bundlefd;
		int off;

		/*
		 * switchboard provides the COMMON system library directories (/lib,
		 * /usr/lib) as descriptors, once per launch, so rtld resolves the
		 * program's NEEDED libraries by openat(2) in capability mode (the
		 * born-in-capmode launch), never by global path.  LD_LIBRARY_PATH_FDS
		 * is a colon-separated fd list, so a bundle does NOT duplicate
		 * libc/libservice/...; it ships only its own private dylibs in lib/,
		 * which is appended last when present.  Opened without O_CLOEXEC so the
		 * descriptors survive fexecve(2).
		 */
		libfd = open("/lib", O_DIRECTORY | O_RDONLY);
		usrlibfd = open("/usr/lib", O_DIRECTORY | O_RDONLY);
		if (libfd >= 0 && usrlibfd >= 0) {
			off = snprintf(libdir_fds_env, sizeof(libdir_fds_env),
			    "LD_LIBRARY_PATH_FDS=%d:%d", libfd, usrlibfd);
			if (off > 0 && off < (int)sizeof(libdir_fds_env) &&
			    snprintf(libdir_path, sizeof(libdir_path), "%s/lib",
			    unit_dir) < (int)sizeof(libdir_path) &&
			    (bundlefd = open(libdir_path,
			    O_DIRECTORY | O_RDONLY)) >= 0)
				(void)snprintf(libdir_fds_env + off,
				    sizeof(libdir_fds_env) - off, ":%d", bundlefd);
			env[envc++] = libdir_fds_env;
		}
	}

	/*
	 * Deliver the unit's bundle Config/ directory as a descriptor so the
	 * program can openat(2) its config files after cap_enter(2), with no
	 * path lookup.  Opt-in by the directory existing; opened after
	 * closefrom(2) without O_CLOEXEC so it survives execve(2).  A read-only
	 * directory capability; service_config_open(3) consumes it.
	 */
	if (!manifest_has_env(m, SERVICE_CONFIG_FD_ENV) &&
	    snprintf(config_dir_path, sizeof(config_dir_path), "%s/Config",
	    unit_dir) < (int)sizeof(config_dir_path)) {
		fd = open(config_dir_path, O_DIRECTORY | O_RDONLY);
		if (fd >= 0) {
			(void)snprintf(config_fd_env, sizeof(config_fd_env),
			    "%s=%d", SERVICE_CONFIG_FD_ENV, fd);
			env[envc++] = config_fd_env;
		}
	}

	/*
	 * Deliver the manifest-declared resource directories as descriptors so a
	 * born-in-capmode daemon reaches them by openat(2) — e.g. a /dev node — with
	 * no global path.  switchboard opens each here (still pre-capmode), without
	 * O_CLOEXEC so it survives the exec, and advertises "path=fd" pairs (colon
	 * separated) in CAPABILITY_DIR_FDS.  A missing directory is skipped
	 * fail-soft; service_resource_dir(3) consumes the map.
	 */
	if (m->nresource_dirs > 0 && !manifest_has_env(m, SERVICE_DIR_FDS_ENV)) {
		int off, r;
		unsigned d;

		off = snprintf(dir_fds_env, sizeof(dir_fds_env), "%s=",
		    SERVICE_DIR_FDS_ENV);
		for (d = 0; d < m->nresource_dirs && off > 0 &&
		    off < (int)sizeof(dir_fds_env); d++) {
			fd = open(m->resource_dirs[d], O_DIRECTORY | O_RDONLY);
			if (fd < 0)
				continue;
			r = snprintf(dir_fds_env + off, sizeof(dir_fds_env) - off,
			    "%s%s=%d", off > (int)strlen(SERVICE_DIR_FDS_ENV) + 1 ?
			    ":" : "", m->resource_dirs[d], fd);
			if (r > 0 && r < (int)sizeof(dir_fds_env) - off)
				off += r;
		}
		if (off > (int)strlen(SERVICE_DIR_FDS_ENV) + 1)
			env[envc++] = dir_fds_env;
	}

	/*
	 * Open the verified bundle program while the launcher still has access to
	 * the sealed bundle tree.  Bundle verification deliberately removes every
	 * permission bit from the bundle and unit directories; reopening the
	 * program after setuid(2) therefore fails for an unprivileged service even
	 * though the file itself is executable.  Keep only these descriptors into
	 * the credential drop and capability-mode transition.  The program still
	 * executes with the requested uid, and fexecve(2) applies that credential's
	 * execute checks to the already-open vnode.
	 */
	if (!m->ambient) {
		/*
		 * O_VERIFY on both the interpreter and the bundle program:
		 * a sandboxed unit is launched as "ld-elf.so.1 -f <tgtfd>",
		 * so rtld mmaps the program image from tgtfd and the kernel's
		 * exec-time veriexec check never sees it -- only O_VERIFY at
		 * open time verifies the program.  When mac_veriexec is loaded
		 * and enforcing, an unfingerprinted or tampered image fails the
		 * open (EAUTH); when veriexec is absent or not enforcing it is a
		 * silent no-op (docs/ipc-anointments-design.md).  The ambient
		 * path below execve()s by path, which the exec-time check covers.
		 */
		ldfd = open("/libexec/ld-elf.so.1", O_EXEC | O_VERIFY);
		if (ldfd == -1)
			_exit(126);
		tgtfd = open(m->program, O_RDONLY | O_VERIFY);
		if (tgtfd == -1)
			_exit(126);
	}

	if (m->user[0] != '\0' && !manifest_has_env(m, "USER")) {
		(void)snprintf(user_env, sizeof(user_env),
		    "USER=%s", m->user);
		env[envc++] = user_env;
	}
	if (m->user[0] != '\0' && !manifest_has_env(m, "HOME")) {
		(void)snprintf(home_env, sizeof(home_env),
		    "HOME=%s", homedir != NULL ? homedir : "/var/empty");
		env[envc++] = home_env;
	}

	env[envc] = NULL;

	/*
	 * Enter the per-instance runtime container as the working directory: the
	 * unit's writable home (macOS-style app container).  Done while still
	 * privileged so the 0700 container is enterable; relative paths and the
	 * shell's notion of "." then resolve inside the container.  Capsicum, not
	 * a chroot, is the confinement, so this is a chdir rather than a jail root.
	 */
	{
		char container_path[PATH_MAX];

		svc_run_container_path(m->label, container_path,
		    sizeof(container_path));
		if (chdir(container_path) == -1)
			_exit(126);
	}

	/*
	 * Pre-exec resource + scheduling policy (launchd Hard/SoftResourceLimits,
	 * ProcessType, Umask).  Applied in the child while still privileged (nice
	 * reductions and hard-limit raises need root) and before exec, so the
	 * ceilings bind the program image from its first instruction.  A failure
	 * is fatal: a unit that asked to be contained must not run uncontained.
	 */
	{
		struct rlimit rl;

		/* core=0 (no dumps) applies even when limits{} is omitted. */
		rl.rlim_cur = rl.rlim_max = (rlim_t)m->limits.core;
		if (setrlimit(RLIMIT_CORE, &rl) == -1)
			_exit(126);
		if (m->limits.mem != SVC_LIMIT_UNSET) {
			rl.rlim_cur = rl.rlim_max = (rlim_t)m->limits.mem;
			if (setrlimit(RLIMIT_AS, &rl) == -1)
				_exit(126);
		}
		if (m->limits.cpu != SVC_LIMIT_UNSET) {
			rl.rlim_cur = rl.rlim_max = (rlim_t)m->limits.cpu;
			if (setrlimit(RLIMIT_CPU, &rl) == -1)
				_exit(126);
		}
		if (m->limits.nproc != SVC_LIMIT_UNSET) {
			rl.rlim_cur = rl.rlim_max = (rlim_t)m->limits.nproc;
			if (setrlimit(RLIMIT_NPROC, &rl) == -1)
				_exit(126);
		}
		if (m->limits.nofile != SVC_LIMIT_UNSET) {
			rl.rlim_cur = rl.rlim_max = (rlim_t)m->limits.nofile;
			if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
				_exit(126);
		}
		if (m->limits.stack != SVC_LIMIT_UNSET) {
			rl.rlim_cur = rl.rlim_max = (rlim_t)m->limits.stack;
			if (setrlimit(RLIMIT_STACK, &rl) == -1)
				_exit(126);
		}
		if (m->limits.fsize != SVC_LIMIT_UNSET) {
			rl.rlim_cur = rl.rlim_max = (rlim_t)m->limits.fsize;
			if (setrlimit(RLIMIT_FSIZE, &rl) == -1)
				_exit(126);
		}

		/*
		 * Scheduling band → nice(2).  Background work yields to
		 * interactive; interactive gets a modest boost (root, so the
		 * negative nice is permitted, applied before the credential drop).
		 * FreeBSD has no base per-process I/O-priority API, so band maps to
		 * CPU nice only.
		 */
		if (m->band == SVC_BAND_BACKGROUND)
			(void)setpriority(PRIO_PROCESS, 0, 10);
		else if (m->band == SVC_BAND_INTERACTIVE)
			(void)setpriority(PRIO_PROCESS, 0, -5);

		/* File-creation mask: explicit value, else the plane default. */
		(void)umask(m->umask_val >= 0 ? (mode_t)m->umask_val : 0077);
	}

	/* Set credentials if specified.  Failures are fatal — running
	 * as root when the manifest requested an unprivileged user
	 * is a privilege escalation.  Always drop group before user;
	 * if only user is set, gid comes from the user's passwd entry. */
	if (have_creds) {
		if (setgroups(ngroups, groups) == -1)
			_exit(126);
		if (setgid(gid) == -1)
			_exit(126);
		if (setuid(uid) == -1)
			_exit(126);
	}

	/* Reset signal dispositions and unblock all signals. */
	for (i = 1; i < NSIG; i++)
		(void)signal(i, SIG_DFL);
	{
		sigset_t emptyset;
		sigemptyset(&emptyset);
		(void)sigprocmask(SIG_SETMASK, &emptyset, NULL);
	}

	argv[0] = strrchr(m->program, '/');
	if (argv[0] != NULL)
		argv[0]++;
	else
		argv[0] = m->program;
	for (i = 0; i < m->narguments; i++)
		argv[i + 1] = m->arguments[i];
	argv[m->narguments + 1] = NULL;

	/*
	 * Launch model (the capability realm is "always in capability mode").
	 *
	 * An ambient-authority provider is the sparingly-used exception: it legitimately
	 * runs outside the sandbox because its work needs the global namespace and
	 * classic privilege (bsdextension's kldload, bsdsysctl's unrestricted sysctl),
	 * so it execs normally and self-manages its authority.
	 *
	 * Every other realm daemon is BORN in capability mode.  switchboard cap_enter(2)s
	 * here, then execs the dynamic binary through rtld's descriptor-direct mode
	 * ("ld-elf.so.1 -f <fd>"): rtld resolves the program's NEEDED libraries from
	 * the delivered lib-dir descriptor (LD_LIBRARY_PATH_FDS) by openat(2), never a
	 * path.  rtld is a static PIE, so the kernel loads no interpreter for it and
	 * the in-capmode interpreter guard is never reached.  The daemon therefore has
	 * no un-sandboxed instant: from its first instruction it can only use the
	 * descriptors switchboard delivered, never open a global path.
	 */
	if (m->ambient) {
		execve(m->program, argv, env);
		_exit(127);
	}
	{
		char *rtld_argv[SWITCHBOARD_MAX_ARGUMENTS + 5];
		char tgtfd_str[16];
		int ai;

		/* The static-PIE rtld and verified target were opened above, before
		 * the credential drop, and are executed only after cap_enter(2). */
		(void)snprintf(tgtfd_str, sizeof(tgtfd_str), "%d", tgtfd);
		ai = 0;
		rtld_argv[ai++] = __DECONST(char *, "ld-elf.so.1");
		rtld_argv[ai++] = __DECONST(char *, "-f");
		rtld_argv[ai++] = tgtfd_str;
		for (i = 0; i < m->narguments + 1; i++)
			rtld_argv[ai++] = argv[i];
		rtld_argv[ai] = NULL;
		if (cap_enter() == -1)
			_exit(126);
		fexecve(ldfd, rtld_argv, env);
		_exit(127);
	}
}

static int svc_exec_native(struct svc_runtime *svc, int kq);
static int svc_exec_rc(struct svc_runtime *svc, int kq);
static int svc_exec_oneshot(struct svc_runtime *svc, int kq);

/*
 * Launch a unit.  Dispatch by kind to the method that matches its
 * readiness contract and confinement.  NATIVE is the capability-service
 * path (fork -> cap mode -> minted tokens).  RC and ONESHOT run a command
 * to completion and are judged by exit status (see svc_exec_command).
 */
int
svc_exec(struct svc_runtime *svc, int kq)
{

	/* An async native launch is already coming up; do not start a second. */
	if (svc->launch != NULL) {
		errno = EALREADY;
		return (-1);
	}
	switch (svc->kind) {
	case SVC_KIND_NATIVE:
		return (svc_exec_native(svc, kq));
	case SVC_KIND_RC:
		return (svc_exec_rc(svc, kq));
	case SVC_KIND_ONESHOT:
		return (svc_exec_oneshot(svc, kq));
	case SVC_KIND_TARGET:
	case SVC_KIND_TIMER:
		syslog(LOG_ERR, "svc_exec %s: unit kind %d not yet supported",
		    svc->manifest.label, svc->kind);
		errno = ENOSYS;
		return (-1);
	}
	syslog(LOG_ERR, "svc_exec %s: unknown unit kind %d",
	    svc->manifest.label, svc->kind);
	errno = EINVAL;
	return (-1);
}

/*
 * Resolve a manifest's user/group into uid/gid + supplementary groups.
 * have_creds stays false when neither is set, meaning "run as switchboard's
 * own credentials" (root).  Separate from svc_exec_native's inline copy so
 * the native path is untouched.
 */
static int
command_resolve_creds(const struct svc_manifest *m, uid_t *uidp, gid_t *gidp,
    gid_t *groups, int *ngroupsp, bool *have_credsp)
{
	struct passwd *pw;
	struct group *gr;
	uid_t uid = 0;
	gid_t gid = 0;
	int ngroups = 0;
	bool have = false;

	if (m->user[0] != '\0') {
		if ((pw = getpwnam(m->user)) == NULL) {
			syslog(LOG_ERR, "unit %s: unknown user %s",
			    m->label, m->user);
			return (-1);
		}
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		have = true;
	}
	if (m->group[0] != '\0') {
		if ((gr = getgrnam(m->group)) == NULL) {
			syslog(LOG_ERR, "unit %s: unknown group %s",
			    m->label, m->group);
			return (-1);
		}
		gid = gr->gr_gid;
		have = true;
	}
	if (have) {
		ngroups = NGROUPS_MAX + 1;
		if (getgrouplist(m->user[0] != '\0' ? m->user : "nobody",
		    gid, groups, &ngroups) == -1) {
			syslog(LOG_ERR, "unit %s: getgrouplist failed", m->label);
			return (-1);
		}
	}
	*uidp = uid;
	*gidp = gid;
	*ngroupsp = ngroups;
	*have_credsp = have;
	return (0);
}

/*
 * Launch an RC or ONESHOT unit: run argv to completion under a process
 * descriptor and judge the unit by the command's exit status.  These
 * units do NOT enter capability mode and are not long-lived children of
 * switchboard — an rc daemon daemonizes and reparents to init, so switchboard
 * supervises only the start command.  Readiness is delivered later, on
 * NOTE_EXIT, by the supervisor (RC exit 0 -> RUNNING/"started";
 * ONESHOT exit 0 -> DONE).  The child gets a clean fd table (closefrom)
 * so it never inherits switchboard's Capsule channel, kqueue, or sockets.
 */
static int
svc_exec_command(struct svc_runtime *svc, int kq, char *argv[], bool for_stop)
{
	struct svc_manifest *m = &svc->manifest;
	struct kevent kev;
	gid_t groups[NGROUPS_MAX + 1];
	uid_t uid = 0;
	gid_t gid = 0;
	int ngroups = 0;
	bool have_creds = false;
	pid_t pid;
	int pd_fd;

	/*
	 * A start launch requires the unit be stopped/done.  A stop launch
	 * (for_stop) runs the "onestop" command against a unit the caller has
	 * already moved to SVC_STATE_STOPPING, so it skips that guard; the
	 * caller is responsible for having closed any stale process descriptor.
	 */
	if (!for_stop && svc->state != SVC_STATE_STOPPED &&
	    svc->state != SVC_STATE_DONE) {
		syslog(LOG_WARNING, "unit %s: not stopped (state %d)",
		    m->label, svc->state);
		return (-1);
	}
	if (command_resolve_creds(m, &uid, &gid, groups, &ngroups,
	    &have_creds) == -1) {
		SWITCHBOARD_PROBE_SVC_EXEC_FAIL(m->label, errno);
		return (-1);
	}

	/*
	 * These units have no channel/coalition/jail.  Force the fd fields
	 * to -1 so any close-guard treats them as absent and never closes
	 * fd 0 (their calloc default).
	 */
	svc->channel_fd = -1;
	svc->coalition_fd = -1;
	svc->control_channel = NULL;

	pid = pdfork(&pd_fd, PD_CLOEXEC);
	if (pid == -1) {
		syslog(LOG_ERR, "unit %s: pdfork: %m", m->label);
		SWITCHBOARD_PROBE_SVC_EXEC_FAIL(m->label, errno);
		return (-1);
	}
	if (pid == 0) {
		sigset_t mask;
		int nullfd, lookup_fd;
		bool drop_ambient;

		/*
		 * stdio.  Ordinary commands get /dev/null.  The rc bootstrap
		 * oneshot (want_console) gets /dev/console with a controlling
		 * terminal, exactly as init gave /etc/rc: its progress is visible
		 * on the console and scripts that expect a tty (fsck prompts, job
		 * control) work.  Console setup is best-effort — on failure we
		 * fall back to /dev/null so the child still runs.
		 */
		nullfd = -1;
		if (svc->want_console) {
			int cfd;

			(void)setsid();
			cfd = open("/dev/console", O_RDWR);
			if (cfd != -1) {
				(void)ioctl(cfd, TIOCSCTTY, NULL);
				if (dup2(cfd, STDIN_FILENO) == -1 ||
				    dup2(cfd, STDOUT_FILENO) == -1 ||
				    dup2(cfd, STDERR_FILENO) == -1)
					_exit(126);
				if (cfd > STDERR_FILENO)
					(void)close(cfd);
			} else {
				nullfd = open("/dev/null", O_RDWR);
			}
		} else {
			nullfd = open("/dev/null", O_RDWR);
		}
		if (nullfd != -1) {
			if (dup2(nullfd, STDIN_FILENO) == -1 ||
			    dup2(nullfd, STDOUT_FILENO) == -1 ||
			    dup2(nullfd, STDERR_FILENO) == -1)
				_exit(126);
			if (nullfd > STDERR_FILENO)
				(void)close(nullfd);
		}
		/*
		 * Scrub the fd table so the child never inherits switchboard's
		 * Capsule channel, kqueue, or sockets — but spare the SYSTEM
		 * ambient lookup channel (§21) when one is installed, so rc and
		 * everything it launches keeps service discovery.  The channel
		 * was made CAP_CLOFORK_UNLOCKED at install, so it survived the
		 * pdfork at its parent number; SERVICE_LOOKUP_FD in the inherited
		 * environment already names it.  closefrom cannot skip a middle
		 * fd, so close around it explicitly.
		 *
		 * SECURITY: the SYSTEM ambient lookup channel confers the admin
		 * bypass — a lookup with requester==NULL on a SYSTEM domain grants
		 * SVC_RIGHTS_ALL, including SVC_RIGHTS_ADMIN, and resolves the
		 * self-served control names (naming.c naming_lookup /
		 * naming_lookup_self_control).  It must therefore NEVER survive a
		 * transition into an unprivileged uid, exactly as login(1)/su(1)
		 * close or re-provision it rather than let a user shell inherit it.
		 * A oneshot/RC unit that drops to a non-root user (manifest user=/
		 * group=) consequently gets NO ambient channel: it is closed with
		 * the rest of the table and SERVICE_LOOKUP_FD is unset so no stale
		 * number is named.  Units that stay root (rc, the want_console
		 * bootstrap) keep it — root is the admin principal by the model.
		 */
		lookup_fd = svc_exec_ambient_spare_fd(have_creds, uid,
		    switchboard_ambient_lookup_fd, &drop_ambient);
		if (lookup_fd > STDERR_FILENO) {
			int scan;

			closefrom(lookup_fd + 1);
			for (scan = STDERR_FILENO + 1; scan < lookup_fd; scan++)
				(void)close(scan);
		} else
			closefrom(STDERR_FILENO + 1);
		if (drop_ambient)
			(void)unsetenv(SERVICE_LOOKUP_ENV);
		if (have_creds) {
			if (setgroups(ngroups, groups) == -1 ||
			    setgid(gid) == -1 || setuid(uid) == -1)
				_exit(126);
		}
		/*
		 * Reset every disposition: the manager ignores the signals it
		 * consumes through kqueue, and SIG_IGN survives exec — without
		 * this, every launched service (including the rc world) is
		 * born deaf to SIGTERM.
		 */
		for (int sig = 1; sig < NSIG; sig++)
			(void)signal(sig, SIG_DFL);
		sigemptyset(&mask);
		(void)sigprocmask(SIG_SETMASK, &mask, NULL);
		execv(argv[0], argv);
		_exit(127);
	}

	svc->pid = pid;
	svc->pd_fd = pd_fd;
	svc->launch_id++;
	/*
	 * A stop command runs while the unit stays SVC_STATE_STOPPING; only a
	 * start moves it to STARTING.  The command's exit is disambiguated by
	 * svc->rc_stopping in the supervisor, not by the state alone.
	 */
	if (!for_stop)
		svc->state = SVC_STATE_STARTING;
	clock_gettime(CLOCK_MONOTONIC, &svc->last_start);
	SWITCHBOARD_PROBE_SVC_START(m->label, pid);

	/* Only NOTE_EXIT: these units never enter capability mode. */
	EV_SET(&kev, pd_fd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, svc);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_ERR, "unit %s: procdesc register: %m", m->label);

	syslog(LOG_INFO, "unit %s: launched %s (pid %jd)",
	    m->label, argv[0], (intmax_t)pid);
	return (0);
}

/*
 * RC unit: probe the rc.d service via service(8).  The unit's label is the
 * rc.d service name.  The exit handler adopts an existing daemon or calls
 * svc_exec_rc_start() when the service is absent.
 *
 * "onestart" (not "faststart") is deliberate: the "one" prefix forces the
 * service to start regardless of its rc.conf <name>_enable rcvar.  switchboard
 * must be able to start a disabled service too.  faststart honors the rcvar
 * and would refuse it, so it cannot be used here.
 */
static int
svc_exec_rc(struct svc_runtime *svc, int kq)
{
	const char *launch[4];
	char *argv[4];
	unsigned i;
	int error;

	/*
	 * /etc/rc may already have started an adopted service: upgraded systems
	 * and explicit administrator overrides can still set <label>_enable=YES.
	 * Probe first so adoption is idempotent instead of issuing a duplicate
	 * onestart.  supervisor_command_exited() turns a successful probe into
	 * RUNNING and follows a negative probe with svc_exec_rc_start().
	 */
	rc_adopt_status_argv(svc->manifest.label, launch);
	for (i = 0; i < 4; i++)
		argv[i] = (char *)(uintptr_t)launch[i];
	error = svc_exec_command(svc, kq, argv, false);
	if (error == 0)
		svc->rc_checking = true;
	return (error);
}

int
svc_exec_rc_start(struct svc_runtime *svc, int kq)
{
	const char *launch[4];
	char *argv[4];
	unsigned i;

	/* Shared with rc_adopt's test so the verb ("onestart") and layout
	 * cannot drift.  execv(2) never modifies the argv strings, so casting
	 * the const builder output to the char *[] svc_exec_command wants is
	 * safe. */
	rc_adopt_launch_argv(svc->manifest.label, launch);
	for (i = 0; i < 4; i++)
		argv[i] = (char *)(uintptr_t)launch[i];
	svc->rc_checking = false;
	return (svc_exec_command(svc, kq, argv, false));
}

/*
 * RC unit stop: run "service <label> onestop", which reads the daemon's
 * pidfile and signals the real (init-reparented) process.  This is the ONLY
 * correct way to stop an adopted rc.d daemon — switchboard's process descriptor
 * refers to the long-exited "onestart" wrapper, not the daemon, so signalling
 * it does nothing.  The unit must already be in SVC_STATE_STOPPING; the caller
 * (svc_graceful_stop) has closed the stale descriptor.  The onestop command's
 * exit is delivered on NOTE_EXIT and, with svc->rc_stopping set, transitions
 * the unit to STOPPED.  Reuses svc_exec_command so onestop gets the same clean
 * fd table, a fresh process descriptor, and NOTE_EXIT registration as onestart.
 */
int
svc_exec_rc_stop(struct svc_runtime *svc, int kq)
{
	const char *launch[4];
	char *argv[4];
	unsigned i;

	/* Shared with rc_adopt's test so the verb ("onestop") and layout cannot
	 * drift.  execv(2) never modifies the argv strings. */
	rc_adopt_stop_argv(svc->manifest.label, launch);
	for (i = 0; i < 4; i++)
		argv[i] = (char *)(uintptr_t)launch[i];
	svc->rc_checking = false;
	return (svc_exec_command(svc, kq, argv, true));
}

/*
 * ONESHOT unit: run the manifest's program+arguments once to completion.
 */
static int
svc_exec_oneshot(struct svc_runtime *svc, int kq)
{
	struct svc_manifest *m = &svc->manifest;
	char *argv[SWITCHBOARD_MAX_ARGUMENTS + 2];
	unsigned i;

	if (m->program[0] != '/') {
		syslog(LOG_ERR, "unit %s: program must be absolute: %s",
		    m->label, m->program);
		return (-1);
	}
	argv[0] = m->program;
	for (i = 0; i < m->narguments && i < SWITCHBOARD_MAX_ARGUMENTS; i++)
		argv[i + 1] = m->arguments[i];
	argv[i + 1] = NULL;
	return (svc_exec_command(svc, kq, argv, false));
}

/*
 * Native-launch context.  svc_exec_native mints tokens/services/coalition
 * synchronously, snapshots every parent-held pre-fork descriptor into this heap
 * context, and then forks and execs from svc_launch_finish().  The context
 * exists only to keep that large rollback record off the stack; the launch is
 * straight-line (advance -> finish), never suspended.  All descriptors here are
 * parent-owned until the fork consumes them (or an abort closes them).
 */
struct svc_launch {
	struct svc_manifest minted;	/* released to Capsule on abort */
	struct timespec	exec_start;

	int		capsule_end;
	int		child_end;
	int		coalition_fd;
	int		capprotect_fd;

	int		token_fds[SVC_MAX_TOKENS];
	unsigned	ntokens;
	unsigned	expected_tokens;

	int		service_fds[SERVICE_BOOTSTRAP_CAPABILITY_MAX];
	char		service_names[SERVICE_BOOTSTRAP_CAPABILITY_MAX]
			    [SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX];
	char		service_types[SERVICE_BOOTSTRAP_CAPABILITY_MAX]
			    [SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX];
	unsigned	nservices;

	uid_t		uid;
	gid_t		gid;
	gid_t		groups[NGROUPS_MAX + 1];
	int		ngroups;
	bool		have_creds;
	char		homedir[PATH_MAX];
};

static void svc_launch_advance(struct svc_runtime *svc, int kq);
static void svc_launch_finish(struct svc_runtime *svc, int kq);
static void svc_launch_abort(struct svc_runtime *svc, int error, int kq);

/*
 * Resolve a native unit's operating domain (§22) — the scope switchboard applies
 * to names the unit itself looks up over its bootstrap channel (handle_lookup
 * consults svc->domain).  An explicit manifest `domain` wins; otherwise the
 * bundle class decides: a base-system bundle (under /Capabilities/System)
 * operates in the SYSTEM domain (resolves every name, as today), an application
 * bundle in the least-privilege USER domain.  System-ness is read from the
 * runtime slot's bundle origin, which startup, activation, on-demand launch,
 * and reload all preserve, even for units that provide no names.
 */
static enum svc_domain_kind
svc_native_domain(const struct svc_runtime *svc)
{
	const struct svc_manifest *m;

	m = &svc->manifest;

	if (m->domain == SVC_MANIFEST_DOMAIN_SYSTEM)
		return (SVC_DOMAIN_SYSTEM);
	if (m->domain == SVC_MANIFEST_DOMAIN_USER)
		return (SVC_DOMAIN_USER);
	/* DEFAULT follows the bundle that owns this runtime slot. */
	if (bundle_registry_is_system(svc->bundle_idx))
		return (SVC_DOMAIN_SYSTEM);
	return (SVC_DOMAIN_USER);
}

static int
svc_exec_native(struct svc_runtime *svc, int kq)
{
	/* switchboard launches on one event-loop thread.  This large rollback
	 * record must not consume the process stack. */
	static struct svc_manifest minted_manifest;
	struct svc_manifest *m;
	struct svc_launch *L;		/* heap snapshot handed to the async path */
	struct passwd *pw;
	struct group *gr;
	struct timespec exec_start;
	char homedir[PATH_MAX];
	int capsule_end, child_end, coalition_fd, capprotect_fd;
	int token_fds[SVC_MAX_TOKENS];
	int service_fds[SERVICE_BOOTSTRAP_CAPABILITY_MAX];
	char service_names[SERVICE_BOOTSTRAP_CAPABILITY_MAX]
	    [SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX];
	char service_types[SERVICE_BOOTSTRAP_CAPABILITY_MAX]
	    [SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX];
	unsigned ntokens, nservices, nlisteners;
	uid_t uid;
	gid_t gid;
	gid_t groups[NGROUPS_MAX + 1];
	int ngroups;
	bool have_creds;
	int saved_errno __unused = 0;	/* consumed only by the DTrace probe */
	unsigned expected_tokens, i;

	m = &svc->manifest;
	/*
	 * Resolve the operating domain (§22) before the provider can issue any
	 * lookup or mint over its bootstrap channel.  Set authoritatively here (not
	 * lazily per request) so the mint escalation guard, which reads svc->domain,
	 * sees the true scope: a USER-domain unit cannot mint (svc_domain_may_mint).
	 */
	svc->domain.kind = svc_native_domain(svc);
	svc->domain.uid = 0;
	/*
	 * The unit's anointment set is its policy file's `anointments`
	 * (docs/ipc-anointments-design.md), recomputed on every exec so a reload
	 * or restart picks up the current policy.  Never "*", never ADMIN.
	 */
	svc_anoint_set_from_manifest(&svc->domain.anoint, m);
	SWITCHBOARD_PROBE_ANOINT_SET(m->label, svc->domain.anoint.n,
	    (int)svc->domain.anoint.all, (int)svc->domain.anoint.admin_rights);
	memset(&minted_manifest, 0, sizeof(minted_manifest));
	strlcpy(minted_manifest.label, m->label, sizeof(minted_manifest.label));
	clock_gettime(CLOCK_MONOTONIC, &exec_start);

	if (svc->state != SVC_STATE_STOPPED) {
		syslog(LOG_WARNING, "svc_exec %s: not stopped (state %d)",
		    m->label, svc->state);
		return (-1);
	}

	/* Stamp the unit's resource-ownership identity (keyed on the label). */
	(void)svc_lifecycle_identity(svc);

	if (m->program[0] != '/') {
		syslog(LOG_ERR, "svc_exec %s: program must be absolute: %s",
		    m->label, m->program);
		return (-1);
	}
	if (strstr(m->program, "/../") != NULL ||
	    strstr(m->program, "/..") == m->program + strlen(m->program) - 3) {
		syslog(LOG_ERR, "svc_exec %s: path traversal in program: %s",
		    m->label, m->program);
		return (-1);
	}
	if (access(m->program, X_OK) != 0) {
		syslog(LOG_ERR, "svc_exec %s: %s not executable: %m",
		    m->label, m->program);
		return (-1);
	}

	/*
	 * The only delegated capability left is the combined system-gate token
	 * (path and network capabilities are retired).  Check the total before
	 * acquiring any launch resources so a malformed manifest can never
	 * overrun token_fds[] or reach pdfork() partially provisioned.
	 */
	if (!svc_launch_counts_valid(m)) {
		/* Keep count validation next to the launch barrier. */
		syslog(LOG_ERR, "svc_exec %s: invalid capability counts",
		    m->label);
		return (-1);
	}
	expected_tokens = svc_launch_token_count(m);
	if (expected_tokens > SVC_MAX_TOKENS) {
		syslog(LOG_ERR, "svc_exec %s: too many capability tokens: %u",
		    m->label, expected_tokens);
		return (-1);
	}
	/*
	 * Admit the complete launch before acquiring its first descriptor.
	 * The fixed margin covers the service channel pair, coalition,
	 * capprotect lease, bootstrap envfd, process descriptor, and peak queued
	 * attachment duplicates.  Capability and named-service descriptors are
	 * added explicitly.
	 */
	/*
	 * Count the manager-owned socket-activation listeners to deliver.  Each
	 * live listen fd is dup'd into the child (switchboard keeps its own copy),
	 * so it adds one descriptor to both the fd budget and the bootstrap
	 * capability table.
	 */
	nlisteners = 0;
	for (i = 0; i < svc->nactivation_listen; i++)
		if (svc->activation_listen_fds[i] >= 0)
			nlisteners++;

	if (switchboard_fd_budget_check((size_t)expected_tokens +
	    nlisteners +
	    12, "service launch") == -1) {
		saved_errno = errno;
		syslog(LOG_ERR,
		    "svc_exec %s: descriptor admission denied: %s",
		    m->label, strerror(saved_errno));
		SWITCHBOARD_PROBE_SVC_EXEC_FAIL(m->label, saved_errno);
		errno = saved_errno;
		return (-1);
	}

	/* Resolve credentials before fork. */
	uid = 0;
	gid = 0;
	ngroups = 0;
	have_creds = false;
	homedir[0] = '\0';
	if (m->user[0] != '\0') {
		pw = getpwnam(m->user);
		if (pw == NULL) {
			syslog(LOG_ERR, "svc_exec %s: unknown user: %s",
			    m->label, m->user);
			return (-1);
		}
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		strlcpy(homedir, pw->pw_dir, sizeof(homedir));
		have_creds = true;
	}
	if (m->group[0] != '\0') {
		gr = getgrnam(m->group);
		if (gr == NULL) {
			syslog(LOG_ERR, "svc_exec %s: unknown group: %s",
			    m->label, m->group);
			return (-1);
		}
		gid = gr->gr_gid;
		have_creds = true;
		if (m->user[0] == '\0') {
			pw = getpwnam("nobody");
			if (pw == NULL) {
				syslog(LOG_ERR, "svc_exec %s: group-only "
				    "manifest requires user nobody",
				    m->label);
				return (-1);
			}
			uid = pw->pw_uid;
			strlcpy(homedir, pw->pw_dir, sizeof(homedir));
		}
	}

	/* Build supplementary group list in the parent (async-signal-safe
	 * setgroups() is used in the child instead of initgroups()). */
	if (have_creds) {
		ngroups = NGROUPS_MAX + 1;
		if (getgrouplist(m->user[0] != '\0' ? m->user : "nobody",
		    gid, groups, &ngroups) == -1) {
			syslog(LOG_ERR, "svc_exec %s: getgrouplist: %m",
			    m->label);
			return (-1);
		}
	}

	/*
	 * Kernel-module loading is no longer switchboard's concern.  A service that
	 * needs a module self-serves it at startup via service_ensure_extension(3)
	 * over system.SystemExtension (bsdextension), exactly as it self-mints storage;
	 * switchboard neither holds kld authority nor loads modules.
	 */

	/* Create channel via Capsule. */
	if (mac_cap_create_channel(
	    &capsule_end, &child_end) == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create channel",
		    m->label);
		SWITCHBOARD_PROBE_CAP_CHANNEL(m->label, -1);
		return (-1);
	}
	if (cap_xfer_limit(capsule_end, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(capsule_end, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(capsule_end, CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_xfer_limit(child_end, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "svc_exec %s: channel confinement: %m",
		    m->label);
		close(capsule_end);
		close(child_end);
		return (-1);
	}
	SWITCHBOARD_PROBE_CAP_CHANNEL(m->label, 0);

	/* Create coalition via Capsule. */
	coalition_fd = mac_cap_create_coalition();
	if (coalition_fd == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create coalition",
		    m->label);
		SWITCHBOARD_PROBE_CAP_COALITION(m->label, -1);
		close(capsule_end);
		close(child_end);
		return (-1);
	}
	if (cap_xfer_limit(coalition_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(coalition_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(coalition_fd, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_ERR, "svc_exec %s: coalition confinement: %m",
		    m->label);
		close(capsule_end);
		close(child_end);
		close(coalition_fd);
		return (-1);
	}
	SWITCHBOARD_PROBE_CAP_COALITION(m->label, 0);

	capprotect_fd = mac_cap_mint_capprotect();
	if (capprotect_fd == -1 && errno != ENOTSUP) {
		syslog(LOG_WARNING, "svc_exec %s: capprotect mint: %m",
		    m->label);
	}
	if (capprotect_fd >= 0 &&
	    cap_xfer_limit(capprotect_fd, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "svc_exec %s: capprotect confinement: %m",
		    m->label);
		close(capsule_end);
		close(child_end);
		close(coalition_fd);
		close(capprotect_fd);
		return (-1);
	}

	/*
	 * Mint tokens via Capsule.  Capsule auto-claims resources
	 * not already in its manifest.  The only remaining delegated capability
	 * is the combined system-gate token; path and network capabilities have
	 * been retired, and storage is self-minted by the consumer via bsdfilesystem
	 * (system.Filesystem) outside switchboard's launch path entirely.
	 */
	{
	ntokens = 0;
	nservices = 0;

	if (m->cap_system != 0) {
		int tfd;
		/*
		 * Per-OID sysctl isolation (docs/capability-sysctl-isolation.md,
		 * Phase 2) is the one extension to the module-only delegation
		 * rule.  It is admitted ONLY in the scoped form: cap_system is
		 * exactly SYS_GATE_SYSCTL and the manifest carries a non-empty
		 * isolate list.  A bare sysctl gate (no isolate set) would be a
		 * coarse "isolate every privileged write" claim and stays
		 * refused; sysctl mixed with any other gate also stays refused
		 * (the scoped token the Capsule daemon mints is single-gate).
		 */
		/*
		 * Which system gates a unit receives is its manifest declaration
		 * (capabilities.system), not a hardcoded allowlist here.  The
		 * declaration is the grant: libcapbundle parses the Unit.ucl with
		 * O_VERIFY and switchboard opens the program with O_VERIFY, so when
		 * mac_veriexec enforces, a unit's gate set is exactly what its
		 * signed bundle declares and cannot be tampered into requesting
		 * more.  A per-OID sysctl isolation set is minted in its scoped
		 * form (a single SYS_GATE_SYSCTL token carrying the OID payload);
		 * every other declared gate is minted coarse.
		 */
		bool sysctl_scoped = (m->cap_system == SYS_GATE_SYSCTL) &&
		    m->n_sysctl_isolate > 0;

		if (sysctl_scoped) {
			uint8_t payload[CAPSULE_MINT_SYSTEM_PAYLOAD_MAX];
			size_t plen;

			if (svc_marshal_sysctl_oidset(m, payload,
			    sizeof(payload), &plen) == 0) {
				syslog(LOG_ERR, "svc_exec %s: no sysctl isolate "
				    "OID resolved; refusing coarse sysctl "
				    "delegation", m->label);
				SWITCHBOARD_PROBE_CAP_MINT(m->label, "system", -1);
				goto fail_tokens;
			}
			tfd = capsule_mint_system_scoped(
			    sd.capsule_channel_fd, m->cap_system, payload,
			    plen);
		} else {
			tfd = capsule_mint_system(sd.capsule_channel_fd,
			    m->cap_system);
		}

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "system token", m->label);
			SWITCHBOARD_PROBE_CAP_MINT(m->label, "system", -1);
			goto fail_tokens;
		}
		SWITCHBOARD_PROBE_CAP_MINT(m->label, "system", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_system = m->cap_system;
	}
	}

	/*
	 * Deliver the manager-owned socket-activation listeners (Phase 4) as
	 * ordinary bootstrap capabilities of type "socket", keyed by their
	 * logical name.  The listen fd is dup'd so the child receives its own
	 * copy through the same remap/dup2 machinery as every other capability
	 * fd; switchboard keeps svc->activation_listen_fds[i] open across this and
	 * every future restart, so a queued connection is never dropped.
	 */
	for (i = 0; i < svc->nactivation_listen; i++) {
		int lfd = svc->activation_listen_fds[i];
		int dfd;

		if (lfd < 0)
			continue;
		if (nservices >= SERVICE_BOOTSTRAP_CAPABILITY_MAX) {
			errno = EOVERFLOW;
			goto fail_tokens;
		}
		dfd = fcntl(lfd, F_DUPFD_CLOEXEC, 0);
		if (dfd == -1)
			goto fail_tokens;
		strlcpy(service_names[nservices], m->activation_sockets[i].name,
		    sizeof(service_names[nservices]));
		strlcpy(service_types[nservices], "socket",
		    sizeof(service_types[nservices]));
		service_fds[nservices++] = dfd;
	}

	/*
	 * Per-instance runtime container (macOS-style app container): the unit's
	 * read-write scratch/home, created before exec and delivered as the
	 * "container" capability.  Every unit gets one; it is removed on stop.
	 */
	if (nservices >= SERVICE_BOOTSTRAP_CAPABILITY_MAX) {
		errno = EOVERFLOW;
		goto fail_tokens;
	} else {
		int cfd = svc_run_container_open(m->label, have_creds ? uid : 0,
		    have_creds ? gid : 0);

		if (cfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: runtime container: %m",
			    m->label);
			goto fail_tokens;
		}
		strlcpy(service_names[nservices], "container",
		    sizeof(service_names[nservices]));
		strlcpy(service_types[nservices], "directory",
		    sizeof(service_types[nservices]));
		service_fds[nservices++] = cfd;
	}

	/*
	 * This is the final all-or-nothing barrier before pdfork().  The child
	 * receives only the complete manifest token set plus the one runtime
	 * container; any missing token takes the fail_tokens cleanup path instead.
	 * (switchboard constructs no jail — a jailed unit self-confines via bsdnamespace(8);
	 * see svc_launch_finish.)
	 */
	if (ntokens != expected_tokens ||
	    nservices != nlisteners + 1) {
		syslog(LOG_ERR, "svc_exec %s: incomplete capability set "
		    "(%u/%u tokens, %u/%u services)", m->label, ntokens,
		    expected_tokens, nservices,
		    nlisteners + 1);
		goto fail_tokens;
	}

	/*
	 * Minting is complete.  Snapshot every parent-held pre-fork descriptor
	 * into a heap launch context, then fork and exec (svc_launch_finish).
	 * From here the descriptors are owned by the launch context, not this
	 * stack frame.
	 */
	L = calloc(1, sizeof(*L));
	if (L == NULL) {
		errno = ENOMEM;
		goto fail_tokens;
	}
	L->minted = minted_manifest;
	L->exec_start = exec_start;
	L->capsule_end = capsule_end;
	L->child_end = child_end;
	L->coalition_fd = coalition_fd;
	L->capprotect_fd = capprotect_fd;
	L->ntokens = ntokens;
	L->expected_tokens = expected_tokens;
	for (i = 0; i < ntokens; i++)
		L->token_fds[i] = token_fds[i];
	L->nservices = nservices;
	for (i = 0; i < nservices; i++) {
		L->service_fds[i] = service_fds[i];
		strlcpy(L->service_names[i], service_names[i],
		    sizeof(L->service_names[i]));
		strlcpy(L->service_types[i], service_types[i],
		    sizeof(L->service_types[i]));
	}
	L->uid = uid;
	L->gid = gid;
	L->ngroups = ngroups;
	for (i = 0; i < (unsigned)ngroups && i < nitems(L->groups); i++)
		L->groups[i] = groups[i];
	L->have_creds = have_creds;
	strlcpy(L->homedir, homedir, sizeof(L->homedir));
	svc->launch = L;
	/*
	 * Drive the launch.  It resolves synchronously (advance -> finish ->
	 * fork) and returns here already STARTING or, on failure, aborted back
	 * to STOPPED with launch cleared.  Report the outcome so callers that
	 * expect a -1 on a failed launch still get one.
	 *
	 * A born-in-capability-mode child may already be in capmode by the time
	 * svc_launch_finish() samples pdincapmode(2) right after the fork; it
	 * then drives the NOTE_CAPMODE transition synchronously, so the launch
	 * resolves to RUNNING (not STARTING) within this call.  That is a
	 * successful launch, not a failure — treat both STARTING (async
	 * readiness still pending) and RUNNING (capmode reached synchronously)
	 * as success, and report failure only when the launch actually aborted
	 * back to STOPPED.  (Without this, a small daemon that wins the
	 * cap_enter race is intermittently mis-logged as "failed to launch"
	 * even though it is fully registered and serving.)
	 */
	svc_launch_advance(svc, kq);
	if (svc->launch == NULL && svc->state != SVC_STATE_STARTING &&
	    svc->state != SVC_STATE_RUNNING) {
		errno = EIO;
		return (-1);
	}
	return (0);


fail_tokens:
	/*
	 * Capability minting is the core privilege primitive; record mint
	 * failures in the audit trail.  errno is unreliable here (the mint
	 * call sites log via syslog before jumping), so report the failure
	 * generically and rely on the text token for detail.
	 */
	switchboard_audit(AUE_SWITCHBOARD_CAP_MINT, getuid(), EIO,
	    "svc=%s capability mint failed after %u tokens", m->label, ntokens);
	capsule_release_manifest(sd.capsule_channel_fd, &minted_manifest);
	close(capsule_end);
	close(child_end);
	close(coalition_fd);
	if (capprotect_fd >= 0)
		close(capprotect_fd);
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);
	for (i = 0; i < nservices; i++)
		close(service_fds[i]);
	return (-1);
}

/*
 * Abandon a launch before the fork: release the minted manifest, close
 * every parent-held descriptor, and return the unit to STOPPED.  Restart
 * policy (if any) re-triggers a fresh launch later.
 */
static void
svc_launch_abort(struct svc_runtime *svc, int error, int kq __unused)
{
	struct svc_launch *L = svc->launch;
	unsigned i;

	if (L == NULL)
		return;
	syslog(LOG_ERR, "svc_exec %s: launch aborted: %s",
	    svc->manifest.label, strerror(error != 0 ? error : EIO));
	SWITCHBOARD_PROBE_SVC_EXEC_FAIL(svc->manifest.label, error);
	capsule_release_manifest(sd.capsule_channel_fd, &L->minted);
	if (L->capsule_end >= 0)
		close(L->capsule_end);
	if (L->child_end >= 0)
		close(L->child_end);
	if (L->coalition_fd >= 0)
		close(L->coalition_fd);
	if (L->capprotect_fd >= 0)
		close(L->capprotect_fd);
	for (i = 0; i < L->ntokens; i++)
		if (L->token_fds[i] >= 0)
			close(L->token_fds[i]);
	for (i = 0; i < L->nservices; i++)
		if (L->service_fds[i] >= 0)
			close(L->service_fds[i]);
	free(L);
	svc->launch = NULL;
	svc->pid = 0;
	svc->state = SVC_STATE_STOPPED;
}

/*
 * Finalize storage delivery, confine child descriptors, and fork/exec.  The
 * tail of the native launch, operating on the launch context.  switchboard builds
 * no jail here — a jailed unit self-confines via bsdnamespace(8) (see below).
 */
static void
svc_launch_finish(struct svc_runtime *svc, int kq)
{
	struct svc_launch *L = svc->launch;
	struct svc_manifest *m = &svc->manifest;
	struct kevent kev[3];
	int bootstrap_fd = -1;
	int pd_fd = -1;
	pid_t pid;
	int saved_errno = 0;
	unsigned i;

	if (L->ntokens > 0)
		syslog(LOG_DEBUG, "svc_exec %s: minted %u tokens", m->label,
		    L->ntokens);

	/*
	 * switchboard does not construct jails.  A jailed unit self-confines through
	 * its library (service_enter_namespace(3)), which resolves bsdnamespace(8) by
	 * name and jail_attach_jd(2)s the process itself — the same on-demand,
	 * library-driven self-service every non-system feature uses.  switchboard
	 * only launches the unit; jails (a weak, opt-in confinement) are entirely
	 * the unit's own concern.
	 */

	if (prepare_child_descriptor(L->child_end) == -1 ||
	    (L->capprotect_fd >= 0 &&
	    prepare_child_descriptor_forkable(L->capprotect_fd) == -1))
		goto fail_prefork;
	for (i = 0; i < L->ntokens; i++)
		if (prepare_child_descriptor(L->token_fds[i]) == -1)
			goto fail_prefork;
	for (i = 0; i < L->nservices; i++) {
		int prepared;

		/*
		 * A storage directory must stay fork-inheritable: a provider
		 * that runs its storage backend in a pdfork(2)ed child (bsdlog)
		 * hands the directory to that child by inheritance.  Hardening
		 * it to CLOFORK_ONCE here latches it to CLOFORK_LOCKED after the
		 * launch fork, and the provider can no longer share it.
		 */
		if (strcmp(L->service_types[i], "directory") == 0)
			prepared = prepare_child_descriptor_forkable(
			    L->service_fds[i]);
		else
			prepared = prepare_child_descriptor(L->service_fds[i]);
		if (prepared == -1)
			goto fail_prefork;
	}

	bootstrap_fd = create_service_bootstrap(m, L->ntokens, L->nservices,
	    L->service_names, L->service_types, L->capprotect_fd >= 0);
	if (bootstrap_fd == -1) {
		syslog(LOG_ERR, "svc_exec %s: bootstrap descriptor: %m",
		    m->label);
		svc_launch_abort(svc, errno, kq);
		return;
	}

	pid = pdfork(&pd_fd, PD_CLOEXEC);
	if (pid == -1) {
		syslog(LOG_ERR, "svc_exec %s: pdfork: %m", m->label);
		close(bootstrap_fd);
		svc_launch_abort(svc, errno, kq);
		return;
	}
	if (pid == 0) {
		child_exec(m, L->child_end, L->capprotect_fd, bootstrap_fd,
		    L->token_fds, L->ntokens, L->service_fds, L->nservices,
		    L->uid, L->gid, L->have_creds,
		    L->homedir[0] != '\0' ? L->homedir : NULL, L->groups,
		    L->ngroups);
		/* NOTREACHED */
	}

	/* Parent: the child owns its copies now. */
	close(L->child_end);
	L->child_end = -1;
	close(bootstrap_fd);
	/*
	 * Launcher-applied protection: shield the child by its process descriptor
	 * now, while pd_fd is still transferable and before the child's program
	 * image runs.  This closes the window a self-applied shield cannot cover
	 * (the interval between fork and the new image installing its own policy)
	 * and does not depend on the child cooperating.  Must precede the pd_fd
	 * cap_xfer_limit(NONE) below, which would otherwise block the fd handoff
	 * to the capprotect instance.
	 */
	if (L->capprotect_fd >= 0 && m->protect_flags != 0) {
		if (mac_cap_protect(L->capprotect_fd, pd_fd,
		    m->protect_flags) == -1)
			syslog(LOG_WARNING, "svc_exec %s: launcher protect: %m",
			    m->label);
		else
			syslog(LOG_INFO, "svc_exec %s: launcher-protected "
			    "pid %d (flags 0x%x)", m->label, (int)pid,
			    m->protect_flags);
	}
	if (L->capprotect_fd >= 0) {
		close(L->capprotect_fd);
		L->capprotect_fd = -1;
	}
	for (i = 0; i < L->ntokens; i++)
		close(L->token_fds[i]);
	L->ntokens = 0;
	for (i = 0; i < L->nservices; i++)
		close(L->service_fds[i]);
	L->nservices = 0;

	if (mac_cap_coalition_enlist(L->coalition_fd, pd_fd) != 0) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: coalition enlist: %m", m->label);
		goto fail_postfork;
	}
	/*
	 * Coalition leadership is best-effort supervision: the leader's death
	 * tears down the coalition's orphaned descendants.  The service itself is
	 * already enlisted (above) and its exit is observed directly through the
	 * process descriptor, so a failed or racy leader assignment must NOT kill
	 * an already-running, boot-critical child.  Warn and continue with
	 * slightly degraded descendant cleanup rather than aborting the launch.
	 * (Historically this goto fail_postfork intermittently killed
	 * system.Notify/bsdnotify at boot when set_leader lost a race with the
	 * freshly-forked child's kernel registration.)
	 */
	if (mac_cap_coalition_set_leader(L->coalition_fd, pd_fd) != 0)
		syslog(LOG_WARNING, "svc_exec %s: coalition set_leader "
		    "(non-fatal, descendant cleanup degraded): %m", m->label);
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_PDKILL, CAP_PDGETPID, CAP_EVENT);
		if (cap_rights_limit(pd_fd, &rights) == -1 ||
		    cap_xfer_limit(pd_fd, CAP_XFER_NONE) == -1 ||
		    cap_clofork_limit(pd_fd, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(pd_fd, CAP_CLOEXEC_LOCKED) == -1 ||
		    cap_clofork_limit(L->capsule_end, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(L->capsule_end, CAP_CLOEXEC_LOCKED) == -1 ||
		    cap_clofork_limit(L->coalition_fd,
		    CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(L->coalition_fd,
		    CAP_CLOEXEC_LOCKED) == -1) {
			saved_errno = errno;
			syslog(LOG_ERR, "svc_exec %s: supervisor fd "
			    "confinement: %m", m->label);
			goto fail_postfork;
		}
	}

	svc->pid = pid;
	svc->launch_id = ++svc_launch_sequence;
	if (svc->launch_id == 0)
		svc->launch_id = ++svc_launch_sequence;
	svc->pd_fd = pd_fd;
	if (svc_channel_attach(svc, L->capsule_end) == -1) {
		saved_errno = errno;
		L->capsule_end = -1;
		syslog(LOG_ERR, "svc_exec %s: control channel: %m", m->label);
		goto fail_postfork;
	}
	L->capsule_end = -1;
	svc->coalition_fd = L->coalition_fd;
	L->coalition_fd = -1;
	svc->state = SVC_STATE_STARTING;
	svc->protocol_ready = false;
	memset(svc->name_state, SVC_NAME_UNCLAIMED, sizeof(svc->name_state));
	memset(svc->name_sendable, 0, sizeof(svc->name_sendable));
	clock_gettime(CLOCK_MONOTONIC, &svc->last_start);

	EV_SET(&kev[0], pd_fd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_EXIT | NOTE_EXEC | NOTE_CAPMODE, 0, svc);
	EV_SET(&kev[1], svc->channel_fd, EVFILT_READ, EV_ADD, 0, 0, svc);
	EV_SET(&kev[2], svc->coalition_fd, EVFILT_READ, EV_ADD, 0, 0, svc);
	if (kevent(kq, kev, 3, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "svc_exec %s: kevent register: %m", m->label);
		pdkill(pd_fd, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
		capsule_release_manifest(sd.capsule_channel_fd, &L->minted);
		close(svc->pd_fd);
		svc->pd_fd = -1;
		svc_channel_close(svc);
		close(svc->coalition_fd);
		svc->coalition_fd = -1;
		svc->pid = 0;
		svc->state = SVC_STATE_STOPPED;
		free(L);
		svc->launch = NULL;
		return;
	}
	svc_channel_sync_events(svc, kq);

	syslog(LOG_INFO, "service %s: started pid %jd uid %ju gid %ju",
	    m->label, (intmax_t)pid, (uintmax_t)L->uid, (uintmax_t)L->gid);
	SWITCHBOARD_PROBE_SVC_START(m->label, pid);
	switchboard_audit(AUE_SWITCHBOARD_SVC_EXEC, getuid(), 0,
	    "svc=%s pid=%jd uid=%u gid=%u creds_changed=%d", m->label,
	    (intmax_t)pid, (unsigned)L->uid, (unsigned)L->gid,
	    L->have_creds ? 1 : 0);

	{
		struct timespec exec_end;
		uint64_t dur __unused;

		clock_gettime(CLOCK_MONOTONIC, &exec_end);
		dur = (uint64_t)(exec_end.tv_sec - L->exec_start.tv_sec) *
		    1000000000ULL +
		    (uint64_t)(exec_end.tv_nsec - L->exec_start.tv_nsec);
		SWITCHBOARD_PROBE_SVC_EXEC_DONE(m->label, dur, L->ntokens);
	}

	/* Launch context is spent; the descriptors it carried now live on the
	 * child, svc->control_channel, and svc->coalition_fd. */
	free(L);
	svc->launch = NULL;

	switch (pdincapmode(pd_fd)) {
	case 1:
		memset(&kev[0], 0, sizeof(kev[0]));
		kev[0].filter = EVFILT_PROCDESC;
		kev[0].fflags = NOTE_CAPMODE;
		kev[0].udata = svc;
		supervisor_handle_procdesc(&kev[0]);
		break;
	case 0:
		break;
	default:
		syslog(LOG_ERR, "svc_exec %s: initial pdincapmode: %m",
		    m->label);
		break;
	}
	return;

fail_prefork:
	saved_errno = errno;
	syslog(LOG_ERR, "svc_exec %s: child descriptor confinement: %m",
	    m->label);
	if (bootstrap_fd >= 0)
		close(bootstrap_fd);
	svc_launch_abort(svc, saved_errno, kq);
	return;

fail_postfork:
	SWITCHBOARD_PROBE_SVC_EXEC_FAIL(m->label, saved_errno);
	pdkill(pd_fd, SIGKILL);
	waitpid(pid, NULL, WNOHANG);
	close(pd_fd);
	/* child_end/bootstrap_fd/token/service fds already closed. */
	svc->pid = 0;
	svc->pd_fd = -1;
	svc_launch_abort(svc, saved_errno, kq);
}

/*
 * Drive the launch to the fork.  With components removed a launch is never
 * suspended: advance goes straight to the fork/exec in svc_launch_finish().
 */
static void
svc_launch_advance(struct svc_runtime *svc, int kq)
{

	if (svc->launch == NULL)
		return;
	svc_launch_finish(svc, kq);
}

void
svc_launch_cancel(struct svc_runtime *svc, int kq)
{

	if (svc->launch != NULL)
		svc_launch_abort(svc, ECANCELED, kq);
}
