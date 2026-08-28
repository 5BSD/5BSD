/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service fork/exec for serviced.
 *
 * Creates a channel, mints capability tokens, pdfork()s a
 * child, scrubs its environment and fds, sets credentials, and
 * exec()s the program from the manifest.  Registers the process
 * descriptor and channel on the kqueue for supervision.
 *
 * Unlike authorityd, serviced does not hold /dev/mac_capability directly.
 * Channel and coalition creation use the delegated mac_capability fd
 * (mac_cap_direct.c).  Token minting goes through the authority
 * channel (authority_client.c).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/mman.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/zfshandle.h>

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
#include <component_session.h>
#include <service_bootstrap.h>
#include <channel.h>
#include <tzfsd.h>

#include "serviced.h"
#include "launch_limits.h"
#include "rc_adopt.h"
#include "storage_delivery.h"
#include "fd_budget.h"
#include "serviced_audit.h"
#include "serviced_probes.h"

#define	SVC_CHANNEL_FD	3	/* well-known fd for the channel */
#define	SVC_CAPPROTECT_FD	4	/* capprotect service instance */

/*
 * Main-loop-owned process incarnation counter.  A PID and service label are
 * not sufficient identity because a restarted process can eventually reuse
 * both.  Zero is reserved for a runtime that has not been launched.
 */
static uint64_t svc_launch_sequence;

/*
 * serviced's retained client end of the SYSTEM ambient lookup channel (§21).
 * -1 until startup.c installs it before running /etc/rc.  Every rc/oneshot
 * child inherits it across pdfork (it is CAP_CLOFORK_UNLOCKED) and svc_exec_command
 * spares it from the child's closefrom(2), so rc and everything it launches —
 * getty, login, su — carries system service discovery.
 */
int serviced_ambient_lookup_fd = -1;

/*
 * Timer-ident domain for the async launch deadline.  The high bits of a
 * uintptr_t tag which subsystem owns an EVFILT_TIMER ident (see the matching
 * STOP_TIMER_BIT / ON_DEMAND_TIMER_BIT / SCTL_CONN_TIMER_BIT allocators);
 * bit (n-4) is reserved here.  Idents are routed back by value, so the tag is
 * immune to services[] compaction moving the owning svc_runtime.
 */
#define	SVC_LAUNCH_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 4))
#define	SVC_LAUNCH_TIMEOUT_SEC	20	/* provider on-demand launch + reply */
static uintptr_t svc_launch_timer_next = SVC_LAUNCH_TIMER_BIT | 1;

#define	SVC_TOKEN_BASE	6	/* after the typed bootstrap descriptor */
#define	SVC_MAX_TOKENS	SVC_LAUNCH_MAX_TOKENS
#define	SVC_INTERNAL_ENV	10	/* PATH, bootstrap, selectors, USER/HOME, NULL */
#define	SVC_MAX_ENV	(SVC_INTERNAL_ENV + SERVICED_MAX_ENVIRONMENT)
/*
 * A component provider forks and initialises a per-session worker before it
 * acknowledges the bootstrap.  On emulated hardware that setup (fork, sandbox
 * entry, and the filesystem provider's mount handoff) runs well past two
 * seconds, so a tight bound timed out every first component session.  Real
 * hardware acknowledges in a few milliseconds; this ceiling is only ever
 * approached on the first, cold session.
 */
#define	SVC_COMPONENT_BOOTSTRAP_TIMEOUT_MS	15000
/*
 * Longest a single wait for the session reply blocks before the main loop's
 * service channels are pumped, so a provider mid-bootstrap can resolve its own
 * IPC dependencies instead of deadlocking against this blocked svc_exec.
 */
#define	SVC_COMPONENT_BOOTSTRAP_PUMP_MS		50

_Static_assert(SVC_CHANNEL_FD < SERVICE_BOOTSTRAP_FD,
    "service channel overlaps bootstrap descriptor");
_Static_assert(SVC_CAPPROTECT_FD < SERVICE_BOOTSTRAP_FD,
    "capprotect overlaps bootstrap descriptor");
_Static_assert(SVC_TOKEN_BASE == SERVICE_BOOTSTRAP_FD + 1,
    "token layout must follow bootstrap descriptor");
_Static_assert(SVC_MAX_TOKENS <= SERVICE_BOOTSTRAP_TOKEN_MAX,
    "bootstrap token table is too small");
_Static_assert(SVC_LAUNCH_MAX_NAMED_FDS <=
    SERVICE_BOOTSTRAP_CAPABILITY_MAX,
    "bootstrap capability table is too small");
_Static_assert(SERVICED_CAP_SERVICE_NAME_MAX <=
    SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX,
    "bootstrap capability name is too small");
_Static_assert(SERVICED_LABEL_MAX <= SERVICE_BOOTSTRAP_LABEL_MAX,
    "bootstrap label is too small");

static const char *
local_component_provider(const struct serviced_component *component)
{

	if (strcmp(component->name, "filesystem") == 0)
		return ("org.5bsd.FileSystemCmp");
	if (strcmp(component->name, "network") == 0)
		return ("org.5bsd.NetworkCmp");
	if (strcmp(component->name, "crypto") == 0)
		return ("org.5bsd.CryptoCmp");
	return (NULL);
}

/*
 * Return the first component provider name this manifest needs that is not
 * registered yet, or NULL when every provider is available.  Callers defer
 * the launch on that name instead of failing the exec with ENOENT.
 */
const char *
svc_exec_blocking_provider(const struct svc_manifest *m)
{
	const char *provider;
	unsigned i;

	for (i = 0; i < m->ncomponents; i++) {
		provider = local_component_provider(&m->components[i]);
		if (provider != NULL && !naming_exists(provider))
			return (provider);
	}
	return (NULL);
}

static const char *
local_component_interface(const struct serviced_component *component)
{

	if (strcmp(component->name, "filesystem") == 0)
		return ("org.5bsd.filesystem");
	if (strcmp(component->name, "network") == 0)
		return ("org.5bsd.network");
	if (strcmp(component->name, "crypto") == 0)
		return ("org.5bsd.crypto");
	return (NULL);
}

struct component_call_state {
	uint64_t		 instance_id;
	int			 member_fd;
	int			 error;
	bool			 done;
	struct channel_request	*request;
};

static void
component_reply(struct channel_request *request,
    struct channel_message *message, int error, void *argument)
{
	struct component_call_state *state;
	const struct component_session_reply *reply;
	size_t nfds;

	state = argument;
	state->request = NULL;
	if (error != 0)
		state->error = error;
	else {
		reply = channel_message_data(message);
		nfds = channel_message_fd_count(message);
		if (channel_message_length(message) != sizeof(*reply) ||
		    reply->magic != COMPONENT_SESSION_MAGIC ||
		    reply->version != COMPONENT_SESSION_VERSION ||
		    reply->header_size != sizeof(*reply) ||
		    reply->instance_id != state->instance_id ||
		    reply->reserved[0] != 0 || reply->reserved[1] != 0 ||
		    reply->reserved[2] != 0 || reply->reserved[3] != 0 ||
		    reply->reserved[4] != 0)
			state->error = EPROTO;
		else if (reply->status != 0) {
			state->error = nfds == 0 ?
			    (reply->status > 0 ? reply->status : EPROTO) :
			    EPROTO;
		} else if (nfds != 1 ||
		    (reply->member_type !=
		    COMPONENT_SESSION_MEMBER_PROCDESC &&
		    reply->member_type !=
		    COMPONENT_SESSION_MEMBER_COALITION))
			state->error = EPROTO;
		else {
			state->member_fd = channel_message_take_fd(message, 0);
			if (state->member_fd == -1)
				state->error = errno;
		}
	}
	if (message != NULL)
		channel_message_free(message);
	channel_request_release(request);
	state->done = true;
}

static int
open_consumer_bundle(const struct svc_manifest *manifest)
{
	char path[PATH_MAX];
	char *marker;

	if (strlcpy(path, manifest->program, sizeof(path)) >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	marker = strstr(path, "/Units/");
	if (marker == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*marker = '\0';
	if (strlen(path) < 4 ||
	    strcmp(path + strlen(path) - 4, ".cap") != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
}

static int
prepare_component_resources(struct svc_runtime *svc,
    const struct svc_manifest *manifest,
    const struct serviced_component *component, uid_t uid, gid_t gid,
    const int *service_fds,
    unsigned nservices,
    char names[][SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX],
    char types[][SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX],
    int fds[static COMPONENT_SESSION_RESOURCE_MAX], size_t *nfdsp)
{
	cap_rights_t rights;
	char storage_role[SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX];
	size_t i;
	int anchor, error;

	*nfdsp = 0;
	if (strcmp(component->name, "filesystem") != 0)
		return (0);
	if (snprintf(storage_role, sizeof(storage_role), "storage:%s",
	    component->storage) >= (int)sizeof(storage_role)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < nservices; i++)
		if (strcmp(names[i], storage_role) == 0 &&
		    strcmp(types[i], "zfshandle") == 0)
			break;
	if (i == nservices) {
		errno = ENOENT;
		return (-1);
	}
	/*
	 * Retain a handle reference for the life of this service before the
	 * launch cleanup closes the delivered service descriptors.  The mount
	 * below is anchored by the handle, and the provider worker receives
	 * only the directory descriptor; without this anchor the mount is
	 * force-unmounted the moment the launch drops its handle, revoking the
	 * worker's directory descriptor mid-session.
	 */
	if (svc->nmount_anchors >= nitems(svc->mount_anchor_fds)) {
		errno = ENOSPC;
		return (-1);
	}
	anchor = fcntl(service_fds[i], F_DUPFD_CLOEXEC, 0);
	if (anchor == -1)
		return (-1);
	if (cap_clofork_limit(anchor, CAP_CLOFORK_LOCKED) == -1) {
		error = errno != 0 ? errno : EIO;
		close(anchor);
		errno = error;
		return (-1);
	}
	fds[0] = tzfsd_mount_dir(service_fds[i], 0);
	if (fds[0] == -1) {
		error = errno != 0 ? errno : EIO;
		close(anchor);
		errno = error;
		return (-1);
	}
	svc->mount_anchor_fds[svc->nmount_anchors++] = anchor;
	if (fchown(fds[0], uid, gid) == -1 ||
	    fchmod(fds[0], 0700) == -1) {
		error = errno != 0 ? errno : EIO;
		close(fds[0]);
		errno = error;
		return (-1);
	}
	fds[1] = open_consumer_bundle(manifest);
	if (fds[1] == -1) {
		error = errno != 0 ? errno : EIO;
		close(fds[0]);
		errno = error;
		return (-1);
	}
	/*
	 * Grant CAP_FLOCK on both resource descriptors.  A component provider
	 * hardens the descriptors it receives with cap_rights_limit(2), and
	 * that only ever narrows a right set — a provider that locks its
	 * backing directory (the filesystem component does) therefore requires
	 * CAP_FLOCK to already be present, or its harden step fails
	 * ENOTCAPABLE and rejects every session.
	 */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_PREAD, CAP_PWRITE,
	    CAP_SEEK, CAP_FCNTL, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FTRUNCATE, CAP_FSYNC, CAP_FLOCK,
	    CAP_CREATE, CAP_MKDIRAT, CAP_UNLINKAT, CAP_RENAMEAT_SOURCE,
	    CAP_RENAMEAT_TARGET);
	if (cap_rights_limit(fds[0], &rights) == -1)
		goto fail;
	if (cap_fcntls_limit(fds[0], 0) == -1)
		goto fail;
	cap_rights_init(&rights, CAP_READ, CAP_PREAD, CAP_SEEK, CAP_FCNTL,
	    CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT, CAP_FLOCK);
	if (cap_rights_limit(fds[1], &rights) == -1)
		goto fail;
	if (cap_fcntls_limit(fds[1], 0) == -1)
		goto fail;
	for (i = 0; i < 2; i++) {
		if (cap_xfer_limit(fds[i], CAP_XFER_ONCE) == -1 ||
		    cap_clofork_limit(fds[i], CAP_CLOFORK_ONCE) == -1 ||
		    cap_cloexec_limit(fds[i], CAP_CLOEXEC_LOCKED) == -1)
			goto fail;
	}
	*nfdsp = 2;
	return (0);

fail:
	error = errno != 0 ? errno : EIO;
	close(fds[0]);
	close(fds[1]);
	errno = error;
	return (-1);
}

static bool
storage_is_filesystem_backing(const struct svc_manifest *manifest,
    const char *name)
{
	unsigned i;

	for (i = 0; i < manifest->ncomponents; i++)
		if (strcmp(manifest->components[i].name, "filesystem") == 0 &&
		    strcmp(manifest->components[i].storage, name) == 0)
			return (true);
	return (false);
}

/*
 * Finalize storage delivery after descriptor factories consumed their private
 * backing handles.  Mount-only claims become ordinary directory capabilities;
 * a filesystem descriptor's backing store is not also exposed to its client.
 */
static int
finalize_storage_descriptors(struct svc_runtime *svc,
    const struct svc_manifest *manifest, uid_t uid,
    gid_t gid, int *fds, unsigned *nfdsp,
    char names[][SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX],
    char types[][SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX])
{
	cap_rights_t rights;
	char role[SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX];
	unsigned claim, i, j;
	int anchor, dirfd, error;
	enum storage_delivery_kind delivery;

	for (claim = 0; claim < manifest->ncap_storage; claim++) {
		if (snprintf(role, sizeof(role), "storage:%s",
		    manifest->cap_storage[claim].name) >= (int)sizeof(role))
			return (errno = EOVERFLOW, -1);
		for (i = 0; i < *nfdsp; i++)
			if (strcmp(names[i], role) == 0 &&
			    strcmp(types[i], "zfshandle") == 0)
				break;
		if (i == *nfdsp)
			return (errno = ENOENT, -1);
		delivery = storage_delivery_select(
		    manifest->cap_storage[claim].rights,
		    storage_is_filesystem_backing(manifest,
		    manifest->cap_storage[claim].name));
		if (delivery == STORAGE_DELIVERY_PRIVATE) {
			close(fds[i]);
			for (j = i + 1; j < *nfdsp; j++) {
				fds[j - 1] = fds[j];
				memcpy(names[j - 1], names[j], sizeof(names[j - 1]));
				memcpy(types[j - 1], types[j], sizeof(types[j - 1]));
			}
			(*nfdsp)--;
			continue;
		}
		if (delivery == STORAGE_DELIVERY_ZFSHANDLE)
			continue;
		/*
		 * The anon mount below is anchored by the storage handle; the
		 * provider receives only the directory descriptor.  Retain a
		 * handle reference for the life of the service before the launch
		 * cleanup closes the delivered handle, or the mount is
		 * force-unmounted the moment the launch drops it and every
		 * fstat(2) on the delivered directory fails EBADF.
		 */
		if (svc->nmount_anchors >= nitems(svc->mount_anchor_fds))
			return (errno = ENOSPC, -1);
		anchor = fcntl(fds[i], F_DUPFD_CLOEXEC, 0);
		if (anchor == -1)
			return (-1);
		if (cap_clofork_limit(anchor, CAP_CLOFORK_LOCKED) == -1) {
			error = errno != 0 ? errno : EIO;
			close(anchor);
			return (errno = error, -1);
		}
		dirfd = tzfsd_mount_dir(fds[i], 0);
		if (dirfd == -1) {
			error = errno != 0 ? errno : EIO;
			close(anchor);
			return (errno = error, -1);
		}
		svc->mount_anchor_fds[svc->nmount_anchors++] = anchor;
		cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_PREAD, CAP_PWRITE,
		    CAP_SEEK, CAP_FCNTL, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
		    CAP_FTRUNCATE, CAP_FSYNC, CAP_CREATE, CAP_MKDIRAT,
		    CAP_UNLINKAT, CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET);
		/*
		 * Status-flag fcntls must survive onto files the provider opens
		 * under this directory: a provider that keeps an append-mode log
		 * (logd) sets O_APPEND with F_SETFL, and an openat(2)ed file never
		 * carries an fcntl its parent directory lacks.  Grant GETFL|SETFL
		 * here so those files can, matching the injected-channel policy.
		 */
		if (fchown(dirfd, uid, gid) == -1 || fchmod(dirfd, 0700) == -1 ||
		    cap_rights_limit(dirfd, &rights) == -1 ||
		    cap_fcntls_limit(dirfd,
		    CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) == -1) {
			error = errno != 0 ? errno : EIO;
			close(dirfd);
			return (errno = error, -1);
		}
		close(fds[i]);
		fds[i] = dirfd;
		strlcpy(types[i], "directory", sizeof(types[i]));
	}
	return (0);
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
    int *service_fds, unsigned nservices, int *component_fds,
    unsigned *component_indices, unsigned ncomponents, int jail_fd,
    uid_t uid, gid_t gid, bool have_creds, const char *homedir,
    gid_t *groups, int ngroups)
{
	char user_env[128], home_env[PATH_MAX + 8];
	char unit_dir[PATH_MAX], unit_dir_env[PATH_MAX + 32];
	char bootstrap_env[32];
	char network_component_env[32];
	char filesystem_component_env[32];
	char crypto_component_env[32];
	char *env[SVC_MAX_ENV];
	char *argv[SERVICED_MAX_ARGUMENTS + 2];
	int nullfd, fd;
	bool have_capprotect;
	unsigned i, envc;

	/* Redirect stdio to /dev/null. */
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd == -1)
		_exit(126);
	if (dup2(nullfd, STDIN_FILENO) == -1 ||
	    dup2(nullfd, STDOUT_FILENO) == -1 ||
	    dup2(nullfd, STDERR_FILENO) == -1)
		_exit(126);
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

		safe_base = SVC_TOKEN_BASE + (int)ntokens + (int)nservices +
		    (int)ncomponents + 1;
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
		for (i = 0; i < ncomponents; i++) {
			if (component_fds[i] < safe_base) {
				fd = fcntl(component_fds[i], F_DUPFD, safe_base);
				if (fd == -1)
					_exit(126);
				(void)close(component_fds[i]);
				component_fds[i] = fd;
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
	for (i = 0; i < ncomponents; i++) {
		fd = SVC_TOKEN_BASE + (int)ntokens + (int)nservices + (int)i;
		if (dup2(component_fds[i], fd) == -1)
			_exit(126);
		(void)close(component_fds[i]);
	}

	/* Attach to jail descriptor before closefrom() destroys it.
	 * Must also happen before credential drop since jail_attach_jd
	 * requires root. */
	if (jail_fd >= 0) {
		if (jail_attach_jd(jail_fd) == -1)
			_exit(126);
		(void)close(jail_fd);
	}

	closefrom(SVC_TOKEN_BASE + (int)ntokens + (int)nservices +
	    (int)ncomponents);

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
	for (i = 0; i < ncomponents; i++) {
		fd = SVC_TOKEN_BASE + (int)ntokens + (int)nservices + (int)i;
		if (fcntl(fd, F_SETFD, 0) == -1 ||
		    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1)
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
	 * Local components are authority descriptors, not discoverable names.
	 * Inject the final descriptor number directly.  Typed libraries consume
	 * and remove these variables; global services never appear here.
	 */
	for (i = 0; i < ncomponents; i++) {
		const struct serviced_component *component;
		int component_fd;

		component = &m->components[component_indices[i]];
		component_fd = SVC_TOKEN_BASE + (int)ntokens + (int)nservices +
		    (int)i;
		if (strcmp(component->name, "network") == 0) {
			if (manifest_has_env(m, SERVICE_NETWORKCMP_ENV))
				_exit(126);
			(void)snprintf(network_component_env,
			    sizeof(network_component_env), "%s=%d",
			    SERVICE_NETWORKCMP_ENV, component_fd);
			env[envc++] = network_component_env;
		} else if (strcmp(component->name, "filesystem") == 0) {
			if (manifest_has_env(m, SERVICE_FILESYSTEMCMP_ENV))
				_exit(126);
			(void)snprintf(filesystem_component_env,
			    sizeof(filesystem_component_env), "%s=%d",
			    SERVICE_FILESYSTEMCMP_ENV, component_fd);
			env[envc++] = filesystem_component_env;
		} else if (strcmp(component->name, "crypto") == 0) {
			if (manifest_has_env(m, SERVICE_CRYPTOCMP_ENV))
				_exit(126);
			(void)snprintf(crypto_component_env,
			    sizeof(crypto_component_env), "%s=%d",
			    SERVICE_CRYPTOCMP_ENV, component_fd);
			env[envc++] = crypto_component_env;
		} else {
			/* The manifest parser must reject all other components. */
			_exit(126);
		}
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

	execve(m->program, argv, env);
	_exit(127);
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
 * have_creds stays false when neither is set, meaning "run as serviced's
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
 * serviced — an rc daemon daemonizes and reparents to init, so serviced
 * supervises only the start command.  Readiness is delivered later, on
 * NOTE_EXIT, by the supervisor (RC exit 0 -> RUNNING/"started";
 * ONESHOT exit 0 -> DONE).  The child gets a clean fd table (closefrom)
 * so it never inherits serviced's authority channel, kqueue, or sockets.
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
		SERVICED_PROBE_SVC_EXEC_FAIL(m->label, errno);
		return (-1);
	}

	/*
	 * These units have no channel/coalition/jail.  Force the fd fields
	 * to -1 so any close-guard treats them as absent and never closes
	 * fd 0 (their calloc default).
	 */
	svc->channel_fd = -1;
	svc->coalition_fd = -1;
	svc->jail_fd = -1;
	svc->control_channel = NULL;

	pid = pdfork(&pd_fd, PD_CLOEXEC);
	if (pid == -1) {
		syslog(LOG_ERR, "unit %s: pdfork: %m", m->label);
		SERVICED_PROBE_SVC_EXEC_FAIL(m->label, errno);
		return (-1);
	}
	if (pid == 0) {
		sigset_t mask;
		int nullfd, lookup_fd;

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
		 * Scrub the fd table so the child never inherits serviced's
		 * authority channel, kqueue, or sockets — but spare the SYSTEM
		 * ambient lookup channel (§21) when one is installed, so rc and
		 * everything it launches keeps service discovery.  The channel
		 * was made CAP_CLOFORK_UNLOCKED at install, so it survived the
		 * pdfork at its parent number; SERVICE_LOOKUP_FD in the inherited
		 * environment already names it.  closefrom cannot skip a middle
		 * fd, so close around it explicitly.
		 */
		lookup_fd = serviced_ambient_lookup_fd;
		if (lookup_fd > STDERR_FILENO) {
			int scan;

			closefrom(lookup_fd + 1);
			for (scan = STDERR_FILENO + 1; scan < lookup_fd; scan++)
				(void)close(scan);
		} else
			closefrom(STDERR_FILENO + 1);
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
	SERVICED_PROBE_SVC_START(m->label, pid);

	/* Only NOTE_EXIT: these units never enter capability mode. */
	EV_SET(&kev, pd_fd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, svc);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_ERR, "unit %s: procdesc register: %m", m->label);

	syslog(LOG_INFO, "unit %s: launched %s (pid %jd)",
	    m->label, argv[0], (intmax_t)pid);
	return (0);
}

/*
 * RC unit: start the rc.d service via service(8), which sources rc.conf,
 * applies jail/KEYWORD filtering, and starts the daemon.  The unit's label is
 * the rc.d service name.
 *
 * "onestart" (not "faststart") is deliberate: the "one" prefix forces the
 * service to start regardless of its rc.conf <name>_enable rcvar.  serviced
 * adopts a curated rc.d service by setting <name>_enable="NO" in the image so
 * the /etc/rc shim skips it (no double-start); serviced must still be able to
 * start the very service /etc/rc was told not to.  faststart honors the rcvar
 * and would refuse a disabled service, so it cannot be used here.
 */
static int
svc_exec_rc(struct svc_runtime *svc, int kq)
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
	return (svc_exec_command(svc, kq, argv, false));
}

/*
 * RC unit stop: run "service <label> onestop", which reads the daemon's
 * pidfile and signals the real (init-reparented) process.  This is the ONLY
 * correct way to stop an adopted rc.d daemon — serviced's process descriptor
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
	return (svc_exec_command(svc, kq, argv, true));
}

/*
 * ONESHOT unit: run the manifest's program+arguments once to completion.
 */
static int
svc_exec_oneshot(struct svc_runtime *svc, int kq)
{
	struct svc_manifest *m = &svc->manifest;
	char *argv[SERVICED_MAX_ARGUMENTS + 2];
	unsigned i;

	if (m->program[0] != '/') {
		syslog(LOG_ERR, "unit %s: program must be absolute: %s",
		    m->label, m->program);
		return (-1);
	}
	argv[0] = m->program;
	for (i = 0; i < m->narguments && i < SERVICED_MAX_ARGUMENTS; i++)
		argv[i + 1] = m->arguments[i];
	argv[i + 1] = NULL;
	return (svc_exec_command(svc, kq, argv, false));
}

/*
 * Async native-launch context.  A native unit that consumes components cannot
 * be launched by a single straight-line svc_exec: opening a component session
 * makes the provider resolve its OWN IPC dependencies (e.g. the filesystem
 * component connecting to the audit component), which serviced must broker
 * from its event loop.  Blocking the loop for the session reply would deadlock
 * against that.  So svc_exec_native mints synchronously, snapshots every
 * pre-fork descriptor into this heap context, and then drives the component
 * sessions asynchronously: each session's request is sent, its reply channel
 * is armed on the main kqueue, and only once every session has completed does
 * the launch fork and exec.  All descriptors here are parent-owned until the
 * fork consumes them (or an abort closes them).
 */
struct svc_launch {
	struct svc_manifest minted;	/* released to authority on abort */
	struct timespec	exec_start;

	int		authority_end;
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

	int		component_fds[SERVICED_MAX_COMPONENTS];
	unsigned	component_indices[SERVICED_MAX_COMPONENTS];
	unsigned	ncomponents;		/* completed sessions */

	uid_t		uid;
	gid_t		gid;
	gid_t		groups[NGROUPS_MAX + 1];
	int		ngroups;
	bool		have_creds;
	char		homedir[PATH_MAX];

	/* In-flight component session (component_indices[ncomponents..]). */
	unsigned	comp_cursor;		/* index into m->components */
	int		session_cfd;		/* the component fd being injected */
	struct channel *session;		/* wraps a dup of session_cfd */
	int		session_fd;		/* channel_fd(session); armed on kq */
	struct component_call_state call;
	int		resource_fds[COMPONENT_SESSION_RESOURCE_MAX];
	size_t		nresources;
	uintptr_t	timer_ident;		/* EVFILT_TIMER; 0 = unarmed */
};

static void svc_launch_advance(struct svc_runtime *svc, int kq);
static void svc_launch_finish(struct svc_runtime *svc, int kq);
static void svc_launch_abort(struct svc_runtime *svc, int error, int kq);
static int svc_launch_component_start(struct svc_runtime *svc, int kq);

static int
svc_exec_native(struct svc_runtime *svc, int kq)
{
	/* serviced launches on one event-loop thread.  This large rollback
	 * record must not consume the process stack. */
	static struct svc_manifest minted_manifest;
	struct svc_manifest *m;
	struct svc_launch *L;		/* heap snapshot handed to the async path */
	struct passwd *pw;
	struct group *gr;
	struct timespec exec_start;
	char homedir[PATH_MAX];
	int authority_end, child_end, coalition_fd, capprotect_fd;
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
	memset(&minted_manifest, 0, sizeof(minted_manifest));
	strlcpy(minted_manifest.label, m->label, sizeof(minted_manifest.label));
	clock_gettime(CLOCK_MONOTONIC, &exec_start);

	if (svc->state != SVC_STATE_STOPPED) {
		syslog(LOG_WARNING, "svc_exec %s: not stopped (state %d)",
		    m->label, svc->state);
		return (-1);
	}

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
	 * One token is delivered for every path, file, network, and jail
	 * capability.  System gates are deliberately combined into one token.
	 * Check the total before acquiring any launch resources so a malformed
	 * manifest can never overrun token_fds[] or reach pdfork() partially
	 * provisioned.
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
	 * capprotect lease, bootstrap envfd, process descriptor, jail handoff,
	 * and peak queued attachment duplicates.  Capability, named-service,
	 * and local-component descriptors are added explicitly.
	 */
	/*
	 * Count the manager-owned socket-activation listeners to deliver.  Each
	 * live listen fd is dup'd into the child (serviced keeps its own copy),
	 * so it adds one descriptor to both the fd budget and the bootstrap
	 * capability table.
	 */
	nlisteners = 0;
	for (i = 0; i < svc->nactivation_listen; i++)
		if (svc->activation_listen_fds[i] >= 0)
			nlisteners++;

	if (serviced_fd_budget_check((size_t)expected_tokens +
	    m->ncap_storage + m->ncap_services + m->ncomponents + nlisteners +
	    12, "service launch") == -1) {
		saved_errno = errno;
		syslog(LOG_ERR,
		    "svc_exec %s: descriptor admission denied: %s",
		    m->label, strerror(saved_errno));
		SERVICED_PROBE_SVC_EXEC_FAIL(m->label, saved_errno);
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

	svc->jail_fd = -1;

	/* Ensure required kernel modules are loaded before launch. */
	if (m->nkmod_requires > 0) {
		if (kldmgr_ensure_loaded(m,
		    bundle_registry_is_system(svc->bundle_idx), kq) != 0) {
			syslog(LOG_ERR, "svc_exec %s: kmod_requires failed",
			    m->label);
			return (-1);
		}
	}

	/* Create channel via authority. */
	if (mac_cap_create_channel(
	    &authority_end, &child_end) == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create channel",
		    m->label);
		SERVICED_PROBE_CAP_CHANNEL(m->label, -1);
		return (-1);
	}
	if (cap_xfer_limit(authority_end, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(authority_end, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(authority_end, CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_xfer_limit(child_end, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "svc_exec %s: channel confinement: %m",
		    m->label);
		close(authority_end);
		close(child_end);
		return (-1);
	}
	SERVICED_PROBE_CAP_CHANNEL(m->label, 0);

	/* Create coalition via authority. */
	coalition_fd = mac_cap_create_coalition();
	if (coalition_fd == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create coalition",
		    m->label);
		SERVICED_PROBE_CAP_COALITION(m->label, -1);
		close(authority_end);
		close(child_end);
		return (-1);
	}
	if (cap_xfer_limit(coalition_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(coalition_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(coalition_fd, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_ERR, "svc_exec %s: coalition confinement: %m",
		    m->label);
		close(authority_end);
		close(child_end);
		close(coalition_fd);
		return (-1);
	}
	SERVICED_PROBE_CAP_COALITION(m->label, 0);

	capprotect_fd = mac_cap_mint_capprotect();
	if (capprotect_fd == -1 && errno != ENOTSUP) {
		syslog(LOG_WARNING, "svc_exec %s: capprotect mint: %m",
		    m->label);
	}
	if (capprotect_fd >= 0 &&
	    cap_xfer_limit(capprotect_fd, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "svc_exec %s: capprotect confinement: %m",
		    m->label);
		close(authority_end);
		close(child_end);
		close(coalition_fd);
		close(capprotect_fd);
		return (-1);
	}

	/*
	 * Mint tokens via authority.  The authority auto-claims resources
	 * not already in its manifest — one trip per token.
	 *
	 * Each mint is a synchronous RPC with SERVICED_RPC_TIMEOUT_MS
	 * timeout.  Track total elapsed time and abort if the mint
	 * phase exceeds SVC_MINT_DEADLINE_MS to avoid blocking the
	 * event loop for an unbounded duration.
	 *
	 * The ceiling must clear the one-time cost of a cold storage
	 * provider: the first AUTHORITY_OP_MINT_STORAGE makes authorityd
	 * posix_spawn(2) tzfsd, which imports the pool and creates the
	 * dataset before replying.  On emulated hardware that cold start
	 * alone can exceed two seconds; a tighter ceiling aborted every
	 * first component/storage launch.  Subsequent mints reuse the
	 * resident tzfsd and return in well under a millisecond, so this
	 * bound is only ever approached once per boot.
	 */
#define	SVC_MINT_DEADLINE_MS	15000	/* max total mint phase */
	{
	struct timespec mint_start, mint_now;
	uint64_t elapsed_ms;

	clock_gettime(CLOCK_MONOTONIC, &mint_start);
	ntokens = 0;
	nservices = 0;

#define	MINT_CHECK_DEADLINE() do {					\
	clock_gettime(CLOCK_MONOTONIC, &mint_now);			\
	elapsed_ms = (uint64_t)(mint_now.tv_sec - mint_start.tv_sec) *	\
	    1000;							\
	if (mint_now.tv_nsec >= mint_start.tv_nsec) {			\
		elapsed_ms +=						\
		    (uint64_t)(mint_now.tv_nsec - mint_start.tv_nsec) /	\
		    1000000;						\
	} else {							\
		elapsed_ms -= 1000;					\
		elapsed_ms +=						\
		    (uint64_t)(1000000000L + mint_now.tv_nsec -		\
		    mint_start.tv_nsec) / 1000000;			\
	}								\
	if (elapsed_ms > SVC_MINT_DEADLINE_MS) {			\
		syslog(LOG_ERR, "svc_exec %s: mint deadline exceeded "	\
		    "(%ju ms, %u/%u tokens)", m->label,			\
		    (uintmax_t)elapsed_ms, ntokens, expected_tokens);	\
		goto fail_tokens;					\
	}								\
} while (0)

	for (i = 0; i < m->ncap_paths; i++) {
		int tfd = authority_mint_path(sd.authority_channel_fd,
		    m->cap_paths[i]);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "token for %s", m->label, m->cap_paths[i]);
			SERVICED_PROBE_CAP_MINT(m->label, "path", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "path", 0);
		token_fds[ntokens++] = tfd;
		strlcpy(minted_manifest.cap_paths[
		    minted_manifest.ncap_paths++], m->cap_paths[i],
		    PATH_MAX);
		MINT_CHECK_DEADLINE();
	}
	for (i = 0; i < m->ncap_files; i++) {
		int tfd = authority_mint_file(sd.authority_channel_fd,
		    m->cap_files[i].path, m->cap_files[i].actions);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "file token for %s", m->label,
			    m->cap_files[i].path);
			SERVICED_PROBE_CAP_MINT(m->label, "file", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "file", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_files[minted_manifest.ncap_files++] =
		    m->cap_files[i];
		MINT_CHECK_DEADLINE();
	}
	for (i = 0; i < m->ncap_net; i++) {
		int tfd = authority_mint_net(sd.authority_channel_fd, &m->cap_net[i]);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "network token %u", m->label, i);
			SERVICED_PROBE_CAP_MINT(m->label, "net", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "net", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_net[minted_manifest.ncap_net++] =
		    m->cap_net[i];
		MINT_CHECK_DEADLINE();
	}
	for (i = 0; i < m->ncap_jail; i++) {
		int tfd = authority_mint_jail(sd.authority_channel_fd,
		    &m->cap_jail[i]);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "jail token %u", m->label, i);
			SERVICED_PROBE_CAP_MINT(m->label, "jail", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "jail", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_jail[minted_manifest.ncap_jail++] =
		    m->cap_jail[i];
		MINT_CHECK_DEADLINE();
	}
	for (i = 0; i < m->ncap_vsock; i++) {
		int tfd = authority_mint_vsock(sd.authority_channel_fd,
		    &m->cap_vsock[i]);
		if (tfd == -1) {
			SERVICED_PROBE_CAP_MINT(m->label, "vsock", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "vsock", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_vsock[minted_manifest.ncap_vsock++] =
		    m->cap_vsock[i];
		MINT_CHECK_DEADLINE();
	}
	for (i = 0; i < m->ncap_storage; i++) {
		int tfd = authority_mint_storage(sd.authority_channel_fd,
		    &m->cap_storage[i]);
		if (tfd == -1) {
			SERVICED_PROBE_CAP_MINT(m->label, "storage", -1);
			goto fail_tokens;
		}
		if (m->cap_storage[i].lifetime == ORT_STORAGE_LEASE &&
		    storage_lease_acquire(&m->cap_storage[i]) == -1) {
			int saved = errno;

			close(tfd);
			(void)authority_destroy_storage(sd.authority_channel_fd,
			    &m->cap_storage[i]);
			errno = saved;
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "storage", 0);
		if (nservices >= SERVICE_BOOTSTRAP_CAPABILITY_MAX ||
		    snprintf(service_names[nservices],
		    sizeof(service_names[nservices]), "storage:%s",
		    m->cap_storage[i].name) >=
		    (int)sizeof(service_names[nservices])) {
			close(tfd);
			errno = EOVERFLOW;
			goto fail_tokens;
		}
		strlcpy(service_types[nservices], "zfshandle",
		    sizeof(service_types[nservices]));
		service_fds[nservices++] = tfd;
		minted_manifest.cap_storage[minted_manifest.ncap_storage++] =
		    m->cap_storage[i];
		MINT_CHECK_DEADLINE();
	}
	if (m->cap_system != 0) {
		int tfd = authority_mint_system(sd.authority_channel_fd,
		    m->cap_system);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "system token", m->label);
			SERVICED_PROBE_CAP_MINT(m->label, "system", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "system", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_system = m->cap_system;
	}
	for (i = 0; i < m->ncap_services; i++) {
		int sfd = authority_delegate_service(sd.authority_channel_fd,
		    m->cap_services[i]);

		if (sfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to delegate "
			    "capability service %s", m->label,
			    m->cap_services[i]);
			SERVICED_PROBE_CAP_SERVICE(m->label,
			    m->cap_services[i], -1);
			goto fail_tokens;
		}
		if (nservices >= SERVICE_BOOTSTRAP_CAPABILITY_MAX) {
			close(sfd);
			errno = EOVERFLOW;
			goto fail_tokens;
		}
		strlcpy(service_names[nservices], m->cap_services[i],
		    sizeof(service_names[nservices]));
		strlcpy(service_types[nservices], m->cap_services[i],
		    sizeof(service_types[nservices]));
		service_fds[nservices++] = sfd;
		SERVICED_PROBE_CAP_SERVICE(m->label, m->cap_services[i], 0);
		MINT_CHECK_DEADLINE();
	}

#undef MINT_CHECK_DEADLINE
	}

	/*
	 * Deliver the manager-owned socket-activation listeners (Phase 4) as
	 * ordinary bootstrap capabilities of type "socket", keyed by their
	 * logical name.  The listen fd is dup'd so the child receives its own
	 * copy through the same remap/dup2 machinery as every other capability
	 * fd; serviced keeps svc->activation_listen_fds[i] open across this and
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
	 * This is the final all-or-nothing barrier before jail creation and
	 * pdfork().  The child receives only the complete manifest token set;
	 * any missing token takes the fail_tokens cleanup path instead.
	 */
	if (ntokens != expected_tokens ||
	    nservices != m->ncap_storage + m->ncap_services + nlisteners) {
		syslog(LOG_ERR, "svc_exec %s: incomplete capability set "
		    "(%u/%u tokens, %u/%u services)", m->label, ntokens,
		    expected_tokens, nservices,
		    m->ncap_storage + m->ncap_services + nlisteners);
		goto fail_tokens;
	}

	/*
	 * Construct each declared local authority replacement before exec.
	 * Component kinds map to fixed internal factories; provider selection
	 * and per-manifest protocol options are deliberately not part of the
	 * application model.
	 */
	/*
	 * Minting is complete.  Snapshot every parent-held pre-fork descriptor
	 * into a heap launch context and drive the component sessions
	 * asynchronously; the fork happens later, once every session reply is
	 * in (svc_launch_finish).  From here the descriptors are owned by the
	 * launch context, not this stack frame.
	 */
	L = calloc(1, sizeof(*L));
	if (L == NULL) {
		errno = ENOMEM;
		goto fail_tokens;
	}
	L->minted = minted_manifest;
	L->exec_start = exec_start;
	L->authority_end = authority_end;
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
	L->comp_cursor = 0;
	L->ncomponents = 0;
	L->session = NULL;
	L->session_fd = -1;
	L->session_cfd = -1;
	svc->launch = L;
	/*
	 * Drive the launch.  A unit with no components resolves synchronously
	 * (advance -> finish -> fork) and returns here already STARTING or, on
	 * failure, aborted back to STOPPED with launch cleared.  A unit with
	 * components suspends with launch != NULL until its session replies
	 * arrive.  Report the synchronous outcome so callers that expect a -1
	 * on a failed launch still get one.
	 */
	svc_launch_advance(svc, kq);
	if (svc->launch == NULL && svc->state != SVC_STATE_STARTING) {
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
	serviced_audit(AUE_SERVICED_CAP_MINT, getuid(), EIO,
	    "svc=%s capability mint failed after %u tokens", m->label, ntokens);
	authority_release_manifest(sd.authority_channel_fd, &minted_manifest);
	close(authority_end);
	close(child_end);
	close(coalition_fd);
	if (capprotect_fd >= 0)
		close(capprotect_fd);
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);
	for (i = 0; i < nservices; i++)
		close(service_fds[i]);
	if (svc->jail_fd >= 0) {
		jail_remove_jd(svc->jail_fd);
		close(svc->jail_fd);
		svc->jail_fd = -1;
	}
	return (-1);
}

/*
 * Arm the overall launch deadline once, at the start of the first component
 * session.  A single EV_ONESHOT timer bounds the entire async launch: if any
 * provider fails to broker its session in time (or hangs after accepting the
 * connection) the launch is aborted rather than pinned open forever.  The
 * ident is tagged and routed by value, so it survives services[] compaction
 * without a udata re-point.
 */
static void
svc_launch_arm_timer(struct svc_runtime *svc, int kq)
{
	struct svc_launch *L = svc->launch;
	struct kevent kev;

	if (L == NULL || L->timer_ident != 0)
		return;
	L->timer_ident = svc_launch_timer_next;
	svc_launch_timer_next = SVC_LAUNCH_TIMER_BIT |
	    ((svc_launch_timer_next + 1) & (SVC_LAUNCH_TIMER_BIT - 1));
	EV_SET(&kev, L->timer_ident, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    NOTE_SECONDS, SVC_LAUNCH_TIMEOUT_SEC, svc);
	(void)kevent(kq, &kev, 1, NULL, 0, NULL);
}

/* Cancel the launch deadline (idempotent). */
static void
svc_launch_disarm_timer(struct svc_runtime *svc, int kq)
{
	struct svc_launch *L = svc->launch;
	struct kevent kev;

	if (L == NULL || L->timer_ident == 0)
		return;
	EV_SET(&kev, L->timer_ident, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	(void)kevent(kq, &kev, 1, NULL, 0, NULL);
	L->timer_ident = 0;
}

/*
 * Arm (or re-arm) the in-flight component session channel on the main kqueue.
 * READ is always watched for the reply; WRITE is watched only while the
 * request still needs flushing.  udata is the svc_runtime so the event loop
 * can route readiness back to svc_launch_channel_event().
 */
static void
svc_launch_arm(struct svc_runtime *svc, int kq)
{
	struct svc_launch *L = svc->launch;
	struct kevent kev[2];
	int wants_write, n;

	if (L == NULL || L->session == NULL || L->session_fd < 0)
		return;
	n = 0;
	EV_SET(&kev[n++], L->session_fd, EVFILT_READ, EV_ADD, 0, 0, svc);
	wants_write = channel_wants_write(L->session);
	EV_SET(&kev[n++], L->session_fd, EVFILT_WRITE,
	    wants_write > 0 ? EV_ADD : EV_DELETE, 0, 0, svc);
	(void)kevent(kq, kev, n, NULL, 0, NULL);
}

/*
 * Re-point a pending launch's session-channel events at the (possibly moved)
 * svc_runtime.  Called from svc_reregister_kevents after services[] compaction,
 * mirroring how pd_fd/channel_fd/coalition_fd udata is refreshed.
 */
void
svc_launch_reregister(struct svc_runtime *svc, int kq)
{

	svc_launch_arm(svc, kq);
}

/* Tear down the in-flight session channel (kqueue events + channel + cfd). */
static void
svc_launch_drop_session(struct svc_runtime *svc, int kq)
{
	struct svc_launch *L = svc->launch;
	struct kevent kev[2];
	size_t r;

	if (L == NULL)
		return;
	if (L->session_fd >= 0) {
		EV_SET(&kev[0], L->session_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		EV_SET(&kev[1], L->session_fd, EVFILT_WRITE, EV_DELETE, 0, 0,
		    NULL);
		(void)kevent(kq, kev, 2, NULL, 0, NULL);
		L->session_fd = -1;
	}
	if (L->call.request != NULL) {
		(void)channel_request_cancel(L->call.request);
		channel_request_release(L->call.request);
		L->call.request = NULL;
	}
	if (L->session != NULL) {
		channel_destroy(L->session);
		L->session = NULL;
	}
	for (r = 0; r < L->nresources; r++)
		if (L->resource_fds[r] >= 0)
			close(L->resource_fds[r]);
	L->nresources = 0;
	if (L->session_cfd >= 0) {
		close(L->session_cfd);
		L->session_cfd = -1;
	}
}

/*
 * Abandon an async launch before the fork: release the minted manifest, close
 * every parent-held descriptor, and return the unit to STOPPED.  Restart
 * policy (if any) re-triggers a fresh launch later; a component consumer whose
 * provider is up will simply be relaunched on the next lookup.
 */
static void
svc_launch_abort(struct svc_runtime *svc, int error, int kq)
{
	struct svc_launch *L = svc->launch;
	unsigned i;

	if (L == NULL)
		return;
	syslog(LOG_ERR, "svc_exec %s: async launch aborted: %s",
	    svc->manifest.label, strerror(error != 0 ? error : EIO));
	SERVICED_PROBE_SVC_EXEC_FAIL(svc->manifest.label, error);
	svc_launch_disarm_timer(svc, kq);
	svc_launch_drop_session(svc, kq);
	authority_release_manifest(sd.authority_channel_fd, &L->minted);
	if (L->authority_end >= 0)
		close(L->authority_end);
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
	for (i = 0; i < L->ncomponents; i++)
		if (L->component_fds[i] >= 0)
			close(L->component_fds[i]);
	if (svc->jail_fd >= 0) {
		jail_remove_jd(svc->jail_fd);
		close(svc->jail_fd);
		svc->jail_fd = -1;
	}
	free(L);
	svc->launch = NULL;
	svc->pid = 0;
	svc->state = SVC_STATE_STOPPED;
}

/*
 * All component sessions are established: finalize storage delivery, create
 * the jail, confine child descriptors, and fork/exec.  Mirrors the tail of the
 * former synchronous svc_exec_native, operating on the launch context.
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

	/* Every session is in hand; the launch deadline no longer applies. */
	svc_launch_disarm_timer(svc, kq);

	if (finalize_storage_descriptors(svc, m, L->uid, L->gid, L->service_fds,
	    &L->nservices, L->service_names, L->service_types) == -1) {
		syslog(LOG_ERR, "svc_exec %s: storage descriptor delivery: %m",
		    m->label);
		svc_launch_abort(svc, errno, kq);
		return;
	}
	if (L->ntokens > 0)
		syslog(LOG_DEBUG, "svc_exec %s: minted %u tokens", m->label,
		    L->ntokens);

	if (m->has_jail) {
		svc->jail_fd = authority_create_jail(sd.authority_channel_fd,
		    m->jail_name, m->jail_path, m->jail_hostname,
		    m->jail_ip4_addr);
		if (svc->jail_fd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to create jail %s: "
			    "%m", m->label, m->jail_name);
			svc_launch_abort(svc, errno, kq);
			return;
		}
		syslog(LOG_INFO, "svc_exec %s: created jail %s jd=%d", m->label,
		    m->jail_name, svc->jail_fd);
	}

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
		 * that runs its storage backend in a pdfork(2)ed child (logd)
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
	for (i = 0; i < L->ncomponents; i++)
		if (prepare_child_descriptor(L->component_fds[i]) == -1)
			goto fail_prefork;

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
		    L->component_fds, L->component_indices, L->ncomponents,
		    svc->jail_fd, L->uid, L->gid, L->have_creds,
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
	for (i = 0; i < L->ncomponents; i++)
		close(L->component_fds[i]);
	L->ncomponents = 0;

	if (svc->jail_fd >= 0 &&
	    (cap_xfer_limit(svc->jail_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(svc->jail_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(svc->jail_fd, CAP_CLOEXEC_LOCKED) == -1)) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: jail fd confinement: %m",
		    m->label);
		goto fail_postfork;
	}
	if (mac_cap_coalition_enlist(L->coalition_fd, pd_fd) != 0) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: coalition enlist: %m", m->label);
		goto fail_postfork;
	}
	if (mac_cap_coalition_set_leader(L->coalition_fd, pd_fd) != 0) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: coalition set_leader: %m",
		    m->label);
		goto fail_postfork;
	}
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_PDKILL, CAP_PDGETPID, CAP_EVENT);
		if (cap_rights_limit(pd_fd, &rights) == -1 ||
		    cap_xfer_limit(pd_fd, CAP_XFER_NONE) == -1 ||
		    cap_clofork_limit(pd_fd, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(pd_fd, CAP_CLOEXEC_LOCKED) == -1 ||
		    cap_clofork_limit(L->authority_end, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(L->authority_end, CAP_CLOEXEC_LOCKED) == -1 ||
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
	if (svc_channel_attach(svc, L->authority_end) == -1) {
		saved_errno = errno;
		L->authority_end = -1;
		syslog(LOG_ERR, "svc_exec %s: control channel: %m", m->label);
		goto fail_postfork;
	}
	L->authority_end = -1;
	svc->coalition_fd = L->coalition_fd;
	L->coalition_fd = -1;
	svc->state = SVC_STATE_STARTING;
	svc->protocol_ready = false;
	memset(svc->name_state, SVC_NAME_UNCLAIMED, sizeof(svc->name_state));
	clock_gettime(CLOCK_MONOTONIC, &svc->last_start);

	EV_SET(&kev[0], pd_fd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_EXIT | NOTE_EXEC | NOTE_CAPMODE, 0, svc);
	EV_SET(&kev[1], svc->channel_fd, EVFILT_READ, EV_ADD, 0, 0, svc);
	EV_SET(&kev[2], svc->coalition_fd, EVFILT_READ, EV_ADD, 0, 0, svc);
	if (kevent(kq, kev, 3, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "svc_exec %s: kevent register: %m", m->label);
		pdkill(pd_fd, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
		authority_release_manifest(sd.authority_channel_fd, &L->minted);
		close(svc->pd_fd);
		svc->pd_fd = -1;
		svc_channel_close(svc);
		close(svc->coalition_fd);
		svc->coalition_fd = -1;
		if (svc->jail_fd >= 0) {
			jail_remove_jd(svc->jail_fd);
			close(svc->jail_fd);
			svc->jail_fd = -1;
		}
		svc->pid = 0;
		svc->state = SVC_STATE_STOPPED;
		free(L);
		svc->launch = NULL;
		return;
	}
	svc_channel_sync_events(svc, kq);

	syslog(LOG_INFO, "service %s: started pid %jd uid %ju gid %ju",
	    m->label, (intmax_t)pid, (uintmax_t)L->uid, (uintmax_t)L->gid);
	SERVICED_PROBE_SVC_START(m->label, pid);
	serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), 0,
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
		SERVICED_PROBE_SVC_EXEC_DONE(m->label, dur, L->ntokens);
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
	SERVICED_PROBE_SVC_EXEC_FAIL(m->label, saved_errno);
	pdkill(pd_fd, SIGKILL);
	waitpid(pid, NULL, WNOHANG);
	close(pd_fd);
	/* child_end/bootstrap_fd/token/service/component fds already closed. */
	svc->pid = 0;
	svc->pd_fd = -1;
	svc_launch_abort(svc, saved_errno, kq);
}

/*
 * Open the next component session asynchronously.  Resolve the provider,
 * mint its resources, send the session request, and arm the reply channel;
 * the fork waits until svc_launch_channel_event() has completed every session.
 */
static int
svc_launch_component_start(struct svc_runtime *svc, int kq)
{
	struct svc_launch *L = svc->launch;
	struct svc_manifest *m = &svc->manifest;
	const struct serviced_component *component;
	const char *provider, *interface;
	struct component_session_bootstrap message;
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	int cfd, owned, error;

	/* Bound the whole async launch the first time we open a session. */
	svc_launch_arm_timer(svc, kq);

	component = &m->components[L->comp_cursor];
	provider = local_component_provider(component);
	interface = local_component_interface(component);
	if (provider == NULL || interface == NULL) {
		syslog(LOG_ERR, "svc_exec %s: invalid component %s", m->label,
		    component->name);
		svc_launch_abort(svc, EINVAL, kq);
		return (-1);
	}
	SERVICED_PROBE_COMPONENT_RESOLVE(m->label, component->name, provider);
	cfd = naming_lookup(provider, svc, &svc->domain, &error);
	if (cfd == -1) {
		syslog(LOG_ERR, "svc_exec %s: component %s provider %s: %s",
		    m->label, component->name, provider, strerror(error));
		svc_launch_abort(svc, error, kq);
		return (-1);
	}
	L->session_cfd = cfd;
	L->nresources = 0;
	if (prepare_component_resources(svc, m, component, L->uid, L->gid,
	    L->service_fds, L->nservices, L->service_names, L->service_types,
	    L->resource_fds, &L->nresources) == -1) {
		error = errno != 0 ? errno : EIO;
		syslog(LOG_ERR, "svc_exec %s: component %s resources: %s",
		    m->label, component->name, strerror(error));
		svc_launch_abort(svc, error, kq);
		return (-1);
	}
	if (cap_xfer_limit(cfd, CAP_XFER_NONE) == -1 ||
	    cap_cloexec_limit(cfd, CAP_CLOEXEC_ONCE) == -1) {
		error = errno != 0 ? errno : EIO;
		svc_launch_abort(svc, error, kq);
		return (-1);
	}

	/*
	 * Record the authority handoff: the consumer's resources are being
	 * delegated to the component provider for this session.
	 */
	syslog(LOG_INFO, "component=%s phase=delegate label=%s provider=%s "
	    "resources=%zu", component->name, m->label, provider, L->nresources);

	memset(&message, 0, sizeof(message));
	message.magic = COMPONENT_SESSION_MAGIC;
	message.version = COMPONENT_SESSION_VERSION;
	message.header_size = sizeof(message);
	arc4random_buf(&message.instance_id, sizeof(message.instance_id));
	strlcpy(message.name, component->name, sizeof(message.name));
	strlcpy(message.interface, interface, sizeof(message.interface));
	strlcpy(message.interface_version, "1.0.0",
	    sizeof(message.interface_version));
	strlcpy(message.client_label, m->label, sizeof(message.client_label));

	owned = fcntl(cfd, F_DUPFD_CLOEXEC, 0);
	if (owned == -1) {
		svc_launch_abort(svc, errno, kq);
		return (-1);
	}
	if (channel_create(owned, &options, &L->session) == -1) {
		error = errno;
		close(owned);
		svc_launch_abort(svc, error, kq);
		return (-1);
	}
	memset(&L->call, 0, sizeof(L->call));
	L->call.instance_id = message.instance_id;
	L->call.member_fd = -1;
	if (channel_send_request(L->session,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &message,
		.length = sizeof(message),
		.fds = L->resource_fds,
		.nfds = L->nresources
	    }, component_reply, &L->call, &L->call.request) == -1) {
		error = errno;
		svc_launch_drop_session(svc, kq);
		svc_launch_abort(svc, error, kq);
		return (-1);
	}
	L->session_fd = channel_fd(L->session);
	svc_launch_arm(svc, kq);
	return (0);
}

/*
 * A component session reply (or writable request) fired.  Flush any pending
 * request, dispatch the reply, and — once the session is complete — enlist and
 * confine the injected descriptor, then advance to the next component.
 */
void
svc_launch_channel_event(struct svc_runtime *svc, int kq)
{
	struct svc_launch *L = svc->launch;
	struct svc_manifest *m = &svc->manifest;
	const struct serviced_component *component;
	cap_rights_t component_rights;
	cap_ioctl_t component_ioctls[] = {
		MAC_CAPABILITY_SENDMSG, MAC_CAPABILITY_RECVMSG,
		MAC_CAPABILITY_GETINFO
	};
	int member_fd, error;

	if (L == NULL || L->session == NULL)
		return;
	if (channel_wants_write(L->session) > 0 &&
	    channel_flush(L->session) == -1) {
		svc_launch_abort(svc, errno != 0 ? errno : EIO, kq);
		return;
	}
	if (channel_dispatch(L->session) == -1) {
		svc_launch_abort(svc, errno != 0 ? errno : ECONNRESET, kq);
		return;
	}
	if (!L->call.done) {
		svc_launch_arm(svc, kq);
		return;
	}
	if (L->call.error != 0) {
		component = &m->components[L->comp_cursor];
		syslog(LOG_ERR, "svc_exec %s: component %s bootstrap: %s",
		    m->label, component->name, strerror(L->call.error));
		svc_launch_abort(svc, L->call.error, kq);
		return;
	}
	member_fd = L->call.member_fd;
	L->call.member_fd = -1;

	error = cap_xfer_limit(member_fd, CAP_XFER_ONCE) == -1 ? errno :
	    mac_cap_coalition_enlist(L->coalition_fd, member_fd);
	if (error != 0) {
		if (member_fd >= 0)
			close(member_fd);
		svc_launch_abort(svc, error, kq);
		return;
	}
	if (member_fd >= 0)
		close(member_fd);

	cap_rights_init(&component_rights, CAP_EVENT, CAP_FCNTL, CAP_FSTAT,
	    CAP_IOCTL);
	/*
	 * The consumer drives this channel from a non-blocking event loop
	 * (libchannel toggles O_NONBLOCK with F_GETFL/F_SETFL), so the injected
	 * descriptor must permit those two status-flag fcntls.  Everything else
	 * — descriptor duplication or ownership changes — stays denied.
	 */
	if (cap_rights_limit(L->session_cfd, &component_rights) == -1 ||
	    cap_fcntls_limit(L->session_cfd,
	    CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) == -1 ||
	    cap_ioctls_limit(L->session_cfd, component_ioctls,
	    nitems(component_ioctls)) == -1) {
		svc_launch_abort(svc, errno, kq);
		return;
	}

	/* Session established: keep the injected cfd, retire the session dup. */
	L->component_fds[L->ncomponents] = L->session_cfd;
	L->component_indices[L->ncomponents] = L->comp_cursor;
	L->ncomponents++;
	L->session_cfd = -1;	/* ownership moved into component_fds[] */
	svc_launch_drop_session(svc, kq);
	SERVICED_PROBE_COMPONENT_SESSION(m->label,
	    m->components[L->comp_cursor].name,
	    local_component_provider(&m->components[L->comp_cursor]), 0);
	L->comp_cursor++;
	svc_launch_advance(svc, kq);
}

static void
svc_launch_advance(struct svc_runtime *svc, int kq)
{
	struct svc_launch *L = svc->launch;

	if (L == NULL)
		return;
	if (L->comp_cursor < svc->manifest.ncomponents) {
		(void)svc_launch_component_start(svc, kq);
		return;
	}
	svc_launch_finish(svc, kq);
}

bool
svc_launch_owns_event(const struct svc_runtime *svc, uintptr_t ident)
{

	return (svc->launch != NULL && svc->launch->session_fd >= 0 &&
	    (int)ident == svc->launch->session_fd);
}

/* True if this EVFILT_TIMER ident belongs to an async launch deadline. */
bool
svc_launch_timer_owns(uintptr_t ident)
{

	return ((ident & SVC_LAUNCH_TIMER_BIT) != 0);
}

/*
 * A launch deadline fired.  Locate the owning unit by ident (compaction-safe)
 * and abort its launch.  The one-shot timer has already been consumed by the
 * kernel, so svc_launch_disarm_timer inside the abort only clears the tag.
 */
void
svc_launch_timer_fire(uintptr_t ident, int kq)
{
	unsigned i;

	for (i = 0; i < sd.nservices; i++) {
		struct svc_runtime *svc = &sd.services[i];

		if (svc->launch != NULL && svc->launch->timer_ident == ident) {
			syslog(LOG_ERR, "svc_exec %s: async launch timed out "
			    "after %d s", svc->manifest.label,
			    SVC_LAUNCH_TIMEOUT_SEC);
			svc_launch_abort(svc, ETIMEDOUT, kq);
			return;
		}
	}
}

void
svc_launch_cancel(struct svc_runtime *svc, int kq)
{

	if (svc->launch != NULL)
		svc_launch_abort(svc, ECANCELED, kq);
}
