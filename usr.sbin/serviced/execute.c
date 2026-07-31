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
 * Unlike oracled, serviced does not hold /dev/mac_capability directly.
 * Channel and coalition creation use the delegated mac_capability fd
 * (mac_cap_direct.c).  Token minting goes through the oracle
 * channel (oracle_client.c).
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

#include "serviced.h"
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
#define	SVC_TOKEN_BASE	6	/* after the typed bootstrap descriptor */
#define	SVC_MAX_TOKENS	(SERVICED_MAX_CAP_PATHS + SERVICED_MAX_CAP_FILES + \
				    SERVICED_MAX_CAP_NET + SERVICED_MAX_CAP_JAIL + \
				    SERVICED_MAX_CAP_VSOCK + 1)
#define	SVC_INTERNAL_ENV	10	/* PATH, bootstrap, selectors, USER/HOME, NULL */
#define	SVC_MAX_ENV	(SVC_INTERNAL_ENV + SERVICED_MAX_ENVIRONMENT)
#define	SVC_COMPONENT_BOOTSTRAP_TIMEOUT_MS	2000
#define	SVC_STORAGE_ROOT	"/var/db/serviced/storage"

_Static_assert(SVC_CHANNEL_FD < SERVICE_BOOTSTRAP_FD,
    "service channel overlaps bootstrap descriptor");
_Static_assert(SVC_CAPPROTECT_FD < SERVICE_BOOTSTRAP_FD,
    "capprotect overlaps bootstrap descriptor");
_Static_assert(SVC_TOKEN_BASE == SERVICE_BOOTSTRAP_FD + 1,
    "token layout must follow bootstrap descriptor");
_Static_assert(SVC_MAX_TOKENS <= SERVICE_BOOTSTRAP_TOKEN_MAX,
    "bootstrap token table is too small");
_Static_assert(SERVICED_MAX_CAP_SERVICES <=
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
	return (NULL);
}

static const char *
local_component_interface(const struct serviced_component *component)
{

	if (strcmp(component->name, "filesystem") == 0)
		return ("org.5bsd.filesystem");
	if (strcmp(component->name, "network") == 0)
		return ("org.5bsd.network");
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
bootstrap_component(int fd, const struct svc_manifest *m,
    const struct serviced_component *component, const int *fds, size_t nfds,
    int *member_fd)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct component_call_state state;
	struct channel *channel;
	struct pollfd descriptor;
	struct timespec deadline, now;
	struct component_session_bootstrap message;
	const char *interface;
	int64_t milliseconds;
	int owned, result, timeout, wants_write;

	if (member_fd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*member_fd = -1;
	interface = local_component_interface(component);
	if (interface == NULL) {
		errno = EINVAL;
		return (-1);
	}
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
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned == -1)
		return (-1);
	if (channel_create(owned, &options, &channel) == -1) {
		result = errno;
		close(owned);
		errno = result;
		return (-1);
	}
	memset(&state, 0, sizeof(state));
	state.instance_id = message.instance_id;
	state.member_fd = -1;
	if (channel_send_request(channel,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &message,
		.length = sizeof(message),
		.fds = fds,
		.nfds = nfds
	    }, component_reply, &state, &state.request) == -1)
		goto fail;
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		goto fail;
	deadline.tv_sec += SVC_COMPONENT_BOOTSTRAP_TIMEOUT_MS / 1000;
	deadline.tv_nsec +=
	    (SVC_COMPONENT_BOOTSTRAP_TIMEOUT_MS % 1000) * 1000000;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}
	while (!state.done) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			goto fail;
		milliseconds = (deadline.tv_sec - now.tv_sec) * 1000 +
		    (deadline.tv_nsec - now.tv_nsec + 999999) / 1000000;
		if (milliseconds <= 0) {
			errno = ETIMEDOUT;
			goto fail;
		}
		timeout = milliseconds > SVC_COMPONENT_BOOTSTRAP_TIMEOUT_MS ?
		    SVC_COMPONENT_BOOTSTRAP_TIMEOUT_MS : (int)milliseconds;
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			goto fail;
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		do {
			result = poll(&descriptor, 1, timeout);
		} while (result == -1 && errno == EINTR);
		if (result == 0) {
			errno = ETIMEDOUT;
			goto fail;
		}
		if (result == -1 ||
		    ((descriptor.revents & POLLOUT) != 0 &&
		    channel_flush(channel) == -1) ||
		    ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1))
			goto fail;
	}
	if (state.error != 0) {
		errno = state.error;
		goto fail;
	}
	*member_fd = state.member_fd;
	channel_destroy(channel);
	return (0);

fail:
	result = errno;
	if (state.request != NULL) {
		(void)channel_request_cancel(state.request);
		channel_request_release(state.request);
	}
	if (state.member_fd >= 0)
		close(state.member_fd);
	channel_destroy(channel);
	errno = result;
	return (-1);
}

static bool
safe_storage_name(const char *name)
{

	return (name != NULL && name[0] != '\0' &&
	    strcmp(name, ".") != 0 && strcmp(name, "..") != 0 &&
	    strchr(name, '/') == NULL);
}

static int
open_component_storage(const char *label, const char *component)
{
	struct passwd *account;
	int base, service_dir, result, error;

	if (!safe_storage_name(label) || !safe_storage_name(component)) {
		errno = EINVAL;
		return (-1);
	}
	account = getpwnam(SERVICED_DEFAULT_USER);
	if (account == NULL) {
		errno = ENOENT;
		return (-1);
	}
	base = open(SVC_STORAGE_ROOT,
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (base == -1)
		return (-1);
	if (mkdirat(base, label, 0700) == -1 && errno != EEXIST)
		goto fail_base;
	service_dir = openat(base, label,
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (service_dir == -1)
		goto fail_base;
	if (fchown(service_dir, account->pw_uid, account->pw_gid) == -1 ||
	    fchmod(service_dir, 0700) == -1 ||
	    (mkdirat(service_dir, component, 0700) == -1 && errno != EEXIST)) {
		error = errno;
		close(service_dir);
		close(base);
		errno = error;
		return (-1);
	}
	result = openat(service_dir, component,
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	error = errno;
	if (result != -1 &&
	    (fchown(result, account->pw_uid, account->pw_gid) == -1 ||
	    fchmod(result, 0700) == -1)) {
		error = errno;
		close(result);
		result = -1;
	}
	close(service_dir);
	close(base);
	errno = error;
	return (result);

fail_base:
	error = errno;
	close(base);
	errno = error;
	return (-1);
}

static int
open_consumer_bundle(const struct svc_manifest *manifest)
{
	char path[PATH_MAX];
	char *marker, *next;

	if (strlcpy(path, manifest->program, sizeof(path)) >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	marker = NULL;
	for (next = strstr(path, "/bin/"); next != NULL;
	    next = strstr(next + 1, "/bin/"))
		marker = next;
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
prepare_component_resources(const struct svc_manifest *manifest,
    const struct serviced_component *component, int fds[static
    COMPONENT_SESSION_RESOURCE_MAX], size_t *nfdsp)
{
	cap_rights_t rights;
	size_t i;
	int error;

	*nfdsp = 0;
	if (strcmp(component->name, "filesystem") != 0)
		return (0);
	fds[0] = open_component_storage(manifest->label, component->name);
	if (fds[0] == -1)
		return (-1);
	fds[1] = open_consumer_bundle(manifest);
	if (fds[1] == -1) {
		error = errno != 0 ? errno : EIO;
		close(fds[0]);
		errno = error;
		return (-1);
	}
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_PREAD, CAP_PWRITE,
	    CAP_SEEK, CAP_FCNTL, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FTRUNCATE, CAP_FSYNC,
	    CAP_CREATE, CAP_MKDIRAT, CAP_UNLINKAT, CAP_RENAMEAT_SOURCE,
	    CAP_RENAMEAT_TARGET);
	if (cap_rights_limit(fds[0], &rights) == -1)
		goto fail;
	if (cap_fcntls_limit(fds[0], 0) == -1)
		goto fail;
	cap_rights_init(&rights, CAP_READ, CAP_PREAD, CAP_SEEK, CAP_FCNTL,
	    CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT);
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

/* Build the immutable descriptor bootstrap consumed by libservice. */
static int
create_service_bootstrap(const struct svc_manifest *m, unsigned ntokens,
    unsigned nservices, bool have_capprotect)
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
		strlcpy(bootstrap.capabilities[i].name, m->cap_services[i],
		    sizeof(bootstrap.capabilities[i].name));
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
	char bootstrap_env[32];
	char network_component_env[32];
	char filesystem_component_env[32];
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

int
svc_exec(struct svc_runtime *svc, int kq)
{
	struct svc_manifest *m;
	struct kevent kev[3];
	struct passwd *pw;
	struct group *gr;
	struct timespec exec_start;
	char homedir[PATH_MAX];
	struct svc_manifest minted_manifest;
	int oracle_end, child_end, coalition_fd, capprotect_fd, bootstrap_fd;
	int token_fds[SVC_MAX_TOKENS];
	int service_fds[SERVICED_MAX_CAP_SERVICES];
	int component_fds[SERVICED_MAX_COMPONENTS];
	unsigned component_indices[SERVICED_MAX_COMPONENTS];
	unsigned ntokens, nservices, ncomponents;
	uid_t uid;
	gid_t gid;
	gid_t groups[NGROUPS_MAX + 1];
	int ngroups;
	bool have_creds;
	pid_t pid;
	int pd_fd;
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
	if (m->ncap_paths > SERVICED_MAX_CAP_PATHS ||
	    m->ncap_files > SERVICED_MAX_CAP_FILES ||
	    m->ncap_net > SERVICED_MAX_CAP_NET ||
	    m->ncap_jail > SERVICED_MAX_CAP_JAIL ||
	    m->ncap_vsock > SERVICED_MAX_CAP_VSOCK ||
	    m->ncap_services > SERVICED_MAX_CAP_SERVICES ||
	    m->ncomponents > SERVICED_MAX_COMPONENTS) {
		/* Keep count validation next to the launch barrier. */
		syslog(LOG_ERR, "svc_exec %s: invalid capability counts",
		    m->label);
		return (-1);
	}
	expected_tokens = m->ncap_paths + m->ncap_files + m->ncap_net +
	    m->ncap_jail + m->ncap_vsock + (m->cap_system != 0 ? 1u : 0u);
	if (expected_tokens > SVC_MAX_TOKENS) {
		syslog(LOG_ERR, "svc_exec %s: too many capability tokens: %u",
		    m->label, expected_tokens);
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

	bootstrap_fd = -1;
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

	/* Create channel via oracle. */
	if (mac_cap_create_channel(
	    &oracle_end, &child_end) == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create channel",
		    m->label);
		SERVICED_PROBE_CAP_CHANNEL(m->label, -1);
		return (-1);
	}
	if (cap_xfer_limit(oracle_end, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(oracle_end, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(oracle_end, CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_xfer_limit(child_end, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "svc_exec %s: channel confinement: %m",
		    m->label);
		close(oracle_end);
		close(child_end);
		return (-1);
	}
	SERVICED_PROBE_CAP_CHANNEL(m->label, 0);

	/* Create coalition via oracle. */
	coalition_fd = mac_cap_create_coalition();
	if (coalition_fd == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create coalition",
		    m->label);
		SERVICED_PROBE_CAP_COALITION(m->label, -1);
		close(oracle_end);
		close(child_end);
		return (-1);
	}
	if (cap_xfer_limit(coalition_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(coalition_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(coalition_fd, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_ERR, "svc_exec %s: coalition confinement: %m",
		    m->label);
		close(oracle_end);
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
		close(oracle_end);
		close(child_end);
		close(coalition_fd);
		close(capprotect_fd);
		return (-1);
	}

	/*
	 * Mint tokens via oracle.  The oracle auto-claims resources
	 * not already in its manifest — one trip per token.
	 *
	 * Each mint is a synchronous RPC with SERVICED_RPC_TIMEOUT_MS
	 * timeout.  Track total elapsed time and abort if the mint
	 * phase exceeds SVC_MINT_DEADLINE_MS to avoid blocking the
	 * event loop for an unbounded duration.
	 */
#define	SVC_MINT_DEADLINE_MS	2000	/* max total mint phase */
	{
	struct timespec mint_start, mint_now;
	uint64_t elapsed_ms;

	clock_gettime(CLOCK_MONOTONIC, &mint_start);
	ntokens = 0;
	nservices = 0;
	ncomponents = 0;

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
		int tfd = oracle_mint_path(sd.oracle_channel_fd,
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
		int tfd = oracle_mint_file(sd.oracle_channel_fd,
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
		int tfd = oracle_mint_net(sd.oracle_channel_fd, &m->cap_net[i]);

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
		int tfd = oracle_mint_jail(sd.oracle_channel_fd,
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
		int tfd = oracle_mint_vsock(sd.oracle_channel_fd,
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
	if (m->cap_system != 0) {
		int tfd = oracle_mint_system(sd.oracle_channel_fd,
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
		int sfd = oracle_delegate_service(sd.oracle_channel_fd,
		    m->cap_services[i]);

		if (sfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to delegate "
			    "capability service %s", m->label,
			    m->cap_services[i]);
			SERVICED_PROBE_CAP_SERVICE(m->label,
			    m->cap_services[i], -1);
			goto fail_tokens;
		}
		service_fds[nservices++] = sfd;
		SERVICED_PROBE_CAP_SERVICE(m->label, m->cap_services[i], 0);
		MINT_CHECK_DEADLINE();
	}

#undef MINT_CHECK_DEADLINE
	}

	/*
	 * This is the final all-or-nothing barrier before jail creation and
	 * pdfork().  The child receives only the complete manifest token set;
	 * any missing token takes the fail_tokens cleanup path instead.
	 */
	if (ntokens != expected_tokens || nservices != m->ncap_services) {
		syslog(LOG_ERR, "svc_exec %s: incomplete capability set "
		    "(%u/%u tokens, %u/%u services)", m->label, ntokens,
		    expected_tokens, nservices, m->ncap_services);
		goto fail_tokens;
	}

	/*
	 * Construct each declared local authority replacement before exec.
	 * Component kinds map to fixed internal factories; provider selection
	 * and per-manifest protocol options are deliberately not part of the
	 * application model.
	 */
	for (i = 0; i < m->ncomponents; i++) {
		const struct serviced_component *component;
		const char *provider;
		cap_rights_t component_rights;
		cap_ioctl_t component_ioctls[] = {
			MAC_CAPABILITY_SENDMSG,
			MAC_CAPABILITY_RECVMSG,
			MAC_CAPABILITY_GETINFO
		};
		int resource_fds[COMPONENT_SESSION_RESOURCE_MAX];
		size_t nresources, resource_index;
		int error, cfd, member_fd;

		component = &m->components[i];
		provider = local_component_provider(component);
		if (provider == NULL) {
			syslog(LOG_ERR, "svc_exec %s: invalid component %s",
			    m->label, component->name);
			goto fail_tokens;
		}
		SERVICED_PROBE_COMPONENT_RESOLVE(m->label, component->name,
		    provider);
		cfd = naming_lookup(provider, svc, &error);
		if (cfd == -1) {
			syslog(LOG_ERR,
			    "svc_exec %s: component %s provider %s: %s",
			    m->label, component->name, provider,
			    strerror(error));
			SERVICED_PROBE_COMPONENT_SESSION(m->label,
			    component->name, provider, error);
			serviced_audit(AUE_SERVICED_COMPONENT, getuid(), error,
			    "svc=%s component=%s provider=%s phase=resolve",
			    m->label, component->name, provider);
			goto fail_tokens;
		}
		nresources = 0;
		error = 0;
		member_fd = -1;
		if (prepare_component_resources(m, component, resource_fds,
		    &nresources) == -1)
			error = errno != 0 ? errno : EIO;
		else if (cap_xfer_limit(cfd, CAP_XFER_NONE) == -1 ||
		    cap_cloexec_limit(cfd, CAP_CLOEXEC_ONCE) == -1)
			error = errno != 0 ? errno : EIO;
		else if (bootstrap_component(cfd, m, component,
		    resource_fds, nresources, &member_fd) == -1)
			error = errno != 0 ? errno : EIO;
		for (resource_index = 0; resource_index < nresources;
		    resource_index++)
			close(resource_fds[resource_index]);
		if (error != 0) {
			close(cfd);
			syslog(LOG_ERR,
			    "svc_exec %s: component %s bootstrap: %s",
			    m->label, component->name, strerror(error));
			SERVICED_PROBE_COMPONENT_SESSION(m->label,
			    component->name, provider, error);
			serviced_audit(AUE_SERVICED_COMPONENT, getuid(), error,
			    "svc=%s component=%s provider=%s phase=bootstrap",
			    m->label, component->name, provider);
			goto fail_tokens;
		}
		error = cap_xfer_limit(member_fd, CAP_XFER_ONCE) == -1 ?
		    errno : mac_cap_coalition_enlist(coalition_fd, member_fd);
		if (error == -1)
			error = errno;
		if (error != 0) {
			close(member_fd);
			close(cfd);
			syslog(LOG_ERR,
			    "svc_exec %s: component %s coalition enlist: %s",
			    m->label, component->name, strerror(error));
			SERVICED_PROBE_COMPONENT_SESSION(m->label,
			    component->name, provider, error);
			serviced_audit(AUE_SERVICED_COMPONENT, getuid(), error,
			    "svc=%s component=%s provider=%s "
			    "phase=coalition-enlist",
			    m->label, component->name, provider);
			goto fail_tokens;
		}
		close(member_fd);
		cap_rights_init(&component_rights, CAP_EVENT, CAP_FCNTL,
		    CAP_FSTAT, CAP_IOCTL);
		if (cap_rights_limit(cfd, &component_rights) == -1 ||
		    cap_fcntls_limit(cfd, 0) == -1 ||
		    cap_ioctls_limit(cfd, component_ioctls,
		    nitems(component_ioctls)) == -1) {
			error = errno;
			close(cfd);
			syslog(LOG_ERR,
			    "svc_exec %s: component %s channel confinement: %s",
			    m->label, component->name, strerror(error));
			SERVICED_PROBE_COMPONENT_SESSION(m->label,
			    component->name, provider, error);
			serviced_audit(AUE_SERVICED_COMPONENT, getuid(), error,
			    "svc=%s component=%s provider=%s "
			    "phase=channel-confinement",
			    m->label, component->name, provider);
			goto fail_tokens;
		}
		component_fds[ncomponents] = cfd;
		component_indices[ncomponents] = i;
		ncomponents++;
		SERVICED_PROBE_COMPONENT_SESSION(m->label, component->name,
		    provider, 0);
		SERVICED_PROBE_COMPONENT_INJECT(m->label, component->name, cfd);
		serviced_audit(AUE_SERVICED_COMPONENT, getuid(), 0,
		    "svc=%s component=%s provider=%s phase=delegate",
		    m->label, component->name, provider);
	}

	if (ntokens > 0)
		syslog(LOG_DEBUG, "svc_exec %s: minted %u tokens",
		    m->label, ntokens);

	/* Create jail via oracle if manifest specifies one. */
	if (m->has_jail) {
		svc->jail_fd = oracle_create_jail(sd.oracle_channel_fd,
		    m->jail_name, m->jail_path,
		    m->jail_hostname, m->jail_ip4_addr);
		if (svc->jail_fd == -1) {
			saved_errno = errno;
			syslog(LOG_ERR, "svc_exec %s: failed to create jail %s: %m",
			    m->label, m->jail_name);
			SERVICED_PROBE_CAP_MINT(m->label, "jail-create", -1);
			serviced_audit(AUE_SERVICED_CAP_MINT, getuid(),
			    saved_errno,
			    "svc=%s jail=%s phase=ensure-persistent",
			    m->label, m->jail_name);
			errno = saved_errno;
			goto fail_tokens;
		}
		syslog(LOG_INFO, "svc_exec %s: created jail %s jd=%d",
		    m->label, m->jail_name, svc->jail_fd);
		SERVICED_PROBE_CAP_MINT(m->label, "jail-create", 0);
		serviced_audit(AUE_SERVICED_CAP_MINT, getuid(), 0,
		    "svc=%s jail=%s phase=ensure-persistent",
		    m->label, m->jail_name);
	}

	if (prepare_child_descriptor(child_end) == -1 ||
	    (capprotect_fd >= 0 &&
	    prepare_child_descriptor(capprotect_fd) == -1))
		goto fail_child_confinement;
	for (i = 0; i < ntokens; i++)
		if (prepare_child_descriptor(token_fds[i]) == -1)
			goto fail_child_confinement;
	for (i = 0; i < nservices; i++)
		if (prepare_child_descriptor(service_fds[i]) == -1)
			goto fail_child_confinement;
	for (i = 0; i < ncomponents; i++)
		if (prepare_child_descriptor(component_fds[i]) == -1)
			goto fail_child_confinement;

	bootstrap_fd = create_service_bootstrap(m, ntokens, nservices,
	    capprotect_fd >= 0);
	if (bootstrap_fd == -1) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: bootstrap descriptor: %m",
		    m->label);
		SERVICED_PROBE_BOOTSTRAP_CREATE(m->label, ntokens,
		    nservices + ncomponents, saved_errno);
		SERVICED_PROBE_SVC_EXEC_FAIL(m->label, saved_errno);
		serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), saved_errno,
		    "svc=%s phase=bootstrap tokens=%u descriptors=%u",
		    m->label, ntokens, nservices + ncomponents);
		errno = saved_errno;
		goto fail_tokens;
	}
	SERVICED_PROBE_BOOTSTRAP_CREATE(m->label, ntokens,
	    nservices + ncomponents, 0);

	/* Fork via pdfork for process descriptor. */
	pid = pdfork(&pd_fd, PD_CLOEXEC);
	if (pid == -1) {
		syslog(LOG_ERR, "svc_exec %s: pdfork: %m", m->label);
		goto fail_tokens;
	}

	if (pid == 0) {
		/* Child — does not return. */
		child_exec(m, child_end, capprotect_fd, bootstrap_fd, token_fds,
		    ntokens, service_fds, nservices, component_fds,
		    component_indices, ncomponents, svc->jail_fd,
		    uid, gid, have_creds,
		    homedir[0] != '\0' ? homedir : NULL,
		    groups, ngroups);
		/* NOTREACHED */
	}

	/* Parent. */
	close(child_end);
	close(bootstrap_fd);
	if (capprotect_fd >= 0)
		close(capprotect_fd);
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);
	for (i = 0; i < nservices; i++)
		close(service_fds[i]);
	for (i = 0; i < ncomponents; i++)
		close(component_fds[i]);
	if (svc->jail_fd >= 0 &&
	    (cap_xfer_limit(svc->jail_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(svc->jail_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(svc->jail_fd, CAP_CLOEXEC_LOCKED) == -1)) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: jail fd confinement: %m",
		    m->label);
		goto fail_postfork;
	}

	/* Enlist in coalition and set as leader. */
	if (mac_cap_coalition_enlist(coalition_fd, pd_fd) != 0) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: coalition enlist: %m",
		    m->label);
		goto fail_postfork;
	}
	if (mac_cap_coalition_set_leader(coalition_fd, pd_fd) != 0) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: coalition set_leader: %m",
		    m->label);
		goto fail_postfork;
	}

	/* Freeze all supervisor-owned authority before another service fork. */
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_PDKILL, CAP_PDGETPID, CAP_EVENT);
		if (cap_rights_limit(pd_fd, &rights) == -1 ||
		    cap_xfer_limit(pd_fd, CAP_XFER_NONE) == -1 ||
		    cap_clofork_limit(pd_fd, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(pd_fd, CAP_CLOEXEC_LOCKED) == -1 ||
		    cap_clofork_limit(oracle_end, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(oracle_end, CAP_CLOEXEC_LOCKED) == -1 ||
		    cap_clofork_limit(coalition_fd, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(coalition_fd, CAP_CLOEXEC_LOCKED) == -1) {
			saved_errno = errno;
			syslog(LOG_ERR,
			    "svc_exec %s: supervisor fd confinement: %m",
			    m->label);
			goto fail_postfork;
		}
	}

	/* Store state. */
	svc->pid = pid;
	svc->launch_id = ++svc_launch_sequence;
	if (svc->launch_id == 0)
		svc->launch_id = ++svc_launch_sequence;
	svc->pd_fd = pd_fd;
	if (svc_channel_attach(svc, oracle_end) == -1) {
		saved_errno = errno;
		oracle_end = -1;
		syslog(LOG_ERR, "svc_exec %s: control channel: %m",
		    m->label);
		goto fail_postfork;
	}
	oracle_end = -1;
	svc->coalition_fd = coalition_fd;
	svc->state = SVC_STATE_STARTING;
	svc->protocol_ready = false;
	memset(svc->name_state, SVC_NAME_UNCLAIMED,
	    sizeof(svc->name_state));
	clock_gettime(CLOCK_MONOTONIC, &svc->last_start);

	/* Register on kqueue. */
	EV_SET(&kev[0], pd_fd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_EXIT | NOTE_EXEC | NOTE_CAPMODE, 0, svc);
	EV_SET(&kev[1], svc->channel_fd, EVFILT_READ, EV_ADD, 0, 0, svc);
	EV_SET(&kev[2], coalition_fd, EVFILT_READ, EV_ADD, 0, 0, svc);

	if (kevent(kq, kev, 3, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "svc_exec %s: kevent register: %m",
		    m->label);
		pdkill(pd_fd, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
		oracle_release_manifest(sd.oracle_channel_fd,
		    &minted_manifest);
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
		return (-1);
	}
	svc_channel_sync_events(svc, kq);

	syslog(LOG_INFO, "service %s: started pid %jd",
	    m->label, (intmax_t)pid);
	SERVICED_PROBE_SVC_START(m->label, pid);

	/*
	 * Audit the launch before a fast child can be promoted to RUNNING.
	 * Executing under changed credentials is a security-relevant
	 * transition, so record the resulting principal in the trusted trail.
	 */
	serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), 0,
	    "svc=%s pid=%jd uid=%u gid=%u creds_changed=%d",
	    m->label, (intmax_t)pid, (unsigned)uid, (unsigned)gid,
	    have_creds ? 1 : 0);

	/*
	 * Close the registration race with a fast child that reaches
	 * cap_enter() before EVFILT_PROCDESC is installed.  Registration
	 * precedes the query: a later transition produces NOTE_CAPMODE,
	 * while an earlier transition is observed here.  The supervisor's
	 * STARTING-state guard makes the event/query overlap idempotent.
	 */
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
	default: {
		int query_error;

		query_error = errno;
		syslog(LOG_ERR, "svc_exec %s: initial pdincapmode: %s",
		    m->label, strerror(query_error));
		SERVICED_PROBE_SVC_EXEC_FAIL(m->label, query_error);
		serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), query_error,
		    "svc=%s phase=capmode-registration-query", m->label);
		break;
	}
	}

	{
		struct timespec exec_end;
		uint64_t dur __unused;

		clock_gettime(CLOCK_MONOTONIC, &exec_end);
		dur = (uint64_t)(exec_end.tv_sec - exec_start.tv_sec) *
		    1000000000ULL +
		    (uint64_t)(exec_end.tv_nsec - exec_start.tv_nsec);
		SERVICED_PROBE_SVC_EXEC_DONE(m->label, dur, ntokens);
	}
	return (0);

fail_child_confinement:
	saved_errno = errno;
	syslog(LOG_ERR, "svc_exec %s: child descriptor confinement: %m",
	    m->label);
	SERVICED_PROBE_SVC_EXEC_FAIL(m->label, saved_errno);
	serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), saved_errno,
	    "svc=%s phase=child-descriptor-confinement tokens=%u "
	    "services=%u components=%u", m->label, ntokens, nservices,
	    ncomponents);
	errno = saved_errno;
	goto fail_tokens;

fail_postfork:
	/* child_end and token_fds already closed by parent path above.
	 * Report the errno captured at the failure site: the intervening
	 * syslog() and the cleanup syscalls below can clobber errno. */
	SERVICED_PROBE_SVC_EXEC_FAIL(m->label, saved_errno);
	pdkill(pd_fd, SIGKILL);
	waitpid(pid, NULL, WNOHANG);
	oracle_release_manifest(sd.oracle_channel_fd, &minted_manifest);
	close(pd_fd);
	close(oracle_end);
	close(coalition_fd);
	if (svc->jail_fd >= 0) {
		jail_remove_jd(svc->jail_fd);
		close(svc->jail_fd);
		svc->jail_fd = -1;
	}
	return (-1);

fail_tokens:
	/*
	 * Capability minting is the core privilege primitive; record mint
	 * failures in the audit trail.  errno is unreliable here (the mint
	 * call sites log via syslog before jumping), so report the failure
	 * generically and rely on the text token for detail.
	 */
	serviced_audit(AUE_SERVICED_CAP_MINT, getuid(), EIO,
	    "svc=%s capability mint failed after %u tokens", m->label, ntokens);
	oracle_release_manifest(sd.oracle_channel_fd, &minted_manifest);
	close(oracle_end);
	close(child_end);
	close(coalition_fd);
	if (capprotect_fd >= 0)
		close(capprotect_fd);
	if (bootstrap_fd >= 0)
		close(bootstrap_fd);
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);
	for (i = 0; i < nservices; i++)
		close(service_fds[i]);
	for (i = 0; i < ncomponents; i++)
		close(component_fds[i]);
	if (svc->jail_fd >= 0) {
		jail_remove_jd(svc->jail_fd);
		close(svc->jail_fd);
		svc->jail_fd = -1;
	}
	return (-1);
}
