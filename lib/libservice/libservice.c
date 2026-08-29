/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice — client library for services managed by serviced(8).
 *
 * Implements serviced discovery and lifecycle over libchannel.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <capability.h>
#include <channel.h>

#include <tzfsd.h>

#include "libservice.h"
#include "service_private.h"
#include "service_bootstrap.h"
#include "serviced_svc_proto.h"

_Static_assert(SERVICE_PROTECT_PTRACE == CP_SF_PTRACE, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_SIGNAL == CP_SF_SIGNAL, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_VISIBLE == CP_SF_VISIBLE, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_WAIT == CP_SF_WAIT, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_SIGKILL == CP_SF_SIGKILL, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_SIGCONT == CP_SF_SIGCONT, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_SCHED == CP_SF_SCHED, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_CORE == CP_SF_CORE, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_KTRACE == CP_SF_KTRACE, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOPRIVS == CP_SF_NOPRIVS, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOFORK == CP_SF_NOFORK, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOIPC == CP_SF_NOIPC, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOFDRECV == CP_SF_NOFDRECV, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOEXEC == CP_SF_NOEXEC, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOSOCK == CP_SF_NOSOCK, "capprotect ABI");

static int pair_fd = -1;
static struct channel *service_control_channel;
static int capprotect_fd = -1;
static bool service_initialized;
struct service_context {
	pid_t	owner;
	size_t	references;
	bool	entered;
	bool	ready;
};
struct service_provider {
	struct service_context	*context;
	pid_t			 owner;
	bool			 quiescing;
	bool			 quiesce_complete;
};
static struct service_context service_default_context;
static pthread_mutex_t service_init_lock = PTHREAD_MUTEX_INITIALIZER;
static bool service_init_attempted;
static int service_init_error;
static char service_label_value[SERVICE_BOOTSTRAP_LABEL_MAX];
static pthread_mutex_t service_state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t service_channel_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t service_atfork_once = PTHREAD_ONCE_INIT;
static int service_atfork_error;
static pthread_t service_dispatch_thread;
static bool service_dispatch_started;
static int service_dispatch_error;
static int service_supervisor_pipe[2] = { -1, -1 };
static void service_after_fork_child(void);
static int rpc(const void *, uint32_t, int *);
static int rpc_fds(const void *, uint32_t, int *, size_t);

struct service_rpc_waiter {
	pthread_cond_t	cond;
	int		status;
	int		fds[2];
	size_t		nfds;
	bool		done;
};

static void
service_atfork_prepare(void) __no_lock_analysis
{

	(void)pthread_mutex_lock(&service_init_lock);
	(void)pthread_mutex_lock(&service_channel_lock);
	(void)pthread_mutex_lock(&service_state_lock);
}

static void
service_atfork_parent(void) __no_lock_analysis
{

	(void)pthread_mutex_unlock(&service_state_lock);
	(void)pthread_mutex_unlock(&service_channel_lock);
	(void)pthread_mutex_unlock(&service_init_lock);
}

static void
service_atfork_child(void) __no_lock_analysis
{
	service_after_fork_child();
	(void)pthread_mutex_unlock(&service_state_lock);
	(void)pthread_mutex_unlock(&service_channel_lock);
	(void)pthread_mutex_unlock(&service_init_lock);
}

static void
service_atfork_init(void)
{

	service_atfork_error = pthread_atfork(service_atfork_prepare,
	    service_atfork_parent, service_atfork_child);
}

#define	SERVICE_CAPABILITY_MAX	SERVICE_BOOTSTRAP_CAPABILITY_MAX
struct service_capability_entry {
	char name[SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX];
	char type[SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX];
	int fd;
};
static struct service_capability_entry capability_fds[SERVICE_CAPABILITY_MAX];
static unsigned ncapability_fds;

/*
 * Isolation authorization is a descriptor lease: the kernel revokes it when
 * the last reference to the activation token closes.  Keep private,
 * close-on-exec duplicates after consuming the descriptors supplied by
 * serviced.  They intentionally remain open until process exit.
 */
#define	SERVICE_TOKEN_MAX	SERVICE_BOOTSTRAP_TOKEN_MAX
static int bootstrap_token_fds[SERVICE_TOKEN_MAX];
static unsigned nbootstrap_token_fds;
static int activated_token_fds[SERVICE_TOKEN_MAX];
static unsigned nactivated_token_fds;

static bool
service_capability_name_valid(const char *name)
{
	const unsigned char *p;
	size_t len;

	if (name == NULL)
		return (false);
	if (strcmp(name, "mount") == 0 || strcmp(name, "node") == 0 ||
	    strcmp(name, "accounting") == 0 || strcmp(name, "identity") == 0 ||
	    strcmp(name, "container") == 0 || strcmp(name, "bundle") == 0)
		return (true);
	if (strncmp(name, "storage:", 8) != 0)
		return (false);
	name += 8;
	len = strlen(name);
	if (len == 0 || len >= SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX - 8 ||
	    name[0] == '-' || name[len - 1] == '-')
		return (false);
	for (p = (const unsigned char *)name; *p != '\0'; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
		    *p == '-'))
			return (false);
	return (true);
}

static bool
service_capability_type_valid(const char *type)
{
	const unsigned char *p;
	size_t len;

	if (type == NULL || (len = strlen(type)) == 0 ||
	    len >= SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX)
		return (false);
	for (p = (const unsigned char *)type; *p != '\0'; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
		    *p == '_') )
			return (false);
	return (true);
}

/*
 * A socket-activation listener (Phase 4) is delivered under an arbitrary
 * logical name rather than one of the fixed capability-service names, so it has
 * its own conservative label charset: non-empty, bounded, [A-Za-z0-9._-].  This
 * mirrors the manifest-side name validation so a name that parsed also passes
 * here.
 */
static bool
service_socket_name_valid(const char *name)
{
	const unsigned char *p;
	size_t len;

	if (name == NULL)
		return (false);
	len = strlen(name);
	if (len == 0 || len >= SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX)
		return (false);
	for (p = (const unsigned char *)name; *p != '\0'; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' ||
		    *p == '-'))
			return (false);
	return (true);
}

/*
 * Validate a delivered socket-activation descriptor.  Unlike a capability
 * descriptor it carries no capability_info, so it is checked structurally: it
 * must be a socket whose type is SOCK_STREAM (and then listening, per
 * SO_ACCEPTCONN) or SOCK_DGRAM.  This is the socket analogue of
 * service_directory_descriptor_valid().
 */
static bool
service_socket_descriptor_valid(int fd)
{
	socklen_t len;
	int type, accepting;

	len = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == -1 ||
	    len != sizeof(type))
		return (false);
	if (type == SOCK_STREAM) {
		len = sizeof(accepting);
		if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting,
		    &len) == -1)
			return (false);
		return (accepting != 0);
	}
	return (type == SOCK_DGRAM);
}

static bool
service_directory_descriptor_valid(int fd)
{
	cap_rights_t actual, expected;
	uint32_t fcntls;
	struct stat sb;

	cap_rights_init(&expected, CAP_READ, CAP_WRITE, CAP_PREAD, CAP_PWRITE,
	    CAP_SEEK, CAP_FCNTL, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FTRUNCATE, CAP_FSYNC, CAP_CREATE, CAP_MKDIRAT, CAP_UNLINKAT,
	    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET);
	return (fstat(fd, &sb) == 0 && S_ISDIR(sb.st_mode) &&
	    cap_rights_get(fd, &actual) == 0 &&
	    cap_rights_contains(&actual, &expected) &&
	    cap_rights_contains(&expected, &actual) &&
	    cap_fcntls_get(fd, &fcntls) == 0 &&
	    fcntls == (CAP_FCNTL_GETFL | CAP_FCNTL_SETFL));
}

static bool
all_zero(const void *buffer, size_t length)
{
	const unsigned char *p;
	size_t i;

	p = buffer;
	for (i = 0; i < length; i++)
		if (p[i] != 0)
			return (false);
	return (true);
}

static bool
zero_padded_string(const char *value, size_t size, bool allow_empty)
{
	size_t length;

	length = strnlen(value, size);
	return (length < size && (allow_empty || length != 0) &&
	    all_zero(value + length + 1, size - length - 1));
}

static int
parse_service_bootstrap(void)
{
	struct service_bootstrap storage;
	const struct service_bootstrap *bootstrap = &storage;
	struct envfd_info envinfo;
	struct capability_info info;
	cap_rights_t actual_rights, expected_rights;
	struct stat sb;
	ssize_t received;
	unsigned i, j;
	int error, expected_fd;

	memset(&envinfo, 0, sizeof(envinfo));
	envinfo.ei_size = sizeof(envinfo);
	if (ioctl(SERVICE_BOOTSTRAP_FD, ENVFD_GETINFO, &envinfo) == -1)
		goto invalid_descriptor_close;
	if (strcmp(envinfo.ei_name, SERVICE_BOOTSTRAP_ENVFD_NAME) != 0 ||
	    envinfo.ei_flags != ENVFD_WRITE_ONCE ||
	    envinfo.ei_state != ENVFD_STATE_SEALED ||
	    envinfo.ei_value_size != sizeof(storage) ||
	    envinfo.ei_max_value_size != sizeof(storage) ||
	    !all_zero(envinfo.ei_reserved, sizeof(envinfo.ei_reserved))) {
		errno = EPROTO;
		goto fail_close;
	}
	if (fstat(SERVICE_BOOTSTRAP_FD, &sb) == -1)
		goto fail_close;
	if (sb.st_size != sizeof(*bootstrap)) {
		errno = EPROTO;
		goto fail_close;
	}
	received = read(SERVICE_BOOTSTRAP_FD, &storage, sizeof(storage));
	if (received != (ssize_t)sizeof(storage)) {
		if (received >= 0)
			errno = EPROTO;
		goto fail_close;
	}
	if (bootstrap->magic != SERVICE_BOOTSTRAP_MAGIC ||
	    bootstrap->version != SERVICE_BOOTSTRAP_VERSION ||
	    bootstrap->header_size != offsetof(struct service_bootstrap, label) ||
	    bootstrap->total_size != sizeof(*bootstrap) ||
	    (bootstrap->flags & ~SERVICE_BOOTSTRAP_FLAGS_MASK) != 0 ||
	    bootstrap->channel_fd != 3 ||
	    bootstrap->ntokens > SERVICE_TOKEN_MAX ||
	    bootstrap->ncapabilities > SERVICE_CAPABILITY_MAX ||
	    !all_zero(bootstrap->reserved, sizeof(bootstrap->reserved)) ||
	    !zero_padded_string(bootstrap->label, sizeof(bootstrap->label),
	    false) ||
	    (((bootstrap->flags & SERVICE_BOOTSTRAP_F_CAPPROTECT) != 0) !=
	    (bootstrap->capprotect_fd == 4)) ||
	    ((bootstrap->flags & SERVICE_BOOTSTRAP_F_CAPPROTECT) == 0 &&
	    bootstrap->capprotect_fd != -1)) {
		errno = EPROTO;
		goto fail_storage;
	}
	expected_fd = SERVICE_BOOTSTRAP_FD + 1;
	for (i = 0; i < bootstrap->ntokens; i++, expected_fd++)
		if (bootstrap->token_fds[i] != expected_fd) {
			errno = EPROTO;
			goto fail_storage;
		}
	if (!all_zero(&bootstrap->token_fds[bootstrap->ntokens],
	    sizeof(bootstrap->token_fds) -
	    bootstrap->ntokens * sizeof(bootstrap->token_fds[0]))) {
		errno = EPROTO;
		goto fail_storage;
	}
	for (i = 0; i < bootstrap->ncapabilities; i++, expected_fd++) {
		const char *cname = bootstrap->capabilities[i].name;
		const char *ctype = bootstrap->capabilities[i].type;

		if (bootstrap->capabilities[i].fd != expected_fd ||
		    bootstrap->capabilities[i].reserved != 0 ||
		    strnlen(cname, SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX) ==
		    SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX ||
		    !zero_padded_string(cname,
		    sizeof(bootstrap->capabilities[i].name), false) ||
		    !zero_padded_string(ctype,
		    sizeof(bootstrap->capabilities[i].type), false) ||
		    !service_capability_type_valid(ctype))
			goto protocol;
		/*
		 * A socket-activation listener carries an arbitrary logical
		 * name, not one of the fixed capability-service names, so
		 * validate it against the looser logical-name charset.
		 */
		if (strcmp(ctype, "socket") == 0) {
			if (!service_socket_name_valid(cname))
				goto protocol;
		} else if (!service_capability_name_valid(cname))
			goto protocol;
		for (j = 0; j < i; j++)
			if (strcmp(bootstrap->capabilities[i].name,
			    bootstrap->capabilities[j].name) == 0)
				goto protocol;
	}
	if (!all_zero(&bootstrap->capabilities[bootstrap->ncapabilities],
	    sizeof(bootstrap->capabilities) -
	    bootstrap->ncapabilities * sizeof(bootstrap->capabilities[0])))
		goto protocol;
	cap_rights_init(&expected_rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_get(SERVICE_BOOTSTRAP_FD, &actual_rights) == -1 ||
	    !cap_rights_contains(&actual_rights, &expected_rights) ||
	    !cap_rights_contains(&expected_rights, &actual_rights))
		goto invalid_descriptor;

	memset(&info, 0, sizeof(info));
	if (fcntl(bootstrap->channel_fd, F_GETFD) == -1 ||
	    capability_get_info(bootstrap->channel_fd, &info) == -1 ||
	    strcmp(info.name, "channel") != 0)
		goto invalid_descriptor;
	if ((bootstrap->flags & SERVICE_BOOTSTRAP_F_CAPPROTECT) != 0) {
		memset(&info, 0, sizeof(info));
		if (fcntl(bootstrap->capprotect_fd, F_GETFD) == -1 ||
		    capability_get_info(bootstrap->capprotect_fd, &info) == -1 ||
		    strcmp(info.name, "capprotect") != 0)
			goto invalid_descriptor;
	}
	for (i = 0; i < bootstrap->ntokens; i++) {
		memset(&info, 0, sizeof(info));
		if (fcntl(bootstrap->token_fds[i], F_GETFD) == -1 ||
		    capability_get_info(bootstrap->token_fds[i], &info) == -1 ||
		    (strcmp(info.name, "isolation") != 0 &&
		    strcmp(info.name, "system") != 0))
			goto invalid_descriptor;
	}
	for (i = 0; i < bootstrap->ncapabilities; i++) {
		if (fcntl(bootstrap->capabilities[i].fd, F_GETFD) == -1)
			goto invalid_descriptor;
		if (strcmp(bootstrap->capabilities[i].type, "directory") == 0) {
			if (!service_directory_descriptor_valid(
			    bootstrap->capabilities[i].fd))
				goto invalid_descriptor;
		} else if (strcmp(bootstrap->capabilities[i].type,
		    "socket") == 0) {
			if (!service_socket_descriptor_valid(
			    bootstrap->capabilities[i].fd))
				goto invalid_descriptor;
		} else if (strcmp(bootstrap->capabilities[i].type,
		    "zfshandle") == 0) {
			/*
			 * A storage zfshandle is a TrustedZFS handle, not a
			 * mac_capability token, so capability_get_info() does not
			 * describe it — its authority is the kernel rights carried
			 * on the handle itself.  The fd's liveness is already
			 * verified above; accept it (service_storage_open mounts it).
			 */
		} else {
			memset(&info, 0, sizeof(info));
			if (capability_get_info(bootstrap->capabilities[i].fd,
			    &info) == -1 ||
			    strncmp(info.name, bootstrap->capabilities[i].type,
			    sizeof(info.name)) != 0)
				goto invalid_descriptor;
		}
	}
	pair_fd = bootstrap->channel_fd;
	capprotect_fd = bootstrap->capprotect_fd;
	nbootstrap_token_fds = bootstrap->ntokens;
	memcpy(bootstrap_token_fds, bootstrap->token_fds,
	    nbootstrap_token_fds * sizeof(bootstrap_token_fds[0]));
	ncapability_fds = bootstrap->ncapabilities;
	for (i = 0; i < ncapability_fds; i++) {
		capability_fds[i].fd = bootstrap->capabilities[i].fd;
		strlcpy(capability_fds[i].name, bootstrap->capabilities[i].name,
		    sizeof(capability_fds[i].name));
		strlcpy(capability_fds[i].type, bootstrap->capabilities[i].type,
		    sizeof(capability_fds[i].type));
	}
	strlcpy(service_label_value, bootstrap->label,
	    sizeof(service_label_value));
	explicit_bzero(&storage, sizeof(storage));
	close(SERVICE_BOOTSTRAP_FD);
	return (0);

protocol:
	errno = EPROTO;
	goto fail_storage;
invalid_descriptor:
	errno = EINVAL;
fail_storage:
	error = errno;
	explicit_bzero(&storage, sizeof(storage));
	close(SERVICE_BOOTSTRAP_FD);
	errno = error;
	return (-1);
invalid_descriptor_close:
	errno = EINVAL;
fail_close:
	error = errno;
	close(SERVICE_BOOTSTRAP_FD);
	errno = error;
	return (-1);
}

#define	SERVICE_LISTENER_QUEUE_MAX	64

struct service_listener_connection {
	struct svc_new_client_msg msg;
	int	fd;
};

struct service_listener {
	struct service_listener	*next;
	struct service_provider	*provider;
	pthread_cond_t		 cond;
	pid_t			 owner;
	char			 name[SERVICED_NAME_MAX + 1];
	struct service_listener_connection
				 queue[SERVICE_LISTENER_QUEUE_MAX];
	unsigned		 head;
	unsigned		 count;
	unsigned		 waiters;
	unsigned		 activations;
	bool			 overflow;
	bool			 closing;
	bool			 claimed;
	bool			 active;
	bool			 activating;
	service_activation_handler activate;
	void			*activate_context;
	int			 event_pipe[2];
};

static struct service_listener *service_listeners;

struct service_activation_work {
	struct service_listener	*listener;
	char			 name[SERVICED_NAME_MAX + 1];
};

/*
 * Report activation completion as an ordinary correlated control request.
 * The worker, rather than the dispatcher, waits for serviced's reply so the
 * sole channel reader is never blocked and listener state cannot get ahead
 * of the naming registry.
 */
static int
service_name_result_rpc(const char *name, int status)
{
	struct svc_name_result_req request;

	if (status < 0)
		status = EIO;
	memset(&request, 0, sizeof(request));
	request.op = SVC_OP_NAME_RESULT;
	request.status = status;
	strlcpy(request.name, name, sizeof(request.name));
	return (rpc(&request, sizeof(request), NULL));
}

/*
 * The dispatcher cannot perform an RPC through the channel it is draining.
 * This path is restricted to rejecting malformed or unowned activation
 * events.  Its correlated acknowledgement is deliberately ignored.
 */
static void
service_discard_reply(struct channel_request *request,
    struct channel_message *message, int error, void *context)
{

	(void)error;
	(void)context;
	channel_message_free(message);
	channel_request_release(request);
}

/*
 * Called only from the libchannel event handler, which already owns the
 * control channel's dispatch context.
 */
static int
service_name_result_reject(const char *name, int status)
{
	struct svc_name_result_req request;
	struct channel_request *pending;

	if (status <= 0 || status > ELAST)
		status = EIO;
	memset(&request, 0, sizeof(request));
	request.op = SVC_OP_NAME_RESULT;
	request.status = status;
	strlcpy(request.name, name, sizeof(request.name));
	return (channel_send_request(service_control_channel,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&request, sizeof(request)),
	    service_discard_reply, NULL, &pending));
}

static void *
service_activation_worker(void *argument) __no_lock_analysis
{
	struct service_activation_work *work;
	struct service_listener *listener;
	bool published;
	int error, report_error, result;

	work = argument;
	listener = work->listener;
	errno = 0;
	result = listener->activate == NULL ? 0 :
	    listener->activate(work->name, listener->activate_context);
	if (result == -1)
		result = errno != 0 ? errno : EIO;
	else if (result < 0 || result > ELAST)
		result = EIO;

	error = pthread_mutex_lock(&service_state_lock);
	if (error == 0) {
		if (listener->closing)
			result = ECANCELED;
		(void)pthread_mutex_unlock(&service_state_lock);
	}
	report_error = service_name_result_rpc(work->name, result);
	published = result == 0 && report_error == 0;
	if (pthread_mutex_lock(&service_state_lock) == 0) {
		listener->active = published;
		listener->activating = false;
		listener->activations--;
		if (published)
			(void)pthread_cond_broadcast(&listener->cond);
		if (listener->closing && listener->activations == 0 &&
		    listener->waiters == 0)
			(void)pthread_cond_signal(&listener->cond);
		(void)pthread_mutex_unlock(&service_state_lock);
	}
	free(work);
	return (NULL);
}

static int
service_listener_activate_locked(struct service_listener *listener)
{
	struct service_activation_work *work;
	pthread_t thread;
	int error;

	/*
	 * serviced coalesces activation requests for a name.  An ACTIVATE event
	 * for an already-published listener therefore indicates stale or
	 * inconsistent supervisor state and must not rerun application setup.
	 */
	if (listener->active) {
		errno = EALREADY;
		return (-1);
	}
	if (listener->activating)
		return (0);
	work = calloc(1, sizeof(*work));
	if (work == NULL)
		return (-1);
	work->listener = listener;
	strlcpy(work->name, listener->name, sizeof(work->name));
	listener->activating = true;
	listener->activations++;
	error = pthread_create(&thread, NULL, service_activation_worker, work);
	if (error != 0) {
		listener->activating = false;
		listener->activations--;
		free(work);
		errno = error;
		return (-1);
	}
	(void)pthread_detach(thread);
	return (0);
}

static struct service_listener *
service_listener_find_locked(const char *name)
{
	struct service_listener *listener;

	for (listener = service_listeners; listener != NULL;
	    listener = listener->next)
		if (strcmp(listener->name, name) == 0)
			return (listener);
	return (NULL);
}

static void
service_listener_signal(struct service_listener *listener)
{
	const uint8_t byte = 1;

	(void)write(listener->event_pipe[1], &byte, sizeof(byte));
	(void)pthread_cond_signal(&listener->cond);
}

static void
service_after_fork_child(void)
{
	struct service_listener *listener;
	unsigned i;

	service_default_context.owner = -1;
	service_default_context.references = 0;

	/*
	 * The dispatcher thread and all waiters disappear across fork.  Every
	 * descriptor retained by libservice is process authority and is
	 * CAP_CLOFORK_LOCKED after the supervised exec, so its numeric slot is
	 * normally already absent in the child.  Clear the complete inventory
	 * anyway: otherwise a later open could reuse one of those numbers and a
	 * stale component entry could accidentally designate unrelated data.
	 *
	 * pdfork(2) does not run pthread_atfork(3) handlers.  Provider workers
	 * therefore call service_worker_drop_inherited_authority() explicitly after
	 * applying their protection policy; that function uses this same path.
	 */
	if (service_control_channel != NULL)
		channel_abandon(service_control_channel);
	else if (pair_fd >= 0)
		(void)close(pair_fd);
	service_control_channel = NULL;
	pair_fd = -1;
	if (service_supervisor_pipe[0] >= 0)
		(void)close(service_supervisor_pipe[0]);
	if (service_supervisor_pipe[1] >= 0)
		(void)close(service_supervisor_pipe[1]);
	service_supervisor_pipe[0] = -1;
	service_supervisor_pipe[1] = -1;
	service_dispatch_started = false;
	service_dispatch_error = ENOTCONN;
	for (listener = service_listeners; listener != NULL;
	    listener = listener->next) {
		for (i = 0; i < listener->count; i++)
			(void)close(listener->queue[(listener->head + i) %
			    SERVICE_LISTENER_QUEUE_MAX].fd);
		(void)close(listener->event_pipe[0]);
		(void)close(listener->event_pipe[1]);
		listener->owner = -1;
		listener->count = 0;
		listener->overflow = false;
	}
	service_listeners = NULL;
	/*
	 * Deliberately retain capprotect_fd here.  A provider forks its session
	 * workers with pdfork(2), whose child runs this handler before the
	 * worker body; the worker must still hold the capprotect descriptor to
	 * apply its own shield via service_worker_protect().  The descriptor is
	 * released explicitly in service_worker_drop_inherited_authority(),
	 * which the worker calls only after shielding.
	 */
	for (i = 0; i < ncapability_fds; i++) {
		if (capability_fds[i].fd >= 0)
			(void)close(capability_fds[i].fd);
		explicit_bzero(&capability_fds[i], sizeof(capability_fds[i]));
		capability_fds[i].fd = -1;
	}
	ncapability_fds = 0;
	for (i = 0; i < nbootstrap_token_fds; i++) {
		if (bootstrap_token_fds[i] >= 0)
			(void)close(bootstrap_token_fds[i]);
		bootstrap_token_fds[i] = -1;
	}
	nbootstrap_token_fds = 0;
	for (i = 0; i < nactivated_token_fds; i++) {
		if (activated_token_fds[i] >= 0)
			(void)close(activated_token_fds[i]);
		activated_token_fds[i] = -1;
	}
	nactivated_token_fds = 0;
	explicit_bzero(service_label_value, sizeof(service_label_value));
}

static void
service_control_reply(struct channel_request *request,
    struct channel_message *message, int error, void *argument)
    __no_lock_analysis
{
	struct service_rpc_waiter *waiter;
	const struct svc_reply *reply;

	waiter = argument;
	if (pthread_mutex_lock(&service_state_lock) != 0) {
		channel_message_free(message);
		channel_request_release(request);
		return;
	}
	waiter->status = error != 0 ? error : EPROTO;
	if (error == 0 && message != NULL &&
	    channel_message_length(message) == sizeof(*reply)) {
		reply = channel_message_data(message);
		if (reply->status >= 0 &&
		    channel_message_fd_count(message) ==
		    (reply->status == 0 ? waiter->nfds : 0)) {
			waiter->status = reply->status;
			if (reply->status == 0)
				for (size_t i = 0; i < waiter->nfds; i++)
					waiter->fds[i] =
					    channel_message_take_fd(message, i);
		}
	}
	waiter->done = true;
	(void)pthread_cond_signal(&waiter->cond);
	(void)pthread_mutex_unlock(&service_state_lock);
	channel_message_free(message);
	channel_request_release(request);
}

static void
service_control_event(struct channel *channel,
    struct channel_message *message, void *unused) __no_lock_analysis
{
	const struct svc_activate_name_msg *activate;
	const struct svc_new_client_msg *notify;
	const struct svc_quiesce_msg *quiesce;
	struct service_listener *listener;
	char reject_name[SERVICED_NAME_MAX + 1];
	unsigned tail;
	int error, fd, reject_error;

	(void)channel;
	(void)unused;
	fd = -1;
	reject_error = 0;
	reject_name[0] = '\0';
	if (pthread_mutex_lock(&service_state_lock) != 0) {
		channel_message_free(message);
		return;
	}
	if (channel_message_length(message) == sizeof(*activate) &&
	    channel_message_fd_count(message) == 0) {
		activate = channel_message_data(message);
		if (activate->op == SVC_OP_ACTIVATE_NAME &&
		    activate->flags == 0 &&
		    strnlen(activate->name, sizeof(activate->name)) <
		    sizeof(activate->name)) {
			listener = service_listener_find_locked(activate->name);
			if (listener == NULL || listener->closing) {
				strlcpy(reject_name, activate->name,
				    sizeof(reject_name));
				reject_error = ENOENT;
			} else if (service_listener_activate_locked(listener) ==
			    -1) {
				error = errno != 0 ? errno : EIO;
				strlcpy(reject_name, activate->name,
				    sizeof(reject_name));
				reject_error = error;
			}
		}
	} else if (channel_message_length(message) == sizeof(*notify) &&
	    channel_message_fd_count(message) == 1) {
		notify = channel_message_data(message);
		if (notify->op == SVC_OP_NEW_CLIENT && notify->flags == 0 &&
		    strnlen(notify->service_name,
		    sizeof(notify->service_name)) <
		    sizeof(notify->service_name) &&
		    strnlen(notify->client_label,
		    sizeof(notify->client_label)) <
		    sizeof(notify->client_label)) {
			listener = service_listener_find_locked(
			    notify->service_name);
			if (listener != NULL &&
			    listener->count < SERVICE_LISTENER_QUEUE_MAX) {
				fd = channel_message_take_fd(message, 0);
				tail = (listener->head + listener->count) %
				    SERVICE_LISTENER_QUEUE_MAX;
				listener->queue[tail].msg = *notify;
				listener->queue[tail].fd = fd;
				listener->count++;
				service_listener_signal(listener);
			} else if (listener != NULL) {
				listener->overflow = true;
				service_listener_signal(listener);
			}
		}
	} else if (channel_message_length(message) == sizeof(*quiesce) &&
	    channel_message_fd_count(message) == 0) {
		quiesce = channel_message_data(message);
		if (quiesce->op == SVC_OP_QUIESCE && quiesce->flags == 0 &&
		    quiesce->deadline_ms != 0 &&
		    quiesce->reason >= SVC_QUIESCE_REASON_STOP &&
		    quiesce->reason <= SVC_QUIESCE_REASON_RELOAD) {
			for (listener = service_listeners; listener != NULL;
			    listener = listener->next) {
				listener->provider->quiescing = true;
				listener->closing = true;
				(void)pthread_cond_broadcast(&listener->cond);
				service_listener_signal(listener);
			}
		}
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	if (reject_error != 0)
		(void)service_name_result_reject(reject_name, reject_error);
	channel_message_free(message);
}

static void *
service_dispatch(void *unused) __no_lock_analysis
{
	struct service_listener *listener;
	int error, ready, wants_write;

	(void)unused;
	error = 0;
	for (;;) {
		if (pthread_mutex_lock(&service_channel_lock) != 0) {
			error = EDEADLK;
			break;
		}
		wants_write = channel_wants_write(service_control_channel);
		(void)pthread_mutex_unlock(&service_channel_lock);
		if (wants_write == -1) {
			error = errno;
			break;
		}
		/*
		 * Block until the control channel is ready (kqueue-only; channels
		 * do not support poll(2)).  An indefinite wait means the thread is
		 * truly idle -- 0% CPU -- between events; outbound writes are
		 * flushed from this same thread's dispatch handlers, so no
		 * cross-thread wakeup is required to re-arm write interest.
		 */
		ready = channel_wait(service_control_channel, wants_write, -1);
		if (ready == -1) {
			error = errno;
			break;
		}
		if (ready == 0)
			continue;
		if (pthread_mutex_lock(&service_channel_lock) != 0) {
			error = EDEADLK;
			break;
		}
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(service_control_channel) == -1)
			error = errno;
		if (error == 0 && (ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(service_control_channel) == -1)
			error = errno;
		(void)pthread_mutex_unlock(&service_channel_lock);
		if (error != 0)
			break;
	}

	(void)pthread_mutex_lock(&service_state_lock);
	if (service_dispatch_error == 0)
		service_dispatch_error = error == 0 ? EIO : error;
	if (service_supervisor_pipe[1] >= 0) {
		const uint8_t byte = 1;

		(void)write(service_supervisor_pipe[1], &byte, sizeof(byte));
	}
	for (listener = service_listeners; listener != NULL;
	    listener = listener->next) {
		service_listener_signal(listener);
		(void)pthread_cond_broadcast(&listener->cond);
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	return (NULL);
}

static int
service_start_dispatch(void) __no_lock_analysis
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	int error;

	error = pthread_once(&service_atfork_once, service_atfork_init);
	if (error == 0)
		error = service_atfork_error;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	error = pthread_mutex_lock(&service_channel_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		(void)pthread_mutex_unlock(&service_channel_lock);
		errno = error;
		return (-1);
	}
	if (service_dispatch_started) {
		error = service_dispatch_error;
		(void)pthread_mutex_unlock(&service_state_lock);
		(void)pthread_mutex_unlock(&service_channel_lock);
		if (error != 0) {
			errno = error;
			return (-1);
		}
		return (0);
	}
	if (pair_fd < 0) {
		(void)pthread_mutex_unlock(&service_state_lock);
		(void)pthread_mutex_unlock(&service_channel_lock);
		errno = ENOTCONN;
		return (-1);
	}
	if (service_control_channel == NULL &&
	    channel_create(pair_fd, &options, &service_control_channel) == -1) {
		error = errno;
		(void)pthread_mutex_unlock(&service_state_lock);
		(void)pthread_mutex_unlock(&service_channel_lock);
		errno = error;
		return (-1);
	}
	pair_fd = channel_fd(service_control_channel);
	if (channel_set_event_handler(service_control_channel,
	    service_control_event, NULL) == -1) {
		error = errno;
		channel_destroy(service_control_channel);
		service_control_channel = NULL;
		pair_fd = -1;
		(void)pthread_mutex_unlock(&service_state_lock);
		(void)pthread_mutex_unlock(&service_channel_lock);
		errno = error;
		return (-1);
	}
	error = pthread_create(&service_dispatch_thread, NULL, service_dispatch,
	    NULL);
	if (error == 0) {
		service_dispatch_started = true;
		(void)pthread_detach(service_dispatch_thread);
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	(void)pthread_mutex_unlock(&service_channel_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

static int
rpc_fds(const void *req, uint32_t reqlen, int *reply_fds, size_t reply_nfds)
    __no_lock_analysis
{
	struct channel_request *request;
	struct service_rpc_waiter waiter;
	int cancel_state, error, result;

	if (service_start_dispatch() == -1)
		return (-1);
	if (reply_nfds > nitems(waiter.fds) ||
	    (reply_nfds != 0 && reply_fds == NULL))
		return (errno = EINVAL, -1);
	memset(&waiter, 0, sizeof(waiter));
	waiter.nfds = reply_nfds;
	for (size_t i = 0; i < nitems(waiter.fds); i++)
		waiter.fds[i] = -1;
	error = pthread_cond_init(&waiter.cond, NULL);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	if (error != 0) {
		(void)pthread_cond_destroy(&waiter.cond);
		errno = error;
		return (-1);
	}
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		(void)pthread_cond_destroy(&waiter.cond);
		(void)pthread_setcancelstate(cancel_state, NULL);
		errno = error;
		return (-1);
	}
	if (service_dispatch_error != 0) {
		error = service_dispatch_error;
		(void)pthread_mutex_unlock(&service_state_lock);
		(void)pthread_cond_destroy(&waiter.cond);
		(void)pthread_setcancelstate(cancel_state, NULL);
		errno = error;
		return (-1);
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	error = pthread_mutex_lock(&service_channel_lock);
	if (error != 0) {
		(void)pthread_cond_destroy(&waiter.cond);
		(void)pthread_setcancelstate(cancel_state, NULL);
		errno = error;
		return (-1);
	}
	if (channel_send_request(service_control_channel,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(req, reqlen),
	    service_control_reply, &waiter, &request) == -1) {
		error = errno;
		(void)pthread_mutex_unlock(&service_channel_lock);
		(void)pthread_cond_destroy(&waiter.cond);
		(void)pthread_setcancelstate(cancel_state, NULL);
		errno = error;
		return (-1);
	}
	(void)pthread_mutex_unlock(&service_channel_lock);
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		/*
		 * This process can no longer synchronize with its callback.
		 * Leave the request to be failed by channel teardown.
		 */
		(void)pthread_cond_destroy(&waiter.cond);
		(void)pthread_setcancelstate(cancel_state, NULL);
		errno = error;
		return (-1);
	}
	while (!waiter.done) {
		error = pthread_cond_wait(&waiter.cond, &service_state_lock);
		if (error != 0) {
			waiter.status = error;
			break;
		}
	}
	error = waiter.status;
	if (error == 0) {
		for (size_t i = 0; i < reply_nfds; i++)
			reply_fds[i] = waiter.fds[i];
	} else {
		for (size_t i = 0; i < nitems(waiter.fds); i++)
			if (waiter.fds[i] >= 0)
				(void)close(waiter.fds[i]);
	}
	result = error == 0 ? 0 : -1;
	(void)pthread_mutex_unlock(&service_state_lock);
	(void)pthread_cond_destroy(&waiter.cond);
	(void)pthread_setcancelstate(cancel_state, NULL);
	errno = error;
	return (result);
}

static int
rpc(const void *req, uint32_t reqlen, int *reply_fd)
{

	return (rpc_fds(req, reqlen, reply_fd, reply_fd != NULL ? 1 : 0));
}

static int
service_initialize_default(void)
{
	const char *bootstrap_fd;
	int error;

	if (service_initialized) {
		errno = EALREADY;
		return (-1);
	}
	pair_fd = capprotect_fd = -1;
	nbootstrap_token_fds = 0;
	ncapability_fds = 0;
	service_label_value[0] = '\0';
	bootstrap_fd = getenv(SERVICE_BOOTSTRAP_ENV);
	if (bootstrap_fd == NULL) {
		errno = EBADF;
		return (-1);
	}
	if (strcmp(bootstrap_fd, "5") != 0) {
		errno = EPROTO;
		return (-1);
	}
	if (parse_service_bootstrap() == -1)
		return (-1);
	if (pipe2(service_supervisor_pipe, O_CLOEXEC | O_NONBLOCK) == -1) {
		error = errno;
		service_worker_drop_inherited_authority();
		errno = error;
		return (-1);
	}
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_EVENT, CAP_FCNTL, CAP_FSTAT,
		    CAP_READ);
		if (cap_rights_limit(service_supervisor_pipe[0], &rights) == -1 ||
		    cap_fcntls_limit(service_supervisor_pipe[0], 0) == -1)
			goto supervisor_pipe_fail;
		cap_rights_init(&rights, CAP_FCNTL, CAP_FSTAT, CAP_WRITE);
		if (cap_rights_limit(service_supervisor_pipe[1], &rights) == -1 ||
		    cap_fcntls_limit(service_supervisor_pipe[1], 0) == -1 ||
		    cap_clofork_limit(service_supervisor_pipe[0],
		    CAP_CLOFORK_LOCKED) == -1 ||
		    cap_clofork_limit(service_supervisor_pipe[1],
		    CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(service_supervisor_pipe[0],
		    CAP_CLOEXEC_LOCKED) == -1 ||
		    cap_cloexec_limit(service_supervisor_pipe[1],
		    CAP_CLOEXEC_LOCKED) == -1)
			goto supervisor_pipe_fail;
	}
	/*
	 * Local-only consumers may never start the serviced dispatcher.  Install
	 * the child cleanup hook now so a fork before service_ready() cannot
	 * leave stale numeric entries for close-on-fork component descriptors.
	 */
	error = pthread_once(&service_atfork_once, service_atfork_init);
	if (error == 0)
		error = service_atfork_error;
	if (error != 0) {
		service_worker_drop_inherited_authority();
		errno = error;
		return (-1);
	}
	service_initialized = true;
	return (0);

supervisor_pipe_fail:
	error = errno;
	service_worker_drop_inherited_authority();
	errno = error;
	return (-1);
}

int
service_acquire(struct service_context **contextp) __no_lock_analysis
{
	int error;

	if (contextp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*contextp = NULL;
	error = pthread_mutex_lock(&service_init_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (service_init_attempted) {
		error = service_init_error;
		if (error == 0 && service_default_context.owner != getpid())
			error = ECHILD;
	} else {
		service_init_attempted = true;
		if (service_initialize_default() == -1)
			service_init_error = errno != 0 ? errno : EIO;
		else {
			service_default_context.owner = getpid();
			service_init_error = 0;
		}
		error = service_init_error;
	}
	if (error == 0) {
		service_default_context.references++;
		*contextp = &service_default_context;
	}
	(void)pthread_mutex_unlock(&service_init_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

void
service_release(struct service_context *context) __no_lock_analysis
{
	int saved_errno;

	if (context == NULL)
		return;
	saved_errno = errno;
	if (pthread_mutex_lock(&service_init_lock) == 0) {
		if (context == &service_default_context &&
		    context->owner == getpid() && context->references != 0)
			context->references--;
		(void)pthread_mutex_unlock(&service_init_lock);
	}
	errno = saved_errno;
}

static bool
service_provider_valid(const struct service_provider *provider)
{

	return (provider != NULL && provider->owner == getpid() &&
	    provider->context == &service_default_context &&
	    provider->context->owner == getpid());
}

int
service_provider_create(struct service_provider **providerp)
{
	struct service_provider *provider;

	if (providerp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*providerp = NULL;
	provider = calloc(1, sizeof(*provider));
	if (provider == NULL)
		return (-1);
	if (service_acquire(&provider->context) == -1) {
		free(provider);
		return (-1);
	}
	provider->owner = getpid();
	*providerp = provider;
	return (0);
}

void
service_provider_destroy(struct service_provider *provider) __no_lock_analysis
{
	struct service_listener *listener;
	int saved_errno;

	if (provider == NULL)
		return;
	saved_errno = errno;
	if (service_provider_valid(provider)) {
		for (;;) {
			if (pthread_mutex_lock(&service_state_lock) != 0)
				break;
			for (listener = service_listeners; listener != NULL;
			    listener = listener->next)
				if (listener->provider == provider)
					break;
			(void)pthread_mutex_unlock(&service_state_lock);
			if (listener == NULL)
				break;
			(void)service_listener_close(listener);
		}
		service_release(provider->context);
	}
	explicit_bzero(provider, sizeof(*provider));
	free(provider);
	errno = saved_errno;
}

int
service_provider_authorize_capabilities(struct service_provider *provider)
{

	if (!service_provider_valid(provider)) {
		errno = EINVAL;
		return (-1);
	}
	return (service_authorize_capabilities(provider->context));
}

int
service_provider_worker_channel(struct service_provider *provider,
    int *provider_fdp, int *worker_fdp)
{
	struct svc_req_hdr request;
	int endpoints[2], error;

	if (!service_provider_valid(provider) || provider_fdp == NULL ||
	    worker_fdp == NULL || provider_fdp == worker_fdp ||
	    provider->context->entered)
		return (errno = EINVAL, -1);
	*provider_fdp = *worker_fdp = -1;
	memset(&request, 0, sizeof(request));
	request.op = SVC_OP_WORKER_CHANNEL;
	if (rpc_fds(&request, sizeof(request), endpoints,
	    nitems(endpoints)) == -1)
		return (-1);
	if (cap_xfer_limit(endpoints[0], CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(endpoints[1], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(endpoints[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_clofork_limit(endpoints[1], CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(endpoints[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_cloexec_limit(endpoints[1], CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		close(endpoints[0]);
		close(endpoints[1]);
		return (errno = error, -1);
	}
	*provider_fdp = endpoints[0];
	*worker_fdp = endpoints[1];
	return (0);
}

int
service_provider_protect(struct service_provider *provider, uint32_t flags)
{

	if (!service_provider_valid(provider)) {
		errno = EINVAL;
		return (-1);
	}
	return (service_worker_protect(flags));
}

int
service_enter_capability_mode(struct service_context *context)
{
	unsigned int mode;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	if (service_start_dispatch() == -1 || cap_getmode(&mode) == -1)
		return (-1);
	if (mode == 0 && cap_enter() == -1)
		return (-1);
	context->entered = true;
	return (0);
}

int
service_ready(struct service_context *context)
{
	struct svc_req_hdr req;
	unsigned int mode;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	if (!context->entered) {
		errno = EPERM;
		return (-1);
	}
	if (cap_getmode(&mode) == -1)
		return (-1);
	if (mode == 0) {
		errno = EPERM;
		return (-1);
	}
	if (context->ready) {
		errno = EALREADY;
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_READY;
	if (rpc(&req, sizeof(req), NULL) == -1)
		return (-1);
	context->ready = true;
	return (0);
}

int
service_idle_shutdown(struct service_context *context, unsigned seconds)
{
	struct svc_idle_req req;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_IDLE;
	req.seconds = seconds;
	return (rpc(&req, sizeof(req), NULL));
}

int
service_provider_enter_capability_mode(struct service_provider *provider)
{

	if (!service_provider_valid(provider)) {
		errno = EINVAL;
		return (-1);
	}
	return (service_enter_capability_mode(provider->context));
}

int
service_provider_ready(struct service_provider *provider)
{

	if (!service_provider_valid(provider)) {
		errno = EINVAL;
		return (-1);
	}
	return (service_ready(provider->context));
}

int
service_provider_quiescing(struct service_provider *provider)
    __no_lock_analysis
{
	int error, result;

	if (!service_provider_valid(provider))
		return (errno = EINVAL, -1);
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0)
		return (errno = error, -1);
	result = provider->quiescing ? 1 : 0;
	(void)pthread_mutex_unlock(&service_state_lock);
	return (result);
}

int
service_provider_quiesce_complete(struct service_provider *provider,
    int status) __no_lock_analysis
{
	struct svc_quiesce_result_req request;
	int error;

	if (!service_provider_valid(provider) || status < 0)
		return (errno = EINVAL, -1);
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0)
		return (errno = error, -1);
	if (!provider->quiescing || provider->quiesce_complete) {
		(void)pthread_mutex_unlock(&service_state_lock);
		return (errno = provider->quiesce_complete ? EALREADY : EPERM, -1);
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	memset(&request, 0, sizeof(request));
	request.op = SVC_OP_QUIESCE_RESULT;
	request.status = status;
	if (rpc(&request, sizeof(request), NULL) == -1)
		return (-1);
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0)
		return (errno = error, -1);
	provider->quiesce_complete = true;
	(void)pthread_mutex_unlock(&service_state_lock);
	return (0);
}

int
service_private_control_fd(struct service_context *context) __no_lock_analysis
{
	int error, fd;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&service_channel_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	fd = service_control_channel != NULL ?
	    channel_fd(service_control_channel) : pair_fd;
	(void)pthread_mutex_unlock(&service_channel_lock);
	return (fd);
}

int
service_supervisor_fd(struct service_context *context) __no_lock_analysis
{
	const uint8_t byte = 1;
	int error;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	if (service_start_dispatch() == -1)
		return (-1);
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (service_supervisor_pipe[0] < 0)
		error = ENOTCONN;
	if (error != 0) {
		(void)pthread_mutex_unlock(&service_state_lock);
		errno = error;
		return (-1);
	}
	if (service_dispatch_error != 0)
		(void)write(service_supervisor_pipe[1], &byte, sizeof(byte));
	error = service_supervisor_pipe[0];
	(void)pthread_mutex_unlock(&service_state_lock);
	return (error);
}

int
service_supervisor_status(struct service_context *context) __no_lock_analysis
{
	int error;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	if (service_start_dispatch() == -1)
		return (-1);
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	error = service_dispatch_error;
	(void)pthread_mutex_unlock(&service_state_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

const char *
service_label(struct service_context *context)
{

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid()) {
		errno = EINVAL;
		return (NULL);
	}
	return (service_label_value);
}

int
service_capability_open(struct service_context *context, const char *name,
    const char *type, int *fdp)
{
	int fd;
	unsigned i;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid() || fdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*fdp = -1;
	if (name == NULL || !service_capability_name_valid(name) ||
	    type == NULL || !service_capability_type_valid(type)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < ncapability_fds; i++) {
		if (strcmp(capability_fds[i].name, name) != 0)
			continue;
		if (strcmp(capability_fds[i].type, type) != 0) {
			errno = EFTYPE;
			return (-1);
		}
		fd = fcntl(capability_fds[i].fd, F_DUPFD_CLOEXEC, 0);
		if (fd == -1)
			return (-1);
		*fdp = fd;
		return (0);
	}
	errno = ENOENT;
	return (-1);
}

/*
 * Mount a delivered storage capability and return its directory root.  serviced
 * delivers "storage:<name>" as a rights-limited "zfshandle"; a mount-rights
 * consumer calls this at startup to mount it lazily (serviced no longer mounts
 * on its behalf).  The handle is RETAINED for the process lifetime because the
 * anonymous mount is anchored by it — dropping it would force-unmount and every
 * access on the returned directory would fail.  The caller hardens the returned
 * directory's rights itself (an openat(2)ed file cannot exceed the directory).
 */
static int service_storage_anchor_fds[SERVICE_TOKEN_MAX];
static unsigned service_storage_nanchors;

int
service_storage_open(struct service_context *context, const char *name,
    int *dirfdp)
{
	char role[SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX];
	int handle = -1, dir, saved;

	if (dirfdp == NULL || name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*dirfdp = -1;
	if (snprintf(role, sizeof(role), "storage:%s", name) >=
	    (int)sizeof(role)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (service_capability_open(context, role, "zfshandle", &handle) == -1)
		return (-1);
	dir = tzfsd_mount_dir(handle, 0);
	if (dir == -1) {
		saved = errno != 0 ? errno : EIO;
		(void)close(handle);
		errno = saved;
		return (-1);
	}
	if (service_storage_nanchors < nitems(service_storage_anchor_fds))
		service_storage_anchor_fds[service_storage_nanchors++] = handle;
	/* else retain by leaving the descriptor open; it still anchors. */
	*dirfdp = dir;
	return (0);
}

/*
 * Return the manager-owned socket-activation listener delivered under the given
 * logical name (Phase 4), or -1 with errno set to ENOENT when the process was
 * not launched with such a listener.  The returned descriptor is owned by
 * libservice and stays valid for the life of the process; the caller accepts(2)
 * or receives on it but must not close it.  EINVAL is returned for a malformed
 * name.
 */
int
service_activation_socket(const char *name)
{
	unsigned i;

	if (name == NULL || !service_socket_name_valid(name)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < ncapability_fds; i++) {
		if (strcmp(capability_fds[i].type, "socket") != 0)
			continue;
		if (strcmp(capability_fds[i].name, name) == 0)
			return (capability_fds[i].fd);
	}
	errno = ENOENT;
	return (-1);
}

int
service_authorize_capabilities(struct service_context *context)
{
	struct capability_info info;
	struct fi_request req;
	struct fi_reply reply;
	struct sys_request sysreq;
	int fds[SERVICE_TOKEN_MAX], owned_fds[SERVICE_TOKEN_MAX];
	bool system_token[SERVICE_TOKEN_MAX];
	unsigned i, nfds;
	int error;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	nfds = nbootstrap_token_fds;
	if (nfds == 0)
		return (0);
	if (nactivated_token_fds + nfds > SERVICE_TOKEN_MAX) {
		errno = EOVERFLOW;
		return (-1);
	}
	for (i = 0; i < nfds; i++) {
		fds[i] = bootstrap_token_fds[i];
		memset(&info, 0, sizeof(info));
		if (fcntl(fds[i], F_GETFD) == -1 ||
		    capability_get_info(fds[i], &info) == -1 ||
		    (strcmp(info.name, "isolation") != 0 &&
		    strcmp(info.name, "system") != 0)) {
			errno = EINVAL;
			return (-1);
		}
		system_token[i] = strcmp(info.name, "system") == 0;
	}
	for (i = 0; i < nfds; i++) {
		owned_fds[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 0);
		if (owned_fds[i] == -1) {
			error = errno;
			while (i > 0)
				(void)close(owned_fds[--i]);
			errno = error;
			return (-1);
		}
	}

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_AUTHORIZE;
	memset(&sysreq, 0, sizeof(sysreq));
	sysreq.op = SYS_OP_AUTHORIZE;
	for (i = 0; i < nfds; i++) {
		size_t reply_length, reply_nfds;

		memset(&reply, 0, sizeof(reply));
		reply_length = system_token[i] ? 0 : sizeof(reply);
		reply_nfds = 0;
		if (capability_kernel_call(owned_fds[i],
		    system_token[i] ? (const void *)&sysreq : &req,
		    system_token[i] ? sizeof(sysreq) : sizeof(req), NULL, 0,
		    system_token[i] ? NULL : &reply, &reply_length, NULL,
		    &reply_nfds) == -1) {
			error = errno;
			goto consume;
		}
		if (reply_length !=
		    (system_token[i] ? 0 : sizeof(reply)) ||
		    reply_nfds != 0) {
			error = EPROTO;
			goto consume;
		}
	}
	error = 0;

consume:
	/*
	 * Activation handles are bootstrap authority, not runtime service
	 * descriptors.  Consume the complete validated list.  Successful private
	 * references are close-on-exec, so a later program image cannot inherit
	 * them and reactivate under another program nonce.
	 */
	for (i = 0; i < nfds; i++) {
		(void)close(fds[i]);
		bootstrap_token_fds[i] = -1;
		if (error == 0)
			activated_token_fds[nactivated_token_fds++] =
			    owned_fds[i];
		else
			(void)close(owned_fds[i]);
	}
	nbootstrap_token_fds = 0;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

int
service_worker_protect(uint32_t flags)
{
	struct cp_request req;
	size_t reply_length, reply_nfds;

	if (capprotect_fd < 0) {
		errno = ENOTSUP;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;

	reply_length = 0;
	reply_nfds = 0;
	if (capability_kernel_call(capprotect_fd, &req, sizeof(req), NULL, 0,
	    NULL, &reply_length, NULL, &reply_nfds) == -1)
		return (-1);
	return (0);
}

void
service_worker_drop_inherited_authority(void)
{
	/*
	 * Close the control channel and any client endpoints that the parent's
	 * dispatcher had queued, then release the capprotect descriptor.  The
	 * shared after-fork path intentionally leaves capprotect_fd open so the
	 * worker could shield itself first; now that it has, drop it too.
	 */
	service_after_fork_child();
	if (capprotect_fd >= 0)
		(void)close(capprotect_fd);
	capprotect_fd = -1;
}

static int
service_claim_name(const char *name, bool sendable)
{
	struct svc_name_claim_req req;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_NAME_CLAIM;
	req.flags = sendable ? SVC_NAME_CLAIM_SENDABLE : 0;
	strlcpy(req.name, name, sizeof(req.name));
	return (rpc(&req, sizeof(req), NULL));
}

static int
service_withdraw_name(const char *name)
{
	struct svc_name_withdraw_req req;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_NAME_WITHDRAW;
	strlcpy(req.name, name, sizeof(req.name));
	return (rpc(&req, sizeof(req), NULL));
}

int
service_connect(struct service_context *context, const char *name,
    int *session_fdp)
{
	struct svc_lookup_req req;
	int fd;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid() || name == NULL ||
	    session_fdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*session_fdp = -1;
	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_LOOKUP;
	strlcpy(req.name, name, sizeof(req.name));

	if (rpc(&req, sizeof(req), &fd) == -1)
		return (-1);
	if (fd < 0) {
		errno = EIO;
		return (-1);
	}
	*session_fdp = fd;
	return (0);
}

/*
 * Launch and connect a private helper declared in this unit's own bundle.
 * serviced resolves the name bundle-locally (never the global system.*
 * namespace) and returns a connected channel in *session_fdp.  ENOENT if the
 * bundle has no such helper unit.
 */
int
service_helper_open(struct service_context *context, const char *name,
    int *session_fdp)
{
	struct svc_helper_req req;
	int fd;

	if (context == NULL || context != &service_default_context ||
	    context->owner != getpid() || name == NULL || session_fdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*session_fdp = -1;
	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_HELPER_OPEN;
	strlcpy(req.name, name, sizeof(req.name));

	if (rpc(&req, sizeof(req), &fd) == -1)
		return (-1);
	if (fd < 0) {
		errno = EIO;
		return (-1);
	}
	*session_fdp = fd;
	return (0);
}

static int
service_expose_internal(struct service_provider *provider, const char *name,
    service_activation_handler activate, void *context, bool sendable,
    struct service_listener **listenerp)
    __no_lock_analysis
{
	struct service_listener *listener;
	int error;

	if (name == NULL || listenerp == NULL || name[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	*listenerp = NULL;
	listener = calloc(1, sizeof(*listener));
	if (listener == NULL)
		return (-1);
	listener->event_pipe[0] = listener->event_pipe[1] = -1;
	listener->owner = getpid();
	listener->provider = provider;
	listener->activate = activate;
	listener->activate_context = context;
	strlcpy(listener->name, name, sizeof(listener->name));
	error = pthread_cond_init(&listener->cond, NULL);
	if (error != 0)
		goto fail;
	if (pipe2(listener->event_pipe, O_CLOEXEC | O_NONBLOCK) == -1) {
		error = errno;
		(void)pthread_cond_destroy(&listener->cond);
		goto fail;
	}
	if (service_start_dispatch() == -1)
		goto fail_pipe;
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		errno = error;
		goto fail_pipe;
	}
	if (service_listener_find_locked(name) != NULL) {
		(void)pthread_mutex_unlock(&service_state_lock);
		errno = EEXIST;
		goto fail_pipe;
	}
	listener->next = service_listeners;
	service_listeners = listener;
	(void)pthread_mutex_unlock(&service_state_lock);
	if (service_claim_name(name, sendable) == -1)
		goto fail_registered;
	listener->claimed = true;
	*listenerp = listener;
	return (0);

fail_registered:
	error = errno;
	if (pthread_mutex_lock(&service_state_lock) != 0) {
		/*
		 * The process can no longer synchronize with its dispatcher.
		 * Retain the unreachable listener rather than freeing memory
		 * still linked from the dispatch path.
		 */
		errno = error;
		return (-1);
	}
	if (service_listeners == listener)
		service_listeners = listener->next;
	else {
		struct service_listener *previous;

		for (previous = service_listeners;
		    previous != NULL && previous->next != listener;
		    previous = previous->next)
			;
		if (previous != NULL)
			previous->next = listener->next;
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	errno = error;
	goto fail_pipe;

fail_pipe:
	error = errno;
	(void)close(listener->event_pipe[0]);
	(void)close(listener->event_pipe[1]);
	(void)pthread_cond_destroy(&listener->cond);
	errno = error;
fail:
	free(listener);
	errno = error;
	return (-1);
}

int
service_provider_expose_lazy(struct service_provider *provider,
    const char *name, service_activation_handler activate, void *context,
    struct service_listener **listenerp)
{
	struct service_listener *listener;

	if (!service_provider_valid(provider)) {
		errno = EINVAL;
		return (-1);
	}
	if (service_expose_internal(provider, name, activate, context, false,
	    &listener) == -1)
		return (-1);
	*listenerp = listener;
	return (0);
}

int
service_provider_expose(struct service_provider *provider, const char *name,
    struct service_listener **listenerp)
{

	return (service_provider_expose_lazy(provider, name, NULL, NULL,
	    listenerp));
}

int
service_provider_expose_sendable(struct service_provider *provider,
    const char *name, struct service_listener **listenerp)
{
	struct service_listener *listener;

	if (!service_provider_valid(provider)) {
		errno = EINVAL;
		return (-1);
	}
	if (service_expose_internal(provider, name, NULL, NULL, true,
	    &listener) == -1)
		return (-1);
	*listenerp = listener;
	return (0);
}

int
service_listener_close(struct service_listener *listener) __no_lock_analysis
{
	struct service_listener *previous;
	unsigned i;
	int error, withdraw_error;
	bool was_claimed;

	if (listener == NULL || listener->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	withdraw_error = 0;
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	previous = NULL;
	for (struct service_listener *current = service_listeners;
	    current != NULL && current != listener; current = current->next)
		previous = current;
	if ((previous == NULL && service_listeners != listener) ||
	    (previous != NULL && previous->next != listener)) {
		(void)pthread_mutex_unlock(&service_state_lock);
		errno = EINVAL;
		return (-1);
	}
	listener->closing = true;
	(void)pthread_cond_broadcast(&listener->cond);
	while (listener->waiters != 0 || listener->activations != 0)
		(void)pthread_cond_wait(&listener->cond, &service_state_lock);
	was_claimed = listener->claimed;
	previous = NULL;
	for (struct service_listener *current = service_listeners;
	    current != NULL && current != listener; current = current->next)
		previous = current;
	if (previous == NULL)
		service_listeners = listener->next;
	else
		previous->next = listener->next;
	for (i = 0; i < listener->count; i++)
		(void)close(listener->queue[(listener->head + i) %
		    SERVICE_LISTENER_QUEUE_MAX].fd);
	listener->count = 0;
	(void)pthread_mutex_unlock(&service_state_lock);
	if (was_claimed && service_withdraw_name(listener->name) == -1)
		withdraw_error = errno;
	(void)close(listener->event_pipe[0]);
	(void)close(listener->event_pipe[1]);
	(void)pthread_cond_destroy(&listener->cond);
	explicit_bzero(listener, sizeof(*listener));
	free(listener);
	if (withdraw_error != 0) {
		errno = withdraw_error;
		return (-1);
	}
	return (0);
}

int
service_listener_fd(const struct service_listener *listener)
{

	if (listener == NULL || listener->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	return (listener->event_pipe[0]);
}

static int
service_listener_accept_fd(struct service_listener *listener,
    struct service_identity *identity) __no_lock_analysis
{
	struct service_listener_connection connection;
	uint8_t byte;
	int cancel_state, error;
	bool registered_waiter;

	if (listener == NULL || listener->owner != getpid() ||
	    (identity != NULL && identity->size != sizeof(*identity))) {
		errno = EINVAL;
		return (-1);
	}
	if (service_start_dispatch() == -1)
		return (-1);
	error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		(void)pthread_setcancelstate(cancel_state, NULL);
		errno = error;
		return (-1);
	}
	registered_waiter = false;
	if (listener->closing)
		error = ECANCELED;
	else {
		listener->waiters++;
		registered_waiter = true;
	}
	while (error == 0 && !listener->closing &&
	    (!listener->active || listener->count == 0) &&
	    !listener->overflow &&
	    service_dispatch_error == 0) {
		error = pthread_cond_wait(&listener->cond, &service_state_lock);
		if (error != 0)
			break;
	}
	if (error == 0 && listener->closing)
		error = ECANCELED;
	if (error == 0 && listener->overflow) {
		listener->overflow = false;
		(void)read(listener->event_pipe[0], &byte, sizeof(byte));
		error = ENOBUFS;
	}
	if (error == 0 && listener->count == 0)
		error = service_dispatch_error != 0 ? service_dispatch_error : EIO;
	if (registered_waiter) {
		listener->waiters--;
		if (listener->closing && listener->waiters == 0)
			(void)pthread_cond_signal(&listener->cond);
	}
	if (error != 0) {
		(void)pthread_mutex_unlock(&service_state_lock);
		(void)pthread_setcancelstate(cancel_state, NULL);
		errno = error;
		return (-1);
	}
	connection = listener->queue[listener->head];
	listener->head = (listener->head + 1) % SERVICE_LISTENER_QUEUE_MAX;
	listener->count--;
	(void)pthread_mutex_unlock(&service_state_lock);
	(void)pthread_setcancelstate(cancel_state, NULL);
	(void)read(listener->event_pipe[0], &byte, sizeof(byte));
	if (identity != NULL) {
		memset(identity, 0, sizeof(*identity));
		identity->size = sizeof(*identity);
		strlcpy(identity->service_name, connection.msg.service_name,
		    sizeof(identity->service_name));
		strlcpy(identity->client_label, connection.msg.client_label,
		    sizeof(identity->client_label));
	}
	return (connection.fd);
}

int
service_listener_accept(struct service_listener *listener,
    struct service_identity *identity, int *session_fdp)
{
	int fd;

	if (session_fdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*session_fdp = -1;
	fd = service_listener_accept_fd(listener, identity);
	if (fd == -1)
		return (-1);
	*session_fdp = fd;
	return (0);
}
