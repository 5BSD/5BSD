/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice — client library for services managed by serviced(8).
 *
 * Wraps common mac_capability lifecycle and transport ioctls into a clean API.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libservice.h"
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
static int capprotect_fd = -1;
static uint64_t next_token = 1;
static bool service_initialized;
static char service_label_value[SERVICE_BOOTSTRAP_LABEL_MAX];

#define	SERVICE_CAPABILITY_MAX	SERVICE_BOOTSTRAP_CAPABILITY_MAX
struct service_capability_entry {
	char name[16];
	int fd;
};
static struct service_capability_entry capability_fds[SERVICE_CAPABILITY_MAX];
static unsigned ncapability_fds;

#define	SERVICE_COMPONENT_MAX	SERVICE_BOOTSTRAP_COMPONENT_MAX
struct service_component_entry {
	char name[64];
	int fd;
};
static struct service_component_entry component_fds[SERVICE_COMPONENT_MAX];
static unsigned ncomponent_fds;

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

	return (strcmp(name, "mount") == 0 || strcmp(name, "node") == 0 ||
	    strcmp(name, "accounting") == 0 || strcmp(name, "identity") == 0);
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
	struct mac_capability_info_args info;
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
	    bootstrap->ncomponents > SERVICE_COMPONENT_MAX ||
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
		if (bootstrap->capabilities[i].fd != expected_fd ||
		    bootstrap->capabilities[i].reserved != 0 ||
		    strnlen(bootstrap->capabilities[i].name,
		    SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX) ==
		    SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX ||
		    !zero_padded_string(bootstrap->capabilities[i].name,
		    sizeof(bootstrap->capabilities[i].name), false) ||
		    !service_capability_name_valid(
		    bootstrap->capabilities[i].name))
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
	for (i = 0; i < bootstrap->ncomponents; i++, expected_fd++) {
		if (bootstrap->components[i].fd != expected_fd ||
		    bootstrap->components[i].reserved != 0 ||
		    !zero_padded_string(bootstrap->components[i].name,
		    sizeof(bootstrap->components[i].name), false))
			goto protocol;
		for (j = 0; j < i; j++)
			if (strcmp(bootstrap->components[i].name,
			    bootstrap->components[j].name) == 0)
				goto protocol;
	}
	if (!all_zero(&bootstrap->components[bootstrap->ncomponents],
	    sizeof(bootstrap->components) -
	    bootstrap->ncomponents * sizeof(bootstrap->components[0])))
		goto protocol;

	cap_rights_init(&expected_rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_get(SERVICE_BOOTSTRAP_FD, &actual_rights) == -1 ||
	    !cap_rights_contains(&actual_rights, &expected_rights) ||
	    !cap_rights_contains(&expected_rights, &actual_rights))
		goto invalid_descriptor;

	memset(&info, 0, sizeof(info));
	if (fcntl(bootstrap->channel_fd, F_GETFD) == -1 ||
	    ioctl(bootstrap->channel_fd, MAC_CAPABILITY_GETINFO, &info) == -1 ||
	    strcmp(info.name, "channel") != 0)
		goto invalid_descriptor;
	if ((bootstrap->flags & SERVICE_BOOTSTRAP_F_CAPPROTECT) != 0) {
		memset(&info, 0, sizeof(info));
		if (fcntl(bootstrap->capprotect_fd, F_GETFD) == -1 ||
		    ioctl(bootstrap->capprotect_fd, MAC_CAPABILITY_GETINFO,
		    &info) == -1 || strcmp(info.name, "capprotect") != 0)
			goto invalid_descriptor;
	}
	for (i = 0; i < bootstrap->ntokens; i++) {
		memset(&info, 0, sizeof(info));
		if (fcntl(bootstrap->token_fds[i], F_GETFD) == -1 ||
		    ioctl(bootstrap->token_fds[i], MAC_CAPABILITY_GETINFO,
		    &info) == -1 ||
		    (strcmp(info.name, "isolation") != 0 &&
		    strcmp(info.name, "system") != 0))
			goto invalid_descriptor;
	}
	for (i = 0; i < bootstrap->ncapabilities; i++) {
		memset(&info, 0, sizeof(info));
		if (fcntl(bootstrap->capabilities[i].fd, F_GETFD) == -1 ||
		    ioctl(bootstrap->capabilities[i].fd,
		    MAC_CAPABILITY_GETINFO, &info) == -1 ||
		    strncmp(info.name, bootstrap->capabilities[i].name,
		    sizeof(info.name)) != 0)
			goto invalid_descriptor;
	}
	for (i = 0; i < bootstrap->ncomponents; i++) {
		memset(&info, 0, sizeof(info));
		if (fcntl(bootstrap->components[i].fd, F_GETFD) == -1 ||
		    ioctl(bootstrap->components[i].fd,
		    MAC_CAPABILITY_GETINFO, &info) == -1 ||
		    strcmp(info.name, "channel") != 0)
			goto invalid_descriptor;
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
	}
	ncomponent_fds = bootstrap->ncomponents;
	for (i = 0; i < ncomponent_fds; i++) {
		component_fds[i].fd = bootstrap->components[i].fd;
		strlcpy(component_fds[i].name, bootstrap->components[i].name,
		    sizeof(component_fds[i].name));
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

/*
 * Pending notification queue.  Notifications (SVC_OP_NEW_CLIENT)
 * can arrive while we're waiting for an RPC reply.  We queue them
 * here and deliver them from service_accept().
 */
#define	PENDING_MAX	256

struct pending_notify {
	struct svc_new_client_msg msg;
	int	fd;
};

static struct pending_notify pending[PENDING_MAX];
static int npending;

static void
queue_notification(const struct svc_new_client_msg *msg, int fd)
{

	if (npending < PENDING_MAX) {
		pending[npending].msg = *msg;
		pending[npending].fd = fd;
		npending++;
	} else {
		/* Queue full — drop the notification. */
		if (fd >= 0)
			close(fd);
	}
}

/*
 * Send a request and wait for the reply.
 * Notifications that arrive before the reply are queued.
 */
static int
rpc(const void *req, uint32_t reqlen, int *reply_fd)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	union {
		struct svc_reply rpl;
		struct svc_new_client_msg notify;
	} buf;
	uint64_t token;
	int fd;

	if (pair_fd < 0) {
		errno = ENOTCONN;
		return (-1);
	}

	token = next_token++;

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.reply_token = token;

	if (ioctl(pair_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1)
		return (-1);

	for (;;) {
		uint32_t op;

		fd = -1;
		memset(&buf, 0, sizeof(buf));
		memset(&ra, 0, sizeof(ra));
		ra.payload = &buf;
		ra.payload_len = sizeof(buf);
		ra.fds = &fd;
		ra.nfds = 1;

		if (ioctl(pair_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}

		/* Check if this is our reply (matching token). */
		if (ra.reply_token == token) {
			/* Reject a reply too short to hold a status word,
			 * rather than reading uninitialized memory. */
			if (ra.payload_len != sizeof(buf.rpl)) {
				if (fd >= 0)
					close(fd);
				errno = EPROTO;
				return (-1);
			}
			if (ra.nfds != (uint32_t)(buf.rpl.status == 0 &&
			    reply_fd != NULL ? 1 : 0)) {
				if (fd >= 0)
					close(fd);
				errno = EPROTO;
				return (-1);
			}
			if (reply_fd != NULL)
				*reply_fd = fd;
			else if (fd >= 0)
				close(fd);

			if (buf.rpl.status != 0) {
				errno = buf.rpl.status;
				return (-1);
			}
			return (0);
		}

		/*
		 * Not our reply — check if it's a notification.
		 * Queue it for service_accept().
		 */
		if (ra.payload_len == sizeof(buf.notify) && ra.nfds == 1 &&
		    buf.notify.flags == 0 &&
		    strnlen(buf.notify.client_label,
		    sizeof(buf.notify.client_label)) <
		    sizeof(buf.notify.client_label)) {
			memcpy(&op, &buf, sizeof(op));
			if (op == SVC_OP_NEW_CLIENT) {
				queue_notification(&buf.notify, fd);
				continue;
			}
		}

		/* Unknown message — discard. */
		if (fd >= 0)
			close(fd);
	}
}

int
service_init(void)
{
	const char *bootstrap_fd;

	if (service_initialized) {
		errno = EALREADY;
		return (-1);
	}
	pair_fd = capprotect_fd = -1;
	nbootstrap_token_fds = 0;
	ncapability_fds = ncomponent_fds = 0;
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
	service_initialized = true;
	return (0);
}

int
service_channel_fd(void)
{

	return (pair_fd);
}

const char *
service_label(void)
{

	if (!service_initialized) {
		errno = ENOTCONN;
		return (NULL);
	}
	return (service_label_value);
}

int
service_capability_fd(const char *name)
{
	unsigned i;

	if (pair_fd < 0) {
		errno = ENOTCONN;
		return (-1);
	}
	if (name == NULL || !service_capability_name_valid(name)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < ncapability_fds; i++) {
		if (strcmp(capability_fds[i].name, name) == 0)
			return (capability_fds[i].fd);
	}
	errno = ENOENT;
	return (-1);
}

int
service_component_fd(const char *name)
{
	unsigned i;

	if (pair_fd < 0) {
		errno = ENOTCONN;
		return (-1);
	}
	if (name == NULL || name[0] == '\0' ||
	    strlen(name) >= sizeof(component_fds[0].name)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < ncomponent_fds; i++) {
		if (strcmp(component_fds[i].name, name) == 0)
			return (component_fds[i].fd);
	}
	errno = ENOENT;
	return (-1);
}

int
service_component_recv_bootstrap(int fd,
    struct component_session_bootstrap *bootstrap, char *options,
    size_t options_size)
{
	struct {
		struct component_session_bootstrap header;
		char options[COMPONENT_SESSION_OPTIONS_MAX];
	} message;
	size_t nfds, options_length;
	ssize_t received;

	if (bootstrap == NULL || options == NULL || options_size == 0) {
		errno = EINVAL;
		return (-1);
	}
	nfds = 0;
	received = service_recv_fds(fd, &message, sizeof(message), NULL, &nfds);
	if (received == -1)
		return (-1);
	options_length = message.header.options_length;
	if ((size_t)received < sizeof(message.header) ||
	    message.header.magic != COMPONENT_SESSION_MAGIC ||
	    message.header.version != COMPONENT_SESSION_VERSION ||
	    message.header.header_size != sizeof(message.header) ||
	    message.header.length != (uint32_t)received ||
	    message.header.scope < COMPONENT_SESSION_SCOPE_PRIVATE ||
	    message.header.scope > COMPONENT_SESSION_SCOPE_SYSTEM ||
	    (message.header.flags & ~COMPONENT_SESSION_F_MASK) != 0 ||
	    message.header.name[0] == '\0' ||
	    memchr(message.header.name, '\0',
	    sizeof(message.header.name)) == NULL ||
	    message.header.interface[0] == '\0' ||
	    memchr(message.header.interface, '\0',
	    sizeof(message.header.interface)) == NULL ||
	    message.header.interface_version[0] == '\0' ||
	    memchr(message.header.interface_version, '\0',
	    sizeof(message.header.interface_version)) == NULL ||
	    message.header.client_label[0] == '\0' ||
	    memchr(message.header.client_label, '\0',
	    sizeof(message.header.client_label)) == NULL ||
	    options_length == 0 ||
	    options_length > COMPONENT_SESSION_OPTIONS_MAX ||
	    sizeof(message.header) + options_length != (size_t)received ||
	    options_length > options_size ||
	    message.options[options_length - 1] != '\0' ||
	    memchr(message.options, '\0', options_length - 1) != NULL) {
		errno = EPROTO;
		return (-1);
	}
	*bootstrap = message.header;
	memcpy(options, message.options, options_length);
	return (0);
}

int
service_component_send_reply(int fd, uint64_t instance_id, int status,
    uint32_t member_type, int member_fd)
{
	struct component_session_reply reply;
	const int *fds;
	size_t nfds;

	if (status < 0 ||
	    (status == 0 && member_fd < 0) ||
	    (status == 0 &&
	    member_type != COMPONENT_SESSION_MEMBER_PROCDESC &&
	    member_type != COMPONENT_SESSION_MEMBER_COALITION) ||
	    (status != 0 && member_fd >= 0)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&reply, 0, sizeof(reply));
	reply.magic = COMPONENT_SESSION_MAGIC;
	reply.version = COMPONENT_SESSION_VERSION;
	reply.header_size = sizeof(reply);
	reply.length = sizeof(reply);
	reply.status = status;
	reply.member_type = status == 0 ? member_type : 0;
	reply.instance_id = instance_id;
	fds = status == 0 ? &member_fd : NULL;
	nfds = status == 0 ? 1 : 0;
	return (service_send_fds(fd, &reply, sizeof(reply), fds, nfds));
}

int
service_authorize_capabilities(void)
{
	struct mac_capability_call_args call;
	struct mac_capability_info_args info;
	struct fi_request req;
	struct fi_reply reply;
	struct sys_request sysreq;
	int fds[SERVICE_TOKEN_MAX], owned_fds[SERVICE_TOKEN_MAX];
	bool system_token[SERVICE_TOKEN_MAX];
	unsigned i, nfds;
	int error;

	if (!service_initialized) {
		errno = ENOTCONN;
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
		    ioctl(fds[i], MAC_CAPABILITY_GETINFO, &info) == -1 ||
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
		memset(&reply, 0, sizeof(reply));
		memset(&call, 0, sizeof(call));
		call.req = system_token[i] ? (const void *)&sysreq : &req;
		call.req_len = system_token[i] ? sizeof(sysreq) : sizeof(req);
		if (!system_token[i]) {
			call.reply = &reply;
			call.reply_len = sizeof(reply);
		}
		if (ioctl(owned_fds[i], MAC_CAPABILITY_CALL, &call) == -1) {
			error = errno;
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
service_protect(uint32_t flags)
{
	struct mac_capability_call_args call;
	struct cp_request req;

	if (capprotect_fd < 0) {
		errno = ENOTSUP;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);

	if (ioctl(capprotect_fd, MAC_CAPABILITY_CALL, &call) == -1)
		return (-1);
	return (0);
}

void
service_drop_inherited_authority(void)
{
	unsigned i;

	if (pair_fd >= 0) {
		close(pair_fd);
		pair_fd = -1;
	}
	if (capprotect_fd >= 0) {
		close(capprotect_fd);
		capprotect_fd = -1;
	}
	for (i = 0; i < ncapability_fds; i++) {
		if (capability_fds[i].fd >= 0)
			close(capability_fds[i].fd);
		explicit_bzero(&capability_fds[i], sizeof(capability_fds[i]));
		capability_fds[i].fd = -1;
	}
	ncapability_fds = 0;
	for (i = 0; i < ncomponent_fds; i++) {
		if (component_fds[i].fd >= 0)
			close(component_fds[i].fd);
		explicit_bzero(&component_fds[i], sizeof(component_fds[i]));
		component_fds[i].fd = -1;
	}
	ncomponent_fds = 0;
	for (i = 0; i < nbootstrap_token_fds; i++) {
		if (bootstrap_token_fds[i] >= 0)
			close(bootstrap_token_fds[i]);
		bootstrap_token_fds[i] = -1;
	}
	nbootstrap_token_fds = 0;
	for (i = 0; i < nactivated_token_fds; i++) {
		if (activated_token_fds[i] >= 0)
			close(activated_token_fds[i]);
		activated_token_fds[i] = -1;
	}
	nactivated_token_fds = 0;
	explicit_bzero(service_label_value, sizeof(service_label_value));
}

int
service_ready(void)
{
	struct svc_req_hdr req;
	unsigned int mode;

	/*
	 * Readiness is a security boundary, not merely an application hint.
	 * Enter capability mode before sending the compatibility notification;
	 * serviced independently observes NOTE_CAPMODE on our procdesc.
	 */
	if (cap_getmode(&mode) == -1)
		return (-1);
	if (mode == 0 && cap_enter() == -1)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_READY;
	return (rpc(&req, sizeof(req), NULL));
}

int
service_register(const char *name)
{
	struct svc_register_req req;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_REGISTER;
	strlcpy(req.name, name, sizeof(req.name));
	return (rpc(&req, sizeof(req), NULL));
}

int
service_unregister(const char *name)
{
	struct svc_unregister_req req;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_UNREGISTER;
	strlcpy(req.name, name, sizeof(req.name));
	return (rpc(&req, sizeof(req), NULL));
}

int
service_lookup(const char *name)
{
	struct svc_lookup_req req;
	int fd;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
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
	return (fd);
}

int
service_accept(char *client_label, size_t labelsz)
{
	struct mac_capability_recvmsg_args ra;
	struct svc_new_client_msg msg;
	int client_fd;

	if (pair_fd < 0) {
		errno = ENOTCONN;
		return (-1);
	}

	/* Check pending queue first (notifications queued during rpc). */
	if (npending > 0) {
		struct pending_notify *pn;

		pn = &pending[0];
		if (client_label != NULL && labelsz > 0)
			strlcpy(client_label, pn->msg.client_label, labelsz);
		client_fd = pn->fd;

		/* Shift queue down. */
		npending--;
		if (npending > 0)
			memmove(&pending[0], &pending[1],
			    (size_t)npending * sizeof(pending[0]));
		return (client_fd);
	}

	/* No pending — block on the pair fd. */
	for (;;) {
		uint32_t op;

		client_fd = -1;
		memset(&ra, 0, sizeof(ra));
		ra.payload = &msg;
		ra.payload_len = sizeof(msg);
		ra.fds = &client_fd;
		ra.nfds = 1;

		if (ioctl(pair_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}

		if (ra.payload_len == sizeof(msg) && ra.nfds == 1 &&
		    msg.flags == 0 &&
		    strnlen(msg.client_label, sizeof(msg.client_label)) <
		    sizeof(msg.client_label)) {
			memcpy(&op, &msg, sizeof(op));
			if (op == SVC_OP_NEW_CLIENT)
				break;
		}

		/* Not a notification — discard. */
		if (client_fd >= 0)
			close(client_fd);
	}

	if (client_label != NULL && labelsz > 0)
		strlcpy(client_label, msg.client_label, labelsz);

	return (client_fd);
}

int
service_send(int fd, const void *data, size_t len)
{
	return (service_send_fds(fd, data, len, NULL, 0));
}

int
service_send_fds(int fd, const void *data, size_t len, const int *fds,
    size_t nfds)
{
	struct mac_capability_sendmsg_args sa;

	if (len > UINT32_MAX || nfds > UINT32_MAX ||
	    (data == NULL && len != 0) || (fds == NULL && nfds != 0)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&sa, 0, sizeof(sa));
	sa.payload = data;
	sa.payload_len = (uint32_t)len;
	sa.fds = fds;
	sa.nfds = (uint32_t)nfds;

	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1)
		return (-1);
	return (0);
}

ssize_t
service_recv(int fd, void *buf, size_t bufsz, int *peer_fd)
{
	ssize_t n;
	size_t nfds;
	int pfd;

	pfd = -1;
	nfds = peer_fd != NULL ? 1 : 0;
	n = service_recv_fds(fd, buf, bufsz,
	    peer_fd != NULL ? &pfd : NULL, &nfds);
	if (n == -1)
		return (-1);
	if (peer_fd != NULL)
		*peer_fd = nfds == 1 ? pfd : -1;
	return (n);
}

ssize_t
service_recv_fds(int fd, void *buf, size_t bufsz, int *fds, size_t *nfds)
{
	struct mac_capability_recvmsg_args ra;
	size_t capacity, i;

	if (nfds == NULL || bufsz > UINT32_MAX || *nfds > UINT32_MAX ||
	    (buf == NULL && bufsz != 0) || (fds == NULL && *nfds != 0)) {
		errno = EINVAL;
		return (-1);
	}
	capacity = *nfds;
	for (i = 0; i < capacity; i++)
		fds[i] = -1;
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = (uint32_t)bufsz;
	ra.fds = fds;
	ra.nfds = (uint32_t)capacity;

	for (;;) {
		if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0)
			break;
		if (errno == EINTR)
			continue;
		for (i = 0; i < capacity; i++) {
			if (fds[i] >= 0)
				close(fds[i]);
		}
		*nfds = 0;
		return (-1);
	}

	*nfds = ra.nfds;
	return ((ssize_t)ra.payload_len);
}
