/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <errno.h>
#include <string.h>
#include "libservice.h"
#include <sysext_proto.h>

static int
valid_name(const char *name)
{
	return (memchr(name, '\0', SYSEXT_NAME_MAX) != NULL &&
	    name[0] != '\0' && strcmp(name, ".") != 0 &&
	    strcmp(name, "..") != 0 && strchr(name, '/') == NULL);
}

static int
protocol_error(struct service_session *session)
{
	(void)service_session_fail(session, EPROTO);
	errno = EPROTO;
	return (-1);
}

static int
extension_call(struct service_session *session, uint32_t op, const char *name,
    void *response, size_t size)
{
	struct sysext_request request = {0};
	struct service_message message = { .size = sizeof(message) };
	struct service_reply reply = { .size = sizeof(reply) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct sysext_reply *basic = response;

	if (session == NULL) {
		errno = EINVAL;
		return (-1);
	}
	request.op = op;
	if (op == SYSEXT_OP_ENSURE || op == SYSEXT_OP_STAT) {
		if (name == NULL) {
			errno = EINVAL;
			return (-1);
		}
		if (strnlen(name, sizeof(request.name)) >= sizeof(request.name)) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		(void)strlcpy(request.name, name, sizeof(request.name));
		if (!valid_name(request.name)) {
			errno = EINVAL;
			return (-1);
		}
	}
	memset(response, 0, size);
	message.data = &request;
	message.length = sizeof(request);
	reply.data = response;
	reply.capacity = size;
	options.timeout_ms = 30000;
	if (service_session_call(session, &message, &reply, &options) == -1) {
		if (errno == EMSGSIZE)
			return (protocol_error(session));
		return (-1);
	}
	if (reply.nfds != 0 || reply.length < sizeof(*basic) ||
	    basic->status < 0 || basic->status > ELAST)
		return (protocol_error(session));
	/* The broker uses a basic reply for framing and authorization errors. */
	if (basic->status != 0) {
		if (reply.length != sizeof(*basic) || basic->_reserved != 0)
			return (protocol_error(session));
		errno = basic->status;
		return (-1);
	}
	if (reply.length != size)
		return (protocol_error(session));
	return (0);
}

int
service_session_extension_load(struct service_session *session, const char *name)
{
	struct sysext_reply reply;

	if (extension_call(session, SYSEXT_OP_ENSURE, name, &reply,
	    sizeof(reply)) == -1)
		return (-1);
	if (reply._reserved != 0)
		return (protocol_error(session));
	return (0);
}

int
service_session_extension_reload(struct service_session *session)
{
	struct sysext_reply reply;

	if (extension_call(session, SYSEXT_OP_RELOAD, NULL, &reply,
	    sizeof(reply)) == -1)
		return (-1);
	if (reply._reserved != 0)
		return (protocol_error(session));
	return (0);
}

int
service_session_extension_stat(struct service_session *session, const char *name,
    int *loaded)
{
	struct sysext_stat_reply reply;

	if (loaded == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*loaded = 0;
	if (extension_call(session, SYSEXT_OP_STAT, name, &reply,
	    sizeof(reply)) == -1)
		return (-1);
	if (reply.loaded != 0 && reply.loaded != 1)
		return (protocol_error(session));
	*loaded = reply.loaded;
	return (0);
}

int
service_session_extension_list(struct service_session *session,
    char (*names)[SERVICE_EXTENSION_NAME_MAX], size_t max, size_t *count)
{
	struct sysext_list_reply reply;
	size_t i;

	_Static_assert(SERVICE_EXTENSION_NAME_MAX == SYSEXT_NAME_MAX,
	    "extension name size mismatch");
	_Static_assert(SERVICE_EXTENSION_LIST_MAX == SYSEXT_LIST_MAX,
	    "extension list size mismatch");
	if (names == NULL || count == NULL || max == 0) {
		errno = EINVAL;
		return (-1);
	}
	*count = 0;
	if (extension_call(session, SYSEXT_OP_LIST, NULL, &reply,
	    sizeof(reply)) == -1)
		return (-1);
	if (reply.count > SYSEXT_LIST_MAX)
		return (protocol_error(session));
	for (i = 0; i < reply.count; i++)
		if (!valid_name(reply.names[i]))
			return (protocol_error(session));
	for (i = reply.count * SYSEXT_NAME_MAX; i < sizeof(reply.names); i++)
		if (((const char *)reply.names)[i] != 0)
			return (protocol_error(session));
	if (reply.count > max) {
		*count = reply.count;
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(names, reply.names, reply.count * sizeof(reply.names[0]));
	*count = reply.count;
	return (0);
}
