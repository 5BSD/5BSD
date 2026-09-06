/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * localsysctl: the system.Sysctl capability provider.  A client holds a
 * system.Sysctl channel and asks the broker to read (and, policy permitting,
 * write) kernel sysctl variables by name, instead of calling sysctl(3) itself
 * or forking a Casper cap_sysctl helper.  __sysctlbyname(2) is capability-mode
 * enabled, so the per-client pdfork worker performs the sysctl directly after a
 * per-label policy check; no Casper is involved.
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>
#include <sysctlcmp.h>
#include <sysctlcmp_server.h>

#include "config.h"

#ifndef SYSCTLCMP_TESTING
/* Loaded once in main() before the provider sandboxes; workers inherit it. */
static struct sysctlcmp_config g_config;
#endif

struct session {
	const char			*label;
	const struct sysctlcmp_config	*config;
	int				 error;
};

/* Header-only reply (HELLO, or an error status = -errno). */
static int
send_status(struct channel_message *request_message,
    const struct sysctlcmp_msg *request, int status)
{
	uint8_t buffer[sizeof(struct sysctlcmp_msg)];
	struct sysctlcmp_msg *reply;

	reply = (void *)buffer;
	if (sysctlcmp_message_init_reply(reply, request, status) == -1)
		return (-1);
	if (sysctlcmp_validate_message(reply, sizeof(*reply),
	    SYSCTLCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, sizeof(*reply))));
}

/* Success reply carrying value_length bytes (0 for a SET). */
static int
send_value(struct channel_message *request_message,
    const struct sysctlcmp_msg *request, const void *value, size_t value_len)
{
	uint8_t buffer[SYSCTLCMP_MAX_MESSAGE];
	struct sysctlcmp_msg *reply;
	struct sysctlcmp_body *body;
	size_t length;

	if (value_len > SYSCTLCMP_MAX_VALUE)
		return (errno = EOVERFLOW, -1);
	memset(buffer, 0, sizeof(struct sysctlcmp_msg) +
	    sizeof(struct sysctlcmp_body));
	reply = (void *)buffer;
	if (sysctlcmp_message_init_reply(reply, request, 0) == -1)
		return (-1);
	body = (void *)(reply + 1);
	body->name_length = 0;
	body->reserved = 0;
	body->value_length = (uint32_t)value_len;
	if (value_len != 0)
		memcpy(body + 1, value, value_len);
	length = sizeof(*reply) + sizeof(*body) + value_len;
	if (sysctlcmp_validate_message(reply, length,
	    SYSCTLCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, length)));
}

/*
 * Introspection via the CTL_SYSCTL magic MIBs (all through __sysctl(2), which is
 * capability-mode enabled).  oid[0]=0 selects CTL_SYSCTL; oid[1] the sub-op.
 */
static int
do_oidfmt(const char *name, void *buf, size_t *buflen)
{
	int oid[CTL_MAXNAME + 2];
	size_t n;

	n = CTL_MAXNAME;
	if (sysctlnametomib(name, oid + 2, &n) == -1)
		return (-1);
	oid[0] = 0;
	oid[1] = 4;			/* CTL_SYSCTL_OIDFMT */
	/* Reply value is exactly {uint32_t kind; char fmt[]} -- our wire layout. */
	return (sysctl(oid, (u_int)(n + 2), buf, buflen, NULL, 0));
}

static int
do_descr(const char *name, void *buf, size_t *buflen)
{
	int oid[CTL_MAXNAME + 2];
	size_t n;

	n = CTL_MAXNAME;
	if (sysctlnametomib(name, oid + 2, &n) == -1)
		return (-1);
	oid[0] = 0;
	oid[1] = 5;			/* CTL_SYSCTL_OIDDESCR */
	return (sysctl(oid, (u_int)(n + 2), buf, buflen, NULL, 0));
}

/*
 * Enumeration that never reveals a name outside the caller's read policy:
 * walk CTL_SYSCTL_NEXT from name (or the root for ""), resolving each next oid
 * to a name and skipping any the label may not read, until a permitted name is
 * found or the tree ends (ENOENT).
 */
static int
do_next(const struct session *session, const char *name, char *out,
    size_t *outlen)
{
	int walk[CTL_MAXNAME + 2], noid[CTL_MAXNAME], qname[CTL_MAXNAME + 2];
	char nm[SYSCTLCMP_MAX_NAME];
	size_t start, nlen, nmlen, nn;

	walk[0] = 0;
	walk[1] = 2;			/* CTL_SYSCTL_NEXT */
	if (name != NULL && name[0] != '\0') {
		start = CTL_MAXNAME;
		if (sysctlnametomib(name, walk + 2, &start) == -1)
			return (-1);
		start += 2;
	} else {
		start = 2;		/* start from the root */
	}
	for (;;) {
		nlen = sizeof(noid);
		if (sysctl(walk, (u_int)start, noid, &nlen, NULL, 0) == -1)
			return (-1);	/* ENOENT past the last variable */
		nn = nlen / sizeof(int);
		qname[0] = 0;
		qname[1] = 1;		/* CTL_SYSCTL_NAME */
		memcpy(qname + 2, noid, nlen);
		nmlen = sizeof(nm);
		if (sysctl(qname, (u_int)(nn + 2), nm, &nmlen, NULL, 0) == -1)
			return (-1);
		if (sysctlcmp_config_permits(session->config, session->label,
		    nm, false)) {
			if (nmlen > *outlen)
				return (errno = ENOMEM, -1);
			memcpy(out, nm, nmlen);
			*outlen = nmlen;
			return (0);
		}
		/* Not permitted: advance past it and keep walking. */
		walk[0] = 0;
		walk[1] = 2;
		memcpy(walk + 2, noid, nlen);
		start = nn + 2;
	}
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct sysctlcmp_msg *request;
	const struct sysctlcmp_body *body;
	struct session *session;
	const char *name;
	const void *newp;
	uint8_t value[SYSCTLCMP_MAX_VALUE];
	size_t value_len, newlen;
	int result;

	session = argument;
	request = channel_message_data(message);
	if (channel_message_fd_count(message) != 0 ||
	    sysctlcmp_validate_message(request, channel_message_length(message),
	    SYSCTLCMP_MESSAGE_REQUEST) == -1) {
		session->error = EPROTO;
		goto out;
	}
	result = 0;
	switch (request->opcode) {
	case SYSCTLCMP_OP_HELLO:
		result = send_status(message, request, 0);
		break;
	case SYSCTLCMP_OP_GET:
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		if (!sysctlcmp_config_permits(session->config, session->label,
		    name, false)) {
			result = send_status(message, request, -EPERM);
			break;
		}
		value_len = sizeof(value);
		if (sysctlbyname(name, value, &value_len, NULL, 0) == -1)
			result = send_status(message, request, -errno);
		else
			result = send_value(message, request, value, value_len);
		break;
	case SYSCTLCMP_OP_SET:
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		newlen = body->value_length;
		newp = (const uint8_t *)(body + 1) + body->name_length;
		if (!sysctlcmp_config_permits(session->config, session->label,
		    name, true)) {
			result = send_status(message, request, -EPERM);
			break;
		}
		if (sysctlbyname(name, NULL, NULL, newp, newlen) == -1)
			result = send_status(message, request, -errno);
		else
			result = send_value(message, request, NULL, 0);
		break;
	case SYSCTLCMP_OP_OIDFMT:
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		if (!sysctlcmp_config_permits(session->config, session->label,
		    name, false)) {
			result = send_status(message, request, -EPERM);
			break;
		}
		value_len = sizeof(value);
		if (do_oidfmt(name, value, &value_len) == -1)
			result = send_status(message, request, -errno);
		else
			result = send_value(message, request, value, value_len);
		break;
	case SYSCTLCMP_OP_DESCR:
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		if (!sysctlcmp_config_permits(session->config, session->label,
		    name, false)) {
			result = send_status(message, request, -EPERM);
			break;
		}
		value_len = sizeof(value);
		if (do_descr(name, value, &value_len) == -1)
			result = send_status(message, request, -errno);
		else
			result = send_value(message, request, value, value_len);
		break;
	case SYSCTLCMP_OP_NEXT:
		/* The cursor name is not gated; do_next() filters the results. */
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		value_len = sizeof(value);
		if (do_next(session, name, (char *)value, &value_len) == -1)
			result = send_status(message, request, -errno);
		else
			result = send_value(message, request, value, value_len);
		break;
	default:
		result = send_status(message, request, -EOPNOTSUPP);
		break;
	}
	if (result == -1)
		session->error = errno;
out:
	channel_message_free(message);
}

static int
serve_session(int fd, const char *label, const struct sysctlcmp_config *config)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel;
	struct session session;
	int ready, wants_write;

	if (fd < 0 || label == NULL || label[0] == '\0' || config == NULL)
		return (errno = EINVAL, -1);
	memset(&session, 0, sizeof(session));
	session.label = label;
	session.config = config;
	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, handle_request,
	    &session) == -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		ready = channel_wait(channel, wants_write, -1);
		if (ready <= 0)
			break;
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
		if (session.error != 0)
			break;
	}
	channel_destroy(channel);
	return (session.error == 0 ? 0 : 1);
}

#ifdef SYSCTLCMP_TESTING
#include "localsysctl_test.h"

int
sysctlcmp_test_serve(int fd, const char *label,
    const struct sysctlcmp_config *config)
{

	return (serve_session(fd, label, config));
}
#else

/*
 * Per-client worker.  localsysctl is a PRIVILEGED provider (like sysextd): it
 * must NOT enter capability mode, because sysctl(3)/sysctlbyname(3) in
 * capability mode is restricted to CTLFLAG_CAPRD/CAPWR nodes only, which
 * excludes almost every variable.  The provider is the trusted concentration
 * point for sysctl access; the per-label policy (checked in handle_request) is
 * the security boundary, not a Capsicum sandbox.  g_config was loaded before
 * the pdfork, so each worker inherits it.
 */
static int
worker(int fd, const char *label)
{

	return (serve_session(fd, label, &g_config));
}

int
main(void)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	int error, fd, cfgfd;

	openlog("localsysctl", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	/*
	 * Per-label policy, via the serviced-delivered Config directory
	 * descriptor.  Fail-soft: a missing/malformed config keeps the built-in
	 * default ACL (a small safe read set, no writes).
	 */
	sysctlcmp_config_defaults(&g_config);
	if (service_config_open(SYSCTLCMP_CONFIG_NAME, &cfgfd) == -1) {
		if (errno != ENOENT)
			syslog(LOG_WARNING, "policy config unavailable; using "
			    "built-in default sysctl policy: %m");
	} else if (sysctlcmp_config_load_fd(&g_config, cfgfd) == -1) {
		syslog(LOG_WARNING, "policy config rejected; using built-in "
		    "default sysctl policy: %m");
	}
	/*
	 * Privileged provider: no service_provider_protect / capability mode,
	 * because the workers must retain unrestricted sysctl(3) access (see
	 * worker()).  Access is bounded by the per-label policy, not a sandbox.
	 */
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, SYSCTLCMP_INTERFACE,
	    &listener) == -1 ||
	    service_provider_enter_privileged(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		pid_t pid;
		int pd;

		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1) {
				int status;

				status = service_provider_quiesce_complete(
				    provider, 0);
				closelog();
				return (status == 0 ? 0 : 1);
			}
			errno = error;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_WARNING, "pdfork for %s: %m",
			    identity.client_label);
			close(fd);
			continue;
		}
		if (pid == 0)
			_exit(worker(fd, identity.client_label));
		close(fd);
		close(pd);
	}
fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
#endif /* !SYSCTLCMP_TESTING */
