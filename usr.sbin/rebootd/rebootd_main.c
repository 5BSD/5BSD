/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/reboot.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "rebootd_proto.h"
#include "rebootd_probes.h"

#define	REBOOT_ALLOWED_FLAGS	(RB_HALT | RB_POWEROFF | RB_REROOT)
#define	REBOOT_SERVICE_NAME	"org.5bsd.system.reboot"
#define	REBOOT_ALLOW_FILE	"/etc/rebootd.allow"
#define	REBOOT_CLIENT_TIMEOUT_MS	30000

struct session {
	const char	*label;
	bool		 allowed;
	int		 error;
};

struct label_policy {
	char	labels[256][64];
	size_t	count;
	bool	wildcard;
};

static volatile sig_atomic_t shutdown_pending;

static void
audit_request(const char *label, uint32_t opcode, int error)
{

	(void)audit_submit((short)AUE_REBOOT, getuid(), (char)error,
	    error != 0, "client=%s opcode=%u result=%d", label, opcode,
	    error);
}

static char *
trim(char *text)
{
	char *end;

	while (isspace((unsigned char)*text))
		text++;
	if (*text == '\0')
		return (text);
	end = text + strlen(text) - 1;
	while (end > text && isspace((unsigned char)*end))
		*end-- = '\0';
	return (text);
}

static int
load_policy(const char *path, struct label_policy *policy)
{
	char line[256], *entry, *comment;
	FILE *file;

	memset(policy, 0, sizeof(*policy));
	file = fopen(path, "r");
	if (file == NULL) {
		if (errno == ENOENT)
			return (0);
		return (-1);
	}
	while (fgets(line, sizeof(line), file) != NULL) {
		comment = strchr(line, '#');
		if (comment != NULL)
			*comment = '\0';
		entry = trim(line);
		if (*entry == '\0')
			continue;
		if (strcmp(entry, "*") == 0) {
			policy->wildcard = true;
			break;
		}
		if (strlen(entry) >= sizeof(policy->labels[0]) ||
		    policy->count == nitems(policy->labels)) {
			fclose(file);
			errno = E2BIG;
			return (-1);
		}
		strlcpy(policy->labels[policy->count++], entry,
		    sizeof(policy->labels[0]));
	}
	if (ferror(file)) {
		fclose(file);
		return (-1);
	}
	return (fclose(file));
}

static bool
policy_allows(const struct label_policy *policy, const char *label)
{
	size_t i;

	if (label == NULL || label[0] == '\0')
		return (false);
	if (policy->wildcard)
		return (true);
	for (i = 0; i < policy->count; i++)
		if (strcmp(policy->labels[i], label) == 0)
			return (true);
	return (false);
}

static void
handle_reboot_op(const struct reboot_req *request,
    struct reboot_reply *reply, const char *label)
{
	int howto;

	if ((request->flags & ~REBOOT_ALLOWED_FLAGS) != 0) {
		syslog(LOG_WARNING, "reboot denied for %s: invalid flags 0x%x",
		    label, request->flags);
		reply->status = REBOOT_STATUS_ERR;
		return;
	}
	howto = request->flags;
	syslog(LOG_NOTICE, "reboot requested by %s (flags 0x%x)",
	    label, howto);
	shutdown_pending = 1;
	if (reboot(howto) == -1) {
		shutdown_pending = 0;
		syslog(LOG_ERR, "reboot(0x%x): %m", howto);
		reply->status = REBOOT_STATUS_ERR;
	} else
		reply->status = REBOOT_STATUS_OK;
}

static void
handle_shutdown_op(struct reboot_reply *reply, const char *label)
{

	syslog(LOG_NOTICE, "shutdown requested by %s", label);
	shutdown_pending = 1;
	if (reboot(RB_HALT | RB_POWEROFF) == -1) {
		shutdown_pending = 0;
		syslog(LOG_ERR, "reboot(RB_HALT|RB_POWEROFF): %m");
		reply->status = REBOOT_STATUS_ERR;
	} else
		reply->status = REBOOT_STATUS_OK;
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct reboot_req *request;
	struct reboot_reply reply;
	struct session *session;

	session = argument;
	request = NULL;
	memset(&reply, 0, sizeof(reply));
	if (channel_message_length(message) != sizeof(*request) ||
	    channel_message_fd_count(message) != 0) {
		reply.status = REBOOT_STATUS_ERR;
		REBOOTD_PROBE_MALFORMED(
		    __DECONST(char *, session->label), EPROTO);
		goto respond;
	}
	request = channel_message_data(message);
	switch (request->op) {
	case REBOOT_OP_REBOOT:
		if (!session->allowed) {
			syslog(LOG_WARNING, "reboot denied for %s by %s",
			    session->label, REBOOT_ALLOW_FILE);
			reply.status = REBOOT_STATUS_PERM;
		} else
			handle_reboot_op(request, &reply, session->label);
		break;
	case REBOOT_OP_SHUTDOWN:
		if (!session->allowed) {
			syslog(LOG_WARNING, "shutdown denied for %s by %s",
			    session->label, REBOOT_ALLOW_FILE);
			reply.status = REBOOT_STATUS_PERM;
		} else
			handle_shutdown_op(&reply, session->label);
		break;
	case REBOOT_OP_STATUS:
		reply.status = shutdown_pending ?
		    REBOOT_STATUS_PENDING : REBOOT_STATUS_OK;
		break;
	default:
		reply.status = REBOOT_STATUS_ERR;
		break;
	}
respond:
	if (request != NULL) {
		int audit_error;

		audit_error = reply.status == REBOOT_STATUS_OK ? 0 :
		    reply.status == REBOOT_STATUS_PERM ? EACCES : EIO;
		if (request->op == REBOOT_OP_REBOOT ||
		    request->op == REBOOT_OP_SHUTDOWN)
			audit_request(session->label, request->op, audit_error);
		REBOOTD_PROBE_REQUEST(__DECONST(char *, session->label),
		    request->op, audit_error);
	}
	if (channel_send_reply(message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply))) == -1)
		session->error = errno;
	channel_message_free(message);
}

static int
serve_client(int fd, const char *label, bool allowed)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel;
	struct pollfd descriptor;
	struct session session;
	int loop_error, result, wants_write;

	service_worker_drop_inherited_authority();
	memset(&session, 0, sizeof(session));
	session.label = label;
	session.allowed = allowed;
	loop_error = 0;
	REBOOTD_PROBE_SESSION_START(__DECONST(char *, label));
	if (channel_create(fd, &options, &channel) == -1) {
		REBOOTD_PROBE_SESSION_END(__DECONST(char *, label), errno);
		return (1);
	}
	if (channel_set_request_handler(channel, handle_request, &session) ==
	    -1) {
		result = errno;
		channel_destroy(channel);
		REBOOTD_PROBE_SESSION_END(__DECONST(char *, label), result);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1) {
			loop_error = errno;
			break;
		}
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		do {
			result = poll(&descriptor, 1, REBOOT_CLIENT_TIMEOUT_MS);
		} while (result == -1 && errno == EINTR);
		if (result == 0) {
			loop_error = ETIMEDOUT;
			break;
		}
		if (result == -1) {
			loop_error = errno;
			break;
		}
		if ((descriptor.revents & POLLOUT) != 0 &&
		    channel_flush(channel) == -1) {
			loop_error = errno;
			break;
		}
		if ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1) {
			loop_error = errno;
			break;
		}
		if (session.error != 0) {
			loop_error = session.error;
			break;
		}
	}
	channel_destroy(channel);
	REBOOTD_PROBE_SESSION_END(__DECONST(char *, label), loop_error);
	return (loop_error == 0 ? 0 : 1);
}

int
main(void)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	struct label_policy policy;
	char label[sizeof(identity.client_label)];
	int client, pd;
	pid_t pid;

	openlog("rebootd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (load_policy(REBOOT_ALLOW_FILE, &policy) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1 ||
	    service_provider_expose(provider, REBOOT_SERVICE_NAME,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &client) == -1) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		strlcpy(label, identity.client_label, sizeof(label));
		pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_WARNING, "fork client %s: %m", label);
			close(client);
			continue;
		}
		if (pid == 0)
			_exit(serve_client(client, label,
			    policy_allows(&policy, label)));
		close(pd);
		close(client);
	}

fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	closelog();
	return (1);
}
