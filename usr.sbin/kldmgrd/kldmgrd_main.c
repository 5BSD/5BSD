/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/procdesc.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "kldmgrd_proto.h"
#include "kldmgrd_probes.h"

#define	KLDMGR_SERVICE_NAME	"org.5bsd.system.kldmgr"
#define	KLDMGR_ALLOW_FILE	"/etc/kldmgrd.allow"
#define	KLDMGR_CLIENT_TIMEOUT_MS	30000

struct label_policy {
	char	labels[256][64];
	size_t	count;
	bool	wildcard;
};

struct session {
	const char	*label;
	bool		 allowed;
	int		 error;
};

static void
audit_request(const char *label, uint32_t opcode, int error)
{
	short event;

	event = opcode == KLDMGR_OP_UNLOAD ? AUE_MODUNLOAD : AUE_MODLOAD;
	(void)audit_submit(event, getuid(), (char)error, error != 0,
	    "client=%s opcode=%u result=%d", label, opcode, error);
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

static int
module_name_valid(const char *name, size_t length)
{
	size_t i, name_length;

	name_length = strnlen(name, length);
	if (name_length == 0 || name_length >= length)
		return (0);
	for (i = 0; i < name_length; i++) {
		if ((name[i] >= 'a' && name[i] <= 'z') ||
		    (name[i] >= 'A' && name[i] <= 'Z') ||
		    (name[i] >= '0' && name[i] <= '9') ||
		    name[i] == '_' || name[i] == '-' || name[i] == '.')
			continue;
		return (0);
	}
	return (1);
}

static void
handle_load(const struct kldmgr_req *request, struct kldmgr_reply *reply)
{
	int id;

	reply->id = -1;
	if (!module_name_valid(request->name, sizeof(request->name))) {
		reply->status = KLDMGR_STATUS_ERR;
		return;
	}
	id = kldload(request->name);
	if (id == -1) {
		syslog(LOG_WARNING, "kldload %s: %m", request->name);
		reply->status = errno == ENOENT ?
		    KLDMGR_STATUS_NOTFOUND : KLDMGR_STATUS_ERR;
	} else {
		syslog(LOG_INFO, "loaded %s (id %d)", request->name, id);
		reply->status = KLDMGR_STATUS_OK;
		reply->id = id;
	}
}

static void
handle_unload(const struct kldmgr_req *request, struct kldmgr_reply *reply)
{
	int id;

	reply->id = -1;
	if (!module_name_valid(request->name, sizeof(request->name))) {
		reply->status = KLDMGR_STATUS_ERR;
		return;
	}
	id = kldfind(request->name);
	if (id == -1) {
		reply->status = KLDMGR_STATUS_NOTFOUND;
		return;
	}
	if (kldunload(id) == -1) {
		syslog(LOG_WARNING, "kldunload %s (id %d): %m",
		    request->name, id);
		reply->status = KLDMGR_STATUS_ERR;
	} else {
		syslog(LOG_INFO, "unloaded %s (id %d)", request->name, id);
		reply->status = KLDMGR_STATUS_OK;
		reply->id = id;
	}
}

static int
respond_list(struct channel_message *message)
{
	char buffer[sizeof(struct kldmgr_list_reply) +
	    KLDMGR_LIST_MAX * sizeof(struct kldmgr_list_entry)];
	struct kldmgr_list_reply *reply;
	struct kld_file_stat status;
	uint32_t count;
	int id;

	memset(buffer, 0, sizeof(buffer));
	reply = (void *)buffer;
	reply->status = KLDMGR_STATUS_OK;
	count = 0;
	for (id = kldnext(0); id > 0 && count < KLDMGR_LIST_MAX;
	    id = kldnext(id)) {
		memset(&status, 0, sizeof(status));
		status.version = sizeof(status);
		if (kldstat(id, &status) == -1)
			continue;
		reply->entries[count].id = id;
		strlcpy(reply->entries[count].name, status.name,
		    sizeof(reply->entries[count].name));
		count++;
	}
	reply->count = count;
	return (channel_send_reply(message,
	    &(struct channel_outgoing)CHANNEL_OUTGOING_INITIALIZER(buffer,
	    sizeof(*reply) + count * sizeof(struct kldmgr_list_entry))));
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct kldmgr_req *request;
	struct kldmgr_reply reply;
	struct session *session;
	int result;

	session = argument;
	request = NULL;
	memset(&reply, 0, sizeof(reply));
	reply.id = -1;
	if (channel_message_length(message) != sizeof(*request) ||
	    channel_message_fd_count(message) != 0) {
		reply.status = KLDMGR_STATUS_ERR;
		KLDMGRD_PROBE_MALFORMED(
		    __DECONST(char *, session->label), EPROTO);
		result = channel_send_reply(message,
		    &(struct channel_outgoing)
		    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply)));
		goto out;
	}
	request = channel_message_data(message);
	if (!session->allowed) {
		reply.status = KLDMGR_STATUS_PERM;
		result = channel_send_reply(message,
		    &(struct channel_outgoing)
		    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply)));
		goto out;
	}
	switch (request->op) {
	case KLDMGR_OP_LOAD:
		handle_load(request, &reply);
		result = channel_send_reply(message,
		    &(struct channel_outgoing)
		    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply)));
		break;
	case KLDMGR_OP_UNLOAD:
		handle_unload(request, &reply);
		result = channel_send_reply(message,
		    &(struct channel_outgoing)
		    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply)));
		break;
	case KLDMGR_OP_LIST:
		result = respond_list(message);
		break;
	default:
		reply.status = KLDMGR_STATUS_ERR;
		result = channel_send_reply(message,
		    &(struct channel_outgoing)
		    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply)));
		break;
	}
out:
	if (request != NULL) {
		int audit_error;

		audit_error = reply.status == KLDMGR_STATUS_OK ? 0 :
		    reply.status == KLDMGR_STATUS_PERM ? EACCES :
		    reply.status == KLDMGR_STATUS_NOTFOUND ? ENOENT : EIO;
		if (request->op == KLDMGR_OP_LOAD ||
		    request->op == KLDMGR_OP_UNLOAD)
			audit_request(session->label, request->op, audit_error);
		KLDMGRD_PROBE_REQUEST(__DECONST(char *, session->label),
		    request->op, audit_error);
	}
	if (result == -1)
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
	KLDMGRD_PROBE_SESSION_START(__DECONST(char *, label));
	if (channel_create(fd, &options, &channel) == -1) {
		KLDMGRD_PROBE_SESSION_END(__DECONST(char *, label), errno);
		return (1);
	}
	if (channel_set_request_handler(channel, handle_request, &session) ==
	    -1) {
		result = errno;
		channel_destroy(channel);
		KLDMGRD_PROBE_SESSION_END(__DECONST(char *, label), result);
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
			result = poll(&descriptor, 1, KLDMGR_CLIENT_TIMEOUT_MS);
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
	KLDMGRD_PROBE_SESSION_END(__DECONST(char *, label), loop_error);
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

	openlog("kldmgrd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (load_policy(KLDMGR_ALLOW_FILE, &policy) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1 ||
	    service_provider_expose(provider, KLDMGR_SERVICE_NAME,
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
