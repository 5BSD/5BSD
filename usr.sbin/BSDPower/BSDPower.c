/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSDPower -- the system.Power capability provider.  A client holds a
 * system.Power channel and asks the broker for the supported ACPI sleep states
 * (STATES, unprivileged) or, when the per-label policy permits, to put the
 * machine to sleep (SUSPEND -- ioctl(2) on /dev/acpi, which needs privilege the
 * sandboxed caller lacks).  BORN IN CAPABILITY MODE: switchboard execs it
 * already sandboxed, and it reaches ACPIIO_REQSLPSTATE only through a delivered
 * /dev/acpi descriptor narrowed with cap_ioctls_limit(2) to that single ioctl,
 * so the cage exposes exactly the one privileged operation.  The per-label
 * policy (power.conf) gates it on top.  reboot/halt stay with capsule(8);
 * BSDPower owns sleep.  Default-deny: no label may suspend unless power.conf
 * grants it.
 */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/sysctl.h>

#include <dev/acpica/acpiio.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <service_runtime.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "BSDPower_probes.h"
#include "config.h"
#include "powercmp_protocol.h"

static int g_acpi_fd = -1;		/* /dev/acpi, narrowed to CAP_IOCTL/REQSLPSTATE */
static uint32_t g_states;		/* supported sleep-state mask, cached at startup */

static struct service_lease_set *g_leases;

struct session {
	struct channel *channel;
	uint64_t owner, lease, last_ms;
	char label_storage[256];
	const char			*label;
	const struct powercmp_config	*config;
	int				 error;
};

/*
 * Read hw.acpi.supported_sleep_state ("S3 S4 S5") into a bitmask: bit N set
 * when SN is supported.  Unprivileged; empty/absent yields 0.
 */
static uint32_t
supported_states(void)
{
	char buf[64];
	size_t len = sizeof(buf) - 1;
	uint32_t mask = 0;
	const char *p;

	if (sysctlbyname("hw.acpi.supported_sleep_state", buf, &len, NULL, 0)
	    == -1)
		return (0);
	buf[len] = '\0';
	for (p = buf; *p != '\0'; p++)
		if ((*p == 'S' || *p == 's') && p[1] >= '1' && p[1] <= '5')
			mask |= (uint32_t)1 << (p[1] - '0');
	return (mask);
}

static void
init_reply(struct powercmp_msg *reply, const struct powercmp_msg *request,
    int status)
{

	memset(reply, 0, sizeof(*reply));
	reply->magic = POWERCMP_MAGIC;
	reply->opcode = request->opcode;
	reply->status = status;
}

static int
send_status(struct channel_message *request_message,
    const struct powercmp_msg *request, int status)
{
	struct powercmp_msg reply;

	init_reply(&reply, request, status);
	if (powercmp_validate_message(&reply, sizeof(reply),
	    POWERCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply))));
}

static int
send_body(struct channel_message *request_message,
    const struct powercmp_msg *request, const struct powercmp_body *value)
{
	uint8_t buffer[POWERCMP_MAX_MESSAGE];
	struct powercmp_msg *reply;
	struct powercmp_body *body;
	size_t length;

	memset(buffer, 0, sizeof(buffer));
	reply = (void *)buffer;
	init_reply(reply, request, 0);
	body = (void *)(reply + 1);
	*body = *value;
	length = sizeof(*reply) + sizeof(*body);
	if (powercmp_validate_message(reply, length, POWERCMP_MESSAGE_REPLY) ==
	    -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, length)));
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct powercmp_msg *request;
	const struct powercmp_body *body;
	struct session *session;
	struct powercmp_body out;
	size_t message_len;
	uint16_t opcode;
	int result, status;

	session = argument;
	if (session->error != 0) {
		channel_message_free(message);
		return;
	}
	session->last_ms = service_monotime_ms();
	request = channel_message_data(message);
	message_len = channel_message_length(message);
	opcode = UINT16_MAX;
	result = 0;
	status = 0;
	if (request != NULL && message_len >= sizeof(*request))
		opcode = request->opcode;

	if (channel_message_fd_count(message) != 0 ||
	    powercmp_validate_message(request, message_len,
	    POWERCMP_MESSAGE_REQUEST) == -1) {
		status = EPROTO;
		session->error = status;
		/* Malformed headers cannot safely be echoed as replies. */
		goto out;
	}
	body = (const void *)(request + 1);

	switch (request->opcode) {
	case POWERCMP_OP_STATES:
		memset(&out, 0, sizeof(out));
		out.supported = g_states;	/* cached pre-capmode at startup */
		result = send_body(message, request, &out);
		break;
	case POWERCMP_OP_INHIBIT:
		if (!powercmp_config_permits_inhibit(session->config,
			session->label))
			status = EPERM;
		else if (session->lease != 0)
			status = EALREADY;
		else if (g_leases == NULL ||
		    service_lease_acquire(g_leases, session->owner,
			&session->lease) == -1)
			status = g_leases == NULL ? ENOTSUP : errno;
		result = send_status(message, request, -status);
		break;
	case POWERCMP_OP_UNINHIBIT:
		if (session->lease == 0)
			status = ENOENT;
		else {
			(void)service_lease_release(g_leases, session->owner,
			    session->lease);
			session->lease = 0;
		}
		result = send_status(message, request, -status);
		break;
	case POWERCMP_OP_INHIBITORS:
		memset(&out, 0, sizeof(out));
		out.supported = g_leases == NULL ?
		    0 :
		    service_lease_count(g_leases);
		result = send_body(message, request, &out);
		break;
	case POWERCMP_OP_SUSPEND: {
		int state;

		if (message_len != sizeof(*request) + sizeof(*body)) {
			status = EPROTO;
			result = send_status(message, request, -status);
			break;
		}
		if (!powercmp_config_permits_suspend(session->config,
		    session->label)) {
			status = EPERM;
			result = send_status(message, request, -status);
			break;
		}
		if (body->state < 1 || body->state > 5) {
			status = EINVAL;
			result = send_status(message, request, -status);
			break;
		}
		if (g_leases != NULL && service_lease_count(g_leases) != 0) {
			status = EBUSY;
			result = send_status(message, request, -status);
			break;
		}
		if (g_acpi_fd < 0) {
			status = ENODEV;
			result = send_status(message, request, -status);
			break;
		}
		state = (int)body->state;
		if (ioctl(g_acpi_fd, ACPIIO_REQSLPSTATE, &state) == -1) {
			status = errno;
			result = send_status(message, request, -status);
			break;
		}
		BSDPOWER_PROBE_SUSPEND(session->label, state);
		syslog(LOG_NOTICE, "suspend to S%d requested by %s", state,
		    session->label);
		result = send_status(message, request, 0);
		break;
	}
	default:
		status = EOPNOTSUPP;
		result = send_status(message, request, -status);
		break;
	}
	if (result == -1)
		session->error = errno;
out:
	BSDPOWER_PROBE_REQUEST(session->label, opcode, status);
	channel_message_free(message);
}

static void
session_close(struct session *s)
{
	if (s->channel != NULL)
		channel_destroy(s->channel);
	service_lease_release_owner(g_leases, s->owner);
	memset(s, 0, sizeof(*s));
}

#ifdef BSDPOWER_TESTING
static int
serve_session(int fd, const char *label, const struct powercmp_config *config)
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
	session.channel = channel;
	if (g_leases != NULL)
		session_close(&session);
	else
		channel_destroy(channel);
	return (0);
}

/*
 * Test entrypoints.  Expose the per-session channel worker and the two
 * startup-cached globals (the supported-state mask and the narrowed /dev/acpi
 * descriptor) to the ATF suite so a test can drive the real request handler
 * (protocol validation, per-label SUSPEND policy, STATES/SUSPEND
 * dispatch) over a connected provider channel without the switchboard launch
 * path.  The daemon build (no -DBSDPOWER_TESTING) compiles main() below
 * instead and never these.
 */
#include "BSDPower_test.h"

int
bsdpower_test_serve_session(int fd, const char *label,
    const struct powercmp_config *config)
{

	return (serve_session(fd, label, config));
}

void
bsdpower_test_set_states(uint32_t mask)
{

	g_states = mask;
}

void
bsdpower_test_set_acpi_fd(int fd)
{

	g_acpi_fd = fd;
}

uint32_t
bsdpower_test_supported_states(void)
{

	return (supported_states());
}
#endif /* BSDPOWER_TESTING */

static struct powercmp_config g_config;

static int
sessions_run(struct service_provider *provider,
    struct service_listener *listener)
{
	struct session sessions[64] = { 0 };
	struct service_channel_slot slots[64];
	struct service_health health = { 0 };
	struct service_identity identity;
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	size_t i, slot, matching;
	int fd, ready, kq, result = -1;
	if (service_lease_set_create(64, &g_leases) == -1)
		return (-1);
	kq = kqueue();
	if (kq == -1) {
		service_lease_set_destroy(g_leases);
		g_leases = NULL;
		return (-1);
	}
	for (;;) {
		if (service_provider_quiescing(provider) == 1) {
			/* Leases keep an idle provider alive; explicit stop still wins. */
			if (service_lease_count(g_leases) != 0) {
				if (service_provider_quiesce_complete(provider, EBUSY) == 0)
					continue;
				if (errno != EINVAL)
					break;
			}
			result = 0;
			break;
		}
		for (i = 0; i < 64; i++) {
			if (sessions[i].channel != NULL &&
			    sessions[i].lease == 0 &&
			    service_monotime_ms() - sessions[i].last_ms >=
				30000)
				session_close(&sessions[i]);
			slots[i].channel = sessions[i].channel;
		}
		ready = service_channels_wait(kq, slots, 64,
		    service_listener_fd(listener), 250);
		if (ready == -1)
			break;
		for (i = 0; i < 64; i++) {
			if (slots[i].error != 0 || sessions[i].error != 0) {
				service_health_record(&health,
				    slots[i].error != 0 ? slots[i].error :
							  sessions[i].error);
				session_close(&sessions[i]);
			}
		}
		if (!ready)
			continue;
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			if (service_provider_quiescing(provider) == 1)
				continue;
			if (errno == EINTR)
				continue;
			break;
		}
		slot = 64;
		matching = 0;
		for (i = 0; i < 64; i++) {
			if (sessions[i].channel == NULL) {
				if (slot == 64)
					slot = i;
			} else if (strcmp(sessions[i].label,
				       identity.client_label) == 0)
				matching++;
		}
		if (slot == 64 || matching >= 4) {
			close(fd);
			service_health_record(&health, ENOSPC);
			continue;
		}
		struct session *s = &sessions[slot];
		strlcpy(s->label_storage, identity.client_label,
		    sizeof(s->label_storage));
		s->label = s->label_storage;
		s->config = &g_config;
		s->owner = slot + 1;
		s->last_ms = service_monotime_ms();
		if (channel_create(fd, &options, &s->channel) == -1) {
			close(fd);
			session_close(s);
			continue;
		}
		if (channel_set_request_handler(s->channel, handle_request,
			s) == -1) {
			session_close(s);
			continue;
		}
		service_health_record(&health, 0);
	}
	for (i = 0; i < 64; i++)
		session_close(&sessions[i]);
	service_lease_set_destroy(g_leases);
	close(kq);
	g_leases = NULL;
	syslog(LOG_INFO, "sessions accepted=%ju failures=%ju",
	    (uintmax_t)health.successes, (uintmax_t)health.failures);
	return (result);
}

#ifdef BSDPOWER_TESTING
int
bsdpower_test_serve_reactor(struct service_provider *provider,
    struct service_listener *listener, const struct powercmp_config *config)
{
	if (config == NULL)
		return (errno = EINVAL, -1);
	g_config = *config;
	return (sessions_run(provider, listener));
}
#else
int
main(void)
{
	struct service_listener *listener;
	struct service_provider *provider;
	cap_rights_t rights;
	const unsigned long acpi_ioctls[] = { ACPIIO_REQSLPSTATE };
	int cfgfd, devdir;

	openlog("BSDPower", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	powercmp_config_defaults(&g_config);
	if (service_config_open(POWERCMP_CONFIG_NAME, &cfgfd) == -1) {
		if (errno != ENOENT)
			syslog(LOG_WARNING, "policy config unavailable; using "
			    "built-in default (deny all suspend): %m");
	} else if (powercmp_config_load_fd(&g_config, cfgfd) == -1) {
		syslog(LOG_WARNING, "policy config rejected; using built-in "
		    "default (deny all suspend): %m");
	}
	/*
	 * Cache the supported sleep-state mask now (hw.acpi.supported_sleep_state
	 * is CTLFLAG_CAPRD, so this one read is valid even though the process is
	 * born in capability mode).  The set is static for the life of the boot.
	 */
	g_states = supported_states();
	/*
	 * Reach /dev/acpi through the delivered /dev directory capability (never a
	 * global path) and narrow it to CAP_IOCTL limited to ACPIIO_REQSLPSTATE
	 * before entering capability mode.  Fail-soft: STATES still works without
	 * it, SUSPEND returns ENODEV.
	 */
	if (service_resource_dir("/dev", &devdir) == -1) {
		syslog(LOG_WARNING, "/dev capability unavailable; SUSPEND "
		    "disabled: %m");
	} else {
		/* devdir is borrowed from libservice (do not close it). */
		g_acpi_fd = openat(devdir, "acpi", O_RDWR | O_CLOEXEC);
		if (g_acpi_fd == -1) {
			syslog(LOG_WARNING, "/dev/acpi unavailable; SUSPEND "
			    "disabled: %m");
		} else {
			cap_rights_init(&rights, CAP_IOCTL, CAP_FSTAT);
			if (cap_rights_limit(g_acpi_fd, &rights) == -1 ||
			    cap_ioctls_limit(g_acpi_fd, acpi_ioctls,
			    nitems(acpi_ioctls)) == -1) {
				syslog(LOG_WARNING, "cannot narrow /dev/acpi; "
				    "SUSPEND disabled: %m");
				(void)close(g_acpi_fd);
				g_acpi_fd = -1;
			}
		}
	}
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1 ||
	    service_provider_expose(provider, POWERCMP_INTERFACE,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	if (sessions_run(provider, listener) == -1)
		goto fail;
	return (service_provider_quiesce_complete(provider, 0) == -1 ? 1 : 0);
fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
#endif /* !BSDPOWER_TESTING */
