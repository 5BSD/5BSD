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

#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.power.v1/c/bsd.h>
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
#include "powercmp.h"

static int g_acpi_fd = -1;		/* /dev/acpi, narrowed to CAP_IOCTL/REQSLPSTATE */
static uint32_t g_states;		/* supported sleep-state mask, cached at startup */

static struct service_lease_set *g_leases;

struct session {
	struct fidl_bsd_connection	*connection;
	uint64_t owner, lease, last_ms;
	char label_storage[256];
	const char			*label;
	const struct powercmp_config	*config;
	bool				 negotiated;
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

/*
 * Every method requires a negotiated session (GetProtocolInfo first).  A
 * failed reply closes the connection; the reactor then reclaims the session
 * and with it any inhibitor lease.  DTrace request probes keep the historical
 * POWERCMP_OP_* operation codes (0 is protocol negotiation).
 */
static bool
ready(struct session *session, struct fidl_bsd_connection *connection,
    unsigned opcode)
{
	session->last_ms = service_monotime_ms();
	if (session->negotiated)
		return (true);
	BSDPOWER_PROBE_REQUEST(session->label, opcode, EPROTO);
	fidl_bsd_connection_close(connection, EPROTO);
	return (false);
}

static void
completed(struct session *session, struct fidl_bsd_connection *connection,
    unsigned opcode, int status, int error)
{
	BSDPOWER_PROBE_REQUEST(session->label, opcode, status);
	if (error != 0)
		fidl_bsd_connection_close(connection, error);
}

static void
protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_power_v1_ProtocolInfo info = { POWERCMP_WIRE_VERSION };
	int error;

	session->last_ms = service_monotime_ms();
	error = bsd_power_v1_Power_GetProtocolInfo_reply(connection, request,
	    &info);
	session->negotiated = error == 0;
	completed(session, connection, 0, 0, error);
}

static void
states(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	/* Cached pre-capmode at startup. */
	struct bsd_power_v1_SleepStates out = { g_states };

	if (!ready(session, connection, POWERCMP_OP_STATES))
		return;
	completed(session, connection, POWERCMP_OP_STATES, 0,
	    bsd_power_v1_Power_States_reply(connection, request, &out));
}

static void
inhibitors(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_power_v1_InhibitorCount out = { g_leases == NULL ? 0 :
		service_lease_count(g_leases) };

	if (!ready(session, connection, POWERCMP_OP_INHIBITORS))
		return;
	completed(session, connection, POWERCMP_OP_INHIBITORS, 0,
	    bsd_power_v1_Power_Inhibitors_reply(connection, request, &out));
}

static void
inhibit(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_power_v1_Power_Inhibit_Result reply = { 0 };
	int status = 0;

	if (!ready(session, connection, POWERCMP_OP_INHIBIT))
		return;
	if (!powercmp_config_permits_inhibit(session->config, session->label))
		status = EPERM;
	else if (session->lease != 0)
		status = EALREADY;
	else if (g_leases == NULL ||
	    service_lease_acquire(g_leases, session->owner,
		&session->lease) == -1)
		status = g_leases == NULL ? ENOTSUP : errno;
	reply.tag = status ? bsd_power_v1_Power_Inhibit_Result_err_tag :
	    bsd_power_v1_Power_Inhibit_Result_response_tag;
	if (status)
		reply.value.err = status;
	completed(session, connection, POWERCMP_OP_INHIBIT, status,
	    bsd_power_v1_Power_Inhibit_reply(connection, request, &reply));
}

static void
uninhibit(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_power_v1_Power_Uninhibit_Result reply = { 0 };
	int status = 0;

	if (!ready(session, connection, POWERCMP_OP_UNINHIBIT))
		return;
	if (session->lease == 0)
		status = ENOENT;
	else {
		(void)service_lease_release(g_leases, session->owner,
		    session->lease);
		session->lease = 0;
	}
	reply.tag = status ? bsd_power_v1_Power_Uninhibit_Result_err_tag :
	    bsd_power_v1_Power_Uninhibit_Result_response_tag;
	if (status)
		reply.value.err = status;
	completed(session, connection, POWERCMP_OP_UNINHIBIT, status,
	    bsd_power_v1_Power_Uninhibit_reply(connection, request, &reply));
}

static void
suspend(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_power_v1_SleepState *value)
{
	struct session *session = argument;
	struct bsd_power_v1_Power_Suspend_Result reply = { 0 };
	int state, status = 0;

	if (!ready(session, connection, POWERCMP_OP_SUSPEND))
		return;
	/* Policy first, then the state range, as before the FIDL migration. */
	if (!powercmp_config_permits_suspend(session->config, session->label))
		status = EPERM;
	else if (value->state < 1 || value->state > 5)
		status = EINVAL;
	else if (g_leases != NULL && service_lease_count(g_leases) != 0)
		status = EBUSY;
	else if (g_acpi_fd < 0)
		status = ENODEV;
	else {
		state = (int)value->state;
		if (ioctl(g_acpi_fd, ACPIIO_REQSLPSTATE, &state) == -1)
			status = errno;
		else {
			BSDPOWER_PROBE_SUSPEND(session->label, state);
			syslog(LOG_NOTICE, "suspend to S%d requested by %s",
			    state, session->label);
		}
	}
	reply.tag = status ? bsd_power_v1_Power_Suspend_Result_err_tag :
	    bsd_power_v1_Power_Suspend_Result_response_tag;
	if (status)
		reply.value.err = status;
	completed(session, connection, POWERCMP_OP_SUSPEND, status,
	    bsd_power_v1_Power_Suspend_reply(connection, request, &reply));
}

/* Bind a FIDL server to an accepted descriptor; consumes fd on every path. */
static int
session_bind(struct session *session, int fd)
{
	static const struct bsd_power_v1_Power_server handlers = {
		.GetProtocolInfo = protocol_info,
		.States = states,
		.Suspend = suspend,
		.Inhibit = inhibit,
		.Uninhibit = uninhibit,
		.Inhibitors = inhibitors
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	int error;

	/* One request at a time; no descriptors are part of this protocol. */
	options.max_pending_requests = 1;
	options.max_queued_messages = 16;
	options.max_queued_bytes = 4096;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(fd, FIDL_BSD_SERVER,
	    &options, &session->connection);
	if (error != 0) {
		(void)close(fd);
		return (errno = error, -1);
	}
	error = bsd_power_v1_Power_bind(session->connection, &handlers,
	    session);
	if (error != 0)
		return (errno = error, -1);
	return (0);
}

static void
session_close(struct session *s)
{
	if (s->connection != NULL)
		fidl_bsd_connection_destroy(s->connection);
	if (g_leases != NULL)
		service_lease_release_owner(g_leases, s->owner);
	memset(s, 0, sizeof(*s));
}

#ifdef BSDPOWER_TESTING
static int
serve_session(int fd, const char *label, const struct powercmp_config *config)
{
	struct session session;

	if (fd < 0 || label == NULL || label[0] == '\0' || config == NULL)
		return (errno = EINVAL, -1);
	memset(&session, 0, sizeof(session));
	session.label = label;
	session.config = config;
	session.owner = 1;
	if (session_bind(&session, fd) == -1) {
		session_close(&session);
		return (1);
	}
	while (fidl_bsd_connection_poll(session.connection, -1) == 0)
		;
	session_close(&session);
	return (0);
}

/*
 * Test entrypoints.  Expose the per-session FIDL server and the two
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
	struct fidl_bsd_connection_slot slots[64];
	struct service_health health = { 0 };
	struct service_identity identity;
	size_t i, slot, matching;
	int error, fd, ready, kq, result = -1;
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
			if (sessions[i].connection != NULL &&
			    sessions[i].lease == 0 &&
			    service_monotime_ms() - sessions[i].last_ms >=
				30000)
				session_close(&sessions[i]);
			slots[i].connection = sessions[i].connection;
		}
		error = fidl_bsd_connections_wait(kq, slots, 64,
		    service_listener_fd(listener), 250, &ready);
		if (error != 0) {
			errno = error;
			break;
		}
		for (i = 0; i < 64; i++) {
			if (slots[i].error != 0) {
				service_health_record(&health, slots[i].error);
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
			if (sessions[i].connection == NULL) {
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
		if (session_bind(s, fd) == -1) {
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
