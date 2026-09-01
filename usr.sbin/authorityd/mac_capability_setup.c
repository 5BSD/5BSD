/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * MAC_CAPABILITY core lifecycle for authorityd.
 *
 * Owns the static service fd variables and provides getter/setter
 * access for sibling mac_capability_*.c files.  Contains setup, teardown,
 * and the shared helpers mac_capability_svc_connect / mac_capability_do_call.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <dev/mac_capability/mac_capability_system_proto.h>
#include <dev/mac_capability/mac_capability_coalition_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <capability.h>

#include "authorityd.h"
#include "gates.h"
#include "probes.h"
#include "mac_capability_priv.h"

/* Service instance fds — shared across mac_capability_*.c files. */
int mac_capability_fd = -1;
int mac_capability_isolation_fd = -1;
int mac_capability_capprotect_fd = -1;
int mac_capability_system_fd = -1;

/*
 * Freeze an authorityd-only authority into this process.  The mechanism lives
 * in libcapability (capability_confine_fd); authorityd keeps the named log.
 */
int
mac_capability_confine_authority_fd(int fd, const char *name)
{

	if (capability_confine_fd(fd) == -1) {
		syslog(LOG_ERR, "confine %s fd: %m", name);
		return (-1);
	}
	return (0);
}

/* --- Shared helpers (thin wrappers over libcapability) --- */

/*
 * Perform an exact synchronous kernel-service call through libcapability.
 */
int
mac_capability_do_call_fds(int fd, const void *req, size_t reqlen,
    const int *req_fds, size_t req_nfds, void *reply, size_t replylen,
    int *reply_fds, size_t expected_reply_nfds)
{

	return (capability_service_call_fds(fd, req, reqlen, req_fds, req_nfds,
	    reply, replylen, reply_fds, expected_reply_nfds));
}

int
mac_capability_do_call(int fd, const void *req, size_t reqlen,
    void *reply, size_t replylen)
{

	return (capability_service_call(fd, req, reqlen, reply, replylen));
}

/*
 * Connect to a named mac_capability service on authorityd's device fd.
 */
int
mac_capability_svc_connect(const char *name)
{
	int fd;

	fd = capability_service_connect(mac_capability_fd, name);
	if (fd == -1)
		syslog(LOG_ERR, "mac_capability connect %s: %m", name);
	return (fd);
}

/* --- Setup / teardown --- */

/*
 * Initialize all mac_capability services.  Called once during startup.
 * All subsystems are required — authorityd must not start without
 * its full resource claim set and integrity protection.
 */
int
mac_capability_setup(void)
{

	mac_capability_fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (mac_capability_fd == -1) {
		syslog(LOG_ERR, "open /dev/mac_capability: %m");
		return (-1);
	}
	syslog(LOG_INFO, "opened /dev/mac_capability");

	if (isolate_resources() == -1) {
		syslog(LOG_ERR, "failed to connect isolation service");
		goto fail;
	}

	if (claim_system_gates() == -1) {
		syslog(LOG_ERR, "failed to claim system operations");
		goto fail;
	}

	if (apply_integrity() == -1) {
		syslog(LOG_ERR, "failed to activate integrity protection");
		goto fail;
	}

	/*
	 * None of authorityd's root authority, claims, or self-protection may be
	 * delegated or inherited by the service-manager child.  Ordinary
	 * FD_CLOEXEC is insufficient because it is mutable and acts only at
	 * exec, after the child has already inherited the descriptor.
	 */
	if (mac_capability_confine_authority_fd(mac_capability_fd,
	    "mac_capability control") == -1 ||
	    mac_capability_confine_authority_fd(mac_capability_isolation_fd,
	    "isolation") == -1 ||
	    mac_capability_confine_authority_fd(mac_capability_system_fd,
	    "system") == -1 ||
	    mac_capability_confine_authority_fd(mac_capability_capprotect_fd,
	    "capprotect") == -1)
		goto fail;

	return (0);

fail:
	mac_capability_teardown();
	return (-1);
}

/*
 * Release all mac_capability services.  Order matters: capprotect first
 * (removes integrity protection), then isolation (releases
 * claims), then the control device itself.
 */
void
mac_capability_teardown(void)
{

	if (mac_capability_capprotect_fd >= 0) {
		close(mac_capability_capprotect_fd);
		mac_capability_capprotect_fd = -1;
		syslog(LOG_INFO, "integrity protection released");
	}
	if (mac_capability_system_fd >= 0) {
		close(mac_capability_system_fd);
		mac_capability_system_fd = -1;
		syslog(LOG_INFO, "system gates released");
	}
	if (mac_capability_isolation_fd >= 0) {
		close(mac_capability_isolation_fd);
		mac_capability_isolation_fd = -1;
		syslog(LOG_INFO, "isolation claim released");
	}
	if (mac_capability_fd >= 0) {
		close(mac_capability_fd);
		mac_capability_fd = -1;
		syslog(LOG_INFO, "closed /dev/mac_capability");
	}
}

/*
 * Mint a new instance of a service from an existing instance fd.
 * Uses MAC_CAPABILITY_MINT_INSTANCE — the service must have MAC_CAPABILITY_SVC_MINTABLE.
 * Returns the new instance fd on success, -1 on failure.
 */
int
mac_capability_mint_instance(int instance_fd)
{
	struct mac_capability_mint_instance_args ma;

	memset(&ma, 0, sizeof(ma));
	if (ioctl(instance_fd, MAC_CAPABILITY_MINT_INSTANCE, &ma) == -1) {
		syslog(LOG_WARNING, "mac_capability_mint_instance: %m");
		return (-1);
	}
	if (fcntl(ma.fd, F_SETFD, FD_CLOEXEC) == -1) {
		close(ma.fd);
		return (-1);
	}
	return (ma.fd);
}

/*
 * Create a service instance for delegation to serviced.
 * Connects to the named service and returns the instance fd.
 */
int
mac_capability_connect_for_delegate(const char *name)
{

	return (mac_capability_svc_connect(name));
}
