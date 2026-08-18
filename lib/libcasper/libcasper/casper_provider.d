/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the Casper userland capability broker.  This is the
 * userspace analogue of the in-kernel "capsicum" provider: every
 * capability-mediated request that a sandboxed process sends to a Casper
 * service funnels through service_message(), and its allow/deny outcome is
 * carried by "error" (0 == allowed).
 */
provider casper {
	/* A request arrived on a service connection: service name, command. */
	probe cmd__dispatch(const char *service, const char *cmd);
	/* A connection narrowed its limits: service name, result. */
	probe limit__set(const char *service, int error);
	/* Final decision for a request: service name, command, result. */
	probe cmd__return(const char *service, const char *cmd, int error);
	/* A process opened a capability channel to a service: name, result. */
	probe service__open(const char *service, int error);
};
