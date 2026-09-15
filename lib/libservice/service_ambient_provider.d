/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the libservice ambient discovery path.  Each probe exposes
 * one step of a process installing its OWN private lookup channel with switchboard
 * (docs/capability-ambient-lookup-per-process.md P2), so the fail-soft fallback
 * to the inherited shared channel is observable in production rather than
 * silent.  Trace with:  dtrace -n 'service_ambient*:::'
 */
provider service_ambient {
	/* mac_capability_channel_create() returned: create_errno==0 -> a pair. */
	probe reg__create(int create_errno);
	/* REGISTER send over the shared channel finished: send_ok (1/0). */
	probe reg__send(int send_ok);
	/* ACK receive on the private endpoint finished: ack_ok (1/0). */
	probe reg__ack(int ack_ok);
	/*
	 * Final decision: use_private (1 -> the process now has a private lookup
	 * channel; 0 -> fell soft to the inherited shared channel), with the three
	 * inputs that produced it so a fallback's cause is always attributable.
	 */
	probe reg__result(int use_private, int create_errno, int send_ok,
	    int ack_ok);
	/* service_elevate(3): requested anointment name at entry ... */
	probe elevate__start(const char *name);
	/* ... and at every exit with the outcome (0 or errno).  No password. */
	probe elevate__done(const char *name, int error);
};
