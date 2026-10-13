/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the libservice ambient discovery path.  Each probe exposes
 * one step of a process installing its OWN private lookup channel with switchboard
 * (docs/book/src/plane/discovery-and-lookup.md P2), so the fail-soft fallback
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
};

/* Shared runtime policy; compiled with the ambient provider in one DOF object. */
/* SPDX-License-Identifier: BSD-2-Clause */
provider service_runtime {
	probe retry__scheduled(uintptr_t a0, uint32_t a1, uint64_t a2);
	probe retry__recovered(uintptr_t a0, uint32_t a1);
	probe health__change(uintptr_t a0, int a1, uint64_t a2);
	probe budget__rejected(int a0, uint32_t a1);
	probe budget__expired(uint64_t a0);
	probe lease__limit(uint64_t a0, uint64_t a1, int a2);
};
