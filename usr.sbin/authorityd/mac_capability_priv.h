/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Private header shared between mac_capability_*.c files in authorityd.
 * Not for external use.
 */

#ifndef MAC_CAPABILITY_PRIV_H
#define MAC_CAPABILITY_PRIV_H

#include <sys/param.h>

#include <dev/mac_capability/mac_capability_capprotect_proto.h>

#include <stdio.h>
#include <string.h>

#include "authorityd.h"

/* Service fd variables (defined in mac_capability_setup.c). */
extern int	mac_capability_fd;
extern int	mac_capability_isolation_fd;
extern int	mac_capability_system_fd;
extern int	mac_capability_capprotect_fd;

/* Internal helpers used by multiple mac_capability_*.c files. */
int	mac_capability_svc_connect(const char *name);
int	mac_capability_confine_authority_fd(int fd, const char *name);
int	mac_capability_do_call(int fd, const void *req, size_t reqlen,
	    void *reply, size_t replylen);
int	mac_capability_do_call_fds(int fd, const void *req, size_t reqlen,
	    const int *req_fds, size_t req_nfds, void *reply, size_t replylen,
	    int *reply_fds, size_t reply_nfds);

/* Claims lifecycle (mac_capability_claims.c), called from mac_capability_setup.c. */
int	isolate_resources(void);
int	apply_integrity(void);
int	apply_signal_shield(void);
int	claim_system_gates(void);

/* Claim/release primitives (mac_capability_claims.c). */
int	mac_capability_claim_path(const char *path);
int	mac_capability_claim_net(const struct ort_net_claim *nc);
int	mac_capability_claim_vsock(const struct ort_vsock_claim *vc);
int	mac_capability_claim_system_gate_bits(uint32_t gates);
int	mac_capability_release_path(const char *path);
int	mac_capability_release_net(const struct ort_net_claim *nc);
int	mac_capability_release_vsock(const struct ort_vsock_claim *vc);
int	mac_capability_release_system_gates(uint32_t gates);

/* --- Shared inline helpers for claim comparison/formatting --- */

static inline void
net_claim_port_string(const struct ort_net_claim *nc, char *buf, size_t len)
{

	if (nc->port_min == 0 && nc->port_max == UINT16_MAX)
		strlcpy(buf, "*", len);
	else if (nc->port_min == nc->port_max)
		snprintf(buf, len, "%u", nc->port_min);
	else
		snprintf(buf, len, "%u-%u", nc->port_min, nc->port_max);
}

/* Integrity flag table (shared between mac_capability_claims.c and mac_capability_status.c). */
static const struct {
	uint32_t	flag;
	const char	*name;
} integrity_flag_names[] = {
	{ CP_SF_PTRACE,		"ptrace" },
	{ CP_SF_SIGNAL,		"signal" },
	{ CP_SF_SIGKILL,	"sigkill" },
	{ CP_SF_SIGCONT,	"sigcont" },
	{ CP_SF_VISIBLE,	"visible" },
	{ CP_SF_WAIT,		"wait" },
	{ CP_SF_SCHED,		"sched" },
	{ CP_SF_CORE,		"core" },
	{ CP_SF_KTRACE,		"ktrace" },
};

#endif /* MAC_CAPABILITY_PRIV_H */
