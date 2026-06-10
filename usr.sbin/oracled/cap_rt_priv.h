/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Private header shared between cap_rt_*.c files in oracled.
 * Not for external use.
 */

#ifndef CAP_RT_PRIV_H
#define CAP_RT_PRIV_H

#include <sys/param.h>

#include <dev/cap_rt/cap_rt_capprotect_proto.h>

#include <stdio.h>
#include <string.h>

#include "oracled.h"

/* Service fd variables (defined in cap_rt_setup.c). */
extern int	cap_rt_fd;
extern int	cap_rt_isolation_fd;
extern int	cap_rt_system_fd;
extern int	cap_rt_capprotect_fd;

/* Internal helpers used by multiple cap_rt_*.c files. */
int	cap_rt_svc_connect(const char *name);
int	cap_rt_do_call(int fd, const void *req, size_t reqlen,
	    void *reply, size_t replylen);

/* Claims lifecycle (cap_rt_claims.c), called from cap_rt_setup.c. */
int	isolate_resources(void);
int	apply_integrity(void);
int	claim_system_gates(void);

/* Claim/release primitives (cap_rt_claims.c). */
int	cap_rt_claim_path(const char *path);
int	cap_rt_claim_net(const struct ort_net_claim *nc);
int	cap_rt_claim_jail(const struct oracled_jail_claim *jc);
int	cap_rt_claim_system_gate_bits(uint32_t gates);
int	cap_rt_release_path(const char *path);
int	cap_rt_release_net(const struct ort_net_claim *nc);
int	cap_rt_release_jail(const struct oracled_jail_claim *jc);
int	cap_rt_release_system_gates(uint32_t gates);

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

static inline void
jail_claim_string(const struct oracled_jail_claim *jc, char *buf, size_t len)
{

	if (jc->jid != 0 && jc->name[0] != '\0')
		snprintf(buf, len, "%s#%d", jc->name, jc->jid);
	else if (jc->jid != 0)
		snprintf(buf, len, "#%d", jc->jid);
	else
		strlcpy(buf, jc->name, len);
}

/* Integrity flag table (shared between cap_rt_claims.c and cap_rt_status.c). */
static const struct {
	uint32_t	flag;
	const char	*name;
} integrity_flag_names[] = {
	{ CP_SF_PTRACE,		"ptrace" },
	{ CP_SF_SIGNAL,		"signal" },
	{ CP_SF_VISIBLE,	"visible" },
	{ CP_SF_WAIT,		"wait" },
	{ CP_SF_SCHED,		"sched" },
	{ CP_SF_CORE,		"core" },
	{ CP_SF_KTRACE,		"ktrace" },
};

#endif /* CAP_RT_PRIV_H */
