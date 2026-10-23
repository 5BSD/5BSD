/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * OpenBSD interface send-queue disciplines (ifq(9), HFSC, FQ-CoDel) used
 * by pf queues.  Queue scheduling on 5BSD interfaces is not wired yet:
 * the disciplines report EOPNOTSUPP so a ruleset with queues fails to
 * load instead of loading without effect.
 */

#include "openbsd_compat.h"

#include <net/pfvar.h>
#include <net/hfsc.h>
#include <net/fq_codel.h>

const struct ifq_ops * const ifq_priq_ops = NULL;
const struct ifq_ops * const ifq_hfsc_ops = NULL;
const struct ifq_ops * const ifq_fqcodel_ops = NULL;

static void *
obsd_pfq_alloc(struct ifnet *ifp)
{
	return (NULL);
}

static int
obsd_pfq_addqueue(void *disc, struct pf_queuespec *q)
{
	return (EOPNOTSUPP);
}

static void
obsd_pfq_free(void *disc)
{
}

static int
obsd_pfq_qstats(struct pf_queuespec *q, void *buf, int *nbytes)
{
	return (EOPNOTSUPP);
}

static const struct pfq_ops obsd_pfq_unsupported = {
	.pfq_alloc = obsd_pfq_alloc,
	.pfq_addqueue = obsd_pfq_addqueue,
	.pfq_free = obsd_pfq_free,
	.pfq_qstats = obsd_pfq_qstats,
};
const struct pfq_ops * const pfq_hfsc_ops = &obsd_pfq_unsupported;
const struct pfq_ops * const pfq_fqcodel_ops = &obsd_pfq_unsupported;

void
hfsc_initialize(void)
{
}

void
obsd_ifq_attach(struct ifnet *ifp, const struct ifq_ops *ops, void *arg)
{
}
