/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_accounting — capability service for resource ledger operations.
 *
 * Charge, release, and enforce resource limits on a process via
 * CAP_RT_CALL with an attached procdesc fd.  If no fd is attached,
 * operates on the caller.
 *
 * This is a sync-only (co_call) service.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/racct.h>
#include <sys/rctl.h>

#include "cap_rt.h"
#include "cap_rt_accounting_proto.h"


/* ----------------------------------------------------------------
 * Operation handlers
 * ---------------------------------------------------------------- */

static int
acct_op_charge(struct proc *p, const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct acct_charge_request *cr = req;
	struct acct_reply *rp = reply;

	if (reqlen < sizeof(*cr) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	if (cr->resource > RACCT_MAX)
		return (EINVAL);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	memset(rp, 0, sizeof(*rp));

#ifdef RACCT
	int error;

	/*
	 * racct_add/sub/set require PROC_LOCK to be held.
	 * They acquire RACCT_LOCK internally.
	 */
	switch (cr->op) {
	case ACCT_OP_CHARGE:
		error = racct_add(p, cr->resource, cr->amount);
		rp->status = (error == 0) ?
		    ACCT_STATUS_OK : ACCT_STATUS_DENIED;
		break;
	case ACCT_OP_RELEASE:
		racct_sub(p, cr->resource, cr->amount);
		rp->status = ACCT_STATUS_OK;
		break;
	case ACCT_OP_SET:
		error = racct_set(p, cr->resource, cr->amount);
		rp->status = (error == 0) ?
		    ACCT_STATUS_OK : ACCT_STATUS_DENIED;
		break;
	default:
		return (EINVAL);
	}
#else
	rp->status = ACCT_STATUS_ERR;
#endif

	return (0);
}

#ifdef RCTL
static int
acct_action_to_rctl(uint32_t action, uint32_t signal)
{

	switch (action) {
	case ACCT_RULE_DENY:
		return (RCTL_ACTION_DENY);
	case ACCT_RULE_LOG:
		return (RCTL_ACTION_LOG);
	case ACCT_RULE_THROTTLE:
		return (RCTL_ACTION_THROTTLE);
	case ACCT_RULE_SIGNAL:
		if (signal < 1 || signal > _SIG_MAXSIG)
			return (-1);
		return ((int)signal);
	default:
		return (-1);
	}
}

static uint32_t
rctl_action_to_acct(int rctl_action, uint32_t *signalp)
{

	*signalp = 0;
	if (rctl_action == RCTL_ACTION_DENY)
		return (ACCT_RULE_DENY);
	if (rctl_action == RCTL_ACTION_LOG)
		return (ACCT_RULE_LOG);
	if (rctl_action == RCTL_ACTION_THROTTLE)
		return (ACCT_RULE_THROTTLE);
	if (rctl_action >= 1 &&
	    rctl_action <= RCTL_ACTION_SIGNAL_MAX) {
		*signalp = (uint32_t)rctl_action;
		return (ACCT_RULE_SIGNAL);
	}
	return (0);
}
#endif /* RCTL */

#ifdef RCTL
static uint32_t
acct_error_status(int error)
{

	switch (error) {
	case 0:
		return (ACCT_STATUS_OK);
	case EPERM:
	case EACCES:
		return (ACCT_STATUS_EPERM);
	default:
		return (ACCT_STATUS_ERR);
	}
}
#endif

static int
acct_op_rctl_rule(struct proc *p, const void *req, size_t reqlen,
    void *reply, size_t *replylenp, bool add)
{
	const struct acct_rule_request *rr = req;
	struct acct_reply *rp = reply;

	if (reqlen < sizeof(*rr) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	memset(rp, 0, sizeof(*rp));

#ifdef RCTL
	{
		struct rctl_rule *rule;
		int rctl_action;
		int error;

		if (rr->resource > RACCT_MAX) {
			rp->status = ACCT_STATUS_ERR;
			return (0);
		}

		rctl_action = acct_action_to_rctl(rr->action, rr->signal);
		if (rctl_action < 0) {
			rp->status = ACCT_STATUS_ERR;
			return (0);
		}

		PROC_LOCK_ASSERT(p, MA_OWNED);

		/*
		 * Drop PROC_LOCK before allocating — rctl_rule_alloc
		 * with M_WAITOK can sleep.  Hold the proc with _PHOLD
		 * to prevent it from being freed.
		 */
		if (p->p_flag & P_WEXIT) {
			rp->status = ACCT_STATUS_DEAD;
			return (0);
		}
		_PHOLD(p);
		PROC_UNLOCK(p);

		rule = rctl_rule_alloc(M_WAITOK | M_ZERO);
		rule->rr_subject_type = RCTL_SUBJECT_TYPE_PROCESS;
		rule->rr_subject.rs_proc = p;
		rule->rr_per = RCTL_SUBJECT_TYPE_PROCESS;
		rule->rr_resource = rr->resource;
		rule->rr_action = rctl_action;
		rule->rr_amount = rr->limit;

		error = add ? rctl_rule_add(rule) : rctl_rule_remove(rule);
		rctl_rule_release(rule);
		rp->status = acct_error_status(error);

		PROC_LOCK(p);
		_PRELE(p);
	}
#else
	rp->status = ACCT_STATUS_ERR;
#endif

	return (0);
}

static int
acct_op_get_rules(struct proc *p, void *reply, size_t *replylenp)
{
	struct acct_rules_reply *rp = reply;

	if (*replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	memset(rp, 0, sizeof(*rp));

#ifdef RCTL
	{
		struct rctl_rule_link *link;
		struct rctl_rule *rule;
		int n = 0;

		PROC_LOCK_ASSERT(p, MA_OWNED);

		if (p->p_racct != NULL) {
			RACCT_LOCK();
			LIST_FOREACH(link, &p->p_racct->r_rule_links,
			    rrl_next) {
				if (n >= ACCT_MAX_RULES)
					break;
				rule = link->rrl_rule;
				if (rule->rr_subject_type !=
				    RCTL_SUBJECT_TYPE_PROCESS)
					continue;
				rp->rules[n].resource = rule->rr_resource;
				rp->rules[n].action =
				    rctl_action_to_acct(rule->rr_action,
				    &rp->rules[n].signal);
				rp->rules[n].limit = rule->rr_amount;
				n++;
			}
			RACCT_UNLOCK();
		}
		rp->nrules = n;
		rp->status = ACCT_STATUS_OK;
	}
#else
	rp->status = ACCT_STATUS_ERR;
#endif

	return (0);
}

/* ----------------------------------------------------------------
 * co_call handler
 * ---------------------------------------------------------------- */

static int
accounting_call(struct cap_rt_instance *s __unused,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps __unused, int nfds,
    void *reply, size_t *replylenp,
    struct file **reply_fds __unused, int *reply_nfdsp __unused,
    void *arg __unused)
{
	const struct acct_charge_request *hdr;
	struct proc *p;
	int error;

	if (reqlen < sizeof(uint32_t))
		return (EINVAL);

	hdr = (const struct acct_charge_request *)req;

	/*
	 * No Capsicum rights check on the attached procdesc.
	 * Authority comes from holding the accounting service fd.
	 * The procdesc is an opaque target identifier.
	 */
	error = cap_rt_resolve_proc(fds, nfds, &p);
	if (error == ESRCH) {
		if (*replylenp >= sizeof(uint32_t)) {
			*(uint32_t *)reply = ACCT_STATUS_DEAD;
			*replylenp = sizeof(uint32_t);
			return (0);
		}
		return (error);
	}
	if (error != 0)
		return (error);

	/* p is PROC_LOCKed. */
	switch (hdr->op) {
	case ACCT_OP_CHARGE:
	case ACCT_OP_RELEASE:
	case ACCT_OP_SET:
		error = acct_op_charge(p, req, reqlen, reply, replylenp);
		break;
	case ACCT_OP_ADD_RULE:
		error = acct_op_rctl_rule(p, req, reqlen, reply, replylenp,
		    true);
		break;
	case ACCT_OP_REMOVE_RULE:
		error = acct_op_rctl_rule(p, req, reqlen, reply, replylenp,
		    false);
		break;
	case ACCT_OP_GET_RULES:
		error = acct_op_get_rules(p, reply, replylenp);
		break;
	default:
		error = EINVAL;
		break;
	}

	PROC_UNLOCK(p);
	return (error);
}

/* ----------------------------------------------------------------
 * Service registration
 * ---------------------------------------------------------------- */

static struct cap_rt_ops accounting_ops = {
	.co_call = accounting_call,
};

static struct cap_rt_service *accounting_svc;

static int
cap_rt_accounting_modevent(module_t mod __unused, int type,
    void *data __unused)
{
	struct cap_rt_service_params params;
	int error;

	switch (type) {
	case MOD_LOAD:
		memset(&params, 0, sizeof(params));
		params.name = "accounting";
		params.ops = &accounting_ops;
		error = cap_rt_service_create(&params, &accounting_svc);
		if (error != 0)
			printf("cap_rt_accounting: create failed: %d\n",
			    error);
		return (error);
	case MOD_UNLOAD:
		if (accounting_svc != NULL)
			cap_rt_service_destroy(accounting_svc);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_accounting_mod = {
	"cap_rt_accounting",
	cap_rt_accounting_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt_accounting, cap_rt_accounting_mod, SI_SUB_PSEUDO,
    SI_ORDER_ANY);
MODULE_DEPEND(cap_rt_accounting, cap_rt, 1, 1, 1);
