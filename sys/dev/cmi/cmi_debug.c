/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_debug — process debug protection capability.
 *
 * Sync-only CMI service.  Calling DEBUG_SHIELD protects the calling
 * process from ptrace and signals via MACF.  DEBUG_MINT creates a
 * debug token that authorizes a specific debugger to override the
 * shield.  Closing the shield fd removes protection.
 *
 * Protocol (sync, via CALL):
 *   DEBUG_SHIELD:   protect calling process
 *   DEBUG_MINT:     create debug token (returned as reply fd)
 *   DEBUG_ACTIVATE: called on token fd, authorizes caller to debug
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "cmi.h"

MALLOC_DEFINE(M_CMI_DEBUG, "cmi_debug", "cmi debug service");

#define	DEBUG_OP_SHIELD		1	/* shield calling process */
#define	DEBUG_OP_MINT		2	/* create debug token */
#define	DEBUG_OP_ACTIVATE	3	/* authorize caller (on token fd) */

struct debug_request {
	uint32_t	op;
} __packed;

/*
 * Per-instance state.
 *
 * Shield instances track the shielded pid.
 * Token instances track the target pid they authorize access to.
 */
struct debug_priv {
	struct mtx	dp_mtx;		/* per-instance lock */
	pid_t		dp_target;	/* shielded pid (shield) or target (token) */
	int		dp_is_token;	/* 1 if this is a debug token */
	int		dp_active;	/* 1 if shield/auth is active */
};

/*
 * Global tables — protected by debug_sx.
 */
static struct sx debug_sx;

/* Shield table: pids that are shielded. */
struct shield_entry {
	LIST_ENTRY(shield_entry) se_link;
	pid_t		se_pid;
};
static LIST_HEAD(, shield_entry) debug_shields =
    LIST_HEAD_INITIALIZER(debug_shields);

/* Auth table: (debugger_pid, target_pid) pairs. */
struct auth_entry {
	LIST_ENTRY(auth_entry) ae_link;
	pid_t		ae_debugger;
	pid_t		ae_target;
	struct cmi_instance *ae_inst;
};
static LIST_HEAD(, auth_entry) debug_auths =
    LIST_HEAD_INITIALIZER(debug_auths);

static struct cmi_service *debug_svc;
static volatile uint64_t debug_next_badge = 1;

static int
debug_is_shielded(pid_t pid)
{
	struct shield_entry *se;

	sx_assert(&debug_sx, SA_LOCKED);
	LIST_FOREACH(se, &debug_shields, se_link) {
		if (se->se_pid == pid)
			return (1);
	}
	return (0);
}

static int
debug_is_authorized(pid_t debugger, pid_t target)
{
	struct auth_entry *ae;

	sx_assert(&debug_sx, SA_LOCKED);
	LIST_FOREACH(ae, &debug_auths, ae_link) {
		if (ae->ae_debugger == debugger && ae->ae_target == target)
			return (1);
	}
	return (0);
}

static void
debug_shield_add(pid_t pid)
{
	struct shield_entry *se;

	sx_xlock(&debug_sx);
	if (!debug_is_shielded(pid)) {
		se = malloc(sizeof(*se), M_CMI_DEBUG, M_WAITOK);
		se->se_pid = pid;
		LIST_INSERT_HEAD(&debug_shields, se, se_link);
	}
	sx_xunlock(&debug_sx);
}

static void
debug_shield_remove(pid_t pid)
{
	struct shield_entry *se;
	struct auth_entry *ae, *ae_tmp;

	sx_xlock(&debug_sx);
	LIST_FOREACH(se, &debug_shields, se_link) {
		if (se->se_pid == pid) {
			LIST_REMOVE(se, se_link);
			free(se, M_CMI_DEBUG);
			break;
		}
	}
	/* Remove all auth entries for this target. */
	LIST_FOREACH_SAFE(ae, &debug_auths, ae_link, ae_tmp) {
		if (ae->ae_target == pid) {
			LIST_REMOVE(ae, ae_link);
			free(ae, M_CMI_DEBUG);
		}
	}
	sx_xunlock(&debug_sx);
}

static void
debug_auth_add(pid_t debugger, pid_t target, struct cmi_instance *inst)
{
	struct auth_entry *ae;

	sx_xlock(&debug_sx);
	ae = malloc(sizeof(*ae), M_CMI_DEBUG, M_WAITOK);
	ae->ae_debugger = debugger;
	ae->ae_target = target;
	ae->ae_inst = inst;
	LIST_INSERT_HEAD(&debug_auths, ae, ae_link);
	sx_xunlock(&debug_sx);
}

static void
debug_auth_remove_by_inst(struct cmi_instance *inst)
{
	struct auth_entry *ae, *ae_tmp;

	sx_xlock(&debug_sx);
	LIST_FOREACH_SAFE(ae, &debug_auths, ae_link, ae_tmp) {
		if (ae->ae_inst == inst) {
			LIST_REMOVE(ae, ae_link);
			free(ae, M_CMI_DEBUG);
		}
	}
	sx_xunlock(&debug_sx);
}

/*
 * co_connect: assign badge.
 */
static int
debug_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	*badge_out = atomic_fetchadd_64(&debug_next_badge, 1);
	return (0);
}

/*
 * co_init: allocate per-instance state.
 */
static int
debug_init(struct cmi_instance *s, void *arg __unused)
{
	struct debug_priv *dp;

	dp = malloc(sizeof(*dp), M_CMI_DEBUG, M_WAITOK | M_ZERO);
	mtx_init(&dp->dp_mtx, "cmi_debug_priv", NULL, MTX_DEF);
	cmi_instance_set_priv(s, dp);
	return (0);
}

/*
 * co_call: all operations are sync (caller context).
 */
static int
debug_call(struct cmi_instance *s,
    const void *req, size_t reqlen,
    struct file **fds __unused, struct filecaps *fcaps __unused, int nfds __unused,
    void *reply __unused, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
    void *arg __unused)
{
	const struct debug_request *dr;
	struct debug_priv *dp;

	if (reqlen < sizeof(struct debug_request))
		return (EINVAL);

	dr = (const struct debug_request *)req;
	dp = cmi_instance_get_priv(s);
	if (dp == NULL)
		return (EINVAL);

	mtx_lock(&dp->dp_mtx);

	switch (dr->op) {
	case DEBUG_OP_SHIELD:
		if (dp->dp_is_token) {
			mtx_unlock(&dp->dp_mtx);
			return (EINVAL);
		}
		if (dp->dp_active) {
			mtx_unlock(&dp->dp_mtx);
			return (0);
		}
		dp->dp_target = curthread->td_proc->p_pid;
		dp->dp_active = 1;
		mtx_unlock(&dp->dp_mtx);
		debug_shield_add(dp->dp_target);
		*replylenp = 0;
		return (0);

	case DEBUG_OP_MINT: {
		struct file *token_fp;
		struct debug_priv *tp;
		int error;

		if (dp->dp_is_token) {
			mtx_unlock(&dp->dp_mtx);
			return (EINVAL);
		}
		if (!dp->dp_active) {
			mtx_unlock(&dp->dp_mtx);
			return (EINVAL);
		}
		if (*reply_nfdsp < 1) {
			mtx_unlock(&dp->dp_mtx);
			return (EINVAL);
		}

		error = cmi_mint_fp(debug_svc, 0, &token_fp);
		if (error != 0) {
			mtx_unlock(&dp->dp_mtx);
			return (error);
		}

		tp = cmi_instance_get_priv(token_fp->f_data);
		if (tp != NULL) {
			mtx_lock(&tp->dp_mtx);
			tp->dp_is_token = 1;
			tp->dp_target = dp->dp_target;
			mtx_unlock(&tp->dp_mtx);
		}

		mtx_unlock(&dp->dp_mtx);
		reply_fds[0] = token_fp;
		*reply_nfdsp = 1;
		*replylenp = 0;
		return (0);
	}

	case DEBUG_OP_ACTIVATE:
		if (!dp->dp_is_token) {
			mtx_unlock(&dp->dp_mtx);
			return (EINVAL);
		}
		if (dp->dp_active) {
			mtx_unlock(&dp->dp_mtx);
			return (0);
		}
		dp->dp_active = 1;
		mtx_unlock(&dp->dp_mtx);
		debug_auth_add(curthread->td_proc->p_pid,
		    dp->dp_target, s);
		*replylenp = 0;
		return (0);

	default:
		mtx_unlock(&dp->dp_mtx);
		return (EOPNOTSUPP);
	}
}

/*
 * co_revoke: clean up shield or auth entries.
 */
static void
debug_revoke(struct cmi_instance *s, uint64_t badge __unused,
    enum cmi_revoke_reason reason __unused, void *arg __unused)
{
	struct debug_priv *dp;

	dp = cmi_instance_get_priv(s);
	if (dp == NULL)
		return;

	if (dp->dp_active) {
		if (dp->dp_is_token) {
			debug_auth_remove_by_inst(s);
		} else {
			debug_shield_remove(dp->dp_target);
		}
	}

	mtx_destroy(&dp->dp_mtx);
	free(dp, M_CMI_DEBUG);
}

static const struct cmi_ops debug_ops = {
	.co_connect = debug_connect,
	.co_init = debug_init,
	.co_call = debug_call,
	.co_revoke = debug_revoke,
};

/* ----------------------------------------------------------------
 * MACF policy — deny ptrace/signal on shielded processes
 * ---------------------------------------------------------------- */

static int
debug_mac_check_debug(struct ucred *cred, struct proc *p)
{
	pid_t caller_pid, target_pid;
	int denied;

	if (curthread->td_proc == NULL)
		return (0);	/* kernel thread, allow */

	target_pid = p->p_pid;
	caller_pid = curthread->td_proc->p_pid;

	sx_slock(&debug_sx);
	if (!debug_is_shielded(target_pid)) {
		sx_sunlock(&debug_sx);
		return (0);		/* not shielded, allow */
	}
	/* Shielded — check for debug authorization. */
	denied = !debug_is_authorized(caller_pid, target_pid);
	sx_sunlock(&debug_sx);

	return (denied ? EACCES : 0);
}

static int
debug_mac_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	pid_t caller_pid, target_pid;
	int denied;

	if (curthread->td_proc == NULL)
		return (0);	/* kernel thread, allow */

	/* Allow self-signal, SIGCONT, and SIGKILL (can't be blocked). */
	if (curthread->td_proc == p || signum == SIGCONT ||
	    signum == SIGKILL)
		return (0);

	target_pid = p->p_pid;
	caller_pid = curthread->td_proc->p_pid;

	sx_slock(&debug_sx);
	if (!debug_is_shielded(target_pid)) {
		sx_sunlock(&debug_sx);
		return (0);
	}
	denied = !debug_is_authorized(caller_pid, target_pid);
	sx_sunlock(&debug_sx);

	return (denied ? EACCES : 0);
}

static struct mac_policy_ops debug_mac_ops = {
	.mpo_proc_check_debug = debug_mac_check_debug,
	.mpo_proc_check_signal = debug_mac_check_signal,
};

MAC_POLICY_SET(&debug_mac_ops, mac_cmi_debug, "CMI debug shield",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static int
cmi_debug_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		sx_init(&debug_sx, "cmi_debug");
		{
			struct cmi_service_params p = {
				.name = "debug",
				.ops = &debug_ops,
			};
			error = cmi_service_create(&p, &debug_svc);
		}
		if (error != 0) {
			sx_destroy(&debug_sx);
			return (error);
		}
		if (bootverbose)
			printf("cmi_debug: loaded\n");
		return (0);

	case MOD_UNLOAD:
		/* Refuse unload if shields or auths are active. */
		sx_slock(&debug_sx);
		if (!LIST_EMPTY(&debug_shields) ||
		    !LIST_EMPTY(&debug_auths)) {
			sx_sunlock(&debug_sx);
			return (EBUSY);
		}
		sx_sunlock(&debug_sx);

		if (debug_svc != NULL)
			cmi_service_destroy(debug_svc);
		/* Clean up any remaining entries (defensive). */
		{
			struct shield_entry *se;
			struct auth_entry *ae;

			sx_xlock(&debug_sx);
			while ((se = LIST_FIRST(&debug_shields)) != NULL) {
				LIST_REMOVE(se, se_link);
				free(se, M_CMI_DEBUG);
			}
			while ((ae = LIST_FIRST(&debug_auths)) != NULL) {
				LIST_REMOVE(ae, ae_link);
				free(ae, M_CMI_DEBUG);
			}
			sx_xunlock(&debug_sx);
		}
		sx_destroy(&debug_sx);
		if (bootverbose)
			printf("cmi_debug: unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cmi_debug_mod = {
	"cmi_debug",
	cmi_debug_modevent,
	NULL,
};

DECLARE_MODULE(cmi_debug, cmi_debug_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cmi_debug, 1);
MODULE_DEPEND(cmi_debug, cmi, 1, 1, 1);
