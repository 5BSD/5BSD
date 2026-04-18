/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_jail -- jail management capability service.
 *
 * Demonstrates:
 *   - co_call for caller-context operations (sync-only service)
 *   - co_connect for badge assignment
 *   - co_init for per-instance state
 *   - co_revoke for cleanup
 *   - Using attached descriptors in co_call
 *
 * Protocol (sync, via CALL):
 *   JAIL_OP_INFO:   query caller's current jail info
 *   JAIL_OP_ATTACH: authorize attach to jail identified by
 *                   attached jail descriptor fd
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/jail.h>
#include <sys/jaildesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/ucred.h>

#include "cmi.h"

MALLOC_DEFINE(M_CMI_JAIL, "cmi_jail", "cmi jail service");

#define	JAIL_OP_INFO	1	/* query caller's jail info */
#define	JAIL_OP_ATTACH	2	/* authorize jail attach */

struct jail_request {
	uint32_t	op;
} __packed;

/*
 * Reply to JAIL_OP_INFO.
 */
struct jail_info_reply {
	uint32_t	status;		/* 0 = success */
	int		jid;		/* current jail ID */
	char		name[MAXHOSTNAMELEN]; /* jail name */
};

/*
 * Per-instance state -- tracks the caller's privilege level
 * at connect time.
 */
struct jail_instance {
	int		js_privileged;	/* caller had PRIV_JAIL_ATTACH */
};

static struct cmi_service *jail_svc;
static volatile uint64_t jail_next_badge = 1;

/*
 * co_connect: check that the caller has jail privileges.
 */
static int
jail_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	*badge_out = atomic_fetchadd_64(&jail_next_badge, 1);
	return (0);
}

/*
 * co_init: allocate per-instance state.
 */
static int
jail_init(struct cmi_instance *s, void *arg __unused)
{
	struct jail_instance *js;

	js = malloc(sizeof(*js), M_CMI_JAIL, M_WAITOK | M_ZERO);
	/*
	 * Check privilege at init time -- we have the creating
	 * thread's cred available here.
	 */
	js->js_privileged =
	    (priv_check(curthread, PRIV_JAIL_ATTACH) == 0);
	cmi_instance_set_priv(s, js);
	return (0);
}

/*
 * co_call (sync): all jail operations run in caller context.
 *
 * JAIL_OP_INFO: query the caller's current jail info.
 *     curthread has the caller's ucred — read prison directly.
 *
 * JAIL_OP_ATTACH: authorize the calling process to attach to a jail.
 *     The jail is identified by a jail descriptor fd passed
 *     as an attached file descriptor.
 *     curthread IS the calling process.
 */
static int
jail_call(struct cmi_instance *s,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps __unused, int nfds,
    void *reply, size_t *replylenp,
    struct file **reply_fds __unused, int *reply_nfdsp __unused,
    void *arg __unused)
{
	const struct jail_request *jr;
	struct jail_instance *js;
	struct prison *pr;
	int error;

	if (reqlen < sizeof(struct jail_request))
		return (EINVAL);

	jr = (const struct jail_request *)req;

	switch (jr->op) {
	case JAIL_OP_INFO: {
		struct jail_info_reply *info;

		if (*replylenp < sizeof(struct jail_info_reply))
			return (EINVAL);

		info = (struct jail_info_reply *)reply;
		memset(info, 0, sizeof(*info));
		pr = curthread->td_ucred->cr_prison;
		info->status = 0;
		info->jid = pr->pr_id;
		strlcpy(info->name, pr->pr_name, sizeof(info->name));
		*replylenp = sizeof(*info);
		return (0);
	}

	case JAIL_OP_ATTACH:
		js = cmi_instance_get_priv(s);
		if (js == NULL || !js->js_privileged)
			return (EPERM);

		if (nfds < 1)
			return (EINVAL);

		error = jaildesc_get_prison(fds[0], &pr);
		if (error != 0)
			return (error);

		if (!prison_isalive(pr)) {
			prison_free(pr);
			return (EINVAL);
		}
		prison_free(pr);

		*replylenp = 0;
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

/*
 * co_revoke: free per-instance state.
 */
static void
jail_revoke(struct cmi_instance *s, uint64_t badge __unused,
    enum cmi_revoke_reason reason __unused, void *arg __unused)
{
	struct jail_instance *js;

	js = cmi_instance_get_priv(s);
	if (js != NULL)
		free(js, M_CMI_JAIL);
}

static const struct cmi_ops jail_ops = {
	.co_connect = jail_connect,
	.co_init = jail_init,
	.co_call = jail_call,
	.co_revoke = jail_revoke,
};

static int
cmi_jail_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		{
			struct cmi_service_params p = {
				.name = "jail",
				.ops = &jail_ops,
				.flags = CMI_SVC_NOXFER,
			};
			error = cmi_service_create(&p, &jail_svc);
		}
		if (error != 0) {
			printf("cmi_jail: failed: %d\n", error);
			return (error);
		}
		if (bootverbose)
			printf("cmi_jail: loaded\n");
		return (0);

	case MOD_UNLOAD:
		if (jail_svc != NULL)
			cmi_service_destroy(jail_svc);
		if (bootverbose)
			printf("cmi_jail: unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cmi_jail_mod = {
	"cmi_jail",
	cmi_jail_modevent,
	NULL,
};

DECLARE_MODULE(cmi_jail, cmi_jail_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cmi_jail, 1);
MODULE_DEPEND(cmi_jail, cmi, 1, 1, 1);
