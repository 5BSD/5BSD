/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_token — kernel-gated authorization token.
 *
 * Sync-only CMI service.  An issuer creates tokens that represent
 * authorization.  Holding a token fd proves the kernel granted it.
 * Tokens can be labeled, validated, and revoked.
 *
 * The issuer connects to "token" and calls TOKEN_CREATE to mint
 * a new token (returned as reply fd).  The token can be passed
 * to other processes.  Any holder can call TOKEN_VALIDATE to
 * check if the token is still live and get its label.
 *
 * Tokens cannot be forged — only the kernel issues them.
 * Tokens cannot be duplicated — dup shares the same instance,
 * so revoking one copy revokes all.
 *
 * Protocol (sync, via CALL):
 *   TOKEN_CREATE:   create a new token (returns token fd)
 *   TOKEN_VALIDATE: check if token is live, get label
 *   TOKEN_REVOKE_TOKEN: revoke a specific token
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
#include <sys/ucred.h>

#include "cmi.h"
#include "cmi_label.h"
#include "cmi_token_proto.h"

MALLOC_DEFINE(M_CMI_TOKEN, "cmi_token", "cmi token service");

#define	TOKEN_ROLE_ISSUER	1
#define	TOKEN_ROLE_TOKEN	2

struct token_priv {
	struct mtx	tp_mtx;
	int		tp_role;
	int		tp_valid;	/* 1 = live */
	uid_t		tp_issuer_uid;
	uint64_t	tp_issuer_nonce;
	char		tp_label[TOKEN_LABEL_MAX];
};

static struct cmi_service *token_svc;
static volatile uint64_t token_next_badge = 1;

static int
token_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	*badge_out = atomic_fetchadd_64(&token_next_badge, 1);
	return (0);
}

static int
token_init(struct cmi_instance *s, void *arg __unused)
{
	struct token_priv *tp;

	tp = malloc(sizeof(*tp), M_CMI_TOKEN, M_WAITOK | M_ZERO);
	mtx_init(&tp->tp_mtx, "cmi_token_priv", NULL, MTX_DEF);
	cmi_instance_set_priv(s, tp);
	return (0);
}

static int
token_call(struct cmi_instance *s,
    const void *req, size_t reqlen,
    struct file **fds __unused, struct filecaps *fcaps __unused,
    int nfds __unused,
    void *reply, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
    void *arg __unused)
{
	const struct token_request *tr;
	struct token_priv *tp;

	if (reqlen < sizeof(struct token_request))
		return (EINVAL);

	tr = (const struct token_request *)req;
	tp = cmi_instance_get_priv(s);
	if (tp == NULL)
		return (EINVAL);

	switch (tr->op) {
	case TOKEN_OP_CREATE: {
		const struct token_create_request *cr;
		struct file *token_fp;
		struct token_priv *child_tp;
		int error;

		/* Only issuers (or fresh instances) can create. */
		mtx_lock(&tp->tp_mtx);
		if (tp->tp_role == TOKEN_ROLE_TOKEN) {
			mtx_unlock(&tp->tp_mtx);
			return (EINVAL);
		}
		tp->tp_role = TOKEN_ROLE_ISSUER;
		mtx_unlock(&tp->tp_mtx);

		if (reqlen < sizeof(struct token_create_request))
			return (EINVAL);
		if (*reply_nfdsp < 1)
			return (EINVAL);

		cr = (const struct token_create_request *)req;

		error = cmi_mint_fp(token_svc, 0, &token_fp);
		if (error != 0)
			return (error);

		child_tp = cmi_instance_get_priv(token_fp->f_data);
		if (child_tp != NULL) {
			mtx_lock(&child_tp->tp_mtx);
			child_tp->tp_role = TOKEN_ROLE_TOKEN;
			child_tp->tp_valid = 1;
			child_tp->tp_issuer_uid = curthread->td_ucred->cr_uid;
			child_tp->tp_issuer_nonce =
			    cmi_proc_nonce(curthread->td_ucred);
			memcpy(child_tp->tp_label, cr->label,
			    TOKEN_LABEL_MAX - 1);
			child_tp->tp_label[TOKEN_LABEL_MAX - 1] = '\0';
			mtx_unlock(&child_tp->tp_mtx);
		}

		reply_fds[0] = token_fp;
		*reply_nfdsp = 1;
		*replylenp = 0;
		return (0);
	}

	case TOKEN_OP_VALIDATE: {
		struct token_validate_reply *vr;

		if (*replylenp < sizeof(struct token_validate_reply)) {
			*replylenp = sizeof(struct token_validate_reply);
			return (EMSGSIZE);
		}

		vr = (struct token_validate_reply *)reply;
		memset(vr, 0, sizeof(*vr));

		mtx_lock(&tp->tp_mtx);
		if (tp->tp_role != TOKEN_ROLE_TOKEN) {
			mtx_unlock(&tp->tp_mtx);
			return (EINVAL);	/* not a token */
		}
		vr->valid = tp->tp_valid;
		vr->issuer_uid = tp->tp_issuer_uid;
		vr->issuer_nonce = tp->tp_issuer_nonce;
		strlcpy(vr->label, tp->tp_label, sizeof(vr->label));
		mtx_unlock(&tp->tp_mtx);

		*replylenp = sizeof(*vr);
		return (0);
	}

	case TOKEN_OP_REVOKE:
		mtx_lock(&tp->tp_mtx);
		if (tp->tp_role != TOKEN_ROLE_TOKEN) {
			mtx_unlock(&tp->tp_mtx);
			return (EINVAL);
		}
		tp->tp_valid = 0;
		mtx_unlock(&tp->tp_mtx);
		*replylenp = 0;
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static void
token_revoke(struct cmi_instance *s, uint64_t badge __unused,
    enum cmi_revoke_reason reason __unused, void *arg __unused)
{
	struct token_priv *tp;

	tp = cmi_instance_get_priv(s);
	if (tp == NULL)
		return;
	mtx_destroy(&tp->tp_mtx);
	free(tp, M_CMI_TOKEN);
}

static const struct cmi_ops token_ops = {
	.co_connect = token_connect,
	.co_init = token_init,
	.co_call = token_call,
	.co_revoke = token_revoke,
};

static int
cmi_token_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		{
			struct cmi_service_params p = {
				.name = "token",
				.ops = &token_ops,
			};
			error = cmi_service_create(&p, &token_svc);
		}
		if (error != 0) {
			printf("cmi_token: failed: %d\n", error);
			return (error);
		}
		if (bootverbose)
			printf("cmi_token: loaded\n");
		return (0);

	case MOD_UNLOAD:
		if (token_svc != NULL)
			cmi_service_destroy(token_svc);
		if (bootverbose)
			printf("cmi_token: unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cmi_token_mod = {
	"cmi_token",
	cmi_token_modevent,
	NULL,
};

DECLARE_MODULE(cmi_token, cmi_token_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cmi_token, 1);
MODULE_DEPEND(cmi_token, cmi, 1, 1, 1);
