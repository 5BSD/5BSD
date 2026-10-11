/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_test_keystore — test fixture: async key-value store
 *
 * Used by the ATF test suite to exercise async messaging, credential
 * access, and badges.  Not a production service.  Async only.
 *
 * Protocol (async via SENDMSG/RECVMSG):
 *   Request:  { uint32_t op; uint32_t keyid; uint8_t data[]; }
 *   Reply:    { uint32_t status; uint8_t data[]; }
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/ucred.h>

#include "mac_capability.h"
#include "mac_capability_test_keystore_proto.h"

MALLOC_DEFINE(M_MAC_CAPABILITY_KS, "mac_capability_test_ks", "mac_capability test keystore");

#define	KS_MAX_VALUE	4096
#define	KS_MAX_KEYS	1024

struct ks_entry {
	LIST_ENTRY(ks_entry) ke_link;
	uid_t		ke_uid;
	uint32_t	ke_keyid;
	void		*ke_data;
	size_t		ke_datalen;
};

static struct mac_capability_service *ks_svc;
static struct mtx ks_mtx;
static LIST_HEAD(, ks_entry) ks_entries = LIST_HEAD_INITIALIZER(ks_entries);
static int ks_nentries;
static volatile uint64_t ks_next_badge = 1;

static struct ks_entry *
ks_find(uid_t uid, uint32_t keyid)
{
	struct ks_entry *ke;

	mtx_assert(&ks_mtx, MA_OWNED);
	LIST_FOREACH(ke, &ks_entries, ke_link) {
		if (ke->ke_uid == uid && ke->ke_keyid == keyid)
			return (ke);
	}
	return (NULL);
}

static int
keystore_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{

	return (MAC_CAPABILITY_CONNECT_BADGE(ks_next_badge, badge_out));
}

static int
keystore_handler(struct mac_capability_instance *s, const struct mac_capability_msg *msg,
    void *arg __unused)
{
	const struct ks_request *req;
	struct ks_entry *ke;
	struct ks_reply reply_hdr;
	uid_t uid;

	if (mac_capability_msg_datalen(msg) < sizeof(struct ks_request)) {
		reply_hdr.status = KS_STATUS_ERR;
		mac_capability_reply(s, mac_capability_msg_token(msg), &reply_hdr,
		    sizeof(reply_hdr), NULL, NULL, 0);
		return (0);
	}

	req = (const struct ks_request *)mac_capability_msg_data(msg);
	uid = mac_capability_msg_cred(msg)->cr_uid;

	switch (req->op) {
	case KS_OP_STORE: {
		struct ks_entry *newke;
		size_t datalen;
		void *newdata, *olddata;

		datalen = mac_capability_msg_datalen(msg) - sizeof(struct ks_request);
		if (datalen > KS_MAX_VALUE) {
			reply_hdr.status = KS_STATUS_ERR;
			mac_capability_reply(s, mac_capability_msg_token(msg), &reply_hdr,
			    sizeof(reply_hdr), NULL, NULL, 0);
			return (0);
		}

		/* Pre-allocate outside the lock. */
		newdata = NULL;
		if (datalen > 0) {
			newdata = malloc(datalen, M_MAC_CAPABILITY_KS, M_WAITOK);
			memcpy(newdata,
			    (const uint8_t *)mac_capability_msg_data(msg) +
			    sizeof(struct ks_request), datalen);
		}
		newke = malloc(sizeof(*newke), M_MAC_CAPABILITY_KS,
		    M_WAITOK | M_ZERO);

		mtx_lock(&ks_mtx);
		ke = ks_find(uid, req->keyid);
		if (ke != NULL) {
			olddata = ke->ke_data;
			ke->ke_data = newdata;
			ke->ke_datalen = datalen;
			mtx_unlock(&ks_mtx);
			free(olddata, M_MAC_CAPABILITY_KS);
			free(newke, M_MAC_CAPABILITY_KS);
		} else {
			if (ks_nentries >= KS_MAX_KEYS) {
				mtx_unlock(&ks_mtx);
				free(newdata, M_MAC_CAPABILITY_KS);
				free(newke, M_MAC_CAPABILITY_KS);
				reply_hdr.status = KS_STATUS_ERR;
				mac_capability_reply(s, mac_capability_msg_token(msg), &reply_hdr,
				    sizeof(reply_hdr), NULL, NULL, 0);
				return (0);
			}
			newke->ke_uid = uid;
			newke->ke_keyid = req->keyid;
			newke->ke_data = newdata;
			newke->ke_datalen = datalen;
			LIST_INSERT_HEAD(&ks_entries, newke, ke_link);
			ks_nentries++;
			mtx_unlock(&ks_mtx);
		}

		reply_hdr.status = KS_STATUS_OK;
		mac_capability_reply(s, mac_capability_msg_token(msg), &reply_hdr,
		    sizeof(reply_hdr), NULL, NULL, 0);
		return (0);
	}

	case KS_OP_DELAY_FETCH:
		/*
		 * Give a multi-threaded service taskqueue time to expose accidental
		 * concurrent dispatch of this instance.  A correct dispatcher keeps
		 * later requests behind this one and therefore preserves FIFO replies.
		 */
		pause("macksd", MAX(1, hz / 10));
		/* FALLTHROUGH */
	case KS_OP_FETCH: {
		char *valbuf, *reply_buf;
		size_t vallen, reply_len;

		mtx_lock(&ks_mtx);
		ke = ks_find(uid, req->keyid);
		if (ke == NULL) {
			mtx_unlock(&ks_mtx);
			reply_hdr.status = KS_STATUS_NOTFOUND;
			mac_capability_reply(s, mac_capability_msg_token(msg), &reply_hdr,
			    sizeof(reply_hdr), NULL, NULL, 0);
			return (0);
		}
		vallen = ke->ke_datalen;
		if (vallen > KS_MAX_VALUE)
			vallen = KS_MAX_VALUE;
		mtx_unlock(&ks_mtx);

		valbuf = NULL;
		if (vallen > 0) {
			valbuf = malloc(vallen, M_MAC_CAPABILITY_KS, M_WAITOK);
			mtx_lock(&ks_mtx);
			ke = ks_find(uid, req->keyid);
			if (ke == NULL || ke->ke_datalen < vallen) {
				mtx_unlock(&ks_mtx);
				free(valbuf, M_MAC_CAPABILITY_KS);
				reply_hdr.status = KS_STATUS_NOTFOUND;
				mac_capability_reply(s, mac_capability_msg_token(msg), &reply_hdr,
				    sizeof(reply_hdr), NULL, NULL, 0);
				return (0);
			}
			memcpy(valbuf, ke->ke_data, vallen);
			mtx_unlock(&ks_mtx);
		}

		reply_len = sizeof(struct ks_reply) + vallen;
		reply_buf = malloc(reply_len, M_MAC_CAPABILITY_KS, M_WAITOK);
		((struct ks_reply *)reply_buf)->status = KS_STATUS_OK;
		if (vallen > 0)
			memcpy(reply_buf + sizeof(struct ks_reply),
			    valbuf, vallen);

		mac_capability_reply(s, mac_capability_msg_token(msg), reply_buf,
		    reply_len, NULL, NULL, 0);
		free(reply_buf, M_MAC_CAPABILITY_KS);
		free(valbuf, M_MAC_CAPABILITY_KS);
		return (0);
	}

	default:
		reply_hdr.status = KS_STATUS_ERR;
		mac_capability_reply(s, mac_capability_msg_token(msg), &reply_hdr,
		    sizeof(reply_hdr), NULL, NULL, 0);
		return (0);
	}
}

static const struct mac_capability_ops keystore_ops = {
	.co_connect = keystore_connect,
	.co_handler = keystore_handler,
};

static void
ks_cleanup(void)
{
	struct ks_entry *ke;

	mtx_lock(&ks_mtx);
	while ((ke = LIST_FIRST(&ks_entries)) != NULL) {
		LIST_REMOVE(ke, ke_link);
		free(ke->ke_data, M_MAC_CAPABILITY_KS);
		free(ke, M_MAC_CAPABILITY_KS);
		ks_nentries--;
	}
	mtx_unlock(&ks_mtx);
}

static int
mac_capability_test_keystore_modevent(module_t mod __unused, int type,
    void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		mtx_init(&ks_mtx, "mac_capability_test_ks", NULL, MTX_DEF);
		{
			struct mac_capability_service_params p = {
				.name = "test_keystore",
				.ops = &keystore_ops,
			};
			error = mac_capability_service_create(&p, &ks_svc);
		}
		if (error != 0) {
			mtx_destroy(&ks_mtx);
			return (error);
		}
		return (0);

	case MOD_UNLOAD:
		if (ks_svc != NULL)
			mac_capability_service_destroy(ks_svc);
		ks_cleanup();
		mtx_destroy(&ks_mtx);
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mac_capability_test_keystore_mod = {
	"mac_capability_test_keystore",
	mac_capability_test_keystore_modevent,
	NULL,
};

DECLARE_MODULE(mac_capability_test_keystore, mac_capability_test_keystore_mod, SI_SUB_PSEUDO,
    SI_ORDER_ANY);
MODULE_VERSION(mac_capability_test_keystore, 1);
MODULE_DEPEND(mac_capability_test_keystore, mac_capability, 1, 1, 1);
