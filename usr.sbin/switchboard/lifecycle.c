/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/event.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "switchboard.h"
#include "switchboard_lifecycle.h"
#include "switchboard_reclamation.h"
#include "switchboard_svc_proto.h"
#include "installation_trace.h"

static char timer_ident;
static size_t replay_cursor;

static bool
cleanup_enabled(void)
{
	const char *value = getenv("SWITCHBOARD_EXPERIMENTAL_RECLAIM");
	return (value != NULL && strcmp(value, "1") == 0);
}

const char *
svc_lifecycle_path(void)
{
	const char *path = getenv("SWITCHBOARD_LIFECYCLE_DIR");

	return (path != NULL && path[0] != '\0' ? path : SL_DIRECTORY);
}

/* Runtime lookups consume installation facts; only installers create them. */
static int
active_owner(struct sl_db *db, const char *label, const uint8_t *generation,
    struct sl_record **result)
{
	struct sl_record *owner;

	owner = generation == NULL ? sl_owner(db, label) :
	    sl_generation(db, label, generation);
	if (owner == NULL)
		return (errno = generation == NULL ? ENOENT : ESTALE, -1);
	if (owner->phase == SL_INSTALLING || owner->phase == SL_PREPARED)
		return (errno = EBUSY, -1);
	if (owner->phase != SL_ACTIVE)
		return (errno = ESTALE, -1);
	*result = owner;
	return (0);
}

int
svc_lifecycle_identity(struct svc_runtime *svc)
{
	struct sl_db db;
	struct sl_record *owner;
	int error = 0;

	if (sl_open_readonly(svc_lifecycle_path(), &db) == -1) {
		svc_trace_installation("start", svc->manifest.label, NULL, SL_UNKNOWN, errno);
		return (-1);
	}
	if (active_owner(&db, svc->manifest.label, NULL, &owner) == -1)
		error = errno;
	else {
		memcpy(svc->installation, owner->generation, sizeof(svc->installation));
		strlcpy(svc->resource_owner, owner->provider, sizeof(svc->resource_owner));
	}
	sl_close(&db);
	svc_trace_installation("start", svc->manifest.label,
	    error == 0 ? svc->installation : NULL,
	    error == 0 ? SL_INSTALLED : SL_UNKNOWN, error);
	return (error != 0 ? (errno = error, -1) : 0);
}

int
svc_lifecycle_client(struct svc_runtime *svc, struct svc_runtime *provider,
    struct svc_new_client_msg *msg)
{
	struct sl_db db;
	struct sl_record *owner;
	int error = 0;
	bool track = cleanup_enabled() && provider != NULL &&
	    provider->reclaim_registered;
	const char *label = svc != NULL ? svc->manifest.label : msg->client_label;

	if ((track ? sl_open(svc_lifecycle_path(), &db) :
	    sl_open_readonly(svc_lifecycle_path(), &db)) == -1) {
		svc_trace_installation("session", label, NULL, SL_UNKNOWN, errno);
		return (-1);
	}
	if (active_owner(&db, label, svc != NULL ? svc->installation : NULL,
	    &owner) == -1)
		error = errno;
	if (error == 0) {
		strlcpy(msg->resource_owner, owner->provider, sizeof(msg->resource_owner));
		memcpy(msg->generation, owner->generation, sizeof(msg->generation));
		/* Experimental tracking may add holdings, never installation identities. */
		if (track && (sl_track_holding(&db, label, provider->manifest.label,
		    msg->generation) == -1 || sl_commit(&db) == -1))
			error = errno;
	}
	sl_close(&db);
	svc_trace_installation("session", label,
	    error == 0 ? msg->generation : (svc != NULL ? svc->installation : NULL),
	    error == 0 ? SL_INSTALLED : SL_UNKNOWN, error);
	return (error != 0 ? (errno = error, -1) : 0);
}

int
svc_lifecycle_register(struct svc_runtime *svc)
{
	struct sl_db db;
	int error = 0;

	if (!cleanup_enabled()) {
		svc->reclaim_registered = true;
		return (0);
	}
	if (sl_open(svc_lifecycle_path(), &db) == -1)
		return (errno);
	if (sl_register_provider(&db, svc->manifest.label) == -1 || sl_commit(&db) == -1)
		error = errno;
	sl_close(&db);
	if (error == 0)
		svc->reclaim_registered = true;
	return (error);
}

int
svc_lifecycle_ack(struct svc_runtime *svc, const struct svc_reclaim_result_req *req)
{
	struct sl_db db;
	int error = 0;

	if (!cleanup_enabled())
		return (ENOTSUP);
	if (!svc->reclaim_registered || !sl_label_valid(req->label) ||
	    !sl_generation_valid(req->generation) || req->status < 0 || req->status > ELAST)
		return (EINVAL);
	if (req->status != 0) {
		syslog(LOG_WARNING, "cleanup %s by %s remains pending: %s", req->label,
		    svc->manifest.label, strerror(req->status));
		return (0);
	}
	if (sl_open(svc_lifecycle_path(), &db) == -1)
		return (errno);
	if (sl_ack(&db, req->label, svc->manifest.label, req->generation) == -1 ||
	    sl_commit(&db) == -1)
		error = errno;
	sl_close(&db);
	return (error);
}

static void
stop_retired(const char *label, const uint8_t *generation, void *context)
{
	struct svc_runtime *svc = svc_by_label(label);

	if (svc != NULL && memcmp(svc->installation, generation,
	    sizeof(svc->installation)) == 0)
		svc_graceful_stop(svc, *(int *)context);
}

unsigned
svc_lifecycle_replay(int kq)
{
	struct sl_db db;
	struct svc_runtime *provider;
	struct svc_reclaim_label_msg msg;
	struct sl_record *d, *owner;
	unsigned sent = 0;
	size_t seen, i;
	static struct sl_query_cache *cache;

	if (!cleanup_enabled()) {
		if (cache == NULL && (cache = sl_query_cache_create()) == NULL)
			return (0);
		(void)sl_query_cached_retired(cache, svc_lifecycle_path(),
		    stop_retired, &kq);
		return (0);
	}
	if (sl_open(svc_lifecycle_path(), &db) == -1)
		return (0);
	/* Stop the retired incarnation; a replacement has a different identity. */
	for (i = 0; i < db.count; i++) {
		owner = &db.records[i];
		if (owner->kind != SL_OWNER ||
		    (owner->phase != SL_PREPARED && owner->phase != SL_RETIRED &&
		    owner->phase != SL_COMPLETE))
			continue;
		provider = svc_by_label(owner->label);
		if (provider != NULL && memcmp(provider->installation,
		    owner->generation, sizeof(owner->generation)) == 0)
			svc_graceful_stop(provider, kq);
	}
	/* Only the opt-in consumer creates delivery records, after removal commits. */
	for (i = 0; i < db.count; i++) {
		owner = &db.records[i];
		if (owner->kind == SL_OWNER && owner->phase == SL_COMPLETE &&
		    sl_cleanup_prepare(&db, owner->label, owner->generation) == -1) {
			sl_close(&db);
			return (0);
		}
	}
	if (sl_commit(&db) == -1) {
		sl_close(&db);
		return (0);
	}
	for (seen = 0; seen < db.count && sent < 32; seen++) {
		i = (replay_cursor + seen) % db.count;
		d = &db.records[i];
		if (d->kind != SL_DELIVERY || d->phase != 0)
			continue;
		owner = sl_generation(&db, d->label, d->generation);
		if (owner == NULL || owner->phase != SL_RETIRED)
			continue;
		provider = svc_by_label(d->provider);
		if (provider == NULL || provider->state != SVC_STATE_RUNNING ||
		    !provider->protocol_ready ||
		    !provider->reclaim_registered || provider->control_channel == NULL)
			continue;
		memset(&msg, 0, sizeof(msg));
		msg.op = SVC_OP_RECLAIM_LABEL;
		strlcpy(msg.label, d->label, sizeof(msg.label));
		strlcpy(msg.owner, owner->provider, sizeof(msg.owner));
		memcpy(msg.generation, d->generation, sizeof(msg.generation));
		if (svc_channel_send_event(provider, &msg, sizeof(msg), NULL, 0, kq) == 0)
			sent++;
	}
	if (db.count != 0)
		replay_cursor = (replay_cursor + seen) % db.count;
	sl_close(&db);
	return (sent);
}

int
svc_retire_label(const char *label __unused, int kq __unused, unsigned *notified)
{
	/* A label-only request cannot identify an installation transaction. */
	*notified = 0;
	return (ENOTSUP);
}

int
svc_lifecycle_init(int kq)
{
	struct sl_db db;
	struct kevent ev;
	static const char *const builtins[] = {
		"system.Filesystem/tzfsd", "system.Namespace/warden",
		"system.Crypto/localcrypto", "system.Log/logd", "system.Waspnest/waspnest"
	};
	int error = 0;

	if ((cleanup_enabled() ? sl_open(svc_lifecycle_path(), &db) :
	    sl_open_readonly(svc_lifecycle_path(), &db)) == -1)
		return (-1);
	/* Migration inventory includes stateful providers that are installed but down. */
	for (size_t i = 0; i < nitems(builtins); i++)
		if (cleanup_enabled() && bundle_registry_label_installed(builtins[i]) &&
		    sl_register_provider(&db, builtins[i]) == -1) {
			error = errno;
			break;
		}
	if (error == 0 && cleanup_enabled() && sl_commit(&db) == -1)
		error = errno;
	sl_close(&db);
	if (error != 0)
		return (errno = error, -1);
	EV_SET(&ev, (uintptr_t)&timer_ident, EVFILT_TIMER, EV_ADD, 0, 1000, NULL);
	return (kevent(kq, &ev, 1, NULL, 0, NULL));
}

bool
svc_lifecycle_event(const struct kevent *ev)
{
	return (ev->filter == EVFILT_TIMER && ev->ident == (uintptr_t)&timer_ident);
}
