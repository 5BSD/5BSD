/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/event.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "switchboard.h"
#include "switchboard_lifecycle.h"
#include "switchboard_reclamation.h"
#include "switchboard_svc_proto.h"
#include "installation_trace.h"
#include "installation_query.h"

static char timer_ident;
static size_t replay_cursor;

static bool replay_requested;
static bool provider_inventory_pending;
static int register_builtin_providers(void);

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
	struct sl_query_cache *cache;
	int error;

	cache = svc_installation_query_cache();
	error = cache == NULL ? errno :
	    sl_query_cached_active(cache, svc_lifecycle_path(),
	    svc->manifest.label, NULL, svc->installation, svc->resource_owner) == -1 ?
	    errno : 0;
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
	bool track = provider != NULL &&
	    provider->reclaim_registered;
	const char *label = svc != NULL ? svc->manifest.label : msg->client_label;

	if (!track) {
		struct sl_query_cache *cache = svc_installation_query_cache();
		if (cache == NULL || sl_query_cached_active(cache,
		    svc_lifecycle_path(), label, svc != NULL ? svc->installation : NULL,
		    msg->generation, msg->resource_owner) == -1)
			error = errno;
		goto done;
	}
	if (sl_open_update(svc_lifecycle_path(), &db) == -1) {
		svc_trace_installation("session", label, NULL, SL_UNKNOWN, errno);
		return (-1);
	}
	if (active_owner(&db, label, svc != NULL ? svc->installation : NULL,
	    &owner) == -1)
		error = errno;
	if (error == 0) {
		strlcpy(msg->resource_owner, owner->provider, sizeof(msg->resource_owner));
		memcpy(msg->generation, owner->generation, sizeof(msg->generation));
		/* Record possible holdings before granting a session; never invent an installation. */
		if (track && (sl_track_holding(&db, label, provider->manifest.label,
		    msg->generation) == -1 || sl_commit(&db) == -1))
			error = errno;
	}
	sl_close(&db);
done:
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

	if (sl_open_update(svc_lifecycle_path(), &db) == -1)
		return (errno);
	if (sl_register_provider(&db, svc->manifest.label) == -1 || sl_commit(&db) == -1)
		error = errno;
	sl_close(&db);
	if (error == 0) {
		svc->reclaim_registered = true;
		replay_requested = true;
	}
	return (error);
}

int
svc_lifecycle_ack(struct svc_runtime *svc, const struct svc_reclaim_result_req *req)
{
	struct sl_db db;
	int error = 0;

	if (!svc->reclaim_registered || !sl_label_valid(req->label) ||
	    !sl_generation_valid(req->generation) || req->status < 0 || req->status > ELAST)
		return (EINVAL);
	if (req->status != 0) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec >= svc->reclaim_warning_at) {
			syslog(LOG_WARNING, "cleanup %s by %s remains pending: %s", req->label,
			    svc->manifest.label, strerror(req->status));
			svc->reclaim_warning_at = now.tv_sec + 30;
		}
		return (0);
	}
	if (sl_open_update(svc_lifecycle_path(), &db) == -1)
		return (errno);
	if (sl_ack(&db, req->label, svc->manifest.label, req->generation) == -1 ||
	    sl_commit(&db) == -1)
		error = errno;
	sl_close(&db);
	svc_trace_installation("cleanup-ack", req->label, req->generation, SL_REMOVED, error);
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
	struct svc_reclaim_label_msg messages[32];
	char providers[32][SL_LABEL_MAX];
	struct sl_record *d, *owner;
	unsigned queued = 0, sent = 0;
	size_t seen, i;
	struct sl_query_cache *cache;
	static uint64_t revision;
	static time_t retry_at;
	struct timespec now;
	bool pending = false;

	if (sd.shutting_down)
		return (0);
	if (provider_inventory_pending) {
		if (register_builtin_providers() == -1)
			return (0);
		provider_inventory_pending = false;
	}
	if ((cache = svc_installation_query_cache()) == NULL)
		return (0);
	if (sl_query_cached_retired(cache, svc_lifecycle_path(), stop_retired, &kq) == -1)
		return (0);
	if (!sl_query_cache_cleanup_pending(cache)) {
		revision = sl_query_cache_revision(cache);
		retry_at = 0;
		replay_requested = false;
		return (0);
	}
	clock_gettime(CLOCK_MONOTONIC, &now);
	if (!replay_requested && revision == sl_query_cache_revision(cache) &&
	    (retry_at == 0 || now.tv_sec < retry_at))
		return (0);
	/* Failed writes (including capacity errors) also use bounded backoff. */
	revision = sl_query_cache_revision(cache);
	replay_requested = false;
	retry_at = now.tv_sec + 30;
	/* Never block the event loop behind an interrupted/paused installer. */
	if (sl_open_update(svc_lifecycle_path(), &db) == -1)
		return (0);
	for (i = 0; i < db.count; i++) {
		owner = &db.records[i];
		if (owner->kind == SL_OWNER &&
		    (owner->phase == SL_COMPLETE || owner->phase == SL_RETIRED) &&
		    strcmp(owner->reference, SL_CLEANUP_PENDING) != 0 &&
		    strcmp(owner->reference, SL_CLEANUP_COMPLETE) != 0 &&
		    sl_cleanup_prepare(&db, owner->label, owner->generation) == -1) {
			sl_close(&db);
			return (0);
		}
	}
	if (db.dirty && sl_commit(&db) == -1) {
		sl_close(&db);
		return (0);
	}
	for (seen = 0; seen < db.count && queued < nitems(messages); seen++) {
		i = (replay_cursor + seen) % db.count;
		d = &db.records[i];
		if (d->kind != SL_DELIVERY || d->phase != 0)
			continue;
		owner = sl_generation(&db, d->label, d->generation);
		if (owner == NULL || owner->phase != SL_RETIRED)
			continue;
		pending = true;
		struct svc_reclaim_label_msg *msg = &messages[queued];
		memset(msg, 0, sizeof(*msg));
		msg->op = SVC_OP_RECLAIM_LABEL;
		strlcpy(msg->label, d->label, sizeof(msg->label));
		strlcpy(msg->owner, owner->provider, sizeof(msg->owner));
		memcpy(msg->generation, d->generation, sizeof(msg->generation));
		strlcpy(providers[queued++], d->provider, SL_LABEL_MAX);
	}
	if (db.count != 0)
		replay_cursor = (replay_cursor + seen) % db.count;
	sl_close(&db);
	revision = sl_query_cache_revision(cache);
	replay_requested = false;
	retry_at = pending ? now.tv_sec + (queued == nitems(messages) ? 1 : 30) : 0;
	/* Launching providers and sending requests must never hold the store lock. */
	for (unsigned n = 0; n < queued; n++) {
		provider = svc_by_label(providers[n]);
		if (kq >= 0 && (provider == NULL || provider->state == SVC_STATE_STOPPED))
			(void)svc_activate_cleanup_provider(providers[n], kq);
		provider = svc_by_label(providers[n]);
		if (provider == NULL || provider->state != SVC_STATE_RUNNING ||
		    !provider->protocol_ready || !provider->reclaim_registered ||
		    provider->control_channel == NULL)
			continue;
		if (svc_channel_send_event(provider, &messages[n], sizeof(messages[n]),
		    NULL, 0, kq) == 0) {
			svc_trace_installation("cleanup-send", messages[n].label,
			    messages[n].generation, SL_REMOVED, 0);
			sent++;
		}
	}
	return (sent);
}

int
svc_retire_label(const char *label __unused, int kq __unused, unsigned *notified)
{
	/* A label-only request cannot identify an installation transaction. */
	*notified = 0;
	return (ENOTSUP);
}

static int
register_builtin_providers(void)
{
	struct sl_db db;
	static const char *const builtins[] = {
		"system.Filesystem/tzfsd", "system.Namespace/warden",
		"system.Crypto/localcrypto", "system.Log/logd", "system.Waspnest/waspnest"
	};
	int error = 0;

	bool missing[nitems(builtins)] = { false }, update = false;
	if (sl_open_readonly(svc_lifecycle_path(), &db) == -1)
		return (-1);
	for (size_t i = 0; i < nitems(builtins); i++) {
		if (!bundle_registry_label_installed(builtins[i]))
			continue;
		missing[i] = true;
		for (size_t j = 0; j < db.count; j++)
			if (db.records[j].kind == SL_PROVIDER &&
			    strcmp(db.records[j].label, builtins[i]) == 0)
				missing[i] = false;
		update |= missing[i];
	}
	sl_close(&db);
	if (update) {
		if (sl_open_update(svc_lifecycle_path(), &db) == -1)
			return (-1);
		for (size_t i = 0; i < nitems(builtins); i++)
			if (missing[i] && sl_register_provider(&db, builtins[i]) == -1) {
				error = errno;
				break;
			}
		if (error == 0 && db.dirty && sl_commit(&db) == -1)
			error = errno;
		sl_close(&db);
		if (error != 0)
			return (errno = error, -1);
	}
	return (0);
}

int
svc_lifecycle_init(int kq)
{
	struct kevent ev;
	if (register_builtin_providers() == -1) {
		/* Capsule starts us before rc remounts the root writable. A paused
		 * installer also must not prevent the runtime from booting. */
		if (errno != EROFS && errno != EWOULDBLOCK)
			return (-1);
		provider_inventory_pending = true;
	}
	replay_requested = true;
	EV_SET(&ev, (uintptr_t)&timer_ident, EVFILT_TIMER, EV_ADD, 0, 1000, NULL);
	return (kevent(kq, &ev, 1, NULL, 0, NULL));
}

bool
svc_lifecycle_event(const struct kevent *ev)
{
	return (ev->filter == EVFILT_TIMER && ev->ident == (uintptr_t)&timer_ident);
}
