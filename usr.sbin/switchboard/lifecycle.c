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

/*
 * Derive a stable installation identity from the label alone.  The ledger
 * tracks resources for reclaim; it must NEVER decide whether a unit may run.
 * A freshly installed system ships its bundles with no ledger records, so a
 * unit without one launches with resource ownership keyed on its stable label
 * and a deterministic generation derived from it -- it is simply not tracked
 * for reclaim until an installer records it.  This is what keeps a fresh image
 * booting (docs/ipc-anointments-design.md is unrelated; see the switchboard
 * installation notes).
 */
static void
svc_identity_from_label(const char *label,
    uint8_t generation[SL_GENERATION_SIZE], char *owner, size_t owner_size)
{
	uint64_t h1 = 1469598103934665603ULL, h2 = 1099511628211ULL;
	const unsigned char *p;

	for (p = (const unsigned char *)label; *p != '\0'; p++) {
		h1 = (h1 ^ *p) * 1099511628211ULL;
		h2 = (h2 + *p) * 1099511628211ULL;
	}
	memcpy(generation, &h1, 8);
	memcpy((uint8_t *)generation + 8, &h2, 8);
	if (!sl_generation_valid(generation))
		generation[0] = 1;			/* never all-zero */
	if (owner != NULL && owner_size > 0) {
		char hex[33];

		/*
		 * The resource owner must be a FLAT key -- providers use it as a
		 * single path/dataset component (tzfsd names a per-owner dataset
		 * by it), so it cannot contain the '/' a bundle label carries
		 * (system.Filesystem/tzfsd).  Derive it from the same
		 * deterministic generation so it is stable per label and a
		 * label-keyed reclaim can recompute it: "cap." + generation hex.
		 */
		sl_generation_format(generation, hex);
		(void)snprintf(owner, owner_size, "cap.%s", hex);
	}
}

int
svc_lifecycle_identity(struct svc_runtime *svc)
{
	/*
	 * Resource ownership is keyed on the stable bundle label, not on a
	 * ledger record: the /Capabilities layout already stores each
	 * capability's data under a per-label subtree (tzfsd), so the path is
	 * the ownership record and cleanup is structural (reclaim/GC by label).
	 * Launch never consults or depends on the installation ledger.
	 */
	svc_identity_from_label(svc->manifest.label, svc->installation,
	    svc->resource_owner, sizeof(svc->resource_owner));
	svc_trace_installation("start", svc->manifest.label, svc->installation,
	    SL_INSTALLED, 0);
	return (0);
}

int
svc_lifecycle_client(struct svc_runtime *svc, struct svc_runtime *provider,
    struct svc_new_client_msg *msg)
{
	const char *label = svc != NULL ? svc->manifest.label : msg->client_label;

	/*
	 * A client's resource ownership is its stable label (see
	 * svc_lifecycle_identity).  No holding record is tracked: reclaim
	 * broadcasts a label to every reclaim-capable provider, which frees
	 * that label's per-capability storage.  `provider` is unused now that
	 * ownership is structural rather than ledger-tracked.
	 */
	(void)provider;
	svc_identity_from_label(label, msg->generation, msg->resource_owner,
	    sizeof(msg->resource_owner));
	svc_trace_installation("session", label, msg->generation,
	    SL_INSTALLED, 0);
	return (0);
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
	if (sl_open_readonly(svc_lifecycle_path(), &db) == -1) {
		/*
		 * A freshly installed system ships the ledger DIRECTORY (the
		 * switchboard package creates it) but nothing inside it, so the
		 * read-only open fails ENOENT -- there is no lock or state yet.
		 * That is not an error: it means every built-in provider is
		 * unregistered.  Fall through to the update path, which
		 * initialises the ledger (creating lock and state) and registers
		 * them.  Without this a fresh image boot-loops on "installation
		 * lifecycle unavailable".  Any other failure (a corrupt or
		 * unreadable ledger) is real and propagates.
		 */
		if (errno != ENOENT)
			return (-1);
		for (size_t i = 0; i < nitems(builtins); i++) {
			missing[i] = bundle_registry_label_installed(builtins[i]);
			update |= missing[i];
		}
	} else {
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
	}
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
		/*
		 * Never boot-loop over the installation ledger.  Capsule starts
		 * us before rc remounts the root writable (EROFS); a paused or
		 * in-progress installer holds the lock (EWOULDBLOCK); and a fresh
		 * image whose ledger directory is absent or uninitialised leaves
		 * it uncreatable for now (ENOENT).  In every case boot with the
		 * inventory pending and let the periodic replay register the
		 * built-in providers once the store is writable.  Only a
		 * genuinely broken ledger (corrupt, EPERM, EIO) is fatal.
		 */
		if (errno != EROFS && errno != EWOULDBLOCK && errno != ENOENT)
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
