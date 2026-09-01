/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * serviced's direct client to tzfsd(8), the [TZFS] storage broker.
 *
 * Storage is a leaf capability owned by tzfsd.  serviced — the service manager
 * that launches and supervises tzfsd — mints per-service dataset handles by
 * talking to tzfsd directly.  authorityd (PID 1) and the authority channel are
 * not involved: storage never transits the init process.
 *
 * The tzfsd channel is cached and carries one boot-scoped session.  On first
 * use serviced mints a random session id and calls tzfsd_begin_session(),
 * which roots this boot's ephemeral leases under ephemeral/lease-<id> and
 * reaps stale leases left by prior boots.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "serviced.h"
#include "tzfsd.h"

static int storage_chan = -1;
static char storage_session[TZFSD_SESSION_MAX];
static bool storage_session_ready;

static void
storage_channel_reset(void)
{

	if (storage_chan != -1) {
		(void)close(storage_chan);
		storage_chan = -1;
	}
	storage_session_ready = false;
}

/*
 * Lazily connect to tzfsd and establish this boot's session.  tzfsd is a
 * serviced-supervised unit, so a storage mint can race its startup or a
 * restart; retry the connect briefly (~5s) to cover that window.
 */
static int
storage_channel_get(void)
{
	int i;

	if (storage_session[0] == '\0') {
		unsigned char rnd[16];
		unsigned j;

		arc4random_buf(rnd, sizeof(rnd));
		for (j = 0; j < sizeof(rnd); j++)
			(void)snprintf(storage_session + j * 2, 3, "%02x",
			    rnd[j]);
		storage_session[TZFSD_SESSION_MAX - 1] = '\0';
	}

	if (storage_chan == -1) {
		storage_chan = tzfsd_connect();
		for (i = 0; i < 100 && storage_chan == -1; i++) {
			struct timespec ts = { 0, 50 * 1000 * 1000 }; /* 50ms */

			(void)nanosleep(&ts, NULL);
			storage_chan = tzfsd_connect();
		}
		if (storage_chan == -1)
			return (-1);
	}

	if (!storage_session_ready) {
		if (tzfsd_begin_session(storage_chan, storage_session) == -1) {
			int saved = errno;

			storage_channel_reset();
			errno = saved;
			return (-1);
		}
		storage_session_ready = true;
	}
	return (storage_chan);
}

/*
 * Mint a bare-dataset handle for a service's storage claim.  owner_uid/gid are
 * conveyed so tzfsd chowns the dataset root to the service at mint (0 = skip).
 * Returns the rights-limited handle fd (caller owns/closes) or -1 with errno.
 */
int
serviced_storage_mint(const struct ort_storage_claim *sc, uid_t owner_uid,
    gid_t owner_gid)
{
	struct tzfsd_req req;
	struct tzfsd_grant grant;
	int chan, e;

	if (sc == NULL || sc->dataset[0] == '\0' ||
	    sc->lifetime > ORT_STORAGE_LEASE) {
		errno = EINVAL;
		return (-1);
	}

	chan = storage_channel_get();
	if (chan == -1)
		return (-1);

	memset(&req, 0, sizeof(req));
	if (strlcpy(req.dataset, sc->dataset, sizeof(req.dataset)) >=
	    sizeof(req.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	req.rights = sc->rights;
	req.lifetime = sc->lifetime;
	req.owner_uid = owner_uid;
	req.owner_gid = owner_gid;

	if (tzfsd_request(chan, &req, &grant) == -1) {
		e = errno;
		if (e == EPIPE || e == ECONNRESET || e == EBADF)
			storage_channel_reset();
		errno = e;
		return (-1);
	}
	return (grant.handle_fd);
}

/*
 * Destroy a lease dataset after its last holder stops.  A missing claim is
 * success (tzfsd_release is idempotent) so stop paths stay clean.
 */
int
serviced_storage_destroy(const struct ort_storage_claim *sc)
{
	int chan, e;

	if (sc == NULL || sc->dataset[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	chan = storage_channel_get();
	if (chan == -1)
		return (-1);
	if (tzfsd_release(chan, sc->dataset) == -1) {
		e = errno;
		if (e == EPIPE || e == ECONNRESET || e == EBADF)
			storage_channel_reset();
		errno = e;
		return (-1);
	}
	return (0);
}
