/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Last-holder accounting for storage with the "lease" lifecycle.
 */

#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "serviced.h"

#define STORAGE_LEASE_MAX \
	(SERVICED_MAX_SERVICES * SERVICED_MAX_CAP_STORAGE)

struct storage_lease_entry {
	char dataset[ORT_STORAGE_DATASET_MAX];
	unsigned holders;
};

static struct storage_lease_entry leases[STORAGE_LEASE_MAX];

void
storage_lifecycle_reset(void)
{

	memset(leases, 0, sizeof(leases));
}

static int
claim_valid(const struct ort_storage_claim *sc)
{

	return (sc != NULL && sc->lifetime == ORT_STORAGE_LEASE &&
	    sc->dataset[0] != '\0' &&
	    strnlen(sc->dataset, sizeof(sc->dataset)) < sizeof(sc->dataset));
}

int
storage_lease_acquire(const struct ort_storage_claim *sc)
{
	unsigned empty, i;

	if (!claim_valid(sc)) {
		errno = EINVAL;
		return (-1);
	}
	empty = STORAGE_LEASE_MAX;
	for (i = 0; i < STORAGE_LEASE_MAX; i++) {
		if (leases[i].holders == 0) {
			if (empty == STORAGE_LEASE_MAX)
				empty = i;
			continue;
		}
		if (strcmp(leases[i].dataset, sc->dataset) == 0) {
			if (leases[i].holders == UINT_MAX) {
				errno = EOVERFLOW;
				return (-1);
			}
			leases[i].holders++;
			return (0);
		}
	}
	if (empty == STORAGE_LEASE_MAX) {
		errno = ENOSPC;
		return (-1);
	}
	strlcpy(leases[empty].dataset, sc->dataset,
	    sizeof(leases[empty].dataset));
	leases[empty].holders = 1;
	return (0);
}

int
storage_lease_release(const struct ort_storage_claim *sc)
{
	unsigned i;

	if (!claim_valid(sc)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < STORAGE_LEASE_MAX; i++) {
		if (leases[i].holders != 0 &&
		    strcmp(leases[i].dataset, sc->dataset) == 0) {
			leases[i].holders--;
			if (leases[i].holders == 0) {
				memset(&leases[i], 0, sizeof(leases[i]));
				return (1);
			}
			return (0);
		}
	}
	errno = ENOENT;
	return (-1);
}
