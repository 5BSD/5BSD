/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "virtio_admin.h"
#include "virtio_admin_sriov.h"
#include "virtio_pci_modern_probes.h"
#include "virtio_state_range.h"

struct virtio_admin_sriov_lifecycle {
	pthread_rwlock_t lock;
	_Atomic(bool) capable;
	_Atomic(bool) vf_enable;
	_Atomic(bool) vf_migration_capable;
	_Atomic(uint16_t) num_vfs;
	_Atomic(uint64_t) generation;
};

static bool
vadmin_sriov_available(struct virtio_admin_sriov_lifecycle *lifecycle)
{

	return (atomic_load_explicit(&lifecycle->capable,
	    memory_order_acquire) &&
	    atomic_load_explicit(&lifecycle->vf_enable,
	    memory_order_acquire));
}

int
virtio_admin_sriov_lifecycle_create(
    struct virtio_admin_sriov_lifecycle **result)
{
	struct virtio_admin_sriov_lifecycle *lifecycle;
	int error;

	if (result == NULL)
		return (EINVAL);
	lifecycle = calloc(1, sizeof(*lifecycle));
	if (lifecycle == NULL)
		return (ENOMEM);
	error = pthread_rwlock_init(&lifecycle->lock, NULL);
	if (error != 0) {
		free(lifecycle);
		return (error);
	}
	atomic_init(&lifecycle->generation, 1);
	*result = lifecycle;
	return (0);
}

void
virtio_admin_sriov_lifecycle_destroy(
    struct virtio_admin_sriov_lifecycle *lifecycle)
{

	if (lifecycle == NULL)
		return;
	pthread_rwlock_destroy(&lifecycle->lock);
	free(lifecycle);
}

int
virtio_admin_sriov_lifecycle_update(
    struct virtio_admin_sriov_lifecycle *lifecycle, bool capable,
    bool vf_enable, bool vf_migration_capable, uint16_t num_vfs)
{
	bool changed;
	uint64_t generation;

	if (lifecycle == NULL || (!capable &&
	    (vf_enable || vf_migration_capable || num_vfs != 0)))
		return (EINVAL);
	pthread_rwlock_wrlock(&lifecycle->lock);
	changed = capable != atomic_load_explicit(&lifecycle->capable,
	    memory_order_relaxed) ||
	    vf_enable != atomic_load_explicit(&lifecycle->vf_enable,
	    memory_order_relaxed) ||
	    vf_migration_capable != atomic_load_explicit(
	    &lifecycle->vf_migration_capable, memory_order_relaxed) ||
	    num_vfs != atomic_load_explicit(&lifecycle->num_vfs,
	    memory_order_relaxed);
	if (changed) {
		atomic_store_explicit(&lifecycle->num_vfs, num_vfs,
		    memory_order_relaxed);
		atomic_store_explicit(&lifecycle->vf_migration_capable,
		    vf_migration_capable, memory_order_relaxed);
		atomic_store_explicit(&lifecycle->vf_enable, vf_enable,
		    memory_order_relaxed);
		atomic_store_explicit(&lifecycle->capable, capable,
		    memory_order_release);
		generation = atomic_load_explicit(&lifecycle->generation,
		    memory_order_relaxed);
		atomic_store_explicit(&lifecycle->generation,
		    generation == UINT64_MAX ? 1 : generation + 1,
		    memory_order_release);
		VIRTIO_PROBE_ADMIN_SRIOV_LIFECYCLE(capable, vf_enable,
		    vf_migration_capable, num_vfs,
		    generation == UINT64_MAX ? 1 : generation + 1);
	}
	pthread_rwlock_unlock(&lifecycle->lock);
	return (0);
}

int
virtio_admin_sriov_lifecycle_get(
    struct virtio_admin_sriov_lifecycle *lifecycle,
    struct virtio_admin_sriov_state *state)
{

	if (lifecycle == NULL || state == NULL)
		return (EINVAL);
	pthread_rwlock_rdlock(&lifecycle->lock);
	if (virtio_state_ranges_overlap(state, sizeof(*state), lifecycle,
	    sizeof(*lifecycle))) {
		pthread_rwlock_unlock(&lifecycle->lock);
		return (EINVAL);
	}
	state->capable = atomic_load_explicit(&lifecycle->capable,
	    memory_order_relaxed);
	state->vf_enable = atomic_load_explicit(&lifecycle->vf_enable,
	    memory_order_relaxed);
	state->vf_migration_capable = atomic_load_explicit(
	    &lifecycle->vf_migration_capable, memory_order_relaxed);
	state->num_vfs = atomic_load_explicit(&lifecycle->num_vfs,
	    memory_order_relaxed);
	state->generation = atomic_load_explicit(&lifecycle->generation,
	    memory_order_relaxed);
	pthread_rwlock_unlock(&lifecycle->lock);
	return (0);
}

bool
virtio_admin_sriov_group_available(void *argument)
{
	struct virtio_admin_sriov_lifecycle *lifecycle;

	lifecycle = argument;
	return (lifecycle != NULL && vadmin_sriov_available(lifecycle));
}

int
virtio_admin_sriov_group_begin(void *argument,
    uint16_t *qualifier) __no_lock_analysis
{
	struct virtio_admin_sriov_lifecycle *lifecycle;

	lifecycle = argument;
	if (lifecycle == NULL || qualifier == NULL)
		return (EINVAL);
	pthread_rwlock_rdlock(&lifecycle->lock);
	if (virtio_state_ranges_overlap(qualifier, sizeof(*qualifier),
	    lifecycle, sizeof(*lifecycle))) {
		pthread_rwlock_unlock(&lifecycle->lock);
		return (EINVAL);
	}
	if (!vadmin_sriov_available(lifecycle)) {
		*qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_GROUP;
		pthread_rwlock_unlock(&lifecycle->lock);
		return (ENXIO);
	}
	if (atomic_load_explicit(&lifecycle->vf_migration_capable,
	    memory_order_acquire)) {
		/*
		 * The driver is required to keep VF Migration Capable clear
		 * while an SR-IOV group command is outstanding.  Refuse to
		 * begin a lease in the conflicting state; a later PCI update
		 * that clears the bit is serialized by this same lock.
		 */
		*qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN;
		pthread_rwlock_unlock(&lifecycle->lock);
		return (EBUSY);
	}
	return (0);
}

void
virtio_admin_sriov_group_end(void *argument) __no_lock_analysis
{
	struct virtio_admin_sriov_lifecycle *lifecycle;

	lifecycle = argument;
	if (lifecycle != NULL)
		pthread_rwlock_unlock(&lifecycle->lock);
}

bool
virtio_admin_sriov_member_valid(void *argument, uint64_t member)
{
	struct virtio_admin_sriov_lifecycle *lifecycle;
	uint16_t num_vfs;

	lifecycle = argument;
	if (lifecycle == NULL || !vadmin_sriov_available(lifecycle))
		return (false);
	num_vfs = atomic_load_explicit(&lifecycle->num_vfs,
	    memory_order_acquire);
	return (member >= 1 && member <= num_vfs);
}
