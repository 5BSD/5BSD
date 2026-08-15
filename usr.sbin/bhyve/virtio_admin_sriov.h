/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_ADMIN_SRIOV_H_
#define	_BHYVE_VIRTIO_ADMIN_SRIOV_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

struct virtio_admin_sriov_lifecycle;

struct virtio_admin_sriov_state {
	bool capable;
	bool vf_enable;
	bool vf_migration_capable;
	uint16_t num_vfs;
	uint64_t generation;
};

/*
 * Transport-neutral lifetime fence for a PCI SR-IOV administration group.
 *
 * PCI configuration code publishes changes with update().  An administration
 * command holds begin()/end() across validation and execution.  update() takes
 * the exclusive side of the same lock, so VF Enable, NumVFs, and VF Migration
 * Capable cannot change while a command is outstanding.  No wait loop or
 * architecture-specific state is embedded here.
 *
 * The callback-shaped functions can be installed directly in
 * virtio_admin_group_config.  available() is a preliminary observation;
 * begin() revalidates after acquiring the stable lease.  member_valid() is
 * safe both within a lease and for diagnostic callers.
 *
 * destroy() requires all administration queues and PCI lifecycle writers to
 * have stopped.  This object deliberately does not serialize PCI state:
 * SR-IOV capability registers are owned and restored by the PCI layer.
 */
int	virtio_admin_sriov_lifecycle_create(
	    struct virtio_admin_sriov_lifecycle **);
void	virtio_admin_sriov_lifecycle_destroy(
	    struct virtio_admin_sriov_lifecycle *);
int	virtio_admin_sriov_lifecycle_update(
	    struct virtio_admin_sriov_lifecycle *, bool, bool, bool, uint16_t);
int	virtio_admin_sriov_lifecycle_get(
	    struct virtio_admin_sriov_lifecycle *,
	    struct virtio_admin_sriov_state *);

bool	virtio_admin_sriov_group_available(void *);
int	virtio_admin_sriov_group_begin(void *, uint16_t *);
void	virtio_admin_sriov_group_end(void *);
bool	virtio_admin_sriov_member_valid(void *, uint64_t);

#endif /* _BHYVE_VIRTIO_ADMIN_SRIOV_H_ */
