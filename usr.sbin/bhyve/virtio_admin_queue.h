/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_ADMIN_QUEUE_H_
#define	_BHYVE_VIRTIO_ADMIN_QUEUE_H_

#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct virtio_admin_owner;
struct virtio_admin_group_fabric;
struct virtio_admin_group_config;
struct virtio_admin_queue_bank;
struct virtio_admin_pci_controller;

enum virtio_admin_pci_queue_kind {
	VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE = 0,
	VIRTIO_ADMIN_PCI_QUEUE_ORDINARY,
	VIRTIO_ADMIN_PCI_QUEUE_ADMIN,
};

/*
 * The PCI common configuration has two deliberately distinct queue
 * namespaces.  num_queues counts only ordinary device queues, while the
 * administration range can begin at any later 16-bit index.  Keeping this
 * description free of vqueue pointers lets the transport validate and stage
 * it before publishing guest-visible capability fields.
 */
struct virtio_admin_pci_queue_namespace {
	uint16_t ordinary_count;
	uint16_t admin_index;
	uint16_t admin_count;
};

#define	BHYVE_VIRTIO_ADMIN_QUEUE_MAX		64
#define	BHYVE_VIRTIO_ADMIN_QUEUE_IOV_MAX	32768
#define	BHYVE_VIRTIO_ADMIN_QUEUE_SCRATCH_MAX	(1024 * 1024)
#define	BHYVE_VIRTIO_ADMIN_QUEUE_SCRATCH_TOTAL_MAX	(16 * 1024 * 1024)

/*
 * Validate the PCI common-configuration administration-queue range from
 * VirtIO 1.4 section 4.1.4.3.1.  The arguments are deliberately wider than
 * their wire fields so callers must validate before narrowing.
 */
bool	virtio_admin_pci_queue_range_valid(uint32_t, uint32_t, uint32_t);
int	virtio_admin_pci_queue_namespace_init(
	    struct virtio_admin_pci_queue_namespace *, uint32_t, uint32_t,
	    uint32_t);
enum virtio_admin_pci_queue_kind virtio_admin_pci_queue_resolve(
	    const struct virtio_admin_pci_queue_namespace *, uint32_t,
	    uint16_t *);

/*
 * Own the immutable self-group topology and bounded command queues used by a
 * future PCI transport binding.  Queue memory and notification routing are
 * intentionally outside this object; the modern transport must attach those
 * before it may advertise VIRTIO_F_ADMIN_VQ.
 */
int	virtio_admin_pci_controller_create(
	    struct virtio_admin_pci_controller **, uint32_t, uint32_t,
	    uint32_t, size_t, size_t);
void	virtio_admin_pci_controller_destroy(
	    struct virtio_admin_pci_controller *);
const struct virtio_admin_pci_queue_namespace *
	virtio_admin_pci_controller_namespace(
	    const struct virtio_admin_pci_controller *);
struct virtio_admin_owner *virtio_admin_pci_controller_self_owner(
	    struct virtio_admin_pci_controller *);
struct virtio_admin_queue_bank *virtio_admin_pci_controller_queue_bank(
	    struct virtio_admin_pci_controller *);
/*
 * Register dynamic PCI groups (notably SR-IOV PF/VF groups) during device
 * construction, then seal before queue state is exposed.  register_group()
 * returns EBUSY after sealing or the first processed command.
 */
int	virtio_admin_pci_controller_register_group(
	    struct virtio_admin_pci_controller *,
	    const struct virtio_admin_group_config *,
	    struct virtio_admin_owner **);
int	virtio_admin_pci_controller_seal(
	    struct virtio_admin_pci_controller *);
int	virtio_admin_pci_controller_process(
	    struct virtio_admin_pci_controller *, uint32_t,
	    const struct iovec *, size_t, size_t, uint32_t *);
int	virtio_admin_pci_controller_process_chain(
	    struct virtio_admin_pci_controller *, uint32_t,
	    const struct iovec *, size_t, size_t, size_t, bool, bool, uint64_t,
	    uint32_t *);
int	virtio_admin_pci_controller_drain_queue(
	    struct virtio_admin_pci_controller *, uint32_t);
void	virtio_admin_pci_controller_reset(
	    struct virtio_admin_pci_controller *);
int	virtio_admin_pci_controller_snapshot_size(
	    struct virtio_admin_pci_controller *, size_t *);
int	virtio_admin_pci_controller_snapshot(
	    struct virtio_admin_pci_controller *, void *, size_t);
int	virtio_admin_pci_controller_restore(
	    struct virtio_admin_pci_controller *, const void *, size_t);
int	virtio_admin_pci_controller_restore_validate(
	    struct virtio_admin_pci_controller *, const void *, size_t);

/*
 * Adapt an ordered virtqueue descriptor chain to the administration command
 * core.  The first readable_count vectors are device-readable and all
 * remaining vectors are device-writable.  Caller-owned scratch storage keeps
 * queue processing bounded and allocation-free.
 */
int	virtio_admin_process_iov(struct virtio_admin_owner *,
	    const struct iovec *, size_t, size_t, void *, size_t, void *, size_t,
	    uint32_t *);

/*
 * A bank supplies the execution semantics shared by PCI administration
 * virtqueues: commands on one queue are serialized, commands on distinct
 * queues may execute concurrently, and lifecycle operations exclude every
 * queue without polling.  The group fabric is non-owning and must outlive
 * the bank.  Scratch storage is allocated once during initialization so a
 * queue kick cannot allocate.
 */
int	virtio_admin_queue_bank_create(struct virtio_admin_queue_bank **,
	    struct virtio_admin_group_fabric *, uint16_t, size_t, size_t);
void	virtio_admin_queue_bank_destroy(struct virtio_admin_queue_bank *);
uint16_t virtio_admin_queue_bank_count(
	    const struct virtio_admin_queue_bank *);
int	virtio_admin_queue_bank_process(struct virtio_admin_queue_bank *,
	    uint16_t, const struct iovec *, size_t, size_t, uint32_t *);
int	virtio_admin_queue_bank_drain(struct virtio_admin_queue_bank *,
	    uint16_t);
void	virtio_admin_queue_bank_reset(struct virtio_admin_queue_bank *);
int	virtio_admin_queue_bank_snapshot_size(
	    struct virtio_admin_queue_bank *, size_t *);
int	virtio_admin_queue_bank_snapshot(
	    struct virtio_admin_queue_bank *, void *, size_t);
bool	virtio_admin_queue_bank_storage_overlaps(
	    struct virtio_admin_queue_bank *, const void *, size_t);
int	virtio_admin_queue_bank_restore(
	    struct virtio_admin_queue_bank *, const void *, size_t);
int	virtio_admin_queue_bank_restore_validate(
	    struct virtio_admin_queue_bank *, const void *, size_t);

#endif /* _BHYVE_VIRTIO_ADMIN_QUEUE_H_ */
