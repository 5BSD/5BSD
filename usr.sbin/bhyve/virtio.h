/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	_BHYVE_VIRTIO_H_
#define	_BHYVE_VIRTIO_H_

#include <sys/endian.h>

#include <assert.h>
#include <stdatomic.h>
#include <string.h>

#include <machine/atomic.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtio_ring.h>
#include <dev/virtio/pci/virtio_pci_var.h>

#include "virtio_dma.h"
#include "virtio_packed.h"

/*
 * The transport and device constants below follow OASIS VirtIO 1.4.
 * Explicit legacy compatibility modes also retain selected historical
 * bhyve identities; those extensions are named separately from standard
 * transitional identities.
 */

/*
 * A virtual device has zero or more "virtual queues" (virtqueue).
 * Each virtqueue uses at least two 4096-byte pages, laid out thus:
 *
 *      +-----------------------------------------------+
 *      |    "desc":  <N> descriptors, 16 bytes each    |
 *      |   -----------------------------------------   |
 *      |   "avail":   2 uint16; <N> uint16; 1 uint16   |
 *      |   -----------------------------------------   |
 *      |              pad to 4k boundary               |
 *      +-----------------------------------------------+
 *      |   "used": 2 x uint16; <N> elems; 1 uint16     |
 *      |   -----------------------------------------   |
 *      |              pad to 4k boundary               |
 *      +-----------------------------------------------+
 *
 * The number <N> that appears here is always a power of two and is
 * limited to no more than 32768 (as it must fit in a 16-bit field).
 * If <N> is sufficiently large, the above will occupy more than
 * two pages.  In any case, all pages must be physically contiguous
 * within the guest's physical address space.
 *
 * The <N> 16-byte "desc" descriptors consist of a 64-bit guest
 * physical address <addr>, a 32-bit length <len>, a 16-bit
 * <flags>, and a 16-bit <next> field (all in guest byte order).
 *
 * There are three flags that may be set :
 *	NEXT    descriptor is chained, so use its "next" field
 *	WRITE   descriptor is for host to write into guest RAM
 *		(else host is to read from guest RAM)
 *	INDIRECT   descriptor address field is (guest physical)
 *		address of a linear array of descriptors
 *
 * Unless INDIRECT is set, <len> is the number of bytes that may
 * be read/written from guest physical address <addr>.  If
 * INDIRECT is set, WRITE is ignored and <len> provides the length
 * of the indirect descriptors (and <len> must be a multiple of
 * 16).  Note that NEXT may still be set in the main descriptor
 * pointing to the indirect, and should be set in each indirect
 * descriptor that uses the next descriptor (these should generally
 * be numbered sequentially).  However, INDIRECT must not be set
 * in the indirect descriptors.  Upon reaching an indirect descriptor
 * without a NEXT bit, control returns to the direct descriptors.
 *
 * Except inside an indirect, each <next> value must be in the
 * range [0 .. N) (i.e., the half-open interval).  (Inside an
 * indirect, each <next> must be in the range [0 .. <len>/16).)
 *
 * The "avail" data structures reside in the same pages as the
 * "desc" structures since both together are used by the device to
 * pass information to the hypervisor's virtual driver.  These
 * begin with a 16-bit <flags> field and 16-bit index <idx>, then
 * have <N> 16-bit <ring> values, followed by one final 16-bit
 * field <used_event>.  The <N> <ring> entries are simply indices
 * into the descriptor ring (and thus must meet the same
 * constraints as each <next> value).  However, <idx> is counted
 * up from 0 (initially) and simply wraps around after 65535; it
 * is taken mod <N> to find the next available entry.
 *
 * The "used" ring occupies a separate page or pages, and contains
 * values written from the virtual driver back to the guest OS.
 * This begins with a 16-bit <flags> and 16-bit <idx>, then there
 * are <N> "vring_used" elements, followed by a 16-bit <avail_event>.
 * The <N> "vring_used" elements consist of a 32-bit <id> and a
 * 32-bit <len> (vu_tlen below).  The <id> is simply the index of
 * the head of a descriptor chain the guest made available
 * earlier, and the <len> is the number of bytes actually written,
 * e.g., in the case of a network driver that provided a large
 * receive buffer but received only a small amount of data.
 *
 * The two event fields, <used_event> and <avail_event>, in the
 * avail and used rings (respectively -- note the reversal!), are
 * always provided, but are used only if the virtual device
 * negotiates the VIRTIO_RING_F_EVENT_IDX feature during feature
 * negotiation.  Similarly, both rings provide a flag --
 * VRING_AVAIL_F_NO_INTERRUPT and VRING_USED_F_NO_NOTIFY -- in
 * their <flags> field, indicating that the guest does not need an
 * interrupt, or that the hypervisor driver does not need a
 * notify, when descriptors are added to the corresponding ring.
 * (These are provided only for interrupt optimization and need
 * not be implemented.)
 */
#define VRING_ALIGN	4096

/*
 * The address of any given virtual queue is determined by a single
 * Page Frame Number register.  The guest writes the PFN into the
 * PCI config space.  However, a device that has two or more
 * virtqueues can have a different PFN, and size, for each queue.
 * The number of queues is determinable via the PCI config space
 * VTCFG_R_QSEL register.  Writes to QSEL select the queue: 0 means
 * queue #0, 1 means queue#1, etc.  Once a queue is selected, the
 * remaining PFN and QNUM registers refer to that queue.
 *
 * QNUM is a read-only register containing a nonzero power of two
 * that indicates the (hypervisor's) queue size.  Or, if reading it
 * produces zero, the hypervisor does not have a corresponding
 * queue.  (The number of possible queues depends on the virtual
 * device.  The block device has just one; the network device
 * provides either two -- 0 = receive, 1 = transmit -- or three,
 * with 2 = control.)
 *
 * PFN is a read/write register giving the physical page address of
 * the virtqueue in guest memory (the guest must allocate enough space
 * based on the hypervisor's provided QNUM).
 *
 * QNOTIFY is effectively write-only: when the guest writes a queue
 * number to the register, the hypervisor should scan the specified
 * virtqueue. (Reading QNOTIFY currently always gets 0).
 */

/*
 * PFN register shift amount
 */
#define	VRING_PFN		12

/* OASIS VirtIO 1.4 sections 4.1.2 and 4.1.2.3. */
#define	VIRTIO_VENDOR			0x1AF4
#define	VIRTIO_PCI_MODERN_DEVICE_BASE	0x1040
#define	VIRTIO_PCI_MODERN_SUBDEV_BASE	0x0040
#define	VIRTIO_PCI_MODERN_REVISION	1
#define	VIRTIO_PCI_TRANSITIONAL_NET	0x1000
#define	VIRTIO_PCI_TRANSITIONAL_BLOCK	0x1001
#define	VIRTIO_PCI_TRANSITIONAL_CONSOLE	0x1003
#define	VIRTIO_PCI_TRANSITIONAL_SCSI	0x1004
#define	VIRTIO_PCI_TRANSITIONAL_ENTROPY	0x1005
#define	VIRTIO_PCI_TRANSITIONAL_9P	0x1009

/*
 * Historical explicit-legacy compatibility identities.  VirtIO 1.4 defines
 * no transitional PCI identity for input or vsock, so neither constant is
 * part of the standards-conforming modern profile.
 */
#define	VIRTIO_PCI_COMPAT_INPUT_DEVICE	0x1052
#define	VIRTIO_PCI_COMPAT_INPUT_REVISION	1
#define	VIRTIO_PCI_COMPAT_INPUT_SUBVENDOR	0x108E
#define	VIRTIO_PCI_COMPAT_INPUT_SUBDEVICE	0x1100
#define	VIRTIO_PCI_COMPAT_VSOCK_DEVICE	0x1013

/* From section 2.3, "Virtqueue Configuration", of the virtio specification */
static inline int
vring_size_aligned(u_int qsz)
{
	return (roundup2(vring_size(qsz, VRING_ALIGN), VRING_ALIGN));
}

struct pci_devinst;
struct pci_snapshot_compat;
struct nvlist;
struct vqueue_info;
struct vm_snapshot_meta;
struct virtio_admin_pci_binding;

#define	VIRTIO_PCI_SHARED_MEMORY_MAX	8

struct virtio_pci_shared_memory_region {
	uint64_t offset;
	uint64_t length;
	uint8_t id;
	uint8_t bar;
};

struct virtio_pci_shared_memory_backing {
	void *base;
	void *arg;
	int (*read)(void *, uint64_t, int, uint64_t *);
	int (*write)(void *, uint64_t, int, uint64_t);
	uint64_t length;
	uint8_t id;
	bool writable;
};

/*
 * Modern PCI transport register state.  Keep this free of host pointers and
 * synchronization objects so restore can stage and roll back it atomically.
 */
struct virtio_pci_modern {
	uint64_t driver_features;
	struct virtio_pci_shared_memory_region
	    shared_memory[VIRTIO_PCI_SHARED_MEMORY_MAX];
	uint32_t device_feature_select;
	uint32_t driver_feature_select;
	int bar;
	uint8_t config_generation;
	uint8_t pci_cfg_capoff;
	uint8_t shared_memory_count;
	bool shared_memory_sealed;
	bool config_changed;
	bool config_pending;
	bool config_deferred;
};

enum virtio_pci_transport {
	VIRTIO_PCI_TRANSPORT_LEGACY,
	VIRTIO_PCI_TRANSPORT_MODERN,
};

enum virtio_pci_transport_policy {
	VIRTIO_PCI_LEGACY_DEFAULT,
	VIRTIO_PCI_MODERN_DEFAULT,
	VIRTIO_PCI_MODERN_ONLY,
};

enum virtio_queue_layout {
	VIRTIO_QUEUE_SPLIT,
	VIRTIO_QUEUE_PACKED,
};

/*
 * A virtual device, with some number (possibly 0) of virtual
 * queues and some size (possibly 0) of configuration-space
 * registers private to the device.  The virtio_softc should come
 * at the front of each "derived class", so that a pointer to the
 * virtio_softc is also a pointer to the more specific, derived-
 * from-virtio driver's softc.
 *
 * Note: inside each hypervisor virtio driver, changes to these
 * data structures must be locked against other threads, if any.
 * Except for PCI config space register read/write, we assume each
 * driver does the required locking, but we need a pointer to the
 * lock (if there is one) for PCI config space read/write ops.
 *
 * When the guest reads or writes the device's config space, the
 * generic layer checks for operations on the special registers
 * described above.  If the offset of the register(s) being read
 * or written is past the CFG area (CFG0 or CFG1), the request is
 * passed on to the virtual device, after subtracting off the
 * generic-layer size.  (So, drivers can just use the offset as
 * an offset into "struct config", for instance.)
 *
 * (The virtio layer also makes sure that the read or write is to/
 * from a "good" config offset, hence vc_cfgsize, and on BAR #0.
 * However, the driver must verify the read or write size and offset
 * and that no one is writing a readonly register.)
 *
 */
#define	VIRTIO_USE_MSIX		0x01

struct virtio_softc {
	struct virtio_consts *vs_vc;	/* constants (see below) */
	const struct virtio_platform_ops *vs_platform_ops;
	void	*vs_platform_arg;
	_Atomic(const struct virtio_dma_domain_ops *) vs_dma_domain_ops;
	void	*vs_dma_domain_arg;
	uint32_t vs_dma_endpoint;
	bool	vs_dma_access_platform_added;
	_Atomic bool vs_dma_detaching;
	_Atomic uint32_t vs_dma_active_requests;
	/*
	 * Runtime mappings for PCI shared-memory regions.  These pointers are
	 * destination-local resources and are intentionally kept out of the
	 * portable modern-transport snapshot.
	 */
	struct virtio_pci_shared_memory_backing
	    vs_shared_memory_backing[VIRTIO_PCI_SHARED_MEMORY_MAX];
	uint8_t vs_shared_memory_backing_count;
	int	vs_flags;		/* VIRTIO_* flags from above */
	pthread_mutex_t *vs_mtx;	/* POSIX mutex, if any */
	/* Innermost lock: never acquire vs_mtx while holding this mutex. */
	pthread_mutex_t vs_isr_mtx;	/* protects ISR and INTx state */
	struct pci_devinst *vs_pi;	/* PCI device instance */
	uint64_t vs_negotiated_caps;	/* negotiated capabilities */
	struct vqueue_info *vs_queues;	/* one per vc_nvq */
	/*
	 * Administration virtqueues occupy a distinct, potentially gapped PCI
	 * queue-number range.  They must never be folded into vc_nvq: the PCI
	 * num_queues field counts ordinary device queues only.  Staging storage
	 * here does not make it guest-visible; lookup admits this range only
	 * after VIRTIO_F_ADMIN_VQ has been negotiated.
	 */
	struct vqueue_info *vs_admin_queues;
	uint16_t vs_admin_queue_index;
	uint16_t vs_admin_queue_count;
	/* Runtime-only owner; portable state is serialized by the binding. */
	struct virtio_admin_pci_binding *vs_admin_binding;
	int	vs_curq;		/* current queue */
	/*
	 * Queue workers inspect status and may report a fatal ring/backend error
	 * without vs_mtx.  They cannot acquire vs_mtx in that path because a
	 * device reset holds it while waiting for those workers to drain.
	 * Keep these small cross-thread state fields atomic; device callbacks
	 * still use vs_mtx for their larger state transitions.
	 */
	_Atomic uint8_t vs_status;	/* value from last status write */
	_Atomic bool vs_resetting;	/* device reset callback is still active */
	_Atomic bool vs_reset_failed;	/* report reset callback failure on reinit */
	/*
	 * A restore callback can sometimes change external state before a later
	 * operation fails.  If its compensating operation also fails, the common
	 * snapshot rollback must not hide the resulting NEEDS_RESET indication
	 * when it restores the old in-memory status byte.
	 */
	_Atomic bool vs_restore_incomplete;
	/*
	 * Guest-visible suspend and bhyve checkpoint pause use the same queue
	 * ownership gate.  Snapshot pause does not alter device status.
	 */
	/*
	 * More than one lifecycle transition can fence queues at the same
	 * time.  In particular, a host checkpoint can overlap the tail of a
	 * guest-visible suspend or resume.  A reference count prevents either
	 * owner from reopening queue access while the other still drains.
	 */
	_Atomic unsigned int vs_quiescing;
	_Atomic bool vs_suspended;
	_Atomic bool vs_checkpoint_paused;
	_Atomic bool vs_config_deferred;
	/*
	 * Even outside reset, odd while a reset callback can drain workers and
	 * temporarily drop device locks.  vi_set_needs_reset() uses the epoch
	 * to detect a reset that crossed its lockless status update.
	 */
	_Atomic uint64_t vs_reset_epoch;
	uint8_t	vs_isr;			/* PCI ISR status flags */
	uint16_t vs_msix_cfg_idx;	/* MSI-X vector for config event */
	enum virtio_pci_transport vs_transport;
	struct virtio_pci_modern *vs_modern;
};

/*
 * Architecture and DMA-domain operations used by the common VirtIO queue
 * engine.  Device models must not translate guest addresses themselves.
 * The PCI default maps a guest physical address directly through vmctx;
 * ACCESS_PLATFORM and non-PCI transports can install a different mapper
 * without changing descriptor parsing or individual devices.
 */
struct virtio_platform_ops {
	void	*(*vpo_map_dma)(void *, uint64_t, size_t,
		    enum virtio_dma_direction);
	int	(*vpo_reverse_ram)(void *, void *, size_t, uint64_t *);
	void	(*vpo_mark_dma_dirty)(void *, void *, size_t);
	size_t	(*vpo_ram_page_size)(void *);
	int	(*vpo_discard_ram)(void *, uint64_t, size_t);
	int	(*vpo_undiscard_ram)(void *, uint64_t, size_t);
	bool	(*vpo_msix_enabled)(void *);
	void	(*vpo_raise_msix)(void *, uint16_t);
	void	(*vpo_raise_msi)(void *);
	void	(*vpo_set_intx)(void *, bool);
};

#define	VS_LOCK(vs)							\
do {									\
	if ((vs)->vs_mtx)						\
		pthread_mutex_lock((vs)->vs_mtx);			\
} while (0)

#define	VS_UNLOCK(vs)							\
do {									\
	if ((vs)->vs_mtx)						\
		pthread_mutex_unlock((vs)->vs_mtx);			\
} while (0)

#define	VS_ISR_LOCK(vs)	pthread_mutex_lock(&(vs)->vs_isr_mtx)
#define	VS_ISR_UNLOCK(vs)	pthread_mutex_unlock(&(vs)->vs_isr_mtx)

struct virtio_consts {
	const char *vc_name;		/* name of driver (for diagnostics) */
	int	vc_nvq;			/* number of virtual queues */
	size_t	vc_cfgsize;		/* size of dev-specific config regs */
	void	(*vc_reset)(void *);	/* called on virtual device reset */
	void	(*vc_qnotify)(void *, struct vqueue_info *);
					/* called on QNOTIFY if no VQ notify */
	int	(*vc_cfgread)(void *, int, int, uint32_t *);
					/* called to read config regs */
	int	(*vc_cfgwrite)(void *, int, int, uint32_t);
					/* called to write config regs */
	int     (*vc_apply_features)(void *, uint64_t);
				/* called to apply negotiated features */
	int	(*vc_qenable)(void *, struct vqueue_info *);
				/* called with vs_mtx held after queue enable */
	int	(*vc_qreset)(void *, struct vqueue_info *, uint64_t);
				/* with vs_mtx held; 0 or async EINPROGRESS */
	int	(*vc_suspend)(void *);
				/* quiesce/drain for guest suspend */
	int	(*vc_resume_device)(void *);
				/* restart after guest suspend */
	void	(*vc_resume_complete)(void *);
				/*
				 * Lifecycle gates are open; restart queue sources.
				 * Guest resume calls with vs_mtx held, checkpoint
				 * resume calls without it, so implementations must
				 * accept either ownership context.
				 */
	void	(*vc_restore_suspended)(void *);
				/*
				 * Infallibly retain guest-suspend ownership when
				 * restore transitions the destination from runnable
				 * to suspended while checkpoint pause still owns
				 * every backend resource.  It is not called for an
				 * already-suspended destination.  The generic snapshot layer
				 * does not impose a private-mutex ownership rule: a device's
				 * pause callback may retain it, while future devices may not.
				 */
	void	(*vc_restore_resumed)(void *);
				/*
				 * Infallibly release pre-existing guest-suspend ownership
				 * when restore transitions the destination from suspended
				 * to runnable.  Checkpoint ownership remains held until
				 * the common resume callback runs.  Like restore_suspended,
				 * it must tolerate either private-mutex ownership context.
				 */
	uint64_t vc_hv_caps;		/* hypervisor-provided capabilities */
	/*
	 * The corresponding guest driver ABI cannot use translated DMA.
	 * Do not place this function in VIOT or add ACCESS_PLATFORM merely
	 * because a VirtIO-IOMMU is present.
	 */
	bool	vc_access_platform_ineligible;
	int	(*vc_pause)(void *);	/* pause; return errno on failure */
	int	(*vc_resume)(void *);	/*
				 * Resume checkpoint ownership; return errno on failure.
				 * A failed resume leaves common checkpoint ownership
				 * intact and this callback can be retried without an
				 * intervening pause.  Implementations must therefore
				 * preserve or re-establish every private admission and
				 * locking invariant needed by that retry.
				 */
	int	(*vc_snapshot)(void *, struct vm_snapshot_meta *);
				/*
				 * Save or restore device state.  A failed restore
				 * must leave device and external-backend state
				 * unchanged.
				 */
};

bool	vi_pci_is_modern(const struct virtio_softc *);
bool	vi_pci_access_platform_eligible(const struct virtio_softc *);
struct virtio_softc *vi_pci_get_softc(struct pci_devinst *);
void	vi_set_platform_ops(struct virtio_softc *,
	    const struct virtio_platform_ops *, void *);
/*
 * Topology lifecycle operations serialize themselves with vs_mtx and must
 * therefore be called without that mutex held.  The caller retains the
 * external DMA-domain object's lifetime until vi_clear_dma_domain() succeeds.
 */
int	vi_set_dma_domain(struct virtio_softc *,
	    const struct virtio_dma_domain_ops *, void *, uint32_t);
int	vi_clear_dma_domain(struct virtio_softc *);
bool	vi_dma_acquire(struct virtio_softc *, struct virtio_dma_lease *);
void	vi_dma_release(struct virtio_softc *, struct virtio_dma_lease *);
void	*vi_map_dma(struct virtio_softc *, uint64_t, size_t,
	    enum virtio_dma_direction);
size_t	vi_platform_ram_page_size(struct virtio_softc *);
int	vi_platform_discard_ram(struct virtio_softc *, uint64_t, size_t);
int	vi_platform_undiscard_ram(struct virtio_softc *, uint64_t, size_t);
int	vi_platform_reverse_ram(struct virtio_softc *, void *, size_t,
	    uint64_t *);
void	vi_mark_dma_dirty(struct virtio_softc *, void *, size_t);
int	vi_config_read_le(const void *, size_t, int, int, uint32_t *);
bool	vi_platform_msix_enabled(struct virtio_softc *);
void	vi_platform_raise_msix(struct virtio_softc *, uint16_t);
void	vi_platform_raise_msi(struct virtio_softc *);
void	vi_platform_set_intx(struct virtio_softc *, bool);

/*
 * Data structure allocated (statically) per virtual queue.
 *
 * Drivers may change vq_qsize after a reset.  When the guest OS
 * requests a device reset, the hypervisor first calls
 * vs->vs_vc->vc_reset(); then the data structure below is
 * reinitialized (for each virtqueue: vs->vs_vc->vc_nvq).
 *
 * The remaining fields should only be fussed-with by the generic
 * code.
 *
 * Note: the addresses of vq_desc, vq_avail, and vq_used are all
 * computable from each other, but it's a lot simpler if we just
 * keep a pointer to each one.  The event indices are similarly
 * (but more easily) computable, and this time we'll compute them:
 * they're just XX_ring[N].
 */
#define	VQ_ALLOC	0x01	/* set once we have a pfn */
struct virtio_packed_completion;

struct vqueue_info {
	uint16_t vq_qsize;	/* split: power of 2; packed: 1..32768 */
	void	(*vq_notify)(void *, struct vqueue_info *);
				/* called instead of vc_notify, if not NULL */

	struct virtio_softc *vq_vs;	/* backpointer to softc */
	uint16_t vq_num;	/* we're the num'th queue in the softc */
	enum virtio_queue_layout vq_layout;

	uint16_t vq_flags;	/* flags (see above) */
	uint16_t vq_last_avail;	/* a recent value of vq_avail->idx */
	uint16_t vq_next_used;	/* index of the next used slot to be filled */
	uint16_t vq_save_used;	/* saved host vq_next_used; see vq_endchains */
	uint16_t vq_msix_idx;	/* MSI-X index, or VIRTIO_MSI_NO_VECTOR */

	uint32_t vq_pfn;	/* PFN of virt queue (not shifted!) */
	uint16_t vq_qsize_max;	/* modern: maximum queue size */
	uint16_t vq_enabled;	/* modern: queue_enable */
	uint16_t vq_reset;	/* modern: queue_reset */
	volatile uint16_t vq_resetting; /* queue backend is being drained */
	bool	 vq_notify_pending; /* kick deferred by status/lifecycle fence */
	uint64_t vq_generation;	/* changes whenever queue ownership resets */
	uint64_t vq_desc_gpa;	/* modern descriptor table address */
	uint64_t vq_driver_gpa;	/* modern available ring address */
	uint64_t vq_device_gpa;	/* modern used ring address */
	uint64_t vq_dma_generation; /* generation of cached ring mappings */
	bool	 vq_dma_generation_valid;
	/*
	 * Split rings do not carry an ownership bit.  Track each outstanding
	 * head in device-owned memory so copied asynchronous completion tokens
	 * cannot publish the same descriptor twice.
	 */
	uint8_t	*vq_split_owners;
	uint16_t vq_split_owner_count;

	struct vring_desc *vq_desc;	/* descriptor array */
	struct vring_avail *vq_avail;	/* the "avail" ring */
	struct vring_used *vq_used;	/* the "used" ring */
	struct virtio_packed_desc *vq_packed_desc;
	struct virtio_packed_event *vq_packed_driver_event;
	struct virtio_packed_event *vq_packed_device_event;
	uint16_t vq_packed_next_avail;
	uint16_t vq_packed_next_used;
	uint16_t vq_packed_save_used;
	bool	 vq_packed_avail_wrap;
	bool	 vq_packed_used_wrap;
	bool	 vq_packed_save_used_wrap;
	/*
	 * Packed queues used by asynchronous device models complete through
	 * this bounded reorder table.  It is host-owned transient state and
	 * is never part of a snapshot; checkpoint quiesce must drain it.
	 */
	struct virtio_packed_completion *vq_packed_completions;
	uint16_t vq_packed_completion_count;

};

static inline struct vqueue_info *
vi_pci_queue_lookup(struct virtio_softc *vs, uint32_t queue)
{
	uint32_t local;

	if (vs == NULL || vs->vs_vc == NULL || vs->vs_vc->vc_nvq < 0)
		return (NULL);
	if (queue < (uint32_t)vs->vs_vc->vc_nvq)
		return (vs->vs_queues == NULL ? NULL : &vs->vs_queues[queue]);
	if ((vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) == 0 ||
	    vs->vs_admin_queues == NULL ||
	    queue < vs->vs_admin_queue_index)
		return (NULL);
	local = queue - vs->vs_admin_queue_index;
	if (local >= vs->vs_admin_queue_count)
		return (NULL);
	return (&vs->vs_admin_queues[local]);
}

/*
 * Iterate allocated queue storage rather than queue selector values.  An
 * administration range may follow a hole, so treating an ordinal as a
 * selector would incorrectly turn the hole into ordinary queues.
 */
static inline size_t
vi_pci_queue_storage_count(const struct virtio_softc *vs)
{

	if (vs == NULL || vs->vs_vc == NULL || vs->vs_vc->vc_nvq < 0)
		return (0);
	return ((size_t)vs->vs_vc->vc_nvq + vs->vs_admin_queue_count);
}

static inline struct vqueue_info *
vi_pci_queue_at(struct virtio_softc *vs, size_t ordinal)
{
	size_t ordinary, local;

	if (vs == NULL || vs->vs_vc == NULL || vs->vs_vc->vc_nvq < 0)
		return (NULL);
	ordinary = (size_t)vs->vs_vc->vc_nvq;
	if (ordinal < ordinary)
		return (vs->vs_queues == NULL ? NULL : &vs->vs_queues[ordinal]);
	local = ordinal - ordinary;
	if (vs->vs_admin_queues == NULL ||
	    local >= vs->vs_admin_queue_count)
		return (NULL);
	return (&vs->vs_admin_queues[local]);
}

static inline bool
vi_pci_queue_is_admin(const struct virtio_softc *vs,
    const struct vqueue_info *vq)
{
	uintptr_t begin, end, candidate;
	size_t length;

	if (vs == NULL || vq == NULL || vs->vs_admin_queues == NULL ||
	    vs->vs_admin_queue_count == 0)
		return (false);
	begin = (uintptr_t)vs->vs_admin_queues;
	candidate = (uintptr_t)vq;
	if (__builtin_mul_overflow((size_t)vs->vs_admin_queue_count,
	    sizeof(*vq), &length) ||
	    __builtin_add_overflow(begin, length, &end))
		return (false);
	return (candidate >= begin && candidate < end &&
	    (candidate - begin) % sizeof(*vq) == 0);
}

/*
 * Modern VirtIO structures are little endian.  The legacy PCI interface
 * retains guest-native byte order; preserving that distinction keeps common
 * ring code portable without extending legacy identities into new devices.
 */
static inline uint16_t
vi16_to_cpu(const struct virtio_softc *vs, uint16_t value)
{

	return ((vs->vs_negotiated_caps & VIRTIO_F_VERSION_1) != 0 ?
	    le16toh(value) : value);
}

static inline uint32_t
vi32_to_cpu(const struct virtio_softc *vs, uint32_t value)
{

	return ((vs->vs_negotiated_caps & VIRTIO_F_VERSION_1) != 0 ?
	    le32toh(value) : value);
}

static inline uint64_t
vi64_to_cpu(const struct virtio_softc *vs, uint64_t value)
{

	return ((vs->vs_negotiated_caps & VIRTIO_F_VERSION_1) != 0 ?
	    le64toh(value) : value);
}

static inline uint16_t
vi16_from_cpu(const struct virtio_softc *vs, uint16_t value)
{

	return ((vs->vs_negotiated_caps & VIRTIO_F_VERSION_1) != 0 ?
	    htole16(value) : value);
}

static inline uint32_t
vi32_from_cpu(const struct virtio_softc *vs, uint32_t value)
{

	return ((vs->vs_negotiated_caps & VIRTIO_F_VERSION_1) != 0 ?
	    htole32(value) : value);
}

/*
 * As noted above, these are sort of backwards, name-wise.  The event fields
 * are trailing uint16_t values in guest little-endian ring images; use byte
 * codecs because the C flexible-array members do not establish alignment for
 * a cast beyond their declared element type.
 */
static inline uint16_t
vq_avail_event_idx(const struct vqueue_info *vq)
{
	uint16_t value;

	memcpy(&value, &vq->vq_used->ring[vq->vq_qsize], sizeof(value));
	return (vi16_to_cpu(vq->vq_vs, value));
}

static inline void
vq_set_avail_event_idx(struct vqueue_info *vq, uint16_t value)
{
	uint16_t encoded;

	encoded = vi16_from_cpu(vq->vq_vs, value);
	vi_mark_dma_dirty(vq->vq_vs,
	    &vq->vq_used->ring[vq->vq_qsize], sizeof(encoded));
	memcpy(&vq->vq_used->ring[vq->vq_qsize], &encoded, sizeof(encoded));
}

static inline uint16_t
vq_used_event_idx(const struct vqueue_info *vq)
{
	uint16_t value;

	memcpy(&value, &vq->vq_avail->ring[vq->vq_qsize], sizeof(value));
	return (vi16_to_cpu(vq->vq_vs, value));
}

/*
 * Is this ring ready for I/O?
 */
static inline int
vq_is_allocated(const struct vqueue_info *vq)
{

	return ((atomic_load_acq_16(&vq->vq_flags) & VQ_ALLOC) != 0);
}

static inline void
vq_set_allocated(struct vqueue_info *vq, bool allocated)
{

	atomic_store_rel_16(&vq->vq_flags, allocated ? VQ_ALLOC : 0);
}

static inline int
vq_is_resetting(const struct vqueue_info *vq)
{

	return (atomic_load_acq_16(&vq->vq_resetting) != 0);
}

static inline void
vq_set_resetting(struct vqueue_info *vq, bool resetting)
{

	atomic_store_rel_16(&vq->vq_resetting, resetting ? 1 : 0);
}

static inline int
vq_ring_ready(struct vqueue_info *vq)
{

	return (vq_is_allocated(vq) &&
	    !vq_is_resetting(vq) &&
	    !vq->vq_vs->vs_quiescing && !vq->vq_vs->vs_suspended &&
	    !vq->vq_vs->vs_checkpoint_paused &&
	    (vq->vq_vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);
}

/*
 * Are there "available" descriptors?  (This does not count
 * how many, just returns True if there are some.)
 */
int	vq_has_descs(struct vqueue_info *);

/*
 * Deliver an interrupt to the guest for a specific MSI-X queue or
 * event.
 */
static inline void
vi_interrupt(struct virtio_softc *vs, uint8_t isr, uint16_t msix_idx)
{

	if (vs->vs_suspended || vs->vs_checkpoint_paused)
		return;
	if (vi_platform_msix_enabled(vs)) {
		/*
		 * VirtIO 1.4 section 4.1.4.5.1 requires the device
		 * configuration bit to be set before a configuration change
		 * notification even when MSI-X is enabled.  Queue interrupts
		 * do not set the ISR in MSI-X mode.
		 */
		if ((isr & VIRTIO_PCI_ISR_CONFIG) != 0) {
			VS_ISR_LOCK(vs);
			vs->vs_isr |= VIRTIO_PCI_ISR_CONFIG;
			VS_ISR_UNLOCK(vs);
		}
		if (msix_idx != VIRTIO_MSI_NO_VECTOR)
			vi_platform_raise_msix(vs, msix_idx);
	} else {
		VS_ISR_LOCK(vs);
		vs->vs_isr |= isr;
		vi_platform_raise_msi(vs);
		vi_platform_set_intx(vs, true);
		VS_ISR_UNLOCK(vs);
	}
}

/*
 * Read and acknowledge all pending non-MSI-X interrupt reasons.  Keep the
 * ISR transition and INTx deassertion atomic with respect to vi_interrupt()
 * so a concurrent interrupt cannot leave a nonzero ISR with INTx deasserted.
 */
static inline uint8_t
vi_isr_read(struct virtio_softc *vs)
{
	uint8_t isr;

	VS_ISR_LOCK(vs);
	isr = vs->vs_isr;
	vs->vs_isr = 0;
	if (isr != 0)
		vi_platform_set_intx(vs, false);
	VS_ISR_UNLOCK(vs);

	return (isr);
}

/*
 * Deliver an interrupt to the guest on the given virtual queue (if
 * possible, or a generic MSI interrupt if not using MSI-X).
 */
static inline void
vq_interrupt(struct virtio_softc *vs, struct vqueue_info *vq)
{

	if (vq_is_resetting(vq))
		return;
	vi_interrupt(vs, VIRTIO_PCI_ISR_INTR, vq->vq_msix_idx);
}

void	vq_kick_enable(struct vqueue_info *);
void	vq_kick_disable(struct vqueue_info *);

struct iovec;

/*
 * Request description returned by vq_getchain.
 *
 * If ordered is true, writable iovecs start at iov[req.readable].
 * VirtIO drivers are required to place all device-readable descriptors
 * before any device-writable descriptors, but device models must validate
 * that guest-provided invariant before relying on it.
 */
struct vi_req {
	int readable;		/* num of readable iovecs */
	int writable;		/* num of writable iovecs */
	uint64_t writable_bytes; /* total device-writable capacity */
	bool ordered;		/* readable descriptors precede writable ones */
	bool lengths_known;	/* capacities came from descriptor parsing */
	unsigned int idx;	/* ring index */
	/*
	 * Completion identity for layout-neutral callers.  Split queues use
	 * only idx.  Packed queues additionally need the consumed descriptor
	 * span and wrap generation because an offset can be reused before an
	 * asynchronous completion returns.
	 */
	uint16_t descriptor_count;
	uint16_t completion_id;
	/*
	 * Split-ring producer cursor immediately after this request was
	 * acquired.  It makes a returned request prove that it is the current
	 * acquisition tail without rereading guest-owned avail memory.
	 */
	uint16_t split_avail_next;
	uint16_t packed_head;
	bool packed_wrap;
	enum virtio_queue_layout queue_layout;
	uint64_t queue_generation;
	bool dma_acquired;
	bool outstanding;
};

struct virtio_packed_completion {
	uint32_t iolen;
	uint16_t descriptor_count;
	uint16_t completion_id;
	uint16_t group_count;
	uint16_t group_prev_head;
	bool group_prev_wrap;
	bool packed_wrap;
	bool valid;
	/*
	 * Zero means the packed head is not held by a backend.  One and two
	 * identify a request acquired with wrap=false and wrap=true,
	 * respectively.  This queue-owned identity survives copied vi_req
	 * tokens and makes completion, rollback, and discard single-use.
	 */
	uint8_t owner_state;
};

void	vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
	    void *dev_softc, struct pci_devinst *pi,
	    struct vqueue_info *queues);
int	vi_pci_stage_admin_queues(struct virtio_softc *,
	    struct vqueue_info *, uint32_t, uint32_t);
int	vi_pci_select_transport(struct virtio_softc *, const struct nvlist *,
	    enum virtio_pci_transport_policy);
int	vi_pci_modern_init(struct virtio_softc *, int);
void	vi_pci_modern_set_identity(struct virtio_softc *, uint16_t);
/*
 * Add immutable PCI topology during single-threaded device initialization.
 * The caller owns the BAR mapping and its lifetime.
 */
int	vi_pci_modern_add_shared_memory(struct virtio_softc *, uint8_t,
	    uint8_t, uint64_t, uint64_t);
void	vi_pci_modern_seal_shared_memory(struct virtio_softc *);
/*
 * Initial backing registration occurs before vCPU start.  Replacement must
 * be performed by a device lifecycle owner while reset/quiesce fences guest
 * BAR access.  Once vCPUs can run, the caller must hold vs_mtx: lifecycle
 * callbacks are invoked with that mutex held, and these helpers deliberately
 * do not relock it before changing the runtime registry.
 */
int	vi_pci_modern_set_shared_memory_backing(struct virtio_softc *,
	    uint8_t, void *, uint64_t, bool);
int	vi_pci_modern_clear_shared_memory_backing(struct virtio_softc *,
	    uint8_t, void *);
/*
 * Callback-backed regions support sparse or dynamically remapped apertures.
 * Callbacks execute with the device mutex held and therefore must not invoke
 * an operation that takes that mutex again or changes transport, queue, or
 * lifecycle state.  A callback may use the lock-free vi_dma_acquire(),
 * vi_dma_release(), and vi_map_dma() lease/map trio: it is the explicitly
 * supported way for a sparse aperture to retain its DMA-domain binding while
 * it accesses destination-local state.  They return zero on success; failed
 * reads are reported to the guest as an all-ones value and failed writes are
 * dropped.
 */
int	vi_pci_modern_set_shared_memory_handler(struct virtio_softc *,
	    uint8_t, uint64_t, bool, void *,
	    int (*)(void *, uint64_t, int, uint64_t *),
	    int (*)(void *, uint64_t, int, uint64_t));
int	vi_pci_modern_clear_shared_memory_handler(struct virtio_softc *,
	    uint8_t, void *);
void	vi_pci_modern_reset(struct virtio_softc *);
void	vi_pci_modern_queue_reset_complete(struct vqueue_info *, uint64_t,
	    int);
/* Record a modern config change and notify; caller holds vs_mtx, if present. */
void	vi_pci_modern_config_changed(struct virtio_softc *);
/*
 * Mark modern device configuration as changed without raising an interrupt.
 * This is for specification-defined fields such as virtio-mem plugged_size
 * whose changes must participate in config_generation stable reads but must
 * not generate a configuration-change notification.
 */
void	vi_pci_modern_config_dirty(struct virtio_softc *);
/* Notify a config change using the active transport; caller holds vs_mtx. */
void	vi_pci_config_changed(struct virtio_softc *);
int	vi_pci_lifecycle_noop(void *);
void	vi_pci_quiesce_enter(struct virtio_softc *);
void	vi_pci_quiesce_exit(struct virtio_softc *);
void	vi_pci_reset_device(struct virtio_softc *);
uint64_t vi_pci_modern_read(struct pci_devinst *, int, uint64_t, int);
void	vi_pci_modern_write(struct pci_devinst *, int, uint64_t, int,
	    uint64_t);
int	vi_pci_modern_cfgread(struct pci_devinst *, int, int, uint32_t *);
int	vi_pci_modern_cfgwrite(struct pci_devinst *, int, int, uint32_t);
void	vi_pci_notify_queue(struct virtio_softc *, uint64_t);
void	vi_pci_notify_ready_queues(struct virtio_softc *);
int	vi_intr_init(struct virtio_softc *vs, int barnum, int use_msix);
void	vi_reset_dev(struct virtio_softc *);
/* Mark an unrecoverable device error and notify an active driver. */
void	vi_set_needs_reset(struct virtio_softc *);
/* Mark a snapshot restore whose external rollback could not be completed. */
void	vi_snapshot_restore_incomplete(struct virtio_softc *);
void	vi_set_io_bar(struct virtio_softc *, int);
uint64_t vi_modern_device_features(const struct virtio_softc *);

int	vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
	    struct vi_req *reqp);
void	vq_retchains(struct vqueue_info *vq, uint16_t n_chains);
/*
 * Return only an immediately rejected tail request.  A request which is not
 * the newest acquired chain cannot safely be returned; use
 * vq_discard_req() after invalidating the queue generation for asynchronous
 * cancellation or reset instead.
 */
void	vq_retchain_req(struct vqueue_info *, struct vi_req *);
void	vq_discard_req(struct vqueue_info *, struct vi_req *);
/*
 * Completion and publication are per-queue serialized operations.  A device
 * may use its device mutex, a queue worker, or another lifecycle-owned lock,
 * but it must never enter these helpers concurrently for the same queue.
 * This preserves packed completion-table ordering and split used-ring cursor
 * ownership while still permitting independent queues to run concurrently.
 */
void	vq_relchain_req(struct vqueue_info *, struct vi_req *, uint32_t);
void	vq_relchain_group(struct vqueue_info *, struct vi_req *,
	    const uint32_t *, unsigned int);
void	vq_endchains(struct vqueue_info *vq, int used_all_avail);
int	vq_packed_completions_init(struct vqueue_info *);
void	vq_packed_completions_fini(struct vqueue_info *);
void	vq_packed_completions_reset(struct vqueue_info *);
bool	vq_packed_completions_empty(const struct vqueue_info *);
bool	vq_split_owners_empty(const struct vqueue_info *);

uint64_t vi_pci_read(struct pci_devinst *pi, int baridx, uint64_t offset,
	    int size);
void	vi_pci_write(struct pci_devinst *pi, int baridx, uint64_t offset,
	    int size, uint64_t value);
#ifdef BHYVE_SNAPSHOT
int	vi_pci_snapshot(struct vm_snapshot_meta *meta);
int	vi_pci_snapshot_compat(struct pci_devinst *,
	    struct pci_snapshot_compat *);
int	vi_pci_pause(struct pci_devinst *pi);
int	vi_pci_resume(struct pci_devinst *pi);
int	vi_pci_modern_snapshot_transport(struct virtio_softc *,
	    struct vm_snapshot_meta *);
#endif
#endif	/* _BHYVE_VIRTIO_H_ */
