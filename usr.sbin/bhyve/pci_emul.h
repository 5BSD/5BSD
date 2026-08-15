/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PCI_EMUL_H_
#define _PCI_EMUL_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/nv.h>
#include <sys/pciio.h>
#include <sys/_pthreadtypes.h>

#include <dev/pci/pcireg.h>

#include <assert.h>
#include <errno.h>
#ifdef BHYVE_SNAPSHOT
#include <string.h>
#endif

#include "pci_irq.h"
#include "pci_config_image.h"

#define	PCI_BARMAX	PCIR_MAX_BAR_0	/* BAR registers in a Type 0 header */
#define PCI_BARMAX_WITH_ROM (PCI_BARMAX + 1)
#define PCI_ROM_IDX (PCI_BARMAX + 1)

struct vmctx;
struct pci_devinst;
struct memory_region;
struct vm_snapshot_meta;

/*
 * Migration is an explicit device-model contract, not an inference from a
 * subset of callbacks.  Each model must attest exactly one compatibility,
 * DMA, and quiesce policy in addition to supplying a portable state codec.
 */
#define	PCI_MIGRATION_F_STATE_CODEC		(1U << 0)
#define	PCI_MIGRATION_F_COMPAT_FIXED		(1U << 1)
#define	PCI_MIGRATION_F_COMPAT_CALLBACK		(1U << 2)
#define	PCI_MIGRATION_F_DMA_NONE			(1U << 3)
#define	PCI_MIGRATION_F_DMA_TRACKED		(1U << 4)
#define	PCI_MIGRATION_F_QUIESCE_NONE		(1U << 5)
#define	PCI_MIGRATION_F_QUIESCE_CALLBACK	(1U << 6)

#define	PCI_MIGRATION_F_ALL	(PCI_MIGRATION_F_STATE_CODEC | \
	PCI_MIGRATION_F_COMPAT_FIXED | PCI_MIGRATION_F_COMPAT_CALLBACK | \
	PCI_MIGRATION_F_DMA_NONE | PCI_MIGRATION_F_DMA_TRACKED | \
	PCI_MIGRATION_F_QUIESCE_NONE | PCI_MIGRATION_F_QUIESCE_CALLBACK)

#define	PCI_MIGRATION_VIRTIO_FLAGS	(PCI_MIGRATION_F_STATE_CODEC | \
	PCI_MIGRATION_F_COMPAT_CALLBACK | PCI_MIGRATION_F_DMA_TRACKED | \
	PCI_MIGRATION_F_QUIESCE_CALLBACK)

#ifdef BHYVE_SNAPSHOT
enum pci_restore_phase {
	/*
	 * Most devices restore in the normal phase.  Fabric devices whose
	 * state is required while restoring another device's DMA or interrupt
	 * state restore first.
	 */
	PCI_RESTORE_NORMAL = 0,
	PCI_RESTORE_FABRIC,
	PCI_RESTORE_PHASE_COUNT
};

#define	PCI_SNAPSHOT_COMPAT_SCHEMA	1
#define	PCI_SNAPSHOT_COMPAT_SHAPE_MAX	1024

/*
 * Architecture-neutral device requirements published alongside a checkpoint.
 * Strings contain canonical, comma-separated decimal values so the metadata
 * does not depend on host structure layout, byte order, or word size.
 */
struct pci_snapshot_compat {
	uint32_t schema;
	uint32_t transport;
	uint32_t queue_count;
	uint32_t msix_table_count;
	uint64_t config_size;
	uint64_t offered_features;
	uint64_t negotiated_features;
	uint32_t payload_crc32;
	char queue_sizes[PCI_SNAPSHOT_COMPAT_SHAPE_MAX];
	char shared_memory[PCI_SNAPSHOT_COMPAT_SHAPE_MAX];
};

static __inline bool
pci_snapshot_compat_shape_canonical(const char *shape, size_t capacity)
{
	const char *terminator;
	size_t used;

	terminator = memchr(shape, '\0', capacity);
	if (terminator == NULL)
		return (false);
	used = (size_t)(terminator - shape) + 1;
	for (size_t i = used; i < capacity; i++) {
		if (shape[i] != '\0')
			return (false);
	}
	return (true);
}

static __inline int
pci_snapshot_compat_validate(const struct pci_snapshot_compat *source,
    const struct pci_snapshot_compat *destination)
{

	if (source == NULL || destination == NULL ||
	    source->schema != PCI_SNAPSHOT_COMPAT_SCHEMA ||
	    destination->schema != PCI_SNAPSHOT_COMPAT_SCHEMA ||
	    !pci_snapshot_compat_shape_canonical(source->queue_sizes,
	    sizeof(source->queue_sizes)) ||
	    !pci_snapshot_compat_shape_canonical(source->shared_memory,
	    sizeof(source->shared_memory)) ||
	    !pci_snapshot_compat_shape_canonical(destination->queue_sizes,
	    sizeof(destination->queue_sizes)) ||
	    !pci_snapshot_compat_shape_canonical(destination->shared_memory,
	    sizeof(destination->shared_memory)))
		return (EINVAL);
	/*
	 * A source cannot have negotiated a bit which its own device did not
	 * offer.  Validate this independently of destination capabilities so a
	 * rewritten but internally checksummed checkpoint cannot synthesize a
	 * negotiation that was impossible on the source.
	 */
	if ((source->negotiated_features & ~source->offered_features) != 0)
		return (EINVAL);
	if (source->transport != destination->transport ||
	    source->queue_count != destination->queue_count ||
	    source->msix_table_count != destination->msix_table_count ||
	    source->config_size != destination->config_size ||
	    memcmp(source->queue_sizes, destination->queue_sizes,
	    sizeof(source->queue_sizes)) != 0 ||
	    memcmp(source->shared_memory, destination->shared_memory,
	    sizeof(source->shared_memory)) != 0)
		return (ENOTSUP);
	if ((source->offered_features & ~destination->offered_features) != 0 ||
	    (source->negotiated_features &
	    ~destination->offered_features) != 0)
		return (ENOTSUP);
	return (0);
}
#endif

struct pci_devemu {
	const char      *pe_emu;	/* Name of device emulation */

	/* instance creation */
	int       (*pe_init)(struct pci_devinst *, nvlist_t *);
	/*
	 * Called after every configured PCI function has completed pe_init()
	 * and BAR assignment, but before interrupt routing and vCPU startup.
	 * Cross-device fabrics such as an IOMMU must discover peers here
	 * rather than depending on slot initialization order.
	 */
	int	(*pe_post_init)(struct pci_devinst *);
	int	(*pe_legacy_config)(nvlist_t *, const char *);
	const char *pe_alias;

	/* ACPI DSDT enumeration */
	void	(*pe_write_dsdt)(struct pci_devinst *);

	/* config space read/write callbacks */
	int	(*pe_cfgwrite)(struct pci_devinst *pi, int offset,
			       int bytes, uint32_t val);
	int	(*pe_cfgread)(struct pci_devinst *pi, int offset,
			      int bytes, uint32_t *retval);

	/* BAR read/write callbacks */
	void      (*pe_barwrite)(struct pci_devinst *pi, int baridx,
				 uint64_t offset, int size, uint64_t value);
	uint64_t  (*pe_barread)(struct pci_devinst *pi, int baridx,
				uint64_t offset, int size);

	void	(*pe_baraddr)(struct pci_devinst *pi,
			      int baridx, int enabled, uint64_t address);

	/* Save/restore device state */
	int	(*pe_snapshot)(struct vm_snapshot_meta *meta);
#ifdef BHYVE_SNAPSHOT
	/*
	 * Consume and validate a restore record without publishing state or
	 * invoking an external backend.  Devices opt in as their codecs are
	 * converted; the restore coordinator runs every available validator
	 * before the first device commit.
	 */
	int	(*pe_snapshot_validate)(struct vm_snapshot_meta *meta);
	/*
	 * Release any temporary cross-device validation view after the
	 * coordinator has preflighted all records.  Most devices leave this
	 * NULL; fabric devices may stage an immutable incoming view which
	 * dependent devices use without publishing it.
	 */
	void	(*pe_snapshot_validate_cleanup)(struct pci_devinst *);
	int	(*pe_snapshot_compat)(struct pci_devinst *,
		    struct pci_snapshot_compat *);
#endif
	int	(*pe_pause)(struct pci_devinst *pi);
	int	(*pe_resume)(struct pci_devinst *pi);
#ifdef BHYVE_SNAPSHOT
	enum pci_restore_phase pe_restore_phase;
	uint32_t pe_migration_flags;
#endif

};
#define PCI_EMUL_SET(x)   DATA_SET(pci_devemu_set, x)

enum pcibar_type {
	PCIBAR_NONE,
	PCIBAR_IO,
	PCIBAR_MEM32,
	PCIBAR_MEM64,
	PCIBAR_MEMHI64,
	PCIBAR_ROM,
};

struct pcibar {
	enum pcibar_type	type;		/* io or memory */
	uint64_t		size;
	uint64_t		addr;
	uint8_t			lobits;
};

#define PI_NAMESZ	40

struct msix_table_entry {
	uint64_t	addr;
	uint32_t	msg_data;
	uint32_t	vector_control;
} __packed;

/*
 * In case the structure is modified to hold extra information, use a define
 * for the size that should be emulated.
 */
#define	MSIX_TABLE_ENTRY_SIZE	16
#define MAX_MSIX_TABLE_ENTRIES	2048
#define	PBA_SIZE(msgnum)	(roundup2((msgnum), 64) / 8)

struct pci_dma_dirty_ops {
	int	(*pddo_mark)(void *, uint64_t, size_t);
	void	(*pddo_fail)(void *, int);
};

/*
 * Direction is expressed from the emulated PCI function's point of view.
 * DEVICE_READ mappings are guest inputs.  DEVICE_WRITE and BIDIRECTIONAL
 * mappings may be changed by the device and therefore participate in the
 * process-local migration dirty epoch.
 */
enum pci_dma_direction {
	PCI_DMA_DEVICE_READ = 0,
	PCI_DMA_DEVICE_WRITE,
	PCI_DMA_BIDIRECTIONAL,
};

struct pci_devinst {
	struct pci_devemu *pi_d;
	struct vmctx *pi_vmctx;
	uint8_t	  pi_bus, pi_slot, pi_func;
	char	  pi_name[PI_NAMESZ];
	int	  pi_bar_getsize;
	int	  pi_prevcap;
	int	  pi_capend;

	struct {
		int8_t    	pin;
		enum {
			IDLE,
			ASSERTED,
			PENDING,
		} state;
		struct pci_irq	irq;
		pthread_mutex_t	lock;
	} pi_lintr;

	struct {
		int		enabled;
		uint64_t	addr;
		uint64_t	msg_data;
		int		maxmsgnum;
	} pi_msi;

	struct {
		int	enabled;
		int	table_bar;
		int	pba_bar;
		uint32_t table_offset;
		int	table_count;
		uint32_t pba_offset;
		int	pba_size;
		int	function_mask;
		struct msix_table_entry *table;	/* allocated at runtime */
		uint8_t *mapped_addr;
		size_t	mapped_size;
	} pi_msix;

	void      *pi_arg;		/* devemu-private data */
	/*
	 * Process-local emulated-DMA dirty source.  The operations remain
	 * installed for the PCI function lifetime and are a no-op until a
	 * migration generation is enabled for pi_vmctx.
	 */
	const struct pci_dma_dirty_ops *pi_dma_dirty_ops;
	void	  *pi_dma_dirty_arg;

#ifdef BHYVE_SNAPSHOT
	/*
	 * Checkpoint pause ownership belongs to the PCI layer, not to callers.
	 * This makes cleanup after a partially completed device walk safe for
	 * backends whose resume operation is not idempotent.
	 */
	bool	  pi_checkpoint_paused;
#endif

	u_char	  pi_cfgdata[PCI_REGMAX + 1];
	/* ROM is handled like a BAR */
	struct pcibar pi_bar[PCI_BARMAX_WITH_ROM + 1];
	uint64_t pi_romoffset;
};

void	*pci_emul_map_dma(struct pci_devinst *, uint64_t, size_t,
	    enum pci_dma_direction);
void	pci_emul_mark_dma_dirty(struct pci_devinst *, uint64_t, size_t);
void	pci_emul_mark_dma_dirty_mapping(struct pci_devinst *, void *, size_t);

/*
 * Preserve the capability-owned MSI control bits and constrain Multiple
 * Message Enable to Multiple Message Capable.  A malformed guest can write
 * the control register through byte, word, or dword config accesses, so this
 * normalization must not depend on one particular access width.
 */
static inline uint16_t
pci_msi_normalize_msgctrl(uint16_t advertised, uint16_t requested)
{
	const uint16_t writable = PCIM_MSICTRL_MME_MASK |
	    PCIM_MSICTRL_MSI_ENABLE;
	uint16_t normalized;
	unsigned int mmc, mme;

	normalized = (advertised & ~writable) | (requested & writable);
	mmc = (advertised & PCIM_MSICTRL_MMC_MASK) >> 1;
	mme = (normalized & PCIM_MSICTRL_MME_MASK) >> 4;
	if (mme > mmc) {
		normalized &= ~PCIM_MSICTRL_MME_MASK;
		normalized |= (uint16_t)(mmc << 4);
	}
	return (normalized);
}

typedef int (*pci_bar_registration_op)(void *, int, bool);

struct pci_bar_registration_result {
	uint32_t completed;
	int error;
	int rollback_error;
};

/*
 * Apply one command-register decode transition atomically.  A PCI command
 * write can enable one address space while disabling the other, so the two
 * masks describe the desired operation for each BAR.  If an intercept
 * operation fails, undo every earlier operation in reverse order before
 * returning the original error.  Keep rollback failure separate: the caller
 * cannot safely continue with an ambiguous host intercept topology.
 */
static inline struct pci_bar_registration_result
pci_bar_registration_transaction(void *arg, uint32_t register_mask,
    uint32_t unregister_mask, pci_bar_registration_op operation)
{
	struct pci_bar_registration_result result;
	const uint32_t valid_mask =
	    (UINT32_C(1) << (PCI_BARMAX_WITH_ROM + 1)) - 1;
	bool registration;
	int error, i;

	result = (struct pci_bar_registration_result){ 0 };
	if (operation == NULL ||
	    (register_mask & unregister_mask) != 0 ||
	    ((register_mask | unregister_mask) & ~valid_mask) != 0) {
		result.error = EINVAL;
		return (result);
	}

	for (i = 0; i < PCI_BARMAX_WITH_ROM + 1; i++) {
		if (((register_mask | unregister_mask) &
		    (UINT32_C(1) << i)) == 0)
			continue;
		registration = (register_mask & (UINT32_C(1) << i)) != 0;
		error = operation(arg, i, registration);
		if (error != 0) {
			result.error = error;
			break;
		}
		result.completed |= UINT32_C(1) << i;
	}
	if (result.error == 0)
		return (result);

	for (i--; i >= 0; i--) {
		if ((result.completed & (UINT32_C(1) << i)) == 0)
			continue;
		registration = (register_mask & (UINT32_C(1) << i)) != 0;
		error = operation(arg, i, !registration);
		if (result.rollback_error == 0 && error != 0)
			result.rollback_error = error;
	}
	return (result);
}

#ifdef BHYVE_SNAPSHOT
typedef void (*pci_snapshot_bar_visitor)(struct pci_devinst *, int, bool,
    void *);

static inline bool
pci_snapshot_restore_in_phase(const struct pci_devinst *pdi,
    enum pci_restore_phase phase)
{

	return (pdi->pi_d->pe_restore_phase == phase);
}

/*
 * A device restore is safe to enter only when the model can both consume the
 * record and perform the side-effect-free preflight which precedes RAM and
 * device publication.  Keep this as a runtime invariant as well as a source
 * audit: a newly added or conditionally initialized model must fail before
 * the destination is mutated, rather than being skipped during validation
 * and discovered by pci_snapshot() during the commit pass.
 */
static inline bool
pci_snapshot_restore_supported(const struct pci_devinst *pdi)
{

	return (pdi != NULL && pdi->pi_d != NULL &&
	    pdi->pi_d->pe_snapshot != NULL &&
	    pdi->pi_d->pe_snapshot_validate != NULL);
}

static inline int
pci_migration_device_validate(const struct pci_devinst *pdi)
{
	const struct pci_devemu *pde;
	uint32_t flags;

	if (pdi == NULL || pdi->pi_d == NULL)
		return (EINVAL);
	pde = pdi->pi_d;
	flags = pde->pe_migration_flags;
	if ((flags & ~PCI_MIGRATION_F_ALL) != 0)
		return (EINVAL);
	if ((flags & PCI_MIGRATION_F_STATE_CODEC) == 0 ||
	    pde->pe_snapshot == NULL || pde->pe_snapshot_validate == NULL)
		return (ENOTSUP);
	if (!!(flags & PCI_MIGRATION_F_COMPAT_FIXED) +
	    !!(flags & PCI_MIGRATION_F_COMPAT_CALLBACK) != 1)
		return (EINVAL);
	if ((flags & PCI_MIGRATION_F_COMPAT_CALLBACK) != 0 &&
	    pde->pe_snapshot_compat == NULL)
		return (EINVAL);
	if ((flags & PCI_MIGRATION_F_COMPAT_FIXED) != 0 &&
	    pde->pe_snapshot_compat != NULL)
		return (EINVAL);
	if (!!(flags & PCI_MIGRATION_F_DMA_NONE) +
	    !!(flags & PCI_MIGRATION_F_DMA_TRACKED) != 1)
		return (EINVAL);
	if (!!(flags & PCI_MIGRATION_F_QUIESCE_NONE) +
	    !!(flags & PCI_MIGRATION_F_QUIESCE_CALLBACK) != 1)
		return (EINVAL);
	if ((flags & PCI_MIGRATION_F_QUIESCE_CALLBACK) != 0 &&
	    (pde->pe_pause == NULL || pde->pe_resume == NULL))
		return (EINVAL);
	if ((flags & PCI_MIGRATION_F_QUIESCE_NONE) != 0 &&
	    (pde->pe_pause != NULL || pde->pe_resume != NULL))
		return (EINVAL);
	return (0);
}

/*
 * Dependency ordering is the inverse for quiesce and resume.  Endpoints must
 * drain before a translation/interrupt fabric is frozen; the fabric must be
 * reconstructed before endpoints can resume DMA.
 */
static inline enum pci_restore_phase
pci_checkpoint_lifecycle_phase(unsigned int index, bool resume)
{

	assert(index < PCI_RESTORE_PHASE_COUNT);
	return (resume ?
	    (enum pci_restore_phase)(PCI_RESTORE_PHASE_COUNT - 1 - index) :
	    (enum pci_restore_phase)index);
}

static inline void
pci_snapshot_validate_cleanup(struct pci_devinst *pdi)
{

	if (pdi != NULL && pdi->pi_d != NULL &&
	    pdi->pi_d->pe_snapshot_validate_cleanup != NULL)
		(*pdi->pi_d->pe_snapshot_validate_cleanup)(pdi);
}

static inline bool
pci_snapshot_msi_state_valid(int enabled, int maxmsgnum)
{

	if (enabled != 0 && enabled != 1)
		return (false);
	if (enabled == 0)
		return (maxmsgnum == 0);
	return (maxmsgnum >= 1 && maxmsgnum <= 32 &&
	    (maxmsgnum & (maxmsgnum - 1)) == 0);
}

static inline bool
pci_snapshot_bar_decoded(const struct pci_devinst *pdi, int idx)
{
	uint16_t command;

	command = pdi->pi_cfgdata[PCIR_COMMAND] |
	    (uint16_t)pdi->pi_cfgdata[PCIR_COMMAND + 1] << 8;
	switch (pdi->pi_bar[idx].type) {
	case PCIBAR_IO:
		return ((command & PCIM_CMD_PORTEN) != 0);
	case PCIBAR_MEM32:
	case PCIBAR_MEM64:
		return ((command & PCIM_CMD_MEMEN) != 0);
	case PCIBAR_ROM:
		return ((command & PCIM_CMD_MEMEN) != 0 &&
		    (pdi->pi_bar[idx].lobits & PCIM_BIOS_ENABLE) != 0);
	default:
		return (false);
	}
}

static inline void
pci_snapshot_visit_decoded_bars(struct pci_devinst *pdi, bool registration,
    pci_snapshot_bar_visitor visitor, void *arg)
{

	for (int i = 0; i < PCI_BARMAX_WITH_ROM + 1; i++) {
		if (pci_snapshot_bar_decoded(pdi, i))
			visitor(pdi, i, registration, arg);
	}
}

static inline int
pci_checkpoint_pause(struct pci_devinst *pdi)
{
	struct pci_devemu *pde;
	int error;

	pde = pdi->pi_d;
	if (pde->pe_pause == NULL && pde->pe_resume == NULL)
		return (0);
	if (pde->pe_pause == NULL || pde->pe_resume == NULL)
		return (ENOTSUP);
	if (pdi->pi_checkpoint_paused)
		return (0);
	error = (*pde->pe_pause)(pdi);
	if (error == 0)
		pdi->pi_checkpoint_paused = true;
	return (error);
}

static inline int
pci_checkpoint_resume(struct pci_devinst *pdi)
{
	struct pci_devemu *pde;
	int error;

	pde = pdi->pi_d;
	if (pde->pe_pause == NULL && pde->pe_resume == NULL)
		return (0);
	if (pde->pe_pause == NULL || pde->pe_resume == NULL)
		return (ENOTSUP);
	if (!pdi->pi_checkpoint_paused)
		return (0);
	error = (*pde->pe_resume)(pdi);
	if (error == 0)
		pdi->pi_checkpoint_paused = false;
	return (error);
}
#endif

struct msicap {
	uint8_t		capid;
	uint8_t		nextptr;
	uint16_t	msgctrl;
	uint32_t	addrlo;
	uint32_t	addrhi;
	uint16_t	msgdata;
} __packed;
static_assert(sizeof(struct msicap) == 14, "compile-time assertion failed");

struct msixcap {
	uint8_t		capid;
	uint8_t		nextptr;
	uint16_t	msgctrl;
	uint32_t	table_info;	/* bar index and offset within it */
	uint32_t	pba_info;	/* bar index and offset within it */
} __packed;
static_assert(sizeof(struct msixcap) == 12, "compile-time assertion failed");

struct pciecap {
	uint8_t		capid;
	uint8_t		nextptr;
	uint16_t	pcie_capabilities;

	uint32_t	dev_capabilities;	/* all devices */
	uint16_t	dev_control;
	uint16_t	dev_status;

	uint32_t	link_capabilities;	/* devices with links */
	uint16_t	link_control;
	uint16_t	link_status;

	uint32_t	slot_capabilities;	/* ports with slots */
	uint16_t	slot_control;
	uint16_t	slot_status;

	uint16_t	root_control;		/* root ports */
	uint16_t	root_capabilities;
	uint32_t	root_status;

	uint32_t	dev_capabilities2;	/* all devices */
	uint16_t	dev_control2;
	uint16_t	dev_status2;

	uint32_t	link_capabilities2;	/* devices with links */
	uint16_t	link_control2;
	uint16_t	link_status2;

	uint32_t	slot_capabilities2;	/* ports with slots */
	uint16_t	slot_control2;
	uint16_t	slot_status2;
} __packed;
static_assert(sizeof(struct pciecap) == 60, "compile-time assertion failed");

typedef void (*pci_lintr_cb)(int b, int s, int pin, struct pci_irq *irq,
    void *arg);
void	pci_lintr_assert(struct pci_devinst *pi);
void	pci_lintr_deassert(struct pci_devinst *pi);
void	pci_lintr_request(struct pci_devinst *pi);
int	pci_count_lintr(int bus);
void	pci_walk_lintr(int bus, pci_lintr_cb cb, void *arg);

int	init_pci(struct vmctx *ctx);
void	pci_callback(void);
uint32_t pci_config_read_reg(const struct pci_conf *host_conf, nvlist_t *nvl,
	    uint32_t reg, uint8_t size, uint32_t def);
int	pci_emul_alloc_bar(struct pci_devinst *pdi, int idx,
	    enum pcibar_type type, uint64_t size);
/*
 * Allocate guest-physical device memory outside ordinary RAM and the PCI
 * MMIO apertures.  Device initialization is serialized by init_pci().
 */
int	pci_emul_alloc_devmem_gpa(uint64_t size, uint64_t alignment,
	    uint64_t *addr);
int 	pci_emul_alloc_rom(struct pci_devinst *const pdi, const uint64_t size,
    	    void **const addr);
int 	pci_emul_add_boot_device(struct pci_devinst *const pi,
	    const int bootindex);
int	pci_emul_add_capability(struct pci_devinst *pi, const u_char *capdata,
	    int caplen);
int	pci_emul_add_msicap(struct pci_devinst *pi, int msgnum);
int	pci_emul_add_pciecap(struct pci_devinst *pi, int pcie_device_type);
void	pci_emul_capwrite(struct pci_devinst *pi, int offset, int bytes,
	    uint32_t val, uint8_t capoff, int capid);
void	pci_emul_cmd_changed(struct pci_devinst *pi, uint16_t old);
void	pci_generate_msi(struct pci_devinst *pi, int msgnum);
void	pci_generate_msix(struct pci_devinst *pi, int msgnum);
int	pci_msi_enabled(struct pci_devinst *pi);
int	pci_msix_enabled(struct pci_devinst *pi);
int	pci_msix_table_bar(struct pci_devinst *pi);
int	pci_msix_pba_bar(struct pci_devinst *pi);
int	pci_msi_maxmsgnum(struct pci_devinst *pi);
int	pci_parse_legacy_config(nvlist_t *nvl, const char *opt);
int	pci_parse_slot(char *opt);
void    pci_print_supported_devices(void);
void	pci_populate_msicap(struct msicap *cap, int msgs, int nextptr);
int	pci_emul_add_msixcap(struct pci_devinst *pi, int msgnum, int barnum);
int	pci_emul_msix_twrite(struct pci_devinst *pi, uint64_t offset, int size,
			     uint64_t value);
uint64_t pci_emul_msix_tread(struct pci_devinst *pi, uint64_t offset, int size);
void	pci_write_dsdt(void);
uint64_t pci_ecfg_base(void);
int	pci_bus_configured(int bus);

struct pci_devinst *pci_next(const struct pci_devinst *cursor);
#ifdef BHYVE_SNAPSHOT
int	pci_snapshot(struct vm_snapshot_meta *meta);
int	pci_snapshot_validate(struct vm_snapshot_meta *meta);
int	pci_snapshot_compat(struct pci_devinst *,
	    struct pci_snapshot_compat *);
int	pci_migration_precopy_validate(void);
int	pci_pause(struct pci_devinst *pdi);
int	pci_resume(struct pci_devinst *pdi);
#endif

static __inline void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t val)
{
	assert(offset <= PCI_REGMAX);
	pci_config_image_store8(pi->pi_cfgdata, offset, val);
}

static __inline void
pci_set_cfgdata16(struct pci_devinst *pi, int offset, uint16_t val)
{
	assert(offset <= (PCI_REGMAX - 1) && (offset & 1) == 0);
	pci_config_image_store16(pi->pi_cfgdata, offset, val);
}

static __inline void
pci_set_cfgdata32(struct pci_devinst *pi, int offset, uint32_t val)
{
	assert(offset <= (PCI_REGMAX - 3) && (offset & 3) == 0);
	pci_config_image_store32(pi->pi_cfgdata, offset, val);
}

static __inline uint8_t
pci_get_cfgdata8(struct pci_devinst *pi, int offset)
{
	assert(offset <= PCI_REGMAX);
	return (pci_config_image_load8(pi->pi_cfgdata, offset));
}

static __inline uint16_t
pci_get_cfgdata16(struct pci_devinst *pi, int offset)
{
	assert(offset <= (PCI_REGMAX - 1) && (offset & 1) == 0);
	return (pci_config_image_load16(pi->pi_cfgdata, offset));
}

static __inline uint32_t
pci_get_cfgdata32(struct pci_devinst *pi, int offset)
{
	assert(offset <= (PCI_REGMAX - 3) && (offset & 3) == 0);
	return (pci_config_image_load32(pi->pi_cfgdata, offset));
}

#endif /* _PCI_EMUL_H_ */
