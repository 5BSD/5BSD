/* Mock of bhyve pci_emul.h for the vsock device harness. */
#ifndef MOCK_PCI_EMUL_H
#define MOCK_PCI_EMUL_H
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
struct vmctx;
struct vm_snapshot_meta;
struct pci_devemu;

/* Keep the mock ABI synchronized with bhyve's explicit migration contract. */
#define PCI_MIGRATION_F_STATE_CODEC		(1U << 0)
#define PCI_MIGRATION_F_COMPAT_FIXED		(1U << 1)
#define PCI_MIGRATION_F_COMPAT_CALLBACK		(1U << 2)
#define PCI_MIGRATION_F_DMA_NONE			(1U << 3)
#define PCI_MIGRATION_F_DMA_TRACKED		(1U << 4)
#define PCI_MIGRATION_F_QUIESCE_NONE		(1U << 5)
#define PCI_MIGRATION_F_QUIESCE_CALLBACK	(1U << 6)
#define PCI_MIGRATION_VIRTIO_FLAGS	(PCI_MIGRATION_F_STATE_CODEC | \
	PCI_MIGRATION_F_COMPAT_CALLBACK | PCI_MIGRATION_F_DMA_TRACKED | \
	PCI_MIGRATION_F_QUIESCE_CALLBACK)

#ifdef BHYVE_SNAPSHOT
#define PCI_SNAPSHOT_COMPAT_SCHEMA 1
#define PCI_SNAPSHOT_COMPAT_SHAPE_MAX 1024
enum pci_restore_phase {
	PCI_RESTORE_NORMAL = 0,
	PCI_RESTORE_FABRIC,
	PCI_RESTORE_PHASE_COUNT
};
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
static inline bool
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
static inline int
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
	if ((source->negotiated_features & ~source->offered_features) != 0)
		return (EINVAL);
	if (source->transport != destination->transport ||
	    source->queue_count != destination->queue_count ||
	    source->msix_table_count != destination->msix_table_count ||
	    source->config_size != destination->config_size ||
	    strcmp(source->queue_sizes, destination->queue_sizes) != 0 ||
	    strcmp(source->shared_memory, destination->shared_memory) != 0)
		return (ENOTSUP);
	if ((source->offered_features & ~destination->offered_features) != 0 ||
	    (source->negotiated_features &
	    ~destination->offered_features) != 0)
		return (ENOTSUP);
	return (0);
}
#endif
enum pcibar_type {
	PCIBAR_NONE,
	PCIBAR_IO,
	PCIBAR_MEM32,
	PCIBAR_MEM64,
};
struct pcibar {
	enum pcibar_type type;
	uint64_t size;
	uint64_t addr;
};
struct pci_dma_dirty_ops {
	int (*pddo_mark)(void *, uint64_t, size_t);
	void (*pddo_fail)(void *, int);
};
struct pci_devinst {
	struct vmctx *pi_vmctx;
	void *pi_arg;
	const struct pci_dma_dirty_ops *pi_dma_dirty_ops;
	void *pi_dma_dirty_arg;
	struct pci_devemu *pi_d;
	int pi_bus;
	int pi_slot;
	int pi_func;
	int pi_prevcap;
	int pi_capend;
	struct {
		int table_count;
	} pi_msix;
	struct pcibar pi_bar[7];
	uint8_t pi_cfgdata[256];
};
struct pci_devemu {
	const char *pe_emu;
	int (*pe_init)(struct pci_devinst *, nvlist_t *);
	int (*pe_post_init)(struct pci_devinst *);
	int (*pe_legacy_config)(nvlist_t *, const char *);
	int (*pe_cfgwrite)(struct pci_devinst *, int, int, uint32_t);
	int (*pe_cfgread)(struct pci_devinst *, int, int, uint32_t *);
	uint64_t (*pe_barread)(struct pci_devinst *, int, uint64_t, int);
	void (*pe_barwrite)(struct pci_devinst *, int, uint64_t, int, uint64_t);
#ifdef BHYVE_SNAPSHOT
	int (*pe_snapshot)(struct vm_snapshot_meta *);
	int (*pe_snapshot_validate)(struct vm_snapshot_meta *);
	void (*pe_snapshot_validate_cleanup)(struct pci_devinst *);
	int (*pe_snapshot_compat)(struct pci_devinst *,
	    struct pci_snapshot_compat *);
	int (*pe_pause)(struct pci_devinst *);
	int (*pe_resume)(struct pci_devinst *);
	enum pci_restore_phase pe_restore_phase;
	uint32_t pe_migration_flags;
#endif
};
#define PCI_EMUL_SET(x)
struct pci_devinst *pci_next(struct pci_devinst *);
int pci_snapshot(struct vm_snapshot_meta *);
int pci_snapshot_validate(struct vm_snapshot_meta *);
void pci_set_cfgdata8(struct pci_devinst *, int, uint8_t);
void pci_set_cfgdata16(struct pci_devinst *, int, uint16_t);
void pci_set_cfgdata32(struct pci_devinst *, int, uint32_t);
uint8_t pci_get_cfgdata8(struct pci_devinst *, int);
uint32_t pci_get_cfgdata32(struct pci_devinst *, int);
int pci_emul_alloc_bar(struct pci_devinst *, int, enum pcibar_type, uint64_t);
int pci_emul_alloc_devmem_gpa(uint64_t, uint64_t, uint64_t *);
int pci_emul_add_capability(struct pci_devinst *, const u_char *, int);
int pci_emul_add_msixcap(struct pci_devinst *, int, int);
int pci_emul_add_boot_device(struct pci_devinst *, int);
void pci_emul_add_msicap(struct pci_devinst *, int);
void pci_lintr_request(struct pci_devinst *);
int pci_msix_enabled(struct pci_devinst *);
int pci_msix_table_bar(struct pci_devinst *);
int pci_msix_pba_bar(struct pci_devinst *);
uint64_t pci_emul_msix_tread(struct pci_devinst *, uint64_t, int);
int pci_emul_msix_twrite(struct pci_devinst *, uint64_t, int, uint64_t);
void pci_generate_msix(struct pci_devinst *, int);
void pci_generate_msi(struct pci_devinst *, int);
void pci_lintr_assert(struct pci_devinst *);
void pci_lintr_deassert(struct pci_devinst *);
#define PCIR_DEVICE   0x02
#define PCIR_VENDOR   0x00
#define PCIR_CLASS    0x0b
#define PCIR_SUBCLASS 0x0a
#define PCIR_SUBVEND_0 0x2c
#define PCIR_SUBDEV_0  0x2e
#define PCIR_REVID     0x08
#define PCIC_SIMPLECOMM 0x07
#define PCIS_SIMPLECOMM_OTHER 0x80
#define PCIC_INPUTDEV 0x09
#define PCIS_INPUTDEV_OTHER 0x80
#define PCIC_CRYPTO 0x10
#define PCIC_STORAGE 0x01
#define PCIS_STORAGE_SCSI 0x00
#define PCIS_STORAGE_OTHER 0x80
#define PCIC_NETWORK 0x02
#define PCIC_MEMORY 0x05
#define PCIS_MEMORY_RAM 0x00
#endif
