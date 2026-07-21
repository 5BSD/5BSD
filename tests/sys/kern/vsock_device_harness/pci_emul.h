/* Mock of bhyve pci_emul.h for the vsock device harness. */
#ifndef MOCK_PCI_EMUL_H
#define MOCK_PCI_EMUL_H
#include <sys/types.h>
#include <stdint.h>
#include "config.h"
struct vmctx;
struct vm_snapshot_meta;
enum pcibar_type {
	PCIBAR_NONE,
	PCIBAR_IO,
	PCIBAR_MEM32,
	PCIBAR_MEM64,
};
struct pci_devinst {
	struct vmctx *pi_vmctx;
	void *pi_arg;
	int pi_slot;
	int pi_func;
	int pi_prevcap;
	int pi_capend;
	struct {
		int table_count;
	} pi_msix;
	uint8_t pi_cfgdata[256];
};
struct pci_devemu {
	const char *pe_emu;
	int (*pe_init)(struct pci_devinst *, nvlist_t *);
	int (*pe_legacy_config)(nvlist_t *, const char *);
	int (*pe_cfgwrite)(struct pci_devinst *, int, int, uint32_t);
	int (*pe_cfgread)(struct pci_devinst *, int, int, uint32_t *);
	uint64_t (*pe_barread)(struct pci_devinst *, int, uint64_t, int);
	void (*pe_barwrite)(struct pci_devinst *, int, uint64_t, int, uint64_t);
#ifdef BHYVE_SNAPSHOT
	int (*pe_snapshot)(struct vm_snapshot_meta *);
	int (*pe_pause)(struct pci_devinst *);
	int (*pe_resume)(struct pci_devinst *);
#endif
};
#define PCI_EMUL_SET(x)
void pci_set_cfgdata8(struct pci_devinst *, int, uint8_t);
void pci_set_cfgdata16(struct pci_devinst *, int, uint16_t);
void pci_set_cfgdata32(struct pci_devinst *, int, uint32_t);
uint8_t pci_get_cfgdata8(struct pci_devinst *, int);
uint32_t pci_get_cfgdata32(struct pci_devinst *, int);
int pci_emul_alloc_bar(struct pci_devinst *, int, enum pcibar_type, uint64_t);
int pci_emul_add_capability(struct pci_devinst *, const u_char *, int);
int pci_emul_add_msixcap(struct pci_devinst *, int, int);
void pci_emul_add_msicap(struct pci_devinst *, int);
void pci_lintr_request(struct pci_devinst *);
int pci_msix_enabled(struct pci_devinst *);
int pci_msix_table_bar(struct pci_devinst *);
int pci_msix_pba_bar(struct pci_devinst *);
uint64_t pci_emul_msix_tread(struct pci_devinst *, uint64_t, int);
void pci_emul_msix_twrite(struct pci_devinst *, uint64_t, int, uint64_t);
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
#define PCIC_INPUTDEV 0x09
#define PCIS_INPUTDEV_OTHER 0x80
#define PCIC_CRYPTO 0x10
#define PCIC_STORAGE 0x01
#define PCIC_NETWORK 0x02
#endif
