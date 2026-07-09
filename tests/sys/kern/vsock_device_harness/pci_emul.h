/* Mock of bhyve pci_emul.h for the vsock device harness. */
#ifndef MOCK_PCI_EMUL_H
#define MOCK_PCI_EMUL_H
#include <stdint.h>
#include "config.h"
struct pci_devinst;
struct pci_devemu {
	const char *pe_emu;
	int (*pe_init)(struct pci_devinst *, nvlist_t *);
	int (*pe_legacy_config)(nvlist_t *, const char *);
	uint64_t (*pe_barread)(struct pci_devinst *, int, uint64_t, int);
	void (*pe_barwrite)(struct pci_devinst *, int, uint64_t, int, uint64_t);
};
#define PCI_EMUL_SET(x)
void pci_set_cfgdata8(struct pci_devinst *, int, uint8_t);
void pci_set_cfgdata16(struct pci_devinst *, int, uint16_t);
#define PCIR_DEVICE   0x02
#define PCIR_VENDOR   0x00
#define PCIR_CLASS    0x0b
#define PCIR_SUBCLASS 0x0a
#define PCIR_SUBVEND_0 0x2c
#define PCIR_SUBDEV_0  0x2e
#define PCIC_SIMPLECOMM 0x07
#endif
