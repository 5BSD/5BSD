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

#include <sys/param.h>
#include <sys/endian.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/pciio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <dev/io/iodev.h>
#include <dev/pci/pcireg.h>
#include <dev/vmm/vmm_mem.h>

#include <vm/vm.h>

#include <machine/iodev.h>
#include <machine/vm.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>

#include <machine/vmm.h>

#include "debug.h"
#include "mem.h"
#include "pci_passthru.h"

#ifndef _PATH_DEVPCI
#define	_PATH_DEVPCI	"/dev/pci"
#endif

#define	LEGACY_SUPPORT	1

#define MSIX_TABLE_COUNT(ctrl) (((ctrl) & PCIM_MSIXCTRL_TABLE_SIZE) + 1)
#define MSIX_CAPLEN 12

#define PASSTHRU_MMIO_MAX 3

static int pcifd = -1;

SET_DECLARE(passthru_dev_set, struct passthru_dev);

struct passthru_bar_handler {
	TAILQ_ENTRY(passthru_bar_handler) chain;
	uint64_t off;
	uint64_t size;
	passthru_read_handler read;
	passthru_write_handler write;
};

struct passthru_softc {
	struct pci_devinst *psc_pi;
	/* ROM is handled like a BAR */
	struct pcibar psc_bar[PCI_BARMAX_WITH_ROM + 1];
	struct {
		int		capoff;
		int		msgctrl;
		int		emulated;
	} psc_msi;
	struct {
		int		capoff;
	} psc_msix;
	struct pcisel psc_sel;

	struct passthru_mmio_mapping psc_mmio_map[PASSTHRU_MMIO_MAX];
	cfgread_handler psc_pcir_rhandler[PCI_REGMAX + 1];
	cfgwrite_handler psc_pcir_whandler[PCI_REGMAX + 1];

	TAILQ_HEAD(,
	    passthru_bar_handler) psc_bar_handler[PCI_BARMAX_WITH_ROM + 1];
};

static int
msi_caplen(int msgctrl)
{
	int len;

	len = 10;		/* minimum length of msi capability */

	if (msgctrl & PCIM_MSICTRL_64BIT)
		len += 4;

#if 0
	/*
	 * Ignore the 'mask' and 'pending' bits in the MSI capability.
	 * We'll let the guest manipulate them directly.
	 */
	if (msgctrl & PCIM_MSICTRL_VECTOR)
		len += 10;
#endif

	return (len);
}

static int
pcifd_open(void)
{
	int fd;

	fd = open(_PATH_DEVPCI, O_RDWR, 0);
	if (fd < 0) {
		warn("failed to open %s", _PATH_DEVPCI);
		return (-1);
	}
	return (fd);
}

static int
pcifd_init(void)
{
	pcifd = pcifd_open();
	if (pcifd < 0)
		return (1);

#ifndef WITHOUT_CAPSICUM
	cap_rights_t pcifd_rights;
	cap_rights_init(&pcifd_rights, CAP_IOCTL, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(pcifd, &pcifd_rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");

	const cap_ioctl_t pcifd_ioctls[] = { PCIOCREAD, PCIOCWRITE, PCIOCGETBAR,
		PCIOCBARIO, PCIOCBARMMAP, PCIOCGETCONF };
	if (caph_ioctls_limit(pcifd, pcifd_ioctls, nitems(pcifd_ioctls)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	return (0);
}

static uint32_t
host_read_config(int fd, const struct pcisel *sel, long reg, int width)
{
	struct pci_io pi;

	bzero(&pi, sizeof(pi));
	pi.pi_sel = *sel;
	pi.pi_reg = reg;
	pi.pi_width = width;

	if (ioctl(fd, PCIOCREAD, &pi) < 0)
		return (0);			/* XXX */
	else
		return (pi.pi_data);
}

static uint32_t
passthru_read_config(const struct pcisel *sel, long reg, int width)
{
	return (host_read_config(pcifd, sel, reg, width));
}

uint32_t
pci_host_read_config(const struct pcisel *sel, long reg, int width)
{
	uint32_t ret;
	int fd;

	fd = pcifd_open();
	if (fd < 0)
		return (0);
	ret = host_read_config(fd, sel, reg, width);
	(void)close(fd);
	return (ret);
}

static void
host_write_config(int fd, const struct pcisel *sel, long reg, int width,
    uint32_t data)
{
	struct pci_io pi;

	bzero(&pi, sizeof(pi));
	pi.pi_sel = *sel;
	pi.pi_reg = reg;
	pi.pi_width = width;
	pi.pi_data = data;

	(void)ioctl(fd, PCIOCWRITE, &pi);		/* XXX */
}

static void
passthru_write_config(const struct pcisel *sel, long reg, int width,
    uint32_t data)
{
	host_write_config(pcifd, sel, reg, width, data);
}

void
pci_host_write_config(const struct pcisel *sel, long reg, int width,
    uint32_t data)
{
	int fd;

	fd = pcifd_open();
	if (fd < 0)
		return;
	host_write_config(fd, sel, reg, width, data);
	(void)close(fd);
}

#ifdef LEGACY_SUPPORT
static int
passthru_add_msicap(struct pci_devinst *pi, int msgnum, int nextptr)
{
	int capoff;
	struct msicap msicap;
	u_char *capdata;

	pci_populate_msicap(&msicap, msgnum, nextptr);

	/*
	 * XXX
	 * Copy the msi capability structure in the last 16 bytes of the
	 * config space. This is wrong because it could shadow something
	 * useful to the device.
	 */
	capoff = 256 - roundup(sizeof(msicap), 4);
	capdata = (u_char *)&msicap;
	for (size_t i = 0; i < sizeof(msicap); i++)
		pci_set_cfgdata8(pi, capoff + i, capdata[i]);

	return (capoff);
}
#endif	/* LEGACY_SUPPORT */

static int
cfginitmsi(struct passthru_softc *sc)
{
	int i, ptr, capptr, cap, sts, caplen, table_size, ncap;
	uint32_t u32;
	struct pcisel sel;
	struct pci_devinst *pi;
	struct msixcap msixcap;
	char *msixcap_ptr;

	pi = sc->psc_pi;
	sel = sc->psc_sel;

	/*
	 * Parse the capabilities and cache the location of the MSI
	 * and MSI-X capabilities.
	 */
	sts = passthru_read_config(&sel, PCIR_STATUS, 2);
	if (sts & PCIM_STATUS_CAPPRESENT) {
		ptr = passthru_read_config(&sel, PCIR_CAP_PTR, 1);
		ncap = 0;
		while (ptr != 0 && ptr != 0xff) {
			if (ptr < 0x40 || ptr > PCI_REGMAX - 3 ||
			    (ptr & 3) != 0 || ++ncap > 48) {
				warnx("invalid PCI capability chain for %d/%d/%d",
				    sel.pc_bus, sel.pc_dev, sel.pc_func);
				return (-1);
			}
			cap = passthru_read_config(&sel, ptr + PCICAP_ID, 1);
			if (cap == PCIY_MSI) {
				/*
				 * Copy the MSI capability into the config
				 * space of the emulated pci device
				 */
				sc->psc_msi.capoff = ptr;
				sc->psc_msi.msgctrl =
				    passthru_read_config(&sel, ptr + 2, 2);
				sc->psc_msi.emulated = 0;
				caplen = msi_caplen(sc->psc_msi.msgctrl);
				if (caplen <= 0 || ptr > PCI_REGMAX + 1 - caplen) {
					warnx("invalid MSI capability for %d/%d/%d",
					    sel.pc_bus, sel.pc_dev, sel.pc_func);
					return (-1);
				}
				capptr = ptr;
				while (caplen > 0) {
					u32 = passthru_read_config(&sel, capptr,
					    4);
					pci_set_cfgdata32(pi, capptr, u32);
					caplen -= 4;
					capptr += 4;
				}
			} else if (cap == PCIY_MSIX) {
				/*
				 * Copy the MSI-X capability
				 */
				sc->psc_msix.capoff = ptr;
				caplen = 12;
				if (ptr > PCI_REGMAX + 1 - caplen) {
					warnx("invalid MSI-X capability for %d/%d/%d",
					    sel.pc_bus, sel.pc_dev, sel.pc_func);
					return (-1);
				}
				msixcap_ptr = (char *)&msixcap;
				capptr = ptr;
				while (caplen > 0) {
					u32 = passthru_read_config(&sel, capptr,
					    4);
					memcpy(msixcap_ptr, &u32, 4);
					pci_set_cfgdata32(pi, capptr, u32);
					caplen -= 4;
					capptr += 4;
					msixcap_ptr += 4;
				}
			}
			ptr = passthru_read_config(&sel, ptr + PCICAP_NEXTPTR,
			    1);
		}
	}

	if (sc->psc_msix.capoff != 0) {
		pi->pi_msix.pba_bar =
		    msixcap.pba_info & PCIM_MSIX_BIR_MASK;
		pi->pi_msix.pba_offset =
		    msixcap.pba_info & ~PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_bar =
		    msixcap.table_info & PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_offset =
		    msixcap.table_info & ~PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_count = MSIX_TABLE_COUNT(msixcap.msgctrl);
		pi->pi_msix.pba_size = PBA_SIZE(pi->pi_msix.table_count);

		/* Allocate the emulated MSI-X table array */
		table_size = pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
		pi->pi_msix.table = calloc(1, table_size);
		if (pi->pi_msix.table == NULL)
			return (-1);

		/* Mask all table entries */
		for (i = 0; i < pi->pi_msix.table_count; i++) {
			pi->pi_msix.table[i].vector_control |=
						PCIM_MSIX_VCTRL_MASK;
		}
	}

#ifdef LEGACY_SUPPORT
	/*
	 * If the passthrough device does not support MSI then craft a
	 * MSI capability for it. We link the new MSI capability at the
	 * head of the list of capabilities.
	 */
	if ((sts & PCIM_STATUS_CAPPRESENT) != 0 && sc->psc_msi.capoff == 0) {
		int origptr, msiptr;
		origptr = passthru_read_config(&sel, PCIR_CAP_PTR, 1);
		msiptr = passthru_add_msicap(pi, 1, origptr);
		sc->psc_msi.capoff = msiptr;
		sc->psc_msi.msgctrl = pci_get_cfgdata16(pi, msiptr + 2);
		sc->psc_msi.emulated = 1;
		pci_set_cfgdata8(pi, PCIR_CAP_PTR, msiptr);
	}
#endif

	/* Make sure one of the capabilities is present */
	if (sc->psc_msi.capoff == 0 && sc->psc_msix.capoff == 0)
		return (-1);
	else
		return (0);
}

static uint64_t
msix_table_read(struct passthru_softc *sc, uint64_t offset, int size)
{
	struct pci_devinst *pi;
	struct msix_table_entry *entry;
	uint64_t data;
	uint64_t table_end;
	uint8_t wire[MSIX_TABLE_ENTRY_SIZE];
	size_t entry_offset;
	uint32_t table_offset;
	int index, table_count;

	pi = sc->psc_pi;
	data = 0;

	table_offset = pi->pi_msix.table_offset;
	table_count = pi->pi_msix.table_count;
	if (pi->pi_msix.mapped_addr == NULL ||
	    !(size == 1 || size == 2 || size == 4 || size == 8) ||
	    offset > pi->pi_msix.mapped_size ||
	    (uint64_t)size > pi->pi_msix.mapped_size - offset)
		return (UINT64_MAX);
	table_end = (uint64_t)table_offset +
	    (uint64_t)table_count * MSIX_TABLE_ENTRY_SIZE;
	if (offset < table_offset ||
	    offset >= table_end) {
		if (offset < table_offset &&
		    (uint64_t)size > table_offset - offset)
			return (UINT64_MAX);
		memcpy(&data, pi->pi_msix.mapped_addr + offset, size);
		switch (size) {
		case 1:
			break;
		case 2:
			data = le16toh((uint16_t)data);
			break;
		case 4:
			data = le32toh((uint32_t)data);
			break;
		case 8:
			data = le64toh(data);
			break;
		}
		return (data);
	}
	if ((uint64_t)size > table_end - offset)
		return (UINT64_MAX);

	offset -= table_offset;
	index = offset / MSIX_TABLE_ENTRY_SIZE;
	if (index < 0 || index >= table_count)
		return (UINT64_MAX);

	entry = &pi->pi_msix.table[index];
	entry_offset = offset % MSIX_TABLE_ENTRY_SIZE;

	if ((size_t)size > sizeof(*entry) - entry_offset)
		return (UINT64_MAX);
	le64enc(wire, entry->addr);
	le32enc(wire + 8, entry->msg_data);
	le32enc(wire + 12, entry->vector_control);
	switch (size) {
	case 1:
		data = wire[entry_offset];
		break;
	case 2:
		data = le16dec(wire + entry_offset);
		break;
	case 4:
		data = le32dec(wire + entry_offset);
		break;
	case 8:
		data = le64dec(wire + entry_offset);
		break;
	default:
		return (UINT64_MAX);
	}

	return (data);
}

static void
msix_table_write(struct passthru_softc *sc, uint64_t offset, int size,
    uint64_t data)
{
	struct pci_devinst *pi;
	struct msix_table_entry *entry;
	uint64_t little_data;
	uint64_t table_end;
	size_t entry_offset;
	uint32_t table_offset, vector_control;
	int index, table_count;

	pi = sc->psc_pi;

	table_offset = pi->pi_msix.table_offset;
	table_count = pi->pi_msix.table_count;
	if (pi->pi_msix.mapped_addr == NULL ||
	    !(size == 1 || size == 2 || size == 4 || size == 8) ||
	    offset > pi->pi_msix.mapped_size ||
	    (uint64_t)size > pi->pi_msix.mapped_size - offset)
		return;
	table_end = (uint64_t)table_offset +
	    (uint64_t)table_count * MSIX_TABLE_ENTRY_SIZE;
	if (offset < table_offset ||
	    offset >= table_end) {
		if (offset < table_offset &&
		    (uint64_t)size > table_offset - offset)
			return;
		switch (size) {
		case 1:
			little_data = data;
			break;
		case 2:
			little_data = htole16(data);
			break;
		case 4:
			little_data = htole32(data);
			break;
		case 8:
			little_data = htole64(data);
			break;
		}
		memcpy(pi->pi_msix.mapped_addr + offset, &little_data, size);
		return;
	}
	if ((uint64_t)size > table_end - offset)
		return;

	offset -= table_offset;
	index = offset / MSIX_TABLE_ENTRY_SIZE;
	if (index < 0 || index >= table_count)
		return;

	entry = &pi->pi_msix.table[index];
	entry_offset = offset % MSIX_TABLE_ENTRY_SIZE;

	/* Only 4 byte naturally-aligned writes are supported */
	if (size != 4 || entry_offset % 4 != 0 ||
	    entry_offset + size > sizeof(*entry))
		return;

	vector_control = entry->vector_control;
	switch (entry_offset) {
	case 0:
		entry->addr = (entry->addr & UINT64_C(0xffffffff00000000)) |
		    (uint32_t)data;
		break;
	case 4:
		entry->addr = (entry->addr & UINT64_C(0x00000000ffffffff)) |
		    ((uint64_t)(uint32_t)data << 32);
		break;
	case 8:
		entry->msg_data = (uint32_t)data;
		break;
	case 12:
		entry->vector_control = (uint32_t)data;
		break;
	default:
		return;
	}
	/* If MSI-X hasn't been enabled, do nothing */
	if (pi->pi_msix.enabled) {
		/* If the entry is masked, don't set it up */
		if ((entry->vector_control & PCIM_MSIX_VCTRL_MASK) == 0 ||
		    (vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
			(void)vm_setup_pptdev_msix(sc->psc_pi->pi_vmctx,
			    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev,
			    sc->psc_sel.pc_func, index, entry->addr,
			    entry->msg_data, entry->vector_control);
		}
	}
}

static int
init_msix_table(struct passthru_softc *sc)
{
	struct pci_devinst *pi = sc->psc_pi;
	struct pci_bar_mmap pbm;
	int b, s, f;
	uint64_t table_size, table_offset;

	if (pci_msix_table_bar(pi) < 0 || pci_msix_pba_bar(pi) < 0)
		return (EINVAL);

	b = sc->psc_sel.pc_bus;
	s = sc->psc_sel.pc_dev;
	f = sc->psc_sel.pc_func;

	/*
	 * Map the region of the BAR containing the MSI-X table.  This is
	 * necessary for two reasons:
	 * 1. The PBA may reside in the first or last page containing the MSI-X
	 *    table.
	 * 2. While PCI devices are not supposed to use the page(s) containing
	 *    the MSI-X table for other purposes, some do in practice.
	 */
	memset(&pbm, 0, sizeof(pbm));
	pbm.pbm_sel = sc->psc_sel;
	pbm.pbm_flags = PCIIO_BAR_MMAP_RW;
	pbm.pbm_reg = PCIR_BAR(pi->pi_msix.table_bar);
	pbm.pbm_memattr = VM_MEMATTR_DEVICE;

	if (ioctl(pcifd, PCIOCBARMMAP, &pbm) != 0) {
		warn("Failed to map MSI-X table BAR on %d/%d/%d", b, s, f);
		return (-1);
	}
	if (pbm.pbm_bar_off != 0 || pbm.pbm_map_base == 0 ||
	    pbm.pbm_map_length == 0) {
		warnx("Invalid MSI-X BAR mapping on %d/%d/%d", b, s, f);
		if (pbm.pbm_map_base != 0 && pbm.pbm_map_length != 0)
			(void)munmap((void *)(uintptr_t)pbm.pbm_map_base,
			    pbm.pbm_map_length);
		return (EINVAL);
	}
	table_offset = rounddown2(pi->pi_msix.table_offset, 4096);
	if (pi->pi_msix.table_count <= 0 ||
	    (uint64_t)pi->pi_msix.table_count >
	    (UINT64_MAX - (pi->pi_msix.table_offset - table_offset)) /
	    MSIX_TABLE_ENTRY_SIZE) {
		warnx("Invalid MSI-X table size on %d/%d/%d", b, s, f);
		(void)munmap((void *)(uintptr_t)pbm.pbm_map_base,
		    pbm.pbm_map_length);
		return (EINVAL);
	}

	table_size = pi->pi_msix.table_offset - table_offset;
	table_size += pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
	if (table_size > UINT64_MAX - 4095) {
		(void)munmap((void *)(uintptr_t)pbm.pbm_map_base,
		    pbm.pbm_map_length);
		return (EINVAL);
	}
	table_size = roundup2(table_size, UINT64_C(4096));
	if (table_offset > pbm.pbm_map_length ||
	    table_size > pbm.pbm_map_length - table_offset) {
		warnx("MSI-X table exceeds BAR mapping on %d/%d/%d", b, s, f);
		(void)munmap((void *)(uintptr_t)pbm.pbm_map_base,
		    pbm.pbm_map_length);
		return (EINVAL);
	}
	pi->pi_msix.mapped_addr = (uint8_t *)(uintptr_t)pbm.pbm_map_base;
	pi->pi_msix.mapped_size = pbm.pbm_map_length;

	/*
	 * Unmap any pages not containing the table, we do not need to emulate
	 * accesses to them.  Avoid releasing address space to help ensure that
	 * a buggy out-of-bounds access causes a crash.
	 */
	if (table_offset != 0)
		if (mprotect(pi->pi_msix.mapped_addr, table_offset,
		    PROT_NONE) != 0)
			warn("Failed to unmap MSI-X table BAR region");
	if (table_offset + table_size != pi->pi_msix.mapped_size)
		if (mprotect(
		    pi->pi_msix.mapped_addr + table_offset + table_size,
		    pi->pi_msix.mapped_size - (table_offset + table_size),
		    PROT_NONE) != 0)
			warn("Failed to unmap MSI-X table BAR region");

	return (0);
}

static int
cfginitbar(struct passthru_softc *sc)
{
	int i, error;
	struct pci_devinst *pi;
	struct pci_bar_io bar;
	enum pcibar_type bartype;
	uint64_t base, size;

	pi = sc->psc_pi;

	/*
	 * Initialize BAR registers
	 */
	for (i = 0; i <= PCI_BARMAX; i++) {
		uint8_t lobits;

		bzero(&bar, sizeof(bar));
		bar.pbi_sel = sc->psc_sel;
		bar.pbi_reg = PCIR_BAR(i);

		if (ioctl(pcifd, PCIOCGETBAR, &bar) < 0)
			continue;

		if (PCI_BAR_IO(bar.pbi_base)) {
			bartype = PCIBAR_IO;
			base = bar.pbi_base & PCIM_BAR_IO_BASE;
		} else {
			switch (bar.pbi_base & PCIM_BAR_MEM_TYPE) {
			case PCIM_BAR_MEM_64:
				bartype = PCIBAR_MEM64;
				break;
			default:
				bartype = PCIBAR_MEM32;
				break;
			}
			base = bar.pbi_base & PCIM_BAR_MEM_BASE;
		}
		size = bar.pbi_length;

		if (bartype != PCIBAR_IO) {
			if (((base | size) & PAGE_MASK) != 0) {
				warnx("passthru device %d/%d/%d BAR %d: "
				    "base %#lx or size %#lx not page aligned\n",
				    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev,
				    sc->psc_sel.pc_func, i, base, size);
				return (-1);
			}
		}

		/* Cache information about the "real" BAR */
		sc->psc_bar[i].type = bartype;
		sc->psc_bar[i].size = size;
		sc->psc_bar[i].addr = base;
		sc->psc_bar[i].lobits = 0;

		/* Allocate the BAR in the guest I/O or MMIO space */
		error = pci_emul_alloc_bar(pi, i, bartype, size);
		if (error)
			return (-1);

		/* Use same lobits as physical bar */
		lobits = (uint8_t)passthru_read_config(&sc->psc_sel,
		    PCIR_BAR(i), 0x01);
		if (bartype == PCIBAR_MEM32 || bartype == PCIBAR_MEM64) {
			lobits &= ~PCIM_BAR_MEM_BASE;
		} else {
			lobits &= ~PCIM_BAR_IO_BASE;
		}
		sc->psc_bar[i].lobits = lobits;
		pi->pi_bar[i].lobits = lobits;

		/*
		 * 64-bit BAR takes up two slots so skip the next one.
		 */
		if (bartype == PCIBAR_MEM64) {
			i++;
			if (i > PCI_BARMAX) {
				warnx("passthru device %d/%d/%d has an invalid "
				    "64-bit BAR at index %d", sc->psc_sel.pc_bus,
				    sc->psc_sel.pc_dev, sc->psc_sel.pc_func, i - 1);
				return (-1);
			}
			sc->psc_bar[i].type = PCIBAR_MEMHI64;
		}
	}
	return (0);
}

static int
cfginit(struct pci_devinst *pi, int bus, int slot, int func)
{
	int error;
	struct passthru_softc *sc;
	uint16_t cmd;
	uint8_t intline, intpin;

	error = 1;
	sc = pi->pi_arg;

	bzero(&sc->psc_sel, sizeof(struct pcisel));
	sc->psc_sel.pc_bus = bus;
	sc->psc_sel.pc_dev = slot;
	sc->psc_sel.pc_func = func;

	/*
	 * Copy physical PCI header to virtual config space.  COMMAND,
	 * INTLINE, and INTPIN shouldn't be aligned with their
	 * physical value and they are already set by pci_emul_init().
	 */
	cmd = pci_get_cfgdata16(pi, PCIR_COMMAND);
	intline = pci_get_cfgdata8(pi, PCIR_INTLINE);
	intpin = pci_get_cfgdata8(pi, PCIR_INTPIN);
	for (int i = 0; i <= PCIR_MAXLAT; i += 4) {
		pci_set_cfgdata32(pi, i,
		    passthru_read_config(&sc->psc_sel, i, 4));
	}
	pci_set_cfgdata16(pi, PCIR_COMMAND, cmd);
	pci_set_cfgdata8(pi, PCIR_INTLINE, intline);
	pci_set_cfgdata8(pi, PCIR_INTPIN, intpin);

	if (cfginitmsi(sc) != 0) {
		warnx("failed to initialize MSI for PCI %d/%d/%d",
		    bus, slot, func);
		goto done;
	}

	if (cfginitbar(sc) != 0) {
		warnx("failed to initialize BARs for PCI %d/%d/%d",
		    bus, slot, func);
		goto done;
	}

	if (pci_msix_table_bar(pi) >= 0) {
		error = init_msix_table(sc);
		if (error != 0) {
			warnx(
			    "failed to initialize MSI-X table for PCI %d/%d/%d: %d",
			    bus, slot, func, error);
			goto done;
		}
	}

	error = 0;				/* success */
done:
	return (error);
}

struct passthru_mmio_mapping *
passthru_get_mmio(struct passthru_softc *sc, int num)
{
	if (sc == NULL || num < 0 || num >= PASSTHRU_MMIO_MAX)
		return (NULL);

	return (&sc->psc_mmio_map[num]);
}

struct pcisel *
passthru_get_sel(struct passthru_softc *sc)
{
	if (sc == NULL)
		return (NULL);

	return (&sc->psc_sel);
}

int
set_pcir_handler(struct passthru_softc *sc, int reg, int len,
    cfgread_handler rhandler, cfgwrite_handler whandler)
{
	if (sc == NULL || reg < 0 || len <= 0 || reg > PCI_REGMAX ||
	    len > PCI_REGMAX + 1 - reg)
		return (-1);

	for (int i = reg; i < reg + len; ++i) {
		if ((sc->psc_pcir_rhandler[i] != NULL && rhandler != NULL) ||
		    (sc->psc_pcir_whandler[i] != NULL && whandler != NULL))
			return (-1);
	}
	for (int i = reg; i < reg + len; ++i) {
		sc->psc_pcir_rhandler[i] = rhandler;
		sc->psc_pcir_whandler[i] = whandler;
	}

	return (0);
}

int
passthru_set_bar_handler(struct passthru_softc *sc, int baridx, uint64_t off,
    uint64_t size, passthru_read_handler rhandler,
    passthru_write_handler whandler)
{
	struct passthru_bar_handler *handler_new;
	struct passthru_bar_handler *handler;

	if (sc == NULL || baridx < 0 || baridx > PCI_BARMAX || size == 0 ||
	    off > UINT64_MAX - size || off + size > sc->psc_bar[baridx].size ||
	    (sc->psc_bar[baridx].type != PCIBAR_IO &&
	    sc->psc_bar[baridx].type != PCIBAR_MEM32 &&
	    sc->psc_bar[baridx].type != PCIBAR_MEM64))
		return (EINVAL);

	handler_new = malloc(sizeof(struct passthru_bar_handler));
	if (handler_new == NULL) {
		return (ENOMEM);
	}

	handler_new->off = off;
	handler_new->size = size;
	handler_new->read = rhandler;
	handler_new->write = whandler;

	TAILQ_FOREACH(handler, &sc->psc_bar_handler[baridx], chain) {
		if (handler->off < handler_new->off) {
			if (handler->off + handler->size > handler_new->off) {
				free(handler_new);
				return (EEXIST);
			}
			continue;
		}
		if (handler->off < handler_new->off + handler_new->size) {
			free(handler_new);
			return (EEXIST);
		}
		TAILQ_INSERT_BEFORE(handler, handler_new, chain);
		return (0);
	}

	TAILQ_INSERT_TAIL(&sc->psc_bar_handler[baridx], handler_new, chain);

	return (0);
}

static int
passthru_legacy_config(nvlist_t *nvl, const char *opts)
{
	const char *cp;
	char *tofree;
	char value[16];
	int bus, slot, func;

	if (opts == NULL)
		return (0);

	cp = strchr(opts, ',');

	if (strncmp(opts, "ppt", strlen("ppt")) == 0) {
		tofree = cp != NULL ? strndup(opts, cp - opts) : strdup(opts);
		if (tofree == NULL)
			return (ENOMEM);
		set_config_value_node(nvl, "pptdev", tofree);
		free(tofree);
	} else if (sscanf(opts, "pci0:%d:%d:%d", &bus, &slot, &func) == 3 ||
	    sscanf(opts, "pci%d:%d:%d", &bus, &slot, &func) == 3 ||
	    sscanf(opts, "%d/%d/%d", &bus, &slot, &func) == 3) {
		snprintf(value, sizeof(value), "%d", bus);
		set_config_value_node(nvl, "bus", value);
		snprintf(value, sizeof(value), "%d", slot);
		set_config_value_node(nvl, "slot", value);
		snprintf(value, sizeof(value), "%d", func);
		set_config_value_node(nvl, "func", value);
	} else {
		EPRINTLN("passthru: invalid options \"%s\"", opts);
		return (-1);
	}

	if (cp == NULL) {
		return (0);
	}

	return (pci_parse_legacy_config(nvl, cp + 1));
}

static int
passthru_init_rom(struct passthru_softc *const sc, const char *const romfile)
{
	if (romfile == NULL) {
		return (0);
	}

	const int fd = open(romfile, O_RDONLY);
	if (fd < 0) {
		warnx("%s: can't open romfile \"%s\"", __func__, romfile);
		return (-1);
	}

	struct stat sbuf;
	if (fstat(fd, &sbuf) < 0) {
		warnx("%s: can't fstat romfile \"%s\"", __func__, romfile);
		close(fd);
		return (-1);
	}
	const uint64_t rom_size = sbuf.st_size;
	if (sbuf.st_size <= 0) {
		warnx("%s: romfile \"%s\" is empty", __func__, romfile);
		close(fd);
		return (-1);
	}

	void *const rom_data = mmap(NULL, rom_size, PROT_READ, MAP_SHARED, fd,
	    0);
	if (rom_data == MAP_FAILED) {
		warnx("%s: unable to mmap romfile \"%s\" (%d)", __func__,
		    romfile, errno);
		close(fd);
		return (-1);
	}

	void *rom_addr;
	int error = pci_emul_alloc_rom(sc->psc_pi, rom_size, &rom_addr);
	if (error) {
		warnx("%s: failed to alloc rom segment", __func__);
		munmap(rom_data, rom_size);
		close(fd);
		return (error);
	}
	memcpy(rom_addr, rom_data, rom_size);

	sc->psc_bar[PCI_ROM_IDX].type = PCIBAR_ROM;
	sc->psc_bar[PCI_ROM_IDX].addr = (uint64_t)rom_addr;
	sc->psc_bar[PCI_ROM_IDX].size = rom_size;

	munmap(rom_data, rom_size);
	close(fd);

	return (0);
}

static bool
passthru_lookup_pptdev(const char *name, int *bus, int *slot, int *func)
{
	struct pci_conf_io pc;
	struct pci_conf conf[1];
	struct pci_match_conf patterns[1];
	char *cp;

	bzero(&pc, sizeof(struct pci_conf_io));
	pc.match_buf_len = sizeof(conf);
	pc.matches = conf;

	bzero(&patterns, sizeof(patterns));

	/*
	 * The pattern structure requires the unit to be split out from
	 * the driver name.  Walk backwards from the end of the name to
	 * find the start of the unit.
	 */
	cp = strchr(name, '\0');
	assert(cp != NULL);
	while (cp != name && isdigit(cp[-1]))
		cp--;
	if (cp == name || !isdigit(*cp)) {
		EPRINTLN("Invalid passthru device name %s", name);
		return (false);
	}
	if ((size_t)(cp - name) + 1 > sizeof(patterns[0].pd_name)) {
		EPRINTLN("Passthru device name %s is too long", name);
		return (false);
	}
	memcpy(patterns[0].pd_name, name, cp - name);
	patterns[0].pd_unit = strtol(cp, &cp, 10);
	if (*cp != '\0') {
		EPRINTLN("Invalid passthru device name %s", name);
		return (false);
	}
	patterns[0].flags = PCI_GETCONF_MATCH_NAME | PCI_GETCONF_MATCH_UNIT;
	pc.num_patterns = 1;
	pc.pat_buf_len = sizeof(patterns);
	pc.patterns = patterns;

	if (ioctl(pcifd, PCIOCGETCONF, &pc) == -1) {
		EPRINTLN("ioctl(PCIOCGETCONF): %s", strerror(errno));
		return (false);
	}
	if (pc.status != PCI_GETCONF_LAST_DEVICE &&
	    pc.status != PCI_GETCONF_MORE_DEVS) {
		EPRINTLN("error returned from PCIOCGETCONF ioctl");
		return (false);
	}
	if (pc.num_matches == 0) {
		EPRINTLN("Passthru device %s not found", name);
		return (false);
	}

	if (conf[0].pc_sel.pc_domain != 0) {
		EPRINTLN("Passthru device %s on unsupported domain", name);
		return (false);
	}
	*bus = conf[0].pc_sel.pc_bus;
	*slot = conf[0].pc_sel.pc_dev;
	*func = conf[0].pc_sel.pc_func;
	return (true);
}

static int
passthru_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	int bus, slot, func, error, memflags;
	struct passthru_softc *sc;
	struct passthru_dev **devpp;
	struct passthru_dev *devp, *dev = NULL;
	const char *value;

	sc = NULL;
	error = 1;

	memflags = vm_get_memflags(pi->pi_vmctx);
	if (!(memflags & VM_MEM_F_WIRED)) {
		warnx("passthru requires guest memory to be wired");
		return (error);
	}

	if (pcifd < 0 && pcifd_init()) {
		return (error);
	}

#define GET_INT_CONFIG(var, name) do {					\
	value = get_config_value_node(nvl, name);			\
	if (value == NULL) {						\
		EPRINTLN("passthru: missing required %s setting", name); \
		return (error);						\
	}								\
	var = atoi(value);						\
} while (0)

	value = get_config_value_node(nvl, "pptdev");
	if (value != NULL) {
		if (!passthru_lookup_pptdev(value, &bus, &slot, &func))
			return (error);
	} else {
		GET_INT_CONFIG(bus, "bus");
		GET_INT_CONFIG(slot, "slot");
		GET_INT_CONFIG(func, "func");
	}

	if (vm_assign_pptdev(pi->pi_vmctx, bus, slot, func) != 0) {
		if (errno == ENOENT) {
			EPRINTLN(
		    "PCI device at %d/%d/%d is not using the ppt driver",
			    bus, slot, func);
		} else {
			EPRINTLN("vm_assign_pptdev: %s", strerror(errno));
		}
		goto done;
	}

	sc = calloc(1, sizeof(struct passthru_softc));
	if (sc == NULL) {
		error = ENOMEM;
		goto done;
	}

	pi->pi_arg = sc;
	sc->psc_pi = pi;

	for (uint8_t i = 0; i < PCI_BARMAX_WITH_ROM + 1; ++i)
		TAILQ_INIT(&sc->psc_bar_handler[i]);

	/* initialize config space */
	if ((error = cfginit(pi, bus, slot, func)) != 0)
		goto done;

	/* initialize ROM */
	if ((error = passthru_init_rom(sc,
            get_config_value_node(nvl, "rom"))) != 0)
		goto done;

	/* Emulate most PCI header register. */
	if ((error = set_pcir_handler(sc, 0, PCIR_MAXLAT + 1,
	    passthru_cfgread_emulate, passthru_cfgwrite_emulate)) != 0)
		goto done;

	/* Allow access to the physical status register. */
	if ((error = set_pcir_handler(sc, PCIR_COMMAND, 0x04, NULL, NULL)) != 0)
		goto done;

	SET_FOREACH(devpp, passthru_dev_set) {
		devp = *devpp;
		assert(devp->probe != NULL);
		if (devp->probe(pi) == 0) {
			dev = devp;
			break;
		}
	}

	if (dev != NULL) {
		error = dev->init(pi, nvl);
		if (error != 0)
			goto done;
	}

	error = 0;		/* success */
done:
	if (error) {
		if (dev != NULL)
			dev->deinit(pi);
		if (sc != NULL) {
			for (int i = 0; i < PCI_BARMAX_WITH_ROM + 1; i++) {
				struct passthru_bar_handler *handler;

				while ((handler =
				    TAILQ_FIRST(&sc->psc_bar_handler[i])) != NULL) {
					TAILQ_REMOVE(&sc->psc_bar_handler[i], handler,
					    chain);
					free(handler);
				}
			}
		}
		if (pi->pi_msix.mapped_addr != NULL) {
			(void)munmap(pi->pi_msix.mapped_addr,
			    pi->pi_msix.mapped_size);
			pi->pi_msix.mapped_addr = NULL;
			pi->pi_msix.mapped_size = 0;
		}
		free(pi->pi_msix.table);
		pi->pi_msix.table = NULL;
		free(sc);
		pi->pi_arg = NULL;
		vm_unassign_pptdev(pi->pi_vmctx, bus, slot, func);
	}
	return (error);
}

static int
msicap_access(struct passthru_softc *sc, int coff)
{
	int caplen;

	if (sc->psc_msi.capoff == 0)
		return (0);

	caplen = msi_caplen(sc->psc_msi.msgctrl);

	if (coff >= sc->psc_msi.capoff && coff < sc->psc_msi.capoff + caplen)
		return (1);
	else
		return (0);
}

static int
msixcap_access(struct passthru_softc *sc, int coff)
{
	if (sc->psc_msix.capoff == 0)
		return (0);

	return (coff >= sc->psc_msix.capoff &&
	        coff < sc->psc_msix.capoff + MSIX_CAPLEN);
}

static int
passthru_cfgread_default(struct passthru_softc *sc,
    struct pci_devinst *pi __unused, int coff, int bytes, uint32_t *rv)
{
	/*
	 * MSI capability is emulated.
	 */
	if (msicap_access(sc, coff) || msixcap_access(sc, coff))
		return (-1);

	/*
	 * Emulate the command register.  If a single read reads both the
	 * command and status registers, read the status register from the
	 * device's config space.
	 */
	if (coff == PCIR_COMMAND) {
		uint32_t st;

		if (bytes <= 2)
			return (-1);
		st = passthru_read_config(&sc->psc_sel, PCIR_STATUS, 2);
		*rv = (st << 16) | pci_get_cfgdata16(pi, PCIR_COMMAND);
		return (0);
	}

	/* Everything else just read from the device's config space */
	*rv = passthru_read_config(&sc->psc_sel, coff, bytes);

	return (0);
}

int
passthru_cfgread_emulate(struct passthru_softc *sc __unused,
    struct pci_devinst *pi __unused, int coff __unused, int bytes __unused,
    uint32_t *rv __unused)
{
	return (-1);
}

static int
passthru_cfgread(struct pci_devinst *pi, int coff, int bytes, uint32_t *rv)
{
	struct passthru_softc *sc;

	if (pi == NULL || rv == NULL)
		return (0);
	sc = pi->pi_arg;
	if (sc == NULL || coff < 0 || coff > PCI_REGMAX ||
	    !(bytes == 1 || bytes == 2 || bytes == 4) ||
	    bytes > PCI_REGMAX + 1 - coff) {
		*rv = UINT32_MAX;
		return (0);
	}

	if (sc->psc_pcir_rhandler[coff] != NULL)
		return (sc->psc_pcir_rhandler[coff](sc, pi, coff, bytes, rv));

	return (passthru_cfgread_default(sc, pi, coff, bytes, rv));
}

static int
passthru_cfgwrite_default(struct passthru_softc *sc, struct pci_devinst *pi,
    int coff, int bytes, uint32_t val)
{
	int error, msix_table_entries, i;
	uint16_t cmd_old;

	/*
	 * MSI capability is emulated
	 */
	if (msicap_access(sc, coff)) {
		pci_emul_capwrite(pi, coff, bytes, val, sc->psc_msi.capoff,
		    PCIY_MSI);
		error = vm_setup_pptdev_msi(pi->pi_vmctx, sc->psc_sel.pc_bus,
			sc->psc_sel.pc_dev, sc->psc_sel.pc_func,
			pi->pi_msi.addr, pi->pi_msi.msg_data,
			pi->pi_msi.maxmsgnum);
		if (error != 0)
			warn("vm_setup_pptdev_msi failed");
		return (0);
	}

	if (msixcap_access(sc, coff)) {
		pci_emul_capwrite(pi, coff, bytes, val, sc->psc_msix.capoff,
		    PCIY_MSIX);
		if (pi->pi_msix.enabled) {
			msix_table_entries = pi->pi_msix.table_count;
			for (i = 0; i < msix_table_entries; i++) {
				error = vm_setup_pptdev_msix(pi->pi_vmctx,
				    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev,
				    sc->psc_sel.pc_func, i,
				    pi->pi_msix.table[i].addr,
				    pi->pi_msix.table[i].msg_data,
				    pi->pi_msix.table[i].vector_control);

				if (error)
					warn("vm_setup_pptdev_msix failed");
			}
		} else {
			error = vm_disable_pptdev_msix(pi->pi_vmctx,
			    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev,
			    sc->psc_sel.pc_func);
			if (error)
				warn("vm_disable_pptdev_msix failed");
		}
		return (0);
	}

	/*
	 * The command register is emulated, but the status register
	 * is passed through.
	 */
	if (coff == PCIR_COMMAND) {
		if (bytes <= 2)
			return (-1);

		/* Update the physical status register. */
		passthru_write_config(&sc->psc_sel, PCIR_STATUS, val >> 16, 2);

		/* Update the virtual command register. */
		cmd_old = pci_get_cfgdata16(pi, PCIR_COMMAND);
		pci_set_cfgdata16(pi, PCIR_COMMAND, val & 0xffff);
		pci_emul_cmd_changed(pi, cmd_old);
		return (0);
	}

	passthru_write_config(&sc->psc_sel, coff, bytes, val);

	return (0);
}

int
passthru_cfgwrite_emulate(struct passthru_softc *sc __unused,
    struct pci_devinst *pi __unused, int coff __unused, int bytes __unused,
    uint32_t val __unused)
{
	return (-1);
}

static int
passthru_cfgwrite(struct pci_devinst *pi, int coff, int bytes, uint32_t val)
{
	struct passthru_softc *sc;

	if (pi == NULL)
		return (0);
	sc = pi->pi_arg;
	if (sc == NULL || coff < 0 || coff > PCI_REGMAX ||
	    !(bytes == 1 || bytes == 2 || bytes == 4) ||
	    bytes > PCI_REGMAX + 1 - coff)
		return (0);

	if (sc->psc_pcir_whandler[coff] != NULL)
		return (sc->psc_pcir_whandler[coff](sc, pi, coff, bytes, val));

	return (passthru_cfgwrite_default(sc, pi, coff, bytes, val));
}

static void
passthru_write(struct pci_devinst *pi, int baridx, uint64_t offset, int size,
    uint64_t value)
{
	struct passthru_softc *sc;
	struct passthru_bar_handler *handler;
	struct pci_bar_ioreq pio;

	if (pi == NULL)
		return;
	sc = pi->pi_arg;
	if (sc == NULL || baridx < 0 || baridx > PCI_BARMAX ||
	    !(size == 1 || size == 2 || size == 4) ||
	    offset > sc->psc_bar[baridx].size ||
	    (uint64_t)size > sc->psc_bar[baridx].size - offset ||
	    offset > UINT32_MAX)
		return;

	if (baridx == pci_msix_table_bar(pi)) {
		msix_table_write(sc, offset, size, value);
	} else {
		TAILQ_FOREACH(handler, &sc->psc_bar_handler[baridx], chain) {
			if (offset >= handler->off + handler->size) {
				continue;
			} else if (offset < handler->off) {
				if ((uint64_t)size > handler->off - offset)
					return;
				/*
				 * The list is sorted in ascending order, so all
				 * remaining handlers will have an even larger
				 * offset.
				 */
				break;
			}

			if ((uint64_t)size >
			    handler->off + handler->size - offset)
				return;

			if (handler->write != NULL)
				handler->write(pi, baridx,
				    offset - handler->off, size, value);
			return;
		}

		bzero(&pio, sizeof(pio));
		pio.pbi_sel = sc->psc_sel;
		pio.pbi_op = PCIBARIO_WRITE;
		pio.pbi_bar = baridx;
		pio.pbi_offset = (uint32_t)offset;
		pio.pbi_width = size;
		pio.pbi_value = (uint32_t)value;

		if (ioctl(pcifd, PCIOCBARIO, &pio) != 0)
			warn("passthru BAR write");
	}
}

static uint64_t
passthru_read(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct passthru_softc *sc;
	struct passthru_bar_handler *handler;
	struct pci_bar_ioreq pio;
	uint64_t val;

	if (pi == NULL)
		return (UINT64_MAX);
	sc = pi->pi_arg;
	if (sc == NULL || baridx < 0 || baridx > PCI_BARMAX ||
	    !(size == 1 || size == 2 || size == 4) ||
	    offset > sc->psc_bar[baridx].size ||
	    (uint64_t)size > sc->psc_bar[baridx].size - offset ||
	    offset > UINT32_MAX)
		return (UINT64_MAX);

	if (baridx == pci_msix_table_bar(pi)) {
		val = msix_table_read(sc, offset, size);
	} else {
		TAILQ_FOREACH(handler, &sc->psc_bar_handler[baridx], chain) {
			if (offset >= handler->off + handler->size) {
				continue;
			} else if (offset < handler->off) {
				if ((uint64_t)size > handler->off - offset)
					return (UINT64_MAX);
				/*
				 * The list is sorted in ascending order, so all
				 * remaining handlers will have an even larger
				 * offset.
				 */
				break;
			}

			if ((uint64_t)size >
			    handler->off + handler->size - offset)
				return (UINT64_MAX);

			if (handler->read == NULL)
				return (UINT64_MAX);
			return (handler->read(pi, baridx,
			    offset - handler->off, size));
		}

		bzero(&pio, sizeof(pio));
		pio.pbi_sel = sc->psc_sel;
		pio.pbi_op = PCIBARIO_READ;
		pio.pbi_bar = baridx;
		pio.pbi_offset = (uint32_t)offset;
		pio.pbi_width = size;

		if (ioctl(pcifd, PCIOCBARIO, &pio) != 0)
			return (UINT64_MAX);

		val = pio.pbi_value;
	}

	return (val);
}

static int
passthru_mmio_map(struct pci_devinst *pi, int baridx, int enabled,
    uint64_t address, uint64_t off, uint64_t size)
{
	struct passthru_softc *sc;

	if (pi == NULL)
		return (-1);
	sc = pi->pi_arg;
	if (sc == NULL || baridx < 0 || baridx > PCI_BARMAX ||
	    size == 0 || off > sc->psc_bar[baridx].size ||
	    size > sc->psc_bar[baridx].size - off ||
	    address > UINT64_MAX - off ||
	    sc->psc_bar[baridx].addr > UINT64_MAX - off)
		return (-1);
	if (!enabled) {
		if (vm_unmap_pptdev_mmio(pi->pi_vmctx, sc->psc_sel.pc_bus,
		    sc->psc_sel.pc_dev, sc->psc_sel.pc_func, address + off,
		    size) != 0) {
			EPRINTLN("pci_passthru: unmap_pptdev_mmio failed: %s",
			    strerror(errno));
			return (-1);
		}
	} else {
		if (vm_map_pptdev_mmio(pi->pi_vmctx, sc->psc_sel.pc_bus,
		    sc->psc_sel.pc_dev, sc->psc_sel.pc_func, address + off,
		    size, sc->psc_bar[baridx].addr + off) != 0) {
			EPRINTLN("pci_passthru: map_pptdev_mmio failed: %s",
			    strerror(errno));
			return (-1);
		}
	}

	return (0);
}

static void
passthru_msix_addr(struct pci_devinst *pi, int baridx, int enabled,
    uint64_t address)
{
	uint64_t remaining, table_size, table_offset;

	if (pi == NULL || baridx < 0 || baridx > PCI_BARMAX)
		return;

	table_offset = rounddown2(pi->pi_msix.table_offset, 4096);
	if (table_offset > 0) {
		(void)passthru_mmio_map(pi, baridx, enabled, address, 0,
		    table_offset);
	}
	table_size = pi->pi_msix.table_offset - table_offset;
	table_size += pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
	table_size = roundup2(table_size, UINT64_C(4096));
	if (table_offset > pi->pi_bar[baridx].size ||
	    table_size > pi->pi_bar[baridx].size - table_offset)
		return;
	remaining = pi->pi_bar[baridx].size - table_offset - table_size;
	if (remaining > 0) {
		(void)passthru_mmio_map(pi, baridx, enabled, address,
		    table_offset + table_size, remaining);
	}
}

static void
passthru_mmio_addr(struct pci_devinst *pi, int baridx, int enabled,
    uint64_t address)
{
	struct passthru_softc *sc;
	struct passthru_bar_handler *handler;
	uint64_t off;

	if (pi == NULL || baridx < 0 || baridx > PCI_BARMAX)
		return;
	sc = pi->pi_arg;
	if (sc == NULL)
		return;

	off = 0;

	/* The queue is sorted by offset in ascending order. */
	TAILQ_FOREACH(handler, &sc->psc_bar_handler[baridx], chain) {
		uint64_t handler_off = trunc_page(handler->off);
		uint64_t handler_end = round_page(handler->off + handler->size);

		/*
		 * When two handlers point to the same page, handler_off can be
		 * lower than off. That's fine because we have nothing to do in
		 * that case.
		 */
		if (handler_off > off) {
			passthru_mmio_map(pi, baridx, enabled, address, off,
			    handler_off - off);
		}

		off = handler_end;
	}

	if (off < sc->psc_bar[baridx].size)
		(void)passthru_mmio_map(pi, baridx, enabled, address, off,
		    sc->psc_bar[baridx].size - off);
}

static void
passthru_addr_rom(struct pci_devinst *const pi, const int idx,
    const int enabled)
{
	const uint64_t addr = pi->pi_bar[idx].addr;
	const uint64_t size = pi->pi_bar[idx].size;

	if (!enabled) {
		if (vm_munmap_memseg(pi->pi_vmctx, addr, size) != 0) {
			warnx("%s: munmap_memseg @ [%016lx - %016lx] failed",
			    __func__, addr, addr + size);
		}

	} else {
		if (vm_mmap_memseg(pi->pi_vmctx, addr, VM_PCIROM,
			pi->pi_romoffset, size, PROT_READ | PROT_EXEC) != 0) {
			warnx("%s: mmap_memseg @ [%016lx - %016lx] failed",
			    __func__, addr, addr + size);
		}
	}
}

static void
passthru_addr(struct pci_devinst *pi, int baridx, int enabled, uint64_t address)
{
	if (pi == NULL || pi->pi_arg == NULL || baridx < 0 ||
	    baridx > PCI_BARMAX_WITH_ROM)
		return;

	switch (pi->pi_bar[baridx].type) {
	case PCIBAR_IO:
		/* IO BARs are emulated */
		break;
	case PCIBAR_ROM:
		passthru_addr_rom(pi, baridx, enabled);
		break;
	case PCIBAR_MEM32:
	case PCIBAR_MEM64:
		if (baridx == pci_msix_table_bar(pi))
			passthru_msix_addr(pi, baridx, enabled, address);
		else
			passthru_mmio_addr(pi, baridx, enabled, address);
		break;
	default:
		warnx("%s: invalid BAR type %d", __func__,
		    pi->pi_bar[baridx].type);
		break;
	}
}

static const struct pci_devemu passthru = {
	.pe_emu		= "passthru",
	.pe_init	= passthru_init,
	.pe_legacy_config = passthru_legacy_config,
	.pe_cfgwrite	= passthru_cfgwrite,
	.pe_cfgread	= passthru_cfgread,
	.pe_barwrite 	= passthru_write,
	.pe_barread    	= passthru_read,
	.pe_baraddr	= passthru_addr,
};
PCI_EMUL_SET(passthru);
