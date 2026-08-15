/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Nahanni Systems, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <dev/vmm/vmm_mem.h>
#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>
#include <vmmapi.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

#include "bhyvegc.h"
#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "console.h"
#include "pci_emul.h"
#include "pci_fbuf_model.h"
#include "rfb.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#ifdef __amd64__
#include "amd64/vga.h"
#endif

/*
 * bhyve Framebuffer device emulation.
 * BAR0 points to the current mode information.
 * BAR1 is the 32-bit framebuffer address.
 *
 *  -s <b>,fbuf,wait,vga=on|io|off,rfb=<ip>:port,w=width,h=height
 */

static int fbuf_debug = 1;
#define	DEBUG_INFO	1
#define	DEBUG_VERBOSE	4
#define	DPRINTF(level, params)  if (level <= fbuf_debug) PRINTLN params


#define	KB	(1024UL)
#define	MB	(1024 * 1024UL)

#define	DMEMSZ	PCI_FBUF_REG_SIZE

#define	FB_SIZE		(32*MB)

#define COLS_MAX	3840
#define ROWS_MAX	2160

#define COLS_DEFAULT	1024
#define ROWS_DEFAULT	768

#define COLS_MIN	640
#define ROWS_MIN	480

struct pci_fbuf_softc {
	struct pci_devinst *fsc_pi;
	uint8_t memregs[PCI_FBUF_REG_SIZE];

	/* rfb server */
	sa_family_t rfb_family;
	char      *rfb_host;
	char      *rfb_password;
	int       rfb_port;
	int       rfb_wait;
	int       vga_enabled;
	int	  vga_full;
	int	  external_source;

	uint32_t  fbaddr;
	char      *fb_base;
	uint16_t  gc_width;
	uint16_t  gc_height;
	void      *vgasc;
	struct bhyvegc_image *gc_image;
};

static struct pci_fbuf_softc *fbuf_sc;

#define	PCI_FBUF_MSI_MSGS	 4

static uint16_t
pci_fbuf_get_u16(const struct pci_fbuf_softc *sc, uint64_t offset)
{
	uint64_t value;

	if (!pci_fbuf_register_read(sc->memregs, offset, 2, &value))
		return (0);
	return ((uint16_t)value);
}

static void
pci_fbuf_set_u16(struct pci_fbuf_softc *sc, uint64_t offset, uint16_t value)
{

	(void)pci_fbuf_register_write(sc->memregs, offset, 2, value);
}

static void
pci_fbuf_update_mode(struct pci_fbuf_softc *sc)
{
	uint16_t height, width;

	height = pci_fbuf_get_u16(sc, PCI_FBUF_REG_HEIGHT);
	width = pci_fbuf_get_u16(sc, PCI_FBUF_REG_WIDTH);
	if (!sc->gc_image->vgamode && width == 0 && height == 0) {
		DPRINTF(DEBUG_INFO, ("switching to VGA mode"));
		sc->gc_image->vgamode = 1;
		sc->gc_width = 0;
		sc->gc_height = 0;
	} else if (sc->gc_image->vgamode && width != 0 && height != 0) {
		DPRINTF(DEBUG_INFO, ("switching to VESA mode"));
		sc->gc_image->vgamode = 0;
	}
}

static void
pci_fbuf_write(struct pci_devinst *pi, int baridx __unused, uint64_t offset,
    int size,
    uint64_t value)
{
	struct pci_fbuf_softc *sc;

	assert(baridx == 0);

	sc = pi->pi_arg;

	DPRINTF(DEBUG_VERBOSE,
	    ("fbuf wr: offset 0x%lx, size: %d, value: 0x%lx",
	    offset, size, value));

	if (!pci_fbuf_register_write(sc->memregs, offset, size, value)) {
		printf("fbuf: write too large, offset %ld size %d\n",
		       offset, size);
		return;
	}
	pci_fbuf_update_mode(sc);
}

static uint64_t
pci_fbuf_read(struct pci_devinst *pi, int baridx __unused, uint64_t offset,
    int size)
{
	struct pci_fbuf_softc *sc;
	uint64_t value;

	assert(baridx == 0);

	sc = pi->pi_arg;


	if (!pci_fbuf_register_read(sc->memregs, offset, size, &value)) {
		printf("fbuf: read too large, offset %ld size %d\n",
		       offset, size);
		return (0);
	}

	DPRINTF(DEBUG_VERBOSE,
	    ("fbuf rd: offset 0x%lx, size: %d, value: 0x%lx",
	     offset, size, value));

	return (value);
}

static void
pci_fbuf_baraddr(struct pci_devinst *pi, int baridx, int enabled,
    uint64_t address)
{
	struct pci_fbuf_softc *sc;
	int prot;

	if (baridx != 1)
		return;

	sc = pi->pi_arg;
	if (!enabled) {
		if (vm_munmap_memseg(pi->pi_vmctx, sc->fbaddr, FB_SIZE) != 0)
			EPRINTLN("pci_fbuf: munmap_memseg failed");
		sc->fbaddr = 0;
	} else {
		prot = PROT_READ | PROT_WRITE;
		if (vm_mmap_memseg(pi->pi_vmctx, address, VM_FRAMEBUFFER, 0,
		    FB_SIZE, prot) != 0)
			EPRINTLN("pci_fbuf: mmap_memseg failed");
		else
			sc->fbaddr = address;
	}
}


static int
pci_fbuf_parse_config(struct pci_fbuf_softc *sc, nvlist_t *nvl)
{
	const char *value;
	uint16_t height, width;
	char *cp;

	sc->rfb_wait = get_config_bool_node_default(nvl, "wait", false);

	/* Prefer "rfb" to "tcp". */
	value = get_config_value_node(nvl, "rfb");
	if (value == NULL)
		value = get_config_value_node(nvl, "tcp");
	if (value != NULL) {
		/*
		 * UNIX -- unix:path/to/socket.sock
		 * IPv4 -- host-ip:port
		 * IPv6 -- [host-ip%zone]:port
		 * XXX for now port is mandatory for IPv4.
		 */
		if (value[0] == '[') {
			sc->rfb_family = AF_INET6;
			cp = strchr(value + 1, ']');
			if (cp == NULL || cp == value + 1) {
				EPRINTLN("fbuf: Invalid IPv6 address: \"%s\"",
				    value);
				return (-1);
			}
			sc->rfb_host = strndup(value + 1, cp - (value + 1));
			if (sc->rfb_host == NULL)
				return (-1);
			cp++;
			if (*cp == ':') {
				cp++;
				if (*cp == '\0') {
					EPRINTLN(
					    "fbuf: Missing port number: \"%s\"",
					    value);
					return (-1);
				}
				sc->rfb_port = atoi(cp);
			} else if (*cp != '\0') {
				EPRINTLN("fbuf: Invalid IPv6 address: \"%s\"",
				    value);
				return (-1);
			}
		} else if (strncmp("unix:", value, 5) == 0) {
			if (strlen(value + 5) > SUNPATHLEN) {
				EPRINTLN(
				    "fbuf: UNIX socket path too long: \"%s\"",
				    value + 5);
				return (-1);
			} else if (*(value + 5) == '\0') {
				EPRINTLN("fbuf: UNIX socket path is empty");
				return (-1);
			} else {
				sc->rfb_family = AF_UNIX;
				sc->rfb_host = strdup(value + 5);
				if (sc->rfb_host == NULL)
					return (-1);
			}
		} else {
			sc->rfb_family = AF_UNSPEC;
			cp = strchr(value, ':');
			if (cp == NULL) {
				sc->rfb_port = atoi(value);
			} else {
				sc->rfb_host = strndup(value, cp - value);
				if (sc->rfb_host == NULL)
					return (-1);
				cp++;
				if (*cp == '\0') {
					EPRINTLN(
					    "fbuf: Missing port number: \"%s\"",
					    value);
					return (-1);
				}
				sc->rfb_port = atoi(cp);
			}
		}
	}

	value = get_config_value_node(nvl, "vga");
	if (value != NULL) {
		if (strcmp(value, "off") == 0) {
			sc->vga_enabled = 0;
		} else if (strcmp(value, "io") == 0) {
			sc->vga_enabled = 1;
			sc->vga_full = 0;
		} else if (strcmp(value, "on") == 0) {
			sc->vga_enabled = 1;
			sc->vga_full = 1;
		} else {
			EPRINTLN("fbuf: Invalid vga setting: \"%s\"", value);
			return (-1);
		}
	}

	value = get_config_value_node(nvl, "source");
	if (value != NULL) {
		if (strcmp(value, "fbuf") == 0)
			sc->external_source = 0;
		else if (strcmp(value, "external") == 0)
			sc->external_source = 1;
		else {
			EPRINTLN("fbuf: Invalid source: \"%s\"", value);
			return (-1);
		}
	}
	if (sc->external_source && sc->vga_enabled) {
		EPRINTLN("fbuf: source=external requires vga=off");
		return (-1);
	}

	value = get_config_value_node(nvl, "w");
	if (value != NULL)
		pci_fbuf_set_u16(sc, PCI_FBUF_REG_WIDTH,
		    strtol(value, NULL, 10));

	value = get_config_value_node(nvl, "h");
	if (value != NULL)
		pci_fbuf_set_u16(sc, PCI_FBUF_REG_HEIGHT,
		    strtol(value, NULL, 10));

	width = pci_fbuf_get_u16(sc, PCI_FBUF_REG_WIDTH);
	height = pci_fbuf_get_u16(sc, PCI_FBUF_REG_HEIGHT);
	if (width > COLS_MAX || height > ROWS_MAX) {
		EPRINTLN("fbuf: max resolution is %ux%u", COLS_MAX, ROWS_MAX);
		return (-1);
	}
	if (width < COLS_MIN || height < ROWS_MIN) {
		EPRINTLN("fbuf: minimum resolution is %ux%u",
		    COLS_MIN, ROWS_MIN);
		return (-1);
	}

	value = get_config_value_node(nvl, "password");
	if (value != NULL) {
		sc->rfb_password = strdup(value);
		if (sc->rfb_password == NULL)
			return (-1);
	}

	return (0);
}

static void
pci_fbuf_render(struct bhyvegc *gc, void *arg)
{
	struct pci_fbuf_softc *sc;
	size_t pixels;
	uint16_t height, width;

	sc = arg;

	if (sc->vga_full && sc->gc_image->vgamode) {
		/* TODO: mode switching to vga and vesa should use the special
		 *      EFI-bhyve protocol port.
		 */
		vga_render(gc, sc->vgasc);
		return;
	}
	/*
	 * BAR0 is guest writable.  Never let an invalid guest-selected geometry
	 * turn the fixed-size framebuffer BAR into an out-of-bounds host read by
	 * the renderer or RFB encoder.
	 */
	width = pci_fbuf_get_u16(sc, PCI_FBUF_REG_WIDTH);
	height = pci_fbuf_get_u16(sc, PCI_FBUF_REG_HEIGHT);
	if (width < COLS_MIN || width > COLS_MAX || height < ROWS_MIN ||
	    height > ROWS_MAX)
		return;
	pixels = (size_t)width * height;
	if (pixels > FB_SIZE / sizeof(uint32_t))
		return;
	if (sc->gc_width != width || sc->gc_height != height) {
		bhyvegc_resize(gc, width, height);
		sc->gc_width = width;
		sc->gc_height = height;
	}
}

static int
pci_fbuf_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	int error;
	bool renderer_registered;
	struct pci_fbuf_softc *sc;

	if (fbuf_sc != NULL) {
		EPRINTLN("Only one frame buffer device is allowed.");
		return (-1);
	}

	sc = calloc(1, sizeof(struct pci_fbuf_softc));
	if (sc == NULL)
		return (-1);
	renderer_registered = false;
	error = -1;

	pi->pi_arg = sc;

	/* initialize config space */
	pci_set_cfgdata16(pi, PCIR_DEVICE, 0x40FB);
	pci_set_cfgdata16(pi, PCIR_VENDOR, 0xFB5D);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_DISPLAY);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_DISPLAY_VGA);

	sc->fb_base = vm_create_devmem(pi->pi_vmctx, VM_FRAMEBUFFER,
	    "framebuffer", FB_SIZE);
	if (sc->fb_base == MAP_FAILED) {
		error = -1;
		goto done;
	}

	error = pci_emul_alloc_bar(pi, 0, PCIBAR_MEM32, DMEMSZ);
	assert(error == 0);

	error = pci_emul_alloc_bar(pi, 1, PCIBAR_MEM32, FB_SIZE);
	assert(error == 0);

	error = pci_emul_add_msicap(pi, PCI_FBUF_MSI_MSGS);
	assert(error == 0);

	(void)pci_fbuf_register_write(sc->memregs, PCI_FBUF_REG_FBSIZE, 4,
	    FB_SIZE);
	pci_fbuf_set_u16(sc, PCI_FBUF_REG_WIDTH, COLS_DEFAULT);
	pci_fbuf_set_u16(sc, PCI_FBUF_REG_HEIGHT, ROWS_DEFAULT);
	pci_fbuf_set_u16(sc, PCI_FBUF_REG_DEPTH, 32);

	sc->vga_enabled = 1;
	sc->vga_full = 0;

	sc->fsc_pi = pi;

	error = pci_fbuf_parse_config(sc, nvl);
	if (error != 0)
		goto done;

	/* XXX until VGA rendering is enabled */
	if (sc->vga_full != 0) {
		EPRINTLN("pci_fbuf: VGA rendering not enabled");
		error = -1;
		goto done;
	}

	DPRINTF(DEBUG_INFO, ("fbuf frame buffer base: %p [sz %lu]",
	        sc->fb_base, FB_SIZE));

	console_init(pci_fbuf_get_u16(sc, PCI_FBUF_REG_WIDTH),
	    pci_fbuf_get_u16(sc, PCI_FBUF_REG_HEIGHT), sc->fb_base);
	if (!sc->external_source) {
		error = console_fb_register("fbuf", pci_fbuf_render, sc);
		if (error != 0) {
			EPRINTLN("fbuf: framebuffer renderer already owned");
			goto done;
		}
		renderer_registered = true;
	}

	if (sc->vga_enabled) {
		sc->vgasc = vga_init(!sc->vga_full);
		if (sc->vgasc == NULL) {
			error = ENXIO;
			goto done;
		}
	}
	sc->gc_image = console_get_image();

	memset((void *)sc->fb_base, 0, FB_SIZE);

	error = rfb_init(sc->rfb_family, sc->rfb_host, sc->rfb_port,
	    sc->rfb_wait, sc->rfb_password);
	if (error == 0)
		fbuf_sc = sc;
done:
	if (error) {
		if (renderer_registered)
			(void)console_fb_unregister("fbuf", sc);
		pi->pi_arg = NULL;
		free(sc->rfb_password);
		free(sc->rfb_host);
		free(sc);
	}

	return (error);
}

#ifdef BHYVE_SNAPSHOT
#define	PCI_FBUF_SNAPSHOT_MAGIC	UINT32_C(0x31424650) /* "PFB1" */

static int
pci_fbuf_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_fbuf_softc *sc;
	uint32_t magic;
	uint8_t registers[PCI_FBUF_REG_SIZE];
	int ret;

	if (meta == NULL || meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);
	magic = PCI_FBUF_SNAPSHOT_MAGIC;
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(registers, sc->memregs, sizeof(registers));
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, err);
	if (vm_snapshot_is_loading(meta) &&
	    magic != PCI_FBUF_SNAPSHOT_MAGIC) {
		ret = EINVAL;
		goto err;
	}
	SNAPSHOT_BUF_OR_LEAVE(registers, sizeof(registers), meta, ret, err);
	SNAPSHOT_BUF_OR_LEAVE(sc->fb_base, FB_SIZE, meta, ret, err);
	if (vm_snapshot_is_restoring(meta)) {
		memcpy(sc->memregs, registers, sizeof(registers));
		pci_fbuf_update_mode(sc);
	}

err:
	return (ret);
}

static int
pci_fbuf_snapshot_validate(struct vm_snapshot_meta *meta)
{
	uint8_t registers[PCI_FBUF_REG_SIZE], scratch[4096];
	uint32_t magic;
	size_t remaining, chunk;
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE)
		return (EINVAL);
	magic = 0;
	error = vm_snapshot_le32(&magic, meta);
	if (error != 0)
		return (error);
	if (magic != PCI_FBUF_SNAPSHOT_MAGIC)
		return (EINVAL);
	error = vm_snapshot_buf(registers, sizeof(registers), meta);
	if (error != 0)
		return (error);
	remaining = FB_SIZE;
	while (remaining != 0) {
		chunk = MIN(remaining, sizeof(scratch));
		error = vm_snapshot_buf(scratch, chunk, meta);
		if (error != 0)
			return (error);
		remaining -= chunk;
	}
	return (0);
}
#endif

static const struct pci_devemu pci_fbuf = {
	.pe_emu =	"fbuf",
	.pe_init =	pci_fbuf_init,
	.pe_barwrite =	pci_fbuf_write,
	.pe_barread =	pci_fbuf_read,
	.pe_baraddr =	pci_fbuf_baraddr,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	pci_fbuf_snapshot,
	.pe_snapshot_validate = pci_fbuf_snapshot_validate,
	.pe_migration_flags = PCI_MIGRATION_F_STATE_CODEC |
	    PCI_MIGRATION_F_COMPAT_FIXED | PCI_MIGRATION_F_DMA_NONE |
	    PCI_MIGRATION_F_QUIESCE_NONE,
#endif
};
PCI_EMUL_SET(pci_fbuf);
