/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2020 Conrad Meyer <cem@FreeBSD.org>.  All rights reserved.
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/uuid.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "acpi.h"
#include "bootrom.h"
#include "vmgenc.h"

_Static_assert(sizeof(struct uuid) == VMGENC_ID_SIZE, "VM generation ID size");

static uint64_t	vmgen_gpa;
static char	*vmgen_region;

void
vmgenc_init(struct vmctx *ctx)
{
	char *region;
	int error;

	/*
	 * The generation ID is random per process, so it must not take part
	 * in the bootrom identity live migration compares.
	 */
	error = bootrom_alloc(ctx, PAGE_SIZE, PROT_READ,
	    BOOTROM_ALLOC_INSTANCE, &region, &vmgen_gpa);
	if (error != 0)
		errx(4, "%s: bootrom_alloc", __func__);

	/*
	 * It is basically harmless to always generate a random ID when
	 * starting a VM.
	 */
	error = getentropy(region, sizeof(struct uuid));
	if (error == -1)
		err(4, "%s: getentropy", __func__);
	vmgen_region = region;

	/*
	 * No notification at boot: the guest reads the ID when its driver
	 * attaches.  Checkpoint restore changes the ID and raises the GPE
	 * through vmgenc_set_id().
	 */
}

#ifdef BHYVE_SNAPSHOT
/* The ID the guest sees; ENOENT without a generation device. */
int
vmgenc_get_id(uint8_t id[VMGENC_ID_SIZE])
{

	if (vmgen_region == NULL)
		return (ENOENT);
	memcpy(id, vmgen_region, VMGENC_ID_SIZE);
	return (0);
}

/*
 * Present a restored or migrated VM's generation ID before any vCPU runs.
 * 'notify' raises the generation GPE, whose _E00 method performs
 * Notify(\_SB.GENC, 0x80).  Does nothing without a generation device.
 */
void
vmgenc_set_id(struct vmctx *ctx, const uint8_t id[VMGENC_ID_SIZE], bool notify)
{

	if (vmgen_region == NULL)
		return;
	memcpy(vmgen_region, id, VMGENC_ID_SIZE);
#ifdef __amd64__
	if (notify)
		acpi_raise_gpe(ctx, GPE_VMGENC);
#else
	(void)ctx;
	(void)notify;
#endif
}
#endif

void
vmgenc_write_dsdt(void)
{
	dsdt_line("");
	dsdt_indent(1);
	dsdt_line("Scope (_SB)");
	dsdt_line("{");

	dsdt_line("  Device (GENC)");
	dsdt_line("  {");

	dsdt_indent(2);
	dsdt_line("Name (_CID, \"VM_Gen_Counter\")");
	dsdt_line("Method (_HID, 0, NotSerialized)");
	dsdt_line("{");
	dsdt_line("  Return (\"Bhyve_V_Gen_Counter_V1\")");
	dsdt_line("}");
	dsdt_line("Name (_UID, 0)");
	dsdt_line("Name (_DDN, \"VM_Gen_Counter\")");
	dsdt_line("Name (ADDR, Package (0x02)");
	dsdt_line("{");
	dsdt_line("  0x%08x,", (uint32_t)vmgen_gpa);
	dsdt_line("  0x%08x", (uint32_t)(vmgen_gpa >> 32));
	dsdt_line("})");

	dsdt_unindent(2);
	dsdt_line("  }");	/* Device (GENC) */

	dsdt_line("}");		/* Scope (_SB) */
	dsdt_line("");

	dsdt_line("Scope (_GPE)");
	dsdt_line("{");
	dsdt_line("  Method (_E%02x, 0, NotSerialized)", GPE_VMGENC);
	dsdt_line("  {");
	dsdt_line("    Notify (\\_SB.GENC, 0x80)");
	dsdt_line("  }");
	dsdt_line("}");
	dsdt_unindent(1);
}
