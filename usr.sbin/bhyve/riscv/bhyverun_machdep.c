/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2024 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Innovate
 * UK project 105694, "Digital Security by Design (DSbD) Technology Platform
 * Prototype".
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
#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <vmmapi.h>
#ifdef BHYVE_SNAPSHOT
#include <machine/vmm_snapshot.h>
#endif

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "fdt.h"
#include "guest_cpu_abi.h"
#include "ipc.h"
#include "mem.h"
#include "pci_emul.h"
#include "pci_irq.h"
#include "snapshot_md.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "uart_emul.h"
#include "riscv.h"

/* Platform device kept for checkpointing. */
static struct uart_ns16550_softc *mmio_uart_softc;
#ifdef BHYVE_SNAPSHOT
static bool mmio_uart_paused;
#endif

#define	FDT_SIZE	(64 * 1024)
#define	FDT_DTB_ALIGN	8

/* Start of lowmem + 64K */
#define	UART_MMIO_BASE	0x10000
#define	UART_MMIO_SIZE	0x1000
#define	UART_INTR	1

#define	APLIC_MEM_BASE		0x2f000000
#define	APLIC_MEM_SIZE		0x10000

#define	PCIE_INTA	2
#define	PCIE_INTB	3
#define	PCIE_INTC	4
#define	PCIE_INTD	5

void
bhyve_init_config(void)
{
	init_config();

	/* Set default values prior to option parsing. */
	set_config_bool("acpi_tables", false);
	set_config_bool("acpi_tables_in_memory", false);
	set_config_value("memory.size", "256M");
	set_config_value("rundir", BHYVE_RUN_DIR);
}

void
bhyve_usage(int code)
{
	const char *progname;

	progname = getprogname();

	fprintf(stderr,
	    "Usage: %s [-CDHhSW]\n"
	    "       %*s [-c [[cpus=]numcpus][,sockets=n][,cores=n][,threads=n]]\n"
	    "       %*s [-k config_file] [-m mem] [-o var=value]\n"
	    "       %*s [-p vcpuN[-vcpuM]]:hostcpuX[-hostcpuY]\n"
	    "       %*s [-r file] [-s pci] [-U uuid] vmname\n"
	    "       -C: include guest memory in core file\n"
	    "       -c: number of CPUs and/or topology specification\n"
	    "       -D: destroy on power-off\n"
	    "       -h: help\n"
	    "       -k: key=value flat config file\n"
	    "       -M: monitor mode\n"
	    "       -m: memory size\n"
	    "       -N: don't reboot while in monitor mode\n"
	    "       -o: set config 'var' to 'value'\n"
	    "       -p: pin 'vcpu' to 'hostcpu'\n"
	    "       -S: guest memory cannot be swapped\n"
	    "       -s: <slot,driver,configinfo> PCI slot config\n"
	    "       -U: UUID\n"
	    "       -W: force virtio to use single-vector MSI\n",
	    progname, (int)strlen(progname), "", (int)strlen(progname), "",
	    (int)strlen(progname), "", (int)strlen(progname), "");
	exit(code);
}

void
bhyve_optparse(int argc, char **argv)
{
	const char *optstr;
	int c;

	optstr = "hCDMNSWk:f:o:p:c:s:m:U:";
	while ((c = getopt(argc, argv, optstr)) != -1) {
		switch (c) {
		case 'c':
			if (bhyve_topology_parse(optarg) != 0) {
				errx(EX_USAGE, "invalid cpu topology '%s'",
				    optarg);
			}
			break;
		case 'C':
			set_config_bool("memory.guest_in_core", true);
			break;
		case 'D':
			set_config_bool("destroy_on_poweroff", true);
			break;
		case 'k':
			bhyve_parse_simple_config_file(optarg);
			break;
		case 'M':
			set_config_bool("monitor.enabled", true);
			break;
		case 'm':
			set_config_value("memory.size", optarg);
			break;
		case 'N':
			set_config_bool("monitor.no_reboot", true);
			break;
		case 'o':
			if (!bhyve_parse_config_option(optarg)) {
				errx(EX_USAGE,
				    "invalid configuration option '%s'",
				    optarg);
			}
			break;
		case 'p':
			if (bhyve_pincpu_parse(optarg) != 0) {
				errx(EX_USAGE,
				    "invalid vcpu pinning configuration '%s'",
				    optarg);
			}
			break;
		case 's':
			if (strncmp(optarg, "help", strlen(optarg)) == 0) {
				pci_print_supported_devices();
				exit(0);
			} else if (pci_parse_slot(optarg) != 0)
				exit(BHYVE_EXIT_ERROR);
			else
				break;
		case 'S':
			set_config_bool("memory.wired", true);
			break;
		case 'U':
			set_config_value("uuid", optarg);
			break;
		case 'W':
			set_config_bool("virtio.msix", false);
			break;
		case 'h':
			bhyve_usage(0);
		default:
			bhyve_usage(1);
		}
	}

	/* Handle backwards compatibility aliases in config options. */
	bhyve_cfg_warn("virtio_msix", "virtio.msix");
	bhyve_cfg_warn("monitor", "monitor.enabled");
}

void
bhyve_init_vcpu(struct vcpu *vcpu __unused)
{
}

void
bhyve_start_vcpu(struct vcpu *vcpu, bool bsp __unused)
{
	int error;

	/* Set hart ID. */
	error = vm_set_register(vcpu, VM_REG_GUEST_A0, vcpu_id(vcpu));
	assert(error == 0);

	fbsdrun_addcpu(vcpu_id(vcpu));
}

/*
 * Load the specified boot code at the beginning of high memory.
 */
static void
load_bootrom(struct vmctx *ctx, const char *path, uint64_t *elrp,
    uint64_t *lenp)
{
	struct stat sb;
	void *data, *gptr;
	vm_paddr_t loadaddr;
	off_t size;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		err(1, "open(%s)", path);
	if (fstat(fd, &sb) != 0)
		err(1, "fstat(%s)", path);

	size = sb.st_size;

	loadaddr = vm_get_highmem_base(ctx);
	gptr = vm_map_gpa(ctx, loadaddr, round_page(size));

	data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED)
		err(1, "mmap(%s)", path);
	(void)close(fd);
	memcpy(gptr, data, size);

	if (munmap(data, size) != 0)
		err(1, "munmap(%s)", path);

	*elrp = loadaddr;
	*lenp = size;
}

static void
mmio_uart_intr_assert(void *arg)
{
	struct vmctx *ctx = arg;

	vm_assert_irq(ctx, UART_INTR);
}

static void
mmio_uart_intr_deassert(void *arg)
{
	struct vmctx *ctx = arg;

	vm_deassert_irq(ctx, UART_INTR);
}

static int
mmio_uart_mem_handler(struct vcpu *vcpu __unused, int dir, uint64_t addr,
    int size __unused, uint64_t *val, void *arg1, long arg2)
{
	struct uart_ns16550_softc *sc = arg1;
	long reg;

	reg = addr - arg2;
	if (dir == MEM_F_WRITE)
		uart_ns16550_write(sc, reg, *val);
	else
		*val = uart_ns16550_read(sc, reg);

	return (0);
}

static bool
init_mmio_uart(struct vmctx *ctx)
{
	struct uart_ns16550_softc *sc;
	struct mem_range mr;
	const char *path;
	int error;

	path = get_config_value("console");
	if (path == NULL)
		return (false);

	sc = uart_ns16550_init(mmio_uart_intr_assert, mmio_uart_intr_deassert,
	    ctx);
	if (uart_ns16550_tty_open(sc, path) != 0) {
		EPRINTLN("Unable to initialize backend '%s' for mmio uart",
		    path);
		assert(0);
	}

	bzero(&mr, sizeof(struct mem_range));
	mr.name = "uart";
	mr.base = UART_MMIO_BASE;
	mr.size = UART_MMIO_SIZE;
	mr.flags = MEM_F_RW;
	mr.handler = mmio_uart_mem_handler;
	mr.arg1 = sc;
	mr.arg2 = mr.base;
	error = register_mem(&mr);
	assert(error == 0);
	mmio_uart_softc = sc;

	return (true);
}

int
bhyve_init_platform(struct vmctx *ctx, struct vcpu *bsp)
{
	const char *bootrom;
	uint64_t elr;
	uint64_t len;
	int error;
	int pcie_intrs[4] = {PCIE_INTA, PCIE_INTB, PCIE_INTC, PCIE_INTD};
	vm_paddr_t fdt_gpa;
	char isa[32];
	uint32_t timebase_frequency;
	int retval;

	bootrom = get_config_value("bootrom");
	if (bootrom == NULL) {
		warnx("no bootrom specified");
		return (ENOENT);
	}
	load_bootrom(ctx, bootrom, &elr, &len);
	error = vm_set_register(bsp, VM_REG_GUEST_SEPC, elr);
	if (error != 0) {
		warn("vm_set_register(GUEST_SEPC)");
		return (error);
	}

	error = vm_get_capability(bsp, VM_CAP_SSTC, &retval);
	if (error != 0)
		return (errno != 0 ? errno : EIO);
	if (retval != 0 && retval != 1)
		return (EPROTO);
	snprintf(isa, sizeof(isa), "%s",
	    retval == 1 ? RISCV_GUEST_ISA_SSTC : RISCV_GUEST_ISA_BASE);
	if (vm_get_riscv_timebase(bsp, &timebase_frequency) != 0)
		return (errno != 0 ? errno : EIO);

	fdt_gpa = vm_get_highmem_base(ctx) + roundup2(len, FDT_DTB_ALIGN);
	error = fdt_init(ctx, guest_ncpus, fdt_gpa, FDT_SIZE, isa,
	    timebase_frequency);
	if (error != 0)
		return (error);

	/* Set FDT base address to the bootable hart. */
	error = vm_set_register(bsp, VM_REG_GUEST_A1, fdt_gpa);
	assert(error == 0);

	fdt_add_aplic(APLIC_MEM_BASE, APLIC_MEM_SIZE, guest_ncpus);
	error = vm_attach_aplic(ctx, APLIC_MEM_BASE, APLIC_MEM_SIZE);
	if (error != 0) {
		warn("vm_attach_aplic()");
		return (error);
	}

	if (init_mmio_uart(ctx))
		fdt_add_uart(UART_MMIO_BASE, UART_MMIO_SIZE, UART_INTR);

	pci_irq_init(pcie_intrs);
	fdt_add_pcie(pcie_intrs);
	vmexit_set_bsp(vcpu_id(bsp));

	return (0);
}

int
bhyve_init_platform_late(struct vmctx *ctx __unused, struct vcpu *bsp __unused)
{

	fdt_finalize();

	return (0);
}

int
bhyve_resume_powered_cpus(struct vmctx *ctx __unused)
{
	int error;

	for (int vcpuid = 0; vcpuid < guest_ncpus; vcpuid++) {
		if (!vmexit_hart_running(CPU_TO_HART(vcpuid)))
			continue;
		error = vm_resume_cpu(fbsdrun_vcpu(vcpuid));
		if (error != 0)
			return (error);
	}
	return (0);
}

#ifdef BHYVE_SNAPSHOT
/*
 * SBI HSM hart state.  Wire: le32 hart count, then one byte per hart
 * (0 = stopped, 1 = started).  At least one hart must be started.
 */
static int
cpu_power_snapshot(struct vm_snapshot_meta *meta)
{
	uint8_t state[CPU_SETSIZE];
	uint32_t ncpus;
	bool any;
	int ret;

	ncpus = (uint32_t)guest_ncpus;
	SNAPSHOT_LE32_OR_LEAVE(ncpus, meta, ret, done);
	if (ncpus != (uint32_t)guest_ncpus || ncpus > CPU_SETSIZE) {
		ret = EINVAL;
		goto done;
	}
	any = false;
	for (uint32_t i = 0; i < ncpus; i++) {
		state[i] = vmexit_hart_running(CPU_TO_HART(i)) ? 1 : 0;
		SNAPSHOT_U8_OR_LEAVE(state[i], meta, ret, done);
		if (state[i] > 1) {
			ret = EINVAL;
			goto done;
		}
		any |= state[i] != 0;
	}
	if (!any) {
		ret = EINVAL;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_RESTORE) {
		for (uint32_t i = 0; i < ncpus; i++)
			vmexit_hart_set_running(CPU_TO_HART(i), state[i] != 0);
	}
done:
	return (ret);
}

static int
uart_snapshot_cb(struct vm_snapshot_meta *meta)
{

	return (uart_ns16550_snapshot(mmio_uart_softc, meta));
}

static int
uart_pause_cb(void)
{
	int error;

	if (mmio_uart_paused)
		return (0);
	error = uart_ns16550_pause(mmio_uart_softc);
	if (error == 0)
		mmio_uart_paused = true;
	return (error);
}

static int
uart_resume_cb(void)
{
	int error;

	if (!mmio_uart_paused)
		return (0);
	error = uart_ns16550_resume(mmio_uart_softc);
	if (error == 0)
		mmio_uart_paused = false;
	return (error);
}

const struct snapshot_md_device *
bhyve_snapshot_md_devices(size_t *count)
{
	static struct snapshot_md_device devices[2];
	size_t n;

	n = 0;
	devices[n++] = (struct snapshot_md_device){
		.name = "cpu_power",
		.snapshot = cpu_power_snapshot,
	};
	/* The MMIO UART exists only when a console backend is configured. */
	if (mmio_uart_softc != NULL)
		devices[n++] = (struct snapshot_md_device){
			.name = "uart",
			.snapshot = uart_snapshot_cb,
			.pause = uart_pause_cb,
			.resume = uart_resume_cb,
		};
	*count = n;
	return (devices);
}
#endif
