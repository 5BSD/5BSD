/* SPDX-License-Identifier: BSD-2-Clause */
/* RISC-V specific Linux system calls. */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <machine/elf.h>
#include <machine/md_var.h>
#include <machine/pmap.h>

#include <riscv/linux/linux.h>
#include <riscv/linux/linux_proto.h>

#define LINUX_RISCV_HWPROBE_BASE_BEHAVIOR 3
#define LINUX_RISCV_HWPROBE_IMA_EXT_0 4
#define LINUX_RISCV_HWPROBE_IMA (1U << 0)
#define LINUX_RISCV_HWPROBE_FD (1U << 0)
#define LINUX_RISCV_HWPROBE_C (1U << 1)
#define LINUX_RISCV_HWPROBE_V (1U << 2)

int
linux_riscv_hwprobe(struct thread *td,
    struct linux_riscv_hwprobe_args *args)
{
	struct l_riscv_hwprobe pair;
	uint64_t extensions;
	size_t i;
	int error;

	(void)td;
	if (args->flags != 0 || args->cpusetsize != 0 || args->cpus != NULL)
		return (EINVAL);
	if (args->pair_count > 1024)
		return (E2BIG);
	extensions = 0;
	if ((elf_hwcap & (HWCAP_ISA_F | HWCAP_ISA_D)) ==
	    (HWCAP_ISA_F | HWCAP_ISA_D))
		extensions |= LINUX_RISCV_HWPROBE_FD;
	if ((elf_hwcap & HWCAP_ISA_C) != 0)
		extensions |= LINUX_RISCV_HWPROBE_C;
	if ((elf_hwcap & HWCAP_ISA_V) != 0 && has_vector)
		extensions |= LINUX_RISCV_HWPROBE_V;
	for (i = 0; i < args->pair_count; i++) {
		error = copyin(&args->pairs[i], &pair, sizeof(pair));
		if (error != 0)
			return (error);
		switch (pair.key) {
		case 0: /* mvendorid: no verified common value across harts */
		case 1: /* marchid */
		case 2: /* mimpid */
			pair.value = UINT64_MAX;
			break;
		case LINUX_RISCV_HWPROBE_BASE_BEHAVIOR:
			pair.value = (elf_hwcap & HWCAP_ISA_G) == HWCAP_ISA_G ?
			    LINUX_RISCV_HWPROBE_IMA : 0;
			break;
		case LINUX_RISCV_HWPROBE_IMA_EXT_0:
			pair.value = extensions;
			break;
		default:
			pair.key = -1;
			pair.value = 0;
			break;
		}
		error = copyout(&pair, &args->pairs[i], sizeof(pair));
		if (error != 0)
			return (error);
	}
	return (0);
}

int
linux_riscv_flush_icache(struct thread *td,
    struct linux_riscv_flush_icache_args *args)
{
	if ((args->flags & ~1UL) != 0)
		return (EINVAL);
	/* Native synchronization covers every active hart and ignores ranges. */
	pmap_sync_icache(vmspace_pmap(td->td_proc->p_vmspace), 0, 0);
	return (0);
}
