/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux remap_file_pages is identical for all supported 64-bit ABIs. */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/proc.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>

#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#include <compat/linux/linux_mmap.h>

int
linux_remap_file_pages(struct thread *td,
    struct linux_remap_file_pages_args *args)
{
	vm_offset_t start;
	vm_size_t size;
	int rv;

	if (args->prot != 0)
		return (EINVAL);
	start = trunc_page(args->start);
	size = trunc_page(args->size);
	if (size == 0 || start + size <= start ||
	    args->pgoff + atop(size) < args->pgoff ||
	    args->pgoff > (INT64_MAX >> PAGE_SHIFT))
		return (EINVAL);
	if (linux_range_sealed(td, start, size))
		return (EPERM);
	rv = vm_map_remap_file_pages(&td->td_proc->p_vmspace->vm_map,
	    start, size, (vm_ooffset_t)args->pgoff << PAGE_SHIFT);
	if (rv != KERN_SUCCESS)
		return (rv == KERN_PROTECTION_FAILURE ? EACCES : EINVAL);
	if ((args->flags & LINUX_MAP_NONBLOCK) == 0)
		linux_mmap_populate(td, start, size, PROT_READ);
	return (0);
}
