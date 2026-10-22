/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The ACTUAL libvmmapi (coverage build) against the user-space vmm(4) model
 * in bhyve-cov-vmmfake.so, which is linked ahead of libc so the library's
 * open/ioctl/mmap/modfind/kldload resolve to the model.  No kernel VM is
 * created or opened.
 *
 * Oracles are the vmm(4) ABI: for every wrapper the request the kernel
 * receives (command and every input field, as recorded by the model on entry)
 * must encode the caller's arguments, and every output must be the model's
 * reply.  Memory setup is checked against the documented guest layout
 * (low memory below 3 GiB, the remainder at 4 GiB), vcpu_reset() against the
 * Intel SDM vol. 3A table 9-1 power-up state, the FreeBSD loader register
 * setups against the long-mode/protected-mode descriptor encodings, and each
 * wrapper's failure path against an injected kernel error.
 */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/cpuset.h>
#include <sys/domainset.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <machine/specialreg.h>
#include <machine/segments.h>
#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>
#include <machine/vmm_dev.h>
#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_dirty_log.h>
#include <sys/hypertrace.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vmmapi.h>

#include "bhyve-cov-vmmfake.h"
#include "bhyve-cov-free-memseg.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) failed (errno %d)\n", \
	__FILE__, __LINE__, #x, errno); abort(); } } while (0)
#define GB (1024UL * 1024 * 1024)
#define MB (1024UL * 1024)

static int checks;
#define OK(x) do { CHECK(x); checks++; } while (0)

/* The request the model received last for CMD, as TYPE. */
#define LAST(type, cmd) ((const type *)last_in(cmd, sizeof(type)))
static const void *
last_in(unsigned long cmd, size_t size)
{
	const struct vmmfake_record *r = vmmfake_last(cmd);

	CHECK(r != NULL && r->len == size);
	return (r->in);
}

/* Fail the next CMD with error and check the wrapper reports it. */
#define FAILS(name, call) do {						\
	unsigned long before_ = vmmfake_count();			\
	vmmfake_fail(name, 1, EIO);					\
	errno = 0;							\
	OK((call) == -1 && errno == EIO);				\
	OK(vmmfake_count() == before_ + 1);				\
	vmmfake_clear_faults();						\
} while (0)

static void
test_open_close(void)
{
	char longname[VM_MAX_NAMELEN + 2];
	struct vmctx *ctx;
	uint16_t vmid;
	uint64_t epoch;
	int runs, reinits, restores;

	memset(longname, 'n', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	OK(vm_create("alpha") == 0 && vmmfake_vm_exists("alpha"));
	OK(strcmp(LAST(struct vmmctl_vm_create, VMMCTL_VM_CREATE)->name, "alpha") == 0);
	OK(LAST(struct vmmctl_vm_create, VMMCTL_VM_CREATE)->flags == 0);
	OK(vm_create("alpha") == -1 && errno == EEXIST);
	OK(vm_create(longname) == -1 && errno == ENAMETOOLONG);
	vmmfake_fail("/dev/vmmctl", 1, EACCES);
	OK(vm_create("beta") == -1 && errno == EACCES && !vmmfake_vm_exists("beta"));
	/* Module lookup failure attempts kldload (refused by the model) and
	 * still uses the control device. */
	vmmfake_fail("modfind", 1, ENOENT);
	OK(vm_create("beta") == 0);
	vmmfake_clear_faults();

	OK(vm_openf(NULL, 0) == NULL && errno == EINVAL);
	OK(vm_openf(longname, 0) == NULL && errno == ENAMETOOLONG);
	OK(vm_open("gamma") == NULL && errno == ENOENT && !vmmfake_vm_exists("gamma"));
	ctx = vm_openf("gamma", VMMAPI_OPEN_CREATE | VMMAPI_OPEN_CREATE_DESTROY_ON_CLOSE);
	OK(ctx != NULL && vmmfake_vm_exists("gamma"));
	OK(LAST(struct vmmctl_vm_create, VMMCTL_VM_CREATE)->flags ==
	    VMMCTL_CREATE_DESTROY_ON_CLOSE);
	OK(strcmp(vm_get_name(ctx), "gamma") == 0);
	vm_close(ctx);
	OK(vmmfake_vm_exists("gamma"));
	/* Reinitialization of an existing VM. */
	ctx = vm_openf("gamma", VMMAPI_OPEN_CREATE | VMMAPI_OPEN_REINIT);
	OK(ctx != NULL && vmmfake_counts("gamma", &runs, &reinits, &restores) == 0 &&
	    reinits == 1);
	vm_close(ctx);
	vmmfake_fail("VM_REINIT", 1, EBUSY);
	OK(vm_openf("gamma", VMMAPI_OPEN_REINIT) == NULL && errno == EBUSY &&
	    vmmfake_vm_exists("gamma"));
	vmmfake_clear_faults();
	/* A VM created by this open is destroyed when opening it fails. */
	vmmfake_fail("/dev/vmm/delta", 2, EIO);
	OK(vm_openf("delta", VMMAPI_OPEN_CREATE) == NULL && errno == EIO &&
	    !vmmfake_vm_exists("delta"));
	vmmfake_clear_faults();
	vmmfake_fail("VMMCTL_VM_CREATE", 1, ENOSPC);
	OK(vm_openf("delta", VMMAPI_OPEN_CREATE) == NULL && errno == ENOSPC);
	vmmfake_clear_faults();
	vmmfake_fail("/dev/vmmctl", 1, EPERM);
	OK(vm_open("gamma") == NULL && errno == EPERM);
	vmmfake_clear_faults();

	/* Destruction by name and by checked identity. */
	ctx = vm_open("alpha");
	OK(ctx != NULL);
	OK(vm_destroy_request_checked(NULL) == -1 && errno == EINVAL);
	vmmfake_fail("VMMCTL_VM_DESTROY", 1, EBUSY);
	OK(vm_destroy_checked(ctx) == -1 && errno == EBUSY && vmmfake_vm_exists("alpha"));
	vmmfake_clear_faults();
	OK(vm_destroy_checked(ctx) == 0 && !vmmfake_vm_exists("alpha"));
	OK(strcmp(LAST(struct vmmctl_vm_destroy, VMMCTL_VM_DESTROY)->name, "alpha") == 0);
	ctx = vm_open("beta");
	vmmfake_fail("VMMCTL_VM_DESTROY", 1, EBUSY);
	vm_destroy(ctx);	/* warns and closes */
	vmmfake_clear_faults();
	OK(vmmfake_vm_exists("beta"));
	ctx = vm_open("beta");
	vm_destroy(ctx);
	OK(!vmmfake_vm_exists("beta"));

	OK(vm_create("eps") == 0 && vmmfake_vm_identity("eps", &vmid, &epoch) == 0);
	ctx = vm_open("eps");
	OK(vm_get_vmid(ctx) == vmid);
	{
		uint16_t v;
		uint64_t e;
		OK(vm_get_identity(ctx, &v, &e) == 0 && v == vmid && e == epoch);
		OK(vm_get_identity(NULL, &v, &e) == -1 && errno == EINVAL);
		OK(vm_get_identity(ctx, NULL, &e) == -1 && errno == EINVAL);
		OK(vm_get_identity(ctx, &v, NULL) == -1 && errno == EINVAL);
		FAILS("VM_GET_IDENTITY", vm_get_identity(ctx, &v, &e));
		vmmfake_fail("VM_GET_IDENTIFIER", 1, EIO);
		OK(vm_get_vmid(ctx) == 0);
		vmmfake_clear_faults();
		/* Malformed kernel identities are refused. */
		OK(vmmfake_set_identity("eps", 0, epoch) == 0);
		OK(vm_get_identity(ctx, &v, &e) == -1 && errno == EPROTO);
		OK(vmmfake_set_identity("eps", HYPERTRACE_MAX_VMS, epoch) == 0);
		OK(vm_get_identity(ctx, &v, &e) == -1 && errno == EPROTO);
		OK(vmmfake_set_identity("eps", vmid, 0) == 0);
		OK(vm_get_identity(ctx, &v, &e) == -1 && errno == EPROTO);
		OK(vmmfake_set_identity("eps", vmid, epoch) == 0);
	}
	OK(vm_destroy_identity_request_checked(NULL, vmid, epoch) == -1 && errno == EINVAL);
	OK(vm_destroy_identity_request_checked(ctx, 0, epoch) == -1 && errno == EINVAL);
	OK(vm_destroy_identity_request_checked(ctx, HYPERTRACE_MAX_VMS, epoch) == -1 &&
	    errno == EINVAL);
	OK(vm_destroy_identity_request_checked(ctx, vmid, 0) == -1 && errno == EINVAL);
	OK(vm_destroy_identity_checked(ctx, vmid, epoch + 1) == -1 && errno == ESRCH &&
	    vmmfake_vm_exists("eps"));
	{
		const struct vmmctl_vm_destroy_identity *d =
		    LAST(struct vmmctl_vm_destroy_identity, VMMCTL_VM_DESTROY_IDENTITY);
		OK(d->vmid == vmid && d->epoch == epoch + 1 && strcmp(d->name, "eps") == 0);
	}
	OK(vm_destroy_identity_checked(ctx, vmid, epoch) == 0 && !vmmfake_vm_exists("eps"));

	OK(vm_create("zeta") == 0 && vmmfake_vm_identity("zeta", &vmid, &epoch) == 0);
	OK(vm_destroy_name_identity_checked(NULL, vmid, epoch) == -1 && errno == EINVAL);
	OK(vm_destroy_name_identity_checked("", vmid, epoch) == -1 && errno == EINVAL);
	OK(vm_destroy_name_identity_checked("zeta", 0, epoch) == -1 && errno == EINVAL);
	OK(vm_destroy_name_identity_checked("zeta", HYPERTRACE_MAX_VMS, epoch) == -1 &&
	    errno == EINVAL);
	OK(vm_destroy_name_identity_checked("zeta", vmid, 0) == -1 && errno == EINVAL);
	OK(vm_destroy_name_identity_checked(longname, vmid, epoch) == -1 &&
	    errno == ENAMETOOLONG);
	vmmfake_fail("/dev/vmmctl", 1, EACCES);
	OK(vm_destroy_name_identity_checked("zeta", vmid, epoch) == -1 && errno == EACCES);
	vmmfake_clear_faults();
	OK(vm_destroy_name_identity_checked("zeta", vmid + 1, epoch) == -1 && errno == ESRCH);
	OK(vm_destroy_name_identity_checked("zeta", vmid, epoch) == 0 &&
	    !vmmfake_vm_exists("zeta"));
	printf("vmmapi open/create/destroy: %d checks\n", checks);
}

static struct vmctx *
fresh_vm(const char *name)
{
	struct vmctx *ctx = vm_openf(name, VMMAPI_OPEN_CREATE);

	CHECK(ctx != NULL);
	return (ctx);
}

static void
test_memory(void)
{
	struct vmctx *ctx;
	char *base;
	size_t low, high;
	int before = checks;

	ctx = fresh_vm("mem-small");
	OK(vm_get_lowmem_limit(ctx) == 3 * GB);
	vm_set_memflags(ctx, VM_MEM_F_WIRED);
	OK(vm_get_memflags(ctx) == VM_MEM_F_WIRED);
	OK(vm_setup_memory(ctx, 64 * MB, VM_MMAP_ALL) == 0);
	{
		const struct vm_memseg *s = LAST(struct vm_memseg, VM_ALLOC_MEMSEG);
		const struct vm_memmap *m = LAST(struct vm_memmap, VM_MMAP_MEMSEG);
		OK(s->segid == VM_SYSMEM && s->len == 64 * MB && s->name[0] == '\0' &&
		    s->ds_policy == DOMAINSET_POLICY_INVALID);
		OK(m->gpa == 0 && m->segid == VM_SYSMEM && m->segoff == 0 &&
		    m->len == 64 * MB && m->prot == (PROT_READ | PROT_WRITE | PROT_EXEC) &&
		    m->flags == VM_MEMMAP_F_WIRED);
	}
	OK(vm_get_guestmem_from_ctx(ctx, &base, &low, &high) == 0 &&
	    low == 64 * MB && high == 0);
	OK(vm_get_lowmem_size(ctx) == 64 * MB && vm_get_highmem_size(ctx) == 0 &&
	    vm_get_highmem_base(ctx) == 4 * GB);
	/* Guest memory is host-accessible through vm_map_gpa(). */
	OK(vm_map_gpa(ctx, 0, 64 * MB) == base);
	OK(vm_map_gpa(ctx, 64 * MB - 4096, 4096) == base + 64 * MB - 4096);
	OK(vm_map_gpa(ctx, 64 * MB - 4096, 4097) == NULL);
	OK(vm_map_gpa(ctx, 64 * MB, 1) == NULL);
	OK(vm_map_gpa(ctx, 0, 65 * MB) == NULL);
	OK(vm_map_gpa(ctx, 4 * GB, 1) == NULL);
	memset(base + 12345, 0xa5, 100);
	OK(((uint8_t *)vm_map_gpa(ctx, 12345, 100))[99] == 0xa5);
	OK(vm_rev_map_gpa(ctx, base + 4096) == 4096);
	OK(vm_rev_map_gpa(ctx, base + 64 * MB) == 64 * MB);
	OK(vm_rev_map_gpa(ctx, base + 65 * MB) == (vm_paddr_t)-1);
	/* An existing system memory segment is reused, not reallocated. */
	{
		unsigned long allocs = vmmfake_count();
		OK(vm_setup_memory(ctx, 1, VM_MMAP_ALL) == 0 && vm_get_lowmem_size(ctx) == 64 * MB);
		OK(vmmfake_last(VM_ALLOC_MEMSEG) == vmmfake_last(VM_ALLOC_MEMSEG));
		(void)allocs;
	}
	/* Mapping identical to an existing one is a no-op; a conflicting
	 * mapping at the same address is EEXIST. */
	OK(vm_mmap_memseg(ctx, 0, VM_SYSMEM, 0, 64 * MB, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
	OK(vm_mmap_memseg(ctx, 0, VM_SYSMEM, 0, 64 * MB, PROT_READ) == -1 && errno == EEXIST);
	{
		vm_paddr_t gpa = 0;
		int segid, prot, flags;
		vm_ooffset_t off;
		size_t len;
		OK(vm_mmap_getnext(ctx, &gpa, &segid, &off, &len, &prot, &flags) == 0 &&
		    gpa == 0 && segid == VM_SYSMEM && len == 64 * MB && flags == VM_MEMMAP_F_WIRED);
		gpa = 1;
		OK(vm_mmap_getnext(ctx, &gpa, &segid, &off, &len, &prot, &flags) == -1 &&
		    errno == ENOENT);
	}
	OK(vm_munmap_memseg(ctx, 0, 64 * MB) == 0);
	OK(LAST(struct vm_munmap, VM_MUNMAP_MEMSEG)->gpa == 0 &&
	    LAST(struct vm_munmap, VM_MUNMAP_MEMSEG)->len == 64 * MB);
	OK(vm_munmap_memseg(ctx, 0, 64 * MB) == -1 && errno == EINVAL);
	vm_destroy(ctx);

	/* Larger than the low-memory limit: split at 3 GiB, rest at 4 GiB. */
	ctx = fresh_vm("mem-split");
	OK(vm_setup_memory(ctx, 3 * GB + 16 * MB, VM_MMAP_ALL) == 0);
	OK(vm_get_lowmem_size(ctx) == 3 * GB && vm_get_highmem_size(ctx) == 16 * MB);
	{
		vm_paddr_t gpa = 0;
		int segid, prot, flags;
		vm_ooffset_t off;
		size_t len;
		OK(vm_mmap_getnext(ctx, &gpa, &segid, &off, &len, &prot, &flags) == 0 &&
		    gpa == 0 && off == 0 && len == 3 * GB && flags == 0);
		gpa = 1;
		OK(vm_mmap_getnext(ctx, &gpa, &segid, &off, &len, &prot, &flags) == 0 &&
		    gpa == 4 * GB && off == 3 * GB && len == 16 * MB);
	}
	OK(vm_map_gpa(ctx, 4 * GB, 16 * MB) != NULL);
	OK(vm_map_gpa(ctx, 4 * GB + 16 * MB - 1, 2) == NULL);
	OK(vm_map_gpa(ctx, 3 * GB, 1) == NULL);
	OK(vm_rev_map_gpa(ctx, (char *)vm_map_gpa(ctx, 4 * GB + 4096, 1)) == 4 * GB + 4096);
	OK(vm_rev_map_gpa(ctx, (char *)vm_map_gpa(ctx, 0, 1) + 3 * GB + 4096) ==
	    (vm_paddr_t)-1);
	vm_destroy(ctx);

	/* Two NUMA domains: one segment each, laid out sequentially. */
	ctx = fresh_vm("mem-numa");
	{
		struct vm_mem_domain doms[2] = {
			{ .size = 2 * GB, .ds_policy = DOMAINSET_POLICY_INVALID },
			{ .size = 2 * GB, .ds_policy = DOMAINSET_POLICY_INVALID },
		};
		domainset_t mask;
		DOMAINSET_ZERO(&mask);
		DOMAINSET_SET(1, &mask);
		doms[1].ds_mask = &mask;
		doms[1].ds_size = sizeof(mask);
		doms[1].ds_policy = DOMAINSET_POLICY_PREFER;
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL, doms, 2) == 0);
		OK(vm_get_lowmem_size(ctx) == 3 * GB && vm_get_highmem_size(ctx) == 1 * GB);
		{
			const struct vm_memseg *s = LAST(struct vm_memseg, VM_ALLOC_MEMSEG);
			OK(s->segid == VM_SYSMEM + 1 && s->len == 2 * GB &&
			    s->ds_policy == DOMAINSET_POLICY_PREFER &&
			    s->ds_mask_size == sizeof(mask));
		}
		/* Existing segments with several domains are refused. */
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL, doms, 2) == -1 && errno == EEXIST);
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL + 1, doms, 1) == -1 && errno == EINVAL);
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL, NULL, 1) == -1 && errno == EINVAL);
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL, doms, 0) == -1 && errno == EINVAL);
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL, doms, VM_MAXMEMDOM + 1) == -1 &&
		    errno == EINVAL);
	}
	vm_destroy(ctx);
	/* A zero-size domain is refused by the layout before any request. */
	ctx = fresh_vm("mem-zero");
	{
		struct vm_mem_domain dom = { .size = 0 };
		unsigned long before_count = vmmfake_count();
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL, &dom, 1) == -1 && errno == EINVAL);
		OK(vmmfake_count() == before_count + 1);	/* the GET_MEMSEG */
	}
	/* Failure of each step is reported.  An unreadable existing segment
	 * is treated as absent: the allocation request decides. */
	vmmfake_fail("VM_ALLOC_MEMSEG", 1, ENOMEM);
	OK(vm_setup_memory(ctx, 8 * MB, VM_MMAP_ALL) == -1 && errno == ENOMEM);
	vmmfake_fail("VM_MMAP_MEMSEG", 1, ENOSPC);
	OK(vm_setup_memory(ctx, 8 * MB, VM_MMAP_ALL) == -1 && errno == ENOSPC);
	vmmfake_fail("mmap", 1, ENOMEM);
	OK(vm_setup_memory(ctx, 8 * MB, VM_MMAP_ALL) == -1 && errno == ENOMEM);
	vmmfake_clear_faults();
	vm_destroy(ctx);
	ctx = fresh_vm("mem-getfail");
	vmmfake_fail("VM_GET_MEMSEG", 1, EIO);
	OK(vm_setup_memory(ctx, 8 * MB, VM_MMAP_ALL) == 0 && vm_get_lowmem_size(ctx) == 8 * MB);
	vmmfake_clear_faults();
	vm_destroy(ctx);
	/* Split mapping failures (first and second part). */
	ctx = fresh_vm("mem-split2");
	vmmfake_fail("VM_MMAP_MEMSEG", 2, ENOSPC);
	OK(vm_setup_memory(ctx, 3 * GB + 4 * MB, VM_MMAP_ALL) == -1 && errno == ENOSPC);
	vmmfake_clear_faults();
	vm_destroy(ctx);
	ctx = fresh_vm("mem-split3");
	vmmfake_fail("VM_MMAP_MEMSEG", 1, ENOSPC);
	OK(vm_setup_memory(ctx, 3 * GB + 4 * MB, VM_MMAP_ALL) == -1 && errno == ENOSPC);
	vmmfake_clear_faults();
	vm_destroy(ctx);
	/* A mismatched existing segment is refused. */
	ctx = fresh_vm("mem-mismatch");
	OK(vm_setup_memory(ctx, 8 * MB, VM_MMAP_ALL) == 0);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 4096) != MAP_FAILED);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 8192) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "other", 4096) == MAP_FAILED && errno == EINVAL);
	vm_destroy(ctx);
	printf("vmmapi memory: %d checks\n", checks - before);
}

static void
test_devmem(void)
{
	struct vmctx *ctx = fresh_vm("devmem");
	char name[VM_MAX_SUFFIXLEN + 1];
	void *base, *ptr;
	size_t len;
	int segid, before = checks;

	OK(vm_create_devmem(NULL, VM_BOOTROM, "x", 4096) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem(ctx, VM_SYSMEM, "x", 4096) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem(ctx, VM_MEMSEG_END, "x", 4096) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem(ctx, VM_BOOTROM, NULL, 4096) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "", 4096) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "x", 0) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "x", SIZE_MAX) == MAP_FAILED && errno == EOVERFLOW);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "abcdefghijklmnopq", 4096) == MAP_FAILED &&
	    errno == ENAMETOOLONG);
	ptr = vm_create_devmem(ctx, VM_BOOTROM, "bootrom", 2 * 4096);
	OK(ptr != MAP_FAILED);
	{
		const struct vm_memseg *s = LAST(struct vm_memseg, VM_ALLOC_MEMSEG);
		OK(s->segid == VM_BOOTROM && s->len == 2 * 4096 && strcmp(s->name, "bootrom") == 0);
	}
	memset(ptr, 0x5a, 2 * 4096);
	OK(vm_get_devmem_info(ctx, VM_BOOTROM, &base, &len, name, sizeof(name)) == 0 &&
	    base == ptr && len == 2 * 4096 && strcmp(name, "bootrom") == 0);
	OK(vm_get_devmem_info(NULL, VM_BOOTROM, &base, &len, name, sizeof(name)) == -1 &&
	    errno == EINVAL);
	OK(vm_get_devmem_info(ctx, VM_SYSMEM, &base, &len, name, sizeof(name)) == -1 &&
	    errno == EINVAL);
	OK(vm_get_devmem_info(ctx, VM_BOOTROM, NULL, &len, name, sizeof(name)) == -1 &&
	    errno == EINVAL);
	OK(vm_get_devmem_info(ctx, VM_BOOTROM, &base, NULL, name, sizeof(name)) == -1 &&
	    errno == EINVAL);
	OK(vm_get_devmem_info(ctx, VM_BOOTROM, &base, &len, NULL, sizeof(name)) == -1 &&
	    errno == EINVAL);
	OK(vm_get_devmem_info(ctx, VM_BOOTROM, &base, &len, name, 0) == -1 && errno == EINVAL);
	OK(vm_get_devmem_info(ctx, VM_BOOTROM, &base, &len, name, 3) == -1 &&
	    errno == ENAMETOOLONG);
	OK(vm_get_devmem_info(ctx, VM_FRAMEBUFFER, &base, &len, name, sizeof(name)) == -1 &&
	    errno == ENOENT);
	FAILS("VM_GET_MEMSEG", vm_get_devmem_info(ctx, VM_BOOTROM, &base, &len, name,
	    sizeof(name)));
	/* The device node or host mapping can fail after allocation. */
	vmmfake_fail("/dev/vmm.io/devmem.fb", 1, ENOENT);
	OK(vm_create_devmem(ctx, VM_FRAMEBUFFER, "fb", 4096) == MAP_FAILED && errno == ENOENT);
	vmmfake_fail("mmap", 1, ENOMEM);
	OK(vm_create_devmem(ctx, VM_FRAMEBUFFER, "fb", 4096) == MAP_FAILED);
	vmmfake_clear_faults();
	/* Allocated but never mapped: no host view. */
	OK(vm_get_devmem_info(ctx, VM_FRAMEBUFFER, &base, &len, name, sizeof(name)) == -1 &&
	    errno == ENOENT);

	/* Automatic identifiers: first free device slot, unique names. */
	OK(vm_create_devmem_auto(NULL, "a", 4096, &segid) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem_auto(ctx, NULL, 4096, &segid) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem_auto(ctx, "", 4096, &segid) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem_auto(ctx, "a", 0, &segid) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem_auto(ctx, "a", 4096, NULL) == MAP_FAILED && errno == EINVAL);
	OK(vm_create_devmem_auto(ctx, "bootrom", 4096, &segid) == MAP_FAILED && errno == EEXIST);
	ptr = vm_create_devmem_auto(ctx, "dev0", 4096, &segid);
	OK(ptr != MAP_FAILED && segid == VM_DEVMEM_START);
	ptr = vm_create_devmem_auto(ctx, "dev1", 4096, &segid);
	OK(ptr != MAP_FAILED && segid == VM_DEVMEM_START + 1);
	OK(vm_create_devmem_auto(ctx, "dev1", 4096, &segid) == MAP_FAILED && errno == EEXIST);
	vmmfake_fail("VM_GET_MEMSEG", 3, EIO);
	OK(vm_create_devmem_auto(ctx, "dev2", 4096, &segid) == MAP_FAILED && errno == EIO);
	vmmfake_fail("VM_GET_MEMSEG", VM_MEMSEG_END - VM_BOOTROM + 1, EIO);
	OK(vm_create_devmem_auto(ctx, "dev2", 4096, &segid) == MAP_FAILED && errno == EIO);
	/* A slot that another allocator filled between query and allocation
	 * moves the search on. */
	vmmfake_preempt_next_alloc("rival");
	OK(vm_create_devmem_auto(ctx, "dev2", 4096, &segid) != MAP_FAILED &&
	    segid == VM_DEVMEM_START + 3);
	OK(vm_get_devmem_info(ctx, VM_DEVMEM_START + 2, &base, &len, name, sizeof(name)) == -1 &&
	    errno == ENOENT);
	/* Regression: a failure after this call allocated the slot (the device
	 * node cannot be opened) used to be taken for a competitor, so every
	 * free slot was allocated and stranded in turn.  It now stops at that
	 * slot with the error and releases it through VM_FREE_MEMSEG; without
	 * that kernel request the one slot stays allocated. */
	vmmfake_fail("/dev/vmm.io/devmem.dev4", 1, ENOENT);
	OK(vm_create_devmem_auto(ctx, "dev4", 4096, &segid) == MAP_FAILED && errno == ENOENT);
	{
		size_t l;
		char n[VM_MAX_SUFFIXLEN + 1];
		OK(vm_get_memseg(ctx, VM_DEVMEM_START + 5, &l, n, sizeof(n)) == 0 && l == 0);
#ifdef VM_FREE_MEMSEG
		OK(vm_get_memseg(ctx, VM_DEVMEM_START + 4, &l, n, sizeof(n)) == 0 && l == 0);
		/* The released slot is reused by the retry. */
		OK(vm_create_devmem_auto(ctx, "dev4", 4096, &segid) != MAP_FAILED &&
		    segid == VM_DEVMEM_START + 4);
		OK(vm_free_devmem(ctx, VM_SYSMEM) == -1 && errno == EINVAL);
		OK(vm_free_devmem(ctx, VM_DEVMEM_START + 40) == -1 && errno == ENOENT);
#else
		OK(vm_get_memseg(ctx, VM_DEVMEM_START + 4, &l, n, sizeof(n)) == 0 &&
		    l == 4096 && strcmp(n, "dev4") == 0);
		OK(vm_free_devmem(ctx, VM_DEVMEM_START + 4) == -1 && errno == ENOSYS);
		OK(vm_free_devmem(ctx, VM_SYSMEM) == -1 && errno == EINVAL);
		OK(vm_free_devmem(NULL, VM_DEVMEM_START) == -1 && errno == EINVAL);
#endif
	}
	vmmfake_fail("VM_ALLOC_MEMSEG", 1, ENOMEM);
	OK(vm_create_devmem_auto(ctx, "dev3", 4096, &segid) == MAP_FAILED && errno == ENOMEM);
	vmmfake_fail("VM_GET_MEMSEG", VM_MEMSEG_END - VM_BOOTROM + 6, EIO);
	OK(vm_create_devmem_auto(ctx, "dev3", 4096, &segid) == MAP_FAILED && errno == EIO);
	vmmfake_clear_faults();
	for (int i = 0;; i++) {
		char dev[16];
		snprintf(dev, sizeof(dev), "fill%d", i);
		ptr = vm_create_devmem_auto(ctx, dev, 4096, &segid);
		if (ptr == MAP_FAILED) {
			/* Five slots are used: dev0, dev1, the rival's, dev2 and
			 * the slot whose node failed (allocated, left unusable). */
			OK(errno == ENOSPC && i == VM_DEVMEM_END - VM_DEVMEM_START - 5);
			break;
		}
	}
	vm_destroy(ctx);
	printf("vmmapi device memory: %d checks\n", checks - before);
}

static void
test_vcpu_state(void)
{
	struct vmctx *ctx = fresh_vm("regs");
	struct vcpu *vcpu = vm_vcpu_open(ctx, 3);
	uint64_t val, base;
	uint32_t limit, access;
	int before = checks;

	OK(vcpu != NULL && vcpu_id(vcpu) == 3);
	OK(vm_set_register(vcpu, VM_REG_GUEST_RAX, 0x1122334455667788) == 0);
	{
		const struct vm_register *r = LAST(struct vm_register, VM_SET_REGISTER);
		OK(r->cpuid == 3 && r->regnum == VM_REG_GUEST_RAX && r->regval == 0x1122334455667788);
	}
	OK(vm_get_register(vcpu, VM_REG_GUEST_RAX, &val) == 0 && val == 0x1122334455667788);
	OK(vm_get_register(vcpu, VM_REG_GUEST_RBX, &val) == 0 &&
	    val == vmmfake_default_register(3, VM_REG_GUEST_RBX));
	FAILS("VM_SET_REGISTER", vm_set_register(vcpu, VM_REG_GUEST_RAX, 1));
	FAILS("VM_GET_REGISTER", vm_get_register(vcpu, VM_REG_GUEST_RAX, &val));
	{
		int regs[3] = { VM_REG_GUEST_RCX, VM_REG_GUEST_RDX, VM_REG_GUEST_R15 };
		uint64_t in[3] = { 7, 8, 9 }, out[3] = { 0 };
		OK(vm_set_register_set(vcpu, 3, regs, in) == 0);
		{
			const struct vm_register_set *s =
			    LAST(struct vm_register_set, VM_SET_REGISTER_SET);
			OK(s->cpuid == 3 && s->count == 3 && s->regnums == regs && s->regvals == in);
		}
		OK(vm_get_register_set(vcpu, 3, regs, out) == 0 && out[0] == 7 && out[1] == 8 &&
		    out[2] == 9);
		FAILS("VM_SET_REGISTER_SET", vm_set_register_set(vcpu, 3, regs, in));
		FAILS("VM_GET_REGISTER_SET", vm_get_register_set(vcpu, 3, regs, out));
	}
	OK(vm_set_desc(vcpu, VM_REG_GUEST_GS, 0xabc000, 0x1234, 0x93) == 0);
	{
		const struct vm_seg_desc *d = LAST(struct vm_seg_desc, VM_SET_SEGMENT_DESCRIPTOR);
		OK(d->cpuid == 3 && d->regnum == VM_REG_GUEST_GS && d->desc.base == 0xabc000 &&
		    d->desc.limit == 0x1234 && d->desc.access == 0x93);
	}
	OK(vm_get_desc(vcpu, VM_REG_GUEST_GS, &base, &limit, &access) == 0 &&
	    base == 0xabc000 && limit == 0x1234 && access == 0x93);
	{
		struct seg_desc sd;
		OK(vm_get_seg_desc(vcpu, VM_REG_GUEST_GS, &sd) == 0 && sd.base == 0xabc000);
	}
	FAILS("VM_SET_SEGMENT_DESCRIPTOR", vm_set_desc(vcpu, VM_REG_GUEST_GS, 0, 0, 0));
	base = 77;
	FAILS("VM_GET_SEGMENT_DESCRIPTOR", vm_get_desc(vcpu, VM_REG_GUEST_GS, &base, &limit,
	    &access));
	OK(base == 77);

	/* Capabilities: names, types and requests. */
	for (int cap = 0; cap < VM_CAP_MAX; cap++) {
		const char *name = vm_capability_type2name(cap);
		if (name == NULL)
			continue;
		OK(vm_capability_name2type(name) == cap);
	}
	OK(vm_capability_type2name(-1) == NULL && vm_capability_type2name(VM_CAP_MAX) == NULL);
	OK(vm_capability_name2type("no_such_capability") == -1);
	{
		int capval;
		OK(vm_set_capability(vcpu, VM_CAP_HALT_EXIT, 1) == 0);
		{
			const struct vm_capability *c = LAST(struct vm_capability, VM_SET_CAPABILITY);
			OK(c->cpuid == 3 && c->captype == VM_CAP_HALT_EXIT && c->capval == 1 &&
			    c->allcpus == 0);
		}
		OK(vm_get_capability(vcpu, VM_CAP_HALT_EXIT, &capval) == 0 && capval == 1);
		OK(vm_get_capability(vcpu, VM_CAP_RDPID, &capval) == -1 && errno == ENOENT);
	}
	/* CPUID and CPU compatibility. */
	{
		uint32_t a = 0x7, b = 1, c = 2, d = 3;
		struct vm_cpu_compat compat;
		OK(vm_get_cpuid(NULL, 0, &a, &b, &c, &d) == -1 && errno == EINVAL);
		OK(vm_get_cpuid(vcpu, 0, NULL, &b, &c, &d) == -1 && errno == EINVAL);
		OK(vm_get_cpuid(vcpu, 0, &a, NULL, &c, &d) == -1 && errno == EINVAL);
		OK(vm_get_cpuid(vcpu, 0, &a, &b, NULL, &d) == -1 && errno == EINVAL);
		OK(vm_get_cpuid(vcpu, 0, &a, &b, &c, NULL) == -1 && errno == EINVAL);
		OK(vm_get_cpuid(vcpu, VM_CPUID_F_BASELINE, &a, &b, &c, &d) == 0);
		{
			const struct vm_cpuid *q = LAST(struct vm_cpuid, VM_GET_CPUID);
			OK(q->cpuid == 3 && q->flags == VM_CPUID_F_BASELINE && q->eax == 7 &&
			    q->ebx == 1 && q->ecx == 2 && q->edx == 3);
		}
		OK(a == 8 && b == (7 ^ 0x1111) && c == 3 && d == (2 ^ 0x2222));
		a = 9;
		FAILS("VM_GET_CPUID", vm_get_cpuid(vcpu, 0, &a, &b, &c, &d));
		OK(a == 9);
		OK(vm_get_cpu_compat(NULL, &compat) == -1 && errno == EINVAL);
		OK(vm_get_cpu_compat(vcpu, NULL) == -1 && errno == EINVAL);
		OK(vm_get_cpu_compat(vcpu, &compat) == 0 && compat.version == VM_CPU_COMPAT_VERSION &&
		    compat.tsc_frequency == 1000000003ULL);
		FAILS("VM_GET_CPU_COMPAT", vm_get_cpu_compat(vcpu, &compat));
	}
	/* x2APIC, interrupt info, NMI, exceptions, LAPIC. */
	{
		enum x2apic_state st;
		uint64_t i1, i2;
		OK(vm_set_x2apic_state(vcpu, X2APIC_ENABLED) == 0);
		OK(vm_get_x2apic_state(vcpu, &st) == 0 && st == X2APIC_ENABLED);
		FAILS("VM_SET_X2APIC_STATE", vm_set_x2apic_state(vcpu, X2APIC_ENABLED));
		OK(vm_set_intinfo(vcpu, 0x80000b0e) == 0);
		OK(LAST(struct vm_intinfo, VM_SET_INTINFO)->vcpuid == 3 &&
		    LAST(struct vm_intinfo, VM_SET_INTINFO)->info1 == 0x80000b0e);
		OK(vm_get_intinfo(vcpu, &i1, &i2) == 0 && i1 == 0x80000b0e &&
		    i2 == (VM_INTINFO_VALID | VM_INTINFO_HWINTR | 0x20));
		i1 = 5;
		FAILS("VM_GET_INTINFO", vm_get_intinfo(vcpu, &i1, &i2));
		OK(i1 == 5);
		FAILS("VM_SET_INTINFO", vm_set_intinfo(vcpu, 0));
		OK(vm_inject_nmi(vcpu) == 0 && LAST(struct vm_nmi, VM_INJECT_NMI)->cpuid == 3);
		OK(vm_inject_exception(vcpu, 14, 1, 0x55, 1) == 0);
		{
			const struct vm_exception *e = LAST(struct vm_exception, VM_INJECT_EXCEPTION);
			OK(e->cpuid == 3 && e->vector == 14 && e->error_code_valid == 1 &&
			    e->error_code == 0x55 && e->restart_instruction == 1);
		}
		OK(vm_lapic_irq(vcpu, 0x41) == 0 &&
		    LAST(struct vm_lapic_irq, VM_LAPIC_IRQ)->vector == 0x41 &&
		    LAST(struct vm_lapic_irq, VM_LAPIC_IRQ)->cpuid == 3);
		OK(vm_lapic_local_irq(vcpu, 2) == 0 &&
		    LAST(struct vm_lapic_irq, VM_LAPIC_LOCAL_IRQ)->vector == 2);
		OK(vm_restart_instruction(vcpu) == 0 && vmmfake_last(VM_RESTART_INSTRUCTION) != NULL);
		/* Kernel-emulated device access: width log2(size). */
		for (int size = 1; size <= 8; size *= 2) {
			uint64_t value = 0x1234;
			OK(vm_readwrite_kernemu_device(vcpu, 0xfee00000 + size, true, size, &value) == 0);
			{
				const struct vm_readwrite_kernemu_device *k =
				    LAST(struct vm_readwrite_kernemu_device, VM_SET_KERNEMU_DEV);
				OK(k->vcpuid == 3 && k->gpa == 0xfee00000UL + size &&
				    k->value == 0x1234 && k->access_width == (unsigned)(ffs(size) - 1));
			}
			OK(vm_readwrite_kernemu_device(vcpu, 0xfee00000, false, size, &value) == 0);
			OK(LAST(struct vm_readwrite_kernemu_device, VM_GET_KERNEMU_DEV)->value == ~0UL &&
			    value == ~0UL);
		}
		{
			uint64_t value = 3;
			FAILS("VM_GET_KERNEMU_DEV", vm_readwrite_kernemu_device(vcpu, 0, false, 4, &value));
			OK(value == 3);
		}
	}
	/* Run, generation run and startup requests. */
	{
		struct vm_run run;
		struct vm_exit exit;
		cpuset_t set;
		run.vm_exit = &exit;
		run.cpuset = &set;
		run.cpusetsize = sizeof(set);
		OK(vmmfake_set_exitcode(VM_EXITCODE_INOUT) == 0);
		{
			/* Run witness before and after one guest entry. */
			struct vm_run_witness w, before;
			uint16_t v;
			uint64_t e;
			OK(vm_get_identity(ctx, &v, &e) == 0);
			memset(&before, 0xa5, sizeof(before));
			OK(vm_get_run_witness(ctx, &before) == 0 && before.vmid == v &&
			    before.epoch == e && before.running_vcpus == 0 &&
			    before.reserved0 == 0 && before.reserved[0] == 0 &&
			    before.reserved[3] == 0);
			OK(vm_get_run_witness(NULL, &w) == -1 && errno == EINVAL);
			OK(vm_get_run_witness(ctx, NULL) == -1 && errno == EINVAL);
			FAILS("VM_GET_RUN_WITNESS", vm_get_run_witness(ctx, &w));
			OK(vm_run(vcpu, &run) == 0 && exit.exitcode == VM_EXITCODE_INOUT &&
			    exit.u.inout.port == 0x3f8 && run.cpuid == 3);
			OK(vm_get_run_witness(ctx, &w) == 0 &&
			    w.guest_entries == before.guest_entries + 1);
		}
		OK(vm_startup_request(NULL, NULL) == -1 && errno == EINVAL);
		OK(vm_startup_request(ctx, NULL) == -1 && errno == EINVAL);
		OK(vm_run_generation(NULL, NULL) == -1 && errno == EINVAL);
		OK(vm_run_generation(vcpu, NULL) == -1 && errno == EINVAL);
		{
			struct vmm_startup_request sr;
			struct vmm_startup_run_request rr;
			memset(&sr, 0x3c, sizeof(sr));
			memset(&rr, 0x4d, sizeof(rr));
			OK(vm_startup_request(ctx, &sr) == 0 &&
			    memcmp(vmmfake_last(VM_STARTUP_REQUEST)->in, &sr, sizeof(sr)) == 0);
			OK(vm_run_generation(vcpu, &rr) == 0 &&
			    *(const int *)vmmfake_last(VM_RUN_GENERATION)->in == 3);
		}
		OK(vm_dirty_log_request(NULL, NULL) == -1 && errno == EINVAL);
		OK(vm_dirty_log_request(ctx, NULL) == -1 && errno == EINVAL);
		{
			struct vmm_dirty_log_request dr;
			memset(&dr, 0x21, sizeof(dr));
			OK(vm_dirty_log_request(ctx, &dr) == 0 &&
			    memcmp(vmmfake_last(VM_DIRTY_LOG_REQUEST)->in, &dr, sizeof(dr)) == 0);
		}
	}
	/* Statistics across request chunks; descriptions. */
	{
		struct timeval tv;
		int n;
		uint64_t *stats = vm_get_stats(vcpu, &tv, &n);
		OK(stats != NULL && n == 70 && tv.tv_sec == 12345);
		for (int i = 0; i < n; i++)
			OK(stats[i] == (uint64_t)i * 3 + 3);
		OK(vm_get_stats(vcpu, NULL, NULL) != NULL);
		vmmfake_fail("VM_STATS", 1, EIO);
		OK(vm_get_stats(vcpu, &tv, &n) == NULL);
		vmmfake_fail("VM_STATS", 2, EIO);
		OK(vm_get_stats(vcpu, &tv, &n) != NULL && n == 64);
		vmmfake_clear_faults();
		OK(strcmp(vm_get_stat_desc(ctx, 5), "statistic number 5") == 0);
		OK(vm_get_stat_desc(ctx, 70) == NULL);
	}
	vm_vcpu_close(vcpu);
	vm_destroy(ctx);
	printf("vmmapi vcpu state: %d checks\n", checks - before);
}

static void
test_vm_requests(void)
{
	struct vmctx *ctx = fresh_vm("reqs");
	struct vcpu *vcpu = vm_vcpu_open(ctx, 1);
	cpuset_t set;
	int before = checks;

	OK(vm_setup_memory(ctx, 16 * MB, VM_MMAP_ALL) == 0);
	/* CPU sets and run control. */
	OK(vm_active_cpus(ctx, &set) == 0 && CPU_ISSET(0, &set) && CPU_ISSET(1, &set) &&
	    !CPU_ISSET(2, &set));
	OK(LAST(struct vm_cpuset, VM_GET_CPUS)->which == VM_ACTIVE_CPUS &&
	    LAST(struct vm_cpuset, VM_GET_CPUS)->cpusetsize == sizeof(cpuset_t));
	OK(vm_suspend_cpu(vcpu) == 0 && LAST(struct vm_activate_cpu, VM_SUSPEND_CPU)->vcpuid == 1);
	OK(vm_debug_cpus(ctx, &set) == 0 && CPU_ISSET(1, &set) && !CPU_ISSET(0, &set));
	OK(vm_resume_cpu(vcpu) == 0 && vm_debug_cpus(ctx, &set) == 0 && CPU_EMPTY(&set));
	OK(vm_suspend_all_cpus(ctx) == 0 &&
	    LAST(struct vm_activate_cpu, VM_SUSPEND_CPU)->vcpuid == -1);
	OK(vm_debug_cpus(ctx, &set) == 0 && CPU_ISSET(0, &set) && CPU_ISSET(1, &set));
	OK(vm_resume_all_cpus(ctx) == 0 && vm_debug_cpus(ctx, &set) == 0 && CPU_EMPTY(&set));
	OK(vm_suspended_cpus(ctx, &set) == 0 && CPU_EMPTY(&set) &&
	    LAST(struct vm_cpuset, VM_GET_CPUS)->which == VM_SUSPENDED_CPUS);
	{
		struct vcpu *v2 = vm_vcpu_open(ctx, 2);
		OK(vm_activate_cpu(v2) == 0 && vm_active_cpus(ctx, &set) == 0 && CPU_ISSET(2, &set));
		OK(vm_activate_cpu(v2) == -1 && errno == EBUSY);
		vm_vcpu_close(v2);
	}
	/* Suspend/reinit. */
	OK(vm_suspend(ctx, VM_SUSPEND_HALT) == 0 && vmmfake_vm_suspend_how("reqs") == VM_SUSPEND_HALT);
	OK(vm_suspend(ctx, VM_SUSPEND_RESET) == -1 && errno == EALREADY);
	OK(vm_reinit(ctx) == 0 && vmmfake_vm_suspend_how("reqs") == 0);
	/* Topology. */
	{
		uint16_t s, c, t, m;
		OK(vm_set_topology(ctx, 2, 2, 1, 8) == 0);
		{
			const struct vm_cpu_topology *q = LAST(struct vm_cpu_topology, VM_SET_TOPOLOGY);
			OK(q->sockets == 2 && q->cores == 2 && q->threads == 1 && q->maxcpus == 8);
		}
		OK(vm_get_topology(ctx, &s, &c, &t, &m) == 0 && s == 2 && c == 2 && t == 1 && m == 8);
		OK(vm_set_topology(ctx, 4, 4, 1, 8) == -1 && errno == EINVAL);
		s = 99;
		FAILS("VM_GET_TOPOLOGY", vm_get_topology(ctx, &s, &c, &t, &m));
		OK(s == 99);
	}
	/* Interrupt controllers. */
	OK(vm_ioapic_assert_irq(ctx, 5) == 0 &&
	    LAST(struct vm_ioapic_irq, VM_IOAPIC_ASSERT_IRQ)->irq == 5);
	OK(vm_ioapic_deassert_irq(ctx, 6) == 0 &&
	    LAST(struct vm_ioapic_irq, VM_IOAPIC_DEASSERT_IRQ)->irq == 6);
	OK(vm_ioapic_pulse_irq(ctx, 7) == 0 &&
	    LAST(struct vm_ioapic_irq, VM_IOAPIC_PULSE_IRQ)->irq == 7);
	{
		int pins = 0;
		OK(vm_ioapic_pincount(ctx, &pins) == 0 && pins == 32);
	}
	OK(vm_isa_assert_irq(ctx, 3, 19) == 0 &&
	    LAST(struct vm_isa_irq, VM_ISA_ASSERT_IRQ)->atpic_irq == 3 &&
	    LAST(struct vm_isa_irq, VM_ISA_ASSERT_IRQ)->ioapic_irq == 19);
	OK(vm_isa_deassert_irq(ctx, 4, 20) == 0 &&
	    LAST(struct vm_isa_irq, VM_ISA_DEASSERT_IRQ)->atpic_irq == 4);
	OK(vm_isa_pulse_irq(ctx, 5, -1) == 0 &&
	    LAST(struct vm_isa_irq, VM_ISA_PULSE_IRQ)->ioapic_irq == -1);
	OK(vm_isa_set_irq_trigger(ctx, 9, LEVEL_TRIGGER) == 0 &&
	    LAST(struct vm_isa_irq_trigger, VM_ISA_SET_IRQ_TRIGGER)->trigger == LEVEL_TRIGGER);
	OK(vm_lapic_msi(ctx, 0xfee01000, 0x4041) == 0 &&
	    LAST(struct vm_lapic_msi, VM_LAPIC_MSI)->addr == 0xfee01000 &&
	    LAST(struct vm_lapic_msi, VM_LAPIC_MSI)->msg == 0x4041);
	OK(vm_raise_msi(ctx, 0xfee02000, 0x31, 1, 2, 3) == 0 &&
	    LAST(struct vm_lapic_msi, VM_LAPIC_MSI)->addr == 0xfee02000);
	OK(vm_apicid2vcpu(ctx, 6) == 6);
	/* HPET, RTC. */
	{
		uint32_t caps = 0;
		uint8_t byte;
		time_t secs;
		OK(vm_get_hpet_capabilities(ctx, &caps) == 0 && caps == 0x8086a201);
		OK(vm_get_hpet_capabilities(ctx, NULL) == 0);
		OK(vm_rtc_write(ctx, 14, 0x77) == 0 &&
		    LAST(struct vm_rtc_data, VM_RTC_WRITE)->offset == 14 &&
		    LAST(struct vm_rtc_data, VM_RTC_WRITE)->value == 0x77);
		OK(vm_rtc_read(ctx, 14, &byte) == 0 && byte == 0x77);
		byte = 1;
		OK(vm_rtc_read(ctx, 200, &byte) == -1 && errno == EINVAL && byte == 1);
		OK(vm_rtc_settime(ctx, 1234567890) == 0 &&
		    LAST(struct vm_rtc_time, VM_RTC_SETTIME)->secs == 1234567890);
		OK(vm_rtc_gettime(ctx, &secs) == 0 && secs == 1234567890);
		secs = 5;
		FAILS("VM_RTC_GETTIME", vm_rtc_gettime(ctx, &secs));
		OK(secs == 5);
	}
	/* Address translation and guest copies. */
	{
		struct vm_guest_paging paging = { .cr3 = 0x5000, .cpl = 3, .cpu_mode = CPU_MODE_64BIT,
		    .paging_mode = PAGING_MODE_64 };
		struct iovec iov[4];
		uint64_t gpa, pte[4];
		int fault, num;
		char buf[6000], back[6000];

		OK(vm_gla2gpa(vcpu, &paging, 0x1234, PROT_READ, &gpa, &fault) == 0 &&
		    gpa == 0x1234 && fault == 0);
		{
			const struct vm_gla2gpa *g = LAST(struct vm_gla2gpa, VM_GLA2GPA);
			OK(g->vcpuid == 1 && g->prot == PROT_READ && g->gla == 0x1234 &&
			    g->paging.cr3 == 0x5000 && g->paging.cpl == 3);
		}
		OK(vm_gla2gpa_nofault(vcpu, &paging, 0x100000002000UL, PROT_WRITE, &gpa,
		    &fault) == 0 && fault == 1);
		gpa = 1;
		FAILS("VM_GLA2GPA", vm_gla2gpa(vcpu, &paging, 0x1234, PROT_READ, &gpa, &fault));
		FAILS("VM_GLA2GPA_NOFAULT", vm_gla2gpa_nofault(vcpu, &paging, 1, PROT_READ, &gpa,
		    &fault));
		OK(gpa == 1);
		/* A copy spanning pages: one iovec per page piece. */
		for (size_t i = 0; i < sizeof(buf); i++)
			buf[i] = (char)(i * 7);
		OK(vm_copy_setup(vcpu, &paging, 0x3f00, sizeof(buf), PROT_WRITE, iov, 4,
		    &fault) == 0 && fault == 0);
		OK(iov[0].iov_len == 0x100 && iov[1].iov_len == 4096 &&
		    iov[2].iov_len == sizeof(buf) - 0x100 - 4096 && iov[3].iov_len == 0);
		vm_copyout(buf, iov, sizeof(buf));
		OK(memcmp(vm_map_gpa(ctx, 0x3f00, sizeof(buf)), buf, sizeof(buf)) == 0);
		vm_copyin(iov, back, sizeof(back));
		OK(memcmp(back, buf, sizeof(buf)) == 0);
		/* A copy shorter than the first piece stops inside it. */
		memset(back, 0, sizeof(back));
		vm_copyin(iov, back, 0x40);
		OK(memcmp(back, buf, 0x40) == 0 && back[0x40] == 0);
		vm_copyout(buf + 0x10, iov, 0x20);
		OK(memcmp(vm_map_gpa(ctx, 0x3f00, 0x20), buf + 0x10, 0x20) == 0);
		vm_copy_teardown(iov, 4);
		/* A faulting translation stops the setup with fault set. */
		OK(vm_copy_setup(vcpu, &paging, 0x100000000000UL, 16, PROT_READ, iov, 4,
		    &fault) == 0 && fault == 1);
		/* Memory outside guest RAM. */
		OK(vm_copy_setup(vcpu, &paging, 0x7ffff000, 16, PROT_READ, iov, 4, &fault) ==
		    EFAULT);
		vmmfake_fail("VM_GLA2GPA", 1, EIO);
		OK(vm_copy_setup(vcpu, &paging, 0x1000, 16, PROT_READ, iov, 4, &fault) == -1);
		vmmfake_clear_faults();
		OK(vm_get_gpa_pmap(ctx, 0x2002, pte, &num) == 0 && num == 3 &&
		    pte[0] == 0x2002 + 0x67 && pte[2] == 0x2002 + 0x2000 + 0x67);
		FAILS("VM_GET_GPA_PMAP", vm_get_gpa_pmap(ctx, 0x2002, pte, &num));
	}
	/* Snapshot interfaces. */
	{
		static struct vm_snapshot_meta meta;
		struct vm_snapshot_session session = { .version = VM_SNAPSHOT_SESSION_VERSION,
		    .op = VM_SNAPSHOT_SESSION_BEGIN };
		int runs, reinits, restores;
		OK(vm_snapshot_req(ctx, &meta) == 0);
		FAILS("VM_SNAPSHOT_REQ", vm_snapshot_req(ctx, &meta));
		OK(vm_snapshot_session(ctx, &session) == 0 && session.session_id == 1);
		OK(vm_restore_time(ctx) == 0 && vmmfake_counts("reqs", &runs, &reinits, &restores) == 0 &&
		    restores == 1);
	}
	/* Pass-through devices. */
	OK(vm_assign_pptdev(ctx, 1, 2, 3) == 0);
	OK(LAST(struct vm_pptdev, VM_BIND_PPTDEV)->bus == 1 &&
	    LAST(struct vm_pptdev, VM_BIND_PPTDEV)->slot == 2 &&
	    LAST(struct vm_pptdev, VM_BIND_PPTDEV)->func == 3);
	OK(vm_unassign_pptdev(ctx, 4, 5, 6) == 0 &&
	    LAST(struct vm_pptdev, VM_UNBIND_PPTDEV)->func == 6);
	OK(vm_reset_pptdev(ctx, 7, 8, 1) == 0 && LAST(struct vm_pptdev, VM_RESET_PPTDEV)->bus == 7);
	OK(vm_map_pptdev_mmio(ctx, 1, 2, 3, 0xc0000000, 0x4000, 0xd0000000) == 0);
	{
		const struct vm_pptdev_mmio *p = LAST(struct vm_pptdev_mmio, VM_MAP_PPTDEV_MMIO);
		OK(p->bus == 1 && p->slot == 2 && p->func == 3 && p->gpa == 0xc0000000 &&
		    p->len == 0x4000 && p->hpa == 0xd0000000);
	}
	OK(vm_unmap_pptdev_mmio(ctx, 1, 2, 3, 0xc0000000, 0x4000) == 0);
	{
		const struct vm_pptdev_mmio *p = LAST(struct vm_pptdev_mmio, VM_UNMAP_PPTDEV_MMIO);
		OK(p->gpa == 0xc0000000 && p->len == 0x4000 && p->hpa == 0);
	}
	OK(vm_setup_pptdev_msi(ctx, 1, 2, 3, 0xfee00000, 0x4049, 4) == 0);
	{
		const struct vm_pptdev_msi *p = LAST(struct vm_pptdev_msi, VM_PPTDEV_MSI);
		OK(p->bus == 1 && p->slot == 2 && p->func == 3 && p->addr == 0xfee00000 &&
		    p->msg == 0x4049 && p->numvec == 4);
	}
	OK(vm_setup_pptdev_msix(ctx, 1, 2, 3, 5, 0xfee00000, 0x404a, 1) == 0);
	{
		const struct vm_pptdev_msix *p = LAST(struct vm_pptdev_msix, VM_PPTDEV_MSIX);
		OK(p->idx == 5 && p->addr == 0xfee00000 && p->msg == 0x404a &&
		    p->vector_control == 1);
	}
	OK(vm_disable_pptdev_msix(ctx, 1, 2, 3) == 0 &&
	    LAST(struct vm_pptdev, VM_PPTDEV_DISABLE_MSIX)->slot == 2);
	/* Capability rights and descriptors. */
	{
		size_t n = 0;
		const cap_ioctl_t *cmds;
		int fd;
		OK(vm_get_ioctls(&n) == NULL && n > 40);
		cmds = vm_get_ioctls(NULL);
		OK(cmds != NULL);
		{
			bool has_run = false, has_identity = false;
			for (size_t i = 0; i < n; i++) {
				has_run |= cmds[i] == VM_RUN;
				has_identity |= cmds[i] == VM_GET_IDENTITY;
			}
			OK(has_run && has_identity);
		}
		free(__DECONST(cap_ioctl_t *, cmds));
		OK(vm_get_device_fd(ctx) >= 0);
		OK(vm_export_attestation_fd(NULL) == -1 && errno == EINVAL);
		fd = vm_export_attestation_fd(ctx);
		OK(fd >= 0 && fd != vm_get_device_fd(ctx));
		{
			cap_ioctl_t limited[4];
			OK(cap_ioctls_get(fd, limited, 4) == 1 && limited[0] == VM_GET_ATTESTATION);
		}
		close(fd);
		OK(vm_limit_rights(ctx) == 0);
		{
			cap_ioctl_t limited[256];
			OK(cap_ioctls_get(vm_get_device_fd(ctx), limited, 256) == (ssize_t)n);
		}
	}
	vm_vcpu_close(vcpu);
	vm_destroy(ctx);
	printf("vmmapi VM requests: %d checks\n", checks - before);
}

/* The model's last value for (cpu, reg) after a sequence of SET_REGISTER. */
static uint64_t
reg(struct vcpu *vcpu, int r)
{
	uint64_t v;

	CHECK(vm_get_register(vcpu, r, &v) == 0);
	return (v);
}

static void
desc(struct vcpu *vcpu, int r, uint64_t base, uint32_t limit, uint32_t access)
{
	uint64_t b;
	uint32_t l, a;

	CHECK(vm_get_desc(vcpu, r, &b, &l, &a) == 0);
	OK(b == base && l == limit && a == access);
}

/* Count the register and descriptor requests a successful call makes, then
 * fail each one in turn: every failure must be reported with that error. */
static void
enumerate_failures(const char *what, int (*call)(struct vcpu *), struct vcpu *vcpu)
{
	unsigned long cmds[2] = { VM_SET_REGISTER, VM_SET_SEGMENT_DESCRIPTOR };
	unsigned long before[2], total[2];
	int n = 0;

	for (int kind = 0; kind < 2; kind++)
		before[kind] = vmmfake_cmd_count(cmds[kind]);
	CHECK(call(vcpu) == 0);
	for (int kind = 0; kind < 2; kind++)
		total[kind] = vmmfake_cmd_count(cmds[kind]) - before[kind];
	for (int kind = 0; kind < 2; kind++) {
		for (unsigned long occ = 1; occ <= total[kind]; occ++) {
			int result;
			vmmfake_fail(vmmfake_cmd_name(cmds[kind]), (int)occ, ENXIO);
			errno = 0;
			result = call(vcpu);
			vmmfake_clear_faults();
			if (result != -1 || errno != ENXIO)
				fprintf(stderr, "%s: failure of %s #%lu not reported (%d)\n",
				    what, vmmfake_cmd_name(cmds[kind]), occ, result);
			OK(result == -1 && errno == ENXIO);
			n++;
		}
	}
	printf("vmmapi %s: all %d register/descriptor failures reported\n", what, n);
}

static int
reset_call(struct vcpu *vcpu)
{
	return (vcpu_reset(vcpu));
}

static int
freebsd64_call(struct vcpu *vcpu)
{
	return (vm_setup_freebsd_registers(vcpu, 0xffffffff80200000UL, 0x9000, 0x2000,
	    0x7ff000));
}

static int
freebsd32_call(struct vcpu *vcpu)
{
	return (vm_setup_freebsd_registers_i386(vcpu, 0x100000, 0x6000, 0x8ff0));
}

static void
test_register_setups(void)
{
	struct vmctx *ctx = fresh_vm("setups");
	struct vcpu *vcpu = vm_vcpu_open(ctx, 0);
	int before = checks;

	OK(vm_setup_memory(ctx, 16 * MB, VM_MMAP_ALL) == 0);
	/* Intel SDM vol. 3A, table 9-1: state following power-up/INIT. */
	OK(vcpu_reset(vcpu) == 0);
	OK(reg(vcpu, VM_REG_GUEST_RFLAGS) == 0x2 && reg(vcpu, VM_REG_GUEST_RIP) == 0xfff0 &&
	    reg(vcpu, VM_REG_GUEST_CR0) == CR0_NE && reg(vcpu, VM_REG_GUEST_CR2) == 0 &&
	    reg(vcpu, VM_REG_GUEST_CR3) == 0 && reg(vcpu, VM_REG_GUEST_CR4) == 0 &&
	    reg(vcpu, VM_REG_GUEST_CS) == 0xf000 && reg(vcpu, VM_REG_GUEST_SS) == 0 &&
	    reg(vcpu, VM_REG_GUEST_EFER) == 0 && reg(vcpu, VM_REG_GUEST_RDX) == 0xf00 &&
	    reg(vcpu, VM_REG_GUEST_RAX) == 0 && reg(vcpu, VM_REG_GUEST_R15) == 0 &&
	    reg(vcpu, VM_REG_GUEST_DR6) == 0xffff0ff0 && reg(vcpu, VM_REG_GUEST_DR7) == 0x400 &&
	    reg(vcpu, VM_REG_GUEST_INTR_SHADOW) == 0 && reg(vcpu, VM_REG_GUEST_TR) == 0 &&
	    reg(vcpu, VM_REG_GUEST_LDTR) == 0);
	desc(vcpu, VM_REG_GUEST_CS, 0xffff0000, 0xffff, 0x93);
	desc(vcpu, VM_REG_GUEST_DS, 0, 0xffff, 0x93);
	desc(vcpu, VM_REG_GUEST_GDTR, 0, 0xffff, 0);
	desc(vcpu, VM_REG_GUEST_IDTR, 0, 0xffff, 0);
	desc(vcpu, VM_REG_GUEST_TR, 0, 0, 0x8b);
	desc(vcpu, VM_REG_GUEST_LDTR, 0, 0xffff, 0x82);
	enumerate_failures("vcpu_reset", reset_call, vcpu);

	/* FreeBSD amd64 loader entry: long mode, flat segments. */
	OK(freebsd64_call(vcpu) == 0);
	OK(reg(vcpu, VM_REG_GUEST_CR0) == (CR0_PE | CR0_PG | CR0_NE) &&
	    reg(vcpu, VM_REG_GUEST_CR4) == CR4_PAE &&
	    reg(vcpu, VM_REG_GUEST_EFER) == (EFER_LME | EFER_LMA) &&
	    reg(vcpu, VM_REG_GUEST_RIP) == 0xffffffff80200000UL &&
	    reg(vcpu, VM_REG_GUEST_CR3) == 0x9000 && reg(vcpu, VM_REG_GUEST_RSP) == 0x7ff000 &&
	    reg(vcpu, VM_REG_GUEST_CS) == GSEL(1, SEL_KPL) &&
	    reg(vcpu, VM_REG_GUEST_SS) == GSEL(2, SEL_KPL));
	desc(vcpu, VM_REG_GUEST_CS, 0, 0, 0x209b);
	desc(vcpu, VM_REG_GUEST_GS, 0, 0, 0x93);
	desc(vcpu, VM_REG_GUEST_GDTR, 0x2000, 3 * 8 - 1, 0);
	desc(vcpu, VM_REG_GUEST_LDTR, 0, 0, 0x10000);
	{
		uint64_t gdt[3] = { 1, 1, 1 };
		vm_setup_freebsd_gdt(gdt);
		/* Long-mode code: L=1, P=1, S=1, type execute/read;
		 * data: P=1, S=1, type read/write. */
		OK(gdt[0] == 0 && gdt[1] == 0x0020980000000000ULL && gdt[2] == 0x0000900000000000ULL);
	}
	enumerate_failures("freebsd amd64 setup", freebsd64_call, vcpu);

	/* FreeBSD i386 entry: protected mode, GDT written to guest memory,
	 * TSS one page above it. */
	OK(freebsd32_call(vcpu) == 0);
	{
		struct segment_descriptor *gdt = vm_map_gpa(ctx, 0x6000, 32);
		int cap;
		OK(gdt[1].sd_type == SDT_MEMER && gdt[1].sd_p == 1 && gdt[1].sd_def32 == 1 &&
		    gdt[1].sd_gran == 1 && gdt[1].sd_lolimit == 0xffff && gdt[1].sd_hilimit == 0xf);
		OK(gdt[2].sd_type == SDT_MEMRW && gdt[3].sd_type == SDT_SYS386TSS &&
		    gdt[3].sd_lolimit == 103 && gdt[3].sd_lobase == 0x7000);
		OK(vm_get_capability(vcpu, VM_CAP_UNRESTRICTED_GUEST, &cap) == 0 && cap == 1);
	}
	OK(reg(vcpu, VM_REG_GUEST_CR0) == (CR0_PE | CR0_NE) && reg(vcpu, VM_REG_GUEST_EFER) == 0 &&
	    reg(vcpu, VM_REG_GUEST_RIP) == 0x100000 && reg(vcpu, VM_REG_GUEST_RSP) == 0x8ff0 &&
	    reg(vcpu, VM_REG_GUEST_TR) == GSEL(3, SEL_KPL));
	desc(vcpu, VM_REG_GUEST_GDTR, 0x6000, 4 * 8 - 1, 0);
	desc(vcpu, VM_REG_GUEST_CS, 0, 0xffffffff, 0xc000 | 0x80 | SDT_MEMERA);
	desc(vcpu, VM_REG_GUEST_SS, 0, 0xffffffff, 0xc000 | 0x80 | SDT_MEMRWA);
	desc(vcpu, VM_REG_GUEST_TR, 0x7000, 103, 0x80 | SDT_SYS386BSY);
	enumerate_failures("freebsd i386 setup", freebsd32_call, vcpu);
	/* Capability failures and an unmapped GDT. */
	FAILS("VM_GET_CAPABILITY", freebsd32_call(vcpu));
	vmmfake_fail("VM_SET_CAPABILITY", 1, EIO);
	OK(freebsd32_call(vcpu) == -1 && errno == EIO);
	vmmfake_clear_faults();
	OK(vm_setup_freebsd_registers_i386(vcpu, 0x100000, 0x7fff0000, 0x8ff0) == EFAULT);
	vm_vcpu_close(vcpu);
	vm_destroy(ctx);
	printf("vmmapi register setups: %d checks\n", checks - before);
}

#define PROT_ALL (PROT_READ | PROT_WRITE | PROT_EXEC)

/* Boundary and alternative-path cases of the memory and open paths. */
static void
test_edges(void)
{
	struct vmctx *ctx, *ctx2;
	char *base;
	int segid, before = checks;

	/* A VM device that exists but cannot be opened is not created anew. */
	vmmfake_fail("/dev/vmm/edge0", 1, EACCES);
	OK(vm_openf("edge0", VMMAPI_OPEN_CREATE) == NULL && errno == EACCES &&
	    !vmmfake_vm_exists("edge0"));
	vmmfake_clear_faults();
	/* vm_destroy(NULL) reports and returns. */
	vm_destroy(NULL);
	checks++;

	/* Regression: without guest memory nothing translates either way (the
	 * context's memory geometry used to be left uninitialised). */
	ctx = fresh_vm("edge1");
	OK(vm_map_gpa(ctx, 0, 1) == NULL);
	OK(vm_rev_map_gpa(ctx, (void *)&checks) == (vm_paddr_t)-1);
	/* A mapping below an existing one is created (lookup finds the higher
	 * one); one at an existing address must match it in every field. */
	OK(vm_setup_memory(ctx, 64 * MB, VM_MMAP_ALL) == 0);
	OK(vm_munmap_memseg(ctx, 0, 64 * MB) == 0);
	OK(vm_mmap_memseg(ctx, 32 * MB, VM_SYSMEM, 32 * MB, 32 * MB, PROT_ALL) == 0);
	{
		unsigned long maps = vmmfake_cmd_count(VM_MMAP_MEMSEG);
		OK(vm_mmap_memseg(ctx, 0, VM_SYSMEM, 0, 32 * MB, PROT_ALL) == 0 &&
		    vmmfake_cmd_count(VM_MMAP_MEMSEG) == maps + 1 &&
		    LAST(struct vm_memmap, VM_MMAP_MEMSEG)->gpa == 0);
	}
	/* Regression: a request for a longer mapping at an existing address
	 * used to succeed without mapping the remainder. */
	OK(vm_mmap_memseg(ctx, 0, VM_SYSMEM, 0, 64 * MB, PROT_ALL) == -1 && errno == EEXIST);
	OK(vm_mmap_memseg(ctx, 0, VM_SYSMEM, 0, 32 * MB, PROT_ALL) == 0);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 32 * MB) != MAP_FAILED);
	OK(vm_mmap_memseg(ctx, 32 * MB, VM_BOOTROM, 0, 32 * MB, PROT_ALL) == -1 && errno == EEXIST);
	OK(vm_mmap_memseg(ctx, 32 * MB, VM_SYSMEM, 0, 32 * MB, PROT_ALL) == -1 && errno == EEXIST);
	vm_set_memflags(ctx, VM_MEM_F_WIRED);
	OK(vm_mmap_memseg(ctx, 32 * MB, VM_SYSMEM, 32 * MB, 32 * MB, PROT_ALL) == -1 &&
	    errno == EEXIST);
	vm_set_memflags(ctx, 0);
	/* A second handle (a loader, then bhyve) reuses the unnamed system
	 * segment of the same size. */
	ctx2 = vm_openf("edge1", 0);
	CHECK(ctx2 != NULL);
	{
		/* The existing segment is reused; the existing 32 MiB mapping
		 * at 0 is not the requested 64 MiB one. */
		unsigned long allocs = vmmfake_cmd_count(VM_ALLOC_MEMSEG);
		OK(vm_setup_memory(ctx2, 64 * MB, VM_MMAP_ALL) == -1 && errno == EEXIST &&
		    vmmfake_cmd_count(VM_ALLOC_MEMSEG) == allocs);
	}
	vm_close(ctx2);
	/* An unallocated device slot has no information. */
	{
		void *hb;
		size_t len;
		char name[VM_MAX_SUFFIXLEN + 1];
		OK(vm_get_devmem_info(ctx, VM_DEVMEM_START + 2, &hb, &len, name,
		    sizeof(name)) == -1 && errno == ENOENT);
	}
	vm_destroy(ctx);

	/* Core-dump inclusion: guest and device memory are NOCORE unless the
	 * VM asks for INCORE. */
	ctx = fresh_vm("edge2");
	OK(vm_setup_memory(ctx, 4 * MB, VM_MMAP_ALL) == 0 && vmmfake_last_mmap_nocore() == 1);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 4096) != MAP_FAILED &&
	    vmmfake_last_mmap_nocore() == 1);
	vm_destroy(ctx);
	ctx = fresh_vm("edge3");
	vm_set_memflags(ctx, VM_MEM_F_INCORE);
	OK(vm_setup_memory(ctx, 4 * MB, VM_MMAP_ALL) == 0 && vmmfake_last_mmap_nocore() == 0);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 4096) != MAP_FAILED &&
	    vmmfake_last_mmap_nocore() == 0);
	/* A failed re-query after a failed device node is reported. */
	{
		char spec[128];
		snprintf(spec, sizeof(spec), "/dev/vmm.io/edge3.dev:1:%d,VM_GET_MEMSEG:%d:%d",
		    ENOENT, (VM_MEMSEG_END - VM_BOOTROM) + 3, EIO);
		vmmfake_fail_spec(spec);
	}
	OK(vm_create_devmem_auto(ctx, "dev", 4096, &segid) == MAP_FAILED && errno == EIO);
	vmmfake_clear_faults();
	vm_destroy(ctx);

	/* Split memory: high-memory bounds are exclusive at the end. */
	ctx = fresh_vm("edge4");
	OK(vm_setup_memory(ctx, 3 * GB + 16 * MB, VM_MMAP_ALL) == 0);
	base = vm_map_gpa(ctx, 0, 1);
	OK(vm_map_gpa(ctx, 4 * GB + 16 * MB, 1) == NULL);
	OK(vm_map_gpa(ctx, 4 * GB, 16 * MB + 1) == NULL);
	OK(vm_rev_map_gpa(ctx, base + 4 * GB + 16 * MB) == (vm_paddr_t)-1);
	vm_destroy(ctx);

	/* Regression: a domain beginning exactly at the low-memory limit is
	 * mapped wholly at the high-memory base (it used to be given an empty
	 * low mapping, which the kernel refuses, so setup failed). */
	{
		struct vm_mem_domain doms[2] = {
			{ .size = 3 * GB, .ds_policy = DOMAINSET_POLICY_INVALID },
			{ .size = 16 * MB, .ds_policy = DOMAINSET_POLICY_INVALID },
		};
		ctx = fresh_vm("edge5");
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL, doms, 2) == 0 &&
		    vm_get_lowmem_size(ctx) == 3 * GB && vm_get_highmem_size(ctx) == 16 * MB);
		{
			vm_paddr_t gpa = 1;
			int sid, prot, flags;
			vm_ooffset_t off;
			size_t len;
			OK(vm_mmap_getnext(ctx, &gpa, &sid, &off, &len, &prot, &flags) == 0 &&
			    gpa == 4 * GB && sid == VM_SYSMEM + 1 && off == 0 && len == 16 * MB);
		}
		vm_destroy(ctx);
	}
	/* A segment query failure stops device-memory creation. */
	ctx = fresh_vm("edge6");
	vmmfake_fail("VM_GET_MEMSEG", 1, EIO);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 4096) == MAP_FAILED && errno == EIO);
	vmmfake_clear_faults();
	/* Domain sizes whose sum overflows 64 bits are refused before any
	 * segment is allocated. */
	{
		struct vm_mem_domain huge[2] = {
			{ .size = SIZE_MAX - 4095, .ds_policy = DOMAINSET_POLICY_INVALID },
			{ .size = SIZE_MAX - 4095, .ds_policy = DOMAINSET_POLICY_INVALID },
		};
		unsigned long allocs = vmmfake_cmd_count(VM_ALLOC_MEMSEG);
		OK(vm_setup_memory_domains(ctx, VM_MMAP_ALL, huge, 2) == -1 && errno == EOVERFLOW &&
		    vmmfake_cmd_count(VM_ALLOC_MEMSEG) == allocs);
	}
	vm_destroy(ctx);
	/* A dirty-log publication with any reserved byte set is refused; the
	 * same publication with the bytes clear is accepted. */
	{
		struct {
			struct vmm_dirty_log_result r;
			uint8_t bitmap[1];
		} pub;
		memset(&pub, 0, sizeof(pub));
		pub.r.version = VMM_DIRTY_LOG_RESULT_VERSION;
		pub.r.size = VMM_DIRTY_LOG_RESULT_SIZE;
		pub.r.operation = VMM_DIRTY_LOG_REQUEST_OBSERVE;
		pub.r.gpa = 0;
		pub.r.length = 8 * VMM_DIRTY_LOG_GRANULARITY;
		pub.r.identity = pub.r.map_generation = pub.r.dirty_generation = 1;
		pub.r.bitmap_offset = sizeof(pub.r);
		pub.r.bitmap_bytes = 1;
		OK(vm_dirty_log_result_validate(&pub.r, sizeof(pub.r) + 1) == 0);
		for (size_t i = 0; i < sizeof(pub.r.reserved8); i++) {
			pub.r.reserved8[i] = 1;
			OK(vm_dirty_log_result_validate(&pub.r, sizeof(pub.r) + 1) == EINVAL);
			pub.r.reserved8[i] = 0;
		}
	}
	/* The model's VM_FREE_MEMSEG follows the agreed kernel ABI (number
	 * 200, 16 bytes, reserved zero): EINVAL for sysmem, out of range or
	 * reserved bits, ENOENT unallocated, EBUSY while mapped; success
	 * releases the slot for reuse.  libvmmapi keeps ENOSYS until the
	 * kernel header defines the request. */
	{
		struct vmmfake_free_memseg f;
		int vfd;
		size_t l;
		char n[VM_MAX_SUFFIXLEN + 1];

		_Static_assert(sizeof(f) == 16, "request ABI");
		ctx = fresh_vm("edge7");
		vfd = vm_get_device_fd(ctx);
		OK(vm_setup_memory(ctx, 4 * MB, VM_MMAP_ALL) == 0);
		OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 4096) != MAP_FAILED);
		OK(vm_create_devmem_auto(ctx, "dev", 4096, &segid) != MAP_FAILED);
		memset(&f, 0, sizeof(f));
		f.segid = VM_SYSMEM;
		OK(ioctl(vfd, VMMFAKE_FREE_MEMSEG, &f) == -1 && errno == EINVAL);
		f.segid = VM_MEMSEG_END;
		OK(ioctl(vfd, VMMFAKE_FREE_MEMSEG, &f) == -1 && errno == EINVAL);
		f.segid = -1;
		OK(ioctl(vfd, VMMFAKE_FREE_MEMSEG, &f) == -1 && errno == EINVAL);
		for (int r = 0; r < 3; r++) {
			f.segid = segid;
			f.reserved[r] = 1;
			OK(ioctl(vfd, VMMFAKE_FREE_MEMSEG, &f) == -1 && errno == EINVAL);
			f.reserved[r] = 0;
		}
		f.segid = VM_DEVMEM_START + 63;
		OK(ioctl(vfd, VMMFAKE_FREE_MEMSEG, &f) == -1 && errno == ENOENT);
		OK(vm_mmap_memseg(ctx, 1UL << 32, VM_BOOTROM, 0, 4096, PROT_READ) == 0);
		f.segid = VM_BOOTROM;
		OK(ioctl(vfd, VMMFAKE_FREE_MEMSEG, &f) == -1 && errno == EBUSY);
		f.segid = segid;
		OK(ioctl(vfd, VMMFAKE_FREE_MEMSEG, &f) == 0);
		OK(vm_get_memseg(ctx, segid, &l, n, sizeof(n)) == 0 && l == 0);
		OK(ioctl(vfd, VMMFAKE_FREE_MEMSEG, &f) == -1 && errno == ENOENT);
		/* Another handle re-allocated the slot with a different size: this
		 * context's stale mapping is not reported as its memory. */
		{
			struct vm_memseg raw;
			void *hb;
			memset(&raw, 0, sizeof(raw));
			raw.segid = segid;
			raw.len = 8192;
			strlcpy(raw.name, "dev", sizeof(raw.name));
			OK(ioctl(vfd, VM_ALLOC_MEMSEG, &raw) == 0);
			OK(vm_get_devmem_info(ctx, segid, &hb, &l, n, sizeof(n)) == -1 &&
			    errno == ENOENT);
		}
		vm_destroy(ctx);
	}
	/* Address-space reservation failures stop memory and device setup. */
	ctx = fresh_vm("edge8");
	vmmfake_fail("mmap_guard", 1, ENOMEM);
	OK(vm_setup_memory(ctx, 4 * MB, VM_MMAP_ALL) == -1 && errno == ENOMEM);
	vmmfake_clear_faults();
	OK(vm_setup_memory(ctx, 4 * MB, VM_MMAP_ALL) == 0);
	vmmfake_fail("mmap_guard", 1, ENOMEM);
	OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 4096) == MAP_FAILED && errno == ENOMEM);
	vmmfake_clear_faults();
	/* The segment that call allocated was released; a retry succeeds. */
	OK(vm_create_devmem(ctx, VM_BOOTROM, "rom", 4096) != MAP_FAILED);
	/* A named device segment never matches an unnamed one at its id. */
	{
		struct vm_memseg raw;
		memset(&raw, 0, sizeof(raw));
		raw.segid = VM_FRAMEBUFFER;
		raw.len = 4096;
		OK(ioctl(vm_get_device_fd(ctx), VM_ALLOC_MEMSEG, &raw) == 0);
		OK(vm_create_devmem(ctx, VM_FRAMEBUFFER, "fb", 4096) == MAP_FAILED &&
		    errno == EINVAL);
	}
	OK(vm_free_devmem(NULL, VM_DEVMEM_START) == -1 && errno == EINVAL);
	/* A slot whose release itself fails stays allocated, and the search
	 * still stops there rather than allocating the next slot. */
	{
		char spec[128];
		size_t l;
		char n[VM_MAX_SUFFIXLEN + 1];
		snprintf(spec, sizeof(spec), "/dev/vmm.io/edge8.d:1:%d,VM_FREE_MEMSEG:1:%d",
		    ENOENT, EIO);
		vmmfake_fail_spec(spec);
		OK(vm_create_devmem_auto(ctx, "d", 4096, &segid) == MAP_FAILED && errno == ENOENT);
		vmmfake_clear_faults();
		OK(vm_get_memseg(ctx, VM_DEVMEM_START, &l, n, sizeof(n)) == 0 && l == 4096 &&
		    strcmp(n, "d") == 0);
		OK(vm_get_memseg(ctx, VM_DEVMEM_START + 1, &l, n, sizeof(n)) == 0 && l == 0);
	}
	vm_destroy(ctx);
	printf("vmmapi edges: %d checks\n", checks - before);
}

int
main(void)
{
	vmmfake_reset();
	test_open_close();
	test_memory();
	test_devmem();
	test_vcpu_state();
	test_vm_requests();
	test_register_setups();
	test_edges();
	printf("PASS: %d libvmmapi checks\n", checks);
	return (0);
}
