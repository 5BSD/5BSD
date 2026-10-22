/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Test-only user-space model of the vmm(4) control and VM devices, loaded
 * with LD_PRELOAD (or linked first) in front of the ACTUAL libvmmapi.  It
 * interposes open(2)/openat(2), close(2), ioctl(2), mmap(2), fcntl(2),
 * modfind(2) and kldload(2) for the vmm device paths only, so the library
 * and bhyvectl run unmodified while no request reaches the kernel:
 *
 *   - /dev/vmmctl, /dev/vmm/NAME, /dev/vmm.io/NAME.SEG and /dev/mem are never
 *     opened for real; they become anonymous shared-memory descriptors which
 *     this model owns;
 *   - an ioctl in the vmm groups ('v', 'V') on any other descriptor fails
 *     with EBADF instead of being forwarded;
 *   - kldload(2) is never called and modfind("vmm") reports the module.
 *
 * The model keeps per-VM state (VMs by name with identity, memory segments
 * and mappings, registers, segment descriptors, capabilities, x2APIC state,
 * interrupt info, CPU sets, topology, RTC, statistics) with the kernel's
 * documented semantics, records every ioctl (command and the input bytes the
 * library supplied) and can fail the Nth instance of any named operation.
 * VMMFAKE_STATE=path persists the model between processes so a sequence of
 * bhyvectl invocations observes one VM.  VMMFAKE_LOG=path appends one line
 * per request.  VMMFAKE_FAIL=name:occurrence:errno[,...] injects failures.
 */
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/time.h>

#include <sys/domainset.h>
#include <vm/vm.h>
#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>
#include <machine/vmm_dev.h>
#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_mem.h>
#include <sys/hypertrace.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bhyve-cov-vmmfake.h"
#include "bhyve-cov-free-memseg.h"

#define MAXVMS	16
#define MAXREGS	1024
#define NCPU	8
#define NSTATS	70

enum fdkind { FK_NONE, FK_CTL, FK_VM, FK_DEVMEM, FK_MEM };
struct fakefd {
	enum fdkind kind;
	int vm;
	int seg;
};

struct regent {
	int cpu;
	int reg;
	uint64_t val;
};

struct fakevm {
	bool used;
	char name[VM_MAX_NAMELEN + 1];
	uint16_t vmid;
	uint64_t epoch;
	uint32_t create_flags;
	struct { size_t len; char name[VM_MAX_SUFFIXLEN + 1]; } segs[VM_MAX_MEMSEGS];
	struct vm_memmap maps[VM_MAX_MEMMAPS];
	int nmaps;
	struct regent regs[MAXREGS];
	int nregs;
	struct { bool set; struct seg_desc d; } descs[NCPU][VM_REG_LAST];
	int caps[NCPU][VM_CAP_MAX];
	bool capset[NCPU][VM_CAP_MAX];
	int x2apic[NCPU];
	uint64_t intinfo[NCPU];
	uint64_t active, suspended, debug;
	struct vm_cpu_topology topology;
	uint8_t nvram[128];
	time_t rtc;
	int suspend_how;
	int run_count;
	int reinit_count;
	int restore_time_count;
	uint64_t snapshot_session;
};

struct model {
	uint32_t magic;
	struct fakevm vms[MAXVMS];
	uint16_t next_vmid;
	int run_exitcode;	/* VM_EXITCODE_* reported by VM_RUN */
};

static struct model m;
static struct fakefd fds[4096];
static struct vmmfake_record ring[VMMFAKE_RING];
static unsigned long nrecords;
static struct { char name[48]; int occurrence; int error; int seen; } faults[16];
static int nfaults;
static int (*real_open)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_close)(int);
static int (*real_ioctl)(int, unsigned long, ...);
static void *(*real_mmap)(void *, size_t, int, int, int, off_t);
static int (*real_fcntl)(int, int, ...);
static const char *state_path, *log_path;

#define	CMD(x) { x, #x }
static const struct { unsigned long cmd; const char *name; } names[] = {
	CMD(VMMCTL_VM_CREATE), CMD(VMMCTL_VM_DESTROY), CMD(VMMCTL_VM_DESTROY_IDENTITY),
	CMD(VM_RUN), CMD(VM_SUSPEND), CMD(VM_REINIT), CMD(VM_ALLOC_MEMSEG),
	CMD(VM_GET_MEMSEG), CMD(VM_MMAP_MEMSEG), CMD(VM_MMAP_GETNEXT),
	{ VMMFAKE_FREE_MEMSEG, "VM_FREE_MEMSEG" },
	CMD(VM_MUNMAP_MEMSEG), CMD(VM_SET_REGISTER), CMD(VM_GET_REGISTER),
	CMD(VM_SET_SEGMENT_DESCRIPTOR), CMD(VM_GET_SEGMENT_DESCRIPTOR),
	CMD(VM_SET_REGISTER_SET), CMD(VM_GET_REGISTER_SET), CMD(VM_SET_KERNEMU_DEV),
	CMD(VM_GET_KERNEMU_DEV), CMD(VM_INJECT_EXCEPTION), CMD(VM_LAPIC_IRQ),
	CMD(VM_LAPIC_LOCAL_IRQ), CMD(VM_LAPIC_MSI), CMD(VM_IOAPIC_ASSERT_IRQ),
	CMD(VM_IOAPIC_DEASSERT_IRQ), CMD(VM_IOAPIC_PULSE_IRQ), CMD(VM_IOAPIC_PINCOUNT),
	CMD(VM_ISA_ASSERT_IRQ), CMD(VM_ISA_DEASSERT_IRQ), CMD(VM_ISA_PULSE_IRQ),
	CMD(VM_ISA_SET_IRQ_TRIGGER), CMD(VM_SET_CAPABILITY), CMD(VM_GET_CAPABILITY),
	CMD(VM_BIND_PPTDEV), CMD(VM_UNBIND_PPTDEV), CMD(VM_MAP_PPTDEV_MMIO),
	CMD(VM_PPTDEV_MSI), CMD(VM_PPTDEV_MSIX), CMD(VM_PPTDEV_DISABLE_MSIX),
	CMD(VM_UNMAP_PPTDEV_MMIO), CMD(VM_RESET_PPTDEV), CMD(VM_INJECT_NMI),
	CMD(VM_STATS), CMD(VM_STAT_DESC), CMD(VM_SET_X2APIC_STATE),
	CMD(VM_GET_X2APIC_STATE), CMD(VM_GET_HPET_CAPABILITIES), CMD(VM_GET_GPA_PMAP),
	CMD(VM_GLA2GPA), CMD(VM_GLA2GPA_NOFAULT), CMD(VM_ACTIVATE_CPU),
	CMD(VM_GET_CPUS), CMD(VM_SUSPEND_CPU), CMD(VM_RESUME_CPU), CMD(VM_SET_INTINFO),
	CMD(VM_GET_INTINFO), CMD(VM_RTC_WRITE), CMD(VM_RTC_READ), CMD(VM_RTC_SETTIME),
	CMD(VM_RTC_GETTIME), CMD(VM_RESTART_INSTRUCTION), CMD(VM_SET_TOPOLOGY),
	CMD(VM_GET_TOPOLOGY), CMD(VM_SNAPSHOT_REQ), CMD(VM_SNAPSHOT_SESSION),
	CMD(VM_RESTORE_TIME), CMD(VM_GET_IDENTIFIER), CMD(VM_GET_IDENTITY),
	CMD(VM_GET_ATTESTATION), CMD(VM_GET_CPUID), CMD(VM_GET_CPU_COMPAT),
	CMD(VM_STARTUP_REQUEST), CMD(VM_RUN_GENERATION), CMD(VM_DIRTY_LOG_REQUEST),
#ifdef VM_GET_RUN_WITNESS
	CMD(VM_GET_RUN_WITNESS),
#endif
};

const char *
vmmfake_cmd_name(unsigned long cmd)
{
	static char buf[32];

	for (size_t i = 0; i < nitems(names); i++)
		if (names[i].cmd == cmd)
			return (names[i].name);
	snprintf(buf, sizeof(buf), "cmd-%#lx", cmd);
	return (buf);
}

/* ------------------------------------------------------------ setup */
static void
resolve(void)
{
	if (real_open != NULL)
		return;
	real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
	real_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");
	real_close = (int (*)(int))dlsym(RTLD_NEXT, "close");
	real_ioctl = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
	real_mmap = (void *(*)(void *, size_t, int, int, int, off_t))dlsym(RTLD_NEXT, "mmap");
	real_fcntl = (int (*)(int, int, ...))dlsym(RTLD_NEXT, "fcntl");
	if (real_open == NULL || real_openat == NULL || real_close == NULL ||
	    real_ioctl == NULL || real_mmap == NULL || real_fcntl == NULL)
		abort();
}

static void
parse_faults(const char *spec)
{
	char copy[512], *word, *save;

	nfaults = 0;
	if (spec == NULL)
		return;
	strlcpy(copy, spec, sizeof(copy));
	for (word = strtok_r(copy, ",", &save); word != NULL && nfaults < 16;
	    word = strtok_r(NULL, ",", &save)) {
		char *a = strchr(word, ':'), *b;
		if (a == NULL || (b = strchr(a + 1, ':')) == NULL)
			abort();
		*a = *b = '\0';
		strlcpy(faults[nfaults].name, word, sizeof(faults[0].name));
		faults[nfaults].occurrence = atoi(a + 1);
		faults[nfaults].error = atoi(b + 1);
		faults[nfaults].seen = 0;
		nfaults++;
	}
}

void
vmmfake_fail(const char *name, int occurrence, int error)
{
	char spec[128];

	snprintf(spec, sizeof(spec), "%s:%d:%d", name, occurrence, error);
	parse_faults(spec);
}

/* Replace the injected faults with SPEC (name:occurrence:errno[,...]). */
void
vmmfake_fail_spec(const char *spec)
{
	parse_faults(spec);
}

static char preempt_name[64];
static int last_mmap_nocore = -1;
int
vmmfake_last_mmap_nocore(void)
{
	return (last_mmap_nocore);
}

void
vmmfake_preempt_next_alloc(const char *name)
{
	strlcpy(preempt_name, name, sizeof(preempt_name));
}

void
vmmfake_clear_faults(void)
{
	nfaults = 0;
}

static int
fault(const char *name)
{
	for (int i = 0; i < nfaults; i++)
		if (strcmp(faults[i].name, name) == 0 &&
		    ++faults[i].seen == faults[i].occurrence)
			return (faults[i].error);
	return (0);
}

static void
save(void)
{
	int fd;

	if (state_path == NULL)
		return;
	fd = real_open(state_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || write(fd, &m, sizeof(m)) != (ssize_t)sizeof(m))
		abort();
	real_close(fd);
}

void
vmmfake_reset(void)
{
	memset(&m, 0, sizeof(m));
	m.magic = 0x766d6d66;
	m.next_vmid = 3;
	m.run_exitcode = VM_EXITCODE_INOUT;
	nrecords = 0;
	save();
}

__attribute__((constructor)) static void
vmmfake_init(void)
{
	int fd;

	resolve();
	state_path = getenv("VMMFAKE_STATE");
	log_path = getenv("VMMFAKE_LOG");
	parse_faults(getenv("VMMFAKE_FAIL"));
	if (state_path != NULL &&
	    (fd = real_open(state_path, O_RDONLY | O_CLOEXEC)) >= 0) {
		if (read(fd, &m, sizeof(m)) != (ssize_t)sizeof(m) ||
		    m.magic != 0x766d6d66)
			abort();
		real_close(fd);
	} else {
		vmmfake_reset();
	}
	if (getenv("VMMFAKE_EXITCODE") != NULL)
		m.run_exitcode = atoi(getenv("VMMFAKE_EXITCODE"));
}

static void
note(const char *fmt, ...)
{
	char line[256];
	va_list ap;
	int fd, n;

	if (log_path == NULL)
		return;
	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n > sizeof(line) - 2)
		n = sizeof(line) - 2;
	line[n++] = '\n';
	fd = real_open(log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (fd >= 0) {
		(void)write(fd, line, (size_t)n);
		real_close(fd);
	}
}

/* ----------------------------------------------------- descriptors */
static int
new_fd(enum fdkind kind, int vm, int seg, size_t size)
{
	int fd = memfd_create("vmmfake", MFD_CLOEXEC);

	if (fd < 0 || fd >= (int)nitems(fds))
		abort();
	if (size != 0 && ftruncate(fd, (off_t)size) != 0)
		abort();
	fds[fd] = (struct fakefd){ kind, vm, seg };
	return (fd);
}

static struct fakefd *
lookup_fd(int fd)
{
	if (fd < 0 || fd >= (int)nitems(fds) || fds[fd].kind == FK_NONE)
		return (NULL);
	return (&fds[fd]);
}

static int
find_vm(const char *name)
{
	for (int i = 0; i < MAXVMS; i++)
		if (m.vms[i].used && strcmp(m.vms[i].name, name) == 0)
			return (i);
	return (-1);
}

int
vmmfake_vm_exists(const char *name)
{
	return (find_vm(name) >= 0);
}

static bool
vmm_path(const char *path)
{
	return (strncmp(path, "/dev/vmm", 8) == 0 || strcmp(path, "/dev/mem") == 0);
}

static int
fake_open(const char *path)
{
	const char *name;
	int vm, error;

	if ((error = fault(path)) != 0 || (error = fault("open")) != 0) {
		errno = error;
		return (-1);
	}
	note("open %s", path);
	if (strcmp(path, "/dev/vmmctl") == 0)
		return (new_fd(FK_CTL, -1, -1, 0));
	if (strcmp(path, "/dev/mem") == 0) {
		/* An MSR permission bitmap: all accesses intercepted (bits
		 * set) except the bytes VMMFAKE_MEM=off=val,... clears. */
		int fd = new_fd(FK_MEM, -1, -1, 4 * PAGE_SIZE);
		uint8_t page[4 * PAGE_SIZE];
		const char *spec = getenv("VMMFAKE_MEM");
		memset(page, 0xff, sizeof(page));
		while (spec != NULL && *spec != '\0') {
			char *end;
			unsigned long off = strtoul(spec, &end, 0);
			if (*end != '=' || off >= sizeof(page))
				abort();
			page[off] = (uint8_t)strtoul(end + 1, &end, 0);
			spec = *end == ',' ? end + 1 : NULL;
		}
		if (pwrite(fd, page, sizeof(page), 0) != (ssize_t)sizeof(page))
			abort();
		return (fd);
	}
	if (strncmp(path, "/dev/vmm/", 9) == 0) {
		name = path + 9;
		if ((vm = find_vm(name)) < 0) {
			errno = ENOENT;
			return (-1);
		}
		return (new_fd(FK_VM, vm, -1, 0));
	}
	if (strncmp(path, "/dev/vmm.io/", 12) == 0) {
		char copy[128], *dot;

		strlcpy(copy, path + 12, sizeof(copy));
		dot = strrchr(copy, '.');
		if (dot != NULL) {
			*dot = '\0';
			vm = find_vm(copy);
			if (vm >= 0)
				for (int s = 0; s < VM_MAX_MEMSEGS; s++)
					if (m.vms[vm].segs[s].len != 0 &&
					    strcmp(m.vms[vm].segs[s].name, dot + 1) == 0)
						return (new_fd(FK_DEVMEM, vm, s,
						    m.vms[vm].segs[s].len));
		}
	}
	errno = ENOENT;
	return (-1);
}

int
open(const char *path, int flags, ...)
{
	va_list ap;
	int mode;

	resolve();
	va_start(ap, flags);
	mode = (flags & O_CREAT) != 0 ? va_arg(ap, int) : 0;
	va_end(ap);
	if (path != NULL && vmm_path(path))
		return (fake_open(path));
	return (real_open(path, flags, mode));
}

int
openat(int dfd, const char *path, int flags, ...)
{
	va_list ap;
	int mode;

	resolve();
	va_start(ap, flags);
	mode = (flags & O_CREAT) != 0 ? va_arg(ap, int) : 0;
	va_end(ap);
	if (path != NULL && path[0] == '/' && vmm_path(path))
		return (fake_open(path));
	return (real_openat(dfd, path, flags, mode));
}

int
close(int fd)
{
	resolve();
	if (lookup_fd(fd) != NULL)
		fds[fd].kind = FK_NONE;
	return (real_close(fd));
}

int
fcntl(int fd, int cmd, ...)
{
	va_list ap;
	long arg;
	int result;

	resolve();
	va_start(ap, cmd);
	arg = va_arg(ap, long);
	va_end(ap);
	result = real_fcntl(fd, cmd, arg);
	if (result >= 0 && (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) &&
	    lookup_fd(fd) != NULL && result < (int)nitems(fds))
		fds[result] = fds[fd];
	return (result);
}

void *
mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	struct fakefd *f;
	int error;

	resolve();
	f = lookup_fd(fd);
	/* Address-space reservations (MAP_GUARD) can be failed by name. */
	if (fd == -1 && (flags & MAP_GUARD) != 0 &&
	    (error = fault("mmap_guard")) != 0) {
		errno = error;
		return (MAP_FAILED);
	}
	if (f == NULL)
		return (real_mmap(addr, len, prot, flags, fd, offset));
	if ((error = fault("mmap")) != 0) {
		errno = error;
		return (MAP_FAILED);
	}
	note("mmap kind %d len %zu off %#jx%s", f->kind, len, (uintmax_t)offset,
	    (flags & MAP_NOCORE) != 0 ? " nocore" : "");
	last_mmap_nocore = (flags & MAP_NOCORE) != 0;
	if (f->kind == FK_VM) {
		/* Guest memory: anonymous pages at the requested address. */
		return (real_mmap(addr, len, prot, (flags & MAP_FIXED) |
		    MAP_ANON | MAP_SHARED, -1, 0));
	}
	/* /dev/mem: the requested physical address is logged; the model's
	 * bitmap page is what any address maps. */
	return (real_mmap(addr, len, prot, flags, fd, f->kind == FK_MEM ? 0 : offset));
}

int
socket(int domain, int type, int protocol)
{
	static int (*real_socket)(int, int, int);
	int error;

	if (real_socket == NULL)
		real_socket = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
	if ((error = fault("socket")) != 0) {
		errno = error;
		return (-1);
	}
	return (real_socket(domain, type, protocol));
}

int
modfind(const char *name)
{
	note("modfind %s", name);
	if (strcmp(name, "vmm") == 0)
		return (fault("modfind") != 0 ? (errno = ENOENT, -1) : 42);
	errno = ENOENT;
	return (-1);
}

int
kldload(const char *name)
{
	/* Never load modules: recorded and refused. */
	note("kldload %s", name);
	errno = EPERM;
	return (-1);
}

/* ------------------------------------------------------- recording */
const struct vmmfake_record *
vmmfake_last(unsigned long cmd)
{
	for (unsigned long i = nrecords; i > 0 && i + VMMFAKE_RING > nrecords; i--)
		if (cmd == 0 || ring[(i - 1) % VMMFAKE_RING].cmd == cmd)
			return (&ring[(i - 1) % VMMFAKE_RING]);
	return (NULL);
}

unsigned long
vmmfake_count(void)
{
	return (nrecords);
}

static unsigned long cmd_counts[nitems(names)];

unsigned long
vmmfake_cmd_count(unsigned long cmd)
{
	for (size_t i = 0; i < nitems(names); i++)
		if (names[i].cmd == cmd)
			return (cmd_counts[i]);
	return (0);
}

static void
record(int fd, unsigned long cmd, const void *arg)
{
	for (size_t i = 0; i < nitems(names); i++)
		if (names[i].cmd == cmd)
			cmd_counts[i]++;
	struct vmmfake_record *r = &ring[nrecords++ % VMMFAKE_RING];
	size_t len = IOCPARM_LEN(cmd);

	r->cmd = cmd;
	r->fd = fd;
	r->len = len;
	memset(r->in, 0, sizeof(r->in));
	if (arg != NULL && len <= sizeof(r->in) && (cmd & IOC_IN) != 0)
		memcpy(r->in, arg, len);
	else if (arg != NULL && len <= sizeof(r->in))
		memcpy(r->in, arg, len);
}

/* -------------------------------------------------------- the model */
uint64_t
vmmfake_default_register(int cpu, int reg)
{
	return (0x1000ULL * (uint64_t)(reg & 0xffffff) + (uint64_t)cpu * 0x10 +
	    0x5 + ((uint64_t)((uint32_t)reg >> 24) << 40));
}

static struct regent *
reg_find(struct fakevm *vm, int cpu, int reg, bool create)
{
	for (int i = 0; i < vm->nregs; i++)
		if (vm->regs[i].cpu == cpu && vm->regs[i].reg == reg)
			return (&vm->regs[i]);
	if (!create || vm->nregs == MAXREGS)
		return (NULL);
	vm->regs[vm->nregs] = (struct regent){ cpu, reg, 0 };
	return (&vm->regs[vm->nregs++]);
}

static int
get_reg(struct fakevm *vm, int cpu, int reg, uint64_t *val)
{
	struct regent *e;

	if (cpu < 0 || cpu >= NCPU)
		return (EINVAL);
	e = reg_find(vm, cpu, reg, false);
	*val = e != NULL ? e->val : vmmfake_default_register(cpu, reg);
	return (0);
}

static int
set_reg(struct fakevm *vm, int cpu, int reg, uint64_t val)
{
	struct regent *e;

	if (cpu < 0 || cpu >= NCPU || reg < 0 ||
	    (reg >= VM_REG_LAST && (reg & 0x80000000) == 0))
		return (EINVAL);
	if ((e = reg_find(vm, cpu, reg, true)) == NULL)
		return (ENOSPC);
	e->val = val;
	return (0);
}

int
vmmfake_cap_available(int cap)
{
	/* Two capabilities are absent, as on hosts without them. */
	return (cap != VM_CAP_RDPID && cap != VM_CAP_NESTED_VMX);
}

static void
cpus_out(struct vm_cpuset *s, uint64_t bits)
{
	cpuset_t set;

	CPU_ZERO(&set);
	for (int i = 0; i < 64; i++)
		if ((bits & (1ULL << i)) != 0)
			CPU_SET(i, &set);
	memcpy(s->cpus, &set, MIN((size_t)s->cpusetsize, sizeof(set)));
}

static int
ctl_ioctl(unsigned long cmd, void *arg)
{
	switch (cmd) {
	case VMMCTL_VM_CREATE: {
		struct vmmctl_vm_create *c = arg;
		int free_slot = -1;

		if (find_vm(c->name) >= 0)
			return (EEXIST);
		for (int i = 0; i < MAXVMS; i++)
			if (!m.vms[i].used) {
				free_slot = i;
				break;
			}
		if (free_slot < 0)
			return (ENOSPC);
		memset(&m.vms[free_slot], 0, sizeof(m.vms[0]));
		m.vms[free_slot].used = true;
		strlcpy(m.vms[free_slot].name, c->name, sizeof(m.vms[0].name));
		m.vms[free_slot].vmid = m.next_vmid++;
		m.vms[free_slot].epoch = 1000 + m.vms[free_slot].vmid;
		m.vms[free_slot].create_flags = c->flags;
		m.vms[free_slot].active = 0x3;
		m.vms[free_slot].topology = (struct vm_cpu_topology){ 1, 2, 1, NCPU };
		m.vms[free_slot].rtc = 1700000000;
		for (int i = 0; i < 128; i++)
			m.vms[free_slot].nvram[i] = (uint8_t)(i ^ 0x5a);
		return (0);
	}
	case VMMCTL_VM_DESTROY: {
		struct vmmctl_vm_destroy *d = arg;
		int vm = find_vm(d->name);

		if (vm < 0)
			return (ENOENT);
		m.vms[vm].used = false;
		return (0);
	}
	case VMMCTL_VM_DESTROY_IDENTITY: {
		struct vmmctl_vm_destroy_identity *d = arg;
		int vm = find_vm(d->name);

		if (vm < 0)
			return (ENOENT);
		if (m.vms[vm].vmid != d->vmid || m.vms[vm].epoch != d->epoch)
			return (ESRCH);
		m.vms[vm].used = false;
		return (0);
	}
	}
	return (ENOTTY);
}

static int
vm_ioctl(struct fakevm *vm, unsigned long cmd, void *arg)
{
	switch (cmd) {
	case VM_GET_REGISTER: {
		struct vm_register *r = arg;
		return (get_reg(vm, r->cpuid, r->regnum, &r->regval));
	}
	case VM_SET_REGISTER: {
		struct vm_register *r = arg;
		return (set_reg(vm, r->cpuid, r->regnum, r->regval));
	}
	case VM_GET_REGISTER_SET: {
		struct vm_register_set *s = arg;
		for (unsigned i = 0; i < s->count; i++) {
			int error = get_reg(vm, s->cpuid, s->regnums[i], &s->regvals[i]);
			if (error != 0)
				return (error);
		}
		return (0);
	}
	case VM_SET_REGISTER_SET: {
		struct vm_register_set *s = arg;
		for (unsigned i = 0; i < s->count; i++) {
			int error = set_reg(vm, s->cpuid, s->regnums[i], s->regvals[i]);
			if (error != 0)
				return (error);
		}
		return (0);
	}
	case VM_GET_SEGMENT_DESCRIPTOR: {
		struct vm_seg_desc *d = arg;
		if (d->cpuid < 0 || d->cpuid >= NCPU || d->regnum < 0 ||
		    d->regnum >= VM_REG_LAST)
			return (EINVAL);
		if (vm->descs[d->cpuid][d->regnum].set)
			d->desc = vm->descs[d->cpuid][d->regnum].d;
		else
			d->desc = (struct seg_desc){
			    .base = 0x100000ULL * (uint64_t)d->regnum + (uint64_t)d->cpuid,
			    .limit = 0xfff0U + (uint32_t)d->regnum,
			    .access = 0x93U + (uint32_t)d->regnum };
		return (0);
	}
	case VM_SET_SEGMENT_DESCRIPTOR: {
		struct vm_seg_desc *d = arg;
		if (d->cpuid < 0 || d->cpuid >= NCPU || d->regnum < 0 ||
		    d->regnum >= VM_REG_LAST)
			return (EINVAL);
		vm->descs[d->cpuid][d->regnum].set = true;
		vm->descs[d->cpuid][d->regnum].d = d->desc;
		return (0);
	}
	case VM_GET_CAPABILITY: {
		struct vm_capability *c = arg;
		if (c->cpuid < 0 || c->cpuid >= NCPU || (int)c->captype < 0 ||
		    c->captype >= VM_CAP_MAX)
			return (EINVAL);
		if (!vmmfake_cap_available(c->captype))
			return (ENOENT);
		c->capval = vm->capset[c->cpuid][c->captype] ?
		    vm->caps[c->cpuid][c->captype] : (c->captype & 1);
		return (0);
	}
	case VM_SET_CAPABILITY: {
		struct vm_capability *c = arg;
		if (c->cpuid < 0 || c->cpuid >= NCPU || (int)c->captype < 0 ||
		    c->captype >= VM_CAP_MAX)
			return (EINVAL);
		if (!vmmfake_cap_available(c->captype))
			return (ENOENT);
		vm->capset[c->cpuid][c->captype] = true;
		vm->caps[c->cpuid][c->captype] = c->capval;
		return (0);
	}
	case VM_GET_X2APIC_STATE: {
		struct vm_x2apic *x = arg;
		if (x->cpuid < 0 || x->cpuid >= NCPU)
			return (EINVAL);
		x->state = vm->x2apic[x->cpuid];
		return (0);
	}
	case VM_SET_X2APIC_STATE: {
		struct vm_x2apic *x = arg;
		if (x->cpuid < 0 || x->cpuid >= NCPU || x->state >= X2APIC_STATE_LAST)
			return (EINVAL);
		vm->x2apic[x->cpuid] = x->state;
		return (0);
	}
	case VM_GET_INTINFO: {
		struct vm_intinfo *ii = arg;
		if (ii->vcpuid < 0 || ii->vcpuid >= NCPU)
			return (EINVAL);
		ii->info1 = vm->intinfo[ii->vcpuid];
		ii->info2 = VM_INTINFO_VALID | VM_INTINFO_HWINTR | 0x20;
		return (0);
	}
	case VM_SET_INTINFO: {
		struct vm_intinfo *ii = arg;
		if (ii->vcpuid < 0 || ii->vcpuid >= NCPU)
			return (EINVAL);
		vm->intinfo[ii->vcpuid] = ii->info1;
		return (0);
	}
	case VM_GET_CPUS: {
		struct vm_cpuset *s = arg;
		if (s->cpusetsize < (int)sizeof(cpuset_t))
			return (ERANGE);
		cpus_out(s, s->which == VM_ACTIVE_CPUS ? vm->active :
		    s->which == VM_SUSPENDED_CPUS ? vm->suspended :
		    s->which == VM_DEBUG_CPUS ? vm->debug : 0);
		return (s->which > VM_DEBUG_CPUS ? EINVAL : 0);
	}
	case VM_ACTIVATE_CPU: {
		struct vm_activate_cpu *a = arg;
		if (a->vcpuid < 0 || a->vcpuid >= NCPU)
			return (EINVAL);
		if ((vm->active & (1ULL << a->vcpuid)) != 0)
			return (EBUSY);
		vm->active |= 1ULL << a->vcpuid;
		return (0);
	}
	case VM_SUSPEND_CPU:
	case VM_RESUME_CPU: {
		struct vm_activate_cpu *a = arg;
		uint64_t bits;
		if (a->vcpuid < -1 || a->vcpuid >= NCPU)
			return (EINVAL);
		bits = a->vcpuid == -1 ? vm->active : (1ULL << a->vcpuid);
		if (cmd == VM_SUSPEND_CPU)
			vm->debug |= bits;
		else
			vm->debug &= ~bits;
		return (0);
	}
	case VM_GET_TOPOLOGY:
		*(struct vm_cpu_topology *)arg = vm->topology;
		return (0);
	case VM_SET_TOPOLOGY: {
		struct vm_cpu_topology *t = arg;
		if (t->sockets == 0 || t->cores == 0 || t->threads == 0 ||
		    (uint32_t)t->sockets * t->cores * t->threads > t->maxcpus)
			return (EINVAL);
		vm->topology = *t;
		return (0);
	}
	case VM_STATS: {
		struct vm_stats *s = arg;
		if (s->cpuid < 0 || s->cpuid >= NCPU || s->index < 0)
			return (EINVAL);
		s->num_entries = MAX(0, MIN(MAX_VM_STATS, NSTATS - s->index));
		for (int i = 0; i < s->num_entries; i++)
			s->statbuf[i] = (uint64_t)(s->index + i) * 3 + (uint64_t)s->cpuid;
		s->tv = (struct timeval){ 12345, 678 };
		return (0);
	}
	case VM_STAT_DESC: {
		struct vm_stat_desc *d = arg;
		if (d->index < 0 || d->index >= NSTATS)
			return (EINVAL);
		snprintf(d->desc, sizeof(d->desc), "statistic number %d", d->index);
		return (0);
	}
	case VM_ALLOC_MEMSEG: {
		struct vm_memseg *s = arg;
		if (s->segid < 0 || s->segid >= VM_MAX_MEMSEGS || s->len == 0)
			return (EINVAL);
		/* A competing allocator wins this identifier first. */
		if (preempt_name[0] != '\0' && vm->segs[s->segid].len == 0) {
			vm->segs[s->segid].len = s->len;
			strlcpy(vm->segs[s->segid].name, preempt_name,
			    sizeof(vm->segs[0].name));
			preempt_name[0] = '\0';
		}
		if (vm->segs[s->segid].len != 0)
			return (EEXIST);
		vm->segs[s->segid].len = s->len;
		strlcpy(vm->segs[s->segid].name, s->name, sizeof(vm->segs[0].name));
		return (0);
	}
	case VMMFAKE_FREE_MEMSEG: {
		/* Kernel ABI (VMM_FREE_MEMSEG_IOCNUM 200): reserved words zero,
		 * device memory only, never while mapped into the guest. */
		struct vmmfake_free_memseg *f = arg;
		if (f->reserved[0] != 0 || f->reserved[1] != 0 ||
		    f->reserved[2] != 0 || f->segid < 0 ||
		    f->segid >= VM_MAX_MEMSEGS || f->segid < VM_BOOTROM)
			return (EINVAL);
		if (vm->segs[f->segid].len == 0)
			return (ENOENT);
		for (int i = 0; i < vm->nmaps; i++)
			if (vm->maps[i].segid == f->segid)
				return (EBUSY);
		memset(&vm->segs[f->segid], 0, sizeof(vm->segs[0]));
		return (0);
	}
	case VM_GET_MEMSEG: {
		struct vm_memseg *s = arg;
		if (s->segid < 0 || s->segid >= VM_MAX_MEMSEGS)
			return (EINVAL);
		s->len = vm->segs[s->segid].len;
		strlcpy(s->name, vm->segs[s->segid].name, sizeof(s->name));
		return (0);
	}
	case VM_MMAP_MEMSEG: {
		struct vm_memmap *mm = arg;
		if (mm->segid < 0 || mm->segid >= VM_MAX_MEMSEGS ||
		    vm->segs[mm->segid].len == 0 || mm->len == 0 ||
		    mm->segoff + mm->len > vm->segs[mm->segid].len)
			return (EINVAL);
		for (int i = 0; i < vm->nmaps; i++)
			if (mm->gpa < vm->maps[i].gpa + vm->maps[i].len &&
			    vm->maps[i].gpa < mm->gpa + mm->len)
				return (EEXIST);
		if (vm->nmaps == VM_MAX_MEMMAPS)
			return (ENOSPC);
		vm->maps[vm->nmaps++] = *mm;
		/* Pass-through capable hosts map guest memory into the IOMMU. */
		if (getenv("VMMFAKE_IOMMU") != NULL)
			vm->maps[vm->nmaps - 1].flags |= VM_MEMMAP_F_IOMMU;
		return (0);
	}
	case VM_MUNMAP_MEMSEG: {
		struct vm_munmap *mu = arg;
		for (int i = 0; i < vm->nmaps; i++)
			if (vm->maps[i].gpa == mu->gpa && vm->maps[i].len == mu->len) {
				vm->maps[i] = vm->maps[--vm->nmaps];
				return (0);
			}
		return (EINVAL);
	}
	case VM_MMAP_GETNEXT: {
		struct vm_memmap *mm = arg;
		int best = -1;
		for (int i = 0; i < vm->nmaps; i++)
			if (vm->maps[i].gpa >= mm->gpa &&
			    (best < 0 || vm->maps[i].gpa < vm->maps[best].gpa))
				best = i;
		if (best < 0)
			return (ENOENT);
		*mm = vm->maps[best];
		return (0);
	}
	case VM_SUSPEND: {
		struct vm_suspend *s = arg;
		if (s->how <= VM_SUSPEND_NONE || s->how >= VM_SUSPEND_LAST)
			return (EINVAL);
		if (vm->suspend_how != 0)
			return (EALREADY);
		vm->suspend_how = s->how;
		return (0);
	}
	case VM_REINIT:
		vm->reinit_count++;
		vm->suspend_how = 0;
		return (0);
	case VM_RUN: {
		struct vm_run *r = arg;
		struct vm_exit *e = r->vm_exit;
		memset(e, 0, sizeof(*e));
		e->rip = 0xfff0 + (uint64_t)vm->run_count;
		e->inst_length = 2;
		e->exitcode = m.run_exitcode;
		switch (m.run_exitcode) {
		case VM_EXITCODE_INOUT:
			e->u.inout.in = vm->run_count & 1;
			e->u.inout.bytes = 4;
			/* VMMFAKE_INOUT_PLAIN: a single, non-repeated access. */
			e->u.inout.string = getenv("VMMFAKE_INOUT_PLAIN") == NULL;
			e->u.inout.rep = getenv("VMMFAKE_INOUT_PLAIN") == NULL;
			e->u.inout.port = 0x3f8;
			e->u.inout.eax = 0x41;
			break;
		case VM_EXITCODE_VMX:
			e->u.vmx.status = 1;
			e->u.vmx.exit_reason = 48;
			e->u.vmx.exit_qualification = 0x181;
			e->u.vmx.inst_type = 3;
			e->u.vmx.inst_error = 7;
			break;
		case VM_EXITCODE_SVM:
			e->u.svm.exitcode = 0x7b;
			e->u.svm.exitinfo1 = 0x10;
			e->u.svm.exitinfo2 = 0x20;
			break;
		}
		vm->run_count++;
		return (0);
	}
	case VM_GET_GPA_PMAP: {
		struct vm_gpa_pte *p = arg;
		p->ptenum = (int)(p->gpa & 3) + 1;
		for (int i = 0; i < p->ptenum; i++)
			p->pte[i] = p->gpa + 0x1000ULL * (uint64_t)i + 0x67;
		return (0);
	}
	case VM_GLA2GPA:
	case VM_GLA2GPA_NOFAULT: {
		struct vm_gla2gpa *g = arg;
		g->fault = (g->gla & 0xf00000000000ULL) != 0;
		g->gpa = g->gla & 0xffffffffULL;
		return (0);
	}
	case VM_RTC_WRITE: {
		struct vm_rtc_data *d = arg;
		if (d->offset < 0 || d->offset >= 128)
			return (EINVAL);
		vm->nvram[d->offset] = d->value;
		return (0);
	}
	case VM_RTC_READ: {
		struct vm_rtc_data *d = arg;
		if (d->offset < 0 || d->offset >= 128)
			return (EINVAL);
		d->value = vm->nvram[d->offset];
		return (0);
	}
	case VM_RTC_SETTIME:
		vm->rtc = ((struct vm_rtc_time *)arg)->secs;
		return (0);
	case VM_RTC_GETTIME:
		((struct vm_rtc_time *)arg)->secs = vm->rtc;
		return (0);
	case VM_IOAPIC_PINCOUNT:
		*(int *)arg = 32;
		return (0);
	case VM_GET_HPET_CAPABILITIES:
		((struct vm_hpet_cap *)arg)->capabilities = 0x8086a201;
		return (0);
	case VM_GET_IDENTIFIER:
		*(uint16_t *)arg = vm->vmid;
		return (0);
	case VM_GET_IDENTITY:
		((struct hypertrace_vm_identity *)arg)->vmid = vm->vmid;
		((struct hypertrace_vm_identity *)arg)->epoch = vm->epoch;
		return (0);
#ifdef VM_GET_RUN_WITNESS
	case VM_GET_RUN_WITNESS: {
		/* The kernel contract: one incarnation's identity, every guest
		 * entry attempt the model has seen (VM_RUN calls) and no running
		 * vCPU (the model never runs one concurrently); reserved zero.
		 * The caller's buffer is overwritten entirely, as copyout does. */
		struct vm_run_witness *w = arg;
		memset(w, 0, sizeof(*w));
		w->vmid = vm->vmid;
		w->epoch = vm->epoch;
		w->guest_entries = (uint64_t)vm->run_count;
		w->running_vcpus = 0;
		return (0);
	}
#endif
	case VM_GET_CPUID: {
		struct vm_cpuid *c = arg;
		if ((c->flags & ~VM_CPUID_F_VALID) != 0)
			return (EINVAL);
		c->ebx = c->eax ^ 0x1111;
		c->edx = c->ecx ^ 0x2222;
		c->eax = c->eax + 1;
		c->ecx = (uint32_t)c->cpuid;
		return (0);
	}
	case VM_GET_CPU_COMPAT: {
		struct vm_cpu_compat_query *q = arg;
		memset(&q->compat, 0, sizeof(q->compat));
		q->compat.version = VM_CPU_COMPAT_VERSION;
		q->compat.tsc_frequency = 1000000000ULL + (uint64_t)q->cpuid;
		return (0);
	}
	case VM_RESTORE_TIME:
		vm->restore_time_count++;
		return (0);
	case VM_SNAPSHOT_SESSION: {
		struct vm_snapshot_session *s = arg;
		if (s->op == VM_SNAPSHOT_SESSION_BEGIN)
			s->session_id = ++vm->snapshot_session;
		return (0);
	}
	default:
		/* Requests whose effect the tests observe through the record. */
		return (0);
	}
}

/* One log line per request with the fields the bhyvectl oracle checks. */
static void
describe(unsigned long cmd, void *arg, int error)
{
	const char *n = vmmfake_cmd_name(cmd);

	if (error != 0) {
		note("ioctl %s error %d", n, error);
		return;
	}
	switch (cmd) {
	case VM_GET_REGISTER:
	case VM_SET_REGISTER: {
		struct vm_register *r = arg;
		note("ioctl %s cpu=%d reg=%#x val=%#jx", n, r->cpuid,
		    (unsigned)r->regnum, (uintmax_t)r->regval);
		break;
	}
	case VM_GET_SEGMENT_DESCRIPTOR:
	case VM_SET_SEGMENT_DESCRIPTOR: {
		struct vm_seg_desc *d = arg;
		note("ioctl %s cpu=%d reg=%d base=%#jx limit=%#x access=%#x", n,
		    d->cpuid, d->regnum, (uintmax_t)d->desc.base, d->desc.limit,
		    d->desc.access);
		break;
	}
	case VM_SUSPEND:
		note("ioctl %s how=%d", n, ((struct vm_suspend *)arg)->how);
		break;
	case VM_LAPIC_LOCAL_IRQ:
	case VM_LAPIC_IRQ:
		note("ioctl %s cpu=%d vector=%d", n, ((struct vm_lapic_irq *)arg)->cpuid,
		    ((struct vm_lapic_irq *)arg)->vector);
		break;
	case VM_INJECT_NMI:
		note("ioctl %s cpu=%d", n, ((struct vm_nmi *)arg)->cpuid);
		break;
	case VM_BIND_PPTDEV:
	case VM_UNBIND_PPTDEV:
	case VM_RESET_PPTDEV: {
		struct vm_pptdev *p = arg;
		note("ioctl %s bus=%d slot=%d func=%d", n, p->bus, p->slot, p->func);
		break;
	}
	case VM_SET_CAPABILITY:
		note("ioctl %s cpu=%d cap=%d val=%d", n, ((struct vm_capability *)arg)->cpuid,
		    ((struct vm_capability *)arg)->captype, ((struct vm_capability *)arg)->capval);
		break;
	case VM_SET_X2APIC_STATE:
		note("ioctl %s cpu=%d state=%d", n, ((struct vm_x2apic *)arg)->cpuid,
		    ((struct vm_x2apic *)arg)->state);
		break;
	case VM_ALLOC_MEMSEG:
		note("ioctl %s segid=%d len=%zu name=%s", n, ((struct vm_memseg *)arg)->segid,
		    ((struct vm_memseg *)arg)->len, ((struct vm_memseg *)arg)->name);
		break;
	case VM_MMAP_MEMSEG: {
		struct vm_memmap *mm = arg;
		note("ioctl %s gpa=%#jx segid=%d off=%#jx len=%zu prot=%d flags=%d", n,
		    (uintmax_t)mm->gpa, mm->segid, (uintmax_t)mm->segoff, mm->len,
		    mm->prot, mm->flags);
		break;
	}
	default:
		note("ioctl %s", n);
		break;
	}
}

int
ioctl(int fd, unsigned long cmd, ...)
{
	struct fakefd *f;
	va_list ap;
	void *arg;
	int error;

	resolve();
	va_start(ap, cmd);
	arg = va_arg(ap, void *);
	va_end(ap);
	f = lookup_fd(fd);
	if (f == NULL) {
		/* Never forward a vmm request to the kernel. */
		if (IOCGROUP(cmd) == 'v' || IOCGROUP(cmd) == 'V') {
			errno = EBADF;
			return (-1);
		}
		return (real_ioctl(fd, cmd, arg));
	}
	record(fd, cmd, arg);
	if ((error = fault(vmmfake_cmd_name(cmd))) != 0) {
		note("ioctl %s failed %d (injected)", vmmfake_cmd_name(cmd), error);
		errno = error;
		return (-1);
	}
	if (f->kind == FK_CTL)
		error = ctl_ioctl(cmd, arg);
	else if (f->kind == FK_VM && m.vms[f->vm].used)
		error = vm_ioctl(&m.vms[f->vm], cmd, arg);
	else
		error = f->kind == FK_VM ? ENXIO : ENOTTY;
	describe(cmd, arg, error);
	save();
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

int
vmmfake_set_exitcode(int exitcode)
{
	m.run_exitcode = exitcode;
	save();
	return (0);
}

int
vmmfake_mark_suspended(const char *name, uint64_t suspended, uint64_t debug)
{
	int vm = find_vm(name);

	if (vm < 0)
		return (ENOENT);
	m.vms[vm].suspended = suspended;
	m.vms[vm].debug = debug;
	save();
	return (0);
}

int
vmmfake_vm_suspend_how(const char *name)
{
	int vm = find_vm(name);

	return (vm < 0 ? -1 : m.vms[vm].suspend_how);
}

int
vmmfake_vm_identity(const char *name, uint16_t *vmid, uint64_t *epoch)
{
	int vm = find_vm(name);

	if (vm < 0)
		return (ENOENT);
	*vmid = m.vms[vm].vmid;
	*epoch = m.vms[vm].epoch;
	return (0);
}

int
vmmfake_counts(const char *name, int *runs, int *reinits, int *restore_times)
{
	int vm = find_vm(name);

	if (vm < 0)
		return (ENOENT);
	*runs = m.vms[vm].run_count;
	*reinits = m.vms[vm].reinit_count;
	*restore_times = m.vms[vm].restore_time_count;
	return (0);
}

int
vmmfake_set_identity(const char *name, uint16_t vmid, uint64_t epoch)
{
	int vm = find_vm(name);

	if (vm < 0)
		return (ENOENT);
	m.vms[vm].vmid = vmid;
	m.vms[vm].epoch = epoch;
	save();
	return (0);
}
