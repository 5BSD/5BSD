/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Production-configuration tests of the bhyve migration adapters.
 *
 * coverage-bhyve.py compiles the ORIGINAL migration_session.c,
 * migration_tls.c, migration_receiver.c, migration_precopy.c,
 * migration_dirty.c, checkpoint_compat.c and libvmmapi's vmmapi_dirty_log.c
 * with their maintained compile commands (BHYVE_SNAPSHOT, BHYVE_GDB,
 * WITH_DTRACE).  This harness supplies only the VM, device, CPU, console,
 * debugger, IPC-quarantine and HyperTrace boundaries.  Real TLS, real
 * journals in private directories and real descriptor passing are used.
 *
 * A source runs in a child process and a destination in another process,
 * connected by a socketpair, exactly as two bhyve processes would be.  Every
 * boundary call is appended to a shared O_APPEND event log with a monotonic
 * timestamp.  Oracles are independent of the implementation:
 *
 *   - guest RAM and device state at the destination equal the source's
 *     state at quiesce (the fake guest keeps writing pages while running);
 *   - the source is never resumed once retirement began;
 *   - a destination never resumes unless the source was destroyed first;
 *   - a destination resumes at most once;
 *   - a committed source exits with BHYVE_EXIT_SUSPEND only after retirement;
 *   - an IPC reply that reports source_runnable describes a source whose
 *     CPUs and devices are running and that was never destroyed;
 *   - a non-runnable source is quarantined (retiring) or wedged (repairable).
 *
 * Fault mode enumerates every boundary call observed in successful runs and
 * reruns the migration with exactly that call failing, checking the
 * invariants above for each.  No VM, device node, daemon or network is used.
 */
#include "test-coverage.h"
#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/nv.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <machine/cpufunc.h>
#include <dev/vmm/vmm_dev.h>
#include <vmmapi.h>
#include <dev/vmm/vmm_dirty_log.h>

#include "bhyverun.h"
#include "checkpoint_compat.h"
#include "console.h"
#include "gdb.h"
#include "hypertrace.h"
#include "ipc.h"
#include "migration_credentials.h"
#include "migration_dirty.h"
#include "migration_precopy.h"
#include "migration_recovery.h"
#include "migration_source_owner.h"
#include "migration_session.h"
#include "migration_snapshot.h"
#include "pci_emul.h"
#include "qemu_fwcfg.h"
#include "snapshot.h"
#include "tpm_device.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "[%c %d] %s:%d: CHECK(%s) failed\n", \
	role, (int)getpid(), __FILE__, __LINE__, #x); abort(); } } while (0)

SET_DECLARE(ipc_cmd_set, struct ipc_command);

/* ------------------------------------------------------------ globals */
static char role = 'P';		/* P driver, S source, D destination */
static int event_fd = -1;
static bool tracing_mode;	/* hypertrace_initialized() */
static char workdir[256];

int guest_ncpus = 2;

/* -------------------------------------------------------- event log */
static void
event(const char *fmt, ...)
{
	char line[256];
	struct timespec now;
	va_list ap;
	int n;

	if (event_fd < 0)
		return;
	clock_gettime(CLOCK_MONOTONIC, &now);
	n = snprintf(line, sizeof(line), "%c %lld.%09ld ", role,
	    (long long)now.tv_sec, now.tv_nsec);
	va_start(ap, fmt);
	n += vsnprintf(line + n, sizeof(line) - n, fmt, ap);
	va_end(ap);
	if (n >= (int)sizeof(line) - 1)
		n = sizeof(line) - 2;
	line[n++] = '\n';
	CHECK(write(event_fd, line, n) == n);
}

/* Simulated abrupt process loss must still flush this process's counters. */
extern int __llvm_profile_write_file(void) __attribute__((weak));
extern void __llvm_profile_set_dumped(void) __attribute__((weak));

static void __attribute__((noreturn))
lose_process(void)
{
	if (__llvm_profile_write_file != NULL) {
		(void)__llvm_profile_write_file();
		__llvm_profile_set_dumped();
	}
	_exit(77);
}

static void
lose_on_signal(int signo)
{
	(void)signo;
	lose_process();
}

/* ------------------------------------------------------------ faults */
#define MAX_BOUNDARIES 96
static struct { const char *name; int count; } boundaries[MAX_BOUNDARIES];
#define FAULT_CRASH 999	/* simulate abrupt process loss at this call */
#define FAULT_NOERRNO 998	/* fail without setting errno */
#define FAIL_ERRNO(e) ((e) == FAULT_NOERRNO ? 0 : (e))
#define MAX_FAULTS 8
static struct { char role; char name[64]; int occurrence, error; } faults[MAX_FAULTS];
static int nfaults;

static int *
boundary_count(const char *name)
{
	for (int i = 0; i < MAX_BOUNDARIES; i++) {
		if (boundaries[i].name == NULL) {
			boundaries[i].name = name;
			return (&boundaries[i].count);
		}
		if (strcmp(boundaries[i].name, name) == 0)
			return (&boundaries[i].count);
	}
	abort();
}

/* Returns the errno to inject for this call of NAME, or 0. */
static int
boundary(const char *name)
{
	int n = ++*boundary_count(name);

	event("B %s %d", name, n);
	for (int i = 0; i < nfaults; i++)
		if (role == faults[i].role && n == faults[i].occurrence &&
		    strcmp(name, faults[i].name) == 0) {
			event("F %s %d %d", name, n, faults[i].error);
			if (faults[i].error == FAULT_CRASH)
				lose_process();
			return (faults[i].error);
		}
	return (0);
}

/* ---------------------------------------------------------- VM model */
#define PAGE 4096UL
#define LOWMEM (64 * PAGE)
#define HIGHBASE (4UL << 30)
#define HIGHMEM (16 * PAGE)
#define TRACK_LEN (HIGHBASE + HIGHMEM)
#define TRACK_PAGES (TRACK_LEN / PAGE)

struct vmctx {
	uint8_t *low, *high;
	uint16_t vmid;
	uint64_t epoch;
	bool destroyed, closed;
	bool dirty_enabled;
	uint8_t *dirty;			/* CPU dirty bitmap over the tracked range */
	uint64_t identity, map_generation, dirty_generation;
	int collects;
	bool cpus_paused, devices_paused, console_paused;
	bool fenced;			/* destination startup fence */
	int resumes;
	uint64_t guest_entries;		/* run witness: entries into the guest */
	uint32_t running_vcpus;
	int witness_identity_delta;	/* run witness names another lifetime */
};
static struct vmctx vm;
static void kernel_set(const char *, uint16_t, uint64_t);

static void
vm_model_init(uint16_t vmid, uint64_t epoch, uint8_t seed)
{
	memset(&vm, 0, sizeof(vm));
	vm.low = calloc(1, LOWMEM);
	vm.high = calloc(1, HIGHMEM);
	vm.dirty = calloc(1, TRACK_PAGES / 8);
	CHECK(vm.low && vm.high && vm.dirty);
	for (size_t i = 0; i < LOWMEM; i++)
		vm.low[i] = (uint8_t)(seed + i * 7 + i / PAGE);
	for (size_t i = 0; i < HIGHMEM; i++)
		vm.high[i] = (uint8_t)(seed ^ (i * 13 + i / PAGE));
	vm.vmid = vmid;
	vm.epoch = epoch;
	vm.identity = 0x1000 + vmid;
	if (workdir[0] != '\0' && role != 'P')
		kernel_set("live", vmid, epoch);
	vm.map_generation = 1;
	vm.dirty_generation = 1;
}

static uint8_t *
gpa_host(uint64_t gpa, size_t len)
{
	if (gpa < LOWMEM && len <= LOWMEM - gpa)
		return (vm.low + gpa);
	if (gpa >= HIGHBASE && gpa - HIGHBASE < HIGHMEM && len <= HIGHMEM - (gpa - HIGHBASE))
		return (vm.high + (gpa - HIGHBASE));
	return (NULL);
}

static void
mark_dirty(uint64_t gpa)
{
	uint64_t page = gpa / PAGE;
	vm.dirty[page / 8] |= (uint8_t)(1U << (page % 8));
}

/* While the source CPUs run, the guest keeps writing a few pages. */
static void
guest_writes(int round)
{
	if (vm.cpus_paused)
		return;
	event("E guest_wrote %d", round);
	for (int i = 0; i < 3; i++) {
		uint64_t gpa = (uint64_t)((round * 5 + i * 11) % 64) * PAGE;
		vm.low[gpa + (size_t)round] ^= 0xa5;
		if (vm.dirty_enabled)
			mark_dirty(gpa);
	}
	uint64_t high = HIGHBASE + (uint64_t)(round % 16) * PAGE;
	vm.high[(high - HIGHBASE) + 1] ^= 0x3c;
	if (vm.dirty_enabled)
		mark_dirty(high);
}

static uint64_t fake_lowmem = LOWMEM, fake_highmem = HIGHMEM, fake_highbase = HIGHBASE;
static uint16_t witness_vmid_delta;	/* run witness names another VM id */

uint64_t
vm_get_lowmem_size(struct vmctx *ctx)
{
	CHECK(ctx == &vm);
	return (fake_lowmem);
}

uint64_t
vm_get_highmem_size(struct vmctx *ctx)
{
	CHECK(ctx == &vm);
	return (fake_highmem);
}

uint64_t
vm_get_highmem_base(struct vmctx *ctx)
{
	CHECK(ctx == &vm);
	return (fake_highbase);
}

void *
vm_map_gpa(struct vmctx *ctx, vm_paddr_t gpa, size_t len)
{
	CHECK(ctx == &vm && !vm.destroyed);
	if (boundary("vm_map_gpa") != 0)
		return (NULL);
	return (gpa_host(gpa, len));
}

int
vm_get_topology(struct vmctx *ctx, uint16_t *sockets, uint16_t *cores,
    uint16_t *threads, uint16_t *maxcpus)
{
	int error = boundary("vm_get_topology");

	CHECK(ctx == &vm);
	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	*sockets = 1;
	*cores = 2;
	*threads = 1;
	*maxcpus = 2;
	return (0);
}

/* Kernel run witness (VM_GET_RUN_WITNESS): one incarnation's guest entry
 * count and running vCPUs, as the model has tracked them. */
int
vm_get_run_witness(struct vmctx *ctx, struct vm_run_witness *witness)
{
	int error = boundary("vm_get_run_witness");

	CHECK(ctx == &vm && witness != NULL);
	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	memset(witness, 0, sizeof(*witness));
	witness->vmid = vm.vmid + witness_vmid_delta;
	witness->epoch = vm.epoch + (uint64_t)vm.witness_identity_delta;
	witness->guest_entries = vm.guest_entries;
	witness->running_vcpus = vm.running_vcpus;
	return (0);
}

int
vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch)
{
	int error = boundary("vm_get_identity");

	CHECK(ctx == &vm);
	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	*vmid = vm.vmid;
	*epoch = vm.epoch;
	return (0);
}

void
vm_close(struct vmctx *ctx)
{
	CHECK(ctx == &vm && vm.destroyed && !vm.closed);
	vm.closed = true;
	event("E vm_close");
}

/* Kernel VM lifetimes outlive bhyve processes: keep them as marker files. */
static void
kernel_marker(char *path, size_t size, const char *state, uint16_t vmid, uint64_t epoch)
{
	snprintf(path, size, "%s/kernel-%s-%u-%ju", workdir, state, vmid, (uintmax_t)epoch);
}

static bool
kernel_has(const char *state, uint16_t vmid, uint64_t epoch)
{
	char path[400];

	kernel_marker(path, sizeof(path), state, vmid, epoch);
	return (access(path, F_OK) == 0);
}

static void
kernel_set(const char *state, uint16_t vmid, uint64_t epoch)
{
	char path[400];
	int fd;

	kernel_marker(path, sizeof(path), state, vmid, epoch);
	fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	CHECK(fd >= 0);
	close(fd);
}

static int
destroy_lifetime(const char *how, uint16_t vmid, uint64_t epoch, int error)
{
	if (error == 0 && (!kernel_has("live", vmid, epoch) ||
	    kernel_has("destroyed", vmid, epoch)))
		error = ENOENT;
	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	kernel_set("destroyed", vmid, epoch);
	if (vmid == vm.vmid && epoch == vm.epoch)
		vm.destroyed = true;
	event("E destroyed vm%u %s", vmid, how);
	return (0);
}

static int
destroy_checked(const char *name, int error)
{
	CHECK(!vm.destroyed);
	return (destroy_lifetime(name, vm.vmid, vm.epoch, error));
}

int
vm_destroy_request_checked(struct vmctx *ctx)
{
	CHECK(ctx == &vm);
	return (destroy_checked("plain", boundary("vm_destroy_request_checked")));
}

int
vm_destroy_identity_request_checked(struct vmctx *ctx, uint16_t vmid, uint64_t epoch)
{
	int error = boundary("vm_destroy_identity_request_checked");

	CHECK(ctx == &vm);
	if (error == 0 && (vmid != vm.vmid || epoch != vm.epoch))
		error = ESTALE;
	return (destroy_checked("identity", error));
}

int
vm_destroy_name_identity_checked(const char *name, uint16_t vmid, uint64_t epoch)
{
	int error = boundary("vm_destroy_name_identity_checked");

	CHECK(name != NULL && strcmp(name, "migrating-vm") == 0);
	return (destroy_lifetime("name", vmid, epoch, error));
}

/* Kernel CPU dirty log: ENABLE marks every backed page dirty so the first
 * generation sends all memory; CLEAR publishes and clears the bitmap. */
int
vm_dirty_log_request(struct vmctx *ctx, const struct vmm_dirty_log_request *request)
{
	int error = boundary("vm_dirty_log_request");

	CHECK(ctx == &vm);
	CHECK(request->version == VMM_DIRTY_LOG_REQUEST_VERSION &&
	    request->size == VMM_DIRTY_LOG_REQUEST_SIZE);
	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	switch (request->operation) {
	case VMM_DIRTY_LOG_REQUEST_ENABLE:
		/* The tracked range covers high memory when the VM has any. */
		CHECK(!vm.dirty_enabled && request->gpa == 0 && request->length ==
		    (fake_highmem != 0 ? TRACK_LEN : fake_lowmem));
		vm.dirty_enabled = true;
		for (uint64_t gpa = 0; gpa < LOWMEM; gpa += PAGE)
			mark_dirty(gpa);
		for (uint64_t gpa = HIGHBASE; gpa < TRACK_LEN; gpa += PAGE)
			mark_dirty(gpa);
		return (0);
	case VMM_DIRTY_LOG_REQUEST_DISABLE:
		CHECK(vm.dirty_enabled);
		vm.dirty_enabled = false;
		return (0);
	case VMM_DIRTY_LOG_REQUEST_OBSERVE:
	case VMM_DIRTY_LOG_REQUEST_CLEAR: {
		struct vmm_dirty_log_result *result =
		    (void *)(uintptr_t)request->output_address;
		size_t bytes = (request->length / PAGE + 7) / 8;

		CHECK(vm.dirty_enabled && request->gpa == 0 && request->length ==
		    (fake_highmem != 0 ? TRACK_LEN : fake_lowmem));
		CHECK(request->output_bytes == sizeof(*result) + bytes);
		memset(result, 0, sizeof(*result));
		result->version = VMM_DIRTY_LOG_RESULT_VERSION;
		result->size = VMM_DIRTY_LOG_RESULT_SIZE;
		result->operation = request->operation;
		result->gpa = request->gpa;
		result->length = request->length;
		result->identity = vm.identity;
		result->map_generation = vm.map_generation;
		result->dirty_generation = vm.dirty_generation++;
		result->bitmap_offset = sizeof(*result);
		result->bitmap_bytes = bytes;
		memcpy(result + 1, vm.dirty, bytes);
		if (request->operation == VMM_DIRTY_LOG_REQUEST_CLEAR) {
			memset(vm.dirty, 0, bytes);
			/* The guest runs between collections. */
			guest_writes(++vm.collects);
		}
		return (0);
	}
	default:
		abort();
	}
}

/* ---------------------------------------------------------- devices */
static struct pci_devemu devemu_fixed = {
	.pe_emu = "fake-fixed",
	.pe_migration_flags = PCI_MIGRATION_F_STATE_CODEC |
	    PCI_MIGRATION_F_COMPAT_FIXED | PCI_MIGRATION_F_DMA_NONE |
	    PCI_MIGRATION_F_QUIESCE_NONE,
};
static struct pci_devemu devemu_callback = {
	.pe_emu = "fake-callback",
	.pe_migration_flags = PCI_MIGRATION_F_STATE_CODEC |
	    PCI_MIGRATION_F_COMPAT_CALLBACK | PCI_MIGRATION_F_DMA_TRACKED |
	    PCI_MIGRATION_F_QUIESCE_CALLBACK,
};
static struct pci_devinst devices[2];
static int topology_variant;	/* destination-only shape change */
static bool compat_invalid;	/* return an unencodable compatibility envelope */

static void
devices_init(void)
{
	memset(devices, 0, sizeof(devices));
	devices[0].pi_d = &devemu_fixed;
	strlcpy(devices[0].pi_name, "fake-fixed", sizeof(devices[0].pi_name));
	devices[0].pi_bar[0].type = PCIBAR_MEM32;
	devices[0].pi_bar[0].size = 4096;
	devices[1].pi_d = &devemu_callback;
	strlcpy(devices[1].pi_name, "fake-callback", sizeof(devices[1].pi_name));
	devices[1].pi_bar[1].type = PCIBAR_MEM64;
	devices[1].pi_bar[1].size = 1 << 20;
	if (role == 'D' && topology_variant == 1)
		devices[1].pi_bar[1].size = 1 << 21;
}

/* Additional fixed-contract devices (topology size limits). */
static int extra_devices;
static struct pci_devinst many_devices[300];

static void
many_devices_init(int n)
{
	CHECK(n >= 0 && n <= 300);
	memset(many_devices, 0, sizeof(many_devices));
	for (int i = 0; i < n; i++) {
		many_devices[i].pi_d = &devemu_fixed;
		snprintf(many_devices[i].pi_name, sizeof(many_devices[i].pi_name), "many-%d", i);
		many_devices[i].pi_bar[0].type = PCIBAR_MEM32;
		many_devices[i].pi_bar[0].size = 4096;
	}
	extra_devices = n;
}

struct pci_devinst *
pci_next(const struct pci_devinst *cursor)
{
	if (cursor == NULL)
		return (&devices[0]);
	if (cursor == &devices[0])
		return (&devices[1]);
	if (cursor == &devices[1])
		return (extra_devices > 0 ? &many_devices[0] : NULL);
	if (cursor >= many_devices && cursor < many_devices + 300) {
		ptrdiff_t i = cursor - many_devices;
		return (i + 1 < extra_devices ? &many_devices[i + 1] : NULL);
	}
	return (NULL);
}

int
pci_snapshot_compat(struct pci_devinst *pdi, struct pci_snapshot_compat *compat)
{
	int error = boundary("pci_snapshot_compat");

	CHECK(pdi == &devices[1]);
	if (error != 0)
		return (error);
	memset(compat, 0, sizeof(*compat));
	if (compat_invalid) {
		compat->schema = 0;	/* not encodable */
		return (0);
	}
	compat->schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
	compat->transport = 1;
	compat->queue_count = 2;
	compat->msix_table_count = 3;
	compat->config_size = 64;
	compat->offered_features = 0x1234;
	compat->negotiated_features = role == 'S' ? 0x34 : 0;
	compat->payload_crc32 = role == 'S' ? 0x77 : 0;
	strlcpy(compat->queue_sizes, "256,256", sizeof(compat->queue_sizes));
	return (0);
}

int
pci_migration_precopy_validate(void)
{
	return (boundary("pci_migration_precopy_validate"));
}

static bool fwcfg_enabled = true;
bool
qemu_fwcfg_enabled(void)
{
	return (fwcfg_enabled);
}

int
qemu_fwcfg_migration_identity(uint32_t *identity)
{
	int error = boundary("qemu_fwcfg_migration_identity");

	if (error == 0)
		*identity = 0xfeedf00d;
	return (error);
}

static bool tpm_present;
bool
tpm_device_present(void)
{
	return (tpm_present);
}

/* ----------------------------------------------- CPU/device/console */
static bool runnable_on_pause_failure = true;

int
fbsdrun_migration_pause_cpus(struct vmctx *ctx, bool *runnable)
{
	int error = boundary("fbsdrun_migration_pause_cpus");

	CHECK(ctx == &vm && !vm.destroyed);
	if (error != 0) {
		/* ETIMEDOUT models a barrier that could not restore the vCPUs. */
		*runnable = runnable_on_pause_failure && error != ETIMEDOUT;
		if (!*runnable)
			vm.cpus_paused = true;
		return (error);
	}
	vm.cpus_paused = true;
	*runnable = false;
	event("E cpus_paused");
	return (0);
}

int
fbsdrun_migration_resume_cpus(struct vmctx *ctx)
{
	int error = boundary("fbsdrun_migration_resume_cpus");

	CHECK(ctx == &vm);
	if (error != 0)
		return (error);
	CHECK(!vm.destroyed);
	vm.cpus_paused = false;
	event("E cpus_resumed");
	return (0);
}

static bool cpus_retiring;
void
fbsdrun_retire_cpus_begin(void)
{
	cpus_retiring = true;
	event("E retire_cpus_begin");
}

bool
fbsdrun_cpus_retiring(void)
{
	return (cpus_retiring);
}

int
fbsdrun_retire_cpus_wait(void)
{
	return (boundary("fbsdrun_retire_cpus_wait"));
}

int
vm_pause_devices(void)
{
	int error = boundary("vm_pause_devices");

	if (error != 0)
		return (error);
	vm.devices_paused = true;
	event("E devices_paused");
	return (0);
}

int
vm_resume_devices(void)
{
	int error = boundary("vm_resume_devices");

	if (error != 0)
		return (error);
	CHECK(!vm.destroyed);
	vm.devices_paused = false;
	event("E devices_resumed");
	return (0);
}

void
console_input_pause(void)
{
	vm.console_paused = true;
	event("E console_paused");
}

void
console_input_resume(void)
{
	vm.console_paused = false;
	event("E console_resumed");
}

/* ----------------------------------------------------------- debugger */
static bool gdb_fenced, gdb_retired;
static const char *gdb_refusal;
int
gdb_migration_fence(const char **reason)
{
	CHECK(!gdb_fenced);
	if (gdb_refusal != NULL) {
		*reason = gdb_refusal;
		return (EBUSY);
	}
	gdb_fenced = true;
	event("E gdb_fenced");
	return (0);
}

void
gdb_migration_unfence(void)
{
	CHECK(!gdb_retired);
	gdb_fenced = false;
	event("E gdb_unfenced");
}

void
gdb_migration_retire(void)
{
	gdb_retired = true;
	event("E gdb_retired");
}

/* ---------------------------------------------------------------- IPC */
static int quarantined, wedged;
void
ipc_quarantine_vm(void)
{
	quarantined = 1;
	wedged = 0;
	event("E quarantined");
}

void
ipc_wedge_vm(void)
{
	CHECK(!quarantined);
	wedged = 1;
	event("E wedged");
}

int
ipc_unwedge_vm(void)
{
	if (!wedged || quarantined)
		return (EPERM);
	wedged = 0;
	event("E unwedged");
	return (0);
}

/* ------------------------------------------------- HyperTrace boundary */
static uint64_t stop_token = 0x5151;

int
hypertrace_initialized(void)
{
	return (tracing_mode);
}

int
hypertrace_retire_transport(void)
{
	return (boundary("hypertrace_retire_transport"));
}

int
pci_vtdtr_checkpoint_stop(void)
{
	return (boundary("pci_vtdtr_checkpoint_stop"));
}

int
hypertrace_session_retired(uint16_t vmid, uint64_t epoch)
{
	int error = boundary("hypertrace_session_retired");

	if (error == 0 && !kernel_has("destroyed", vmid, epoch))
		error = kernel_has("live", vmid, epoch) ? EBUSY : ENOENT;
	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	return (0);
}

int
vm_migrate_stop_tracing(struct vmctx *ctx, uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE])
{
	struct hypertrace_session_record r = {
		.vmid = vm.vmid, .epoch = vm.epoch, .stop_token = stop_token,
		.features = HYPERTRACE_SESSION_FEATURES,
	};
	int error = boundary("vm_migrate_stop_tracing");

	CHECK(ctx == &vm);
	if (error != 0)
		return (error);
	CHECK(hypertrace_session_record_encode(record, HYPERTRACE_SESSION_RECORD_SIZE, &r) == 0);
	event("E tracing_stopped");
	return (0);
}

/* --------------------------------------------- snapshot/state boundary */
#define META_LEN 300
#define KERNEL_LEN 5000

static void
fill_state(uint8_t *p, size_t n, uint8_t seed)
{
	for (size_t i = 0; i < n; i++)
		p[i] = (uint8_t)(seed + i * 31 + (i >> 8));
}

static int
make_blob(uint8_t **buf, size_t *len, const uint8_t *record)
{
	size_t total = MIGRATE_BLOB_HDR + META_LEN + KERNEL_LEN +
	    (record != NULL ? HYPERTRACE_SESSION_RECORD_SIZE : 0);
	uint8_t *blob = malloc(total);

	if (blob == NULL)
		return (ENOMEM);
	le64enc(blob, META_LEN);
	le64enc(blob + 8, KERNEL_LEN);
	fill_state(blob + MIGRATE_BLOB_HDR, META_LEN + KERNEL_LEN, 0x42);
	if (record != NULL)
		memcpy(blob + MIGRATE_BLOB_HDR + META_LEN + KERNEL_LEN, record,
		    HYPERTRACE_SESSION_RECORD_SIZE);
	*buf = blob;
	*len = total;
	return (0);
}

int
vm_snapshot_dev_state_to_mem(struct vmctx *ctx, uint8_t **buf, size_t *len)
{
	int error = boundary("vm_snapshot_dev_state_to_mem");

	CHECK(ctx == &vm && vm.cpus_paused && vm.devices_paused);
	return (error != 0 ? error : make_blob(buf, len, NULL));
}

int
vm_snapshot_fresh_dev_state_to_mem(struct vmctx *ctx,
    const uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE], uint8_t **buf, size_t *len)
{
	int error = boundary("vm_snapshot_fresh_dev_state_to_mem");

	CHECK(ctx == &vm && vm.cpus_paused && vm.devices_paused);
	return (error != 0 ? error : make_blob(buf, len, record));
}

static uint8_t committed_blob[MIGRATE_BLOB_HDR + META_LEN + KERNEL_LEN +
    HYPERTRACE_SESSION_RECORD_SIZE];
static size_t committed_len;
static struct pci_devinst fresh_device;

int
vm_migrate_commit_state(struct vmctx *ctx, const uint8_t *blob, size_t len)
{
	int error = boundary("vm_migrate_commit_state");

	CHECK(ctx == &vm && vm.fenced);
	if (error != 0)
		return (error);
	CHECK(len <= sizeof(committed_blob));
	memcpy(committed_blob, blob, len);
	committed_len = len;
	event("E committed");
	return (0);
}

int
vm_migrate_fresh_commit_state(struct vmctx *ctx, const uint8_t *blob, size_t len,
    struct pci_devinst **device)
{
	int error = boundary("vm_migrate_fresh_commit_state");

	CHECK(ctx == &vm && vm.fenced);
	if (error != 0)
		return (error);
	CHECK(len <= sizeof(committed_blob));
	memcpy(committed_blob, blob, len);
	committed_len = len;
	*device = &fresh_device;
	event("E committed");
	return (0);
}

static int
resume_destination(const char *how, int error)
{
	if (error != 0)
		return (error);
	CHECK(vm.fenced);
	vm.fenced = false;
	vm.resumes++;
	/* Lifting the startup fence lets vCPUs enter the guest. */
	vm.guest_entries++;
	event("E dest_resumed %s", how);
	return (0);
}

int
vm_migrate_resume(struct vmctx *ctx)
{
	CHECK(ctx == &vm);
	return (resume_destination("plain", boundary("vm_migrate_resume")));
}

int
vm_migrate_fresh_resume(struct vmctx *ctx, struct pci_devinst *device,
    const uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE])
{
	struct hypertrace_session_record r;

	CHECK(ctx == &vm && device == &fresh_device);
	CHECK(hypertrace_session_record_decode(record, HYPERTRACE_SESSION_RECORD_SIZE, &r) == 0);
	return (resume_destination("fresh", boundary("vm_migrate_fresh_resume")));
}

bool
checkpoint_restore_startup_held(void)
{
	return (vm.fenced);
}

/* ------------------------------------------- journal syscall faults */
/* Journals and locks are real files; their durability calls are fault
 * boundaries so the enumeration also fails each fsync/rename/unlink/flock. */
int __real_fsync(int);
int __real_renameat(int, const char *, int, const char *);
int __real_unlinkat(int, const char *, int);
int __real_flock(int, int);

int
__wrap_fsync(int fd)
{
	int error = role == 'P' ? 0 : boundary("fsync");

	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	return (__real_fsync(fd));
}

int
__wrap_renameat(int a, const char *b, int c, const char *d)
{
	int error = role == 'P' ? 0 : boundary("renameat");

	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	return (__real_renameat(a, b, c, d));
}

int
__wrap_unlinkat(int a, const char *b, int c)
{
	int error = role == 'P' ? 0 : boundary("unlinkat");

	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	return (__real_unlinkat(a, b, c));
}

int
__wrap_flock(int fd, int op)
{
	int error = role == 'P' ? 0 : boundary("flock");

	if (error != 0) {
		errno = FAIL_ERRNO(error);
		return (-1);
	}
	return (__real_flock(fd, op));
}

/* ------------------------------------------------- filesystem anchor */
/* migration_prod_source_prepare() opens "/" and walks var/db/bhyve/migration
 * requiring administrator-owned parents.  Redirect "/" to a private anchor
 * and report uid 0 for the three parents; the journal directory keeps its
 * real owner and mode, which the production check also enforces. */
static ino_t root_inodes[4];
int __real_open(const char *, int, ...);
int __real_fstat(int, struct stat *);

int
__wrap_open(const char *path, int flags, ...)
{
	va_list ap;
	int mode;
	char anchor[300];

	va_start(ap, flags);
	mode = va_arg(ap, int);
	va_end(ap);
	if (strcmp(path, "/") == 0 && workdir[0] != '\0') {
		snprintf(anchor, sizeof(anchor), "%s/anchor", workdir);
		return (__real_open(anchor, flags, mode));
	}
	return (__real_open(path, flags, mode));
}

int
__wrap_fstat(int fd, struct stat *st)
{
	int error = __real_fstat(fd, st);

	if (error == 0)
		for (int i = 0; i < 4; i++)
			if (root_inodes[i] != 0 && st->st_ino == root_inodes[i]) {
				st->st_uid = 0;
				st->st_mode &= ~(mode_t)022;
			}
	return (error);
}

static void
make_dir(const char *path, mode_t mode)
{
	CHECK(mkdir(path, mode) == 0 || errno == EEXIST);
	CHECK(chmod(path, mode) == 0);
}

static void
setup_anchor(void)
{
	char path[400];
	const char *parts[] = { "anchor", "anchor/var", "anchor/var/db",
	    "anchor/var/db/bhyve", "anchor/var/db/bhyve/migration" };
	struct stat st;

	for (int i = 0; i < 5; i++) {
		snprintf(path, sizeof(path), "%s/%s", workdir, parts[i]);
		make_dir(path, i == 4 ? 0700 : 0755);
		if (i < 4) {
			CHECK(stat(path, &st) == 0);
			root_inodes[i] = st.st_ino;
		}
	}
}

/* ------------------------------------------------------- TLS material */
static int
open_file(const char *name)
{
	char path[400];
	int fd;

	snprintf(path, sizeof(path), "%s/../%s", workdir, name);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0);
	return (fd);
}

static void
read_pin(const char *name, char hex[65])
{
	char path[400];
	uint8_t pin[32];
	FILE *f;

	snprintf(path, sizeof(path), "%s/../%s", workdir, name);
	f = fopen(path, "rb");
	CHECK(f != NULL && fread(pin, 1, 32, f) == 32);
	fclose(f);
	for (int i = 0; i < 32; i++)
		snprintf(hex + 2 * i, 3, "%02x", pin[i]);
}

static void
source_credentials(nvlist_t *nvl)
{
	char hex[65];

	nvlist_move_descriptor(nvl, "tls_certificate_fd", open_file("source.pem"));
	nvlist_move_descriptor(nvl, "tls_private_key_fd", open_file("source.key"));
	nvlist_move_descriptor(nvl, "tls_trust_fd", open_file("destination.pem"));
	read_pin("destination.pin", hex);
	nvlist_add_string(nvl, "tls_peer_sha256", hex);
}

static void
destination_credentials(struct migration_tls_credentials *c)
{
	char hex[65];

	c->certificate_fd = open_file("destination.pem");
	c->private_key_fd = open_file("destination.key");
	c->trust_fd = open_file("source.pem");
	read_pin("source.pin", hex);
	CHECK(migration_credentials_pin(hex, c->peer_certificate_sha256) == 0);
}

/* ------------------------------------------------------ IPC dispatch */
static nvlist_t *
ipc_call(const char *name, const nvlist_t *request)
{
	struct ipc_command **cmd;

	SET_FOREACH(cmd, ipc_cmd_set)
		if (strcmp((*cmd)->name, name) == 0)
			return ((*cmd)->handler(&vm, request));
	abort();
}

/* ------------------------------------------------------- scenarios */
struct outcome;
static int count_events(const char *who_what);
static int reply_number(const nvlist_t *, const char *);
static int kv_int(const char *, const char *);
static void read_kv(const char *, const char *, char *, size_t);
static unsigned long expected_ram_crc(int);
static int reply_bool(const nvlist_t *, const char *);
struct migration_dest_result;
struct scenario {
	const char *name;
	void (*recover)(const struct scenario *, struct outcome *);
	/* Run in the destination process after serving, while a retained
	 * owner (if any) is still held; returns a check count or -1. */
	int (*dest_resolve)(const struct scenario *, const struct migration_dest_result *, int);
	int resolve_variant;
	bool dest_recovery;	/* ordinary destination with a recovery directory */
	bool no_highmem;	/* both VMs have low memory only */
	bool recover_ipc;	/* operator recovery through the source process */
	bool repair_ipc;	/* operator repair through the source process */
	const char *recovery_dir;	/* recovery_fddir relative to workdir */
	bool restart_probe;	/* restarted recovery while the source lives */
	bool recovery_image;	/* destination preserves an HDI1 image */
	bool tracing;		/* fresh-session migration (TLS mandatory) */
	bool tls;
	bool managed;		/* destination through the managed receiver */
	int topology_variant;
	const char *gdb_refusal;
	uint64_t max_rounds;	/* 0: default */
};

static int control_fd = -1;
static pid_t destination_pid;

static int
connect_recovery(void)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	CHECK(fd >= 0);
	snprintf(address.sun_path, sizeof(address.sun_path), "%s/recovery.sock", workdir);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

/* Operator recovery through the original source process (IPC migrate_recover). */
static nvlist_t *dead_peer_request(void);

static void
source_recover(const struct scenario *s)
{
	nvlist_t *request = nvlist_create(0), *reply;
	char path[400];
	FILE *out;
	int fd;
	bool destroyed = vm.destroyed;

	(void)s;
	/*
	 * Malformed recovery requests are refused before any connection or
	 * state change: no descriptor, a substituted journal root, missing or
	 * partial credentials, and a peer that vanished before TLS.  The
	 * source never becomes runnable and its VM state is unchanged.
	 */
	{
		static const struct { int kind, error; } bad[] = {
			{ 0, EINVAL }, { 1, EINVAL }, { 2, EACCES }, { 3, EINVAL }, { 4, -1 },
		};
		for (size_t i = 0; i < nitems(bad); i++) {
			nvlist_t *req = bad[i].kind == 4 ? dead_peer_request() : nvlist_create(0);
			if (bad[i].kind != 0 && bad[i].kind != 4) {
				int pair[2];
				CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
				close(pair[1]);
				nvlist_move_descriptor(req, "fd", pair[0]);
			}
			if (bad[i].kind == 1) {
				source_credentials(req);
				nvlist_move_descriptor(req, "recovery_fddir",
				    open(workdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
			}
			if (bad[i].kind == 3)
				nvlist_add_string(req, "tls_peer_sha256", "00");
			if (bad[i].kind == 4)
				source_credentials(req);
			reply = ipc_call("migrate_recover", req);
			nvlist_destroy(req);
			/* Without a retirement there is nothing to recover. */
			if (nvlist_get_number(reply, "error_code") == EOPNOTSUPP) {
				CHECK(i == 0 && !nvlist_get_bool(reply, "confirmed"));
				nvlist_destroy(reply);
				break;
			}
			CHECK(!nvlist_get_bool(reply, "confirmed") &&
			    !nvlist_get_bool(reply, "source_runnable"));
			if (bad[i].error > 0)
				CHECK(nvlist_get_number(reply, "error_code") == (uint64_t)bad[i].error);
			else
				CHECK(nvlist_get_number(reply, "error_code") != 0);
			CHECK(vm.destroyed == destroyed);
			nvlist_destroy(reply);
		}
	}
	fd = connect_recovery();
	CHECK(fd >= 0);
	nvlist_move_descriptor(request, "fd", fd);
	source_credentials(request);
	reply = ipc_call("migrate_recover", request);
	nvlist_destroy(request);
	snprintf(path, sizeof(path), "%s/source-recover", workdir);
	out = fopen(path, "w");
	CHECK(out != NULL);
	fprintf(out, "confirmed %d\nerror_code %d\nrunnable %d\n",
	    nvlist_get_bool(reply, "confirmed"),
	    nvlist_exists_number(reply, "error_code") ?
	    (int)nvlist_get_number(reply, "error_code") : 0,
	    nvlist_get_bool(reply, "source_runnable"));
	fprintf(out, "state cpus_paused %d devices_paused %d console_paused %d destroyed %d\n",
	    vm.cpus_paused, vm.devices_paused, vm.console_paused, vm.destroyed);
	fclose(out);
	event("E source_recover_returned %d", nvlist_get_bool(reply, "confirmed"));
	nvlist_destroy(reply);
}

/* Operator repair of a wedged source, then a second (redundant) request. */
static void
source_repair(void)
{
	nvlist_t *reply;
	char path[400];
	FILE *out;

	snprintf(path, sizeof(path), "%s/source-repair", workdir);
	out = fopen(path, "w");
	CHECK(out != NULL);
	for (int i = 0; i < 2; i++) {
		reply = ipc_call("migrate_repair", NULL);
		fprintf(out, "repaired%d %d\nattempts%d %d\nerror%d %d\nrunnable%d %d\n",
		    i, reply_bool(reply, "repaired"), i, reply_number(reply, "repair_attempts"),
		    i, reply_number(reply, "error_code"), i, reply_bool(reply, "source_runnable"));
		nvlist_destroy(reply);
	}
	fprintf(out, "state cpus_paused %d devices_paused %d console_paused %d wedged %d "
	    "gdb_fenced %d\n", vm.cpus_paused, vm.devices_paused, vm.console_paused, wedged,
	    gdb_fenced);
	fclose(out);
}

static void
restart_credentials(struct migration_tls_credentials *c)
{
	char hex[65];

	c->certificate_fd = open_file("source.pem");
	c->private_key_fd = open_file("source.key");
	c->trust_fd = open_file("destination.pem");
	read_pin("destination.pin", hex);
	CHECK(migration_credentials_pin(hex, c->peer_certificate_sha256) == 0);
}

static int
journal_root(void)
{
	char path[400];
	int fd;

	snprintf(path, sizeof(path), "%s/anchor/var/db/bhyve/migration", workdir);
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(fd >= 0);
	return (fd);
}

/* A restarted source bhyve (no VM context): recovery from the durable
 * journal only.  Runs in its own process; results go to restart-<tag>. */
static void
restart_recovery(const char *tag, const char *name, bool twice)
{
	pid_t child;
	int status;

	fflush(stdout);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		struct migration_tls_credentials c;
		char path[400];
		FILE *out;
		int error, dirfd, fd;

		role = 'R';
		alarm(60);
		restart_credentials(&c);
		dirfd = journal_root();
		snprintf(path, sizeof(path), "%s/restart-%s", workdir, tag);
		out = fopen(path, "w");
		CHECK(out != NULL);
		for (int i = 0; i < (twice ? 2 : 1); i++) {
			fd = connect_recovery();	/* -1 once no destination listens */
			error = i == 0 && twice ?
			    migration_prod_source_recover_restart_named(fd, dirfd, 7, 70, &c, NULL) :
			    migration_prod_source_recover_restart_named(fd, dirfd, 7, 70, &c, name);
			if (fd >= 0)
				close(fd);
			fprintf(out, "error%d %d\n", i, error);
			fflush(out);
		}
		fclose(out);
		exit(0);
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);
}

static void
recover_by_restart(const struct scenario *s, struct outcome *o)
{
	(void)s;
	(void)o;
	/* First without the local name (no destruction authority), then with it. */
	restart_recovery("crashed", "migrating-vm", true);
}

/* ------------------------------------------ destination reconstruction */
static bool
image_challenge(uint8_t challenge[32], char *hex, size_t size)
{
	char path[400];
	DIR *d;
	struct dirent *e;
	bool found = false;

	snprintf(path, sizeof(path), "%s/destination-journal", workdir);
	d = opendir(path);
	CHECK(d != NULL);
	while ((e = readdir(d)) != NULL) {
		size_t n = strlen(e->d_name);
		if (n == 2 + 64 + 6 && strncmp(e->d_name, "d-", 2) == 0 &&
		    strcmp(e->d_name + n - 6, ".image") == 0) {
			for (int i = 0; i < 32; i++) {
				unsigned v;
				CHECK(sscanf(e->d_name + 2 + 2 * i, "%2x", &v) == 1);
				challenge[i] = (uint8_t)v;
			}
			strlcpy(hex, e->d_name + 2, size < 65 ? size : 65);
			found = true;
		}
	}
	closedir(d);
	return (found);
}

/* A successor bhyve (new kernel lifetime 10/100) for a lost destination
 * controller: admission before Capsicum, then reconstruction from HDI1 and
 * managed service until authenticated recovery resumes it. */
static void __attribute__((noreturn))
run_successor(const char *name, uint16_t vmid, uint64_t epoch, bool serve)
{
	struct migration_session_config config = {0};
	struct migration_tls_credentials credentials;
	struct migration_dest_result result;
	struct migration_prod_reconstruct *state = NULL;
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	uint8_t challenge[32];
	char hex[65], path[400];
	FILE *out;
	int error, dirfd, listener;

	role = 'N';
	nfaults = 0;
	vm_model_init(vmid, epoch, 0x55);
	devices_init();
	vm.fenced = true;
	tracing_mode = true;
	destination_credentials(&credentials);
	snprintf(path, sizeof(path), "%s/destination-journal", workdir);
	dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(dirfd >= 0 && image_challenge(challenge, hex, sizeof(hex)));
	error = migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge, name, &state);
	snprintf(path, sizeof(path), "%s/successor-%u", workdir, vmid);
	out = fopen(path, "w");
	CHECK(out != NULL);
	fprintf(out, "begin %d\n", error);
	fflush(out);
	if (error != 0 || !serve) {
		if (state != NULL)
			migration_prod_dest_reconstruct_abandon(state);
		fclose(out);
		exit(0);
	}
	config.version_max = MIGRATION_PROTO_VERSION;
	config.version_min = MIGRATION_PROTO_VERSION_MIN;
	config.tls_credentials = &credentials;
	config.recovery_enabled = true;
	config.recovery_dirfd = dirfd;
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	snprintf(address.sun_path, sizeof(address.sun_path), "%s/recovery.sock", workdir);
	(void)unlink(address.sun_path);
	CHECK(listener >= 0 && bind(listener, (struct sockaddr *)&address,
	    sizeof(address)) == 0 && listen(listener, 4) == 0);
	event("E successor_listening");
	error = migration_prod_dest_reconstruct_managed(&vm, state, listener, &config, &result);
	fprintf(out, "error %d\nresumed %d\nphase %u\nram_crc %08lx\nblob %zu\nresumes %d\n",
	    error, result.resumed, result.phase,
	    crc32(crc32(0, vm.low, LOWMEM), vm.high, HIGHMEM), committed_len, vm.resumes);
	fclose(out);
	exit(0);
}

static pid_t
start_successor(const char *name, uint16_t vmid, uint64_t epoch, bool serve)
{
	pid_t child;

	fflush(stdout);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		alarm(60);
		run_successor(name, vmid, epoch, serve);
	}
	return (child);
}

static void
wait_child(pid_t child)
{
	int status;

	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);
}

static int
successor_value(uint16_t vmid, const char *key)
{
	char file[64];

	snprintf(file, sizeof(file), "successor-%u", vmid);
	return (kv_int(file, key));
}

/*
 * Admission refusals of migration_prod_dest_reconstruct_prepared(): every
 * refusal consumes its admitted state, so each row admits a fresh successor
 * lifetime (20+i / 200+i, retiring the previous one by name) and then breaks
 * exactly one prerequisite.  Oracle: the documented error of that check, the
 * state is consumed (no owner), and the previous lifetime was destroyed.
 */
enum refusal { R_CTX, R_CONFIG, R_RESULT, R_OWNER, R_OWNER_SET, R_TRACING,
	R_RECOVERY, R_TLS, R_FENCE, R_DIRFD, R_OTHER_DIR, R_IDENTITY_FAIL,
	R_IDENTITY, R_GEOMETRY, R_IMAGE_MAP, R_COMMIT_STATE, R_IDENTITY_VMID,
	R_IDENTITY_NOERRNO, R_HIGHMEM_BASE, R_HIGHMEM_LENGTH, R_OTHER_DEVICE, R_COUNT };
static const struct { enum refusal what; int error; const char *label; } refusal_table[] = {
	{ R_CTX, EINVAL, "ctx" }, { R_CONFIG, EINVAL, "config" },
	{ R_RESULT, EINVAL, "result" }, { R_OWNER, EINVAL, "owner" },
	{ R_OWNER_SET, EINVAL, "owner-set" }, { R_TRACING, EOPNOTSUPP, "tracing" },
	{ R_RECOVERY, EACCES, "recovery" }, { R_TLS, EACCES, "tls" },
	{ R_FENCE, EBUSY, "fence" }, { R_DIRFD, EBADF, "dirfd" },
	{ R_OTHER_DIR, EXDEV, "other-dir" }, { R_IDENTITY_FAIL, ENXIO, "identity-fail" },
	{ R_IDENTITY, ESTALE, "identity" }, { R_GEOMETRY, ESTALE, "geometry" },
	{ R_IMAGE_MAP, -1, "image-map" }, { R_COMMIT_STATE, ENOMEM, "commit-state" },
	{ R_IDENTITY_VMID, ESTALE, "identity-vmid" }, { R_IDENTITY_NOERRNO, EIO, "identity-noerrno" },
	{ R_HIGHMEM_BASE, ESTALE, "highmem-base" }, { R_HIGHMEM_LENGTH, ESTALE, "highmem-length" },
	{ R_OTHER_DEVICE, EXDEV, "other-device" },
};

static int private_dir(const char *, mode_t);

static void __attribute__((noreturn))
run_reconstruct_refusals(void)
{
	struct migration_session_config config = {0};
	struct migration_tls_credentials credentials;
	struct migration_dest_result result;
	uint8_t challenge[32];
	char hex[65], path[400];
	FILE *out;
	int dirfd, other;

	role = 'N';
	nfaults = 0;
	destination_credentials(&credentials);
	snprintf(path, sizeof(path), "%s/destination-journal", workdir);
	dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(dirfd >= 0 && image_challenge(challenge, hex, sizeof(hex)));
	other = private_dir("not-the-journal", 0700);
	snprintf(path, sizeof(path), "%s/refusals", workdir);
	out = fopen(path, "w");
	CHECK(out != NULL);
	for (size_t i = 0; i < nitems(refusal_table); i++) {
		struct migration_prod_reconstruct *state = NULL;
		struct migration_prod_dest *owner = NULL, *preset = (void *)&config;
		struct migration_session_config *cp = &config;
		struct migration_dest_result *rp = &result;
		struct migration_prod_dest **op = &owner;
		struct vmctx *ctx = &vm;
		int begin, error;

		vm_model_init((uint16_t)(20 + i), 200 + i, 0x55);
		devices_init();
		vm.fenced = true;
		tracing_mode = true;
		fake_lowmem = LOWMEM;
		fake_highmem = HIGHMEM;
		fake_highbase = HIGHBASE;
		memset(&config, 0, sizeof(config));
		config.version_max = MIGRATION_PROTO_VERSION;
		config.version_min = MIGRATION_PROTO_VERSION_MIN;
		config.tls_credentials = &credentials;
		config.recovery_enabled = true;
		config.recovery_dirfd = dirfd;
		begin = migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge,
		    "migrating-vm", &state);
		CHECK(begin == 0 && state != NULL);
		switch (refusal_table[i].what) {
		case R_CTX: ctx = NULL; break;
		case R_CONFIG: cp = NULL; break;
		case R_RESULT: rp = NULL; break;
		case R_OWNER: op = NULL; break;
		case R_OWNER_SET: op = &preset; break;
		case R_TRACING: tracing_mode = false; break;
		case R_RECOVERY: config.recovery_enabled = false; break;
		case R_TLS: config.tls_credentials = NULL; break;
		case R_FENCE: vm.fenced = false; break;
		case R_DIRFD: config.recovery_dirfd = -1; break;
		case R_OTHER_DIR: config.recovery_dirfd = other; break;
		case R_IDENTITY_FAIL:
			nfaults = 1;
			faults[0].role = 'N';
			strlcpy(faults[0].name, "vm_get_identity", sizeof(faults[0].name));
			faults[0].occurrence = *boundary_count("vm_get_identity") + 1;
			faults[0].error = ENXIO;
			break;
		case R_IDENTITY: vm.epoch++; break;
		case R_IDENTITY_VMID: vm.vmid++; break;
		case R_IDENTITY_NOERRNO:
			nfaults = 1;
			faults[0].role = 'N';
			strlcpy(faults[0].name, "vm_get_identity", sizeof(faults[0].name));
			faults[0].occurrence = *boundary_count("vm_get_identity") + 1;
			faults[0].error = FAULT_NOERRNO;
			break;
		case R_GEOMETRY: fake_lowmem = LOWMEM - PAGE; break;
		case R_HIGHMEM_BASE: fake_highbase = HIGHBASE + PAGE; break;
		case R_HIGHMEM_LENGTH: fake_highmem = HIGHMEM - PAGE; break;
		case R_OTHER_DEVICE:
			/* The same inode number could exist on another file system. */
			config.recovery_dirfd = open("/dev", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
			CHECK(config.recovery_dirfd >= 0);
			break;
		case R_IMAGE_MAP:
			nfaults = 1;
			faults[0].role = 'N';
			strlcpy(faults[0].name, "vm_map_gpa", sizeof(faults[0].name));
			faults[0].occurrence = *boundary_count("vm_map_gpa") + 1;
			faults[0].error = EFAULT;
			break;
		case R_COMMIT_STATE:
			nfaults = 1;
			faults[0].role = 'N';
			strlcpy(faults[0].name, "vm_migrate_fresh_commit_state",
			    sizeof(faults[0].name));
			faults[0].occurrence =
			    *boundary_count("vm_migrate_fresh_commit_state") + 1;
			faults[0].error = ENOMEM;
			break;
		default: abort();
		}
		error = migration_prod_dest_reconstruct_prepared(ctx, state, cp, rp, op);
		nfaults = 0;
		fprintf(out, "%s %d owner %d previous_destroyed %d\n", refusal_table[i].label,
		    error, owner != NULL,
		    kernel_has("destroyed", i == 0 ? 9 : (uint16_t)(19 + i),
		    i == 0 ? 90 : 199 + i));
	}
	fclose(out);
	/* Abandoning an admitted controller before any guest state was loaded
	 * releases the controller lock: a second admission succeeds. */
	{
		struct migration_prod_reconstruct *state = NULL;
		int first, second;

		snprintf(path, sizeof(path), "%s/abandon", workdir);
		out = fopen(path, "w");
		CHECK(out != NULL);
		for (int k = 0; k < 2; k++) {
			vm_model_init((uint16_t)(60 + k), 600 + k, 0x55);
			devices_init();
			vm.fenced = true;
			tracing_mode = true;
			fake_lowmem = LOWMEM;
			fake_highmem = HIGHMEM;
			fake_highbase = HIGHBASE;
			*(k == 0 ? &first : &second) = migration_prod_dest_reconstruct_begin(&vm,
			    dirfd, challenge, "migrating-vm", &state);
			fprintf(out, "%d %d\n", k == 0 ? first : second, state != NULL);
			migration_prod_dest_reconstruct_abandon(state);
			state = NULL;
		}
		fclose(out);
	}
	exit(0);
}

static void
check_reconstruct_refusals(void)
{
	char line[200];
	FILE *in;
	char path[400];
	size_t row = 0;

	snprintf(path, sizeof(path), "%s/refusals", workdir);
	in = fopen(path, "r");
	CHECK(in != NULL);
	while (fgets(line, sizeof(line), in) != NULL) {
		char label[32];
		int error, owner, destroyed;
		CHECK(sscanf(line, "%31s %d owner %d previous_destroyed %d", label, &error,
		    &owner, &destroyed) == 4);
		CHECK(row < nitems(refusal_table) &&
		    strcmp(label, refusal_table[row].label) == 0);
		if (refusal_table[row].error == -1)
			CHECK(error != 0);
		else if (error != refusal_table[row].error)
			fprintf(stderr, "refusal %s: got %d want %d\n", label, error,
			    refusal_table[row].error);
		CHECK(refusal_table[row].error == -1 || error == refusal_table[row].error);
		CHECK(owner == 0 && destroyed == 1);
		row++;
	}
	fclose(in);
	CHECK(row == nitems(refusal_table));
	snprintf(path, sizeof(path), "%s/abandon", workdir);
	in = fopen(path, "r");
	CHECK(in != NULL);
	for (int k = 0; k < 2; k++) {
		int error, admitted;
		CHECK(fgets(line, sizeof(line), in) != NULL &&
		    sscanf(line, "%d %d", &error, &admitted) == 2);
		CHECK(error == 0 && admitted == 1);
	}
	fclose(in);
	printf("reconstruction admission refusals: %zu rows, abandon releases the lock\n", row);
}

static void
recover_by_reconstruction(const struct scenario *s, struct outcome *o)
{
	pid_t successor;
	int status;

	(void)s;
	(void)o;
	/* While the original controller lives, no successor is admitted. */
	wait_child(start_successor("migrating-vm", 10, 100, false));
	CHECK(successor_value(10, "begin") == EBUSY);
	/* Controller loss: the destination process dies abruptly (its counters
	 * are flushed by the test-only handler first). */
	CHECK(kill(destination_pid, SIGUSR1) == 0);
	CHECK(waitpid(destination_pid, &status, 0) == destination_pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 77);
	destination_pid = 0;
	/* The new context must be a distinct lifetime. */
	wait_child(start_successor("migrating-vm", 9, 90, false));
	CHECK(successor_value(9, "begin") == EBUSY);
	/* The previous incarnation still exists: without a name it is not
	 * retired and admission fails; nothing is published. */
	wait_child(start_successor(NULL, 11, 110, false));
	CHECK(successor_value(11, "begin") == EBUSY);
	/* With the local name the exact previous lifetime is destroyed: first
	 * by each row of the refusal table, then by the serving successor. */
	{
		pid_t child;
		fflush(stdout);
		child = fork();
		CHECK(child >= 0);
		if (child == 0) {
			alarm(60);
			run_reconstruct_refusals();
		}
		wait_child(child);
		check_reconstruct_refusals();
	}
	CHECK(count_events("N E destroyed vm9 name") == 1);
	successor = start_successor("migrating-vm", 10, 100, true);
	for (int i = 0; i < 3000 && count_events("N E successor_listening") == 0; i++)
		usleep(2000);
	{
		char last[64];
		snprintf(last, sizeof(last), "N E destroyed vm%zu name",
		    19 + nitems(refusal_table));
		CHECK(count_events(last) == 1);
	}
	/* The source (already retired before it was lost) completes RETIRED
	 * and releases the successor through the recovery protocol. */
	restart_recovery("successor", NULL, false);
	CHECK(kv_int("restart-successor", "error0") == 0);
	wait_child(successor);
}

/* Source process body.  Returns only by exit(). */
static void __attribute__((noreturn))
run_source(const struct scenario *s, int fd)
{
	nvlist_t *request, *reply;
	FILE *out;
	char path[400];

	role = 'S';
	vm_model_init(7, 70, 0x11);
	devices_init();
	gdb_refusal = s->gdb_refusal;
	if (s->tracing) {
		setup_anchor();
		CHECK(migration_prod_source_prepare() == 0);
	}
	request = nvlist_create(0);
	nvlist_move_descriptor(request, "fd", fd);
	if (s->tls) {
		source_credentials(request);
		/* An explicit "no" is the same as absent. */
		nvlist_add_bool(request, "plaintext_unix", false);
	} else	/* a local socketpair: the explicit plaintext opt-in */
		nvlist_add_bool(request, "plaintext_unix", true);
	if (s->no_highmem)
		fake_highmem = 0;
	if (s->max_rounds != 0)
		nvlist_add_number(request, "max_rounds", s->max_rounds);
	nvlist_add_number(request, "converge_pages", 1);
	if (s->recovery_dir != NULL) {
		snprintf(path, sizeof(path), "%s/%s", workdir, s->recovery_dir);
		make_dir(path, 0700);
		nvlist_move_descriptor(request, "recovery_fddir",
		    open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	}
	reply = ipc_call("migrate", request);
	nvlist_destroy(request);
	/* Only a failed migration returns: record the reply and the state. */
	snprintf(path, sizeof(path), "%s/source-reply", workdir);
	out = fopen(path, "w");
	CHECK(out != NULL);
	fprintf(out, "runnable %d\nphase %d\nreason %d\n",
	    nvlist_exists_bool(reply, "source_runnable") ?
	    nvlist_get_bool(reply, "source_runnable") : -1,
	    nvlist_exists_number(reply, "phase") ? (int)nvlist_get_number(reply, "phase") : -1,
	    nvlist_exists_number(reply, "reason") ? (int)nvlist_get_number(reply, "reason") : -1);
	fprintf(out, "repaired %d\nattempts %d\n",
	    nvlist_exists_bool(reply, "repaired") ? nvlist_get_bool(reply, "repaired") : -1,
	    nvlist_exists_number(reply, "repair_attempts") ?
	    (int)nvlist_get_number(reply, "repair_attempts") : -1);
	fprintf(out, "error %s\n", nvlist_exists_string(reply, "error") ?
	    nvlist_get_string(reply, "error") : "-");
	fprintf(out, "state cpus_paused %d devices_paused %d console_paused %d destroyed %d "
	    "quarantined %d wedged %d gdb_fenced %d\n", vm.cpus_paused, vm.devices_paused,
	    vm.console_paused, vm.destroyed, quarantined, wedged, gdb_fenced);
	fclose(out);
	event("E source_returned");
	nvlist_destroy(reply);
	/* The driver decides whether the operator recovers through this process. */
	char command = 'X';
	(void)read(control_fd, &command, 1);
	if (command == 'R')
		source_recover(s);
	if (command == 'P')
		source_repair();
	exit(0);
}

static void __attribute__((noreturn))
run_destination(const struct scenario *s, int fd)
{
	struct migration_session_config config = {0};
	struct migration_tls_credentials credentials;
	struct migration_dest_result result;
	char path[400];
	FILE *out;
	int error, listener = -1, dirfd = -1;

	role = 'D';
	signal(SIGUSR1, lose_on_signal);
	vm_model_init(9, 90, 0x99);
	devices_init();
	vm.fenced = true;
	if (s->no_highmem)
		fake_highmem = 0;
	config.version_max = MIGRATION_PROTO_VERSION;
	config.version_min = MIGRATION_PROTO_VERSION_MIN;
	if (s->tls) {
		destination_credentials(&credentials);
		config.tls_credentials = &credentials;
	} else
		config.plaintext_unix = true;
	if (s->dest_recovery && !s->tracing) {
		snprintf(path, sizeof(path), "%s/destination-journal", workdir);
		make_dir(path, 0700);
		dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		CHECK(dirfd >= 0);
		config.recovery_enabled = true;
		config.recovery_dirfd = dirfd;
	}
	if (s->tracing) {
		snprintf(path, sizeof(path), "%s/destination-journal", workdir);
		make_dir(path, 0700);
		dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		CHECK(dirfd >= 0);
		config.recovery_enabled = true;
		config.recovery_dirfd = dirfd;
		config.recovery_image = s->recovery_image;
	}
	if (s->managed) {
		struct sockaddr_un address = { .sun_family = AF_UNIX };
		listener = socket(AF_UNIX, SOCK_STREAM, 0);
		snprintf(address.sun_path, sizeof(address.sun_path), "%s/recovery.sock", workdir);
		CHECK(listener >= 0 && bind(listener, (struct sockaddr *)&address,
		    sizeof(address)) == 0 && listen(listener, 4) == 0);
		error = migration_prod_dest_serve_managed(&vm, fd, listener, &config, &result);
	} else
		error = migration_prod_dest_serve(&vm, fd, &config, &result);
	int resolve_checks = s->dest_resolve != NULL ?
	    s->dest_resolve(s, &result, error) : -1;
	snprintf(path, sizeof(path), "%s/destination-result", workdir);
	out = fopen(path, "w");
	CHECK(out != NULL);
	fprintf(out, "resolve %d\n", resolve_checks);
	fprintf(out, "error %d\nphase %u\nreason %u\nresumed %d\nretained %d\nack %d\n",
	    error, result.phase, result.reason, result.resumed, result.retained,
	    result.release_ack_sent);
	fprintf(out, "resumes %d\nram_crc %08lx\nblob %zu\n", vm.resumes,
	    crc32(crc32(0, vm.low, LOWMEM), vm.high, HIGHMEM), committed_len);
	fclose(out);
	event("E destination_returned %d", error);
	exit(0);
}

/* ----------------------------------------------------------- oracle */
struct outcome {
	int source_status;		/* exit status of the source process */
	bool source_replied;
	int runnable, phase, reason, repaired, attempts;
	char error[256], state[256];
	int dest_error, dest_resumed, dest_resumes, dest_retained;
	unsigned long dest_crc;
	size_t dest_blob;
	unsigned long source_crc;	/* source RAM at quiesce */
	bool fault_fired, dest_blocked, recovered, dest_crashed;
	int recover_confirmed, recover_error;
	int events_source_destroyed, events_dest_resumed;
};

static void
read_kv(const char *file, const char *key, char *value, size_t size)
{
	char path[400], line[512];
	FILE *f;

	value[0] = '\0';
	snprintf(path, sizeof(path), "%s/%s", workdir, file);
	f = fopen(path, "r");
	if (f == NULL)
		return;
	while (fgets(line, sizeof(line), f) != NULL)
		if (strncmp(line, key, strlen(key)) == 0 && line[strlen(key)] == ' ') {
			strlcpy(value, line + strlen(key) + 1, size);
			value[strcspn(value, "\n")] = '\0';
			break;
		}
	fclose(f);
}

static int
kv_int(const char *file, const char *key)
{
	char v[64];

	read_kv(file, key, v, sizeof(v));
	return (v[0] == '\0' ? -99 : (int)strtol(v, NULL, 0));
}

/* Invariants over the merged event log of both processes. */
static void
check_events(const char *label, struct outcome *o)
{
	char path[400], line[300];
	FILE *f;
	double retire_begin = -1, destroyed = -1, first_dest_resume = -1;
	int dest_resumes = 0;
	bool source_resumed_after_retire = false;

	snprintf(path, sizeof(path), "%s/events", workdir);
	f = fopen(path, "r");
	CHECK(f != NULL);
	while (fgets(line, sizeof(line), f) != NULL) {
		char who, what[64] = "", arg[64] = "";
		double ts;

		if (sscanf(line, "%c %lf E %63s %63s", &who, &ts, what, arg) < 3) {
			if (strstr(line, " F ") != NULL)
				o->fault_fired = true;
			continue;
		}
		if (who == 'S' && (strcmp(what, "quarantined") == 0 ||
		    strcmp(what, "retire_cpus_begin") == 0) && retire_begin < 0)
			retire_begin = ts;
		if (strcmp(what, "destroyed") == 0 && strcmp(arg, "vm7") == 0) {
			destroyed = ts;
			o->events_source_destroyed++;
		}
		if (who == 'S' && retire_begin >= 0 && (strcmp(what, "cpus_resumed") == 0 ||
		    strcmp(what, "devices_resumed") == 0 || strcmp(what, "console_resumed") == 0))
			source_resumed_after_retire = true;
		if ((who == 'D' || who == 'N') && strcmp(what, "dest_resumed") == 0) {
			dest_resumes++;
			if (first_dest_resume < 0)
				first_dest_resume = ts;
		}
	}
	fclose(f);
	o->events_dest_resumed = dest_resumes;
	if (source_resumed_after_retire || dest_resumes > 1 ||
	    (first_dest_resume >= 0 && (destroyed < 0 || destroyed > first_dest_resume))) {
		fprintf(stderr, "%s: invariant violated (resume-after-retire %d, dest resumes %d, "
		    "destroyed %f, dest resume %f)\n", label, source_resumed_after_retire,
		    dest_resumes, destroyed, first_dest_resume);
		abort();
	}
}

static void
run_scenario(const struct scenario *s, const char *fault, struct outcome *o)
{
	int pair[2], status;
	pid_t source, destination;
	char path[400];

	memset(o, 0, sizeof(*o));
	snprintf(workdir, sizeof(workdir), "%s", "work.XXXXXX");
	CHECK(mkdtemp(workdir) != NULL);
	{
		char absolute[256];
		CHECK(realpath(workdir, absolute) != NULL);
		strlcpy(workdir, absolute, sizeof(workdir));
	}
	snprintf(path, sizeof(path), "%s/events", workdir);
	event_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	CHECK(event_fd >= 0);
	tracing_mode = s->tracing;
	topology_variant = s->topology_variant;
	nfaults = 0;
	for (const char *spec = fault; spec != NULL && *spec != '\0'; ) {
		CHECK(nfaults < MAX_FAULTS);
		CHECK(sscanf(spec, "%c:%63[^:]:%d:%d", &faults[nfaults].role,
		    faults[nfaults].name, &faults[nfaults].occurrence,
		    &faults[nfaults].error) == 4);
		nfaults++;
		spec = strchr(spec, ',');
		if (spec != NULL)
			spec++;
	}
	int control[2];
	CHECK(pipe2(control, O_CLOEXEC) == 0);
	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
	fflush(stdout);
	fflush(stderr);
	destination = fork();
	CHECK(destination >= 0);
	destination_pid = destination;
	if (destination == 0) {
		alarm(60);
		close(pair[0]);
		run_destination(s, pair[1]);
	}
	source = fork();
	CHECK(source >= 0);
	if (source == 0) {
		alarm(60);
		close(pair[1]);
		close(control[1]);
		control_fd = control[0];
		run_source(s, pair[0]);
	}
	close(pair[0]);
	close(pair[1]);
	close(control[0]);
	/* Wait for the source to commit (exit) or to reply (then it waits for a
	 * control byte), and give the destination time to finish. */
	bool source_done = false, dest_done = false;
	int dest_status = 0;
	char reply_path[400];
	snprintf(reply_path, sizeof(reply_path), "%s/source-reply", workdir);
	for (int i = 0; i < 6000 && !source_done; i++) {
		if (waitpid(source, &status, WNOHANG) == source)
			source_done = true;
		else if (access(reply_path, F_OK) == 0 && count_events("S E source_returned") > 0)
			break;
		else
			usleep(2000);
	}
	for (int i = 0; i < 300 && !dest_done; i++) {
		if (waitpid(destination, &dest_status, WNOHANG) == destination)
			dest_done = true;
		else
			usleep(10000);
	}
	/* A retained destination waits (by design) for authenticated recovery. */
	if (!dest_done && !source_done && s->restart_probe)
		restart_recovery("probe", NULL, false);
	char command = !dest_done && s->recover_ipc && !source_done ? 'R' : 'X';
	if (!source_done && s->repair_ipc && count_events("S E wedged") > 0)
		command = 'P';
	if (!source_done) {
		CHECK(write(control[1], &command, 1) == 1);
		CHECK(waitpid(source, &status, 0) == source);
	}
	close(control[1]);
	o->source_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	o->recovered = command == 'R';
	if (!dest_done && command != 'R' && s->recover != NULL) {
		s->recover(s, o);
		if (destination_pid == 0) {	/* the hook replaced the destination */
			dest_done = true;
			dest_status = 0;
		}
	}
	for (int i = 0; i < 300 && !dest_done; i++) {
		if (waitpid(destination, &dest_status, WNOHANG) == destination)
			dest_done = true;
		else
			usleep(10000);
	}
	if (!dest_done) {
		o->dest_blocked = true;
		CHECK(kill(destination, SIGUSR1) == 0);
		CHECK(waitpid(destination, &dest_status, 0) == destination);
	} else {
		CHECK(WIFEXITED(dest_status));
		o->dest_crashed = WEXITSTATUS(dest_status) == 77;
		CHECK(WEXITSTATUS(dest_status) == 0 || o->dest_crashed);
	}
	o->recover_confirmed = kv_int("source-recover", "confirmed");
	o->recover_error = kv_int("source-recover", "error_code");
	close(event_fd);
	event_fd = -1;
	o->source_replied = o->source_status == 0;
	o->runnable = kv_int("source-reply", "runnable");
	o->phase = kv_int("source-reply", "phase");
	o->reason = kv_int("source-reply", "reason");
	o->repaired = kv_int("source-reply", "repaired");
	o->attempts = kv_int("source-reply", "attempts");
	read_kv("source-reply", "error", o->error, sizeof(o->error));
	read_kv("source-reply", "state", o->state, sizeof(o->state));
	o->dest_error = kv_int("destination-result", "error");
	o->dest_resumed = kv_int("destination-result", "resumed");
	o->dest_retained = kv_int("destination-result", "retained");
	o->dest_resumes = kv_int("destination-result", "resumes");
	{
		char v[32];
		read_kv("destination-result", "ram_crc", v, sizeof(v));
		o->dest_crc = strtoul(v, NULL, 16);
		read_kv("destination-result", "blob", v, sizeof(v));
		o->dest_blob = strtoul(v, NULL, 10);
	}
	check_events(s->name, o);
	/* Committed source: exit status 5 only after its own destruction. */
	if (o->source_status == BHYVE_EXIT_SUSPEND)
		CHECK(o->events_source_destroyed == 1);
	else
		CHECK(o->source_status == 0 || (o->source_status == 77 && o->fault_fired));
	if (o->source_replied && o->runnable == 1) {
		CHECK(strstr(o->state, "cpus_paused 0 devices_paused 0 console_paused 0 "
		    "destroyed 0 quarantined 0 wedged 0") != NULL);
	}
	if (o->source_replied && o->runnable == 0)
		CHECK(strstr(o->state, "quarantined 1") != NULL ||
		    strstr(o->state, "wedged 1") != NULL);
	if (o->dest_resumed == 1)
		CHECK(o->events_source_destroyed == 1 && o->dest_resumes == 1);
}

/* Expected source RAM at quiesce, computed independently from the guest
 * write model: the guest writes during every collection while running. */
static unsigned long
expected_ram_crc(int collects_before_pause)
{
	char saved = role;
	unsigned long crc;

	int saved_fd = event_fd;

	event_fd = -1;
	vm_model_init(7, 70, 0x11);
	for (int round = 1; round <= collects_before_pause; round++)
		guest_writes(round);
	crc = crc32(crc32(0, vm.low, LOWMEM), vm.high, HIGHMEM);
	event_fd = saved_fd;
	role = saved;
	return (crc);
}

/* A destination without high memory receives low memory only; its own high
 * memory model keeps the destination seed. */
static unsigned long
expected_ram_crc_lowmem(int collects_before_pause)
{
	char saved = role;
	int saved_fd = event_fd;
	unsigned long crc;

	event_fd = -1;
	vm_model_init(7, 70, 0x11);
	for (int round = 1; round <= collects_before_pause; round++)
		guest_writes(round);
	crc = crc32(0, vm.low, LOWMEM);
	vm_model_init(9, 90, 0x99);
	crc = crc32(crc, vm.high, HIGHMEM);
	event_fd = saved_fd;
	role = saved;
	return (crc);
}

static int
count_events(const char *who_what)
{
	char path[400], line[300];
	FILE *f;
	int n = 0;

	snprintf(path, sizeof(path), "%s/events", workdir);
	f = fopen(path, "r");
	CHECK(f != NULL);
	while (fgets(line, sizeof(line), f) != NULL) {
		char *space = strchr(line, ' ');
		char *rest = space != NULL ? strchr(space + 1, ' ') : NULL;
		if (rest != NULL && line[0] == who_what[0] &&
		    strncmp(rest + 1, who_what + 2, strlen(who_what + 2)) == 0)
			n++;
	}
	fclose(f);
	return (n);
}

static void
test_success(const struct scenario *s)
{
	struct outcome o;

	run_scenario(s, NULL, &o);
	CHECK(o.source_status == BHYVE_EXIT_SUSPEND);
	CHECK(o.dest_error == 0 && o.dest_resumed == 1 && o.dest_resumes == 1);
	/* The source collected once per generation; the guest wrote after each
	 * collection until the CPUs paused (after the final collection the
	 * CPUs are already paused). */
	int collects = count_events("S B vm_dirty_log_request") - 2;	/* minus enable/disable */
	int writes = count_events("S E guest_wrote");
	CHECK(collects >= 2 && writes == collects - 1);
	CHECK(o.dest_crc == (s->no_highmem ? expected_ram_crc_lowmem(writes) :
	    expected_ram_crc(writes)));
	CHECK(o.dest_blob == MIGRATE_BLOB_HDR + META_LEN + KERNEL_LEN +
	    (s->tracing ? HYPERTRACE_SESSION_RECORD_SIZE : 0));
	/* INTENT and retirement each assert the irreversible quarantine (every
	 * migration records INTENT since protocol 2's journal). */
	CHECK(count_events("S E quarantined") == 2);
	CHECK(count_events("S E gdb_fenced") == 1 && count_events("S E gdb_retired") == 1);
	printf("success %-24s collections %d, RAM and %zu-byte state equal\n", s->name,
	    collects, o.dest_blob);
}

/* ------------------------------------------- single-process admission */
static const char *
reply_string(const nvlist_t *r, const char *key)
{
	return (nvlist_exists_string(r, key) ? nvlist_get_string(r, key) : "");
}

static int
reply_number(const nvlist_t *r, const char *key)
{
	return (nvlist_exists_number(r, key) ? (int)nvlist_get_number(r, key) : -1);
}

static int
reply_bool(const nvlist_t *r, const char *key)
{
	return (nvlist_exists_bool(r, key) ? nvlist_get_bool(r, key) : -1);
}

static void
in_child(const char *label, void (*fn)(void))
{
	pid_t child;
	int status;

	fflush(stdout);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		alarm(60);
		fn();
		exit(0);
	}
	CHECK(waitpid(child, &status, 0) == child);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "%s failed (status %d)\n", label, status);
		abort();
	}
	printf("%s\n", label);
}

static void
fresh_workdir(void)
{
	char absolute[256];

	snprintf(workdir, sizeof(workdir), "%s", "work.XXXXXX");
	CHECK(mkdtemp(workdir) != NULL);
	CHECK(realpath(workdir, absolute) != NULL);
	strlcpy(workdir, absolute, sizeof(workdir));
}

/* A request whose transport would only be reached through a dead peer. */
static nvlist_t *
dead_peer_request(void)
{
	nvlist_t *request = nvlist_create(0);
	int pair[2];

	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
	close(pair[1]);
	nvlist_move_descriptor(request, "fd", pair[0]);
	return (request);
}

static void
check_untouched_source(void)
{
	CHECK(!vm.cpus_paused && !vm.devices_paused && !vm.console_paused &&
	    !vm.destroyed && !quarantined && !wedged && !gdb_fenced);
	CHECK(*boundary_count("fbsdrun_migration_pause_cpus") == 0);
}

static void
admission_plain(void)
{
	nvlist_t *request, *reply;

	role = 'S';
	fresh_workdir();
	vm_model_init(7, 70, 0x11);
	devices_init();
	tracing_mode = false;
	/* Recovery before any migration has nothing to recover. */
	request = dead_peer_request();
	source_credentials(request);
	reply = ipc_call("migrate_recover", request);
	CHECK(reply_number(reply, "error_code") == EOPNOTSUPP &&
	    reply_bool(reply, "confirmed") == 0 && reply_bool(reply, "source_runnable") == 1);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	/* Repair without any owned context is not permitted. */
	reply = ipc_call("migrate_repair", NULL);
	CHECK(reply_bool(reply, "repaired") == 0 && reply_number(reply, "error_code") == EPERM &&
	    reply_number(reply, "repair_attempts") == 0);
	CHECK(strcmp(reply_string(reply, "error"), "migration repair: Operation not permitted") == 0);
	nvlist_destroy(reply);
	/* No stream descriptor. */
	request = nvlist_create(0);
	reply = ipc_call("migrate", request);
	CHECK(strcmp(reply_string(reply, "error"), strerror(EINVAL)) == 0);
	CHECK(!nvlist_exists_bool(reply, "source_runnable"));
	nvlist_destroy(reply);
	nvlist_destroy(request);
	/* The 32-bit round counter must stay representable. */
	request = dead_peer_request();
	nvlist_add_number(request, "max_rounds", UINT32_MAX);
	reply = ipc_call("migrate", request);
	CHECK(strcmp(reply_string(reply, "error"), "max_rounds exceeds the supported range") == 0);
	CHECK(reply_number(reply, "phase") == MIGRATION_PHASE_FAILED &&
	    reply_number(reply, "reason") == MIGRATION_REASON_STATE &&
	    reply_bool(reply, "source_runnable") == 1);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	/* Incomplete TLS credentials. */
	request = dead_peer_request();
	nvlist_add_string(request, "tls_peer_sha256", "00");
	reply = ipc_call("migrate", request);
	CHECK(strstr(reply_string(reply, "error"), "migration transport setup failed: ") != NULL);
	CHECK(strstr(reply_string(reply, "error"), strerror(EINVAL)) != NULL);
	CHECK(reply_number(reply, "reason") == MIGRATION_REASON_TRANSPORT &&
	    reply_bool(reply, "source_runnable") == 1);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	/* TLS handshake against a vanished peer. */
	request = dead_peer_request();
	source_credentials(request);
	reply = ipc_call("migrate", request);
	CHECK(strstr(reply_string(reply, "error"), "migration transport setup failed") != NULL);
	CHECK(reply_bool(reply, "source_runnable") == 1);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	/* Neither credentials nor the plaintext opt-in: refused (mutual TLS
	 * is required), and the source stays runnable. */
	request = dead_peer_request();
	reply = ipc_call("migrate", request);
	CHECK(strstr(reply_string(reply, "error"), "migration transport setup failed: ") != NULL);
	CHECK(strstr(reply_string(reply, "error"), strerror(EACCES)) != NULL);
	CHECK(reply_number(reply, "reason") == MIGRATION_REASON_TRANSPORT &&
	    reply_bool(reply, "source_runnable") == 1);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	/* The plaintext opt-in admits only an AF_UNIX stream socket. */
	{
		int pp[2];

		CHECK(pipe2(pp, O_CLOEXEC) == 0);
		close(pp[1]);
		request = nvlist_create(0);
		nvlist_move_descriptor(request, "fd", pp[0]);
		nvlist_add_bool(request, "plaintext_unix", true);
		reply = ipc_call("migrate", request);
		CHECK(strstr(reply_string(reply, "error"), strerror(EPROTONOSUPPORT)) != NULL);
		CHECK(reply_bool(reply, "source_runnable") == 1);
		nvlist_destroy(reply);
		nvlist_destroy(request);
	}
	/* A debugger that owns the guest refuses before anything is quiesced. */
	gdb_refusal = "a GDB client is attached";
	request = dead_peer_request();
	nvlist_add_bool(request, "plaintext_unix", true);
	reply = ipc_call("migrate", request);
	CHECK(strcmp(reply_string(reply, "error"),
	    "migration refused: a GDB client is attached") == 0);
	CHECK(reply_number(reply, "reason") == MIGRATION_REASON_STATE &&
	    reply_bool(reply, "source_runnable") == 1);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	gdb_refusal = NULL;
	check_untouched_source();
	/* With an owned but running context there is nothing to repair. */
	reply = ipc_call("migrate_repair", NULL);
	CHECK(reply_bool(reply, "repaired") == 0 && reply_number(reply, "error_code") == EALREADY);
	nvlist_destroy(reply);
	/* Recovery is refused for a source that never began retirement. */
	request = dead_peer_request();
	reply = ipc_call("migrate_recover", request);
	CHECK(reply_bool(reply, "confirmed") == 0 &&
	    reply_number(reply, "error_code") == EOPNOTSUPP &&
	    reply_bool(reply, "source_runnable") == 1);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	check_untouched_source();
}

static void
admission_fresh(void)
{
	nvlist_t *request, *reply;
	char path[400];

	role = 'S';
	fresh_workdir();
	vm_model_init(7, 70, 0x11);
	devices_init();
	tracing_mode = true;
	/* The source journal root was never prepared. */
	request = dead_peer_request();
	source_credentials(request);
	reply = ipc_call("migrate", request);
	CHECK(strstr(reply_string(reply, "error"), strerror(ENXIO)) != NULL);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	setup_anchor();
	CHECK(migration_prod_source_prepare() == 0);
	CHECK(migration_prod_source_prepare() == 0);	/* idempotent */
	/* Fresh tracing requires authenticated transport, even with the
	 * plaintext opt-in. */
	for (int optin = 0; optin < 2; optin++) {
		request = dead_peer_request();
		if (optin)
			nvlist_add_bool(request, "plaintext_unix", true);
		reply = ipc_call("migrate", request);
		CHECK(strstr(reply_string(reply, "error"), strerror(EACCES)) != NULL);
		CHECK(reply_bool(reply, "source_runnable") == 1);
		nvlist_destroy(reply);
		nvlist_destroy(request);
	}
	/* A different private directory never replaces the pinned root.  The
	 * handshake succeeds only against a live peer, so use a TLS peer that
	 * completes a handshake in a thread. */
	snprintf(path, sizeof(path), "%s/other", workdir);
	make_dir(path, 0700);
	request = dead_peer_request();
	source_credentials(request);
	nvlist_move_descriptor(request, "recovery_fddir",
	    open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	reply = ipc_call("migrate", request);
	/* The dead peer fails the handshake first; the root check needs a
	 * connected channel (covered by the two-process scenarios). */
	CHECK(strstr(reply_string(reply, "error"), "transport setup failed") != NULL);
	nvlist_destroy(reply);
	nvlist_destroy(request);
	check_untouched_source();
}

/* ------------------------------------------- adapter entry contracts */
static int
private_dir(const char *name, mode_t mode)
{
	char path[400];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", workdir, name);
	make_dir(path, mode);
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(fd >= 0);
	return (fd);
}

static int
dead_peer(void)
{
	int pair[2];

	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
	close(pair[1]);
	return (pair[0]);
}

static void
destination_contracts(void)
{
	struct migration_session_config config = {0};
	struct migration_tls_credentials credentials;
	struct migration_dest_result result;
	struct migration_prod_dest *owner = NULL, *busy = (void *)&config;
	int dirfd, open_dir;

	role = 'D';
	fresh_workdir();
	vm_model_init(9, 90, 0x99);
	devices_init();
	destination_credentials(&credentials);
	dirfd = private_dir("journal", 0700);
	open_dir = private_dir("public", 0755);
	tracing_mode = false;
	CHECK(migration_prod_dest_serve_prepared(&vm, 3, &config, &result, NULL) == EINVAL);
	CHECK(migration_prod_dest_serve_prepared(&vm, 3, &config, &result, &busy) == EBUSY);
	CHECK(migration_prod_dest_serve(NULL, 3, &config, &result) == EINVAL);
	CHECK(migration_prod_dest_serve(&vm, 3, NULL, &result) == EINVAL);
	CHECK(migration_prod_dest_serve(&vm, 3, &config, NULL) == EINVAL);
	/* An image is preserved only for a retained fresh owner. */
	config.recovery_image = true;
	CHECK(migration_prod_dest_serve(&vm, 3, &config, &result) == EINVAL);
	CHECK(result.phase == MIGRATION_PHASE_FAILED && result.reason == MIGRATION_REASON_STATE);
	config.recovery_image = false;
	/* A recoverable owner duplicates its journal directory first. */
	config.recovery_enabled = true;
	config.recovery_dirfd = -1;
	CHECK(migration_prod_dest_serve_prepared(&vm, 3, &config, &result, &owner) == EBADF);
	CHECK(owner == NULL && result.reason == MIGRATION_REASON_STATE);
	/* Transport setup failure is reported as a transport reason. */
	config.recovery_dirfd = dirfd;
	config.tls_credentials = &credentials;
	CHECK(migration_prod_dest_serve_prepared(&vm, dead_peer(), &config, &result,
	    &owner) != 0);
	CHECK(owner == NULL && result.phase == MIGRATION_PHASE_FAILED &&
	    result.reason == MIGRATION_REASON_TRANSPORT);
	/* Fresh tracing: only the managed receiver may serve. */
	tracing_mode = true;
	vm.fenced = true;
	CHECK(migration_prod_dest_serve(&vm, 3, &config, &result) == EOPNOTSUPP);
	CHECK(result.reason == MIGRATION_REASON_STATE);
	config.recovery_enabled = false;
	CHECK(migration_prod_dest_serve_prepared(&vm, 3, &config, &result, &owner) == EACCES);
	config.recovery_enabled = true;
	config.tls_credentials = NULL;
	CHECK(migration_prod_dest_serve_prepared(&vm, 3, &config, &result, &owner) == EACCES);
	config.tls_credentials = &credentials;
	vm.fenced = false;
	CHECK(migration_prod_dest_serve_prepared(&vm, 3, &config, &result, &owner) == EBUSY);
	vm.fenced = true;
	config.recovery_dirfd = open_dir;
	CHECK(migration_prod_dest_serve_prepared(&vm, 3, &config, &result, &owner) == EPERM);
	CHECK(owner == NULL);
	/* Recovery validates before touching any owner. */
	CHECK(migration_prod_dest_recover_release(NULL, 3, &credentials) == EINVAL);
	/* Reconstruction admission refusals before any journal is read. */
	{
		struct migration_prod_reconstruct *state = NULL, *taken = (void *)&config;
		uint8_t challenge[32] = { 1 };
		CHECK(migration_prod_dest_reconstruct_begin(NULL, dirfd, challenge, NULL, &state) == EINVAL);
		CHECK(migration_prod_dest_reconstruct_begin(&vm, dirfd, NULL, NULL, &state) == EINVAL);
		CHECK(migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge, NULL, NULL) == EINVAL);
		CHECK(migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge, NULL, &taken) == EINVAL);
		vm.fenced = false;
		CHECK(migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge, NULL, &state) == EBUSY);
		vm.fenced = true;
		CHECK(migration_prod_dest_reconstruct_begin(&vm, -1, challenge, NULL, &state) == EBADF);
		CHECK(migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge, NULL, &state) == ENOENT);
		CHECK(state == NULL);
		nfaults = 1;
		faults[0].role = 'D';
		strlcpy(faults[0].name, "vm_get_identity", sizeof(faults[0].name));
		faults[0].occurrence = *boundary_count("vm_get_identity") + 1;
		faults[0].error = ENXIO;
		CHECK(migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge, NULL, &state) == ENXIO);
		nfaults = 1;
		faults[0].occurrence = *boundary_count("vm_get_identity") + 1;
		faults[0].error = FAULT_NOERRNO;
		CHECK(migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge, NULL, &state) == EIO);
		nfaults = 0;
		nfaults = 0;
		tracing_mode = false;
		CHECK(migration_prod_dest_reconstruct_begin(&vm, dirfd, challenge, NULL, &state) == EOPNOTSUPP);
		migration_prod_dest_reconstruct_abandon(NULL);
		/* Every prepared() refusal consumes the state: a NULL state is
		 * reported as such. */
		CHECK(migration_prod_dest_reconstruct_prepared(&vm, NULL, &config, &result, &owner) == EINVAL);
		CHECK(result.phase == MIGRATION_PHASE_FAILED);
	}
}

/* An attempt record for source lifetime vmid/epoch in PHASE. */
static struct migration_recovery_record
intent_record(uint16_t phase, uint16_t vmid, uint64_t epoch)
{
	struct migration_recovery_record r;
	struct hypertrace_session_record session = { .vmid = vmid, .epoch = epoch,
	    .stop_token = 0x77, .features = HYPERTRACE_SESSION_FEATURES };

	memset(&r, 0, sizeof(r));
	r.phase = phase;
	CHECK(hypertrace_session_record_encode(r.session, sizeof(r.session), &session) == 0);
	r.destination_vmid = 9;
	r.destination_epoch = 90;
	memset(r.challenge, 0x31, 32);
	memset(r.state_digest, 0x32, 32);
	memset(r.source_certificate_sha256, 0x33, 32);
	memset(r.destination_certificate_sha256, 0x34, 32);
	return (r);
}

static void
inject(const char *name, int extra, int error)
{
	nfaults = 1;
	faults[0].role = role;
	strlcpy(faults[0].name, name, sizeof(faults[0].name));
	faults[0].occurrence = *boundary_count(name) + extra;
	faults[0].error = error;
}

/*
 * migration_prod_source_finish_intent(): each row builds a fresh journal
 * holding the attempt for source lifetime 7/70 (or none) and a fresh kernel
 * view, then checks the documented decision: already retired phases are a
 * no-op; INTENT completes to RETIRED only with retirement evidence, and only
 * the exact live lifetime is destroyed (through the supplied context).
 * Oracles: the return value, the stored phase afterwards, and whether the
 * lifetime was destroyed.
 */
enum fi_row { FI_RETIRED_NOOP, FI_NO_OWNER, FI_NO_RECORD, FI_ALREADY_GONE,
	FI_ABSENT, FI_LIVE_NO_CTX, FI_IDENTITY_FAIL, FI_IDENTITY, FI_DEVICE_STOP,
	FI_TRANSPORT, FI_DESTROY, FI_SECOND_QUERY, FI_STORE, FI_DESTROY_OK,
	FI_DRAIN, FI_DRAIN_RETRY, FI_RETIRED_NOERRNO, FI_IDENTITY_NOERRNO,
	FI_IDENTITY_VMID, FI_SECOND_QUERY_NOERRNO, FI_GONE_DRAIN };
static const struct { enum fi_row row; int error; uint16_t phase_after;
    bool destroyed; const char *label; } fi_table[] = {
	{ FI_RETIRED_NOOP, 0, MIGRATION_REC_SOURCE_RELEASED, false, "retired-noop" },
	{ FI_NO_OWNER, ENOENT, 0, false, "no-owner" },
	{ FI_NO_RECORD, ENOENT, 0, false, "no-record" },
	{ FI_ALREADY_GONE, 0, MIGRATION_REC_SOURCE_RETIRED, false, "already-gone" },
	{ FI_ABSENT, ENOENT, MIGRATION_REC_SOURCE_INTENT, false, "absent" },
	{ FI_LIVE_NO_CTX, EBUSY, MIGRATION_REC_SOURCE_INTENT, false, "live-no-ctx" },
	{ FI_IDENTITY_FAIL, ENXIO, MIGRATION_REC_SOURCE_INTENT, false, "identity-fail" },
	{ FI_IDENTITY, ESTALE, MIGRATION_REC_SOURCE_INTENT, false, "identity" },
	{ FI_DEVICE_STOP, EIO, MIGRATION_REC_SOURCE_INTENT, false, "device-stop" },
	{ FI_TRANSPORT, EIO, MIGRATION_REC_SOURCE_INTENT, false, "transport" },
	{ FI_DESTROY, EIO, MIGRATION_REC_SOURCE_INTENT, false, "destroy" },
	{ FI_SECOND_QUERY, EIO, MIGRATION_REC_SOURCE_INTENT, true, "second-query" },
	{ FI_STORE, EIO, MIGRATION_REC_SOURCE_INTENT, true, "store" },
	{ FI_DESTROY_OK, 0, MIGRATION_REC_SOURCE_RETIRED, true, "destroy-ok" },
	{ FI_DRAIN, EIO, MIGRATION_REC_SOURCE_INTENT, true, "drain" },
	/* The lifetime is already retired (destroyed above) but this process's
	 * own retirement drain is still pending and fails again. */
	{ FI_GONE_DRAIN, EIO, MIGRATION_REC_SOURCE_INTENT, true, "gone-drain" },
	{ FI_DRAIN_RETRY, 0, MIGRATION_REC_SOURCE_RETIRED, true, "drain-retry" },
	/* Failures that report no errno are EIO; the other identity field. */
	{ FI_RETIRED_NOERRNO, EIO, MIGRATION_REC_SOURCE_INTENT, false, "retired-noerrno" },
	{ FI_IDENTITY_NOERRNO, EIO, MIGRATION_REC_SOURCE_INTENT, false, "identity-noerrno" },
	{ FI_IDENTITY_VMID, ESTALE, MIGRATION_REC_SOURCE_INTENT, false, "identity-vmid" },
	{ FI_SECOND_QUERY_NOERRNO, EIO, MIGRATION_REC_SOURCE_INTENT, true, "second-query-noerrno" },
};

static void
finish_intent_table(void)
{
	char name[32];
	int rows = 0;
	uint64_t fresh_epoch = 0;

	for (size_t i = 0; i < nitems(fi_table); i++) {
		struct migration_recovery_record expected, stored;
		struct vmctx *ctx = &vm, **cp = &ctx;
		uint16_t phase = 0;
		int dirfd, error;
		bool keep_retiring = fi_table[i].row == FI_DRAIN_RETRY ||
		    fi_table[i].row == FI_GONE_DRAIN;

		/* Lifetime 7/(700+i): distinct kernel markers per row. */
		uint64_t epoch = 700 + i;
		if (!keep_retiring) {
			vm_model_init(7, epoch, 0x11);
			fresh_epoch = epoch;
		} else
			epoch = fresh_epoch;	/* continue the drained row's lifetime */
		snprintf(name, sizeof(name), "fi-%zu", i);
		dirfd = private_dir(name, 0700);
		/* FI_ABSENT: an attempt for a lifetime the kernel never had. */
		expected = intent_record(MIGRATION_REC_SOURCE_INTENT, 7,
		    fi_table[i].row == FI_ABSENT ? epoch + 50 : epoch);
		stored = expected;
		if (fi_table[i].row != FI_NO_OWNER)
			CHECK(migration_source_owner_at(dirfd, &expected, true) == 0);
		if (fi_table[i].row != FI_NO_OWNER && fi_table[i].row != FI_NO_RECORD)
			CHECK(migration_recovery_store_at(dirfd, &stored) == 0);
		if (fi_table[i].row == FI_RETIRED_NOOP) {
			/* Phases advance one step at a time. */
			stored.phase = MIGRATION_REC_SOURCE_RETIRED;
			CHECK(migration_recovery_store_at(dirfd, &stored) == 0);
			stored.phase = MIGRATION_REC_SOURCE_RELEASED;
			CHECK(migration_recovery_store_at(dirfd, &stored) == 0);
		}
		switch (fi_table[i].row) {
		case FI_ALREADY_GONE: kernel_set("destroyed", 7, epoch); break;
		case FI_LIVE_NO_CTX: cp = NULL; break;
		case FI_IDENTITY_FAIL: inject("vm_get_identity", 1, ENXIO); break;
		case FI_IDENTITY: vm.epoch++; break;
		case FI_DEVICE_STOP: inject("pci_vtdtr_checkpoint_stop", 1, EIO); break;
		case FI_TRANSPORT: inject("hypertrace_retire_transport", 1, EIO); break;
		case FI_DESTROY: inject("vm_destroy_identity_request_checked", 1, EIO); break;
		case FI_SECOND_QUERY: inject("hypertrace_session_retired", 2, EIO); break;
		case FI_STORE: inject("renameat", 1, EIO); break;
		case FI_DRAIN: inject("fbsdrun_retire_cpus_wait", 1, EIO); break;
		case FI_RETIRED_NOERRNO: inject("hypertrace_session_retired", 1, FAULT_NOERRNO); break;
		case FI_IDENTITY_NOERRNO: inject("vm_get_identity", 1, FAULT_NOERRNO); break;
		case FI_IDENTITY_VMID: vm.vmid++; break;
		case FI_SECOND_QUERY_NOERRNO: inject("hypertrace_session_retired", 2, FAULT_NOERRNO); break;
		case FI_GONE_DRAIN: inject("fbsdrun_retire_cpus_wait", 1, EIO); break;
		default: break;
		}
		error = migration_prod_source_finish_intent(cp, dirfd, &expected);
		nfaults = 0;
		if (error != fi_table[i].error)
			fprintf(stderr, "finish_intent %s: got %d want %d\n",
			    fi_table[i].label, error, fi_table[i].error);
		CHECK(error == fi_table[i].error);
		if (fi_table[i].phase_after != 0) {
			CHECK(migration_recovery_load_at(dirfd, &expected, &phase) == 0);
			if (phase != fi_table[i].phase_after)
				fprintf(stderr, "finish_intent %s: phase %u want %u\n",
				    fi_table[i].label, phase, fi_table[i].phase_after);
			CHECK(phase == fi_table[i].phase_after);
		}
		if (kernel_has("destroyed", 7, epoch) !=
		    (fi_table[i].destroyed || fi_table[i].row == FI_ALREADY_GONE))
			fprintf(stderr, "finish_intent %s: destroyed %d\n", fi_table[i].label,
			    kernel_has("destroyed", 7, epoch));
		CHECK(kernel_has("destroyed", 7, epoch) ==
		    (fi_table[i].destroyed || fi_table[i].row == FI_ALREADY_GONE));
		/* The supplied context is consumed exactly when destroyed here. */
		CHECK((ctx == NULL) == (fi_table[i].destroyed && !keep_retiring));
		close(dirfd);
		rows++;
	}
	printf("source finish_intent table: %d rows\n", rows);
}

static void
source_contracts(void)
{
	struct migration_tls_credentials credentials;
	struct migration_recovery_record expected;
	int dirfd;

	role = 'S';
	fresh_workdir();
	vm_model_init(7, 70, 0x11);
	restart_credentials(&credentials);
	dirfd = private_dir("journal", 0700);
	memset(&expected, 0, sizeof(expected));
	CHECK(migration_prod_source_finish_intent(NULL, dirfd, NULL) == EINVAL);
	expected.phase = MIGRATION_REC_SOURCE_INTENT - 1;
	CHECK(migration_prod_source_finish_intent(NULL, dirfd, &expected) == EINVAL);
	expected.phase = MIGRATION_REC_SOURCE_CONFIRMED + 1;
	CHECK(migration_prod_source_finish_intent(NULL, dirfd, &expected) == EINVAL);
	finish_intent_table();
	CHECK(migration_prod_source_recover_restart_named(3, dirfd, 7, 70, NULL, "x") == EINVAL);
	CHECK(migration_prod_source_recover_restart_named(3, dirfd, 7, 70, &credentials, NULL) == ENOENT);
	/* Prepared fill helpers validate their arguments. */
	{
		struct migration_hello hello;
		struct migration_topology *topo = calloc(1, sizeof(*topo));
		CHECK(migration_prod_fill_hello(NULL, &hello) == EINVAL);
		CHECK(migration_prod_fill_hello(&vm, NULL) == EINVAL);
		CHECK(migration_prod_fill_topology(NULL, topo) == EINVAL);
		CHECK(migration_prod_fill_topology(&vm, NULL) == EINVAL);
		/* TPM state has no portable contract: refused. */
		tpm_present = true;
		CHECK(migration_prod_fill_topology(&vm, topo) == ENOTSUP);
		tpm_present = false;
		devices_init();
		CHECK(migration_prod_fill_topology(&vm, topo) == 0);
		CHECK(topo->device_count == 3 && topo->sockets == 1 && topo->cores == 2);
		CHECK(strcmp(topo->devices[2].name, "qemu_fwcfg") == 0 ||
		    topo->devices[2].compat_crc32 == 0xfeedf00d);
		/* Topology query failure leaves CPU shape zero but succeeds. */
		nfaults = 1;
		faults[0].role = 'S';
		strlcpy(faults[0].name, "vm_get_topology", sizeof(faults[0].name));
		faults[0].occurrence = *boundary_count("vm_get_topology") + 1;
		faults[0].error = EIO;
		CHECK(migration_prod_fill_topology(&vm, topo) == 0 && topo->sockets == 0);
		nfaults = 0;
		free(topo);
	}
}

/* Every distinct boundary call of a successful run, failed in turn. */
struct fault_point { char role; char name[64]; int occurrence; };

static int
collect_points(struct fault_point *points, int max)
{
	char path[400], line[300];
	FILE *f;
	int n = 0;
	struct { char role; char name[64]; int last; } seen[128];
	int nseen = 0;

	snprintf(path, sizeof(path), "%s/events", workdir);
	f = fopen(path, "r");
	CHECK(f != NULL);
	while (fgets(line, sizeof(line), f) != NULL) {
		char who, name[64];
		double ts;
		int occurrence, i;

		if (sscanf(line, "%c %lf B %63s %d", &who, &ts, name, &occurrence) != 4)
			continue;
		for (i = 0; i < nseen; i++)
			if (seen[i].role == who && strcmp(seen[i].name, name) == 0)
				break;
		if (i == nseen) {
			CHECK(nseen < 128);
			seen[nseen].role = who;
			strlcpy(seen[nseen].name, name, sizeof(seen[nseen].name));
			nseen++;
		}
		seen[i].last = occurrence;
		/* First and second occurrence of each boundary. */
		if (occurrence <= 2) {
			CHECK(n < max);
			points[n].role = who;
			strlcpy(points[n].name, name, sizeof(points[n].name));
			points[n].occurrence = occurrence;
			n++;
		}
	}
	fclose(f);
	/* And the last occurrence when it differs. */
	for (int i = 0; i < nseen; i++)
		if (seen[i].last > 2) {
			CHECK(n < max);
			points[n].role = seen[i].role;
			strlcpy(points[n].name, seen[i].name, sizeof(points[n].name));
			points[n].occurrence = seen[i].last;
			n++;
		}
	return (n);
}

static void
test_faults(const struct scenario *s)
{
	struct fault_point points[256];
	struct outcome o;
	int n, defunct = 0, runnable = 0, wedged_runs = 0, quarantined_runs = 0,
	    dest_resumed = 0, retained = 0, repaired = 0, blocked = 0, noerrno_runs = 0;

	run_scenario(s, NULL, &o);
	CHECK(o.source_status == BHYVE_EXIT_SUSPEND);
	n = collect_points(points, 256);
	for (int i = 0; i < n; i++) {
		char spec[128];
		int err = EIO;

		if (strcmp(points[i].name, "hypertrace_session_retired") == 0)
			err = EBUSY;
		snprintf(spec, sizeof(spec), "%c:%s:%d:%d", points[i].role,
		    points[i].name, points[i].occurrence, err);
		run_scenario(s, spec, &o);
		if (!o.fault_fired) {
			fprintf(stderr, "%s %s: injected fault did not fire\n", s->name, spec);
			abort();
		}
		defunct += o.source_status == BHYVE_EXIT_SUSPEND;
		runnable += o.source_replied && o.runnable == 1;
		wedged_runs += strstr(o.state, "wedged 1") != NULL;
		quarantined_runs += strstr(o.state, "quarantined 1") != NULL;
		dest_resumed += o.dest_resumed == 1;
		retained += o.dest_retained == 1;
		repaired += o.repaired == 1;
		blocked += o.dest_blocked;
		if (o.recovered || o.dest_blocked)
			printf("  %s: recovery %s confirmed %d error %d; destination %s; source destroyed %d\n",
			    spec, o.recovered ? "attempted" : "not attempted", o.recover_confirmed,
			    o.recover_error, o.dest_blocked ? "still retained" : "resumed",
			    o.events_source_destroyed);
		/* Authenticated recovery resumes the retained destination exactly
		 * when it confirms; it never resumes without source destruction. */
		if (o.recovered)
			CHECK((o.recover_confirmed == 1) == (o.dest_resumed == 1));
	}
	/*
	 * Errno-less failures.  vm_get_identity(), the retirement witness and the
	 * identity-checked destroy document errno on failure; their callers map a
	 * failure that left errno 0 to EIO.  Oracle: each such failure produces
	 * exactly the outcome of an EIO failure at the same call (same source
	 * exit, runnable state, reason, destination resume and retention).
	 */
	for (int i = 0; i < n; i++) {
		static const char *const reporting[] = { "vm_get_identity",
		    "hypertrace_session_retired", "vm_destroy_name_identity_checked" };
		struct outcome eio;
		char spec[128];
		bool listed = false;

		for (size_t k = 0; k < nitems(reporting); k++)
			listed |= strcmp(points[i].name, reporting[k]) == 0;
		if (!listed)
			continue;
		snprintf(spec, sizeof(spec), "%c:%s:%d:%d", points[i].role,
		    points[i].name, points[i].occurrence, EIO);
		run_scenario(s, spec, &eio);
		CHECK(eio.fault_fired);
		snprintf(spec, sizeof(spec), "%c:%s:%d:%d", points[i].role,
		    points[i].name, points[i].occurrence, FAULT_NOERRNO);
		run_scenario(s, spec, &o);
		CHECK(o.fault_fired);
		if (o.source_status != eio.source_status || o.runnable != eio.runnable ||
		    o.reason != eio.reason || o.dest_resumed != eio.dest_resumed ||
		    o.dest_retained != eio.dest_retained || o.repaired != eio.repaired) {
			fprintf(stderr, "%s %s: errno-less outcome differs from EIO "
			    "(status %d/%d runnable %d/%d reason %d/%d resumed %d/%d "
			    "retained %d/%d repaired %d/%d)\n", s->name, spec,
			    o.source_status, eio.source_status, o.runnable, eio.runnable,
			    o.reason, eio.reason, o.dest_resumed, eio.dest_resumed,
			    o.dest_retained, eio.dest_retained, o.repaired, eio.repaired);
			abort();
		}
		noerrno_runs++;
	}
	/* ETIMEDOUT: CPU barrier fails without restoring the vCPUs. */
	{
		char spec[128];
		snprintf(spec, sizeof(spec), "S:fbsdrun_migration_pause_cpus:1:%d", ETIMEDOUT);
		run_scenario(s, spec, &o);
		/* The failed barrier left the source quiesced but never retiring:
		 * the automatic bounded repair resumes it on the first attempt. */
		CHECK(o.source_replied && o.runnable == 1 && o.repaired == 1 && o.attempts == 1);
		CHECK(o.dest_resumed != 1);
		n++;
	}
	printf("faults %-25s %3d injected: %d committed, %d runnable rollback, %d repaired, "
	    "%d wedged, %d quarantined, %d destination resumed, %d retained, %d blocked; "
	    "%d errno-less failures matched EIO\n",
	    s->name, n, defunct, runnable, repaired, wedged_runs, quarantined_runs,
	    dest_resumed, retained, blocked, noerrno_runs);
}

static void
test_root_mismatch(void)
{
	static const struct scenario s = { .name = "fresh-other-root", .tracing = true,
	    .tls = true, .managed = true, .recovery_dir = "other" };
	static const struct scenario same = { .name = "fresh-same-root", .tracing = true,
	    .tls = true, .managed = true, .recovery_dir = "anchor/var/db/bhyve/migration" };
	struct outcome o;

	run_scenario(&s, NULL, &o);
	CHECK(o.source_replied && o.runnable == 1);
	CHECK(strstr(o.error, "migration recovery root: ") != NULL &&
	    strstr(o.error, strerror(EXDEV)) != NULL);
	CHECK(count_events("S E cpus_paused") == 0 && o.dest_resumed != 1);
	run_scenario(&same, NULL, &o);
	CHECK(o.source_status == BHYVE_EXIT_SUSPEND && o.dest_resumed == 1);
	printf("recovery root: alias accepted, different directory refused before quiesce\n");
}

static void
test_repair(void)
{
	static const struct scenario s = { .name = "fresh-repair", .tracing = true,
	    .tls = true, .managed = true, .repair_ipc = true };
	char spec[256];
	struct outcome o;

	/* Destination refuses COMMIT state; the first rollback resume fails and
	 * the automatic repair succeeds on its first attempt. */
	run_scenario(&s, "D:vm_migrate_fresh_commit_state:1:5,S:vm_resume_devices:1:5", &o);
	CHECK(o.source_replied && o.runnable == 1 && o.repaired == 1 && o.attempts == 1);
	CHECK(strstr(o.state, "wedged 0") != NULL && strstr(o.state, "gdb_fenced 0") != NULL);
	/* Second attempt succeeds after a back-off. */
	run_scenario(&s, "D:vm_migrate_fresh_commit_state:1:5,S:vm_resume_devices:1:5,"
	    "S:vm_resume_devices:2:5", &o);
	CHECK(o.runnable == 1 && o.repaired == 1 && o.attempts == 2);
	/* The CPU barrier can fail too; the bounded retry resumes it later. */
	run_scenario(&s, "D:vm_migrate_fresh_commit_state:1:5,S:fbsdrun_migration_resume_cpus:1:5", &o);
	CHECK(o.runnable == 1 && o.repaired == 1 && o.attempts == 1);
	/* Every bounded attempt fails: the source is wedged (reversible), keeps
	 * the debugger fence, and the operator repair resumes it once. */
	snprintf(spec, sizeof(spec), "D:vm_migrate_fresh_commit_state:1:5,S:vm_resume_devices:1:5,"
	    "S:vm_resume_devices:2:5,S:vm_resume_devices:3:5,S:vm_resume_devices:4:5");
	run_scenario(&s, spec, &o);
	CHECK(o.runnable == 0 && o.repaired == 0 && o.attempts == 3);
	CHECK(strstr(o.state, "wedged 1") != NULL && strstr(o.state, "quarantined 0") != NULL &&
	    strstr(o.state, "gdb_fenced 1") != NULL);
	CHECK(kv_int("source-repair", "repaired0") == 1 && kv_int("source-repair", "attempts0") == 1 &&
	    kv_int("source-repair", "runnable0") == 1);
	CHECK(kv_int("source-repair", "repaired1") == 0 &&
	    kv_int("source-repair", "error1") == EALREADY &&
	    kv_int("source-repair", "runnable1") == 1);
	{
		char state[256];
		read_kv("source-repair", "state", state, sizeof(state));
		CHECK(strcmp(state, "cpus_paused 0 devices_paused 0 console_paused 0 wedged 0 "
		    "gdb_fenced 0") == 0);
	}
	printf("repair: automatic 1st/2nd attempt, CPU barrier, wedge then operator repair\n");
}

static void
test_restart_recovery(void)
{
	static const struct scenario crashed = { .name = "fresh-source-crash",
	    .tracing = true, .tls = true, .managed = true, .recover = recover_by_restart };
	static const struct scenario alive = { .name = "fresh-source-alive",
	    .tracing = true, .tls = true, .managed = true, .recover_ipc = true,
	    .restart_probe = true };
	struct outcome o;

	/* Source process lost after durable INTENT, before destruction: the
	 * restarted source cannot prove retirement without destruction
	 * authority (EBUSY, destination still retained); with the local name it
	 * destroys exactly that lifetime, publishes RETIRED and releases. */
	run_scenario(&crashed, "S:pci_vtdtr_checkpoint_stop:1:999", &o);
	CHECK(o.source_status == 77 && !o.dest_blocked && o.dest_resumed == 1);
	CHECK(kv_int("restart-crashed", "error0") == EBUSY &&
	    kv_int("restart-crashed", "error1") == 0);
	CHECK(count_events("R E destroyed vm7 name") == 1 && o.events_source_destroyed == 1);
	/* Lost after destruction, before RETIRED: the kernel witness alone
	 * completes INTENT on the first restart, without any destruction. */
	run_scenario(&crashed, "S:fbsdrun_retire_cpus_wait:1:999", &o);
	CHECK(o.source_status == 77 && o.dest_resumed == 1);
	CHECK(kv_int("restart-crashed", "error0") == 0 && count_events("R E destroyed") == 0);
	/* Lost before COMMIT: the destination discards the attempt, there is
	 * no durable owner, and a restart finds nothing to recover. */
	run_scenario(&crashed, "S:vm_snapshot_fresh_dev_state_to_mem:1:999", &o);
	CHECK(o.source_status == 77 && !o.dest_blocked && o.dest_resumed == 0 &&
	    o.dest_retained == 0);
	restart_recovery("none", "migrating-vm", false);
	CHECK(kv_int("restart-none", "error0") == ENOENT);
	CHECK(count_events("R E destroyed") == 0 && o.events_source_destroyed == 0);
	printf("restart recovery: witness-less refusal, named destruction, witness-only "
	    "completion, no owner before COMMIT\n");
	/* While the original source process lives it holds the controller lock;
	 * a restarted controller is refused and IPC recovery completes. */
	run_scenario(&alive, "S:pci_vtdtr_checkpoint_stop:1:5", &o);
	CHECK(kv_int("restart-probe", "error0") == EBUSY);
	CHECK(o.recovered && o.recover_confirmed == 1 && o.dest_resumed == 1);
	printf("restart recovery refused while the source controller lives\n");
}

static void
test_reconstruction(void)
{
	static const struct scenario s = { .name = "fresh-image", .tracing = true,
	    .tls = true, .managed = true, .recovery_image = true,
	    .recover = recover_by_reconstruction };
	struct outcome o;

	/* The source retires (VM destroyed) and is lost before RETIRED/RELEASE;
	 * the destination is STAGED with a preserved image and then lost too. */
	run_scenario(&s, "S:fbsdrun_retire_cpus_wait:1:999", &o);
	CHECK(o.source_status == 77 && o.events_source_destroyed == 1);
	CHECK(successor_value(10, "begin") == 0 && successor_value(10, "error") == 0 &&
	    successor_value(10, "resumed") == 1 && successor_value(10, "resumes") == 1);
	{
		char v[32];
		read_kv("successor-10", "ram_crc", v, sizeof(v));
		CHECK(strtoul(v, NULL, 16) == expected_ram_crc(count_events("S E guest_wrote")));
		CHECK(successor_value(10, "blob") == MIGRATE_BLOB_HDR + META_LEN + KERNEL_LEN +
		    HYPERTRACE_SESSION_RECORD_SIZE);
	}
	/* The image was retired after the successful resume. */
	{
		uint8_t challenge[32];
		char hex[65];
		CHECK(!image_challenge(challenge, hex, sizeof(hex)));
	}
	printf("reconstruction: controller-held refusal, identity reuse refusal, unnamed "
	    "refusal, named retirement, image load, one resume, image retired\n");
}

int
main(int argc, char **argv)
{
	static const struct scenario plain = { .name = "plain" };
	static const struct scenario plain_tls = { .name = "plain-tls", .tls = true,
	    .max_rounds = 7 };
	static const struct scenario lowmem_only = { .name = "plain-lowmem", .no_highmem = true };
	static const struct scenario fresh = { .name = "fresh-managed", .tracing = true,
	    .tls = true, .managed = true, .recover_ipc = true };

	signal(SIGPIPE, SIG_IGN);
	if (argc > 1 && strcmp(argv[1], "protocol") == 0) {
		extern int protocol_main(void);
		return (protocol_main());
	}
	in_child("admission plain: 8 refusals with the source untouched", admission_plain);
	in_child("admission fresh: 3 refusals with the source untouched", admission_fresh);
	in_child("destination contracts: 33 refusals", destination_contracts);
	in_child("source contracts: 17 refusals", source_contracts);
	test_success(&plain);
	test_success(&plain_tls);
	test_success(&lowmem_only);
	test_success(&fresh);
	test_root_mismatch();
	test_repair();
	test_restart_recovery();
	test_reconstruction();
	test_faults(&plain);
	test_faults(&plain_tls);
	test_faults(&fresh);
	printf("PASS: production migration adapters\n");
	return (0);
}
