/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * HWT context management — wraps the FreeBSD hwt(4) ioctl interface.
 *
 * Every struct passed to ioctl(2) is defined in <sys/hwt.h> with
 * __aligned(16).  Since this is plain C compiled with the same
 * toolchain as the kernel, the struct layouts match exactly — no
 * bridging or alignment guessing required.
 *
 * Key correctness notes (from the kernel source):
 *
 *   - hwt_alloc.ident and hwt_alloc.backend_name are userspace
 *     pointers.  The kernel uses copyout()/copyinstr() on them.
 *
 *   - hwt_record_get.nentries is a pointer to int.  The kernel
 *     copyin()s the requested count and copyout()s the actual count.
 *
 *   - hwt_set_config.config is a userspace pointer to the backend
 *     config struct.  The kernel copyin()s config_size bytes.
 *
 *   - HWT_IOC_SET_CONFIG MUST be called before HWT_IOC_START.
 *     The PT backend dereferences ctx->config on the first
 *     hwt_switch_in — if it's NULL, the kernel page-faults.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/cpuctl.h>
#include <sys/hwt.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdtrace.h"

/* ------------------------------------------------------------------ */
/* Detection                                                           */
/* ------------------------------------------------------------------ */

int
hwt_available(void)
{
	int fd;

	fd = open("/dev/hwt", O_RDWR);
	if (fd < 0)
		return (0);
	close(fd);
	return (1);
}

int
hwt_hooks_enabled(void)
{
	char *conftxt;
	size_t len;
	int enabled;

	len = 0;
	if (sysctlbyname("kern.conftxt", NULL, &len, NULL, 0) != 0)
		return (-1);
	if (len == 0)
		return (-1);

	conftxt = calloc(1, len + 1);
	if (conftxt == NULL)
		return (-1);

	if (sysctlbyname("kern.conftxt", conftxt, &len, NULL, 0) != 0) {
		free(conftxt);
		return (-1);
	}

	enabled = strstr(conftxt, "options\tHWT_HOOKS") != NULL;
	free(conftxt);
	return (enabled ? 1 : 0);
}

char *
hwt_detect_backend(void)
{
	static const char *backends[] = { "pt", "coresight", "spe" };
	size_t i;

	for (i = 0; i < nitems(backends); i++) {
		if (kldfind(backends[i]) != -1)
			return (strdup(backends[i]));
	}
	return (NULL);
}

/*
 * Query CPUID leaf 0x14 to find the lowest supported MTC frequency
 * and CYC threshold encodings.  Returns 0/0 if the CPU doesn't
 * support configurable timing.  Encoding 0 is the kernel's sentinel
 * for "off", so we scan from 1.
 */
void
hwt_pt_default_timing(uint32_t *mtc_out, uint32_t *cyc_out)
{
	uint32_t eax, ebx, ecx, edx;
	uint32_t mtc_bitmap, cyc_bitmap;
	int i;

	*mtc_out = 0;
	*cyc_out = 0;

	/* Leaf 0x14 subleaf 1: timing bitmaps. */
	__asm__ __volatile__("cpuid"
	    : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
	    : "a"(0x14), "c"(1));

	/* MTC bitmap: EAX[31:16] — scan from 1, skip 0. */
	mtc_bitmap = (eax >> 16) & 0xffff;
	for (i = 1; i < 16; i++) {
		if (mtc_bitmap & (1 << i)) {
			*mtc_out = i;
			break;
		}
	}

	/* CYC bitmap: EBX[15:0] — scan from 1, skip 0. */
	cyc_bitmap = ebx & 0xffff;
	for (i = 1; i < 16; i++) {
		if (cyc_bitmap & (1 << i)) {
			*cyc_out = i;
			break;
		}
	}
}

/*
 * Collect the capture-machine environment for the .meta sidecar:
 * CPU identity (for decode-time errata), the CPUID 0x15 TSC/CTC
 * ratio (without which libipt silently drops every MTC packet's
 * time contribution), and the nominal frequency (CBR-based CYC
 * calibration).  All values describe the *capture* machine and are
 * replayed into pt_config at decode time — never read again on the
 * decode host.
 */
int
hwt_pt_capture_env(struct pt_capture_env *env)
{
	uint32_t eax, ebx, ecx, edx, maxleaf;
	uint32_t base_family, base_model, ext_family, ext_model;

	memset(env, 0, sizeof(*env));

	/* Leaf 0: max leaf + vendor. */
	__asm__ __volatile__("cpuid"
	    : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
	    : "a"(0), "c"(0));
	maxleaf = eax;
	/* "GenuineIntel" */
	if (ebx != 0x756e6547 || edx != 0x49656e69 || ecx != 0x6c65746e)
		return (-1);

	/* Leaf 1: family/model/stepping, with the extended fields. */
	__asm__ __volatile__("cpuid"
	    : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
	    : "a"(1), "c"(0));
	env->stepping = eax & 0xf;
	base_family = (eax >> 8) & 0xf;
	base_model = (eax >> 4) & 0xf;
	ext_family = (eax >> 20) & 0xff;
	ext_model = (eax >> 16) & 0xf;
	env->family = base_family == 0xf ?
	    (uint16_t)(base_family + ext_family) : (uint16_t)base_family;
	env->model = (base_family == 0x6 || base_family == 0xf) ?
	    (uint8_t)((ext_model << 4) | base_model) : (uint8_t)base_model;

	/* Leaf 0x15: TSC/core-crystal ratio (MTC time correlation). */
	if (maxleaf >= 0x15) {
		__asm__ __volatile__("cpuid"
		    : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		    : "a"(0x15), "c"(0));
		env->cpuid_15_eax = eax;
		env->cpuid_15_ebx = ebx;
	}

	/*
	 * Nominal frequency: MSR_PLATFORM_INFO[15:8] (the base bus
	 * ratio in 100 MHz units).  The MSR needs cpuctl(4); fall
	 * back to CPUID leaf 0x16 (base frequency in MHz), which is
	 * unprivileged and present on Skylake and later.
	 */
	{
		int fd;

		fd = open("/dev/cpuctl0", O_RDONLY);
		if (fd >= 0) {
			cpuctl_msr_args_t args;

			memset(&args, 0, sizeof(args));
			args.msr = 0xce;	/* MSR_PLATFORM_INFO */
			if (ioctl(fd, CPUCTL_RDMSR, &args) == 0)
				env->nom_freq =
				    (uint8_t)((args.data >> 8) & 0xff);
			close(fd);
		}
		if (env->nom_freq == 0 && maxleaf >= 0x16) {
			__asm__ __volatile__("cpuid"
			    : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
			    : "a"(0x16), "c"(0));
			/* EAX = base frequency in MHz; the ratio is
			 * in 100 MHz units, so round to nearest. */
			if (eax > 0)
				env->nom_freq =
				    (uint8_t)((eax + 50) / 100);
		}
	}

	env->valid = true;
	return (0);
}

/* ------------------------------------------------------------------ */
/* Context allocation                                                  */
/* ------------------------------------------------------------------ */

int
hwt_ctx_alloc(struct hwt_ctx *ctx, int mode, pid_t pid,
    int tid, size_t bufsize, const char *backend)
{
	struct hwt_alloc ha;
	char devpath[64];
	int ident;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ctl_fd = -1;
	ctx->ctx_fd = -1;
	ctx->kq_fd = -1;
	for (int i = 0; i < MAX_THREADS; i++)
		ctx->threads[i].fd = -1;
	ctx->mode = mode;
	ctx->tid = tid;
	ctx->pid = pid;

	if (backend == NULL || backend[0] == '\0') {
		warnx("empty HWT backend name");
		errno = EINVAL;
		return (-1);
	}
	if (strlcpy(ctx->backend_name, backend, sizeof(ctx->backend_name)) >=
	    sizeof(ctx->backend_name)) {
		warnx("HWT backend name too long: %s", backend);
		errno = ENAMETOOLONG;
		return (-1);
	}

	/*
	 * The kernel requires bufsize to be a multiple of PAGE_SIZE
	 * (hwt_ioctl.c returns EINVAL otherwise).  Round up.
	 */
	if (bufsize == 0)
		bufsize = 64 * 1024 * 1024;
	bufsize = (bufsize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	ctx->bufsize = bufsize;

	/* Open /dev/hwt control device. */
	ctx->ctl_fd = open("/dev/hwt", O_RDWR);
	if (ctx->ctl_fd < 0) {
		warn("open /dev/hwt");
		return (-1);
	}

	/* Create kqueue for event notification. */
	ctx->kq_fd = kqueue();
	if (ctx->kq_fd < 0) {
		warn("kqueue");
		goto fail;
	}

	/*
	 * Allocate HWT context via ioctl.
	 *
	 * The hwt_alloc struct is __aligned(16).  All pointer fields
	 * (ident, backend_name, cpu_map) are userspace addresses that
	 * the kernel accesses via copyin/copyout/copyinstr.
	 *
	 * Kernel constraints (from hwt_ioctl.c):
	 *   - bufsize must be <= 32 GB and page-aligned
	 *   - backend_name must not be NULL
	 *   - mode must be HWT_MODE_THREAD or HWT_MODE_CPU
	 */
	ident = 0;
	memset(&ha, 0, sizeof(ha));
	ha.bufsize = bufsize;
	ha.mode = mode;
	ha.pid = pid;
	ha.cpu_map = NULL;
	ha.cpusetsize = 0;
	ha.backend_name = ctx->backend_name;
	ha.ident = &ident;
	ha.kqueue_fd = ctx->kq_fd;

	if (ioctl(ctx->ctl_fd, HWT_IOC_ALLOC, &ha) != 0) {
		warn("failed to allocate trace context "
		    "(backend=%s, pid=%d, bufsize=%zu)",
		    backend, (int)pid, bufsize);
		goto fail;
	}
	ctx->ident = ident;

	/*
	 * Open the per-context character device.
	 *
	 * In thread mode the kernel names devices hwt_<ident>_<counter>
	 * starting at 0 (the main thread).  In CPU mode the suffix is
	 * the cpu_id.  We always open thread/cpu 0.
	 */
	snprintf(devpath, sizeof(devpath), "/dev/hwt_%d_%d",
	    ctx->ident, ctx->tid);
	ctx->ctx_fd = open(devpath, O_RDWR);
	if (ctx->ctx_fd < 0) {
		warn("open %s", devpath);
		goto fail;
	}

	return (0);

fail:
	hwt_ctx_close(ctx);
	return (-1);
}

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/*
 * Send the PT backend configuration to a specific device fd.
 * This is the common implementation used by both the primary thread
 * (ctx->ctx_fd) and additional thread devices opened via
 * hwt_ctx_open_thread().
 */
static int
hwt_ctx_set_config_on_fd(struct hwt_ctx *ctx, int fd, bool pause_on_mmap)
{
	struct hwt_set_config sc;
	struct pt_cpu_config ptcfg;

	/*
	 * Build the PT backend configuration.
	 *
	 * The kernel's pt_backend_configure() (pt.c) casts ctx->config
	 * to (struct pt_cpu_config *) and immediately dereferences it:
	 *
	 *   cfg = (struct pt_cpu_config *)ctx->config;
	 *   cfg->rtit_ctl &= PT_SUPPORTED_FLAGS;
	 *
	 * If ctx->config is NULL (SET_CONFIG never called, or failed),
	 * this is a kernel page fault.  This was the vmcore.4 crash.
	 *
	 * Minimum viable config: user-mode branch tracing.
	 *   RTIT_CTL_USER    (bit 3)  — trace user-mode only
	 *   RTIT_CTL_BRANCHEN (bit 13) — enable branch tracing
	 *
	 * The PT backend adds RTIT_CTL_TOPA and RTIT_CTL_TRACEEN itself.
	 */
	memset(&ptcfg, 0, sizeof(ptcfg));
	ptcfg.rtit_ctl = RTIT_CTL_USER | RTIT_CTL_BRANCHEN;
	if (ctx->ptwrite)
		ptcfg.rtit_ctl |= RTIT_CTL_PTWEN | RTIT_CTL_FUPONPTW;
	if (ctx->os_trace)
		ptcfg.rtit_ctl |= RTIT_CTL_OS;

	/*
	 * Hardware IP range filtering.
	 *
	 * ADDR0_CFG = 1 (FilterEn): trace only when IP is within range.
	 * The 4-bit config field at RTIT_CTL bits 32-35 (ADDR0) and
	 * 36-39 (ADDR1) selects the filter mode:
	 *   0 = disabled
	 *   1 = FilterEn (trace within range)
	 *   2 = TraceStop (stop on entering range)
	 */
	/* PSB / MTC / CYC frequency fields — passed to kernel as-is. */
	ptcfg.psb_freq = ctx->psb_freq;
	ptcfg.mtc_freq = ctx->mtc_freq;
	ptcfg.cyc_thresh = ctx->cyc_thresh;
	if (ctx->mtc_freq > 0 || ctx->cyc_thresh > 0)
		ptcfg.rtit_ctl |= RTIT_CTL_TSCEN;

	ptcfg.nranges = ctx->filter.nranges;
	for (int r = 0; r < ctx->filter.nranges && r < 2; r++) {
		ptcfg.ip_ranges[r].start = ctx->filter.ranges[r].start;
		ptcfg.ip_ranges[r].end = ctx->filter.ranges[r].end;
		ptcfg.ip_ranges[r].mode = ctx->filter.modes[r];
	}

	/*
	 * Fill the hwt_set_config struct (__aligned(16)).
	 *
	 * sc.config is a userspace pointer.  The kernel's hwt_config_set()
	 * does:
	 *   config = malloc(config_size, ...);
	 *   copyin(sconf->config, config, config_size);
	 *   ctx->config = config;
	 *
	 * So config_size MUST equal sizeof(struct pt_cpu_config) as the
	 * kernel compiled it.  Since we use the identical struct definition
	 * and the same compiler, sizeof matches.
	 */
	memset(&sc, 0, sizeof(sc));
	sc.pause_on_mmap = pause_on_mmap ? 1 : 0;
	sc.config = &ptcfg;
	sc.config_size = sizeof(ptcfg);
	sc.config_version = 0;

	if (ioctl(fd, HWT_IOC_SET_CONFIG, &sc) != 0) {
		warn("failed to configure trace backend (fd=%d)", fd);
		return (-1);
	}

	return (0);
}

int
hwt_ctx_set_config(struct hwt_ctx *ctx, bool pause_on_mmap)
{

	if (ctx->backend_name[0] == '\0') {
		warnx("HWT backend name missing from context");
		errno = EINVAL;
		return (-1);
	}

	if (strcmp(ctx->backend_name, "pt") == 0)
		return (hwt_ctx_set_config_on_fd(ctx, ctx->ctx_fd,
		    pause_on_mmap));

	warnx("unsupported HWT backend '%s': refusing to send Intel PT config "
	    "bytes to a non-PT backend", ctx->backend_name);
	errno = EOPNOTSUPP;
	return (-1);
}

/* ------------------------------------------------------------------ */
/* Start / Stop                                                        */
/* ------------------------------------------------------------------ */

int
hwt_ctx_start(struct hwt_ctx *ctx)
{
	struct hwt_start hs;

	memset(&hs, 0, sizeof(hs));
	if (ioctl(ctx->ctx_fd, HWT_IOC_START, &hs) != 0) {
		warn("failed to start tracing");
		return (-1);
	}
	return (0);
}

int
hwt_ctx_stop(struct hwt_ctx *ctx)
{
	struct hwt_stop hs;

	if (ctx->ctx_fd < 0)
		return (0);

	memset(&hs, 0, sizeof(hs));
	if (ioctl(ctx->ctx_fd, HWT_IOC_STOP, &hs) != 0) {
		warn("failed to stop tracing");
		return (-1);
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* Record polling                                                      */
/* ------------------------------------------------------------------ */

int
hwt_ctx_poll_records(struct hwt_ctx *ctx,
    struct bsdtrace_record *records, int maxrecords,
    bool wait, int *nout)
{
	struct hwt_record_user_entry *entries;
	struct hwt_record_get rg;
	int nentries;
	int i;

	/*
	 * The kernel limits nentries to 1024 (hwt_record.c:258).
	 * Clamp our request to avoid ENXIO.
	 */
	if (maxrecords > 1024)
		maxrecords = 1024;

	entries = calloc(maxrecords, sizeof(*entries));
	if (entries == NULL) {
		warn("calloc");
		return (-1);
	}

	/*
	 * hwt_record_get is __aligned(16).
	 *
	 * rg.records — userspace buffer for the kernel to copyout into.
	 * rg.nentries — pointer to int; kernel copyin()s the request
	 *               count, then copyout()s the actual count.
	 * rg.wait — if non-zero, kernel sleeps until records arrive.
	 */
	nentries = maxrecords;
	memset(&rg, 0, sizeof(rg));
	rg.records = entries;
	rg.nentries = &nentries;
	rg.wait = wait ? 1 : 0;

	if (ioctl(ctx->ctx_fd, HWT_IOC_RECORD_GET, &rg) != 0) {
		warn("failed to read trace records");
		free(entries);
		return (-1);
	}

	/*
	 * Convert kernel union entries to our flat struct.
	 *
	 * The hwt_record_user_entry union layout (from sys/hwt.h):
	 *   - MMAP/EXECUTABLE/KERNEL: fullpath[], addr, baseaddr
	 *   - BUFFER: buf_id, curpage, offset
	 *   - THREAD_CREATE/THREAD_SET_NAME: thread_id
	 *
	 * The kernel's hwt_record_to_user() (hwt_record.c:85) populates
	 * only the fields relevant to each record_type.
	 */
	for (i = 0; i < nentries; i++) {
		struct hwt_record_user_entry *e = &entries[i];
		struct bsdtrace_record *r = &records[i];

		memset(r, 0, sizeof(*r));
		r->type = e->record_type;

		switch (e->record_type) {
		case HWT_RECORD_MMAP:
		case HWT_RECORD_EXECUTABLE:
		case HWT_RECORD_KERNEL:
			strlcpy(r->fullpath, e->fullpath,
			    sizeof(r->fullpath));
			r->addr = e->addr;
			r->baseaddr = e->baseaddr;
			r->pgoff = (uint64_t)e->pgoff;
			r->maplen = (uint64_t)e->len;
			break;
		case HWT_RECORD_MUNMAP:
			r->addr = e->addr;
			break;
		case HWT_RECORD_BUFFER:
		case HWT_RECORD_OVERFLOW:
			r->buf_id = e->buf_id;
			r->curpage = e->curpage;
			r->offset = e->offset;
			break;
		case HWT_RECORD_THREAD_CREATE:
		case HWT_RECORD_THREAD_SET_NAME:
			r->thread_id = e->thread_id;
			break;
		default:
			break;
		}
	}

	free(entries);
	*nout = nentries;
	return (0);
}

/* ------------------------------------------------------------------ */
/* Wakeup (for pause-on-mmap)                                          */
/* ------------------------------------------------------------------ */

int
hwt_ctx_wakeup(struct hwt_ctx *ctx)
{
	struct hwt_wakeup hw;
	int error, i;

	/*
	 * The kernel's HWT_IOC_WAKEUP wakes only the thread that owns
	 * the device fd it is issued on, and the mmapping thread sleeps
	 * on its own hwt_thread.  Broadcast to every open thread device
	 * so a pause-on-mmap sleep in a secondary thread is woken too.
	 * A wakeup with no sleeper is harmless.
	 */
	memset(&hw, 0, sizeof(hw));
	error = 0;
	if (ioctl(ctx->ctx_fd, HWT_IOC_WAKEUP, &hw) != 0) {
		warn("failed to resume target after mmap");
		error = -1;
	}
	for (i = 0; i < ctx->nthreads; i++) {
		if (ctx->threads[i].fd < 0)
			continue;
		memset(&hw, 0, sizeof(hw));
		(void)ioctl(ctx->threads[i].fd, HWT_IOC_WAKEUP, &hw);
	}
	return (error);
}

/* ------------------------------------------------------------------ */
/* Buffer mmap                                                         */
/* ------------------------------------------------------------------ */

void *
hwt_ctx_map_buffer(struct hwt_ctx *ctx)
{
	void *ptr;

	if (ctx->trace_buf != NULL)
		return (ctx->trace_buf);

	ptr = mmap(NULL, ctx->bufsize, PROT_READ, MAP_SHARED,
	    ctx->ctx_fd, 0);
	if (ptr == MAP_FAILED) {
		warn("mmap trace buffer");
		return (NULL);
	}
	ctx->trace_buf = ptr;
	return (ptr);
}

/*
 * Query the kernel for the authoritative buffer write position on
 * a specific device fd.  Used for both the primary thread and
 * additional thread devices.
 */
static int
hwt_ctx_bufptr_get_fd(int fd, int *page_out, vm_offset_t *offset_out)
{
	struct hwt_bufptr_get bg;
	int ident;
	vm_offset_t offset;

	memset(&bg, 0, sizeof(bg));
	bg.ident = &ident;
	bg.offset = &offset;
	bg.data = NULL;

	if (ioctl(fd, HWT_IOC_BUFPTR_GET, &bg) != 0) {
		warn("failed to read buffer position (fd=%d)", fd);
		return (-1);
	}

	*page_out = ident;
	*offset_out = offset;
	return (0);
}

/*
 * Query the kernel for the authoritative buffer write position.
 * This reads the value that pt_cpu_stop() saved from the hardware
 * MSR after tracing stopped — it's exact, unlike BUFFER records
 * which are delivered asynchronously and may not arrive at all.
 */
int
hwt_ctx_bufptr_get(struct hwt_ctx *ctx, int *page_out,
    vm_offset_t *offset_out)
{

	return (hwt_ctx_bufptr_get_fd(ctx->ctx_fd, page_out, offset_out));
}

/* ------------------------------------------------------------------ */
/* Buffer snapshot                                                     */
/* ------------------------------------------------------------------ */

ssize_t
hwt_ctx_snapshot_buffer(struct hwt_ctx *ctx, const char *path,
    int last_page, vm_offset_t last_offset)
{
	const uint8_t *buf;
	size_t total;
	ssize_t nw;
	size_t off;
	int fd;

	if (last_page < 0) {
		warnx("no BUFFER records seen — nothing to snapshot");
		return (0);
	}

	buf = hwt_ctx_map_buffer(ctx);
	if (buf == NULL)
		return (-1);

	total = (size_t)last_page * PAGE_SIZE + last_offset;
	if (total > ctx->bufsize)
		total = ctx->bufsize;
	if (total == 0) {
		warnx("PT buffer is empty (0 bytes)");
		return (0);
	}

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		warn("open %s", path);
		return (-1);
	}

	off = 0;
	while (off < total) {
		nw = write(fd, buf + off, total - off);
		if (nw < 0) {
			warn("write %s", path);
			close(fd);
			return (-1);
		}
		off += nw;
	}

	close(fd);
	return ((ssize_t)total);
}

/* ------------------------------------------------------------------ */
/* Multi-thread support                                                */
/* ------------------------------------------------------------------ */

/*
 * Open an additional thread's device node and set PT config.
 * Called when a THREAD_CREATE record arrives and all_threads mode
 * is active.  Returns 0 on success, -1 on failure (the thread may
 * have already exited — that's normal, warn and continue).
 */
int
hwt_ctx_open_thread(struct hwt_ctx *ctx, int thread_id, bool pause_on_mmap)
{
	char devpath[64];
	int fd, i;

	if (ctx->nthreads >= MAX_THREADS) {
		warnx("too many threads (%d max), ignoring thread %d",
		    MAX_THREADS, thread_id);
		return (-1);
	}

	/* Skip if this thread_id is already open. */
	for (i = 0; i < ctx->nthreads; i++) {
		if (ctx->threads[i].thread_id == thread_id)
			return (0);
	}

	snprintf(devpath, sizeof(devpath), "/dev/hwt_%d_%d",
	    ctx->ident, thread_id);
	fd = open(devpath, O_RDWR);
	if (fd < 0) {
		warn("open %s (thread may have already exited)", devpath);
		return (-1);
	}

	ctx->threads[ctx->nthreads].fd = fd;
	ctx->threads[ctx->nthreads].thread_id = thread_id;
	ctx->threads[ctx->nthreads].trace_buf = NULL;
	ctx->nthreads++;

	/*
	 * HWT_IOC_SET_CONFIG is context-scoped, not per-device.  Once the
	 * primary thread device has started tracing, repeating SET_CONFIG on
	 * a later-opened thread device returns ENXIO because ctx->state is
	 * already RUNNING.  The shared ctx->config set before START applies
	 * to all per-thread devices in this context.
	 */
	fprintf(stderr, "opened thread %d device %s\n", thread_id, devpath);
	return (0);
}

/* ------------------------------------------------------------------ */
/* Cleanup                                                             */
/* ------------------------------------------------------------------ */

void
hwt_ctx_close(struct hwt_ctx *ctx)
{
	int i;

	/*
	 * Ensure tracing is stopped before closing fds.  If the caller
	 * already called hwt_ctx_stop() the ioctl fails harmlessly.
	 * Without this, early-exit error paths and signal-killed
	 * processes leave stale PT state in the kernel, causing the
	 * next trace session to get garbage buffer data.
	 */
	if (ctx->ctx_fd >= 0) {
		struct hwt_stop hs;
		memset(&hs, 0, sizeof(hs));
		(void)ioctl(ctx->ctx_fd, HWT_IOC_STOP, &hs);
	}

	/* Close additional thread devices. */
	for (i = 0; i < ctx->nthreads; i++) {
		if (ctx->threads[i].trace_buf != NULL) {
			munmap(ctx->threads[i].trace_buf, ctx->bufsize);
			ctx->threads[i].trace_buf = NULL;
		}
		if (ctx->threads[i].fd >= 0) {
			close(ctx->threads[i].fd);
			ctx->threads[i].fd = -1;
		}
	}
	ctx->nthreads = 0;

	if (ctx->trace_buf != NULL) {
		munmap(ctx->trace_buf, ctx->bufsize);
		ctx->trace_buf = NULL;
	}
	if (ctx->ctx_fd >= 0) {
		close(ctx->ctx_fd);
		ctx->ctx_fd = -1;
	}
	if (ctx->kq_fd >= 0) {
		close(ctx->kq_fd);
		ctx->kq_fd = -1;
	}
	if (ctx->ctl_fd >= 0) {
		close(ctx->ctl_fd);
		ctx->ctl_fd = -1;
	}
}
