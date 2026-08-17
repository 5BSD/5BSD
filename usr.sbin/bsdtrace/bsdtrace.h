/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * bsdtrace — process tracing via FreeBSD Hardware Trace (HWT).
 *
 * Shared header: types, prototypes, and the PT backend config struct
 * (which is not installed as a public kernel header).
 */

#ifndef BSDTRACE_H
#define BSDTRACE_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/hwt.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * PT backend per-CPU configuration.
 *
 * Copied from <amd64/pt/pt.h> which is NOT installed as a public
 * header.  This struct is passed to the kernel via HWT_IOC_SET_CONFIG;
 * the kernel stores it in ctx->config and later casts it back to
 * (struct pt_cpu_config *) in pt_backend_configure().
 *
 * If ctx->config is NULL when the traced thread is scheduled in,
 * the kernel will page-fault (NULL deref) — this was the cause of
 * the vmcore.4 panic.
 *
 * Guard: if someone compiles with -I/usr/src/sys and the real
 * pt.h gets included first, its include guard skips our copy.
 */
#ifndef _AMD64_PT_PT_H_
#define	PT_IP_FILTER_MAX_RANGES	2

#define	PT_RANGE_FILTER		1
#define	PT_RANGE_TRACESTOP	2

struct pt_cpu_config {
	uint64_t	rtit_ctl;
	register_t	cr3_filter;
	int		nranges;
	struct {
		vm_offset_t	start;
		vm_offset_t	end;
		int		mode;	/* PT_RANGE_FILTER or _TRACESTOP */
	} ip_ranges[PT_IP_FILTER_MAX_RANGES];
	uint32_t	mtc_freq;
	uint32_t	cyc_thresh;
	uint32_t	psb_freq;
};
#endif /* !_AMD64_PT_PT_H_ */

#ifdef __amd64__
_Static_assert(sizeof(struct pt_cpu_config) == 88,
    "pt_cpu_config size drifted from amd64/pt/pt.h");
_Static_assert(offsetof(struct pt_cpu_config, cr3_filter) == 8,
    "pt_cpu_config.cr3_filter offset mismatch");
_Static_assert(offsetof(struct pt_cpu_config, nranges) == 16,
    "pt_cpu_config.nranges offset mismatch");
_Static_assert(offsetof(struct pt_cpu_config, ip_ranges) == 24,
    "pt_cpu_config.ip_ranges offset mismatch");
_Static_assert(offsetof(struct pt_cpu_config, mtc_freq) == 72,
    "pt_cpu_config.mtc_freq offset mismatch");
_Static_assert(offsetof(struct pt_cpu_config, cyc_thresh) == 76,
    "pt_cpu_config.cyc_thresh offset mismatch");
_Static_assert(offsetof(struct pt_cpu_config, psb_freq) == 80,
    "pt_cpu_config.psb_freq offset mismatch");
#endif

_Static_assert(sizeof(struct hwt_alloc) == 64 && _Alignof(struct hwt_alloc) == 16,
    "hwt_alloc ABI mismatch");
_Static_assert(sizeof(struct hwt_start) == 16 && _Alignof(struct hwt_start) == 16,
    "hwt_start ABI mismatch");
_Static_assert(sizeof(struct hwt_stop) == 16 && _Alignof(struct hwt_stop) == 16,
    "hwt_stop ABI mismatch");
_Static_assert(sizeof(struct hwt_record_get) == 32 &&
    _Alignof(struct hwt_record_get) == 16,
    "hwt_record_get ABI mismatch");
_Static_assert(sizeof(struct hwt_set_config) == 32 &&
    _Alignof(struct hwt_set_config) == 16,
    "hwt_set_config ABI mismatch");
_Static_assert(sizeof(struct hwt_wakeup) == 16 &&
    _Alignof(struct hwt_wakeup) == 16,
    "hwt_wakeup ABI mismatch");

/*
 * RTIT_CTL bits used by bsdtrace.
 *
 * Defined in <x86/specialreg.h> but guarded here in case that
 * header is unavailable on non-x86 builds.
 */
#ifndef RTIT_CTL_USER
#define	RTIT_CTL_USER		(1 << 3)
#endif
#ifndef RTIT_CTL_BRANCHEN
#define	RTIT_CTL_BRANCHEN	(1 << 13)
#endif
#ifndef RTIT_CTL_TSCEN
#define	RTIT_CTL_TSCEN		(1 << 10)
#endif
#ifndef RTIT_CTL_PTWEN
#define	RTIT_CTL_PTWEN		(1 << 12)
#endif
#ifndef RTIT_CTL_FUPONPTW
#define	RTIT_CTL_FUPONPTW	(1 << 5)
#endif
#ifndef RTIT_CTL_OS
#define	RTIT_CTL_OS		(1 << 2)
#endif
#ifndef RTIT_CTL_ADDR_CFG_S
#define	RTIT_CTL_ADDR_CFG_S(n)	(32 + (n) * 4)
#endif

/*
 * HWT_RECORD_OVERFLOW may not be in the installed kernel headers yet.
 */
#ifndef HWT_RECORD_OVERFLOW
#define	HWT_RECORD_OVERFLOW	7
#endif

/* ------------------------------------------------------------------ */

/* Output format. */
enum bsdtrace_fmt {
	FMT_TEXT,
	FMT_JSON,
	FMT_PROFILE,
	FMT_TREE,
	FMT_COLLAPSED,
	FMT_SPEEDSCOPE,
	FMT_CALLERS
};

/*
 * Parsed HWT record — mirrors the kernel's hwt_record_user_entry
 * but flattened so callers don't need to navigate the union.
 */
struct bsdtrace_record {
	enum hwt_record_type	type;
	char			fullpath[MAXPATHLEN];
	uintptr_t		addr;
	uintptr_t		baseaddr;
	uint64_t		pgoff;	/* MMAP file offset (0 = unknown) */
	uint64_t		maplen;	/* MMAP length (0 = unknown) */
	int			buf_id;
	int			curpage;
	vm_offset_t		offset;
	int			thread_id;
};

/*
 * HWT context handle — owns the file descriptors and state for one
 * tracing session.
 *
 * Lifecycle: alloc → set_config → start → poll/map → stop → close
 */
/*
 * IP range filter for hardware-level filtering.
 * Up to 2 ranges supported by Intel PT (ADDR0, ADDR1).
 */
struct ip_filter {
	int		nranges;
	struct {
		uint64_t	start;
		uint64_t	end;
	} ranges[2];
	int		modes[2];	/* PT_RANGE_FILTER or _TRACESTOP */
};

/*
 * Range specification — parsed from -r, either a hex address range
 * or a function name to resolve from ELF symbols.
 */
#define	RANGE_SPEC_SYMLEN	256

enum range_spec_type {
	RANGE_ADDR,
	RANGE_SYMBOL
};

struct range_spec {
	enum range_spec_type	type;
	uint64_t		start;		/* RANGE_ADDR only */
	uint64_t		end;		/* RANGE_ADDR only */
	char			symbol[RANGE_SPEC_SYMLEN]; /* RANGE_SYMBOL */
	int			mode;		/* PT_RANGE_FILTER(1) or _TRACESTOP(2) */
};

/*
 * Per-thread trace context — one for each additional thread opened
 * in all-threads mode.  The primary thread uses ctx_fd/trace_buf
 * in hwt_ctx directly.
 */
#define	MAX_THREADS	64

struct hwt_thread_ctx {
	int		fd;		/* /dev/hwt_<ident>_<thread_id>, or -1 */
	int		thread_id;
	void		*trace_buf;	/* mmap'd buffer, or NULL */
};

struct hwt_ctx {
	int		ctl_fd;		/* /dev/hwt                       */
	int		ctx_fd;		/* /dev/hwt_<ident>_<tid>         */
	int		kq_fd;		/* kqueue for event notification   */
	int		ident;		/* kernel-assigned context ident   */
	int		mode;		/* HWT_MODE_THREAD or _CPU        */
	int		tid;		/* thread index (default 0)       */
	pid_t		pid;		/* target PID (thread mode)       */
	char		backend_name[HWT_BACKEND_MAXNAMELEN];
	size_t		bufsize;	/* trace buffer size in bytes     */
	void		*trace_buf;	/* mmap'd trace buffer, or NULL   */
	struct ip_filter filter;	/* hardware IP range filter       */
	uint32_t	psb_freq;	/* PSB sync frequency (0=default) */
	uint32_t	mtc_freq;	/* MTC timing frequency (0=off)   */
	uint32_t	cyc_thresh;	/* CYC cycle-accurate thresh (0=off) */
	bool		ptwrite;	/* true if -W (PTWRITE enabled)   */
	bool		os_trace;	/* true if -K (OS/kernel trace)   */
	bool		all_threads;	/* true if -T all                 */
	int		requested_tids[MAX_THREADS]; /* -T 0,1,3 list      */
	int		nrequested;	/* count of requested tids        */
	struct hwt_thread_ctx threads[MAX_THREADS];
	int		nthreads;	/* count of opened thread devices */
};

/* ------------------------------------------------------------------ */
/* hwt.c — HWT context management                                     */
/* ------------------------------------------------------------------ */

int	 hwt_available(void);
int	 hwt_hooks_enabled(void);
char	*hwt_detect_backend(void);

void	 hwt_pt_default_timing(uint32_t *mtc_out, uint32_t *cyc_out);
struct pt_capture_env;
int	 hwt_pt_capture_env(struct pt_capture_env *env);

int	 hwt_ctx_alloc(struct hwt_ctx *ctx, int mode, pid_t pid,
	    int tid, size_t bufsize, const char *backend);
int	 hwt_ctx_set_config(struct hwt_ctx *ctx, bool pause_on_mmap);
int	 hwt_ctx_start(struct hwt_ctx *ctx);
int	 hwt_ctx_stop(struct hwt_ctx *ctx);
int	 hwt_ctx_poll_records(struct hwt_ctx *ctx,
	    struct bsdtrace_record *records, int maxrecords,
	    bool wait, int *nout);
int	 hwt_ctx_wakeup(struct hwt_ctx *ctx);
void	*hwt_ctx_map_buffer(struct hwt_ctx *ctx);
int	 hwt_ctx_bufptr_get(struct hwt_ctx *ctx, int *page_out,
	    vm_offset_t *offset_out);
ssize_t	 hwt_ctx_snapshot_buffer(struct hwt_ctx *ctx, const char *path,
	    int last_page, vm_offset_t last_offset);
int	 hwt_ctx_open_thread(struct hwt_ctx *ctx, int thread_id,
	    bool pause_on_mmap);
void	 hwt_ctx_close(struct hwt_ctx *ctx);

/* ------------------------------------------------------------------ */
/* Shared types                                                        */
/* ------------------------------------------------------------------ */

/*
 * Binary image section collected from EXEC / MMAP HWT records.
 */
struct pt_image_info {
	char		path[MAXPATHLEN];
	uint64_t	load_addr;	/* addr from EXEC/MMAP record */
	uint64_t	base_addr;	/* baseaddr (interp base for EXEC) */
	uint64_t	pgoff;		/* mapping file offset (0 = unknown) */
	uint64_t	maplen;		/* mapping length (0 = unknown) */
	int		type;		/* HWT_RECORD_EXECUTABLE or _MMAP */
};

/*
 * Symbol table — maps runtime addresses to function names.
 */
struct sym_entry {
	uint64_t	addr;		/* runtime virtual address */
	uint64_t	size;		/* symbol size (0 if unknown) */
	int64_t		slide;		/* runtime - file address offset */
	char		*name;		/* function name (strdup'd) */
	char		*binary;	/* binary basename (strdup'd) */
};

struct sym_table {
	struct sym_entry	*entries;
	int			count;
	int			capacity;
};

/*
 * Binary load range — for showing binary+offset when no symbol matches.
 */
#define	MAX_BIN_RANGES	256

struct bin_range {
	char		name[64];	/* basename of binary */
	uint64_t	lo;		/* lowest runtime text address */
	uint64_t	hi;		/* highest runtime text address */
	uint64_t	base;		/* load base (slide origin) */
};

/*
 * Per-trace accumulator — tracks image sections, buffer state, and
 * metadata across the polling loop.
 */
/* Per-buffer extent/wrap tracking for secondary thread buffers. */
struct trace_buf_state {
	int			buf_id;
	int			max_page;
	bool			wrapped;
};

struct trace_state {
	struct pt_image_info	*sections;
	int			nsections;
	int			sections_cap;
	struct meta_writer	*meta;
	int			buf_tid;	/* primary buffer id */
	int			last_buf_page;
	int			max_buf_page;
	vm_offset_t		last_buf_offset;
	bool			buf_wrapped;
	int			overflow_count;
	struct trace_buf_state	*tbufs;
	int			ntbufs;
	int			tbufs_cap;
};

bool	 trace_state_thread_wrapped(const struct trace_state *ts, int buf_id);

struct decode_probe_result {
	int	total;
	int	exec_hits;
};

/* ------------------------------------------------------------------ */
/* format.c — output formatting                                        */
/* ------------------------------------------------------------------ */

void	 fmt_record_text(const struct bsdtrace_record *rec, pid_t pid);
void	 fmt_record_json(const struct bsdtrace_record *rec, pid_t pid);
int	 json_escape(char *dst, size_t dstlen, const char *src);

/* ------------------------------------------------------------------ */
/* elf.c — ELF parsing                                                 */
/* ------------------------------------------------------------------ */

struct pt_image;	/* forward decl (libipt) */
struct _Elf;		/* forward decl (libelf) */
typedef struct _Elf Elf;

/*
 * Capture-machine environment.  Recorded in the .meta sidecar at
 * capture time and fed to libipt's pt_config at decode time so
 * offline (and cross-machine) decode uses the CPU identity, TSC/CTC
 * ratio, nominal frequency, and address-filter setup of the machine
 * that produced the trace — not the decode host's.  Without the
 * CPUID 0x15 ratio libipt silently drops every MTC packet's time
 * contribution; without nom_freq CYC calibration degrades; without
 * the CPU identity errata workarounds are misapplied.
 */
struct pt_capture_env {
	bool		valid;
	uint16_t	family;
	uint8_t		model;
	uint8_t		stepping;
	uint32_t	cpuid_15_eax;	/* TSC/CTC ratio denominator */
	uint32_t	cpuid_15_ebx;	/* TSC/CTC ratio numerator */
	uint8_t		nom_freq;	/* MSR_PLATFORM_INFO[15:8] */
	/* Hardware address filter as programmed at capture. */
	int		nranges;
	uint64_t	range_a[2];
	uint64_t	range_b[2];
	int		range_cfg[2];	/* RTIT_CTL ADDRn_CFG encoding */
};

struct pt_decode_opts {
	int		tid;
	uint8_t		mtc_freq;
	uint8_t		cyc_thresh;
	const char	**filter_funcs;	/* -F func1,func2 (NULL = no filter) */
	int		nfilter_funcs;
	struct pt_capture_env env;
};

bool	 is_user_addr(uint64_t addr);
int	 elf_base_vaddr(Elf *elf, uint64_t *base_out);
int	 elf_exec_map_vaddr(Elf *elf, uint64_t *exec_out);
int	 elf_preferred_symtab_type(Elf *elf);
int	 elf_effective_load_addr(Elf *elf, int type, uint64_t record_addr,
	    uint64_t pgoff, uint64_t maplen, uint64_t *load_out);
bool	 section_should_use(const struct pt_image_info *sections, int nsections,
	    int idx);
int	 add_elf_to_image(struct pt_image *image, const char *path,
	    uint64_t load_addr);
int	 elf_get_interp(const char *path, char *interp, size_t interpsz);
int	 build_bin_ranges(const struct pt_image_info *sections, int nsections,
	    struct bin_range *ranges, int maxranges);
const char *find_binary_for_ip(const struct bin_range *ranges, int nranges,
	    uint64_t ip, uint64_t *offset);

/* ------------------------------------------------------------------ */
/* symbols.c — symbol table                                            */
/* ------------------------------------------------------------------ */

void	 sym_table_init(struct sym_table *st);
void	 sym_table_add(struct sym_table *st, uint64_t addr, uint64_t size,
	    const char *name, const char *binary, int64_t slide);
void	 sym_table_add_elf(struct sym_table *st, const char *path,
	    int64_t slide);
void	 sym_table_sort(struct sym_table *st);
const struct sym_entry *sym_table_lookup(const struct sym_table *st,
	    uint64_t ip);
void	 sym_table_free(struct sym_table *st);

/* ------------------------------------------------------------------ */
/* resolve.c — symbol-to-address range resolution                      */
/* ------------------------------------------------------------------ */

int	 parse_range_spec(const char *arg, struct range_spec *spec);
int	 resolve_symbol_in_elf(const char *path, int64_t slide,
	    const char *name, uint64_t *start_out, uint64_t *end_out);
int	 process_exe_fullpath(pid_t pid, char *buf, size_t bufsz);
int	 process_load_addr(pid_t pid, const char *exe_path,
	    uint64_t *load_out);
int	 process_exec_mmaps(pid_t pid,
	    struct pt_image_info **sections_out, int *nsections_out);
int	 elf_is_pie(const char *path);
int	 resolve_range_specs(struct range_spec *specs, int nspecs,
	    struct ip_filter *filter, pid_t pid, const char *exe_path,
	    bool is_exec_mode, bool *aslr_disable);

/* ------------------------------------------------------------------ */
/* decode.c — PT packet / instruction decoder                          */
/* ------------------------------------------------------------------ */

int	 decode_pt_buffer(const void *buf, size_t len, enum bsdtrace_fmt fmt);
int	 decode_pt_insn(const void *buf, size_t len,
	    const struct pt_image_info *sections, int nsections,
	    enum bsdtrace_fmt fmt, const struct pt_decode_opts *opts);
int	 decode_pt_probe(const void *buf, size_t len,
	    const struct pt_image_info *sections, int nsections,
	    const struct pt_decode_opts *opts,
	    struct decode_probe_result *result);

/* ------------------------------------------------------------------ */
/* dwarf.c — DWARF source-line resolution                              */
/* ------------------------------------------------------------------ */

struct dwarf_cache;
struct dwarf_cache *dwarf_cache_open(const char *binary_path, int64_t slide);
int	 dwarf_addr_to_line(struct dwarf_cache *dc, uint64_t addr,
	    char *file_out, size_t filesz, int *line_out);
void	 dwarf_cache_close_all(void);

/* ------------------------------------------------------------------ */
/* meta.c — .meta sidecar writer/reader                                */
/* ------------------------------------------------------------------ */

struct meta_writer;

struct meta_writer *meta_writer_open(const char *path);
void	 meta_writer_header(struct meta_writer *mw, pid_t pid, int tid);
void	 meta_writer_timing(struct meta_writer *mw, uint8_t mtc_freq,
	    uint8_t cyc_thresh);
void	 meta_writer_record(struct meta_writer *mw,
	    const struct bsdtrace_record *rec);
void	 meta_writer_sections(struct meta_writer *mw,
	    const struct pt_image_info *sections, int nsections);
void	 meta_writer_close(struct meta_writer *mw);
int	 meta_read_tid(const char *path);
int	 meta_read_mtc_freq(const char *path);
int	 meta_read_cyc_thresh(const char *path);
void	 meta_writer_capture_env(struct meta_writer *mw,
	    const struct pt_capture_env *env, const struct ip_filter *filter);
int	 meta_read_capture_env(const char *path, struct pt_capture_env *env);
int	 meta_read_sections(const char *path,
	    struct pt_image_info **sections_out, int *nsections_out);

/* ------------------------------------------------------------------ */
/* trace.c — trace state and shared helpers                            */
/* ------------------------------------------------------------------ */

void	 trace_state_init(struct trace_state *ts, struct meta_writer *meta);
void	 trace_state_process(struct trace_state *ts,
	    const struct bsdtrace_record *rec);
int	 trace_state_drain_post_stop(struct hwt_ctx *ctx,
	    struct trace_state *ts);
int	 trace_state_seed_process_mmaps(struct trace_state *ts, pid_t pid);
void	 trace_state_free(struct trace_state *ts);
ssize_t	 snapshot_and_decode(struct hwt_ctx *ctx, struct trace_state *ts,
	    const char *pt_output, enum bsdtrace_fmt fmt,
	    const struct pt_decode_opts *opts);

void	 emit_and_process(const struct bsdtrace_record *rec, pid_t pid,
	    enum bsdtrace_fmt fmt, bool pause_on_mmap, struct hwt_ctx *ctx,
	    struct trace_state *ts);
const char *resolve_backend(const char *explicit_name, char **detected_out,
	    bool dryrun);
int	 check_hwt_hooks(bool dryrun);
void	 derive_meta_path(const char *pt_output, char *meta_path,
	    size_t meta_pathsz);
int	 trace_finalize(struct hwt_ctx *ctx, struct trace_state *ts,
	    struct meta_writer *meta, const char *pt_output, pid_t pid,
	    enum bsdtrace_fmt fmt, int totalrecords,
	    const struct pt_decode_opts *opts);

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

int	 cmd_list(int argc, char **argv);
int	 cmd_exec(int argc, char **argv);
int	 cmd_trace(int argc, char **argv);
int	 cmd_decode(int argc, char **argv);

/* ------------------------------------------------------------------ */
/* bsdtrace.c — shared helpers                                         */
/* ------------------------------------------------------------------ */

size_t	 parse_size(const char *s);
const char *elf_strptr_safe(Elf *elf, size_t link, size_t off);
const char *process_name(pid_t pid, char *buf, size_t bufsz);

#endif /* !BSDTRACE_H */
