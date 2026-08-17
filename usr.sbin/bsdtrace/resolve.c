/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * resolve.c — resolve -r arguments to runtime IP address ranges.
 *
 * Supports two forms:
 *   -r 0xstart:0xend   → raw hex addresses (passed through)
 *   -r my_function      → ELF symbol lookup with slide correction
 *
 * For trace mode (attach to running process), the load address is
 * read from the kernel via KERN_PROC_VMMAP.  For exec mode, ASLR
 * is disabled so the ELF addresses are the runtime addresses.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdtrace.h"

#define	UNKNOWN_SIZE_FALLBACK	4096

/* ------------------------------------------------------------------ */
/* Argument parsing                                                    */
/* ------------------------------------------------------------------ */

/*
 * Detect whether a -r argument is a hex range or a symbol name.
 * Returns 0 on success, -1 on parse error.
 */
int
parse_range_spec(const char *arg, struct range_spec *spec)
{
	const char *inner;

	memset(spec, 0, sizeof(*spec));
	spec->mode = PT_RANGE_FILTER;

	/* Check for "stop:" prefix → TraceStop mode. */
	if (strncmp(arg, "stop:", 5) == 0) {
		spec->mode = PT_RANGE_TRACESTOP;
		inner = arg + 5;
	} else {
		inner = arg;
	}

	if (sscanf(inner, "0x%lx:0x%lx", &spec->start, &spec->end) == 2) {
		if (spec->end <= spec->start) {
			warnx("-r range end 0x%lx must be greater than "
			    "start 0x%lx", (unsigned long)spec->end,
			    (unsigned long)spec->start);
			return (-1);
		}
		spec->type = RANGE_ADDR;
		return (0);
	}

	if (inner[0] == '\0') {
		warnx("empty -r argument");
		return (-1);
	}
	spec->type = RANGE_SYMBOL;
	if (strlcpy(spec->symbol, inner, sizeof(spec->symbol)) >=
	    sizeof(spec->symbol)) {
		warnx("symbol name too long: %s", inner);
		return (-1);
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* ELF symbol lookup                                                   */
/* ------------------------------------------------------------------ */

/*
 * Result of a symbol-table scan for one name.
 */
struct sym_scan {
	bool		found_func;	/* an STT_FUNC matched */
	bool		found_ifunc;	/* an STT_GNU_IFUNC matched */
	uint64_t	value;		/* first STT_FUNC match value */
	uint64_t	size;		/* first STT_FUNC match size */
};

static const GElf_Word resolve_sec_types[] = { SHT_SYMTAB, SHT_DYNSYM };

/*
 * Scan .symtab then .dynsym for symbols named 'name'.  Records the
 * first STT_FUNC match (so .symtab is preferred) and whether any
 * STT_GNU_IFUNC of that name exists.
 */
static void
scan_symbol(Elf *elf, const char *name, struct sym_scan *ss)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	Elf_Data *data;
	GElf_Sym sym;
	const char *sname;
	size_t nsyms;
	size_t i;
	int stype;

	memset(ss, 0, sizeof(*ss));

	for (int t = 0; t < (int)nitems(resolve_sec_types); t++) {
		scn = NULL;
		while ((scn = elf_nextscn(elf, scn)) != NULL) {
			if (gelf_getshdr(scn, &shdr) == NULL)
				continue;
			if (shdr.sh_type != resolve_sec_types[t])
				continue;
			if (shdr.sh_entsize !=
			    gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT))
				continue;

			data = NULL;
			while ((data = elf_getdata(scn, data)) != NULL) {
				nsyms = data->d_size / shdr.sh_entsize;
				for (i = 0; i < nsyms; i++) {
					if (gelf_getsym(data, (int)i, &sym) ==
					    NULL)
						continue;
					stype = GELF_ST_TYPE(sym.st_info);
					if (stype != STT_FUNC &&
					    stype != STT_GNU_IFUNC)
						continue;
					if (sym.st_value == 0)
						continue;

					sname = elf_strptr_safe(elf,
					    shdr.sh_link, sym.st_name);
					if (sname == NULL)
						continue;
					if (strcmp(sname, name) != 0)
						continue;

					if (stype == STT_GNU_IFUNC) {
						ss->found_ifunc = true;
						continue;
					}
					if (!ss->found_func) {
						ss->found_func = true;
						ss->value = sym.st_value;
						ss->size = sym.st_size;
					}
				}
			}
		}
	}
}

/*
 * Find the lowest function-symbol address strictly above 'after' —
 * the sorted-table successor, which is the natural end boundary for
 * a size-0 symbol.  Returns 0 if no such symbol exists.
 */
static uint64_t
next_symbol_addr(Elf *elf, uint64_t after)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	Elf_Data *data;
	GElf_Sym sym;
	uint64_t next;
	size_t nsyms;
	size_t i;
	int stype;

	next = 0;

	for (int t = 0; t < (int)nitems(resolve_sec_types); t++) {
		scn = NULL;
		while ((scn = elf_nextscn(elf, scn)) != NULL) {
			if (gelf_getshdr(scn, &shdr) == NULL)
				continue;
			if (shdr.sh_type != resolve_sec_types[t])
				continue;
			if (shdr.sh_entsize !=
			    gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT))
				continue;

			data = NULL;
			while ((data = elf_getdata(scn, data)) != NULL) {
				nsyms = data->d_size / shdr.sh_entsize;
				for (i = 0; i < nsyms; i++) {
					if (gelf_getsym(data, (int)i, &sym) ==
					    NULL)
						continue;
					stype = GELF_ST_TYPE(sym.st_info);
					if (stype != STT_FUNC &&
					    stype != STT_GNU_IFUNC)
						continue;
					if (sym.st_value <= after)
						continue;
					if (next == 0 || sym.st_value < next)
						next = sym.st_value;
				}
			}
		}
	}

	return (next);
}

/*
 * Find a function symbol in an ELF file and return its runtime
 * address range (start, start+size).
 *
 * slide is the runtime adjustment: load_addr - base_vaddr.
 * For non-PIE with ASLR disabled, slide is 0.
 *
 * STT_GNU_IFUNC-only matches are rejected: the ifunc symbol's address
 * is the resolver stub, and programming the hardware range filter on
 * it would capture nothing from the runtime-selected implementation.
 * If both a FUNC and an IFUNC of the same name exist, the FUNC wins.
 *
 * Returns 0 on success, -1 if the symbol is not found.
 */
int
resolve_symbol_in_elf(const char *path, int64_t slide,
    const char *name, uint64_t *start_out, uint64_t *end_out)
{
	Elf *elf;
	struct sym_scan ss;
	uint64_t next;
	int fd;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return (-1);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		warn("open %s", path);
		return (-1);
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		warnx("elf_begin: %s: %s", path, elf_errmsg(-1));
		close(fd);
		return (-1);
	}

	scan_symbol(elf, name, &ss);

	if (!ss.found_func) {
		if (ss.found_ifunc) {
			warnx("'%s' is an ifunc (STT_GNU_IFUNC): its "
			    "implementation is chosen by a resolver at "
			    "runtime, so filtering on the symbol would "
			    "trace only the resolver stub", name);
			warnx("use a raw address range instead: "
			    "-r 0xstart:0xend, with the implementation's "
			    "addresses obtained from the running process");
		} else {
			warnx("symbol '%s' not found in %s", name, path);
		}
		elf_end(elf);
		close(fd);
		return (-1);
	}

	*start_out = ss.value + slide;
	if (ss.size > 0) {
		*end_out = ss.value + ss.size + slide;
	} else {
		next = next_symbol_addr(elf, ss.value);
		if (next != 0) {
			warnx("symbol '%s' has no size info, bounding "
			    "range at next symbol", name);
			*end_out = next + slide;
		} else {
			warnx("symbol '%s' has no size info, using "
			    "%d-byte estimate", name,
			    UNKNOWN_SIZE_FALLBACK);
			*end_out = ss.value + UNKNOWN_SIZE_FALLBACK +
			    slide;
		}
	}

	elf_end(elf);
	close(fd);
	return (0);
}

/* ------------------------------------------------------------------ */
/* PIE detection                                                       */
/* ------------------------------------------------------------------ */

/*
 * Check if an ELF binary is position-independent (ET_DYN).
 * Returns 1 for PIE, 0 for non-PIE, -1 on error.
 */
int
elf_is_pie(const char *path)
{
	Elf *elf;
	GElf_Ehdr ehdr;
	int fd, result;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return (-1);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (-1);

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		close(fd);
		return (-1);
	}

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		elf_end(elf);
		close(fd);
		return (-1);
	}

	result = (ehdr.e_type == ET_DYN) ? 1 : 0;
	elf_end(elf);
	close(fd);
	return (result);
}

/* ------------------------------------------------------------------ */
/* Process introspection                                               */
/* ------------------------------------------------------------------ */

/*
 * Get the full executable path for a running process.
 * Returns 0 on success, -1 on failure.
 */
int
process_exe_fullpath(pid_t pid, char *buf, size_t bufsz)
{
	int mib[4];
	size_t len;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = pid;
	len = bufsz;

	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0)
		return (-1);
	return (0);
}

/*
 * Find the load address of a process's main executable by walking
 * its VM map via KERN_PROC_VMMAP.
 *
 * Looks for the first executable vnode mapping whose path matches
 * exe_path.  Returns the mapping's start address in *load_out.
 *
 * Returns 0 on success, -1 on failure.
 */
int
process_load_addr(pid_t pid, const char *exe_path, uint64_t *load_out)
{
	int mib[4];
	char *buf, *p, *end;
	struct kinfo_vmentry *kve;
	size_t len;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_VMMAP;
	mib[3] = pid;

	len = 0;
	if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
		warn("sysctl KERN_PROC_VMMAP (size)");
		return (-1);
	}

	/* Add slack — new mappings may appear between calls. */
	len = len * 4 / 3;
	buf = malloc(len);
	if (buf == NULL) {
		warn("malloc");
		return (-1);
	}

	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) {
		warn("sysctl KERN_PROC_VMMAP");
		free(buf);
		return (-1);
	}

	p = buf;
	end = buf + len;
	while (p < end) {
		/* Guard against a truncated buffer before touching kve. */
		if ((size_t)(end - p) < sizeof(int))
			break;
		kve = (struct kinfo_vmentry *)p;
		if (kve->kve_structsize <= 0 ||
		    kve->kve_structsize > end - p)
			break;

		if (kve->kve_type == KVME_TYPE_VNODE &&
		    (kve->kve_protection & KVME_PROT_EXEC) != 0 &&
		    kve->kve_path[0] != '\0' &&
		    strcmp(kve->kve_path, exe_path) == 0) {
			*load_out = kve->kve_start;
			free(buf);
			return (0);
		}

		p += kve->kve_structsize;
	}

	warnx("no executable mapping found for %s in pid %d",
	    exe_path, (int)pid);
	free(buf);
	return (-1);
}

int
process_exec_mmaps(pid_t pid,
    struct pt_image_info **sections_out, int *nsections_out)
{
	struct pt_image_info *sections, *newsections;
	struct kinfo_vmentry *kve;
	int mib[4];
	char *buf, *p, *end;
	size_t len;
	int nsections, capacity;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_VMMAP;
	mib[3] = pid;

	len = 0;
	if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
		warn("sysctl KERN_PROC_VMMAP (size)");
		return (-1);
	}

	len = len * 4 / 3;
	buf = malloc(len);
	if (buf == NULL) {
		warn("malloc");
		return (-1);
	}

	if (sysctl(mib, 4, buf, &len, NULL, 0) != 0) {
		warn("sysctl KERN_PROC_VMMAP");
		free(buf);
		return (-1);
	}

	sections = NULL;
	nsections = 0;
	capacity = 0;

	p = buf;
	end = buf + len;
	while (p < end) {
		/* Guard against a truncated buffer before touching kve. */
		if ((size_t)(end - p) < sizeof(int))
			break;
		kve = (struct kinfo_vmentry *)p;
		if (kve->kve_structsize <= 0 ||
		    kve->kve_structsize > end - p)
			break;

		if (kve->kve_type == KVME_TYPE_VNODE &&
		    (kve->kve_protection & KVME_PROT_EXEC) != 0 &&
		    kve->kve_path[0] != '\0') {
			if (nsections >= capacity) {
				capacity = capacity == 0 ? 16 : capacity * 2;
				newsections = realloc(sections,
				    (size_t)capacity * sizeof(*sections));
				if (newsections == NULL) {
					free(sections);
					free(buf);
					return (-1);
				}
				sections = newsections;
			}

			memset(&sections[nsections], 0,
			    sizeof(sections[nsections]));
			strlcpy(sections[nsections].path, kve->kve_path,
			    sizeof(sections[nsections].path));
			sections[nsections].load_addr = kve->kve_start;
			sections[nsections].base_addr = 0;
			sections[nsections].pgoff =
			    (uint64_t)kve->kve_offset;
			sections[nsections].maplen =
			    kve->kve_end - kve->kve_start;
			sections[nsections].type = HWT_RECORD_MMAP;
			nsections++;
		}

		p += kve->kve_structsize;
	}

	free(buf);
	*sections_out = sections;
	*nsections_out = nsections;
	return (0);
}

/* ------------------------------------------------------------------ */
/* Top-level resolver                                                  */
/* ------------------------------------------------------------------ */

/*
 * Compute the slide for symbol resolution.
 * Opens the ELF once to get base_vaddr and (in exec mode) check PIE.
 *
 * For exec mode: non-PIE → slide=0, PIE → error (not yet supported).
 * For trace mode: reads VMMAP to get runtime load address, then
 *   slide = load_addr - base_vaddr.
 *
 * Sets *need_aslr_disable to true if exec mode requires ASLR off.
 * Returns 0 on success, -1 on error.
 */
static int
compute_slide(const char *exe_path, pid_t pid, bool is_exec_mode,
    int64_t *slide_out, bool *need_aslr_disable)
{
	Elf *elf;
	GElf_Ehdr ehdr;
	uint64_t base_vaddr, load_addr;
	int fd;

	*need_aslr_disable = false;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return (-1);

	fd = open(exe_path, O_RDONLY);
	if (fd < 0) {
		warn("open %s", exe_path);
		return (-1);
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		warnx("elf_begin: %s: %s", exe_path, elf_errmsg(-1));
		close(fd);
		return (-1);
	}

	if (is_exec_mode) {
		if (gelf_getehdr(elf, &ehdr) == NULL) {
			elf_end(elf);
			close(fd);
			return (-1);
		}
		if (ehdr.e_type == ET_DYN) {
			warnx("symbol-based range filter is not yet "
			    "supported for PIE binaries in exec mode");
			warnx("use 'bsdtrace trace' mode instead, or "
			    "pass raw addresses with -r 0xstart:0xend");
			elf_end(elf);
			close(fd);
			return (-1);
		}
		*need_aslr_disable = true;
		*slide_out = 0;
		elf_end(elf);
		close(fd);
		return (0);
	}

	/*
	 * Trace mode — compute slide from runtime load address.
	 *
	 * process_load_addr() returns the start of the first
	 * *executable* mapping of the binary, so it must be paired
	 * with the lowest executable PT_LOAD vaddr, not the first
	 * PT_LOAD: FreeBSD lld splits R and RX into separate
	 * segments, and the R segment maps first.  Pairing with the
	 * first PT_LOAD skews the slide by the text offset (and
	 * makes it nonzero even for non-PIE binaries).
	 */
	if (elf_exec_map_vaddr(elf, &base_vaddr) != 0) {
		warnx("cannot determine ELF exec segment vaddr: %s",
		    exe_path);
		elf_end(elf);
		close(fd);
		return (-1);
	}
	elf_end(elf);
	close(fd);

	if (process_load_addr(pid, exe_path, &load_addr) != 0)
		return (-1);

	*slide_out = (int64_t)load_addr - (int64_t)base_vaddr;
	return (0);
}

/*
 * Resolve an array of range_spec entries into an ip_filter.
 *
 * For RANGE_ADDR specs, the addresses are copied through.
 * For RANGE_SYMBOL specs, the ELF is opened and the symbol is
 * looked up with the appropriate slide.
 *
 * Sets *aslr_disable if ASLR must be disabled (exec mode with symbols).
 * Returns 0 on success, -1 on error.
 */
int
resolve_range_specs(struct range_spec *specs, int nspecs,
    struct ip_filter *filter, pid_t pid, const char *exe_path,
    bool is_exec_mode, bool *aslr_disable)
{
	int64_t slide;
	bool need_resolve, need_aslr;
	int i;

	memset(filter, 0, sizeof(*filter));
	*aslr_disable = false;

	need_resolve = false;
	for (i = 0; i < nspecs; i++) {
		if (specs[i].type == RANGE_SYMBOL) {
			need_resolve = true;
			break;
		}
	}

	slide = 0;
	if (need_resolve) {
		if (exe_path == NULL || exe_path[0] == '\0') {
			warnx("cannot resolve symbol: no executable path");
			return (-1);
		}
		if (compute_slide(exe_path, pid, is_exec_mode,
		    &slide, &need_aslr) != 0)
			return (-1);
		*aslr_disable = need_aslr;
	}

	for (i = 0; i < nspecs; i++) {
		if (filter->nranges >= 2) {
			warnx("too many ranges (max 2)");
			return (-1);
		}

		/*
		 * Both spec forms produce an EXCLUSIVE end
		 * ([start, end)), but IA32_RTIT_ADDRn_B is INCLUSIVE
		 * ("ADDRn_A <= IP <= ADDRn_B", and libipt's decode-side
		 * filter matches) — programming `end` verbatim would
		 * include the first byte of whatever follows the range.
		 * In TraceStop mode that means any entry into the
		 * adjacent next function kills the trace.  Convert here
		 * so the MSR, the sidecar, and the decoder all agree.
		 */
		switch (specs[i].type) {
		case RANGE_ADDR:
			filter->ranges[filter->nranges].start = specs[i].start;
			filter->ranges[filter->nranges].end =
			    specs[i].end - 1;
			filter->modes[filter->nranges] = specs[i].mode;
			filter->nranges++;
			break;
		case RANGE_SYMBOL:
			if (resolve_symbol_in_elf(exe_path, slide,
			    specs[i].symbol,
			    &filter->ranges[filter->nranges].start,
			    &filter->ranges[filter->nranges].end) != 0)
				return (-1);
			filter->ranges[filter->nranges].end -= 1;
			fprintf(stderr, "resolved '%s' -> "
			    "0x%lx:0x%lx (inclusive)%s\n",
			    specs[i].symbol,
			    filter->ranges[filter->nranges].start,
			    filter->ranges[filter->nranges].end,
			    specs[i].mode == PT_RANGE_TRACESTOP ?
			    " (tracestop)" : "");
			filter->modes[filter->nranges] = specs[i].mode;
			filter->nranges++;
			break;
		}
	}

	return (0);
}
