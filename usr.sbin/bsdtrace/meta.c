/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Metadata sidecar (.meta) — save and load EXEC/MMAP/THREAD records
 * as JSONL alongside the .pt file for offline decode.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/hwt.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsdtrace.h"

/* ------------------------------------------------------------------ */
/* Writer                                                              */
/* ------------------------------------------------------------------ */

struct meta_writer {
	FILE	*fp;
};

struct meta_writer *
meta_writer_open(const char *path)
{
	struct meta_writer *mw;

	mw = calloc(1, sizeof(*mw));
	if (mw == NULL)
		return (NULL);

	mw->fp = fopen(path, "w");
	if (mw->fp == NULL) {
		warn("fopen %s", path);
		free(mw);
		return (NULL);
	}
	/* Line-buffer so each JSONL record is flushed immediately.
	 * Without this, SIGPIPE or Ctrl-C loses all buffered metadata. */
	setvbuf(mw->fp, NULL, _IOLBF, 0);
	return (mw);
}

void
meta_writer_header(struct meta_writer *mw, pid_t pid, int tid)
{

	if (mw == NULL || mw->fp == NULL)
		return;
	fprintf(mw->fp,
	    "{\"type\":\"header\",\"pid\":%d,\"tid\":%d}\n",
	    (int)pid, tid);
}

void
meta_writer_timing(struct meta_writer *mw, uint8_t mtc_freq, uint8_t cyc_thresh)
{

	if (mw == NULL || mw->fp == NULL)
		return;
	if (mtc_freq == 0 && cyc_thresh == 0)
		return;
	fprintf(mw->fp,
	    "{\"type\":\"timing\",\"mtc_freq\":%u,\"cyc_thresh\":%u}\n",
	    mtc_freq, cyc_thresh);
}

void
meta_writer_capture_env(struct meta_writer *mw,
    const struct pt_capture_env *env, const struct ip_filter *filter)
{
	int i;

	if (mw == NULL || mw->fp == NULL)
		return;
	if (env != NULL && env->valid)
		fprintf(mw->fp,
		    "{\"type\":\"capture_env\",\"family\":%u,"
		    "\"model\":%u,\"stepping\":%u,"
		    "\"cpuid15_eax\":%u,\"cpuid15_ebx\":%u,"
		    "\"nom_freq\":%u}\n",
		    (unsigned)env->family, (unsigned)env->model,
		    (unsigned)env->stepping,
		    (unsigned)env->cpuid_15_eax,
		    (unsigned)env->cpuid_15_ebx,
		    (unsigned)env->nom_freq);
	if (filter != NULL) {
		for (i = 0; i < filter->nranges && i < 2; i++)
			fprintf(mw->fp,
			    "{\"type\":\"addr_range\",\"a\":\"0x%lx\","
			    "\"b\":\"0x%lx\",\"cfg\":%d}\n",
			    (unsigned long)filter->ranges[i].start,
			    (unsigned long)filter->ranges[i].end,
			    filter->modes[i]);
	}
}

void
meta_writer_record(struct meta_writer *mw, const struct bsdtrace_record *rec)
{
	/* json_escape emits at most 6 bytes per input byte. */
	char epath[MAXPATHLEN * 6 + 1];

	if (mw == NULL || mw->fp == NULL)
		return;

	switch (rec->type) {
	case HWT_RECORD_EXECUTABLE:
		json_escape(epath, sizeof(epath), rec->fullpath);
		fprintf(mw->fp,
		    "{\"type\":\"exec\",\"path\":\"%s\","
		    "\"addr\":\"0x%lx\",\"base\":\"0x%lx\"}\n",
		    epath,
		    (unsigned long)rec->addr,
		    (unsigned long)rec->baseaddr);
		break;
	case HWT_RECORD_MMAP:
		json_escape(epath, sizeof(epath), rec->fullpath);
		if (rec->maplen > 0)
			fprintf(mw->fp,
			    "{\"type\":\"mmap\",\"path\":\"%s\","
			    "\"addr\":\"0x%lx\",\"base\":\"0x%lx\","
			    "\"pgoff\":\"0x%lx\",\"len\":\"0x%lx\"}\n",
			    epath,
			    (unsigned long)rec->addr,
			    (unsigned long)rec->baseaddr,
			    (unsigned long)rec->pgoff,
			    (unsigned long)rec->maplen);
		else
			fprintf(mw->fp,
			    "{\"type\":\"mmap\",\"path\":\"%s\","
			    "\"addr\":\"0x%lx\",\"base\":\"0x%lx\"}\n",
			    epath,
			    (unsigned long)rec->addr,
			    (unsigned long)rec->baseaddr);
		break;
	case HWT_RECORD_KERNEL:
		json_escape(epath, sizeof(epath), rec->fullpath);
		fprintf(mw->fp,
		    "{\"type\":\"kernel\",\"path\":\"%s\","
		    "\"addr\":\"0x%lx\",\"base\":\"0x%lx\"}\n",
		    epath,
		    (unsigned long)rec->addr,
		    (unsigned long)rec->baseaddr);
		break;
	case HWT_RECORD_MUNMAP:
		if (rec->addr != 0)
			fprintf(mw->fp,
			    "{\"type\":\"munmap\",\"addr\":\"0x%lx\"}\n",
			    (unsigned long)rec->addr);
		break;
	case HWT_RECORD_THREAD_CREATE:
		fprintf(mw->fp,
		    "{\"type\":\"thread_create\",\"tid\":%d}\n",
		    rec->thread_id);
		break;
	case HWT_RECORD_THREAD_SET_NAME:
		fprintf(mw->fp,
		    "{\"type\":\"thread_set_name\",\"tid\":%d}\n",
		    rec->thread_id);
		break;
	default:
		break;
	}
}

void
meta_writer_sections(struct meta_writer *mw,
    const struct pt_image_info *sections, int nsections)
{
	char epath[MAXPATHLEN * 6 + 1];
	int i;

	if (mw == NULL || mw->fp == NULL)
		return;

	for (i = 0; i < nsections; i++) {
		const char *type;

		type = sections[i].type == HWT_RECORD_EXECUTABLE ?
		    "exec" :
		    sections[i].type == HWT_RECORD_KERNEL ?
		    "kernel" : "mmap";
		json_escape(epath, sizeof(epath), sections[i].path);
		if (sections[i].maplen > 0)
			fprintf(mw->fp,
			    "{\"type\":\"%s\",\"path\":\"%s\","
			    "\"addr\":\"0x%lx\",\"base\":\"0x%lx\","
			    "\"pgoff\":\"0x%lx\",\"len\":\"0x%lx\"}\n",
			    type, epath,
			    (unsigned long)sections[i].load_addr,
			    (unsigned long)sections[i].base_addr,
			    (unsigned long)sections[i].pgoff,
			    (unsigned long)sections[i].maplen);
		else
			fprintf(mw->fp,
			    "{\"type\":\"%s\",\"path\":\"%s\","
			    "\"addr\":\"0x%lx\",\"base\":\"0x%lx\"}\n",
			    type, epath,
			    (unsigned long)sections[i].load_addr,
			    (unsigned long)sections[i].base_addr);
	}
}

void
meta_writer_close(struct meta_writer *mw)
{

	if (mw == NULL)
		return;
	if (mw->fp != NULL && fclose(mw->fp) != 0)
		warn("metadata sidecar close failed — .meta may be truncated");
	free(mw);
}

/* ------------------------------------------------------------------ */
/* Reader                                                              */
/* ------------------------------------------------------------------ */

static int
hexval(int c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

/*
 * Reverse json_escape() in place.  Paths are stored JSON-escaped in
 * the sidecar, so e.g. a literal backslash round-trips as "\\" and
 * would otherwise make open() fail during offline decode.  \uXXXX
 * sequences below 0x100 become the raw byte (matching json_escape's
 * latin-1 escaping); higher ones are not producible by json_escape
 * and are kept verbatim.  Returns 0, or -1 on a malformed escape
 * (caller should skip the record).  Output is never longer than the
 * input, so in-place rewriting is safe.
 */
static int
json_unescape(char *s)
{
	char *r, *w;

	for (r = w = s; *r != '\0'; r++) {
		if (*r != '\\') {
			*w++ = *r;
			continue;
		}
		r++;
		switch (*r) {
		case '"':  *w++ = '"'; break;
		case '\\': *w++ = '\\'; break;
		case 'b':  *w++ = '\b'; break;
		case 'f':  *w++ = '\f'; break;
		case 'n':  *w++ = '\n'; break;
		case 'r':  *w++ = '\r'; break;
		case 't':  *w++ = '\t'; break;
		case 'u': {
			unsigned int v;
			int h, k;

			v = 0;
			for (k = 1; k <= 4; k++) {
				h = hexval((unsigned char)r[k]);
				if (h < 0)
					return (-1);
				v = v * 16 + (unsigned int)h;
			}
			if (v < 0x100) {
				*w++ = (char)v;
				r += 4;
			} else {
				/* Not ours; keep verbatim. */
				*w++ = '\\';
				*w++ = 'u';
			}
			break;
		}
		default:
			return (-1);
		}
	}
	*w = '\0';
	return (0);
}

int
meta_read_tid(const char *path)
{
	FILE *fp;
	char line[256];
	int tid;

	fp = fopen(path, "r");
	if (fp == NULL)
		return (-1);

	/* The header is the first line: {"type":"header","pid":N,"tid":N} */
	if (fgets(line, sizeof(line), fp) != NULL &&
	    sscanf(line, "{\"type\":\"header\",\"pid\":%*d,\"tid\":%d}",
	    &tid) == 1) {
		fclose(fp);
		return (tid);
	}

	fclose(fp);
	return (-1);
}

int
meta_read_mtc_freq(const char *path)
{
	FILE *fp;
	char line[256];
	unsigned int mtc_freq;

	fp = fopen(path, "r");
	if (fp == NULL)
		return (0);

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line,
		    "{\"type\":\"timing\",\"mtc_freq\":%u",
		    &mtc_freq) == 1) {
			fclose(fp);
			return ((int)mtc_freq);
		}
	}

	fclose(fp);
	return (0);
}

int
meta_read_cyc_thresh(const char *path)
{
	FILE *fp;
	char line[256];
	unsigned int cyc_thresh;

	fp = fopen(path, "r");
	if (fp == NULL)
		return (0);

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line,
		    "{\"type\":\"timing\",\"mtc_freq\":%*u,\"cyc_thresh\":%u}",
		    &cyc_thresh) == 1) {
			fclose(fp);
			return ((int)cyc_thresh);
		}
	}

	fclose(fp);
	return (0);
}

int
meta_read_sections(const char *path,
    struct pt_image_info **sections_out, int *nsections_out)
{
	FILE *fp;
	struct pt_image_info *sections;
	struct pt_image_info *newsections;
	int nsections, capacity;
	/*
	 * Paths are stored JSON-escaped at up to 6 bytes per input
	 * byte, so the line and path buffers must hold the ESCAPED
	 * form of a MAXPATHLEN path or long paths silently fail to
	 * round-trip.
	 */
	char line[MAXPATHLEN * 6 + 256];
	char type[32], fpath[MAXPATHLEN * 6 + 1];
	uint64_t addr, base, pgoff, maplen;
	int nf;

	fp = fopen(path, "r");
	if (fp == NULL) {
		warn("fopen %s", path);
		return (-1);
	}

	sections = NULL;
	nsections = 0;
	capacity = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		type[0] = '\0';
		fpath[0] = '\0';
		addr = 0;
		base = 0;
		pgoff = 0;
		maplen = 0;

		/*
		 * munmap records invalidate earlier mappings at that
		 * address so a later mapping reuse decodes against
		 * the right bytes.
		 */
		if (sscanf(line, "{\"type\":\"munmap\",\"addr\":\"0x%lx\"}",
		    &addr) == 1) {
			int k, kept = 0;

			/* Parity with trace_state_remove_section(). */
			if (addr == 0)
				continue;

			for (k = 0; k < nsections; k++) {
				if (sections[k].load_addr == addr &&
				    sections[k].type != HWT_RECORD_KERNEL)
					continue;
				sections[kept++] = sections[k];
			}
			nsections = kept;
			continue;
		}

		/*
		 * Parse JSONL lines for exec/mmap records.  Paths are
		 * JSON-escaped on write, so unescape after the scan.
		 * (The %[^"] scanset means a path containing a literal
		 * '"' still cannot round-trip; such records fail the
		 * match and are skipped.)
		 */
		_Static_assert(MAXPATHLEN == 1024,
		    "%6144 scanset width must match the escaped-path "
		    "buffer (MAXPATHLEN * 6)");
		/*
		 * Try the extended form (with the mapping's file
		 * offset and length) first, then the legacy form so
		 * old sidecars keep working (pgoff/len stay 0 =
		 * unknown).
		 */
		nf = sscanf(line,
		    "{\"type\":\"%31[^\"]\",\"path\":\"%6144[^\"]\","
		    "\"addr\":\"0x%lx\",\"base\":\"0x%lx\","
		    "\"pgoff\":\"0x%lx\",\"len\":\"0x%lx\"}",
		    type, fpath, &addr, &base, &pgoff, &maplen);
		if (nf != 6) {
			pgoff = 0;
			maplen = 0;
			nf = sscanf(line,
			    "{\"type\":\"%31[^\"]\",\"path\":\"%6144[^\"]\","
			    "\"addr\":\"0x%lx\",\"base\":\"0x%lx\"}",
			    type, fpath, &addr, &base);
		}
		if (nf < 4) {
#define	LINE_HAS(lit)	(strncmp(line, lit, sizeof(lit) - 1) == 0)
			if (LINE_HAS("{\"type\":\"mmap\"") ||
			    LINE_HAS("{\"type\":\"exec\"") ||
			    LINE_HAS("{\"type\":\"kernel\""))
				warnx("%s: unparsable section record "
				    "skipped", path);
#undef LINE_HAS
			continue;
		}
		if (nf >= 4) {
			if (strcmp(type, "exec") != 0 &&
			    strcmp(type, "mmap") != 0 &&
			    strcmp(type, "kernel") != 0)
				continue;

			if (json_unescape(fpath) != 0) {
				warnx("%s: malformed escape in path — "
				    "record skipped", path);
				continue;
			}

			/*
			 * An EXEC record means the process replaced its
			 * address space.  Discard earlier user-space
			 * sections, but keep kernel sections: KERNEL
			 * records are queued at context alloc, before
			 * the EXEC record arrives, and the live
			 * accumulator keeps them too.
			 */
			if (strcmp(type, "exec") == 0) {
				int k, kept = 0;

				for (k = 0; k < nsections; k++)
					if (sections[k].type ==
					    HWT_RECORD_KERNEL)
						sections[kept++] =
						    sections[k];
				nsections = kept;
			}

			/*
			 * Keep all records — section_should_use() handles
			 * deduplication at decode time, picking the lowest-
			 * address MMAP per path rather than first-wins.
			 */
			if (nsections >= capacity) {
				/* Cap growth so the signed doubling
				 * cannot overflow on a hostile sidecar. */
				if (capacity >= (1 << 20)) {
					warnx("%s: too many sections; "
					    "ignoring the rest", path);
					break;
				}
				capacity = capacity == 0 ? 16 :
				    capacity * 2;
				newsections = realloc(sections,
				    (size_t)capacity *
				    sizeof(*sections));
				if (newsections == NULL) {
					fclose(fp);
					free(sections);
					return (-1);
				}
				sections = newsections;
			}

			if (strlcpy(sections[nsections].path, fpath,
			    sizeof(sections[nsections].path)) >=
			    sizeof(sections[nsections].path)) {
				warnx("%s: over-long path in section "
				    "record — skipped", path);
				continue;
			}
			sections[nsections].load_addr = addr;
			sections[nsections].base_addr = base;
			sections[nsections].pgoff = pgoff;
			sections[nsections].maplen = maplen;
			sections[nsections].type =
			    strcmp(type, "exec") == 0 ?
			    HWT_RECORD_EXECUTABLE :
			    strcmp(type, "kernel") == 0 ?
			    HWT_RECORD_KERNEL : HWT_RECORD_MMAP;
			nsections++;
		}
	}

	fclose(fp);
	*sections_out = sections;
	*nsections_out = nsections;
	return (0);
}

/*
 * Read the capture-machine environment (and any address-filter
 * ranges) back from the sidecar.  Returns 0 if a capture_env record
 * was found; env->valid reflects the result either way.
 */
int
meta_read_capture_env(const char *path, struct pt_capture_env *env)
{
	FILE *fp;
	char line[1024];
	unsigned int family, model, stepping, eax15, ebx15, nomfreq;
	unsigned long a, b;
	int cfg;

	memset(env, 0, sizeof(*env));
	fp = fopen(path, "r");
	if (fp == NULL)
		return (-1);
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line,
		    "{\"type\":\"capture_env\",\"family\":%u,"
		    "\"model\":%u,\"stepping\":%u,"
		    "\"cpuid15_eax\":%u,\"cpuid15_ebx\":%u,"
		    "\"nom_freq\":%u}",
		    &family, &model, &stepping, &eax15, &ebx15,
		    &nomfreq) == 6) {
			/* Untrusted input: clamp to the field widths. */
			if (family > UINT16_MAX || model > UINT8_MAX ||
			    stepping > UINT8_MAX || nomfreq > UINT8_MAX)
				continue;
			env->family = (uint16_t)family;
			env->model = (uint8_t)model;
			env->stepping = (uint8_t)stepping;
			env->cpuid_15_eax = eax15;
			env->cpuid_15_ebx = ebx15;
			env->nom_freq = (uint8_t)nomfreq;
			env->valid = true;
			continue;
		}
		if (sscanf(line,
		    "{\"type\":\"addr_range\",\"a\":\"0x%lx\","
		    "\"b\":\"0x%lx\",\"cfg\":%d}", &a, &b, &cfg) == 3) {
			if (env->nranges >= 2 || cfg < 0 || cfg > 4 ||
			    b <= a)
				continue;
			env->range_a[env->nranges] = a;
			env->range_b[env->nranges] = b;
			env->range_cfg[env->nranges] = cfg;
			env->nranges++;
		}
	}
	fclose(fp);
	return (env->valid ? 0 : -1);
}
