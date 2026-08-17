/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dwarf.c — DWARF .debug_line resolution for source-line attribution.
 *
 * Resolves instruction addresses to source file:line using libdwarf.
 * Caches per-binary Dwarf_Debug handles to avoid re-parsing.
 *
 * Error-object note: this builds against FreeBSD's elftoolchain
 * libdwarf (/usr/include/libdwarf.h), where Dwarf_Error is a by-value
 * struct on the caller's stack — not the SGI/libdwarf heap object.
 * dwarf_dealloc() has no DW_DLA_ERROR case in this implementation
 * (see contrib/elftoolchain/libdwarf/dwarf_dealloc.c), so there is
 * nothing to free on DW_DLV_ERROR paths; error handling below only
 * distinguishes hard errors (DW_DLV_ERROR) from absence of data
 * (DW_DLV_NO_ENTRY) where the two need different behavior.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <dwarf.h>
#include <libdwarf.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdtrace.h"

#define	MAX_DWARF_CACHES	32

struct dwarf_cache {
	char		path[MAXPATHLEN];
	Dwarf_Debug	dbg;
	int		fd;
	int64_t		slide;
};

static struct dwarf_cache caches[MAX_DWARF_CACHES];
static int ncaches;

struct dwarf_cache *
dwarf_cache_open(const char *binary_path, int64_t slide)
{
	struct dwarf_cache *dc;
	Dwarf_Error err;
	int i, fd, rc;

	/*
	 * Key the cache on (path, slide): the same binary mapped at a
	 * different slide (e.g. traced twice at different load
	 * addresses) must get its own entry, or the first entry's
	 * stale slide stays pinned for all later lookups.
	 */
	for (i = 0; i < ncaches; i++) {
		if (strcmp(caches[i].path, binary_path) == 0 &&
		    caches[i].slide == slide)
			return (&caches[i]);
	}

	if (ncaches >= MAX_DWARF_CACHES)
		return (NULL);

	fd = open(binary_path, O_RDONLY);
	if (fd < 0)
		return (NULL);

	dc = &caches[ncaches];
	memset(dc, 0, sizeof(*dc));
	strlcpy(dc->path, binary_path, sizeof(dc->path));
	dc->fd = fd;
	dc->slide = slide;

	rc = dwarf_init(fd, DW_DLC_READ, NULL, NULL,
	    &dc->dbg, &err);
	if (rc != DW_DLV_OK) {
		/* NO_ENTRY (no debug info) is expected; stay quiet. */
		if (rc == DW_DLV_ERROR)
			warnx("dwarf_init: %s: %s", binary_path,
			    dwarf_errmsg(err));
		close(fd);
		return (NULL);
	}

	ncaches++;
	return (dc);
}

int
dwarf_addr_to_line(struct dwarf_cache *dc, uint64_t addr,
    char *file_out, size_t filesz, int *line_out)
{
	Dwarf_Line *lines;
	Dwarf_Signed nlines;
	Dwarf_Unsigned cu_header_length, next_cu_offset;
	Dwarf_Half version_stamp, address_size, length_size, extension_size;
	Dwarf_Off abbrev_offset;
	Dwarf_Sig8 sig;
	Dwarf_Die cu_die;
	Dwarf_Error err;
	Dwarf_Addr lineaddr;
	Dwarf_Unsigned lineno;
	char *src;
	uint64_t file_addr;
	int i, rc;
	Dwarf_Addr global_best_addr, endseq_below;
	Dwarf_Bool endseq;
	char global_best_file[MAXPATHLEN];
	int global_best_line;
	bool found, endseq_above;

	if (dc == NULL || dc->dbg == NULL)
		return (-1);

	file_addr = addr - dc->slide;
	found = false;
	global_best_addr = 0;
	global_best_file[0] = '\0';
	global_best_line = 0;
	endseq_below = 0;
	endseq_above = false;

	/* Rewind the CU iterator (NO_ENTRY means it wrapped around). */
	while ((rc = dwarf_next_cu_header_c(dc->dbg, 1,
	    &cu_header_length, &version_stamp, &abbrev_offset,
	    &address_size, &length_size, &extension_size,
	    &sig, &next_cu_offset, NULL, &err)) == DW_DLV_OK)
		;
	if (rc == DW_DLV_ERROR) {
		/* Iterator state is unreliable after a hard error. */
		return (-1);
	}

	/* Search all CUs for the best matching line. */
	while ((rc = dwarf_next_cu_header_c(dc->dbg, 1,
	    &cu_header_length, &version_stamp, &abbrev_offset,
	    &address_size, &length_size, &extension_size,
	    &sig, &next_cu_offset, NULL, &err)) == DW_DLV_OK) {

		if (dwarf_siblingof_b(dc->dbg, NULL, &cu_die, 1,
		    &err) != DW_DLV_OK)
			continue;

		if (dwarf_srclines(cu_die, &lines, &nlines,
		    &err) != DW_DLV_OK) {
			dwarf_dealloc(dc->dbg, cu_die, DW_DLA_DIE);
			continue;
		}

		for (i = 0; i < nlines; i++) {
			if (dwarf_lineaddr(lines[i], &lineaddr,
			    &err) != DW_DLV_OK)
				continue;
			if (dwarf_lineendsequence(lines[i], &endseq,
			    &err) != DW_DLV_OK)
				continue;
			if (endseq) {
				/*
				 * An end_sequence row carries the
				 * address one-past-the-end of its
				 * sequence with STALE file/line
				 * registers: it terminates a sequence
				 * and must never be a candidate
				 * itself.  Record it as a boundary:
				 * the highest boundary at or below
				 * file_addr tells us whether the best
				 * candidate's sequence ended before
				 * file_addr, and any boundary above
				 * file_addr proves at least one
				 * sequence extends past the address.
				 */
				if (lineaddr <= file_addr) {
					if (lineaddr > endseq_below)
						endseq_below = lineaddr;
				} else {
					endseq_above = true;
				}
				continue;
			}
			if (lineaddr <= file_addr &&
			    lineaddr > global_best_addr) {
				/*
				 * Only accept a row whose file AND line
				 * both resolve — a partial update would
				 * pair one row's file with another
				 * row's line number.
				 */
				if (dwarf_lineno(lines[i], &lineno,
				    &err) != DW_DLV_OK)
					continue;
				if (dwarf_linesrc(lines[i], &src,
				    &err) != DW_DLV_OK)
					continue;
				global_best_addr = lineaddr;
				strlcpy(global_best_file, src,
				    sizeof(global_best_file));
				dwarf_dealloc(dc->dbg, src,
				    DW_DLA_STRING);
				global_best_line = (int)lineno;
				found = true;
			}
		}

		dwarf_srclines_dealloc(dc->dbg, lines, nlines);
		dwarf_dealloc(dc->dbg, cu_die, DW_DLA_DIE);
	}
	/*
	 * rc is DW_DLV_NO_ENTRY when all CUs were scanned, DW_DLV_ERROR
	 * if the CU walk died early; rows collected from CUs that did
	 * parse are still valid either way, so fall through.
	 */

	if (!found)
		return (-1);

	/*
	 * A sequence's rows cover [row_addr, end_sequence_addr).  If
	 * an end_sequence boundary lies in (best_addr, file_addr],
	 * the best row's sequence ended at or before file_addr: the
	 * address falls in a gap (e.g. just past one CU's text) and
	 * must NOT inherit the stale last line of another sequence.
	 * (A boundary exactly at best_addr is the *previous*
	 * sequence's terminator and is harmless.)
	 */
	if (endseq_below > global_best_addr)
		return (-1);

	/*
	 * Well-formed DWARF terminates every sequence with an
	 * end_sequence row, so once the check above passes, the best
	 * row's own terminator must lie beyond file_addr and the
	 * match is exact — the old 64-byte proximity heuristic is
	 * redundant then.  Keep it only as a fallback when no
	 * terminator beyond file_addr was seen at all (malformed or
	 * truncated line program), where nothing else bounds how far
	 * past the last row we would otherwise attribute.
	 */
	if (!endseq_above && (file_addr - global_best_addr) >= 64)
		return (-1);

	strlcpy(file_out, global_best_file, filesz);
	*line_out = global_best_line;
	return (0);
}

void
dwarf_cache_close_all(void)
{
	Dwarf_Error err;
	int i;

	for (i = 0; i < ncaches; i++) {
		if (caches[i].dbg != NULL)
			dwarf_finish(caches[i].dbg, &err);
		if (caches[i].fd >= 0)
			close(caches[i].fd);
	}
	ncaches = 0;
}
