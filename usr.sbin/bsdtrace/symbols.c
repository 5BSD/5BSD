/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Symbol table — maps runtime addresses to function names.
 * Built from ELF .dynsym / .symtab sections using libelf/gelf.
 */

#include <sys/types.h>

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdtrace.h"

#define	SYM_INIT_CAP	256

/*
 * elf_strptr() bounds-checks only the offset, not the string — a
 * crafted ELF whose string table ends without a terminating NUL
 * would let callers read past the section data.  Validate that the
 * string terminates inside its section before use.
 */
const char *
elf_strptr_safe(Elf *elf, size_t link, size_t off)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	const char *s;

	s = elf_strptr(elf, link, off);
	if (s == NULL)
		return (NULL);
	scn = elf_getscn(elf, link);
	if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL)
		return (NULL);
	if (off >= shdr.sh_size ||
	    memchr(s, '\0', shdr.sh_size - off) == NULL)
		return (NULL);
	return (s);
}


void
sym_table_init(struct sym_table *st)
{

	memset(st, 0, sizeof(*st));
}

void
sym_table_add(struct sym_table *st, uint64_t addr, uint64_t size,
    const char *name, const char *binary, int64_t slide)
{
	struct sym_entry *e;
	struct sym_entry *newentries;

	if (name == NULL || name[0] == '\0')
		return;

	if (st->count >= st->capacity) {
		int newcap = st->capacity == 0 ? SYM_INIT_CAP :
		    st->capacity * 2;
		newentries = realloc(st->entries,
		    (size_t)newcap * sizeof(*st->entries));
		if (newentries == NULL)
			return;
		st->entries = newentries;
		st->capacity = newcap;
	}

	e = &st->entries[st->count++];
	e->addr = addr;
	e->size = size;
	e->slide = slide;
	e->name = strdup(name);
	e->binary = strdup(binary);
	if (e->name == NULL || e->binary == NULL) {
		free(e->name);
		free(e->binary);
		st->count--;
	}
}

void
sym_table_add_elf(struct sym_table *st, const char *path, int64_t slide)
{
	Elf *elf;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	Elf_Data *data;
	GElf_Sym sym;
	GElf_Word symtab_type;
	const char *name, *bn;
	char *pathcopy;
	size_t nsyms;
	int fd;
	size_t i;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		close(fd);
		return;
	}

	pathcopy = strdup(path);
	if (pathcopy == NULL) {
		elf_end(elf);
		close(fd);
		return;
	}
	bn = basename(pathcopy);
	symtab_type = elf_preferred_symtab_type(elf);
	(void)symtab_type;

	/*
	 * Scan BOTH .symtab and .dynsym: FreeBSD's libc exports some
	 * symbols (including its ifuncs) only through .dynsym, so a
	 * .symtab-only scan misses them.  Duplicates that appear in
	 * both tables land as same-address ties, which the lookup's
	 * tie-walk already handles.
	 */
	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL)
			continue;
		if (shdr.sh_type != SHT_SYMTAB &&
		    shdr.sh_type != SHT_DYNSYM)
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
				/*
				 * Accept STT_GNU_IFUNC alongside STT_FUNC:
				 * libc exports (memcmp, strncmp, ...) are
				 * ifuncs, and dropping them would leave
				 * their addresses unnamed in decode output.
				 * Symbolization is best-effort — the
				 * resolver-selected implementation body may
				 * still be unnamed if it lives elsewhere.
				 */
				if (GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
				    GELF_ST_TYPE(sym.st_info) != STT_GNU_IFUNC)
					continue;
				if (sym.st_value == 0)
					continue;

				name = elf_strptr_safe(elf, shdr.sh_link,
				    sym.st_name);
				if (name == NULL)
					continue;
				sym_table_add(st, sym.st_value + slide,
				    sym.st_size, name, bn, slide);
			}
		}
	}

	free(pathcopy);
	elf_end(elf);
	close(fd);
}

static int
sym_entry_cmp(const void *a, const void *b)
{
	const struct sym_entry *sa = a, *sb = b;

	if (sa->addr < sb->addr)
		return (-1);
	if (sa->addr > sb->addr)
		return (1);
	/*
	 * Break address ties by descending st_size so sized symbols
	 * sort before their size-0 aliases and cannot be masked by
	 * them during lookup.
	 */
	if (sa->size > sb->size)
		return (-1);
	if (sa->size < sb->size)
		return (1);
	return (0);
}

void
sym_table_sort(struct sym_table *st)
{

	if (st->count > 1)
		qsort(st->entries, st->count, sizeof(*st->entries),
		    sym_entry_cmp);
}

const struct sym_entry *
sym_table_lookup(const struct sym_table *st, uint64_t ip)
{
	const struct sym_entry *entries, *e;
	uint64_t addr, bound;
	int lo, hi, mid, best, first, next, i;

	if (st->count == 0)
		return (NULL);

	entries = st->entries;
	lo = 0;
	hi = st->count - 1;
	best = -1;

	while (lo <= hi) {
		mid = lo + (hi - lo) / 2;
		if (entries[mid].addr <= ip) {
			best = mid;
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}

	if (best < 0)
		return (NULL);

	/*
	 * The binary search lands on the LAST entry of a same-address
	 * tie run, which with the descending-size tie-break is the
	 * smallest (typically size-0) alias.  Walk back to the start
	 * of the run so sized symbols are tried first and a size-0
	 * alias cannot mask a sized symbol at the same address.
	 */
	addr = entries[best].addr;
	first = best;
	while (first > 0 && entries[first - 1].addr == addr)
		first--;

	/* First entry past the tie run (its addr is > ip if it exists). */
	next = best + 1;

	for (i = first; i <= best; i++) {
		e = &entries[i];
		if (e->size > 0) {
			if (ip < e->addr + e->size)
				return (e);
			continue;
		}
		/*
		 * Size-0 symbol: bound the match window at the next
		 * symbol's address when the sorted-table successor
		 * belongs to the same binary (it is the natural end of
		 * this symbol); keep the fixed 4096-byte fallback only
		 * when there is no such successor.
		 */
		if (next < st->count &&
		    strcmp(entries[next].binary, e->binary) == 0)
			bound = entries[next].addr;
		else
			bound = e->addr + 4096;
		if (ip < bound)
			return (e);
	}

	return (NULL);
}

void
sym_table_free(struct sym_table *st)
{
	int i;

	for (i = 0; i < st->count; i++) {
		free(st->entries[i].name);
		free(st->entries[i].binary);
	}
	free(st->entries);
	memset(st, 0, sizeof(*st));
}
