/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ELF parsing — load executable segments into a pt_image, resolve
 * the dynamic linker via PT_INTERP, and build binary address ranges
 * for IP-to-binary fallback.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <intel-pt.h>

#include "bsdtrace.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

bool
is_user_addr(uint64_t addr)
{

	if (addr == 0)
		return (false);
	if (addr >= 0x0000800000000000ULL)
		return (false);
	return (true);
}

/*
 * Find the p_vaddr of the first PT_LOAD segment in an open ELF.
 * Returns 0 on success, -1 if no PT_LOAD found.
 */
int
elf_base_vaddr(Elf *elf, uint64_t *base_out)
{
	GElf_Phdr phdr;
	size_t phdrnum;
	size_t i;

	if (elf_getphdrnum(elf, &phdrnum) != 0)
		return (-1);

	for (i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(elf, (int)i, &phdr) == NULL)
			continue;
		if (phdr.p_type == PT_LOAD) {
			*base_out = phdr.p_vaddr;
			return (0);
		}
	}
	return (-1);
}

/*
 * Find the page-aligned virtual address of the lowest executable PT_LOAD
 * segment in an open ELF.  MMAP records report the mapped address of an
 * executable segment, not the ELF image base, so this is the segment basis
 * we need to recover the runtime slide.
 */
int
elf_exec_map_vaddr(Elf *elf, uint64_t *exec_out)
{
	GElf_Phdr phdr;
	size_t phdrnum;
	uint64_t best;
	bool found;
	size_t i;

	if (elf_getphdrnum(elf, &phdrnum) != 0)
		return (-1);

	best = 0;
	found = false;
	for (i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(elf, (int)i, &phdr) == NULL)
			continue;
		if (phdr.p_type != PT_LOAD)
			continue;
		if ((phdr.p_flags & PF_X) == 0)
			continue;
		if (phdr.p_filesz == 0)
			continue;

		if (!found || trunc_page(phdr.p_vaddr) < best) {
			best = trunc_page(phdr.p_vaddr);
			found = true;
		}
	}

	if (!found)
		return (-1);

	*exec_out = best;
	return (0);
}

int
elf_preferred_symtab_type(Elf *elf)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	GElf_Word have_dynsym;

	scn = NULL;
	have_dynsym = SHT_NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL)
			continue;
		if (shdr.sh_type == SHT_SYMTAB)
			return (SHT_SYMTAB);
		if (shdr.sh_type == SHT_DYNSYM)
			have_dynsym = SHT_DYNSYM;
	}

	return ((int)have_dynsym);
}

/*
 * When the MMAP record carries the mapping's file offset, find the
 * PT_LOAD whose file range covers that offset and derive the vaddr
 * corresponding to it.  The bias is an object-wide constant, so ANY
 * covering segment gives the right answer — including a whole-file
 * PROT_EXEC mapping from offset 0, whose covering segment is the
 * non-executable R segment on split R/RX layouts.  An exact
 * segment-start match (the rtld case) is a degenerate instance:
 * the correction term is then zero.  Returns -1 if no PT_LOAD
 * covers the offset.
 */
static int
elf_pgoff_map_vaddr(Elf *elf, uint64_t pgoff, uint64_t *vaddr_out)
{
	GElf_Phdr phdr;
	size_t phdrnum;
	size_t i;

	if (elf_getphdrnum(elf, &phdrnum) != 0)
		return (-1);
	for (i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(elf, (int)i, &phdr) == NULL)
			continue;
		if (phdr.p_type != PT_LOAD)
			continue;
		if (phdr.p_filesz == 0)
			continue;
		if (trunc_page(phdr.p_offset) <= pgoff &&
		    pgoff < phdr.p_offset + phdr.p_filesz) {
			*vaddr_out = trunc_page(phdr.p_vaddr) +
			    (trunc_page(pgoff) -
			    trunc_page(phdr.p_offset));
			return (0);
		}
	}
	return (-1);
}

int
elf_effective_load_addr(Elf *elf, int type, uint64_t record_addr,
    uint64_t pgoff, uint64_t maplen, uint64_t *load_out)
{
	uint64_t base_vaddr, exec_map_vaddr;

	if (elf_base_vaddr(elf, &base_vaddr) != 0)
		return (-1);

	switch (type) {
	case HWT_RECORD_EXECUTABLE:
		if (record_addr == 0)
			*load_out = base_vaddr;
		else
			*load_out = base_vaddr + record_addr;
		return (0);
	case HWT_RECORD_MMAP:
		/*
		 * With a known file offset (maplen > 0 marks the
		 * record as carrying real mapping geometry), match
		 * the exact executable PT_LOAD instead of assuming
		 * the mapping is the lowest one.
		 */
		if (maplen > 0 &&
		    elf_pgoff_map_vaddr(elf, pgoff,
		    &exec_map_vaddr) == 0) {
			if (record_addr < exec_map_vaddr)
				return (-1);
			*load_out = base_vaddr +
			    (record_addr - exec_map_vaddr);
			return (0);
		}
		if (elf_exec_map_vaddr(elf, &exec_map_vaddr) != 0)
			return (-1);
		if (record_addr < exec_map_vaddr)
			return (-1);
		*load_out = base_vaddr + (record_addr - exec_map_vaddr);
		return (0);
	default:
		*load_out = record_addr;
		return (0);
	}
}

bool
section_should_use(const struct pt_image_info *sections, int nsections, int idx)
{
	const struct pt_image_info *sec;
	int i;

	sec = &sections[idx];
	if (sec->path[0] == '\0')
		return (false);

	switch (sec->type) {
	case HWT_RECORD_EXECUTABLE:
		for (i = 0; i < idx; i++) {
			if (sections[i].type != HWT_RECORD_EXECUTABLE)
				continue;
			if (strcmp(sections[i].path, sec->path) == 0)
				return (false);
		}
		return (true);
	case HWT_RECORD_MMAP:
		/*
		 * EXEC records carry authoritative load information for the
		 * main image.  Otherwise keep only the lowest executable MMAP
		 * per path, which corresponds to the lowest executable PT_LOAD.
		 */
		for (i = 0; i < nsections; i++) {
			if (sections[i].type != HWT_RECORD_EXECUTABLE)
				continue;
			if (strcmp(sections[i].path, sec->path) == 0)
				return (false);
		}
		for (i = 0; i < nsections; i++) {
			if (i == idx || sections[i].type != HWT_RECORD_MMAP)
				continue;
			if (strcmp(sections[i].path, sec->path) != 0)
				continue;
			if (sections[i].load_addr < sec->load_addr)
				return (false);
			if (sections[i].load_addr == sec->load_addr && i < idx)
				return (false);
		}
		return (true);
	default:
		return (true);
	}
}

/* ------------------------------------------------------------------ */
/* Add ELF executable segments to pt_image                             */
/* ------------------------------------------------------------------ */

int
add_elf_to_image(struct pt_image *image, const char *path,
    uint64_t load_addr)
{
	Elf *elf;
	GElf_Phdr phdr;
	size_t phdrnum;
	uint64_t base_vaddr, runtime_vaddr;
	int64_t slide;
	int fd, added, err;
	size_t i;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return (0);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (0);

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		close(fd);
		return (0);
	}

	if (elf_base_vaddr(elf, &base_vaddr) != 0)
		goto done;

	slide = (int64_t)load_addr - (int64_t)base_vaddr;

	added = 0;
	if (elf_getphdrnum(elf, &phdrnum) != 0)
		goto done;

	for (i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(elf, (int)i, &phdr) == NULL)
			continue;
		if (phdr.p_type != PT_LOAD)
			continue;
		if (!(phdr.p_flags & PF_X))
			continue;
		if (phdr.p_filesz == 0)
			continue;

		runtime_vaddr = phdr.p_vaddr + slide;
		err = pt_image_add_file(image, path,
		    phdr.p_offset, phdr.p_filesz,
		    NULL, runtime_vaddr);
		if (err >= 0)
			added++;
	}

	elf_end(elf);
	close(fd);
	return (added);

done:
	elf_end(elf);
	close(fd);
	return (0);
}

/* ------------------------------------------------------------------ */
/* PT_INTERP lookup                                                    */
/* ------------------------------------------------------------------ */

int
elf_get_interp(const char *path, char *interp, size_t interpsz)
{
	Elf *elf;
	GElf_Phdr phdr;
	size_t phdrnum;
	int fd;
	size_t i;

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

	if (elf_getphdrnum(elf, &phdrnum) != 0)
		goto fail;

	for (i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(elf, (int)i, &phdr) == NULL)
			continue;
		if (phdr.p_type != PT_INTERP)
			continue;

		if (phdr.p_filesz == 0 || phdr.p_filesz >= interpsz)
			goto fail;

		if (lseek(fd, phdr.p_offset, SEEK_SET) == -1)
			goto fail;

		memset(interp, 0, interpsz);
		if (read(fd, interp, phdr.p_filesz) !=
		    (ssize_t)phdr.p_filesz)
			goto fail;

		elf_end(elf);
		close(fd);
		return (0);
	}

fail:
	elf_end(elf);
	close(fd);
	return (-1);
}

/* ------------------------------------------------------------------ */
/* Binary range tracking                                               */
/* ------------------------------------------------------------------ */

int
build_bin_ranges(const struct pt_image_info *sections, int nsections,
    struct bin_range *ranges, int maxranges)
{
	Elf *elf;
	GElf_Phdr phdr;
	size_t phdrnum;
	uint64_t base_vaddr;
	int64_t slide;
	int fd, nranges;
	size_t j;
	char interp[MAXPATHLEN];
	char *pathcopy, *bn;
	int i;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return (0);

	nranges = 0;

	for (i = 0; i < nsections && nranges < maxranges; i++) {
		uint64_t load_addr;

		if (!section_should_use(sections, nsections, i))
			continue;

		fd = open(sections[i].path, O_RDONLY);
		if (fd < 0)
			continue;
		elf = elf_begin(fd, ELF_C_READ, NULL);
		if (elf == NULL) {
			close(fd);
			continue;
		}

		if (elf_base_vaddr(elf, &base_vaddr) != 0) {
			elf_end(elf);
			close(fd);
			continue;
		}

		load_addr = sections[i].load_addr;
		if (elf_effective_load_addr(elf, sections[i].type,
		    sections[i].load_addr, sections[i].pgoff,
		    sections[i].maplen, &load_addr) != 0) {
			elf_end(elf);
			close(fd);
			continue;
		}

		slide = (int64_t)load_addr - (int64_t)base_vaddr;

		if (elf_getphdrnum(elf, &phdrnum) == 0) {
			for (j = 0; j < phdrnum && nranges < maxranges;
			    j++) {
				if (gelf_getphdr(elf, (int)j, &phdr) == NULL)
					continue;
				if (phdr.p_type != PT_LOAD ||
				    !(phdr.p_flags & PF_X) ||
				    phdr.p_filesz == 0)
					continue;

				pathcopy = strdup(sections[i].path);
				if (pathcopy == NULL)
					continue;
				bn = basename(pathcopy);
				strlcpy(ranges[nranges].name, bn,
				    sizeof(ranges[nranges].name));
				free(pathcopy);
				ranges[nranges].lo = phdr.p_vaddr + slide;
				ranges[nranges].hi = phdr.p_vaddr + slide +
				    phdr.p_filesz;
				ranges[nranges].base = load_addr;
				nranges++;
			}
		}

		/*
		 * Handle interpreter for EXEC records.
		 * Skip if the interpreter has its own MMAP section.
		 */
		if (sections[i].type == HWT_RECORD_EXECUTABLE &&
		    is_user_addr(sections[i].base_addr) &&
		    sections[i].base_addr != load_addr) {
			if (elf_get_interp(sections[i].path,
			    interp, sizeof(interp)) == 0) {
				int k;
				bool have_mmap = false;

				for (k = 0; k < nsections; k++) {
					if (sections[k].type ==
					    HWT_RECORD_MMAP &&
					    strcmp(sections[k].path,
					    interp) == 0) {
						have_mmap = true;
						break;
					}
				}

				if (!have_mmap) {
					Elf *elf2;
					uint64_t interp_base;
					int fd2 = open(interp, O_RDONLY);
					if (fd2 >= 0) {
						elf2 = elf_begin(fd2,
						    ELF_C_READ, NULL);
						if (elf2 != NULL &&
						    elf_base_vaddr(elf2,
						    &interp_base) == 0) {
							int64_t islide =
							    (int64_t)sections[i].base_addr -
							    (int64_t)interp_base;
							size_t iphdrnum;
							if (elf_getphdrnum(
							    elf2,
							    &iphdrnum) == 0) {
								for (j = 0;
								    j < iphdrnum &&
								    nranges <
								    maxranges;
								    j++) {
									if (gelf_getphdr(
									    elf2,
									    (int)j,
									    &phdr)
									    == NULL)
										continue;
									if (phdr.p_type != PT_LOAD ||
									    !(phdr.p_flags & PF_X) ||
									    phdr.p_filesz == 0)
										continue;
									const char *ibn;

									/* Label with the real interp. */
									ibn = strrchr(interp, '/');
									ibn = ibn != NULL ?
									    ibn + 1 : interp;
									strlcpy(
									    ranges[nranges].name,
									    ibn,
									    sizeof(ranges[nranges].name));
									ranges[nranges].lo =
									    phdr.p_vaddr +
									    islide;
									ranges[nranges].hi =
									    phdr.p_vaddr +
									    islide +
									    phdr.p_filesz;
									ranges[nranges].base =
									    sections[i].base_addr;
									nranges++;
								}
							}
						}
						if (elf2 != NULL)
							elf_end(elf2);
						close(fd2);
					}
				}
			}
		}

		elf_end(elf);
		close(fd);
	}

	return (nranges);
}

const char *
find_binary_for_ip(const struct bin_range *ranges, int nranges,
    uint64_t ip, uint64_t *offset)
{
	int i;

	for (i = 0; i < nranges; i++) {
		if (ip >= ranges[i].lo && ip < ranges[i].hi) {
			*offset = ip - ranges[i].lo;
			return (ranges[i].name);
		}
	}
	return (NULL);
}
