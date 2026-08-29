/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "servicectl.h"

static bool
contains(const unsigned char *data, size_t size, const char *needle)
{
	size_t length, i;

	length = strlen(needle);
	if (length == 0 || length > size)
		return (false);
	for (i = 0; i <= size - length; i++)
		if (memcmp(data + i, needle, length) == 0)
			return (true);
	return (false);
}

static void
inspect_dynamic(Elf *elf, Elf_Scn *scn, const GElf_Shdr *shdr,
    bool *network, bool *crypto)
{
	GElf_Dyn dyn;
	Elf_Data *data;
	const char *needed;
	size_t count, i;

	data = NULL;
	while ((data = elf_getdata(scn, data)) != NULL) {
		if (shdr->sh_entsize == 0 ||
		    data->d_size % shdr->sh_entsize != 0)
			errx(1, "malformed ELF dynamic section");
		count = data->d_size / shdr->sh_entsize;
		for (i = 0; i < count; i++) {
			if (gelf_getdyn(data, (int)i, &dyn) == NULL)
				errx(1, "malformed ELF dynamic entry: %s",
				    elf_errmsg(-1));
			if (dyn.d_tag != DT_NEEDED)
				continue;
			needed = elf_strptr(elf, shdr->sh_link,
			    dyn.d_un.d_val);
			if (needed == NULL)
				errx(1, "malformed ELF dependency: %s",
				    elf_errmsg(-1));
			if (strcmp(needed, "libnetworkcmp.so") == 0 ||
			    strncmp(needed, "libnetworkcmp.so.",
			    sizeof("libnetworkcmp.so.") - 1) == 0)
				*network = true;
			if (strcmp(needed, "libcryptocmp.so") == 0 ||
			    strncmp(needed, "libcryptocmp.so.",
			    sizeof("libcryptocmp.so.") - 1) == 0)
				*crypto = true;
		}
	}
}

static void
inspect_descriptor_note(Elf_Scn *scn, bool *network, bool *crypto)
{
	Elf_Data *data;

	data = NULL;
	while ((data = elf_getdata(scn, data)) != NULL) {
		if (data->d_buf == NULL)
			continue;
		if (contains(data->d_buf, data->d_size,
		    "interface=system.Network"))
			*network = true;
		if (contains(data->d_buf, data->d_size,
		    "interface=system.Crypto"))
			*crypto = true;
	}
}

int
cmd_deps(const char *program)
{
	GElf_Shdr shdr;
	Elf *elf;
	Elf_Scn *scn;
	struct stat st;
	const char *name;
	size_t shstrndx;
	bool crypto, network;
	int fd;

	fd = open(program, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		err(1, "%s", program);
	if (fstat(fd, &st) == -1)
		err(1, "%s", program);
	if (!S_ISREG(st.st_mode) || st.st_size <= 0)
		errx(1, "%s: not a non-empty regular file", program);
	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "libelf initialization failed");
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL)
		errx(1, "%s: %s", program, elf_errmsg(-1));
	if (elf_kind(elf) != ELF_K_ELF)
		errx(1, "%s: not an ELF object", program);
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		errx(1, "%s: malformed ELF section table: %s", program,
		    elf_errmsg(-1));

	network = false;
	crypto = false;
	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL)
			errx(1, "%s: malformed ELF section: %s", program,
			    elf_errmsg(-1));
		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (name == NULL)
			errx(1, "%s: malformed ELF section name: %s", program,
			    elf_errmsg(-1));
		if (strcmp(name, ".note.5bsd.descriptors") == 0)
			inspect_descriptor_note(scn, &network, &crypto);
		if (shdr.sh_type == SHT_DYNAMIC)
			inspect_dynamic(elf, scn, &shdr, &network, &crypto);
	}

	printf("# %s discovers its capability services at runtime via\n", program);
	printf("# service_connect(3); no manifest descriptor declaration is required.\n");
	/*
	 * The eager descriptor model was retired: capability libraries
	 * (libnetworkcmp, libcryptocmp, ...) connect to their system.* service
	 * lazily on first use.  The detected linkage is now informational only.
	 */
	(void)network;
	(void)crypto;
	elf_end(elf);
	close(fd);
	return (0);
}
