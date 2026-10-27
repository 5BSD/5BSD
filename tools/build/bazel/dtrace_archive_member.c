/* SPDX-License-Identifier: BSD-2-Clause */
/* Experimental section-associated static DTrace archive composition. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct object {
	Elf *elf;
	int fd;
	size_t count;
	const char *path;
};

static struct object
open_object(const char *path, int write)
{
	struct object o = { .path = path };
	GElf_Ehdr header;

	if ((o.fd = open(path, write ? O_RDWR : O_RDONLY)) < 0)
		err(1, "%s", path);
	o.elf = elf_begin(o.fd, write ? ELF_C_RDWR : ELF_C_READ, NULL);
	if (o.elf == NULL || gelf_getehdr(o.elf, &header) == NULL ||
	    header.e_type != ET_REL || elf_getshdrnum(o.elf, &o.count) != 0)
		errx(1, "%s: expected a relocatable ELF object", path);
	return (o);
}

static void
close_object(struct object *o, int write)
{
	if (write && elf_update(o->elf, ELF_C_WRITE) < 0)
		errx(1, "%s: cannot update ELF: %s", o->path, elf_errmsg(-1));
	elf_end(o->elf);
	if (close(o->fd) != 0)
		err(1, "%s", o->path);
}

static Elf_Scn *
section_header(struct object *o, size_t index, GElf_Shdr *header)
{
	Elf_Scn *section;

	if (index >= o->count ||
	    (section = elf_getscn(o->elf, index)) == NULL ||
	    gelf_getshdr(section, header) == NULL)
		errx(1, "%s: invalid section %zu", o->path, index);
	return (section);
}

/* Inspect REL/RELA through GElf so this transformation is not ELF64-specific. */
static size_t
relocation_parent(struct object *o, size_t index, int probes)
{
	GElf_Shdr relhdr, symhdr, target;
	GElf_Sym symbol;
	GElf_Rela rela;
	GElf_Rel rel;
	Elf_Scn *section, *symbols;
	Elf_Data *data = NULL, *symdata;
	size_t parent = 0;

	section = section_header(o, index, &relhdr);
	symbols = section_header(o, relhdr.sh_link, &symhdr);
	symdata = elf_getdata(symbols, NULL);
	if (symhdr.sh_type != SHT_SYMTAB || symdata == NULL ||
	    relhdr.sh_entsize == 0 || symhdr.sh_entsize == 0 ||
	    elf_getdata(symbols, symdata) != NULL)
		errx(1, "%s: invalid relocation symbol table", o->path);
	while ((data = elf_getdata(section, data)) != NULL) {
		if (data->d_size % relhdr.sh_entsize != 0 ||
		    data->d_size / relhdr.sh_entsize > INT_MAX)
			errx(1, "%s: invalid relocation count", o->path);
		for (size_t i = 0; i < data->d_size / relhdr.sh_entsize; i++) {
			GElf_Xword info;
			size_t candidate;
			const char *name, *tail;

			if (relhdr.sh_type == SHT_RELA) {
				if (gelf_getrela(data, (int)i, &rela) == NULL)
					errx(1, "%s: invalid RELA entry", o->path);
				info = rela.r_info;
			} else {
				if (gelf_getrel(data, (int)i, &rel) == NULL)
					errx(1, "%s: invalid REL entry", o->path);
				info = rel.r_info;
			}
			if (GELF_R_SYM(info) > INT_MAX ||
			    gelf_getsym(symdata, (int)GELF_R_SYM(info), &symbol) == NULL)
				errx(1, "%s: invalid relocation symbol", o->path);
			if (probes) {
				if (symbol.st_shndx != SHN_UNDEF)
					continue;
				name = elf_strptr(o->elf, symhdr.sh_link, symbol.st_name);
				if (name == NULL)
					errx(1, "%s: invalid symbol name", o->path);
				if (strncmp(name, "__dtrace_", 9) == 0)
					tail = name + 9;
				else if (strncmp(name, "__dtraceenabled_", 16) == 0)
					tail = name + 16;
				else
					continue;
				if (strstr(tail, "___") == NULL)
					continue;
				candidate = relhdr.sh_info;
			} else {
				if (symbol.st_shndx == SHN_UNDEF ||
				    symbol.st_shndx >= SHN_LORESERVE)
					errx(1, "%s: DOF reference lacks a regular code section", o->path);
				candidate = symbol.st_shndx;
			}
			section_header(o, candidate, &target);
			if (!(target.sh_flags & SHF_EXECINSTR) ||
			    (parent != 0 && parent != candidate))
				errx(1, "%s: metadata spans multiple or non-code sections", o->path);
			parent = candidate;
		}
	}
	return (parent);
}

static size_t *
probe_sections(const char *path, size_t *count)
{
	struct object o = open_object(path, 0);
	GElf_Shdr header;
	size_t *indices, found = 0;
	unsigned char *seen;

	indices = calloc(o.count, sizeof (*indices));
	seen = calloc(o.count, sizeof (*seen));
	if (indices == NULL || seen == NULL)
		err(1, "calloc");
	for (size_t i = 1; i < o.count; i++) {
		size_t parent;
		section_header(&o, i, &header);
		if (header.sh_type != SHT_REL && header.sh_type != SHT_RELA)
			continue;
		parent = relocation_parent(&o, i, 1);
		if (parent != 0 && !seen[parent]) {
			seen[parent] = 1;
			indices[found++] = parent;
		}
	}
	free(seen);
	close_object(&o, 0);
	*count = found;
	return (indices);
}

static void
associate(struct object *o, size_t index, size_t parent)
{
	GElf_Shdr header;
	Elf_Scn *section = section_header(o, index, &header);

	if (header.sh_flags & SHF_LINK_ORDER || header.sh_link != 0 ||
	    parent == 0 || parent > UINT_MAX)
		errx(1, "%s: unexpected existing section association", o->path);
	header.sh_flags |= SHF_LINK_ORDER;
	header.sh_link = parent;
	if (!gelf_update_shdr(section, &header))
		errx(1, "%s: cannot associate section", o->path);
}

/* Only generated provider objects are edited here, never user constructors. */
static void
associate_registration(const char *path)
{
	struct object o = open_object(path, 1);
	GElf_Shdr header;
	size_t dof = 0, init = 0, fini = 0;

	for (size_t i = 1; i < o.count; i++) {
		section_header(&o, i, &header);
		if (header.sh_type == SHT_SUNW_dof) {
			if (dof != 0)
				errx(1, "%s: expected one DOF section", path);
			dof = i;
		}
	}
	if (dof == 0)
		errx(1, "%s: missing DOF section", path);
	for (size_t i = 1; i < o.count; i++) {
		section_header(&o, i, &header);
		if (header.sh_type == SHT_INIT_ARRAY) {
			associate(&o, i, dof);
			init++;
		} else if (header.sh_type == SHT_FINI_ARRAY) {
			associate(&o, i, dof);
			fini++;
		}
	}
	if (init == 0 || fini == 0)
		errx(1, "%s: missing provider registration/finalization", path);
	close_object(&o, 1);
}

static void
associate_code(const char *path, size_t expected)
{
	struct object o = open_object(path, 1);
	GElf_Shdr header, target;
	size_t *parents, found = 0;

	parents = calloc(o.count, sizeof (*parents));
	if (parents == NULL)
		err(1, "calloc");
	/* One relocation scan, rather than rescanning the object for every DOF. */
	for (size_t i = 1; i < o.count; i++) {
		size_t parent, index;
		section_header(&o, i, &header);
		if (header.sh_type != SHT_REL && header.sh_type != SHT_RELA)
			continue;
		index = header.sh_info;
		section_header(&o, index, &target);
		if (target.sh_type != SHT_SUNW_dof)
			continue;
		parent = relocation_parent(&o, i, 0);
		if (parent != 0) {
			if (parents[index] != 0 && parents[index] != parent)
				errx(1, "%s: DOF spans code sections", path);
			parents[index] = parent;
		}
	}
	for (size_t i = 1; i < o.count; i++) {
		section_header(&o, i, &header);
		if (header.sh_type != SHT_SUNW_dof)
			continue;
		if (parents[i] == 0)
			errx(1, "%s: DOF has no code parent", path);
		associate(&o, i, parents[i]);
		found++;
	}
	if (found != expected)
		errx(1, "%s: DOF count changed during composition", path);
	free(parents);
	close_object(&o, 1);
}

/* Reserve scratch paths before invoking tools that replace their output. */
static int
reserve_file(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);

	if (fd == -1) {
		warn("%s", path);
		return (1);
	}
	if (close(fd) != 0)
		err(1, "%s", path);
	return (0);
}

static int
copy_file(const char *source, const char *target, mode_t mode)
{
	char buffer[65536];
	ssize_t count, written, offset;
	int input, output, error = 0;

	input = open(source, O_RDONLY);
	if (input == -1) {
		perror(source);
		return (1);
	}
	/* Never truncate an existing output or an alias of the original input. */
	output = open(target, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (output == -1) {
		perror(target);
		close(input);
		return (1);
	}
	for (;;) {
		count = read(input, buffer, sizeof(buffer));
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0) {
			if (count < 0) {
				perror(source);
				error = 1;
			}
			break;
		}
		for (offset = 0; offset < count; offset += written) {
			written = write(output, buffer + offset, count - offset);
			if (written < 0 && errno == EINTR) {
				written = 0;
				continue;
			}
			if (written <= 0) {
				perror(target);
				error = 1;
				goto done;
			}
		}
	}
 done:
	if (close(output) != 0) {
		perror(target);
		error = 1;
	}
	close(input);
	return (error);
}

static int
run(char **arguments)
{
	int status;
	pid_t child = fork();

	if (child == -1)
		err(1, "fork");
	if (child == 0) {
		execv(arguments[0], arguments);
		err(127, "%s", arguments[0]);
	}
	while (waitpid(child, &status, 0) == -1)
		if (errno != EINTR)
			err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		warnx("%s failed (wait status %d)", arguments[0], status);
		return (1);
	}
	return (0);
}

int
main(int argc, char **argv)
{
	char *copy, *linked, **providers, **command, **linkargs;
	size_t count, *indices, output_slot = 0;
	int result, linked_created = 0;

	if (argc < 6 || strcmp(argv[4], "--") != 0)
		errx(1, "usage: member input output linker -- dtrace arguments...");
	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "libelf initialization failed");
	indices = probe_sections(argv[1], &count);
	if (count == 0) {
		free(indices);
		return (copy_file(argv[1], argv[2], 0600));
	}
	if (asprintf(&copy, "%s.rewrite.o", argv[2]) < 0 ||
	    asprintf(&linked, "%s.linked.o", argv[2]) < 0)
		err(1, "asprintf");
	if (strcmp(argv[argc - 1], copy) != 0)
		errx(1, "DTrace input must name the private rewritten copy");
	command = calloc((size_t)argc + 1, sizeof (*command));
	providers = calloc(count, sizeof (*providers));
	linkargs = calloc(count + 7, sizeof (*linkargs));
	if (command == NULL || providers == NULL || linkargs == NULL)
		err(1, "calloc");
	command[0] = argv[5];
	command[1] = "-x";
	for (int i = 6; i < argc; i++) {
		command[i - 3] = argv[i];
		if (strcmp(argv[i], "-o") == 0) {
			if (output_slot != 0 || i + 1 >= argc)
				errx(1, "expected one DTrace output option");
			output_slot = i - 2;
		}
	}
	if (output_slot == 0)
		errx(1, "missing DTrace output option");
	result = copy_file(argv[1], copy, 0600);
	if (result != 0)
		return (result); /* Do not unlink a pre-existing private-copy path. */
	for (size_t i = 0; result == 0 && i < count; i++) {
		char *option;
		if (asprintf(&providers[i], "%s.dof.%zu.o", argv[2], i) < 0 ||
		    asprintf(&option, "linksection=%zu", indices[i]) < 0)
			err(1, "asprintf");
		if (reserve_file(providers[i]) != 0) {
			free(providers[i]);
			providers[i] = NULL;
			free(option);
			result = 1;
			break;
		}
		command[2] = option;
		command[output_slot] = providers[i];
		result = run(command);
		free(option);
		if (result == 0)
			associate_registration(providers[i]);
	}
	if (result == 0) {
		/* Keep each provider's code/data/DOF separate through ld -r. */
		linkargs[0] = argv[3];
		linkargs[1] = "-r";
		linkargs[2] = "--unique";
		linkargs[3] = "-o";
		linkargs[4] = linked;
		linkargs[5] = copy;
		for (size_t i = 0; i < count; i++)
			linkargs[6 + i] = providers[i];
		result = reserve_file(linked);
		if (result == 0) {
			linked_created = 1;
			result = run(linkargs);
		}
	}
	if (result == 0) {
		associate_code(linked, count);
		/* Publish exclusively: never overwrite an existing output/input. */
		if (link(linked, argv[2]) != 0) {
			warn("%s", argv[2]);
			result = 1;
		}
	}
	(void)unlink(copy);
	if (linked_created)
		(void)unlink(linked);
	for (size_t i = 0; i < count; i++) {
		if (providers[i] != NULL) {
			(void)unlink(providers[i]);
			free(providers[i]);
		}
	}
	free(copy);
	free(linked);
	free(providers);
	free(command);
	free(linkargs);
	free(indices);
	return (result);
}
