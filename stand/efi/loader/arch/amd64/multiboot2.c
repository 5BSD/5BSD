/*-
 * Copyright (c) 2021 Roger Pau Monné <royger@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This multiboot2 implementation only implements a subset of the full
 * multiboot2 specification in order to be able to boot Xen and a
 * FreeBSD Dom0. Trying to use it to boot other multiboot2 compliant
 * kernels will most surely fail.
 *
 * The full multiboot specification can be found here:
 * https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html
 */

#include <sys/param.h>
#include <sys/exec.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stdint.h>
#define _MACHINE_ELF_WANT_32BIT
#include <machine/elf.h>
#include <machine/metadata.h>
#include <string.h>
#include <stand.h>

#include <efi.h>
#include <efilib.h>

#include "bootstrap.h"
#include "multiboot2.h"
#include "loader_efi.h"
#include "modinfo.h"

extern int elf32_loadfile_raw(char *filename, uint64_t dest,
    struct preloaded_file **result, int multiboot);
extern int elf64_load_modmetadata(struct preloaded_file *fp, uint64_t dest);
extern int elf64_obj_loadfile(char *filename, uint64_t dest,
    struct preloaded_file **result);

extern void multiboot2_exec(void *entry, uint64_t multiboot_info,
    uint64_t stack);

/*
 * Multiboot2 header information to pass between the loading and the exec
 * functions.
 */
struct mb2hdr {
	uint32_t efi64_entry;
};

static int
loadfile(char *filename, uint64_t dest, struct preloaded_file **result)
{
	unsigned int		 i;
	int			 error, fd;
	void			*header_search = NULL;
	void			*multiboot;
	size_t			 tags_size, tag_size;
	ssize_t			 search_size;
	struct multiboot_header	*header;
	struct mb2hdr		 hdr;
	bool			 keep_bs = false, end_seen = false;

	/*
	 * Read MULTIBOOT_SEARCH size in order to search for the
	 * multiboot magic header.
	 */
	if (filename == NULL)
		return (EFTYPE);
	if ((fd = open(filename, O_RDONLY)) == -1)
		return (errno);
#ifdef LOADER_VERITY_SUPPORT
	if (verity_check_source(fd) != 0) {
		close(fd);
		return (EAUTH);
	}
#endif
	header_search = malloc(MULTIBOOT_SEARCH);
	if (header_search == NULL) {
		error = ENOMEM;
		goto out;
	}
	search_size = read(fd, header_search, MULTIBOOT_SEARCH);
	if (search_size < 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	if ((size_t)search_size < sizeof(*header)) {
		error = EFTYPE;
		goto out;
	}

	for (i = 0; i + sizeof(*header) <= (size_t)search_size;
	    i += MULTIBOOT_HEADER_ALIGN) {
		header = header_search + i;
		if (header->magic == MULTIBOOT2_HEADER_MAGIC)
			break;
	}

	if (i + sizeof(*header) > (size_t)search_size) {
		error = EFTYPE;
		goto out;
	}

	/* Valid multiboot header has been found, validate checksum */
	if (header->magic + header->architecture + header->header_length +
	    header->checksum != 0) {
		printf("Multiboot checksum failed, magic: %#x "
		    "architecture: %#x header_length %#x checksum: %#x\n",
		    header->magic, header->architecture, header->header_length,
		    header->checksum);
		error = EFTYPE;
		goto out;
	}

	if (header->architecture != MULTIBOOT2_ARCHITECTURE_I386) {
		printf("Unsupported architecture: %#x\n",
		    header->architecture);
		error = EFTYPE;
		goto out;
	}

	/* The entire header must fit in the search window and bytes read. */
	if (header->header_length < sizeof(*header) + sizeof(struct multiboot_header_tag) ||
	    header->header_length > (size_t)search_size - i) {
		error = EINVAL;
		goto out;
	}
	multiboot = (char *)header + sizeof(*header);
	tags_size = header->header_length - sizeof(*header);

	bzero(&hdr, sizeof(hdr));
	for (i = 0; i < tags_size; ) {
		struct multiboot_header_tag *tag;
		struct multiboot_header_tag_entry_address *entry;
		struct multiboot_header_tag_information_request *req;
		unsigned int j;

		if (tags_size - i < sizeof(*tag)) {
			error = EINVAL;
			goto out;
		}
		tag = multiboot + i;
		if (tag->size < sizeof(*tag) || tag->size > tags_size - i) {
			error = EINVAL;
			goto out;
		}
		tag_size = roundup2(tag->size, MULTIBOOT_TAG_ALIGN);
		if (tag_size > tags_size - i) {
			error = EINVAL;
			goto out;
		}

		switch(tag->type) {
		case MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST:
			if ((tag->size - sizeof(*tag)) % sizeof(uint32_t) != 0) {
				error = EINVAL;
				goto out;
			}
			req = (void *)tag;
			for (j = 0;
			    j < (tag->size - sizeof(*tag)) / sizeof(uint32_t);
			    j++) {
				switch (req->requests[j]) {
				case MULTIBOOT_TAG_TYPE_MMAP:
				case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
					/* Only applicable to BIOS. */
					break;

				case MULTIBOOT_TAG_TYPE_EFI_BS:
				case MULTIBOOT_TAG_TYPE_EFI64:
				case MULTIBOOT_TAG_TYPE_EFI64_IH:
					/* Tags unconditionally added. */
					break;

				default:
					if (req->flags &
					    MULTIBOOT_HEADER_TAG_OPTIONAL)
						break;

					printf(
				"Unknown non-optional information request %u\n",
					    req->requests[j]);
					error = EINVAL;
					goto out;
				}
			}
			break;

		case MULTIBOOT_HEADER_TAG_EFI_BS:
			if (tag->size != sizeof(*tag)) {
				error = EINVAL;
				goto out;
			}
			/* Never shut down BS. */
			keep_bs = true;
			break;

		case MULTIBOOT_HEADER_TAG_MODULE_ALIGN:
			/* We will align modules by default already. */
		case MULTIBOOT_HEADER_TAG_END:
			if (tag->size != sizeof(*tag)) {
				error = EINVAL;
				goto out;
			}
			end_seen = tag->type == MULTIBOOT_HEADER_TAG_END;
			break;

		case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI64:
			if (tag->size != sizeof(*entry)) {
				error = EINVAL;
				goto out;
			}
			entry = (void *)tag;
			hdr.efi64_entry = entry->entry_addr;
			break;

		default:
			if (tag->flags & MULTIBOOT_HEADER_TAG_OPTIONAL)
				break;
			printf("Unknown header tag %#x not optional\n",
			    tag->type);
			error = EINVAL;
			goto out;
		}

		i += tag_size;
		if (tag->type == MULTIBOOT_HEADER_TAG_END)
			break;
	}

	if (!end_seen) {
		error = EINVAL;
		goto out;
	}
	if (hdr.efi64_entry == 0) {
		printf("No EFI64 entry address provided\n");
		error = EINVAL;
		goto out;
	}
	if (!keep_bs) {
		printf("Unable to boot MB2 with BS exited\n");
		error = EINVAL;
		goto out;
	}

	error = elf32_loadfile_raw(filename, dest, result, 1);
	if (error != 0) {
		printf(
	"elf32_loadfile_raw failed: %d unable to load multiboot kernel\n",
		    error);
		goto out;
	}

	file_addmetadata(*result, MODINFOMD_NOCOPY | MODINFOMD_MB2HDR,
	    sizeof(hdr), &hdr);

	/*
	 * f_addr is already aligned to PAGE_SIZE, make sure
	 * f_size it's also aligned so when the modules are loaded
	 * they are aligned to PAGE_SIZE.
	 */
	(*result)->f_size = roundup((*result)->f_size, PAGE_SIZE);

out:
	if (header_search != NULL)
		free(header_search);
	close(fd);
	return (error);
}

/* All tag writes reserve aligned space before touching the output page. */
struct mb2_builder {
	char *next;
	size_t remaining;
};

static void *
mb2_reserve(struct mb2_builder *builder, size_t size)
{
	void *result;
	size_t aligned;

	if (size > UINT32_MAX || size > SIZE_MAX - (MULTIBOOT_TAG_ALIGN - 1))
		return (NULL);
	aligned = roundup2(size, MULTIBOOT_TAG_ALIGN);
	if (aligned > builder->remaining)
		return (NULL);
	result = builder->next;
	memset(result, 0, aligned);
	builder->next += aligned;
	builder->remaining -= aligned;
	return (result);
}

static int
add_string(struct mb2_builder *builder, unsigned int type, const char *str)
{
	struct multiboot_tag *tag;
	size_t len;

	/* Bound scanning as well as copying by the remaining output capacity. */
	len = strnlen(str, builder->remaining);
	if (len == builder->remaining ||
	    len > SIZE_MAX - sizeof(*tag) - 1)
		return (E2BIG);
	tag = mb2_reserve(builder, sizeof(*tag) + len + 1);
	if (tag == NULL)
		return (E2BIG);
	tag->type = type;
	tag->size = sizeof(*tag) + len + 1;
	memcpy((char *)tag + sizeof(*tag), str, len + 1);
	return (0);
}

static int
add_efi(struct mb2_builder *builder)
{
	struct multiboot_tag *bs;
	struct multiboot_tag_efi64 *efi64;
	struct multiboot_tag_efi64_ih *ih;

	bs = mb2_reserve(builder, sizeof(*bs));
	if (bs == NULL)
		return (E2BIG);
	bs->type = MULTIBOOT_TAG_TYPE_EFI_BS;
	bs->size = sizeof(*bs);
	efi64 = mb2_reserve(builder, sizeof(*efi64));
	if (efi64 == NULL)
		return (E2BIG);
	efi64->type = MULTIBOOT_TAG_TYPE_EFI64;
	efi64->size = sizeof(*efi64);
	efi64->pointer = (uintptr_t)ST;
	ih = mb2_reserve(builder, sizeof(*ih));
	if (ih == NULL)
		return (E2BIG);
	ih->type = MULTIBOOT_TAG_TYPE_EFI64_IH;
	ih->size = sizeof(*ih);
	ih->pointer = (uintptr_t)IH;
	return (0);
}

static int
add_module(struct mb2_builder *builder, vm_offset_t start, vm_offset_t end,
    const char *cmdline)
{
	struct multiboot_tag_module *mod;
	size_t len = 0;

	if (cmdline != NULL) {
		len = strnlen(cmdline, builder->remaining);
		if (len == builder->remaining ||
		    len > SIZE_MAX - sizeof(*mod) - 1)
			return (E2BIG);
		len++;
	}
	mod = mb2_reserve(builder, sizeof(*mod) + len);
	if (mod == NULL)
		return (E2BIG);
	mod->type = MULTIBOOT_TAG_TYPE_MODULE;
	mod->size = sizeof(*mod) + len;
	mod->mod_start = start;
	mod->mod_end = end;
	if (len != 0)
		memcpy((char *)mod + sizeof(*mod), cmdline, len);
	return (0);
}

static int
add_end(struct mb2_builder *builder)
{
	struct multiboot_tag *tag;

	tag = mb2_reserve(builder, sizeof(*tag));
	if (tag == NULL)
		return (E2BIG);
	tag->type = MULTIBOOT_TAG_TYPE_END;
	tag->size = sizeof(*tag);
	return (0);
}

static int
exec(struct preloaded_file *fp)
{
	EFI_PHYSICAL_ADDRESS		 addr = 0;
	EFI_PHYSICAL_ADDRESS		 stack = 0;
	EFI_STATUS			 status;
	struct mb2_builder		 builder;
	vm_offset_t			 modulep, kernend, kern_base,
					 payload_base;
	char				*cmdline = NULL;
	size_t				 len, name_len, args_len;
	int				 error;
	uint32_t			*total_size;
	struct file_metadata		*md;
	struct xen_header		 header;
	struct mb2hdr			*hdr;


	_Static_assert(sizeof(header) <= PAGE_SIZE, "header too big");

	if ((md = file_findmetadata(fp,
	    MODINFOMD_NOCOPY | MODINFOMD_MB2HDR)) == NULL) {
		printf("Missing Multiboot2 EFI64 entry point\n");
		return(EFTYPE);
	}
	hdr = (void *)&md->md_data;

	status = BS->AllocatePages(AllocateAnyPages, EfiLoaderData,
	    EFI_SIZE_TO_PAGES(PAGE_SIZE), &addr);
	if (EFI_ERROR(status)) {
		printf("Failed to allocate pages for multiboot2 header: %lu\n",
		    DECODE_ERROR(status));
		error = ENOMEM;
		goto error;
	}
	status = BS->AllocatePages(AllocateAnyPages, EfiLoaderData,
	    EFI_SIZE_TO_PAGES(128 * 1024), &stack);
	if (EFI_ERROR(status)) {
		printf("Failed to allocate pages for Xen stack: %lu\n",
		    DECODE_ERROR(status));
		error = ENOMEM;
		goto error;
	}

	/*
	 * Scratch space to build the multiboot2 header. Reserve the start of
	 * the space to place the header with the size, which we don't know
	 * yet.
	 */
	builder.next = (char *)(uintptr_t)(addr + sizeof(uint32_t) * 2);
	builder.remaining = PAGE_SIZE - sizeof(uint32_t) * 2;
	memset((void *)(uintptr_t)addr, 0, sizeof(uint32_t) * 2);

	/*
	 * Don't pass the memory size found by the bootloader, the memory
	 * available to Dom0 will be lower than that.
	 */
	unsetenv("smbios.memory.enabled");

	/* Set the Xen command line. */
	if (fp->f_args == NULL) {
		/* Add the Xen command line if it is set. */
		cmdline = getenv("xen_cmdline");
		if (cmdline != NULL) {
			if (strnlen(cmdline, PAGE_SIZE) == PAGE_SIZE) {
				error = E2BIG;
				goto error;
			}
			fp->f_args = strdup(cmdline);
			if (fp->f_args == NULL) {
				error = ENOMEM;
				goto error;
			}
		}
	}
	if (fp->f_args != NULL) {
		name_len = strnlen(fp->f_name, PAGE_SIZE);
		args_len = strnlen(fp->f_args, PAGE_SIZE);
		if (name_len == PAGE_SIZE || args_len == PAGE_SIZE ||
		    name_len + args_len + 2 > PAGE_SIZE) {
			error = E2BIG;
			goto error;
		}
		len = name_len + args_len + 2;
		cmdline = malloc(len);
		if (cmdline == NULL) {
			error = ENOMEM;
			goto error;
		}
		snprintf(cmdline, len, "%s %s", fp->f_name, fp->f_args);
		error = add_string(&builder, MULTIBOOT_TAG_TYPE_CMDLINE, cmdline);
		free(cmdline);
		if (error != 0)
			goto error;
	}

	error = add_string(&builder, MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME,
	    "FreeBSD Loader");
	if (error != 0)
		goto error;
	error = add_efi(&builder);
	if (error != 0)
		goto error;

	/*
	 * Prepare the multiboot module list, Xen assumes the first
	 * module is the Dom0 kernel, and the second one is the initramfs.
	 * This is not optimal for FreeBSD, that doesn't have a initramfs
	 * but instead loads modules dynamically and creates the metadata
	 * info on-the-fly.
	 *
	 * As expected, the first multiboot module is going to be the
	 * FreeBSD kernel loaded as a raw file. The second module is going
	 * to contain the metadata info and the loaded modules.
	 *
	 * There's a small header prefixed in the second module that contains
	 * some information required to calculate the relocated address of
	 * modulep based on the original offset of modulep from the start of
	 * the module address. Note other fields might be added to this header
	 * if required.
	 *
	 * Native layout:
	 *           fp->f_addr + fp->f_size
	 * +---------+----------------+------------+
	 * |         |                |            |
	 * | Kernel  |    Modules     |  Metadata  |
	 * |         |                |            |
	 * +---------+----------------+------------+
	 * fp->f_addr                 modulep      kernend
	 *
	 * Xen dom0 layout:
	 * fp->f_addr             fp->f_addr + fp->f_size
	 * +---------+------------+----------------+------------+
	 * |         |            |                |            |
	 * | Kernel  | xen_header |    Modules     |  Metadata  |
	 * |         |            |                |            |
	 * +---------+------------+----------------+------------+
	 * 	                                   modulep      kernend
	 * \________/\__________________________________________/
	 *  module 0                 module 1
	 */

	fp = file_findfile(NULL, md_kerntype);
	if (fp == NULL) {
		printf("No FreeBSD kernel provided, aborting\n");
		error = EINVAL;
		goto error;
	}

	error = bi_load(fp->f_args, &modulep, &kernend, false);
	if (error != 0)
		goto error;

	/*
	 * Note that the Xen kernel requires to be started with BootServices
	 * enabled, and hence we cannot use efi_copy_finish to relocate the
	 * loaded data from the staging area to the expected loaded addresses.
	 * This is fine because the Xen kernel is relocatable, so it can boot
	 * fine straight from the staging area. We use efi_translate to get the
	 * staging addresses where the kernels and metadata are currently
	 * loaded.
	 */
	kern_base = (uintptr_t)efi_translate(fp->f_addr);
	payload_base = kern_base + fp->f_size - PAGE_SIZE;
	error = add_module(&builder, kern_base, payload_base, NULL);
	if (error != 0)
		goto error;
	error = add_module(&builder, payload_base,
	    (uintptr_t)efi_translate(kernend), "header");
	if (error != 0)
		goto error;

	header.flags = XENHEADER_HAS_MODULEP_OFFSET;
	header.modulep_offset = modulep - (fp->f_addr + fp->f_size - PAGE_SIZE);
	archsw.arch_copyin(&header, fp->f_addr + fp->f_size - PAGE_SIZE,
	    sizeof(header));

	error = add_end(&builder);
	if (error != 0)
		goto error;
	total_size = (uint32_t *)(uintptr_t)(addr);
	*total_size = PAGE_SIZE - builder.remaining;

	efi_time_fini();
	dev_cleanup();
	multiboot2_exec(efi_translate(hdr->efi64_entry), addr,
	    stack + 128 * 1024);

	panic("exec returned");

error:
	if (addr)
		BS->FreePages(addr, EFI_SIZE_TO_PAGES(PAGE_SIZE));
	if (stack)
		BS->FreePages(stack, EFI_SIZE_TO_PAGES(128 * 1024));
	return (error);
}

static int
obj_loadfile(char *filename, uint64_t dest, struct preloaded_file **result)
{
	struct preloaded_file	*mfp, *kfp, *rfp;
	int			 error;

	/* See if there's a multiboot kernel loaded */
	mfp = file_findfile(NULL, md_kerntype_mb);
	if (mfp == NULL)
		return (EFTYPE);

	/*
	 * We have a multiboot kernel loaded, see if there's a FreeBSD
	 * kernel loaded also.
	 */
	kfp = file_findfile(NULL, md_kerntype);
	if (kfp == NULL) {
		/*
		 * No kernel loaded, this must be it. The kernel has to
		 * be loaded as a raw file, it will be processed by
		 * Xen and correctly loaded as an ELF file.
		 */
		rfp = file_loadraw(filename, md_kerntype, 0);
		if (rfp == NULL) {
			printf(
			"Unable to load %s as a multiboot payload kernel\n",
			filename);
			return (EINVAL);
		}

		/* Load kernel metadata... */
		setenv("kernelname", filename, 1);
		error = elf64_load_modmetadata(rfp, rfp->f_addr + rfp->f_size);
		if (error) {
			printf("Unable to load kernel %s metadata error: %d\n",
			    rfp->f_name, error);
			return (EINVAL);
		}


		/*
		 * Reserve one page at the end of the kernel to place some
		 * metadata in order to cope for Xen relocating the modules and
		 * the metadata information.
		 */
		rfp->f_size = roundup(rfp->f_size, PAGE_SIZE);
		rfp->f_size += PAGE_SIZE;
		*result = rfp;
	} else {
		/* The rest should be loaded as regular modules */
		error = elf64_obj_loadfile(filename, dest, result);
		if (error != 0) {
			printf("Unable to load %s as an object file, error: %d",
			    filename, error);
			return (error);
		}
	}

	return (0);
}

static int
obj_exec(struct preloaded_file *fp)
{

	return (EFTYPE);
}

struct file_format multiboot2 = {
	.l_load = loadfile,
	.l_exec = exec
};
struct file_format multiboot2_obj = {
	.l_load = obj_loadfile,
	.l_exec = obj_exec
};
