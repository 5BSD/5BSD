/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "elf_cache_eligible.h"

/* A cache slice must not expose adjacent images through malformed segments.
 * Leave unusual objects requiring writable text or read-only BSS fixups on
 * the ordinary loader path, whose compatibility behavior remains intact. */
bool
rtld_cache_eligible(const void *bytes, size_t size, size_t page)
{
	Elf_Ehdr h;
	Elf_Phdr p;
	Elf_Dyn d;
	bool dynamic = false, load = false;
	const unsigned char *data = bytes;

	if (size < sizeof(h) || page == 0 || (page & (page - 1)) != 0)
		return (false);
	memcpy(&h, data, sizeof(h));
	if (memcmp(h.e_ident, ELFMAG, SELFMAG) != 0 ||
	    h.e_ident[EI_CLASS] != ELF_TARG_CLASS || h.e_ident[EI_DATA] != ELF_TARG_DATA ||
	    h.e_ident[EI_VERSION] != EV_CURRENT || h.e_version != EV_CURRENT ||
	    h.e_type != ET_DYN || h.e_machine != ELF_TARG_MACH ||
	    h.e_ehsize != sizeof(h) || h.e_phentsize != sizeof(p) ||
	    h.e_phnum == 0 || h.e_phnum > 4096 || h.e_phoff > size ||
	    h.e_phnum > (size - h.e_phoff) / sizeof(p))
		return (false);
	for (unsigned i = 0; i < h.e_phnum; i++) {
		memcpy(&p, data + h.e_phoff + i * sizeof(p), sizeof(p));
		if (p.p_offset > size || p.p_filesz > size - p.p_offset ||
		    p.p_type == PT_INTERP)
			return (false);
		if (p.p_type == PT_LOAD) {
			if (p.p_memsz < p.p_filesz || p.p_memsz > UINTPTR_MAX - p.p_vaddr ||
			    p.p_vaddr % page != p.p_offset % page ||
			    (p.p_flags & (PF_W | PF_X)) == (PF_W | PF_X) ||
			    ((p.p_flags & PF_W) == 0 && p.p_memsz != p.p_filesz))
				return (false);
			load = true;
		}
		if (p.p_type == PT_DYNAMIC) {
			if (p.p_filesz % sizeof(d) != 0)
				return (false);
			bool terminated = false;
			for (size_t off = 0; off < p.p_filesz; off += sizeof(d)) {
				memcpy(&d, data + p.p_offset + off, sizeof(d));
				if (d.d_tag == DT_TEXTREL ||
				    (d.d_tag == DT_FLAGS && (d.d_un.d_val & DF_TEXTREL) != 0))
					return (false);
				if (d.d_tag == DT_NULL) { terminated = true; break; }
			}
			if (!terminated)
				return (false);
			dynamic = true;
		}
	}
	return (load && dynamic);
}
