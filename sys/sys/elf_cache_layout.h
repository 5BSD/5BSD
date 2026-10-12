/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_ELF_CACHE_LAYOUT_H_
#define _SYS_ELF_CACHE_LAYOUT_H_
#include <sys/types.h>
#include <sys/stdint.h>
#include <sys/endian.h>
#include <sys/elf64.h>
#include <sys/elf_cache.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/errno.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#endif

/* A shared, allocation-free decoder for the builder, broker and kernel.
 * The callback returns an errno value and must transfer the complete request. */
struct elf_cache_layout_reader {
	int (*read)(void *, uint64_t, void *, size_t);
	void *argument;
	uint64_t size;
};
struct elf_cache_layout_image {
	uint64_t map_size;
	uint64_t relro_vaddr;
	uint64_t relro_size;
};
static __inline int
elf_cache_layout_read(const struct elf_cache_layout_reader *r, uint64_t offset,
    void *data, size_t size)
{
	if (offset > r->size || size > r->size - offset)
		return (EINVAL);
	return (r->read(r->argument, offset, data, size));
}
static __inline int
elf_cache_layout_round(uint64_t value, uint64_t alignment, uint64_t *out)
{
	if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
	    value > UINT64_MAX - (alignment - 1))
		return (EINVAL);
	*out = (value + alignment - 1) & ~(alignment - 1);
	return (0);
}
static __inline int
elf_cache_layout_image(const struct elf_cache_layout_reader *r,
    const struct elf_cache_entry *entry, uint32_t machine, uint32_t page,
    struct elf_cache_layout_image *out)
{
	Elf64_Ehdr h;
	Elf64_Phdr p, loads[64];
	Elf64_Dyn d;
	uint64_t base, size, low = UINT64_MAX, high = 0, start, end;
	uint64_t relro_start = 0, relro_end = 0, phoff, off, filesz, memsz, addr;
	unsigned phnum, nloads = 0, nrelro = 0;
	bool dynamic = false, contained = false;
	int error;

	memset(out, 0, sizeof(*out));
	base = le64toh(entry->offset);
	size = le64toh(entry->size);
	if (page == 0 || (page & (page - 1)) != 0 || size < sizeof(h) ||
	    base > r->size || size > r->size - base)
		return (EINVAL);
	error = elf_cache_layout_read(r, base, &h, sizeof(h));
	if (error != 0)
		return (error);
	phoff = le64toh(h.e_phoff);
	phnum = le16toh(h.e_phnum);
	if (memcmp(h.e_ident, ELFMAG, SELFMAG) != 0 ||
	    h.e_ident[EI_CLASS] != ELFCLASS64 || h.e_ident[EI_DATA] != ELFDATA2LSB ||
	    h.e_ident[EI_VERSION] != EV_CURRENT || le32toh(h.e_version) != EV_CURRENT ||
	    le16toh(h.e_type) != ET_DYN || le16toh(h.e_machine) != machine ||
	    le16toh(h.e_ehsize) != sizeof(h) ||
	    le16toh(h.e_phentsize) != sizeof(p) || phnum == 0 || phnum > 64 ||
	    phoff < sizeof(h) || phoff > size || phnum > (size - phoff) / sizeof(p))
		return (EINVAL);
	for (unsigned i = 0; i < phnum; i++) {
		error = elf_cache_layout_read(r, base + phoff + i * sizeof(p), &p, sizeof(p));
		if (error != 0)
			return (error);
		off = le64toh(p.p_offset); filesz = le64toh(p.p_filesz);
		memsz = le64toh(p.p_memsz); addr = le64toh(p.p_vaddr);
		if (off > size || filesz > size - off || le32toh(p.p_type) == PT_INTERP)
			return (EINVAL);
		if (le32toh(p.p_type) == PT_LOAD) {
			if (filesz > memsz || memsz > UINT64_MAX - addr ||
			    addr % page != off % page ||
			    (le32toh(p.p_flags) & (PF_W | PF_X)) == (PF_W | PF_X) ||
			    ((le32toh(p.p_flags) & PF_W) == 0 && memsz != filesz) ||
			    elf_cache_layout_round(addr + memsz, page, &end) != 0)
				return (EINVAL);
			start = addr & ~(uint64_t)(page - 1);
			for (unsigned j = 0; j < nloads; j++) {
				uint64_t a = loads[j].p_vaddr, b = loads[j].p_memsz;
				if (start < b && a < end)
					return (EINVAL);
			}
			loads[nloads] = p;
			loads[nloads].p_vaddr = start;
			loads[nloads++].p_memsz = end;
			if (start < low) low = start;
			if (end > high) high = end;
		} else if (le32toh(p.p_type) == PT_GNU_RELRO) {
			if (++nrelro != 1 || memsz == 0 || memsz > UINT64_MAX - addr ||
			    elf_cache_layout_round(addr + memsz, page, &relro_end) != 0)
				return (EINVAL);
			relro_start = addr & ~(uint64_t)(page - 1);
		} else if (le32toh(p.p_type) == PT_DYNAMIC) {
			if (dynamic || filesz % sizeof(d) != 0 || filesz > 1024 * 1024)
				return (EINVAL);
			for (uint64_t j = 0; j < filesz; j += sizeof(d)) {
				error = elf_cache_layout_read(r, base + off + j, &d, sizeof(d));
				if (error != 0) return (error);
				if (le64toh(d.d_tag) == DT_TEXTREL ||
				    (le64toh(d.d_tag) == DT_FLAGS &&
				    (le64toh(d.d_un.d_val) & DF_TEXTREL) != 0))
					return (EINVAL);
				if (le64toh(d.d_tag) == DT_NULL) { dynamic = true; break; }
			}
			if (!dynamic) return (EINVAL);
		}
	}
	if (nloads == 0 || low != 0 || high == 0 || !dynamic ||
	    high > ELF_CACHE_LAYOUT_MAX_SPAN)
		return (EINVAL);
	if (nrelro != 0) {
		for (unsigned i = 0; i < nloads; i++)
			if ((le32toh(loads[i].p_flags) & (PF_R | PF_W | PF_X)) == (PF_R | PF_W) &&
			    loads[i].p_vaddr <= relro_start && relro_end <= loads[i].p_memsz)
				contained = true;
		if (!contained) return (EINVAL);
		out->relro_vaddr = relro_start;
		out->relro_size = relro_end - relro_start;
	}
	out->map_size = high;
	return (0);
}

/* Validates the sidecar including its correspondence to every selected ELF.
 * Signature and whole-cache digest verification belong to the issuer/broker;
 * these readers must describe immutable pinned objects before validation. */
static __inline int
elf_cache_layout_validate(const void *bytes, size_t length,
    const struct elf_cache_layout_reader *cache, uint32_t machine, uint32_t page)
{
	struct elf_cache_layout_header h;
	struct elf_cache_layout_entry e;
	struct elf_cache_header ch;
	struct elf_cache_entry ce;
	struct elf_cache_layout_image image;
	uint64_t slot_end = 0, cursor, offset, span, size, index_bytes;
	uint32_t count, cache_count, last = 0;
	int error;

	if (length < sizeof(h) || length > ELF_CACHE_LAYOUT_MAX_SIZE)
		return (EINVAL);
	memcpy(&h, bytes, sizeof(h));
	count = le32toh(h.count);
	if (memcmp(h.magic, "5BSDLAY", 8) != 0 ||
	    le32toh(h.version) != ELF_CACHE_LAYOUT_VERSION ||
	    le32toh(h.header_size) != sizeof(h) || le32toh(h.machine) != machine ||
	    le32toh(h.page_size) != page || page == 0 || (page & (page - 1)) != 0 ||
	    count == 0 || count > ELF_CACHE_MAX_ENTRIES ||
	    le32toh(h.entry_size) != sizeof(e) ||
	    length != sizeof(h) + (size_t)count * sizeof(e) ||
	    le64toh(h.slot_alignment) != ELF_CACHE_LAYOUT_ALIGNMENT ||
	    ELF_CACHE_LAYOUT_ALIGNMENT % page != 0 ||
	    le64toh(h.cache_size) != cache->size || cache->size > ELF_CACHE_MAX_SIZE ||
	    le64toh(h.layout_span) == 0 ||
	    le64toh(h.layout_span) > ELF_CACHE_LAYOUT_MAX_SPAN ||
	    le64toh(h.layout_span) % ELF_CACHE_LAYOUT_ALIGNMENT != 0 ||
	    le64toh(h.relro_size) > ELF_CACHE_RELRO_MAX_SIZE ||
	    memcmp(h.reserved, (unsigned char[32]){0}, sizeof(h.reserved)) != 0 ||
	    elf_cache_layout_round(sizeof(struct elf_cache_relro_header) + count,
	    page, &cursor) != 0)
		return (EINVAL);
	error = elf_cache_layout_read(cache, 0, &ch, sizeof(ch));
	if (error != 0) return (error);
	cache_count = le32toh(ch.count);
	if (memcmp(ch.magic, "5BSDELF", 8) != 0 || le32toh(ch.version) != ELF_CACHE_VERSION ||
	    cache_count == 0 || cache_count > ELF_CACHE_MAX_ENTRIES ||
	    le64toh(ch.file_size) != cache->size ||
	    le32toh(ch.alignment) != ELF_CACHE_ALIGNMENT ||
	    le32toh(ch.entry_size) != sizeof(ce) ||
	    memcmp(ch.reserved, (unsigned char[32]){0}, sizeof(ch.reserved)) != 0)
		return (EINVAL);
	index_bytes = sizeof(ch) + (uint64_t)cache_count * sizeof(ce);
	if (index_bytes > cache->size) return (EINVAL);
	for (unsigned i = 0; i < count; i++) {
		memcpy(&e, (const char *)bytes + sizeof(h) + i * sizeof(e), sizeof(e));
		uint32_t index = le32toh(e.cache_index);
		if (e.reserved != 0 || index >= cache_count || (i != 0 && index <= last))
			return (EINVAL);
		last = index;
		error = elf_cache_layout_read(cache, sizeof(ch) + (uint64_t)index * sizeof(ce), &ce, sizeof(ce));
		if (error != 0) return (error);
		offset = le64toh(ce.offset); size = le64toh(ce.size);
		if (le32toh(ce.directory) > 1 || ce.reserved != 0 || ce.name[0] == 0 ||
		    memchr(ce.name, 0, sizeof(ce.name)) == NULL || strchr(ce.name, '/') != NULL ||
		    offset < index_bytes || offset % ELF_CACHE_ALIGNMENT != 0 ||
		    offset > cache->size || size > cache->size - offset ||
		    le64toh(ce.source_size) < size || memcmp(e.sha256, ce.sha256, 32) != 0)
			return (EINVAL);
		error = elf_cache_layout_image(cache, &ce, machine, page, &image);
		if (error != 0) return (error);
		offset = le64toh(e.slot_offset); span = le64toh(h.layout_span);
		if (offset % ELF_CACHE_LAYOUT_ALIGNMENT != 0 || offset < slot_end ||
		    offset > span || image.map_size > span - offset ||
		    le64toh(e.map_size) != image.map_size ||
		    le64toh(e.relro_vaddr) != image.relro_vaddr ||
		    le64toh(e.relro_size) != image.relro_size)
			return (EINVAL);
		slot_end = offset + image.map_size;
		if (image.relro_size != 0) {
			if (le64toh(e.relro_offset) != cursor || cursor > ELF_CACHE_RELRO_MAX_SIZE ||
			    image.relro_size > ELF_CACHE_RELRO_MAX_SIZE - cursor)
				return (EINVAL);
			cursor += image.relro_size;
		} else if (e.relro_offset != 0)
			return (EINVAL);
	}
	return (cursor == le64toh(h.relro_size) ? 0 : EINVAL);
}
#endif
