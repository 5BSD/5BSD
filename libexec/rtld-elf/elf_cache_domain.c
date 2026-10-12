/* SPDX-License-Identifier: BSD-2-Clause */
/* Optional authority-selected placement and exact post-relocation sharing. */
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/elf_cache.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "rtld.h"
#include "rtld_libc.h"

void *
rtld_cache_domain_address(int cachefd, off_t file_offset, size_t mapsize,
    struct rtld_cache_domain *state)
{
	struct cap_cache_domain_result result;
	struct elf_cache_layout_header h;
	struct elf_cache_header cache;
	const struct elf_cache_entry *cache_entries;
	struct stat st;
	const struct elf_cache_layout_entry *entries;
	void *mapping = MAP_FAILED, *cache_mapping = MAP_FAILED, *address = NULL;
	size_t length = 0, cache_index_size = 0;
	uint32_t count;
	int fd;

	/* No environment, ambient pathname, or caller descriptor selects a domain. */
	fd = syscall(SYS_cap_process, CAP_CACHE_DOMAIN_GET_LAYOUT, -1, 0, &result);
	if (fd < 0)
		return (NULL);
	if (result.reserved != 0 || result.domain_id == 0 ||
	    fstat(cachefd, &st) != 0 || result.cache_device != (uint64_t)st.st_dev ||
	    result.cache_inode != (uint64_t)st.st_ino ||
	    result.cache_size != (uint64_t)st.st_size ||
	    pread(cachefd, &cache, sizeof(cache), 0) != sizeof(cache) ||
	    le32toh(cache.count) > ELF_CACHE_MAX_ENTRIES ||
	    fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(h) ||
	    st.st_size > ELF_CACHE_LAYOUT_MAX_SIZE ||
	    pread(fd, &h, sizeof(h), 0) != sizeof(h))
		goto out;
	length = st.st_size;
	count = le32toh(h.count);
	if (memcmp(h.magic, "5BSDLAY", 8) != 0 ||
	    le32toh(h.version) != ELF_CACHE_LAYOUT_VERSION ||
	    le32toh(h.header_size) != sizeof(h) ||
	    le32toh(h.page_size) != page_size || count == 0 ||
	    count > ELF_CACHE_MAX_ENTRIES ||
	    le32toh(h.entry_size) != sizeof(*entries) ||
	    length != sizeof(h) + count * sizeof(*entries) ||
	    le64toh(h.cache_size) != result.cache_size ||
	    le64toh(h.relro_size) > ELF_CACHE_RELRO_MAX_SIZE)
		goto out;
	mapping = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED)
		goto out;
	entries = (const void *)((const char *)mapping + sizeof(h));
	cache_index_size = sizeof(cache) + le32toh(cache.count) * sizeof(*cache_entries);
	if (cache_index_size > result.cache_size)
		goto out;
	cache_mapping = mmap(NULL, cache_index_size, PROT_READ, MAP_PRIVATE, cachefd, 0);
	if (cache_mapping == MAP_FAILED)
		goto out;
	cache_entries = (const void *)((const char *)cache_mapping + sizeof(cache));
	for (uint32_t i = 0; i < count; i++) {
		const struct elf_cache_layout_entry *e = &entries[i];
		uint32_t index = le32toh(e->cache_index);
		uint64_t offset = le64toh(e->slot_offset);
		if (index >= le32toh(cache.count))
			goto out;
		const struct elf_cache_entry *ce = &cache_entries[index];
		if (le64toh(ce->offset) != (uint64_t)file_offset)
			continue;
		if (le64toh(e->map_size) != mapsize ||
		    memcmp(e->sha256, ce->sha256, sizeof(e->sha256)) != 0 ||
		    offset > UINTPTR_MAX - result.domain_base ||
		    mapsize > UINTPTR_MAX - result.domain_base - offset)
			goto out;
		state->identity = result.domain_id;
		state->base = result.domain_base;
		state->index = i;
		state->count = count;
		state->relro_vaddr = le64toh(e->relro_vaddr);
		state->relro_size = le64toh(e->relro_size);
		state->relro_offset = le64toh(e->relro_offset);
		state->file_size = le64toh(h.relro_size);
		memcpy(state->cache_sha256, h.cache_sha256, sizeof(state->cache_sha256));
		address = (void *)(uintptr_t)(result.domain_base + offset);
		break;
	}
out:
	if (cache_mapping != MAP_FAILED)
		munmap(cache_mapping, cache_index_size);
	if (mapping != MAP_FAILED)
		munmap(mapping, length);
	close(fd);
	return (address);
}

static bool
capture_write(int fd, const void *bytes, size_t size, off_t offset)
{
	while (size != 0) {
		ssize_t n = syscall(SYS_pwrite, fd, bytes, size, offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (false);
		bytes = (const char *)bytes + n;
		size -= n;
		offset += n;
	}
	return (true);
}

void
rtld_cache_domain_relro(Obj_Entry *obj)
{
	struct rtld_cache_domain *state = &obj->cache_domain;
	struct cap_cache_domain_result result;
	struct elf_cache_relro_header h;
	struct stat st;
	unsigned char complete;
	char *local;
	void *canonical = MAP_FAILED;
	int fd;

	if (state->identity == 0 || state->done || state->resolving || state->relro_size == 0)
		return;
	state->done = true;
	if (state->relro_vaddr > obj->mapsize ||
	    state->relro_size > obj->mapsize - state->relro_vaddr ||
	    state->relro_offset > state->file_size ||
	    state->relro_size > state->file_size - state->relro_offset)
		return;
	fd = syscall(SYS_cap_process, CAP_CACHE_DOMAIN_GET_RELRO, -1, 0, &result);
	if (fd < 0)
		return;
	if (result.domain_id != state->identity || result.domain_base != state->base ||
	    result.reserved != 0 || fstat(fd, &st) != 0 ||
	    (uint64_t)st.st_size != state->file_size ||
	    pread(fd, &h, sizeof(h), 0) != sizeof(h) ||
	    memcmp(h.magic, "5BSDRLO", 8) != 0 ||
	    le32toh(h.version) != ELF_CACHE_RELRO_VERSION ||
	    le32toh(h.header_size) != sizeof(h) ||
	    le64toh(h.domain_id) != state->identity ||
	    le64toh(h.domain_base) != state->base ||
	    le32toh(h.count) != state->count ||
	    le32toh(h.completed_offset) != sizeof(h) ||
	    le64toh(h.file_size) != state->file_size ||
	    memcmp(h.cache_sha256, state->cache_sha256, sizeof(h.cache_sha256)) != 0)
		goto out;
	local = obj->relocbase + state->relro_vaddr;
	if ((result.flags & CAP_CACHE_DOMAIN_SEED) != 0) {
		/* Completion is published only after the whole slice was captured. */
		complete = 0;
		if (!capture_write(fd, &complete, 1, sizeof(h) + state->index))
			goto out;
		if (capture_write(fd, local, state->relro_size, state->relro_offset)) {
			complete = 1;
			(void)capture_write(fd, &complete, 1, sizeof(h) + state->index);
		}
		goto out;
	}
	if ((result.flags & CAP_CACHE_DOMAIN_READY) == 0 ||
	    pread(fd, &complete, 1, sizeof(h) + state->index) != 1 || complete != 1)
		goto out;
	canonical = mmap(NULL, state->relro_size, PROT_READ, MAP_PRIVATE,
	    fd, state->relro_offset);
	if (canonical == MAP_FAILED)
		goto out;
	for (size_t pos = 0; pos < state->relro_size;) {
		/* Lazy/eager bindings, interposition, IFUNC, and TLS differences all
		 * remain private. Never reuse canonical relocations speculatively. */
		if (memcmp(local + pos, (const char *)canonical + pos, page_size) != 0) {
			pos += page_size;
			continue;
		}
		/* Replace a contiguous matching run with one mapping.  Compare
		 * every page first; a differing page always splits the run. */
		size_t start = pos;
		do {
			pos += page_size;
		} while (pos < state->relro_size &&
		    memcmp(local + pos, (const char *)canonical + pos, page_size) == 0);
		(void)mmap(local + start, pos - start,
		    PROT_READ | PROT_MAX(PROT_READ | PROT_WRITE), MAP_PRIVATE | MAP_FIXED,
		    fd, state->relro_offset + start);
	}
out:
	if (canonical != MAP_FAILED)
		munmap(canonical, state->relro_size);
	close(fd);
}
