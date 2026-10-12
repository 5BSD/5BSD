/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/elf_cache_layout.h>
#include <sys/stat.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <capimage.h>

static int
layout_read(void *argument, uint64_t offset, void *data, size_t size)
{
	int fd = *(int *)argument;
	unsigned char *p = data;
	while (size != 0) {
		ssize_t n = pread(fd, p, size, (off_t)offset);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return (n == 0 ? EIO : errno);
		p += n; offset += n; size -= (size_t)n;
	}
	return (0);
}
static void
layout_hash(int fd, uint64_t size, unsigned char digest[32])
{
	unsigned char buffer[16384];
	unsigned length;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		errx(1, "layout digest initialization");
	for (uint64_t off = 0; off < size;) {
		size_t n = size - off < sizeof(buffer) ? (size_t)(size - off) : sizeof(buffer);
		if (layout_read(&fd, off, buffer, n) != 0 || EVP_DigestUpdate(ctx, buffer, n) != 1)
			errx(1, "layout digest input");
		off += n;
	}
	if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 || length != 32)
		errx(1, "layout digest finalization");
	EVP_MD_CTX_free(ctx);
}
void elfcache_layout_build(const char *, const char *, const char *, const char *);
void
elfcache_layout_build(const char *input, const char *output, const char *key,
    const char *public)
{
	struct elf_cache_header cache_header;
	struct elf_cache_entry entry;
	struct elf_cache_layout_header *h;
	struct elf_cache_layout_entry *entries;
	struct elf_cache_layout_image image;
	struct elf_cache_layout_reader reader;
	struct stat st;
	unsigned char digest[32];
	char *temporary, *sealpath = NULL, *destination, error[256];
	uint64_t span = 0, cursor;
	unsigned count = 0, total;
	int fd, out, seal = -1, e;
	uint32_t page = 4096;

	fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) != 0) err(1, "%s", input);
	if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(cache_header) ||
	    (uint64_t)st.st_size > ELF_CACHE_MAX_SIZE)
		errx(1, "invalid layout cache input");
	if (public != NULL) {
		if (asprintf(&destination, "%s.sig", input) < 0) err(1, "asprintf");
		seal = open(destination, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); free(destination);
		if (seal < 0 || capimage_check_seal(fd, seal, ELF_CACHE_DOMAIN, public,
		    error, sizeof(error)) < 0) errx(1, "cache signature: %s", seal < 0 ? strerror(errno) : error);
		close(seal); seal = -1;
	}
	if (layout_read(&fd, 0, &cache_header, sizeof(cache_header)) != 0)
		errx(1, "cache header read");
	total = le32toh(cache_header.count);
	if (memcmp(cache_header.magic, "5BSDELF", 8) != 0 ||
	    le32toh(cache_header.version) != ELF_CACHE_VERSION || total == 0 ||
	    total > ELF_CACHE_MAX_ENTRIES || le64toh(cache_header.file_size) != (uint64_t)st.st_size ||
	    le32toh(cache_header.entry_size) != sizeof(entry))
		errx(1, "invalid cache header");
	h = calloc(1, sizeof(*h) + total * sizeof(*entries));
	if (h == NULL) err(1, "layout allocation");
	entries = (void *)(h + 1);
	reader = (struct elf_cache_layout_reader){layout_read, &fd, (uint64_t)st.st_size};
	layout_hash(fd, reader.size, h->cache_sha256);
	for (unsigned i = 0; i < total; i++) {
		if (layout_read(&fd, sizeof(cache_header) + (uint64_t)i * sizeof(entry), &entry, sizeof(entry)) != 0)
			errx(1, "cache index read");
		if (elf_cache_layout_image(&reader, &entry, EM_X86_64, page, &image) != 0)
			continue; /* Unusual ELF objects retain ordinary private placement. */
		if (span > ELF_CACHE_LAYOUT_MAX_SPAN || image.map_size > ELF_CACHE_LAYOUT_MAX_SPAN - span)
			errx(1, "layout address span exceeds bound");
		entries[count].cache_index = htole32(i);
		entries[count].slot_offset = htole64(span);
		entries[count].map_size = htole64(image.map_size);
		entries[count].relro_vaddr = htole64(image.relro_vaddr);
		entries[count].relro_size = htole64(image.relro_size);
		memcpy(entries[count].sha256, entry.sha256, 32);
		if (elf_cache_layout_round(span + image.map_size, ELF_CACHE_LAYOUT_ALIGNMENT, &span) != 0)
			errx(1, "layout address span overflow");
		count++;
	}
	if (count == 0) errx(1, "no layout-eligible cache images");
	if (elf_cache_layout_round(sizeof(struct elf_cache_relro_header) + count, page, &cursor) != 0)
		errx(1, "canonical header overflow");
	for (unsigned i = 0; i < count; i++) {
		uint64_t size = le64toh(entries[i].relro_size);
		if (size == 0) continue;
		if (cursor > ELF_CACHE_RELRO_MAX_SIZE || size > ELF_CACHE_RELRO_MAX_SIZE - cursor)
			errx(1, "canonical backing exceeds bound");
		entries[i].relro_offset = htole64(cursor); cursor += size;
	}
	memcpy(h->magic, "5BSDLAY", 8);
	h->version = htole32(ELF_CACHE_LAYOUT_VERSION); h->header_size = htole32(sizeof(*h));
	h->machine = htole32(EM_X86_64); h->page_size = htole32(page);
	h->count = htole32(count); h->entry_size = htole32(sizeof(*entries));
	h->slot_alignment = htole64(ELF_CACHE_LAYOUT_ALIGNMENT); h->layout_span = htole64(span);
	h->cache_size = htole64(reader.size); h->relro_size = htole64(cursor);
	size_t length = sizeof(*h) + count * sizeof(*entries);
	e = elf_cache_layout_validate(h, length, &reader, EM_X86_64, page);
	if (e != 0) errx(1, "layout validation: %s", strerror(e));
	layout_hash(fd, reader.size, digest);
	if (memcmp(digest, h->cache_sha256, 32) != 0) errx(1, "cache changed while constructing layout");
	if (asprintf(&temporary, "%s.tmp.XXXXXX", output) < 0) err(1, "asprintf");
	out = mkstemp(temporary);
	if (out < 0 || write(out, h, length) != (ssize_t)length || fchmod(out, 0444) != 0 || fsync(out) != 0)
		err(1, "write layout");
	if (key != NULL) {
		if (asprintf(&sealpath, "%s.sig", temporary) < 0) err(1, "asprintf");
		seal = open(sealpath, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (seal < 0 || capimage_seal(out, seal, ELF_CACHE_LAYOUT_DOMAIN, key, error, sizeof(error)) < 0)
			errx(1, "layout signature: %s", seal < 0 ? strerror(errno) : error);
		if (fchmod(seal, 0444) != 0 || fsync(seal) != 0 || close(seal) != 0) err(1, "finish layout signature");
	}
	if (link(temporary, output) != 0) err(1, "publish %s", output);
	if (sealpath != NULL) {
		if (asprintf(&destination, "%s.sig", output) < 0) err(1, "asprintf");
		if (link(sealpath, destination) != 0) { unlink(output); err(1, "publish layout signature"); }
		unlink(sealpath); free(sealpath); free(destination);
	}
	unlink(temporary); free(temporary); close(out); close(fd); free(h);
	printf("layout_entries=%u skipped=%u address_span=%ju canonical_bytes=%ju layout_bytes=%zu\n",
	    count, total - count, (uintmax_t)span, (uintmax_t)cursor, length);
}

/* Offline inputs can change. Authenticate and inspect the same private copy. */
static FILE *
layout_verified_copy(const char *path, const char *domain, const char *public,
    uint64_t maximum)
{
	struct stat st;
	unsigned char buffer[16384];
	char *signature, error[256];
	FILE *copy;
	int fd, seal;

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) != 0) err(1, "%s", path);
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 || (uint64_t)st.st_size > maximum)
		errx(1, "invalid verification input: %s", path);
	copy = tmpfile();
	if (copy == NULL) err(1, "verification snapshot");
	for (uint64_t offset = 0; offset < (uint64_t)st.st_size;) {
		size_t n = (uint64_t)st.st_size - offset < sizeof(buffer) ?
		    (size_t)((uint64_t)st.st_size - offset) : sizeof(buffer);
		if (layout_read(&fd, offset, buffer, n) != 0 ||
		    fwrite(buffer, 1, n, copy) != n)
			errx(1, "verification snapshot input: %s", path);
		offset += n;
	}
	close(fd);
	if (fflush(copy) != 0) err(1, "verification snapshot flush");
	if (asprintf(&signature, "%s.sig", path) < 0) err(1, "asprintf");
	seal = open(signature, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	free(signature);
	if (seal < 0 || capimage_check_seal(fileno(copy), seal, domain, public,
	    error, sizeof(error)) < 0)
		errx(1, "%s signature: %s", path, seal < 0 ? strerror(errno) : error);
	close(seal);
	return (copy);
}

void elfcache_layout_verify(const char *, const char *, const char *);
void
elfcache_layout_verify(const char *cachepath, const char *layoutpath,
    const char *public)
{
	struct elf_cache_layout_header *h;
	struct elf_cache_layout_reader reader;
	struct stat st;
	unsigned char digest[32];
	FILE *cache, *layout;
	size_t length;
	int cachefd, layoutfd, error;

	cache = layout_verified_copy(cachepath, ELF_CACHE_DOMAIN, public,
	    ELF_CACHE_MAX_SIZE);
	layout = layout_verified_copy(layoutpath, ELF_CACHE_LAYOUT_DOMAIN, public,
	    ELF_CACHE_LAYOUT_MAX_SIZE);
	cachefd = fileno(cache); layoutfd = fileno(layout);
	if (fstat(cachefd, &st) != 0) err(1, "cache stat");
	reader = (struct elf_cache_layout_reader){layout_read, &cachefd, st.st_size};
	if (fstat(layoutfd, &st) != 0) err(1, "layout stat");
	length = st.st_size;
	if (length < sizeof(*h)) errx(1, "truncated layout header");
	h = malloc(length);
	if (h == NULL) err(1, "layout allocation");
	if (layout_read(&layoutfd, 0, h, length) != 0) errx(1, "layout read");
	error = elf_cache_layout_validate(h, length, &reader, EM_X86_64, 4096);
	if (error != 0) errx(1, "layout validation: %s", strerror(error));
	layout_hash(cachefd, reader.size, digest);
	if (memcmp(digest, h->cache_sha256, sizeof(digest)) != 0)
		errx(1, "layout cache generation mismatch");
	printf("verified layout_entries=%u cache_bytes=%ju\n",
	    le32toh(h->count), (uintmax_t)reader.size);
	free(h); fclose(layout); fclose(cache);
}
