/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/endian.h>
#include "sys/elf_cache.h"
#include <sys/stat.h>
#include <dirent.h>
#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <capimage.h>

void elfcache_layout_verify(const char *, const char *, const char *);
void elfcache_layout_build(const char *, const char *, const char *, const char *);

static const char *directories[] = {"/lib", "/usr/lib"};
struct input {
	struct elf_cache_entry entry;
	int fd;
};
static struct input inputs[ELF_CACHE_MAX_ENTRIES];
static unsigned count;
static char *selection[ELF_CACHE_MAX_ENTRIES];
static bool selected_seen[ELF_CACHE_MAX_ENTRIES];
static unsigned selection_count;
static bool have_selection;
static void
read_selection(const char *path)
{
	char line[PATH_MAX];
	FILE *file = fopen(path, "r");
	if (file == NULL) err(1, "%s", path);
	have_selection = true;
	while (fgets(line, sizeof(line), file) != NULL) {
		size_t length = strlen(line);
		if (length == sizeof(line) - 1 && line[length-1] != '\n')
			errx(1, "overlong cache selection line");
		if (length > 0 && line[length-1] == '\n') line[--length] = 0;
		if (length == 0 || line[0] == '#') continue;
		const char *name = strncmp(line, "/lib/", 5) == 0 ? line+5 :
		    strncmp(line, "/usr/lib/", 9) == 0 ? line+9 : NULL;
		if (name == NULL || name[0] == 0 || strlen(name) >= ELF_CACHE_NAME_MAX ||
		    strspn(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-") != strlen(name) ||
		    strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
			errx(1, "invalid cache selection path: %s", line);
		for (unsigned i = 0; i < selection_count; i++)
			if (strcmp(selection[i], line) == 0) errx(1, "duplicate selection: %s", line);
		if (selection_count == ELF_CACHE_MAX_ENTRIES) errx(1, "too many selected libraries");
		selection[selection_count] = strdup(line);
		if (selection[selection_count++] == NULL) err(1, "selection allocation");
	}
	if (ferror(file)) err(1, "read selection");
	fclose(file);
	if (selection_count == 0) errx(1, "empty cache selection");
}
static int
selection_index(unsigned directory, const char *name)
{
	char path[PATH_MAX];
	if (!have_selection) return (-2);
	if (snprintf(path, sizeof(path), "%s/%s", directories[directory], name) >= (int)sizeof(path))
		return (-1);
	for (unsigned i = 0; i < selection_count; i++)
		if (strcmp(selection[i], path) == 0) return ((int)i);
	return (-1);
}
static void
usage(void)
{
	fprintf(stderr, "usage: elfcache build -r root -o cache [-k private.pem] [-l library-list]\n"
	    "       elfcache layout-verify -p public.pem -l layout cache\n"
	    "       elfcache layout [-k private.pem] [-p public.pem] -o layout cache\n"
	    "       elfcache inspect|list cache\n"
	    "       elfcache map [-j] cache\n"
	    "       elfcache info [-j] cache\n"
	    "       elfcache verify [-j] [-p public.pem] cache\n"
	    "       elfcache extract [-p public.pem] -o new-directory cache\n");
	exit(64);
}
static void
readall(int fd, void *data, size_t size, off_t off)
{
	unsigned char *p = data;
	while (size != 0) {
		ssize_t n = pread(fd, p, size, off);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) errx(1, "short read at %jd", (intmax_t)off);
		p += n; size -= (size_t)n; off += n;
	}
}
static void
writeall(int fd, const void *data, size_t size, off_t off)
{
	const unsigned char *p = data;
	while (size != 0) {
		ssize_t n = pwrite(fd, p, size, off);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) err(1, "write at %jd", (intmax_t)off);
		p += n; size -= (size_t)n; off += n;
	}
}
static void
hash(int fd, off_t start, uint64_t size, unsigned char digest[32])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned char buffer[16384];
	unsigned digest_size;
	if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		errx(1, "SHA256 init failed");
	while (size != 0) {
		size_t n = size < sizeof(buffer) ? (size_t)size : sizeof(buffer);
		readall(fd, buffer, n, start);
		if (EVP_DigestUpdate(ctx, buffer, n) != 1)
			errx(1, "SHA256 failed");
		size -= n; start += (off_t)n;
	}
	if (EVP_DigestFinal_ex(ctx, digest, &digest_size) != 1 || digest_size != 32)
		errx(1, "SHA256 final failed");
	EVP_MD_CTX_free(ctx);
}
static int
compare(const void *va, const void *vb)
{
	const struct input *a = va, *b = vb;
	uint32_t ad = le32toh(a->entry.directory), bd = le32toh(b->entry.directory);
	return (ad != bd ? (ad < bd ? -1 : 1) : strcmp(a->entry.name, b->entry.name));
}
/* Retain source descriptors until the copy and its digest have been checked.
 * Inputs must come from a quiescent staged generation, not a live upgrade. */
static void
scan(const char *root, unsigned index)
{
	char path[PATH_MAX], resolved[PATH_MAX], resolved_root[PATH_MAX];
	DIR *dir;
	struct dirent *de;
	struct stat st;
	unsigned char ident[20];
	int fd;
	if (realpath(root, resolved_root) == NULL)
		err(1, "%s", root);
	if (snprintf(path, sizeof(path), "%s%s", root, directories[index]) >= (int)sizeof(path))
		errx(1, "root path too long");
	dir = opendir(path);
	if (dir == NULL) err(1, "%s", path);
	while ((de = readdir(dir)) != NULL) {
		int selected = selection_index(index, de->d_name);
		if (selected == -1) continue;
		const char *suffix = strstr(de->d_name, ".so");
		if (suffix == NULL || (suffix[3] != 0 && suffix[3] != '.')) continue;
		if (strlen(de->d_name) >= ELF_CACHE_NAME_MAX)
			errx(1, "library name too long: %s", de->d_name);
		if (snprintf(path, sizeof(path), "%s%s/%s", root, directories[index], de->d_name) >= (int)sizeof(path))
			errx(1, "library path too long");
		if (realpath(path, resolved) == NULL)
			err(1, "%s", path);
		size_t rootlen = strlen(resolved_root);
		if (strcmp(resolved_root, "/") != 0 &&
		    (strncmp(resolved, resolved_root, rootlen) != 0 || resolved[rootlen] != '/'))
			errx(1, "library escapes staged root: %s", path);
		fd = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0 || fstat(fd, &st) < 0) err(1, "%s", path);
		if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
		    (uint64_t)st.st_size > CAPIMAGE_FILE_MAX) errx(1, "invalid library: %s", path);
		if (st.st_size < SELFMAG) { close(fd); continue; }
		readall(fd, ident, SELFMAG, 0);
		if (memcmp(ident, ELFMAG, SELFMAG) != 0) {
			/* Linker scripts named lib*.so are not runtime ELF libraries. */
			close(fd); continue;
		}
		if (st.st_size < (off_t)sizeof(Elf32_Ehdr))
			errx(1, "truncated ELF: %s", path);
		readall(fd, ident, sizeof(ident), 0);
		if ((ident[EI_CLASS] != ELFCLASS32 && ident[EI_CLASS] != ELFCLASS64) ||
		    (ident[EI_DATA] != ELFDATA2LSB && ident[EI_DATA] != ELFDATA2MSB) ||
		    (ident[EI_DATA] == ELFDATA2LSB ? le16dec(ident + 16) : be16dec(ident + 16)) != ET_DYN)
			errx(1, "not an ELF shared object: %s", path);
		if (count == ELF_CACHE_MAX_ENTRIES) errx(1, "too many libraries");
		/* Verify and cache identical bytes.  Keeping a private snapshot also
		 * prevents a source rewrite between verification and cache copying. */
		FILE *snapshot = tmpfile();
		if (snapshot == NULL) err(1, "library snapshot");
		unsigned char snapshot_buffer[16384];
		for (off_t position = 0; position < st.st_size;) {
			size_t length = st.st_size - position < (off_t)sizeof(snapshot_buffer) ?
			    (size_t)(st.st_size - position) : sizeof(snapshot_buffer);
			readall(fd, snapshot_buffer, length, position);
			writeall(fileno(snapshot), snapshot_buffer, length, position);
			position += length;
		}
		close(fd);
		fd = fcntl(fileno(snapshot), F_DUPFD_CLOEXEC, 0);
		if (fd < 0) err(1, "library snapshot descriptor");
		fclose(snapshot);
		struct capimage_policy policy;
		char signature_error[256];
		if (capimage_verify_integrity(fd, &policy, signature_error,
		    sizeof(signature_error)) == 0)
			capimage_policy_free(&policy);
		else if (errno != ENOENT && errno != ENOATTR)
			errx(1, "%s: %s", path, signature_error);
		inputs[count].fd = fd;
		inputs[count].entry.directory = htole32(index);
		off_t payload_size;
		char error[256];
		if (capimage_cache_size(fd, &payload_size, error, sizeof(error)) < 0)
			errx(1, "%s: %s", path, error);
		inputs[count].entry.size = htole64((uint64_t)payload_size);
		inputs[count].entry.source_size = htole64((uint64_t)st.st_size);
		strlcpy(inputs[count].entry.name, de->d_name, ELF_CACHE_NAME_MAX);
		hash(fd, 0, (uint64_t)payload_size, inputs[count].entry.sha256);
		count++;
		if (selected >= 0) selected_seen[selected] = true;
	}
	closedir(dir);
}
static void
build(const char *root, const char *output, const char *key)
{
	struct elf_cache_header header = {0};
	unsigned char buf[16384], digest[32];
	char *temporary, *sealpath = NULL, error[256];
	uint64_t offset, total_input = 0, unique = 0;
	int out, seal;
	scan(root, 0); scan(root, 1);
	for (unsigned i = 0; i < selection_count; i++)
		if (!selected_seen[i]) errx(1, "selected library missing or not ELF: %s", selection[i]);
	if (count == 0) errx(1, "no shared libraries");
	qsort(inputs, count, sizeof(inputs[0]), compare);
	if (asprintf(&temporary, "%s.tmp.XXXXXX", output) < 0) err(1, "asprintf");
	out = mkstemp(temporary);
	if (out < 0) err(1, "%s", temporary);
	/* The temporary pathname is removed on validation failures by operators;
	 * it is never discoverable as an active generation. */
	offset = (sizeof(header) + count * sizeof(struct elf_cache_entry) + ELF_CACHE_ALIGNMENT - 1) &
	    ~(uint64_t)(ELF_CACHE_ALIGNMENT - 1);
	for (unsigned i = 0; i < count; i++) {
		struct elf_cache_entry *e = &inputs[i].entry;
		uint64_t size = le64toh(e->size);
		bool duplicate = false;
		total_input += le64toh(e->source_size);
		for (unsigned j = 0; j < i; j++) {
			if (inputs[j].entry.size == e->size &&
			    memcmp(inputs[j].entry.sha256, e->sha256, 32) == 0) {
				e->offset = inputs[j].entry.offset;
				duplicate = true; break;
			}
		}
		if (!duplicate) {
			if (offset > ELF_CACHE_MAX_SIZE || size > ELF_CACHE_MAX_SIZE - offset)
				errx(1, "cache exceeds size bound");
			e->offset = htole64(offset);
			for (uint64_t pos = 0; pos < size;) {
				size_t n = size - pos < sizeof(buf) ? (size_t)(size - pos) : sizeof(buf);
				readall(inputs[i].fd, buf, n, (off_t)pos);
				writeall(out, buf, n, (off_t)(offset + pos));
				pos += n;
			}
			hash(out, (off_t)offset, size, digest);
			if (memcmp(digest, e->sha256, 32) != 0)
				errx(1, "source changed while building: %s", e->name);
			offset = (offset + size + ELF_CACHE_ALIGNMENT - 1) & ~(uint64_t)(ELF_CACHE_ALIGNMENT - 1);
			unique += size;
		}
		close(inputs[i].fd);
		writeall(out, e, sizeof(*e), (off_t)(sizeof(header) + i * sizeof(*e)));
	}
	memcpy(header.magic, "5BSDELF", 8);
	header.version = htole32(ELF_CACHE_VERSION);
	header.count = htole32(count);
	header.file_size = htole64(offset);
	header.alignment = htole32(ELF_CACHE_ALIGNMENT);
	header.entry_size = htole32(sizeof(struct elf_cache_entry));
	writeall(out, &header, sizeof(header), 0);
	if (ftruncate(out, (off_t)offset) < 0 || fchmod(out, 0444) < 0 || fsync(out) < 0)
		err(1, "finish cache");
	if (key != NULL) {
		if (asprintf(&sealpath, "%s.sig", temporary) < 0) err(1, "asprintf");
		seal = open(sealpath, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (seal < 0) err(1, "%s", sealpath);
		if (capimage_seal(out, seal, ELF_CACHE_DOMAIN, key, error, sizeof(error)) < 0)
			errx(1, "%s", error);
		if (fchmod(seal, 0444) < 0 || fsync(seal) < 0 || close(seal) < 0)
			err(1, "finish signature");
	}
	if (link(temporary, output) < 0) err(1, "publish %s", output);
	if (sealpath != NULL) {
		char *dest;
		if (asprintf(&dest, "%s.sig", output) < 0) err(1, "asprintf");
		if (link(sealpath, dest) < 0) {
			unlink(output); err(1, "publish %s", dest);
		}
		unlink(sealpath); free(sealpath); free(dest);
	}
	unlink(temporary); free(temporary); close(out);
	printf("entries=%u input_bytes=%ju unique_bytes=%ju cache_bytes=%ju\n", count,
	    (uintmax_t)total_input, (uintmax_t)unique, (uintmax_t)offset);
}
/* JSON paths use byte-preserving escapes: each non-ASCII byte is represented
 * as U+00xx, so consumers can recover the original filesystem bytes. */
static void
json_bytes(const char *value)
{
	putchar('"');
	for (const unsigned char *p = (const unsigned char *)value; *p != 0; p++) {
		if (*p == '"' || *p == '\\') printf("\\%c", *p);
		else if (*p < 0x20 || *p >= 0x7f) printf("\\u%04x", *p);
		else putchar(*p);
	}
	putchar('"');
}
static void
json_images(const struct elf_cache_header *header,
    const struct elf_cache_entry *entries, uint32_t image_count)
{
	printf("{\"schema\":\"org.5bsd.elfcache.images.v1\","
	    "\"format_version\":%u,\"authenticated\":false,"
	    "\"payload_digests_verified\":false,\"path_encoding\":\"byte-values\",\"images\":[",
	    le32toh(header->version));
	for (uint32_t i = 0; i < image_count; i++) {
		const struct elf_cache_entry *e = &entries[i];
		char path[ELF_CACHE_NAME_MAX + 16];
		uint32_t canonical = i;
		for (uint32_t j = 0; j < i; j++) {
			if (e->offset == entries[j].offset && e->size == entries[j].size) {
				canonical = j;
				break;
			}
		}
		snprintf(path, sizeof(path), "%s/%s", directories[le32toh(e->directory)], e->name);
		printf("%s{\"index\":%u,\"path\":", i == 0 ? "" : ",", i);
		json_bytes(path);
		printf(",\"cache_offset\":%ju,\"payload_bytes\":%ju,"
		    "\"source_bytes\":%ju,\"canonical_index\":%u,\"payload_sha256\":\"",
		    (uintmax_t)le64toh(e->offset), (uintmax_t)le64toh(e->size),
		    (uintmax_t)le64toh(e->source_size), canonical);
		for (size_t j = 0; j < sizeof(e->sha256); j++) printf("%02x", e->sha256[j]);
		printf("\"}");
	}
	printf("]}\n");
}
static void
inspect(const char *path, bool verify, const char *key, const char *destination, bool information, bool json, bool images)
{
	struct elf_cache_header h;
	struct elf_cache_entry e, previous = {0};
	struct stat st;
	unsigned char digest[32];
	char *sealpath, error[256];
	uint32_t n, unique_count = 0;
	uint64_t input_bytes = 0, unique_bytes = 0;
	struct elf_cache_entry *entries;
	FILE *snapshot = NULL;
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) err(1, "%s", path);
	/* Authenticate and extract the same private snapshot, even if an offline
	 * input pathname is concurrently replaced or its inode is rewritten. */
	if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(h) ||
	    st.st_size > (off_t)ELF_CACHE_MAX_SIZE)
		errx(1, "invalid cache file");
	if (verify) {
		unsigned char buffer[16384];
		snapshot = tmpfile();
		if (snapshot == NULL) err(1, "cache snapshot");
		for (off_t pos = 0; pos < st.st_size;) {
			size_t len = st.st_size - pos < (off_t)sizeof(buffer) ?
			    (size_t)(st.st_size - pos) : sizeof(buffer);
			readall(fd, buffer, len, pos);
			writeall(fileno(snapshot), buffer, len, pos);
			pos += len;
		}
		close(fd);
		fd = fileno(snapshot);
	}
	readall(fd, &h, sizeof(h), 0);
	n = le32toh(h.count);
	if (memcmp(h.magic, "5BSDELF", 8) != 0 || le32toh(h.version) != ELF_CACHE_VERSION ||
	    n == 0 || n > ELF_CACHE_MAX_ENTRIES || le64toh(h.file_size) != (uint64_t)st.st_size ||
	    st.st_size > (off_t)ELF_CACHE_MAX_SIZE || le32toh(h.alignment) != ELF_CACHE_ALIGNMENT ||
	    le32toh(h.entry_size) != sizeof(e) ||
	    memcmp(h.reserved, (unsigned char[32]){0}, 32) != 0)
		errx(1, "invalid cache header");
	if (verify) {
		if (asprintf(&sealpath, "%s.sig", path) < 0) err(1, "asprintf");
		int seal = open(sealpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (seal < 0) err(1, "%s", sealpath);
		if (capimage_check_seal(fd, seal, ELF_CACHE_DOMAIN, key, error, sizeof(error)) < 0)
			errx(1, "%s", error);
		close(seal); free(sealpath);
	}
	entries = calloc(n, sizeof(*entries));
	if (entries == NULL) err(1, "cache entries");
	for (uint32_t i = 0; i < n; i++) {
		uint64_t offset, size;
		uint32_t dir;
		readall(fd, &e, sizeof(e), (off_t)(sizeof(h) + i * sizeof(e)));
		offset = le64toh(e.offset); size = le64toh(e.size); dir = le32toh(e.directory);
		if (dir > 1 || e.reserved != 0 || e.name[0] == 0 ||
		    memchr(e.name, 0, sizeof(e.name)) == NULL || strchr(e.name, '/') != NULL ||
		    strcmp(e.name, ".") == 0 || strcmp(e.name, "..") == 0 ||
		    offset % ELF_CACHE_ALIGNMENT != 0 || offset < sizeof(h) + n * sizeof(e) ||
		    size < sizeof(Elf32_Ehdr) || le64toh(e.source_size) < size ||
		    le64toh(e.source_size) > CAPIMAGE_FILE_MAX || offset > (uint64_t)st.st_size ||
		    size > (uint64_t)st.st_size - offset ||
		    (i > 0 && (dir < le32toh(previous.directory) ||
		    (dir == le32toh(previous.directory) && strcmp(e.name, previous.name) <= 0))))
			errx(1, "invalid cache entry %u", i);
		if (verify) {
			hash(fd, (off_t)offset, size, digest);
			if (memcmp(digest, e.sha256, 32) != 0)
				errx(1, "library digest mismatch: %s", e.name);
		}
		bool alias = false;
		for (uint32_t j = 0; j < i; j++) {
			uint64_t other = le64toh(entries[j].offset);
			uint64_t other_size = le64toh(entries[j].size);
			if (offset < other + other_size && other < offset + size) {
				if (offset != other || size != other_size ||
				    memcmp(e.sha256, entries[j].sha256, 32) != 0)
					errx(1, "inconsistent overlapping cache entries");
				alias = true;
			}
		}
		input_bytes += le64toh(e.source_size);
		if (!alias) { unique_bytes += size; unique_count++; }
		if (!information && !json)
		    printf("%s/%s offset=%ju bytes=%ju\n", directories[dir], e.name,
		    (uintmax_t)offset, (uintmax_t)size);
		entries[i] = e;
		previous = e;
	}
	if (json && images)
		json_images(&h, entries, n);
	else if (json)
		printf("{\"schema\":\"org.5bsd.elfcache.summary.v1\",\"format_version\":%u,"
		    "\"authenticated\":%s,\"payload_digests_verified\":%s,"
		    "\"verification_key_source\":\"%s\",\"entries\":%u,\"unique_images\":%u,"
		    "\"input_bytes\":%ju,\"unique_bytes\":%ju,\"cache_bytes\":%ju,"
		    "\"overhead_bytes\":%ju}\n",
		    le32toh(h.version), verify ? "true" : "false",
		    verify ? "true" : "false",
		    !verify ? "none" : key != NULL ? "explicit" : "system",
		    n, unique_count, (uintmax_t)input_bytes, (uintmax_t)unique_bytes,
		    (uintmax_t)st.st_size,
		    (uintmax_t)((uint64_t)st.st_size - unique_bytes));
	else if (information)
		printf("version=%u entries=%u unique_images=%u input_bytes=%ju "
		    "unique_bytes=%ju cache_bytes=%ju overhead_bytes=%ju\n",
		    le32toh(h.version), n, unique_count, (uintmax_t)input_bytes,
		    (uintmax_t)unique_bytes, (uintmax_t)st.st_size,
		    (uintmax_t)((uint64_t)st.st_size - unique_bytes));
	if (destination != NULL) {
		int rootfd, usrfd, dirs[2];
		unsigned char buffer[16384];
		/* Existing destinations, including symlinks, are never accepted. */
		if (mkdir(destination, 0700) < 0) err(1, "%s", destination);
		rootfd = open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (rootfd < 0 || mkdirat(rootfd, "lib", 0755) < 0 ||
		    mkdirat(rootfd, "usr", 0755) < 0) err(1, "extraction directories");
		usrfd = openat(rootfd, "usr", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (usrfd < 0 || mkdirat(usrfd, "lib", 0755) < 0) err(1, "usr/lib");
		dirs[0] = openat(rootfd, "lib", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		dirs[1] = openat(usrfd, "lib", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (dirs[0] < 0 || dirs[1] < 0) err(1, "library directories");
		for (uint32_t i = 0; i < n; i++) {
			e = entries[i];
			int out = openat(dirs[le32toh(e.directory)], e.name,
			    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
			if (out < 0) err(1, "extract %s", e.name);
			uint64_t size = le64toh(e.size), offset = le64toh(e.offset);
			for (uint64_t pos = 0; pos < size;) {
				size_t len = size - pos < sizeof(buffer) ?
				    (size_t)(size - pos) : sizeof(buffer);
				readall(fd, buffer, len, (off_t)(offset + pos));
				writeall(out, buffer, len, (off_t)pos);
				pos += len;
			}
			hash(out, 0, size, digest);
			if (memcmp(digest, e.sha256, sizeof(digest)) != 0)
				errx(1, "extracted digest mismatch: %s", e.name);
			if (fchmod(out, 0444) < 0 || fsync(out) < 0 || close(out) < 0)
				err(1, "finish extracted library");
		}
		close(dirs[0]); close(dirs[1]); close(usrfd); close(rootfd);
	}
	free(entries);
	if (snapshot != NULL) fclose(snapshot); else close(fd);
}

int
main(int argc, char **argv)
{
	const char *command, *root = NULL, *output = NULL, *key = NULL, *public = NULL, *list = NULL;
	int ch;
	bool json = false;
	if (argc < 2) usage();
	command = argv[1]; argc--; argv++;
	while ((ch = getopt(argc, argv, "jr:o:k:p:l:")) != -1) {
		switch (ch) {
		case 'j': json = true; break;
		case 'l': list = optarg; break;
		case 'r': root = optarg; break;
		case 'o': output = optarg; break;
		case 'k': key = optarg; break;
		case 'p': public = optarg; break;
		default: usage();
		}
	}
	argc -= optind; argv += optind;
	if (strcmp(command, "build") == 0) {
		if (argc != 0 || root == NULL || output == NULL || public != NULL || json) usage();
		if (list != NULL) read_selection(list);
		build(root, output, key);
	} else if (strcmp(command, "layout-verify") == 0) {
		if (argc != 1 || root != NULL || output != NULL || key != NULL ||
		    public == NULL || list == NULL || json) usage();
		elfcache_layout_verify(argv[0], list, public);
	} else if (strcmp(command, "layout") == 0) {
		if (argc != 1 || root != NULL || output == NULL || list != NULL || json) usage();
		elfcache_layout_build(argv[0], output, key, public);
	} else if (strcmp(command, "inspect") == 0 || strcmp(command, "list") == 0 || strcmp(command, "map") == 0 ||
	    strcmp(command, "info") == 0 || strcmp(command, "verify") == 0) {
		bool verify = strcmp(command, "verify") == 0;
		if (argc != 1 || root != NULL || output != NULL || key != NULL ||
		    list != NULL || (!verify && public != NULL) ||
		    (json && !verify && strcmp(command, "info") != 0 && strcmp(command, "map") != 0)) usage();
		inspect(argv[0], verify, public, NULL, strcmp(command, "info") == 0, json, strcmp(command, "map") == 0);
	} else if (strcmp(command, "extract") == 0) {
		if (argc != 1 || output == NULL || root != NULL || key != NULL ||
		    list != NULL || json) usage();
		inspect(argv[0], true, public, output, false, false, false);
	} else usage();
	return (0);
}
