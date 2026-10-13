/* SPDX-License-Identifier: BSD-2-Clause */
/* ELF cache preserves ordinary ELF lookup and source identity.
 * The issuer authenticates and pins the cache. Signed source identities are
 * bound to payloads by its index, with a kernel-verified source handle held
 * through adoption. Unsigned sources require exact byte comparison.
 * Relocations and writable state remain process-private. */
#include <sys/types.h>
#include "sys/cap_authority.h"
#include "sys/capimage.h"
#include <sys/endian.h>
#include "sys/elf_cache.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "security/mac_veriexec/mac_veriexec.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "debug.h"
#include "rtld.h"
#include "elf_cache_profile.h"
#include "rtld_libc.h"
#include "sys/capimage_elf.h"

static int
rtld_capimage_read(void *context, uint64_t offset, void *data, size_t size)
{
	int fd = *(int *)context;
	unsigned char *cursor = data;

	while (size != 0) {
		ssize_t n = pread(fd, cursor, size, offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		cursor += n;
		offset += n;
		size -= n;
	}
	return (0);
}

/* A caller-supplied descriptor does not pass through O_VERIFY. Recognize
 * either locator, rejecting a damaged one rather than treating it as unsigned. */
int
rtld_verify_object_signature(const char *path, int fd, const struct stat *st,
    bool required)
{
	struct capimage_elf_info image;
	int probe = capimage_elf_probe(rtld_capimage_read, &fd, st->st_size, &image);

	if (probe < 0 || (required && probe == 0)) {
		_rtld_error("Invalid library signature container: %s",
		    path != NULL ? path : "<descriptor>");
		return (-1);
	}
	if (probe == 0)
		return (0);
	if (syscall(SYS_mac_syscall, MAC_VERIEXEC_NAME,
	    MAC_VERIEXEC_CHECK_CAPIMAGE_FD_SYSCALL, (void *)(intptr_t)fd) < 0) {
		_rtld_error("Library signature verification failed: %s",
		    path != NULL ? path : "<descriptor>");
		return (-1);
	}
	return (0);
}

/* No pinning support is never permission to consume an unverified source. */
static bool
rtld_cache_pin_fallback(const char *path, int source, const struct stat *st,
    int result, int error)
{
	return (result < 0 && (error == EOPNOTSUPP || error == ENOSYS ||
	    error == ECAPMODE) &&
	    rtld_verify_object_signature(path, source, st, true) == 0);
}

struct cache_view {
	dev_t device;
	ino_t inode;
	void *index;
	size_t index_size;
	uint64_t size;
	uint32_t count;
};
static struct cache_view views[2];
static bool unavailable;

static struct cache_view *
cache_view(int dirfd, int *cachefd)
{
	struct cap_cache_result result;
	struct elf_cache_header h;
	struct elf_cache_entry previous;
	struct stat st;
	struct cache_view *view;
	const struct elf_cache_entry *entries;
	int fd;
	if (unavailable)
		return (NULL);
	fd = syscall(SYS_cap_process, CAP_CACHE_GET, dirfd, 0, &result);
	if (fd < 0) {
		if (errno == ENOSYS || errno == EINVAL)
			unavailable = true;
		return (NULL);
	}
	if (result.directory > 1 || result.reserved != 0)
		goto invalid;
	view = &views[result.directory];
	if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(h) ||
	    (uint64_t)st.st_size > ELF_CACHE_MAX_SIZE)
		goto invalid;
	/* Applications may close arbitrary descriptor numbers, including with
	 * closefrom(). Keep only the pinned index mapping between loader calls;
	 * every load owns a freshly acquired descriptor. The mapping also keeps
	 * the old inode alive, preventing identity reuse across generations. */
	if (view->index != NULL && view->device == st.st_dev &&
	    view->inode == st.st_ino && view->size == (uint64_t)st.st_size) {
		*cachefd = fd;
		return (view);
	}
	if (view->index != NULL) {
		munmap(view->index, view->index_size);
		view->index = NULL;
	}
	if (pread(fd, &h, sizeof(h), 0) != sizeof(h) ||
	    memcmp(h.magic, "5BSDELF", 8) != 0 || le32toh(h.version) != ELF_CACHE_VERSION ||
	    le32toh(h.count) == 0 || le32toh(h.count) > ELF_CACHE_MAX_ENTRIES ||
	    le64toh(h.file_size) != (uint64_t)st.st_size ||
	    le32toh(h.alignment) != ELF_CACHE_ALIGNMENT ||
	    ELF_CACHE_ALIGNMENT % page_size != 0 ||
	    le32toh(h.entry_size) != sizeof(struct elf_cache_entry) ||
	    memcmp(h.reserved, (unsigned char[32]){0}, sizeof(h.reserved)) != 0)
		goto invalid;
	view->count = le32toh(h.count);
	view->index_size = sizeof(h) + view->count * sizeof(struct elf_cache_entry);
	if (view->index_size > (uint64_t)st.st_size)
		goto invalid;
	view->index = mmap(NULL, view->index_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (view->index == MAP_FAILED)
		goto invalid;
	entries = (const void *)((const char *)view->index + sizeof(h));
	memset(&previous, 0, sizeof(previous));
	for (unsigned i = 0; i < view->count; i++) {
		const struct elf_cache_entry *e = &entries[i];
		uint64_t off = le64toh(e->offset), size = le64toh(e->size);
		uint32_t dir = le32toh(e->directory);
		if (dir > 1 || e->reserved != 0 || e->name[0] == 0 ||
		    memchr(e->name, 0, sizeof(e->name)) == NULL || strchr(e->name, '/') != NULL ||
		    off < view->index_size || off % ELF_CACHE_ALIGNMENT != 0 || size < sizeof(Elf_Ehdr) || le64toh(e->source_size) < size ||
		    off > (uint64_t)st.st_size || size > (uint64_t)st.st_size - off ||
		    (i > 0 && (dir < le32toh(previous.directory) ||
		    (dir == le32toh(previous.directory) && strcmp(e->name, previous.name) <= 0)))) {
			munmap(view->index, view->index_size);
			goto invalid;
		}
		previous = *e;
	}
	view->device = st.st_dev;
	view->inode = st.st_ino;
	*cachefd = fd;
	view->size = (uint64_t)st.st_size;
	return (view);
invalid:
	close(fd);
	_rtld_error("Invalid issuer-selected ELF library cache");
	rtld_die();
}

int
rtld_cache_substitute(const char *path, int source, const struct stat *st,
    int *cachefd, off_t *offset, off_t *payload_size, unsigned *reason,
    int *source_handle)
{
	struct cache_view *view;
	const struct elf_cache_entry *entries, *entry = NULL;
	const char *name;
	char number[24];
	uint32_t directory;
	int dirfd, fd = -1, handle = -1;
	bool close_directory = false;
	void *cached;
	unsigned char buffer[16384];
	*source_handle = -1;
	*reason = ELF_CACHE_OUTSIDE;
	if (path == NULL || st->st_size <= 0 || (uint64_t)st->st_size > SIZE_MAX)
		return (false);
	if (strncmp(path, "/lib/", 5) == 0) {
		directory = 0; name = path + 5;
		dirfd = open("/lib", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		close_directory = true;
	} else if (strncmp(path, "/usr/lib/", 9) == 0) {
		directory = 1; name = path + 9;
		dirfd = open("/usr/lib", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		close_directory = true;
	} else if (path[0] == '#' && (name = strchr(path, '/')) != NULL) {
		size_t length = (size_t)(name - path - 1);
		if (length == 0 || length >= sizeof(number))
			return (false);
		memcpy(number, path + 1, length);
		number[length] = 0;
		dirfd = 0;
		for (size_t i = 0; i < length; i++) {
			if (number[i] < '0' || number[i] > '9' ||
			    dirfd > (INT_MAX - (number[i] - '0')) / 10)
				return (false);
			dirfd = dirfd * 10 + number[i] - '0';
		}
		name++;
		directory = UINT32_MAX;
	} else
		return (false);
	if (dirfd < 0)
		return (false);
	*reason = ELF_CACHE_UNAVAILABLE;
	view = cache_view(dirfd, &fd);
	if (close_directory)
		close(dirfd);
	if (view == NULL || strchr(name, '/') != NULL)
		goto miss;
	/* A descriptor lookup is resolved by vnode identity in the kernel. */
	if (directory == UINT32_MAX)
		directory = (uint32_t)(view - views);
	entries = (const void *)((const char *)view->index + sizeof(struct elf_cache_header));
	for (unsigned low = 0, high = view->count; low < high;) {
		unsigned mid = low + (high - low) / 2;
		const struct elf_cache_entry *e = &entries[mid];
		uint32_t d = le32toh(e->directory);
		int order = d != directory ? (d < directory ? -1 : 1) : strcmp(e->name, name);
		if (order < 0) low = mid + 1;
		else if (order > 0) high = mid;
		else { entry = e; break; }
	}
	*reason = ELF_CACHE_NOT_LISTED;
	if (entry == NULL) goto miss;
	*reason = ELF_CACHE_SIZE_CHANGED;
	if (le64toh(entry->source_size) != (uint64_t)st->st_size) goto miss;
	off_t size = (off_t)le64toh(entry->size);
	/* A signed cache binds the exact source digest to its extracted payload.
	 * There is no runtime ELF rewriting or exception to byte comparisons. */
	bool signed_source = le64toh(entry->source_size) > le64toh(entry->size);
	if (signed_source) {
		struct capimage_prepare prepare = {
		    .version = CAPIMAGE_HANDLE_VERSION,
		    .struct_size = sizeof(prepare), .source_fd = source,
		    .flags = CAPIMAGE_PREPARE_REQUIRED | CAPIMAGE_PREPARE_RAW_DIGEST |
		        CAPIMAGE_PREPARE_VVERIFY
		};
		int result = syscall(SYS_mac_syscall, CAPIMAGE_MAC_POLICY,
		    CAPIMAGE_PREPARE_SYSCALL, &prepare);
		if (result <= 0) {
			/* Unsupported pinning, including the capability-mode syscall
			 * gate, is a cache miss only after required integrity verification.
			 * Never broaden authority or hide an authentication failure. */
			if (rtld_cache_pin_fallback(path, source, st, result, errno))
				goto miss;
			goto bad_signature;
		}
		handle = result - 1;
		struct capimage_info_request request = {
		    .version = CAPIMAGE_HANDLE_VERSION,
		    .struct_size = sizeof(request), .handle_fd = handle
		};
		if (fcntl(handle, F_SETFD, FD_CLOEXEC) < 0 ||
		    syscall(SYS_mac_syscall, CAPIMAGE_MAC_POLICY,
		    CAPIMAGE_HANDLE_INFO_SYSCALL, &request) < 0)
			goto bad_signature;
		const struct capimage_info *info = &request.info;
		if (info->version != CAPIMAGE_HANDLE_VERSION ||
		    info->struct_size != sizeof(*info) ||
		    info->available != CAPIMAGE_INFO_RAW_DIGEST ||
		    info->container_version != CAPIMAGE_VERSION ||
		    info->file_size != (uint64_t)st->st_size ||
		    info->policy_size == 0 || info->policy_size > CAPIMAGE_POLICY_MAX ||
		    info->policy_offset > info->file_size ||
		    info->policy_size > info->file_size - info->policy_offset)
			goto bad_signature;
		for (size_t i = 0; i < sizeof(info->reserved)/sizeof(info->reserved[0]); i++)
			if (info->reserved[i] != 0) goto bad_signature;
		if (memcmp(info->raw_digest, entry->source_sha256, 32) != 0) {
			*reason = ELF_CACHE_BYTES_CHANGED;
			goto miss;
		}
	}
	*reason = ELF_CACHE_MAP_FAILED;
	cached = mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE,
	    fd, (off_t)le64toh(entry->offset));
	if (cached == MAP_FAILED)
		goto miss;
	*reason = ELF_CACHE_INELIGIBLE;
	if (!rtld_cache_eligible(cached, (size_t)size, page_size)) {
		munmap(cached, (size_t)size);
		goto miss;
	}
	/* Read mutable source files through pread: truncation must cause a
	 * cache miss rather than SIGBUS in the loader. Cached bytes are pinned. */
	bool same = true;
	for (off_t pos = 0; !signed_source && pos < size;) {
		size_t length = (uint64_t)(size - pos) < sizeof(buffer) ?
		    (size_t)(size - pos) : sizeof(buffer);
		ssize_t n = pread(source, buffer, length, pos);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0 || memcmp(buffer, (const char *)cached + pos, (size_t)n) != 0) {
			same = false;
			break;
		}
		pos += n;
	}
	munmap(cached, (size_t)size);
	*reason = ELF_CACHE_BYTES_CHANGED;
	if (!same) {
		dbg("ELF cache stale entry: %s", path);
		goto miss;
	}
	*reason = ELF_CACHE_HIT;
	*source_handle = handle;
	*payload_size = size;
	*cachefd = fd;
	*offset = (off_t)le64toh(entry->offset);
	dbg("ELF cache hit: %s offset %ju", path, (uintmax_t)*offset);
	return (true);
bad_signature:
	*reason = ELF_CACHE_SIGNATURE_FAILED;
	if (handle >= 0) close(handle);
	if (fd >= 0) close(fd);
	_rtld_error("Cache source signature verification failed: %s", path);
	return (-1);
miss:
	if (handle >= 0) close(handle);
	if (fd >= 0)
		close(fd);
	return (false);
}

/* Missing-file lookup only. The kernel verifies directory vnode identity,
 * prison and issuer lifetime; a pathname or environment value cannot select
 * cache authority. Existing files and verification failures take precedence. */
int
rtld_cache_open_at(int directory_fd, const char *name,
    struct rtld_cache_image *image)
{
    struct cache_view *view;
    const struct elf_cache_entry *entries, *entry = NULL;
    int fd = -1;
    void *bytes;
    if (name == NULL || name[0] == 0 || strchr(name, '/') != NULL)
        return (-1);
    view = cache_view(directory_fd, &fd);
    if (view == NULL)
        return (-1);
    entries = (const void *)((const char *)view->index +
        sizeof(struct elf_cache_header));
    unsigned directory = (unsigned)(view - views);
    /* Publication validates ordering; avoid scanning thousands of images
     * for every dependency opened without an individual library file. */
    unsigned low = 0, high = view->count;
    while (low < high) {
        unsigned middle = low + (high - low) / 2;
        unsigned candidate = le32toh(entries[middle].directory);
        int order = candidate < directory ? -1 : candidate > directory ? 1 :
            strcmp(entries[middle].name, name);
        if (order < 0)
            low = middle + 1;
        else if (order > 0)
            high = middle;
        else {
            entry = &entries[middle];
            break;
        }
    }
    if (entry == NULL)
        goto miss;
    off_t offset = (off_t)le64toh(entry->offset);
    size_t size = (size_t)le64toh(entry->size);
    bytes = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
    if (bytes == MAP_FAILED)
        goto miss;
    bool eligible = rtld_cache_eligible(bytes, size, page_size);
    munmap(bytes, size);
    if (!eligible)
        goto miss;
    image->selected = true;
    image->offset = offset;
    image->size = (off_t)size;
    return (fd);
miss:
    close(fd);
    return (-1);
}

int
rtld_cache_open_path(const char *path, struct rtld_cache_image *image)
{
    const char *slash;
    char directory[PATH_MAX];
    int dirfd, fd;
    if (path == NULL || (slash = strrchr(path, '/')) == NULL ||
        slash == path || (size_t)(slash - path) >= sizeof(directory))
        return (-1);
    memcpy(directory, path, (size_t)(slash - path));
    directory[slash - path] = 0;
    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return (-1);
    fd = rtld_cache_open_at(dirfd, slash + 1, image);
    close(dirfd);
    return (fd);
}
