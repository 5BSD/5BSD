/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "switchboard_lifecycle.h"
#include "switchboard_lifecycle_private.h"

#define SL_MAGIC UINT64_C(0x354253444c494645)
#define SL_VERSION 4
struct sl_header { uint64_t magic; uint32_t version; uint32_t count;
	uint32_t checksum; uint32_t reserved; };

/* Compact owner facts, sorted by label, generation, then ledger position. */
struct sl_query_entry {
	char label[SL_LABEL_MAX];
	struct sl_installation facts;
	uint32_t position;
	bool removing;
	bool retired;
};

/* One validated snapshot, owned by a single-threaded reader. */
struct sl_query_cache {
	int queue;
	int statefd;
	struct stat identity;
	bool retry;
	struct sl_query_entry *entries;
	size_t count;
};

static void
cache_clear(struct sl_query_cache *cache)
{
	int error = errno;

	free(cache->entries);
	cache->entries = NULL;
	cache->count = 0;
	if (cache->statefd >= 0)
		close(cache->statefd);
	cache->statefd = -1;
	errno = error;
}

struct sl_query_cache *
sl_query_cache_create(void)
{
	struct sl_query_cache *cache;

	cache = calloc(1, sizeof(*cache));
	if (cache == NULL)
		return (NULL);
	cache->statefd = -1;
	cache->queue = kqueuex(KQUEUE_CLOEXEC);
	if (cache->queue == -1) {
		free(cache);
		return (NULL);
	}
	return (cache);
}

void
sl_query_cache_destroy(struct sl_query_cache *cache)
{
	int error = errno;

	if (cache != NULL) {
		cache_clear(cache);
		close(cache->queue);
		free(cache);
	}
	errno = error;
}

static bool
same_snapshot(const struct stat *a, const struct stat *b)
{
	return (a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
	    a->st_gen == b->st_gen && a->st_size == b->st_size &&
	    a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
	    a->st_mode == b->st_mode && a->st_flags == b->st_flags &&
	    a->st_nlink == b->st_nlink &&
	    timespeccmp(&a->st_mtim, &b->st_mtim, ==) &&
	    timespeccmp(&a->st_ctim, &b->st_ctim, ==) &&
	    timespeccmp(&a->st_birthtim, &b->st_birthtim, ==));
}

/* Vnode events also catch in-place changes with unchanged/coarse timestamps. */
static int
cache_events(struct sl_query_cache *cache)
{
	struct kevent event;
	const struct timespec zero = { 0, 0 };
	int n;

	do {
		n = kevent(cache->queue, NULL, 0, &event, 1, &zero);
	} while (n == -1 && errno == EINTR);
	return (n);
}

static int
entry_compare(const void *va, const void *vb)
{
	const struct sl_query_entry *a = va, *b = vb;
	int order;

	order = strcmp(a->label, b->label);
	if (order == 0)
		order = memcmp(a->facts.generation, b->facts.generation,
		    SL_GENERATION_SIZE);
	if (order == 0)
		order = (a->position > b->position) - (a->position < b->position);
	return (order);
}

/* Lower bound also preserves the uncached query's first-owner semantics. */
static size_t
entry_find(struct sl_query_cache *cache, const char *label,
    const uint8_t *generation)
{
	size_t lo = 0, hi = cache->count, mid;
	int order;

	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		order = strcmp(cache->entries[mid].label, label);
		if (order == 0 && generation != NULL)
			order = memcmp(cache->entries[mid].facts.generation,
			    generation, SL_GENERATION_SIZE);
		if (order < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (lo);
}

static int
cache_build(struct sl_query_cache *cache, const struct sl_db *db)
{
	struct sl_query_entry *entry, *first;
	const struct sl_record *r;
	size_t owners = 0, n = 0, at;

	for (size_t i = 0; i < db->count; i++)
		owners += db->records[i].kind == SL_OWNER;
	cache->entries = calloc(owners == 0 ? 1 : owners,
	    sizeof(*cache->entries));
	if (cache->entries == NULL)
		return (-1);
	cache->count = owners;
	for (size_t i = 0; i < db->count; i++) {
		r = &db->records[i];
		if (r->kind != SL_OWNER)
			continue;
		entry = &cache->entries[n++];
		strlcpy(entry->label, r->label, sizeof(entry->label));
		memcpy(entry->facts.generation, r->generation, SL_GENERATION_SIZE);
		entry->position = i;
		entry->retired = r->phase == SL_PREPARED ||
		    r->phase == SL_RETIRED || r->phase == SL_COMPLETE;
		switch (r->phase) {
		case SL_ACTIVE: entry->facts.state = SL_INSTALLED; break;
		case SL_INSTALLING: entry->facts.state = SL_INSTALL_IN_PROGRESS; break;
		case SL_PREPARED: entry->facts.state = SL_REMOVE_IN_PROGRESS; break;
		default: entry->facts.state = SL_REMOVED; break;
		}
	}
	qsort(cache->entries, owners, sizeof(*cache->entries), entry_compare);
	for (size_t i = 0; i < db->count; i++) {
		r = &db->records[i];
		if (r->kind != SL_REFERENCE &&
		    !(r->kind == SL_OPERATION && r->phase == SL_REMOVE_PENDING))
			continue;
		at = entry_find(cache, r->label, r->generation);
		if (at == owners)
			continue;
		entry = &cache->entries[at];
		if (strcmp(entry->label, r->label) != 0 ||
		    memcmp(entry->facts.generation, r->generation,
		    SL_GENERATION_SIZE) != 0)
			continue;
		if (r->kind == SL_REFERENCE) {
			entry->facts.live_sources += r->phase == SL_REF_LIVE;
			entry->facts.staged_sources += r->phase == SL_REF_STAGED;
		} else
			entry->removing = true;
	}
	/* Duplicate owner rows are legal in older stores. Share generation
	 * counts without changing which owner supplies the phase. */
	first = NULL;
	for (size_t i = 0; i < owners; i++) {
		entry = &cache->entries[i];
		if (first == NULL || strcmp(first->label, entry->label) != 0 ||
		    memcmp(first->facts.generation, entry->facts.generation,
		    SL_GENERATION_SIZE) != 0)
			first = entry;
		entry->facts.live_sources = first->facts.live_sources;
		entry->facts.staged_sources = first->facts.staged_sources;
		if (first->removing)
			entry->facts.state = SL_REMOVE_IN_PROGRESS;
	}
	return (0);
}

static int
cache_query(struct sl_query_cache *cache, const char *label,
    const uint8_t *generation, struct sl_installation *out)
{
	size_t at, latest;

	if (!sl_label_valid(label) ||
	    (generation != NULL && !sl_generation_valid(generation)))
		return (errno = EINVAL, -1);
	at = entry_find(cache, label, generation);
	if (at == cache->count || strcmp(cache->entries[at].label, label) != 0)
		return (0);
	if (generation != NULL) {
		if (memcmp(cache->entries[at].facts.generation, generation,
		    SL_GENERATION_SIZE) != 0)
			return (0);
	} else {
		latest = at;
		for (size_t i = at + 1; i < cache->count &&
		    strcmp(cache->entries[i].label, label) == 0; i++)
			if (cache->entries[i].position > cache->entries[latest].position)
				latest = i;
		at = latest;
	}
	*out = cache->entries[at].facts;
	return (0);
}

/* Reflected CRC32C (Castagnoli), identical to the original bitwise format. */
static const uint32_t checksum_table[256] = {
	0x00000000U, 0xf26b8303U, 0xe13b70f7U, 0x1350f3f4U,
	0xc79a971fU, 0x35f1141cU, 0x26a1e7e8U, 0xd4ca64ebU,
	0x8ad958cfU, 0x78b2dbccU, 0x6be22838U, 0x9989ab3bU,
	0x4d43cfd0U, 0xbf284cd3U, 0xac78bf27U, 0x5e133c24U,
	0x105ec76fU, 0xe235446cU, 0xf165b798U, 0x030e349bU,
	0xd7c45070U, 0x25afd373U, 0x36ff2087U, 0xc494a384U,
	0x9a879fa0U, 0x68ec1ca3U, 0x7bbcef57U, 0x89d76c54U,
	0x5d1d08bfU, 0xaf768bbcU, 0xbc267848U, 0x4e4dfb4bU,
	0x20bd8edeU, 0xd2d60dddU, 0xc186fe29U, 0x33ed7d2aU,
	0xe72719c1U, 0x154c9ac2U, 0x061c6936U, 0xf477ea35U,
	0xaa64d611U, 0x580f5512U, 0x4b5fa6e6U, 0xb93425e5U,
	0x6dfe410eU, 0x9f95c20dU, 0x8cc531f9U, 0x7eaeb2faU,
	0x30e349b1U, 0xc288cab2U, 0xd1d83946U, 0x23b3ba45U,
	0xf779deaeU, 0x05125dadU, 0x1642ae59U, 0xe4292d5aU,
	0xba3a117eU, 0x4851927dU, 0x5b016189U, 0xa96ae28aU,
	0x7da08661U, 0x8fcb0562U, 0x9c9bf696U, 0x6ef07595U,
	0x417b1dbcU, 0xb3109ebfU, 0xa0406d4bU, 0x522bee48U,
	0x86e18aa3U, 0x748a09a0U, 0x67dafa54U, 0x95b17957U,
	0xcba24573U, 0x39c9c670U, 0x2a993584U, 0xd8f2b687U,
	0x0c38d26cU, 0xfe53516fU, 0xed03a29bU, 0x1f682198U,
	0x5125dad3U, 0xa34e59d0U, 0xb01eaa24U, 0x42752927U,
	0x96bf4dccU, 0x64d4cecfU, 0x77843d3bU, 0x85efbe38U,
	0xdbfc821cU, 0x2997011fU, 0x3ac7f2ebU, 0xc8ac71e8U,
	0x1c661503U, 0xee0d9600U, 0xfd5d65f4U, 0x0f36e6f7U,
	0x61c69362U, 0x93ad1061U, 0x80fde395U, 0x72966096U,
	0xa65c047dU, 0x5437877eU, 0x4767748aU, 0xb50cf789U,
	0xeb1fcbadU, 0x197448aeU, 0x0a24bb5aU, 0xf84f3859U,
	0x2c855cb2U, 0xdeeedfb1U, 0xcdbe2c45U, 0x3fd5af46U,
	0x7198540dU, 0x83f3d70eU, 0x90a324faU, 0x62c8a7f9U,
	0xb602c312U, 0x44694011U, 0x5739b3e5U, 0xa55230e6U,
	0xfb410cc2U, 0x092a8fc1U, 0x1a7a7c35U, 0xe811ff36U,
	0x3cdb9bddU, 0xceb018deU, 0xdde0eb2aU, 0x2f8b6829U,
	0x82f63b78U, 0x709db87bU, 0x63cd4b8fU, 0x91a6c88cU,
	0x456cac67U, 0xb7072f64U, 0xa457dc90U, 0x563c5f93U,
	0x082f63b7U, 0xfa44e0b4U, 0xe9141340U, 0x1b7f9043U,
	0xcfb5f4a8U, 0x3dde77abU, 0x2e8e845fU, 0xdce5075cU,
	0x92a8fc17U, 0x60c37f14U, 0x73938ce0U, 0x81f80fe3U,
	0x55326b08U, 0xa759e80bU, 0xb4091bffU, 0x466298fcU,
	0x1871a4d8U, 0xea1a27dbU, 0xf94ad42fU, 0x0b21572cU,
	0xdfeb33c7U, 0x2d80b0c4U, 0x3ed04330U, 0xccbbc033U,
	0xa24bb5a6U, 0x502036a5U, 0x4370c551U, 0xb11b4652U,
	0x65d122b9U, 0x97baa1baU, 0x84ea524eU, 0x7681d14dU,
	0x2892ed69U, 0xdaf96e6aU, 0xc9a99d9eU, 0x3bc21e9dU,
	0xef087a76U, 0x1d63f975U, 0x0e330a81U, 0xfc588982U,
	0xb21572c9U, 0x407ef1caU, 0x532e023eU, 0xa145813dU,
	0x758fe5d6U, 0x87e466d5U, 0x94b49521U, 0x66df1622U,
	0x38cc2a06U, 0xcaa7a905U, 0xd9f75af1U, 0x2b9cd9f2U,
	0xff56bd19U, 0x0d3d3e1aU, 0x1e6dcdeeU, 0xec064eedU,
	0xc38d26c4U, 0x31e6a5c7U, 0x22b65633U, 0xd0ddd530U,
	0x0417b1dbU, 0xf67c32d8U, 0xe52cc12cU, 0x1747422fU,
	0x49547e0bU, 0xbb3ffd08U, 0xa86f0efcU, 0x5a048dffU,
	0x8ecee914U, 0x7ca56a17U, 0x6ff599e3U, 0x9d9e1ae0U,
	0xd3d3e1abU, 0x21b862a8U, 0x32e8915cU, 0xc083125fU,
	0x144976b4U, 0xe622f5b7U, 0xf5720643U, 0x07198540U,
	0x590ab964U, 0xab613a67U, 0xb831c993U, 0x4a5a4a90U,
	0x9e902e7bU, 0x6cfbad78U, 0x7fab5e8cU, 0x8dc0dd8fU,
	0xe330a81aU, 0x115b2b19U, 0x020bd8edU, 0xf0605beeU,
	0x24aa3f05U, 0xd6c1bc06U, 0xc5914ff2U, 0x37faccf1U,
	0x69e9f0d5U, 0x9b8273d6U, 0x88d28022U, 0x7ab90321U,
	0xae7367caU, 0x5c18e4c9U, 0x4f48173dU, 0xbd23943eU,
	0xf36e6f75U, 0x0105ec76U, 0x12551f82U, 0xe03e9c81U,
	0x34f4f86aU, 0xc69f7b69U, 0xd5cf889dU, 0x27a40b9eU,
	0x79b737baU, 0x8bdcb4b9U, 0x988c474dU, 0x6ae7c44eU,
	0xbe2da0a5U, 0x4c4623a6U, 0x5f16d052U, 0xad7d5351U,
};

static uint32_t
checksum(const void *data, size_t length)
{
	const uint8_t *p = data;
	uint32_t value = UINT32_MAX;

	while (length-- != 0)
		value = checksum_table[(value ^ *p++) & 0xff] ^ (value >> 8);
	return (~value);
}

static int
initialize_marker(struct sl_db *db)
{
	struct stat st;
	uint64_t magic = SL_MAGIC;
	int fd, error;

	fd = openat(db->dirfd, "initialized", O_WRONLY | O_CREAT | O_EXCL |
	    O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd == -1)
		return (errno == EEXIST ? 0 : -1);
	if (fstat(db->dirfd, &st) == -1 ||
	    (geteuid() == 0 && fchown(fd, st.st_uid, st.st_gid) == -1) ||
	    write(fd, &magic, sizeof(magic)) != sizeof(magic) || fsync(fd) == -1) {
		error = errno != 0 ? errno : EIO;
		close(fd);
		return (errno = error, -1);
	}
	if (close(fd) == -1 || fsync(db->dirfd) == -1)
		return (-1);
	return (0);
}

bool
sl_label_valid(const char *s)
{
	size_t n;

	if (s == NULL || (n = strnlen(s, SL_LABEL_MAX)) == 0 ||
	    n == SL_LABEL_MAX || s[0] == '/' || strstr(s, "//") != NULL ||
	    strcmp(s, ".") == 0 || strcmp(s, "..") == 0 ||
	    strstr(s, "/../") != NULL || strncmp(s, "../", 3) == 0 ||
	    (n >= 3 && strcmp(s + n - 3, "/..") == 0))
		return (false);
	return (strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-") == n);
}

bool
sl_generation_valid(const uint8_t *g)
{
	uint8_t any = 0;

	for (size_t i = 0; i < SL_GENERATION_SIZE; i++)
		any |= g[i];
	return (any != 0);
}

void
sl_generation_format(const uint8_t *g, char out[33])
{
	static const char hex[] = "0123456789abcdef";

	for (size_t i = 0; i < SL_GENERATION_SIZE; i++) {
		out[2 * i] = hex[g[i] >> 4];
		out[2 * i + 1] = hex[g[i] & 15];
	}
	out[32] = '\0';
}

int
sl_generation_parse(const char *s, uint8_t *g)
{
	const char *p;
	static const char hex[] = "0123456789abcdef";

	if (s == NULL || strlen(s) != 32)
		return (errno = EINVAL, -1);
	memset(g, 0, SL_GENERATION_SIZE);
	for (size_t i = 0; i < 32; i++) {
		p = strchr(hex, s[i]);
		if (p == NULL)
			return (errno = EINVAL, -1);
		g[i / 2] = (uint8_t)((g[i / 2] << 4) | (p - hex));
	}
	return (sl_generation_valid(g) ? 0 : (errno = EINVAL, -1));
}

static int
io_full(int fd, void *buf, size_t len, bool writing)
{
	ssize_t n;
	char *p = buf;

	while (len != 0) {
		n = writing ? write(fd, p, len) : read(fd, p, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (n == 0 ? (errno = EIO, -1) : -1);
		p += n;
		len -= (size_t)n;
	}
	return (0);
}

static bool
trusted(const struct stat *st, bool directory)
{
	return ((directory ? S_ISDIR(st->st_mode) : S_ISREG(st->st_mode)) &&
	    (st->st_uid == 0 || st->st_uid == geteuid()) &&
	    (st->st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
	    (directory || st->st_nlink == 1));
}

void
sl_close(struct sl_db *db)
{
	int saved = errno;

	if (db->records != NULL) {
		if (db->readonly)
			munmap(db->records, (db->count == 0 ? 1 : db->count) *
			    sizeof(*db->records));
		else
			free(db->records);
	}
	if (db->lockfd >= 0)
		close(db->lockfd);
	if (db->dirfd >= 0)
		close(db->dirfd);
	memset(db, 0, sizeof(*db));
	db->dirfd = db->lockfd = -1;
	errno = saved;
}

static int
open_database(const char *path, struct sl_db *db, bool readonly,
    struct sl_query_cache *cache)
{
	struct sl_header h;
	struct stat st, after;
	struct kevent watch;
	int fd = -1;

	memset(db, 0, sizeof(*db));
	db->dirfd = db->lockfd = -1;
	db->readonly = readonly;
	if (cache != NULL)
		cache->retry = false;
	db->dirfd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (db->dirfd == -1 || fstat(db->dirfd, &st) == -1)
		goto fail;
	/* The package helper runs as root against the capability-owned store. */
	if (geteuid() == 0 && st.st_uid == 976)
		st.st_uid = 0;
	if (!trusted(&st, true)) {
		errno = EPERM;
		goto fail;
	}
	db->lockfd = openat(db->dirfd, "lock", (readonly ? O_RDONLY : O_RDWR | O_CREAT) | O_NOFOLLOW |
	    O_CLOEXEC, 0600);
	if (db->lockfd == -1 || fstat(db->lockfd, &st) == -1)
		goto fail;
	if (geteuid() == 0 && st.st_uid == 976)
		st.st_uid = 0;
	if (!trusted(&st, false)) {
		errno = EPERM;
		goto fail;
	}
	if (!readonly && geteuid() == 0 && (fstat(db->dirfd, &st) == -1 ||
	    fchown(db->lockfd, st.st_uid, st.st_gid) == -1))
		goto fail;
	if (flock(db->lockfd, readonly ? LOCK_SH | LOCK_NB : LOCK_EX) == -1)
		goto fail;
	fd = openat(db->dirfd, "state", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1) {
		if (!readonly && errno == ENOENT && fstatat(db->dirfd, "initialized", &st,
		    AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT)
			return (0);
		errno = EIO;
		goto fail;
	}
	if (fstat(fd, &st) == -1)
		goto fail;
	if (geteuid() == 0 && st.st_uid == 976)
		st.st_uid = 0;
	if (!trusted(&st, false) || io_full(fd, &h, sizeof(h), false) == -1 ||
	    h.magic != SL_MAGIC || (h.version != SL_VERSION && h.version != 3) || h.reserved != 0 ||
	    h.count > SL_MAX_RECORDS || st.st_size !=
	    (off_t)(sizeof(h) + h.count * sizeof(struct sl_record))) {
		errno = EINVAL;
		goto fail;
	}
	if (cache != NULL) {
		if (cache->statefd >= 0 && same_snapshot(&st, &cache->identity) &&
		    cache_events(cache) == 0) {

			db->has_state = true;
			close(fd);
			return (0);
		}
		cache_clear(cache);
		/* Watch before reading, so a concurrent in-place edit invalidates it. */
		EV_SET(&watch, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
		    NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK |
		    NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE, 0, NULL);
		if (kevent(cache->queue, &watch, 1, NULL, 0, NULL) == -1)
			goto fail;
	}
	db->count = h.count;
	if (readonly) {
		db->records = mmap(NULL, (h.count == 0 ? 1 : h.count) *
		    sizeof(*db->records), PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0);
		if (db->records == MAP_FAILED)
			db->records = NULL;
	} else
		db->records = calloc(h.count == 0 ? 1 : h.count, sizeof(*db->records));
	if (db->records == NULL || io_full(fd, db->records,
	    h.count * sizeof(*db->records), false) == -1)
		goto fail;
	if (h.checksum != checksum(db->records, h.count * sizeof(*db->records))) {
		errno = EILSEQ;
		goto fail;
	}
	db->has_state = true;
	db->count = h.count;
	for (size_t i = 0; i < db->count; i++) {
		struct sl_record *r = &db->records[i];
		if (memchr(r->provider, '\0', sizeof(r->provider)) == NULL ||
		    memchr(r->reference, '\0', sizeof(r->reference)) == NULL ||
		    memchr(r->source, '\0', sizeof(r->source)) == NULL ||
		    !sl_label_valid(r->label) || r->kind < SL_OWNER ||
		    r->kind > SL_TICKET ||
		    (r->kind == SL_OWNER && (r->phase < SL_ACTIVE ||
		    r->phase > SL_INSTALLING || !sl_label_valid(r->provider) ||
		    !sl_generation_valid(r->generation))) ||
		    ((r->kind == SL_DELIVERY || r->kind == SL_HOLDING) && (!sl_label_valid(r->provider) ||
		    r->phase > (r->kind == SL_DELIVERY ? 1U : 0U) ||
		    !sl_generation_valid(r->generation)))) {
			errno = EINVAL;
			goto fail;
		}
		uint8_t ticket[16];
		if ((r->kind == SL_POLICY && (strcmp(r->label, "authority.policy") != 0 || r->phase != 0)) ||
		    (r->kind == SL_TICKET && (strcmp(r->label, "authority.operation") != 0 ||
		    r->phase != 0 || sl_generation_parse(r->provider, ticket) == -1 ||
		    memcmp(ticket, r->generation, sizeof(ticket)) != 0))) {
			errno = EINVAL;
			goto fail;
		}
		if ((r->kind == SL_OPERATION &&
		    ((!sl_label_valid(r->provider) || strlen(r->provider) != 32) ||
		    !sl_label_valid(r->reference) || !sl_generation_valid(r->generation) ||
		    !((r->phase >= SL_INSTALL_PENDING && r->phase <= SL_INSTALL_CANCELLED) ||
		    (r->phase >= SL_REMOVE_PENDING && r->phase <= SL_REMOVE_CANCELLED)))) ||
		    (r->kind == SL_REFERENCE && (!sl_label_valid(r->reference) ||
		    !sl_generation_valid(r->generation) || r->phase > SL_REF_REMOVED))) {
			errno = EINVAL;
			goto fail;
		}
	}
	if (cache != NULL) {
		if (cache_build(cache, db) == -1)
			goto fail;
		if (fstat(fd, &after) == -1)
			goto fail;
		if (geteuid() == 0 && after.st_uid == 976)
			after.st_uid = 0;
		if (!same_snapshot(&st, &after) || cache_events(cache) != 0) {
			cache->retry = true;
			errno = EAGAIN;
			goto fail;
		}
		cache->identity = st;
		cache->statefd = fd;

	} else {
		close(fd);
	}
	return (0);
fail:
	if (fd >= 0)
		close(fd);
	if (cache != NULL)
		cache_clear(cache);
	sl_close(db);
	return (-1);
}

int
sl_commit(struct sl_db *db)
{
	struct sl_header h;
	struct stat st;
	uint8_t nonce[16];
	char tmp[33];
	int fd, error;

	if (db->readonly)
		return (errno = EROFS, -1);
	if (!db->dirty)
		return (db->has_state ? initialize_marker(db) : 0);
	if (sl_history_due(db) && sl_prune_history(db, SL_HISTORY_KEEP, NULL) == -1)
		return (-1);
	h = (struct sl_header){ SL_MAGIC, SL_VERSION, (uint32_t)db->count,
	    checksum(db->records, db->count * sizeof(*db->records)), 0 };
	arc4random_buf(nonce, sizeof(nonce));
	sl_generation_format(nonce, tmp);
	fd = openat(db->dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600);
	if (fd == -1)
		return (-1);
	if (fstat(db->dirfd, &st) == -1 ||
	    (geteuid() == 0 && fchown(fd, st.st_uid, st.st_gid) == -1) ||
	    io_full(fd, &h, sizeof(h), true) == -1 ||
	    io_full(fd, db->records, db->count * sizeof(*db->records), true) == -1 ||
	    fsync(fd) == -1) {
		error = errno;
		close(fd);
		unlinkat(db->dirfd, tmp, 0);
		return (errno = error, -1);
	}
	if (close(fd) == -1 || renameat(db->dirfd, tmp, db->dirfd, "state") == -1 ||
	    fsync(db->dirfd) == -1) {
		error = errno;
		unlinkat(db->dirfd, tmp, 0);
		return (errno = error, -1);
	}
	db->has_state = true;
	if (initialize_marker(db) == -1)
		return (-1);
	db->dirty = false;
	return (0);
}

struct sl_record *
sl_append(struct sl_db *db)
{
	struct sl_record *p;

	if (db->readonly)
		return (errno = EROFS, NULL);
	if (db->count >= SL_MAX_RECORDS) {
		errno = ENOSPC;
		return (NULL);
	}
	p = reallocarray(db->records, db->count + 1, sizeof(*p));
	if (p == NULL)
		return (NULL);
	db->records = p;
	memset(&p[db->count], 0, sizeof(*p));
	db->dirty = true;
	return (&p[db->count++]);
}

struct sl_record *
sl_owner(struct sl_db *db, const char *label)
{
	for (size_t i = db->count; i != 0; i--)
		if (db->records[i - 1].kind == SL_OWNER &&
		    strcmp(db->records[i - 1].label, label) == 0)
			return (&db->records[i - 1]);
	return (NULL);
}

struct sl_record *
sl_generation(struct sl_db *db, const char *label, const uint8_t *generation)
{
	for (size_t i = 0; i < db->count; i++)
		if (db->records[i].kind == SL_OWNER &&
		    strcmp(db->records[i].label, label) == 0 &&
		    memcmp(db->records[i].generation, generation, SL_GENERATION_SIZE) == 0)
			return (&db->records[i]);
	return (NULL);
}

bool
sl_blocked(struct sl_db *db, const char *label)
{
	/* An unfinished package removal needs explicit finish/cancel first. */
	for (size_t i = 0; i < db->count; i++)
		if (db->records[i].kind == SL_OWNER &&
		    strcmp(db->records[i].label, label) == 0 &&
		    (db->records[i].phase == SL_PREPARED ||
		    db->records[i].phase == SL_INSTALLING))
			return (true);
	return (false);
}

static int
activate(struct sl_db *db, const char *label, uint8_t *generation, bool legacy)
{
	struct sl_record *r;
	char hex[33];

	if (!sl_label_valid(label))
		return (errno = EINVAL, -1);
	if (sl_blocked(db, label))
		return (errno = EBUSY, -1);
	r = sl_owner(db, label);
	/* Migration cannot revive a previously removed installation. */
	if (legacy && r != NULL && r->phase != SL_ACTIVE)
		return (errno = ESTALE, -1);
	if (r == NULL || r->phase != SL_ACTIVE) {
		bool migrating = r == NULL && legacy;
		r = sl_append(db);
		if (r == NULL)
			return (-1);
		r->kind = SL_OWNER;
		strlcpy(r->label, label, sizeof(r->label));
		do {
			arc4random_buf(r->generation, sizeof(r->generation));
		} while (!sl_generation_valid(r->generation));
		r->phase = SL_ACTIVE;
		/* provider is the resource ownership key for an OWNER record. */
		if (migrating)
			strlcpy(r->provider, label, sizeof(r->provider));
		else {
			sl_generation_format(r->generation, hex);
			snprintf(r->provider, sizeof(r->provider), "install.%s", hex);
		}
		db->dirty = true;
	}
	memcpy(generation, r->generation, SL_GENERATION_SIZE);
	return (0);
}

int
sl_adopt(struct sl_db *db, const char *label, uint8_t *generation)
{
	return (activate(db, label, generation, true));
}

int
sl_install(struct sl_db *db, const char *label, uint8_t *generation)
{
	return (activate(db, label, generation, false));
}

int
sl_prepare(struct sl_db *db, const char *label, uint8_t *generation)
{
	struct sl_record *r;

	if (!sl_label_valid(label))
		return (errno = EINVAL, -1);
	r = sl_owner(db, label);
	if (r == NULL)
		return (errno = ESTALE, -1);
	if (r->phase == SL_ACTIVE) {
		r->phase = SL_PREPARED;
		db->dirty = true;
	}
	memcpy(generation, r->generation, SL_GENERATION_SIZE);
	return (0);
}

int
sl_retire(struct sl_db *db, const char *label, const uint8_t *generation)
{
	struct sl_record *r;

	if (!sl_label_valid(label) || generation == NULL || !sl_generation_valid(generation))
		return (errno = EINVAL, -1);
	r = sl_generation(db, label, generation);
	if (r == NULL)
		return (errno = ESTALE, -1);
	if (r->phase == SL_RETIRED || r->phase == SL_COMPLETE)
		return (0);
	if (r->phase != SL_PREPARED)
		return (errno = EBUSY, -1);
	/* Installation completion never schedules or waits for provider cleanup. */
	r->phase = SL_COMPLETE;
	db->dirty = true;
	return (0);
}

/* Transactions retain their exact generation even after a same-label reinstall. */
struct sl_record *
sl_operation(struct sl_db *db, const char *label, const char *operation)
{
	for (size_t i = 0; i < db->count; i++)
		if (db->records[i].kind == SL_OPERATION &&
		    strcmp(db->records[i].label, label) == 0 &&
		    strcmp(db->records[i].provider, operation) == 0)
			return (&db->records[i]);
	return (NULL);
}

static struct sl_record *
reference_record(struct sl_db *db, const char *label, const char *reference,
    const uint8_t *generation)
{
	for (size_t i = db->count; i != 0; i--) {
		struct sl_record *r = &db->records[i - 1];
		if (r->kind == SL_REFERENCE && strcmp(r->label, label) == 0 &&
		    strcmp(r->reference, reference) == 0 &&
		    (generation == NULL || memcmp(r->generation, generation, 16) == 0))
			return (r);
	}
	return (NULL);
}

static bool
other_reference(struct sl_db *db, const char *label, const char *reference,
    const uint8_t *generation)
{
	for (size_t i = 0; i < db->count; i++) {
		struct sl_record *r = &db->records[i];
		if (r->kind == SL_REFERENCE && r->phase == SL_REF_LIVE &&
		    strcmp(r->label, label) == 0 &&
		    memcmp(r->generation, generation, 16) == 0 &&
		    strcmp(r->reference, reference) != 0)
			return (true);
	}
	return (false);
}

static bool
pending_operation(struct sl_db *db, const char *label)
{
	for (size_t i = 0; i < db->count; i++)
		if (db->records[i].kind == SL_OPERATION &&
		    strcmp(db->records[i].label, label) == 0 &&
		    (db->records[i].phase == SL_INSTALL_PENDING ||
		    db->records[i].phase == SL_REMOVE_PENDING))
			return (true);
	return (false);
}

static int
operation_begin(struct sl_db *db, const char *label, const char *reference,
    const char *operation, bool installing)
{
	struct sl_record *r, *owner, *ref;
	uint8_t token[16], generation[16];
	uint32_t pending = installing ? SL_INSTALL_PENDING : SL_REMOVE_PENDING;
	bool had_owner, had_reference;

	if (!sl_label_valid(label) || !sl_label_valid(reference) ||
	    sl_generation_parse(operation, token) == -1)
		return (errno = EINVAL, -1);
	r = sl_operation(db, label, operation);
	if (r != NULL) {
		if (strcmp(r->reference, reference) != 0 ||
		    r->phase < pending || r->phase > pending + 2)
			return (errno = EINVAL, -1);
		return (r->phase == pending + 2 ? (errno = ECANCELED, -1) : 0);
	}
	if (sl_history_strict(db) && !sl_operation_issued(db, operation))
		return (errno = ESTALE, -1);
	if (pending_operation(db, label) || sl_blocked(db, label))
		return (errno = EBUSY, -1);
	owner = sl_owner(db, label);
	had_owner = owner != NULL && owner->phase == SL_ACTIVE;
	ref = reference_record(db, label, reference, NULL);
	if (installing) {
		had_reference = ref != NULL && ref->phase == SL_REF_LIVE;
		if (sl_install(db, label, generation) == -1)
			return (-1);
		ref = had_reference ? reference_record(db, label, reference, generation) :
		    sl_append(db);
		if (ref == NULL)
			return (errno = EIO, -1);
		ref->kind = SL_REFERENCE;
		ref->phase = SL_REF_STAGED;
		strlcpy(ref->label, label, sizeof(ref->label));
		strlcpy(ref->reference, reference, sizeof(ref->reference));
		memcpy(ref->generation, generation, sizeof(generation));
		/* Preserve whether cancellation must restore an existing installation. */
		ref->provider[0] = had_owner ? '1' : '0';
		ref->provider[1] = had_reference ? '1' : '0';
		owner = sl_owner(db, label);
		owner->phase = SL_INSTALLING;
	} else {
		/* Missing ownership is not authority to retire the current label. */
		if (ref == NULL || ref->phase != SL_REF_LIVE || owner == NULL ||
		    owner->phase != SL_ACTIVE ||
		    memcmp(ref->generation, owner->generation, 16) != 0)
			return (errno = ESTALE, -1);
		memcpy(generation, ref->generation, sizeof(generation));
		if (!other_reference(db, label, reference, generation))
			owner->phase = SL_PREPARED;
	}
	r = sl_append(db);
	if (r == NULL)
		return (-1);
	r->kind = SL_OPERATION;
	r->phase = pending;
	strlcpy(r->label, label, sizeof(r->label));
	strlcpy(r->provider, operation, sizeof(r->provider));
	strlcpy(r->reference, reference, sizeof(r->reference));
	memcpy(r->generation, generation, sizeof(generation));
	return (0);
}

int
sl_install_begin(struct sl_db *db, const char *label, const char *reference,
    const char *operation)
{
	return (operation_begin(db, label, reference, operation, true));
}

int
sl_remove_begin(struct sl_db *db, const char *label, const char *reference,
    const char *operation)
{
	return (operation_begin(db, label, reference, operation, false));
}

static int
operation_finish(struct sl_db *db, const char *label, const char *operation,
    bool cancel, bool installing)
{
	struct sl_record *r, *owner, *ref;
	uint8_t generation[16];
	char reference[SL_LABEL_MAX];
	uint32_t pending = installing ? SL_INSTALL_PENDING : SL_REMOVE_PENDING;

	r = sl_operation(db, label, operation);
	if (r == NULL)
		return (errno = ESTALE, -1);
	if (r->phase == pending + (cancel ? 2 : 1))
		return (0);
	if (r->phase != pending)
		return (errno = ECANCELED, -1);
	memcpy(generation, r->generation, sizeof(generation));
	strlcpy(reference, r->reference, sizeof(reference));
	owner = sl_generation(db, label, generation);
	ref = reference_record(db, label, reference, generation);
	if (owner == NULL || ref == NULL)
		return (errno = EIO, -1);
	if (installing) {
		if (owner->phase != SL_INSTALLING || ref->phase != SL_REF_STAGED)
			return (errno = EIO, -1);
		ref->phase = cancel && ref->provider[1] != '1' ? SL_REF_REMOVED : SL_REF_LIVE;
		owner->phase = cancel && ref->provider[0] == '0' ? SL_COMPLETE : SL_ACTIVE;
	} else {
		if (ref->phase != SL_REF_LIVE ||
		    (owner->phase != SL_ACTIVE && owner->phase != SL_PREPARED))
			return (errno = EIO, -1);
		if (cancel)
			owner->phase = SL_ACTIVE;
		else {
			ref->phase = SL_REF_REMOVED;
			if (!other_reference(db, label, reference, generation)) {
				owner->phase = SL_PREPARED;
				if (sl_retire(db, label, generation) == -1)
					return (-1);
			}
		}
	}
	r = sl_operation(db, label, operation);
	r->phase = pending + (cancel ? 2 : 1);
	db->dirty = true;
	return (0);
}

int
sl_install_finish(struct sl_db *db, const char *label, const char *operation,
    bool cancel)
{
	return (operation_finish(db, label, operation, cancel, true));
}

int
sl_remove_finish(struct sl_db *db, const char *label, const char *operation,
    bool cancel)
{
	return (operation_finish(db, label, operation, cancel, false));
}



int
sl_open(const char *path, struct sl_db *db)
{
	return (open_database(path, db, false, NULL));
}

int
sl_open_readonly(const char *path, struct sl_db *db)
{
	return (open_database(path, db, true, NULL));
}

static int
cache_open(struct sl_query_cache *cache, const char *path, struct sl_db *db)
{
	if (cache == NULL || path == NULL)
		return (errno = EINVAL, -1);
	/* Every hit reopens trusted paths and takes a fresh nonblocking lock. */
	for (unsigned attempt = 0;; attempt++) {
		if (open_database(path, db, true, cache) == 0)
			return (0);
		/* UFS can finish deferred metadata updates during a read. Discard
		 * that snapshot and retry validation, with a strict work bound.
		 * Writer contention and other errors return immediately. */
		if (!cache->retry || attempt == 2)
			return (-1);
	}
}

int
sl_query_cached(struct sl_query_cache *cache, const char *path,
    const char *label, const uint8_t *generation, struct sl_installation *out)
{
	struct sl_db db;
	int result;

	if (out == NULL)
		return (errno = EINVAL, -1);
	memset(out, 0, sizeof(*out));
	if (cache_open(cache, path, &db) == -1)
		return (-1);
	result = cache_query(cache, label, generation, out);
	/* Release the validation buffer and transaction lock after every miss. */
	sl_close(&db);
	return (result);
}

int
sl_query_cached_retired(struct sl_query_cache *cache, const char *path,
    void (*visit)(const char *, const uint8_t *, void *), void *context)
{
	struct sl_db db;

	if (visit == NULL)
		return (errno = EINVAL, -1);
	if (cache_open(cache, path, &db) == -1)
		return (-1);
	for (size_t i = 0; i < cache->count; i++)
		if (cache->entries[i].retired)
			visit(cache->entries[i].label,
			    cache->entries[i].facts.generation, context);
	sl_close(&db);
	return (0);
}

const char *
sl_state_name(enum sl_installation_state state)
{
	static const char *const names[] = {
		"unknown", "installed", "installing", "removing", "removed"
	};
	return ((unsigned)state < sizeof(names) / sizeof(names[0]) ? names[state] : "unknown");
}

int
sl_query(struct sl_db *db, const char *label, const uint8_t *generation,
    struct sl_installation *out)
{
	struct sl_record *owner, *r;

	if (out == NULL)
		return (errno = EINVAL, -1);
	memset(out, 0, sizeof(*out));
	if (!sl_label_valid(label) ||
	    (generation != NULL && !sl_generation_valid(generation)))
		return (errno = EINVAL, -1);
	owner = generation != NULL ? sl_generation(db, label, generation) :
	    sl_owner(db, label);
	if (owner == NULL)
		return (0);
	memcpy(out->generation, owner->generation, sizeof(out->generation));
	switch (owner->phase) {
	case SL_ACTIVE: out->state = SL_INSTALLED; break;
	case SL_INSTALLING: out->state = SL_INSTALL_IN_PROGRESS; break;
	case SL_PREPARED: out->state = SL_REMOVE_IN_PROGRESS; break;
	case SL_RETIRED:
	case SL_COMPLETE: out->state = SL_REMOVED; break;
	default: return (errno = EIO, -1);
	}
	for (size_t i = 0; i < db->count; i++) {
		r = &db->records[i];
		if (strcmp(r->label, label) != 0 ||
		    memcmp(r->generation, out->generation, sizeof(out->generation)) != 0)
			continue;
		if (r->kind == SL_REFERENCE) {
			out->live_sources += r->phase == SL_REF_LIVE;
			out->staged_sources += r->phase == SL_REF_STAGED;
		}
		/* Also report a pending removal of one of several live sources. */
		if (r->kind == SL_OPERATION && r->phase == SL_REMOVE_PENDING)
			out->state = SL_REMOVE_IN_PROGRESS;
	}
	return (0);
}

int
sl_record_source(struct sl_db *db, const char *label, const char *operation,
    const char *source)
{
	struct sl_record *op, *ref;
	size_t len;

	if (source == NULL || (len = strnlen(source, SL_SOURCE_MAX)) == 0 ||
	    len == SL_SOURCE_MAX)
		return (errno = EINVAL, -1);
	for (size_t i = 0; i < len; i++)
		if ((unsigned char)source[i] < 32 || (unsigned char)source[i] == 127)
			return (errno = EINVAL, -1);
	op = sl_operation(db, label, operation);
	if (op == NULL)
		return (errno = ESTALE, -1);
	ref = reference_record(db, label, op->reference, op->generation);
	if (ref == NULL)
		return (errno = EIO, -1);
	if ((op->source[0] != '\0' && strcmp(op->source, source) != 0) ||
	    (ref->source[0] != '\0' && strcmp(ref->source, source) != 0))
		return (errno = EINVAL, -1);
	if (op->source[0] == '\0' || ref->source[0] == '\0') {
		strlcpy(op->source, source, sizeof(op->source));
		strlcpy(ref->source, source, sizeof(ref->source));
		db->dirty = true;
	}
	return (0);
}
