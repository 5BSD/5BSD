/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include "sys/cap_authority.h"
#include "sys/elf_cache.h"
#include <capimage.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "switchboard.h"
#include "library_cache_stats.h"

static bool cache_selected;
static uint64_t cache_device, cache_inode;

int
svc_library_cache_init(void)
{
	struct cap_cache_prepare prepare = {.backing_fd = -1, .directory_fds = {-1, -1}};
	struct cap_cache_publish publish;
	struct elf_cache_header h;
	struct elf_cache_entry e, previous = {0};
	struct stat st;
	char error[256] = "invalid cache structure";
	uint32_t count;
	int pinned = -1, seal = -1, result = -1, saved;
	prepare.backing_fd = open(ELF_CACHE_PATH, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_VERIFY);
	if (prepare.backing_fd < 0)
		return (errno == ENOENT ? 0 : -1);
	prepare.directory_fds[0] = open("/lib", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	prepare.directory_fds[1] = open("/usr/lib", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (prepare.directory_fds[0] < 0 || prepare.directory_fds[1] < 0)
		goto out;
	/* Pin before hashing; all later maps retain this exact backing object. */
	pinned = syscall(SYS_cap_process, CAP_CACHE_PREPARE, sd.authority_issuer_fd, 0, &prepare);
	if (pinned < 0)
		goto out;
	seal = open(ELF_CACHE_SEAL_PATH, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (seal < 0 || capimage_check_seal(pinned, seal, ELF_CACHE_DOMAIN,
	    NULL, error, sizeof(error)) < 0)
		goto out;
	if (fstat(pinned, &st) < 0 || pread(pinned, &h, sizeof(h), 0) != sizeof(h))
		goto out;
	count = le32toh(h.count);
	if (memcmp(h.magic, "5BSDELF", 8) != 0 || le32toh(h.version) != ELF_CACHE_VERSION ||
	    count == 0 || count > ELF_CACHE_MAX_ENTRIES ||
	    le64toh(h.file_size) != (uint64_t)st.st_size ||
	    le32toh(h.alignment) != ELF_CACHE_ALIGNMENT ||
	    le32toh(h.entry_size) != sizeof(e) ||
	    memcmp(h.reserved, (unsigned char[32]){0}, sizeof(h.reserved)) != 0) {
		errno = EFTYPE; goto out;
	}
	for (unsigned i = 0; i < count; i++) {
		if (pread(pinned, &e, sizeof(e), (off_t)(sizeof(h) + i * sizeof(e))) != sizeof(e))
			goto out;
		uint64_t offset = le64toh(e.offset), size = le64toh(e.size);
		uint32_t dir = le32toh(e.directory);
		if (dir > 1 || e.reserved != 0 || e.name[0] == 0 ||
		    memchr(e.name, 0, sizeof(e.name)) == NULL || strchr(e.name, '/') != NULL ||
		    offset % ELF_CACHE_ALIGNMENT != 0 || offset < sizeof(h) + count * sizeof(e) ||
		    size < 64 || le64toh(e.source_size) < size ||
		    le64toh(e.source_size) > CAPIMAGE_FILE_MAX || offset > (uint64_t)st.st_size || size > (uint64_t)st.st_size - offset ||
		    (i > 0 && (dir < le32toh(previous.directory) ||
		    (dir == le32toh(previous.directory) && strcmp(e.name, previous.name) <= 0)))) {
			errno = EFTYPE; goto out;
		}
		previous = e;
	}
	publish = (struct cap_cache_publish){.cache_fd = pinned};
	result = syscall(SYS_cap_process, CAP_CACHE_PUBLISH, sd.authority_issuer_fd, 0, &publish);
	if (result == 0) {
		cache_selected = true;
		cache_device = st.st_dev;
		cache_inode = st.st_ino;
		syslog(LOG_NOTICE, "verified ELF cache selected: %u entries, %ju bytes",
		    count, (uintmax_t)st.st_size);
	}
	if (result == 0)
		result = svc_library_cache_policy_init(pinned);
out:
	saved = errno;
	if (result != 0)
		syslog(LOG_ERR, "ELF cache refused: %s: %s", error, strerror(saved));
	if (pinned >= 0) close(pinned);
	if (seal >= 0) close(seal);
	if (prepare.backing_fd >= 0) close(prepare.backing_fd);
	for (unsigned i = 0; i < 2; i++)
		if (prepare.directory_fds[i] >= 0) close(prepare.directory_fds[i]);
	errno = saved;
	return (result);
}

/* The launcher already holds the provider's protection authority. Report
 * only cache counters to an attributed status client; never delegate debug
 * authority, expose virtual addresses, or accept an arbitrary target PID. */
int
svc_library_cache_status(pid_t pid, char *summary, size_t size)
{
	struct kinfo_vmentry *maps;
	struct library_cache_stats stats = {0};
	int count, error;

	if (!cache_selected) {
		snprintf(summary, size, "pid=%jd cache_selected=0\n", (intmax_t)pid);
		return (0);
	}
	errno = 0;
	maps = kinfo_getvmmap(pid, &count);
	if (maps == NULL)
		return (errno != 0 ? errno : EIO);
	error = library_cache_stats_collect(maps, count, cache_device,
	    cache_inode, &stats);
	free(maps);
	if (error != 0)
		return (error);
	snprintf(summary, size, "pid=%jd cache_selected=1 "
	    "executable_mappings=%ju executable_virtual_bytes=%ju\n",
	    (intmax_t)pid, (uintmax_t)stats.executable_mappings,
	    (uintmax_t)stats.executable_virtual_bytes);
	return (0);
}
