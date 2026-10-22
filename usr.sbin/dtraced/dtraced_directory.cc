/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/hypertrace.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>


#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <new>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_derived.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"
#include "dtraced_protocol.h"
#include "dtraced_rebind_wire.h"
#include "dtraced_transfer_wire.h"
#include "dtraced_process.h"

#include <atomic>

#define SOCKFD_NAME "sub.sock"

namespace dtraced {

char INBOUNDDIR[MAXPATHLEN]  = "/var/ddtrace/inbound/";
char OUTBOUNDDIR[MAXPATHLEN] = "/var/ddtrace/outbound/";
char BASEDIR[MAXPATHLEN]     = "/var/ddtrace/base/";

/*
 * Remove a publication temporary after linkat() gave its inode the final
 * name. Until it is gone the authoritative record has two links and readers
 * that require a private file (st_nlink == 1) refuse it with EPROTO. Retry a
 * failed removal in place so a transient error does not leave that state
 * until the next start's populate_existing(). ENOENT: already removed.
 */
static int
unlink_published_temporary_at(int directory, const char *temporary)
{
	int error = 0;
	for (int attempt = 0; attempt < 4; attempt++) {
		if (unlinkat(directory, temporary, 0) == 0 || errno == ENOENT)
			return (0);
		error = errno;
	}
	errno = error;
	return (-1);
}

static void
identified_spool_name(const uint8_t program[16], const uint8_t source[16],
    char name[70])
{
	static const char hex[] = "0123456789abcdef";
	memcpy(name, "elf.", 4);
	for (size_t i = 0; i < 16; ++i) {
		name[4 + 2 * i] = hex[program[i] >> 4];
		name[5 + 2 * i] = hex[program[i] & 15];
		name[37 + 2 * i] = hex[source[i] >> 4];
		name[38 + 2 * i] = hex[source[i] & 15];
	}
	name[36] = '.';
	name[69] = '\0';
}

/* Publish only complete files, using names relative to the held directory. */
static bool
publish_spool(int directory, const unsigned char *data, size_t length, int source,
    const uint8_t *identity = nullptr, bool *created = nullptr,
    const uint8_t *source_id = nullptr)
{
	char temporary[80], completed[80];
	unsigned char block[65536];
	int fd = -1, existing = -1, error;
	struct stat sb;
	size_t offset = 0;
	if (created != nullptr)
		*created = false;

	if (length == 0 || length > max_request_bytes - DTRACED_MSGHDRSIZE ||
	    (data == nullptr && source < 0) ||
	    (identity != nullptr && source >= 0)) {
		errno = EINVAL;
		return (false);
	}
	for (unsigned attempt = 0; attempt < 8; attempt++) {
		uint64_t nonce[2];
		arc4random_buf(nonce, sizeof(nonce));
		snprintf(temporary, sizeof(temporary), ".elf.%016jx%016jx",
		    (uintmax_t)nonce[0], (uintmax_t)nonce[1]);
		fd = openat(directory, temporary,
		    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (fd >= 0)
			break;
		if (errno != EEXIST)
			return (false);
	}
	if (fd < 0)
		return (false);
	while (offset < length) {
		size_t chunk = MIN(sizeof(block), length - offset);
		const unsigned char *bytes = data != nullptr ? data + offset : block;
		if (source >= 0) {
			ssize_t n = read(source, block, chunk);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0) {
				if (n == 0) errno = EIO;
				goto fail;
			}
			chunk = (size_t)n;
		}
		for (size_t written = 0; written < chunk;) {
			ssize_t n = write(fd, bytes + written, chunk - written);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0) {
				if (n == 0) errno = EIO;
				goto fail;
			}
			written += (size_t)n;
		}
		offset += chunk;
	}
	if (fsync(fd) != 0)
		goto fail;
	error = close(fd);
	fd = -1;
	if (error != 0)
		goto fail;
	if (identity != nullptr) {
		const uint8_t zero[16] = {};
		if (memcmp(identity, zero, 16) == 0) {
			errno = EINVAL;
			goto fail;
		}
		memcpy(completed, "elf.", 4);
		for (size_t i = 0; i < 16; i++) {
			static const char hex[] = "0123456789abcdef";
			completed[4 + 2 * i] = hex[identity[i] >> 4];
			completed[5 + 2 * i] = hex[identity[i] & 15];
		}
		completed[36] = '\0';
	} else {
		strlcpy(completed, temporary + 1, sizeof(completed));
	}
	if (source_id != nullptr) {
		const uint8_t zero[16] = {};
		if (memcmp(source_id, zero, 16) == 0) {
			errno = EINVAL;
			goto fail;
		}
		static const char hex[] = "0123456789abcdef";
		completed[36] = '.';
		for (size_t i = 0; i < 16; i++) {
			completed[37 + 2 * i] = hex[source_id[i] >> 4];
			completed[38 + 2 * i] = hex[source_id[i] & 15];
		}
		completed[69] = '\0';
	}
	if (identity != nullptr) {
		/* A program ID owns one name, regardless of lineage suffix. */
		int scanfd = openat(directory, ".",
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (scanfd < 0)
			goto fail;
		DIR *scan = fdopendir(scanfd);
		if (scan == nullptr) {
			error = errno;
			close(scanfd);
			errno = error;
			goto fail;
		}
		for (;;) {
			errno = 0;
			struct dirent *entry = readdir(scan);
			if (entry == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(entry->d_name, completed, 36) == 0 &&
			    (entry->d_name[36] == '\0' || entry->d_name[36] == '.') &&
			    strcmp(entry->d_name, completed) != 0) {
				error = EEXIST;
				break;
			}
		}
		if (closedir(scan) != 0 && error == 0)
			error = errno;
		if (error != 0) {
			errno = error;
			goto fail;
		}
		if (linkat(directory, temporary, directory, completed, 0) != 0) {
			if (errno != EEXIST)
				goto fail;
			existing = openat(directory, completed,
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (existing < 0 || fstat(existing, &sb) != 0 ||
			    !S_ISREG(sb.st_mode) || sb.st_size != (off_t)length) {
				errno = EEXIST;
				goto fail;
			}
			for (size_t pos = 0; pos < length;) {
				size_t chunk = MIN(sizeof(block), length - pos);
				ssize_t n = read(existing, block, chunk);
				if (n < 0 && errno == EINTR)
					continue;
				if (n <= 0 || memcmp(block, data + pos, (size_t)n) != 0) {
					errno = EEXIST;
					goto fail;
				}
				pos += (size_t)n;
			}
			if (close(existing) != 0) {
				existing = -1;
				goto fail;
			}
			existing = -1;
			if (unlink_published_temporary_at(directory, temporary) != 0)
				goto fail;
			/* A retry can finish an earlier link interrupted before sync. */
			if (fsync(directory) != 0)
				return (false);
			return (true);
		}
		if (unlink_published_temporary_at(directory, temporary) != 0) {
			error = errno;
			(void)unlinkat(directory, completed, 0);
			errno = error;
			goto fail;
		}
	} else {
		if (renameat(directory, temporary, directory, completed) != 0)
			goto fail;
	}
	/* The name is not crash-durable until its containing directory is. */
	if (fsync(directory) != 0) {
		error = errno;
		(void)unlinkat(directory, completed, 0);
		(void)fsync(directory);
		errno = error;
		return (false);
	}
	if (created != nullptr)
		*created = true;
	return (true);
fail:
	error = errno;
	if (existing >= 0)
		close(existing);
	if (fd >= 0)
		close(fd);
	(void)unlinkat(directory, temporary, 0);
	errno = error;
	return (false);
}

bool
dir::write_data(unsigned char *data, size_t nbytes)
{
	return (publish_spool(this->dirfd, data, nbytes, -1));
}

bool
dir::write_data_with_source(const unsigned char *data, size_t nbytes,
    const uint8_t source_id[16])
{
	return (publish_spool(this->dirfd, data, nbytes, -1, nullptr,
	    nullptr, source_id));
}

static bool
source_tombstone_name(const uint8_t source_id[16], char name[41])
{
	const uint8_t zero[16] = {};
	if (source_id == nullptr || memcmp(source_id, zero, 16) == 0) {
		errno = EINVAL;
		return (false);
	}
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".revoke.", 8);
	for (size_t i = 0; i < 16; ++i) {
		name[8 + 2 * i] = hex[source_id[i] >> 4];
		name[9 + 2 * i] = hex[source_id[i] & 15];
	}
	name[40] = '\0';
	return (true);
}

static bool
durable_kill_name(const durable_kill &record, char name[70])
{
	char source[41];
	if (record.pid <= 1 || record.vmid == 0 ||
	    record.vmid >= HYPERTRACE_MAX_VMS || record.epoch == 0 ||
	    !source_tombstone_name(record.source_id.data(), source)) {
		errno = EINVAL;
		return (false);
	}
	int length = snprintf(name, 70, ".kill.%04x.%016llx.%08x.%s",
	    (unsigned)record.vmid, (unsigned long long)record.epoch,
	    (unsigned)(uint32_t)record.pid, source + 8);
	if (length != 69) {
		errno = EINVAL;
		return (false);
	}
	return (true);
}

static bool
parse_hex(const char *digits, size_t length, uint64_t &value)
{
	value = 0;
	for (size_t i = 0; i < length; ++i) {
		char c = digits[i];
		if (c >= '0' && c <= '9')
			value = value * 16 + (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			value = value * 16 + (unsigned)(c - 'a' + 10);
		else
			return (false);
	}
	return (true);
}

static bool
parse_durable_kill(const char *name, durable_kill &record)
{
	uint64_t vmid, epoch, pid, octet;
	if (strlen(name) != 69 || strncmp(name, ".kill.", 6) != 0 ||
	    name[10] != '.' || name[27] != '.' || name[36] != '.' ||
	    !parse_hex(name + 6, 4, vmid) ||
	    !parse_hex(name + 11, 16, epoch) ||
	    !parse_hex(name + 28, 8, pid) ||
	    vmid == 0 || vmid >= HYPERTRACE_MAX_VMS ||
	    epoch == 0 || pid <= 1 || pid > INT_MAX)
		return (false);
	record.vmid = (uint16_t)vmid;
	record.epoch = epoch;
	record.pid = (pid_t)pid;
	for (size_t i = 0; i < record.source_id.size(); ++i) {
		if (!parse_hex(name + 37 + 2 * i, 2, octet))
			return (false);
		record.source_id[i] = (uint8_t)octet;
	}
	const uint8_t zero[16] = {};
	return (memcmp(record.source_id.data(), zero, 16) != 0);
}

static int
kill_record_status_at(int directory, const char *name)
{
	struct stat sb;
	if (fstatat(directory, name, &sb, AT_SYMLINK_NOFOLLOW) != 0)
		return (-1);
	if (!S_ISREG(sb.st_mode) || sb.st_size != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

/* A daemon restart can overlap the old process.  Serializing durable
 * admission with PREPARE needs a filesystem lock across both processes. */
class handoff_process_lock {
	int fd = -1;

public:
	explicit handoff_process_lock(int directory, bool enabled = true)
	{
		if (!enabled)
			return;
		fd = openat(directory, ".handoff.lock",
		    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (fd < 0)
			return;
		struct stat sb;
		int error = fstat(fd, &sb) != 0 ? errno :
		    (!S_ISREG(sb.st_mode) ? EPROTO : 0);
		if (error != 0) {
			close(fd);
			fd = -1;
			errno = error;
			return;
		}
		while (flock(fd, LOCK_EX) != 0) {
			if (errno == EINTR)
				continue;
			int error = errno;
			close(fd);
			fd = -1;
			errno = error;
			return;
		}
	}

	~handoff_process_lock()
	{
		if (fd >= 0)
			close(fd);
	}
	handoff_process_lock(const handoff_process_lock &) = delete;
	handoff_process_lock &operator=(const handoff_process_lock &) = delete;
	bool held() const { return (fd >= 0); }
};

consumer_outcome_lock::consumer_outcome_lock(int directory)
{
	fd = openat(directory, ".outcome.lock",
	    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno :
	    (!S_ISREG(sb.st_mode) ? EPROTO : 0);
	if (error == 0) {
		while (flock(fd, LOCK_EX) != 0) {
			if (errno == EINTR)
				continue;
			error = errno;
			break;
		}
	}
	if (error != 0) {
		close(fd);
		fd = -1;
		errno = error;
	}
}

consumer_outcome_lock::~consumer_outcome_lock()
{
	if (fd >= 0)
		close(fd);
}

/* The marker is published before any guest journal rewrite. A daemon which
 * still holds the source identity must not mint another source record after
 * the rekey lock is released. Callers hold .handoff.lock across the check. */
static bool
guest_rekey_marker_name(uint16_t vmid, uint64_t epoch, char name[40])
{
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EINVAL;
		return (false);
	}
	return (snprintf(name, 40, ".guest-rekey.%04x.%016llx",
	    (unsigned)vmid, (unsigned long long)epoch) == 34);
}

static int
guest_rekey_marker_at(int directory, uint16_t vmid, uint64_t epoch,
    uint16_t *new_vmid = nullptr, uint64_t *new_epoch = nullptr)
{
	char name[40];
	uint8_t data[14] = {};
	struct stat sb;
	if (!guest_rekey_marker_name(vmid, epoch, name))
		return (-1);
	int fd = openat(directory, name,
	    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	int error = fstat(fd, &sb) != 0 ? errno :
	    (!S_ISREG(sb.st_mode) || sb.st_size != (off_t)sizeof(data) ? EPROTO : 0);
	size_t offset = 0;
	while (error == 0 && offset < sizeof(data)) {
		ssize_t n = read(fd, data + offset, sizeof(data) - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EPROTO;
			break;
		}
		offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	uint16_t destination = (uint16_t)data[4] | (uint16_t)data[5] << 8;
	uint64_t destination_epoch = 0;
	for (unsigned i = 0; error == 0 && i < 8; i++)
		destination_epoch |= (uint64_t)data[6 + i] << (8 * i);
	if (error == 0 && (memcmp(data, "GRK1", 4) != 0 ||
	    destination == 0 || destination >= HYPERTRACE_MAX_VMS ||
	    destination_epoch == 0 ||
	    (destination == vmid && destination_epoch == epoch)))
		error = EPROTO;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (new_vmid != nullptr)
		*new_vmid = destination;
	if (new_epoch != nullptr)
		*new_epoch = destination_epoch;
	return (1);
}

static bool
guest_rekey_marker_ensure(int directory, uint16_t old_vmid,
    uint64_t old_epoch, uint16_t new_vmid, uint64_t new_epoch)
{
	char name[40], temporary[44];
	uint16_t recorded_vmid = 0;
	uint64_t recorded_epoch = 0;
	int present = guest_rekey_marker_at(directory, old_vmid, old_epoch,
	    &recorded_vmid, &recorded_epoch);
	if (present < 0)
		return (false);
	if (present != 0) {
		if (recorded_vmid != new_vmid || recorded_epoch != new_epoch) {
			errno = EPROTO;
			return (false);
		}
		return (fsync(directory) == 0);
	}
	if (new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 ||
	    (new_vmid == old_vmid && new_epoch == old_epoch) ||
	    !guest_rekey_marker_name(old_vmid, old_epoch, name)) {
		errno = EINVAL;
		return (false);
	}
	if (snprintf(temporary, sizeof(temporary), ".tmp%s", name) >=
	    (int)sizeof(temporary)) {
		errno = EOVERFLOW;
		return (false);
	}
	if (unlinkat(directory, temporary, 0) == 0) {
		if (fsync(directory) != 0)
			return (false);
	} else if (errno != ENOENT)
		return (false);
	int fd = openat(directory, temporary,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (false);
	uint8_t data[14] = {'G', 'R', 'K', '1', (uint8_t)new_vmid,
	    (uint8_t)(new_vmid >> 8)};
	for (unsigned i = 0; i < 8; i++)
		data[6 + i] = (uint8_t)(new_epoch >> (8 * i));
	size_t offset = 0;
	int error = 0;
	while (offset < sizeof(data)) {
		ssize_t n = write(fd, data + offset, sizeof(data) - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		(void)unlinkat(directory, temporary, 0);
		errno = error;
		return (false);
	}
	if (renameat(directory, temporary, directory, name) != 0)
		return (false);
	return (fsync(directory) == 0);
}

static bool guest_rekey_marker_preflight_at(int, uint16_t, uint64_t,
    uint16_t, uint64_t);

static constexpr size_t max_durable_kills = 16384;

static int
kill_record_count_at(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (-1);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (-1);
	}
	size_t count = 0;
	int error = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		if (strncmp(entry->d_name, ".kill.", 6) != 0)
			continue;
		if (count >= max_durable_kills) {
			error = ENOSPC;
			break;
		}
		durable_kill record{};
		if (!parse_durable_kill(entry->d_name, record) ||
		    kill_record_status_at(directory, entry->d_name) != 0) {
			error = errno == 0 ? EPROTO : errno;
			break;
		}
		count++;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return ((int)count);
}

static int
source_revoked_at(int directory, const uint8_t source_id[16],
    uint16_t vmid = 0, uint64_t epoch = 0)
{
	char name[41];
	struct stat sb;
	if (!source_tombstone_name(source_id, name))
		return (-1);
	if (fstatat(directory, name, &sb, AT_SYMLINK_NOFOLLOW) == 0) {
		if (!S_ISREG(sb.st_mode) || sb.st_size != 0) {
			errno = EPROTO;
			return (-1);
		}
		return (1);
	}
	if (errno != ENOENT)
		return (-1);
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (-1);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (-1);
	}
	int found = 0, error = 0;
	size_t count = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		if (strncmp(entry->d_name, ".kill.", 6) != 0)
			continue;
		if (count >= max_durable_kills) {
			error = ENOSPC;
			break;
		}
		count++;
		durable_kill record{};
		if (!parse_durable_kill(entry->d_name, record) ||
		    kill_record_status_at(directory, entry->d_name) != 0) {
			error = errno == 0 ? EPROTO : errno;
			break;
		}
		if (memcmp(record.source_id.data(), source_id, 16) == 0 &&
		    (vmid == 0 || (record.vmid == vmid && record.epoch == epoch)))
			found = 1;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (found);
}

static int handoff_source_state_at(int, uint16_t, uint64_t,
    durable_handoff &);
static bool derived_claim_valid(const durable_derived_claim &);
static bool derived_claim_record_at(int, const durable_derived_claim &);

dir::source_transaction::source_transaction(dir &owner,
    const uint8_t source_id[16], uint16_t vmid, uint64_t epoch)
    : owner(owner), vmid(vmid), epoch(epoch), local(owner.publishmtx),
      process(std::make_unique<handoff_process_lock>(owner.dirfd))
{
	memcpy(this->source_id.data(), source_id, 16);
	if (!process->held())
		return;
	int result = source_revoked_at(owner.dirfd, source_id, vmid, epoch);
	if (result >= 0) {
		complete = true;
		revoked = result != 0;
	}
}

dir::source_transaction::~source_transaction() = default;

static bool list_deliveries_at(int,
    std::vector<durable_delivery_state> &);
static bool source_drain_receipts_complete_at(int,
    const durable_handoff &, const std::vector<uint8_t> &);
static bool list_derived_claims_at(int,
    std::vector<durable_derived_claim> &);
static bool derived_outbound_was_delivered(delivery_phase);

bool
dir::source_transaction::publish_derived(const durable_derived_claim &claim,
    const unsigned char *data, size_t length, bool *created)
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint8_t bare_digest[SHA256_DIGEST_LENGTH];
	hypertrace_vm_envelope target{};
	if (!this->valid() || this->source_revoked() || data == nullptr ||
	    length < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4 ||
	    !derived_claim_valid(claim) ||
	    claim.ingress_source_id != this->source_id ||
	    claim.ingress_vmid != this->vmid ||
	    claim.ingress_epoch != this->epoch ||
	    SHA256(data, length, digest) == nullptr ||
	    SHA256(data + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
	    length - HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
	    bare_digest) == nullptr ||
	    memcmp(digest, claim.payload_digest.data(), sizeof(digest)) != 0 ||
	    memcmp(bare_digest, claim.bare_elf_digest.data(),
	    sizeof(bare_digest)) != 0) {
		errno = EINVAL;
		return (false);
	}
	hypertrace_envelope_decode(&target, data);
	if (target.magic != HYPERTRACE_TARGET_MAGIC ||
	    target.version != HYPERTRACE_ENVELOPE_VERSION ||
	    target.vmid != claim.target_vmid ||
	    target.epoch != claim.target_epoch || target.name_length != 0 ||
	    memcmp(data + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
	    "\177ELF", 4) != 0) {
		errno = EPROTO;
		return (false);
	}
	/* Freeze one result before the watcher can observe its spool. The
	 * transaction owns both publication locks through both fsyncs. */
	if (!derived_claim_record_at(this->owner.dirfd, claim))
		return (false);
	/* An exact consumer retry must not resurrect a spool after the guest
	 * accepted and retired this derived program. The immutable outbound
	 * receipt proves the same original target and bare ELF digest. */
	std::vector<durable_delivery_state> deliveries;
	if (!list_deliveries_at(this->owner.dirfd, deliveries))
		return (false);
	bool delivered = false, pending = false;
	for (const auto &entry : deliveries) {
		const auto &record = entry.record;
		if (record.scope != 0 ||
		    record.program_id != claim.derived_program_id)
			continue;
		uint16_t payload_vmid = record.journal_version == 5 ?
		    record.payload_vmid : record.vmid;
		uint64_t payload_epoch = record.journal_version == 5 ?
		    record.payload_epoch : record.epoch;
		if (record.source_id != claim.ingress_source_id ||
		    (record.journal_version != 4 &&
		    record.journal_version != 5) ||
		    payload_vmid != claim.target_vmid ||
		    payload_epoch != claim.target_epoch ||
		    record.payload_digest != claim.bare_elf_digest) {
			errno = EPROTO;
			return (false);
		}
		if (derived_outbound_was_delivered(entry.phase))
			delivered = true;
		else
			pending = true;
	}
	if (delivered && !pending) {
		uint8_t existing[SHA256_DIGEST_LENGTH];
		uint8_t existing_bare[SHA256_DIGEST_LENGTH];
		bool spool_present = this->owner.hash_identified_data(
		    claim.derived_program_id.data(),
		    claim.ingress_source_id.data(), existing, false, true,
		    existing_bare);
		if (!spool_present && errno != ENOENT)
			return (false);
		if (spool_present &&
		    (memcmp(existing, claim.payload_digest.data(),
		    sizeof(existing)) != 0 ||
		    memcmp(existing_bare, claim.bare_elf_digest.data(),
		    sizeof(existing_bare)) != 0)) {
			errno = EPROTO;
			return (false);
		}
		if (created != nullptr)
			*created = false;
		return (fsync(this->owner.dirfd) == 0);
	}
	return (publish_spool(this->owner.dirfd, data, length, -1,
	    claim.derived_program_id.data(), created, this->source_id.data()));
}

std::unique_ptr<dir::source_transaction>
dir::lock_live_source(const uint8_t source_id[16], uint16_t vmid,
    uint64_t epoch)
{
	auto transaction = this->lock_source_snapshot(source_id, vmid, epoch);
	if (transaction && transaction->source_revoked()) {
		transaction.reset();
		errno = ECANCELED;
		return (nullptr);
	}
	if (transaction) {
		/* The source transaction owns the same cross-process lock as
		 * PREPARE. A new upload cannot enter after the durable cut, and an
		 * already active upload must finish before PREPARE can publish. */
		durable_handoff active{};
		int phase = handoff_source_state_at(this->dirfd, vmid, epoch,
		    active);
		if (phase != 0) {
			int error = phase < 0 ? errno : EBUSY;
			transaction.reset();
			errno = error;
			return (nullptr);
		}
	}
	return (transaction);
}

std::unique_ptr<dir::source_transaction>
dir::lock_source_snapshot(const uint8_t source_id[16], uint16_t vmid,
    uint64_t epoch)
{
	if (source_id == nullptr || vmid == 0 ||
	    vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EINVAL;
		return (nullptr);
	}
	try {
		auto transaction = std::unique_ptr<source_transaction>(
		    new source_transaction(*this, source_id, vmid, epoch));
		if (!transaction->valid()) {
			int error = errno;
			transaction.reset();
			errno = error;
			return (nullptr);
		}
		return (transaction);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (nullptr);
	}
}

int
dir::source_revoked(const uint8_t source_id[16])
{
	std::lock_guard lk(this->publishmtx);
	return (source_revoked_at(this->dirfd, source_id));
}

int
dir::source_revoked_for_vm(const uint8_t source_id[16], uint16_t vmid,
    uint64_t epoch)
{
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	return (source_revoked_at(this->dirfd, source_id, vmid, epoch));
}

bool
dir::revoke_source(const uint8_t source_id[16])
{
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	char name[41];
	if (!source_tombstone_name(source_id, name))
		return (false);
	int fd = openat(this->dirfd, name,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		if (errno != EEXIST || source_revoked_at(this->dirfd, source_id) != 1)
			return (false);
	} else {
		if (fsync(fd) != 0) {
			int error = errno;
			close(fd);
			(void)unlinkat(this->dirfd, name, 0);
			errno = error;
			return (false);
		}
		if (close(fd) != 0)
			return (false);
	}
	return (fsync(this->dirfd) == 0);
}

static bool
record_kill_at(int directory, const durable_kill &record,
    bool sync_directory = true)
{
	char name[70];
	if (!durable_kill_name(record, name))
		return (false);
	/* An exact retry is safe even when the journal is at capacity. */
	if (kill_record_status_at(directory, name) == 0)
		return (!sync_directory || fsync(directory) == 0);
	if (errno != ENOENT)
		return (false);
	int count = kill_record_count_at(directory);
	if (count < 0)
		return (false);
	if ((size_t)count >= max_durable_kills) {
		errno = ENOSPC;
		return (false);
	}
	int fd = openat(directory, name,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		if (errno != EEXIST || kill_record_status_at(directory, name) != 0)
			return (false);
	} else {
		if (fsync(fd) != 0) {
			int error = errno;
			close(fd);
			(void)unlinkat(directory, name, 0);
			errno = error;
			return (false);
		}
		if (close(fd) != 0)
			return (false);
	}
	return (!sync_directory || fsync(directory) == 0);
}

bool
dir::record_kill(const durable_kill &record,
    const std::function<bool(const std::vector<durable_kill> &)> &prepare)
{
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	try {
		/* The guest inbound journal has no handoff lineage.  Preserve its
		 * allocation-free KILL persistence under memory pressure. */
		if (!prepare) {
			int retired = guest_rekey_marker_at(this->dirfd,
			    record.vmid, record.epoch);
			if (retired < 0)
				return (false);
			if (retired != 0) {
				errno = ESTALE;
				return (false);
			}
			durable_handoff first{};
			int phase = handoff_source_state_at(this->dirfd,
			    record.vmid, record.epoch, first);
			if (phase < 0)
				return (false);
			if (phase != (int)handoff_phase::claimed)
				return (record_kill_at(this->dirfd, record));
		}
		std::vector<durable_kill> lineage{record};
		for (;;) {
			const durable_kill &current = lineage.back();
			durable_handoff ticket{};
			int phase = handoff_source_state_at(this->dirfd,
			    current.vmid, current.epoch, ticket);
			if (phase < 0)
				return (false);
			if (phase != (int)handoff_phase::claimed)
				break;
			/* HT-C BEGIN: disabled trace continuity. */
			durable_kill next = current;
			next.vmid = ticket.destination_vmid;
			next.epoch = ticket.destination_epoch;
			if (lineage.size() >= max_durable_kills ||
			    std::any_of(lineage.begin(), lineage.end(),
			    [&next](const durable_kill &seen) {
				return (seen.vmid == next.vmid &&
				    seen.epoch == next.epoch);
			    })) {
				errno = ELOOP;
				return (false);
			}
			lineage.push_back(next);
			/* HT-C END */
		}
		/* Admission may allocate jobs here, before any KILL is written.
		 * Keep the cross-process lock through publication so CLAIM cannot
		 * extend this lineage between recipient selection and the journal. */
		if (prepare && !prepare(lineage))
			return (false);
		/* The active destination goes first.  A failed or interrupted write
		 * cannot leave a durable source KILL without its claimed descendants. */
		for (auto it = lineage.rbegin(); it != lineage.rend(); ++it) {
			if (!record_kill_at(this->dirfd, *it))
				return (false);
		}
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

static bool
kill_applied_name(const durable_kill &record, char name[73])
{
	char kill_name[70];

	if (!durable_kill_name(record, kill_name))
		return (false);
	return (snprintf(name, 73, ".killack.%s", kill_name + 6) == 72);
}

bool
dir::record_kill_applied(const durable_kill &record)
{
	std::lock_guard lk(this->publishmtx);
	/* An older daemon may still be publishing an ACK while restore rekeys
	 * the same journal. Keep the exact-record check and ACK publication on
	 * the same cross-process side of that transition. */
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	int retired = guest_rekey_marker_at(this->dirfd, record.vmid,
	    record.epoch);
	if (retired < 0)
		return (false);
	if (retired != 0) {
		errno = ESTALE;
		return (false);
	}
	char kill_name[70], ack_name[73];
	if (!durable_kill_name(record, kill_name) ||
	    !kill_applied_name(record, ack_name) ||
	    kill_record_status_at(this->dirfd, kill_name) != 0)
		return (false);
	if (kill_record_status_at(this->dirfd, ack_name) == 0)
		return (fsync(this->dirfd) == 0);
	if (errno != ENOENT)
		return (false);
	int fd = openat(this->dirfd, ack_name,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		if (errno != EEXIST ||
		    kill_record_status_at(this->dirfd, ack_name) != 0)
			return (false);
	} else {
		if (fsync(fd) != 0) {
			int error = errno;
			close(fd);
			(void)unlinkat(this->dirfd, ack_name, 0);
			errno = error;
			return (false);
		}
		if (close(fd) != 0)
			return (false);
	}
	return (fsync(this->dirfd) == 0);
}

int
dir::kill_applied(const durable_kill &record)
{
	std::lock_guard lk(this->publishmtx);
	char kill_name[70], ack_name[73];
	if (!durable_kill_name(record, kill_name) ||
	    !kill_applied_name(record, ack_name) ||
	    kill_record_status_at(this->dirfd, kill_name) != 0)
		return (-1);
	if (kill_record_status_at(this->dirfd, ack_name) == 0)
		return (1);
	return (errno == ENOENT ? 0 : -1);
}

static bool
list_kills_at(int directory, std::vector<durable_kill> &records)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	std::vector<durable_kill> recovered;
	int error = 0;
	size_t count = 0;
	try {
		for (;;) {
			errno = 0;
			struct dirent *entry = readdir(scan);
			if (entry == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(entry->d_name, ".kill.", 6) != 0)
				continue;
			if (count >= max_durable_kills) {
				error = ENOSPC;
				break;
			}
			durable_kill record{};
			if (!parse_durable_kill(entry->d_name, record) ||
			    kill_record_status_at(directory, entry->d_name) != 0) {
				error = errno == 0 ? EPROTO : errno;
				break;
			}
			recovered.push_back(record);
			count++;
		}
	} catch (const std::bad_alloc &) {
		error = ENOMEM;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	records.swap(recovered);
	return (true);
}

static bool
cleanup_name(const durable_cleanup &record, char phase, char name[50])
{
	if ((phase != 'p' && phase != 'a' && phase != 'g') ||
	    record.vmid == 0 || record.vmid >= HYPERTRACE_MAX_VMS ||
	    record.epoch == 0 || record.delivery_id == 0) {
		errno = EINVAL;
		return (false);
	}
	return (snprintf(name, 50, ".cleanup.%04x.%016llx.%016llx.%c",
	    (unsigned)record.vmid, (unsigned long long)record.epoch,
	    (unsigned long long)record.delivery_id, phase) == 49);
}

static bool
parse_cleanup_name(const char *name, durable_cleanup &record, char &phase)
{
	uint64_t vmid, epoch, delivery_id;
	if (strlen(name) != 49 || strncmp(name, ".cleanup.", 9) != 0 ||
	    name[13] != '.' || name[30] != '.' || name[47] != '.' ||
	    (name[48] != 'p' && name[48] != 'a' && name[48] != 'g') ||
	    !parse_hex(name + 9, 4, vmid) ||
	    !parse_hex(name + 14, 16, epoch) ||
	    !parse_hex(name + 31, 16, delivery_id) ||
	    vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    delivery_id == 0)
		return (false);
	record.vmid = (uint16_t)vmid;
	record.epoch = epoch;
	record.delivery_id = delivery_id;
	phase = name[48];
	return (true);
}

static bool
list_pending_cleanups_at(int directory,
    std::vector<durable_cleanup> &records, size_t *total = nullptr,
    std::vector<source_journal_cleanup> *all = nullptr)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	std::vector<durable_cleanup> recovered;
	std::vector<source_journal_cleanup> recovered_all;
	int error = 0;
	size_t count = 0;
	try {
		for (;;) {
			errno = 0;
			struct dirent *entry = readdir(scan);
			if (entry == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(entry->d_name, ".cleanup.", 9) != 0)
				continue;
			if (++count > max_durable_kills) {
				error = ENOSPC;
				break;
			}
			durable_cleanup record{};
			char phase = 0;
			if (!parse_cleanup_name(entry->d_name, record, phase) ||
			    kill_record_status_at(directory, entry->d_name) != 0) {
				error = errno == 0 ? EPROTO : errno;
				break;
			}
			if (phase == 'p')
				recovered.push_back(record);
			if (all != nullptr)
				recovered_all.push_back({record, phase});
		}
	} catch (const std::bad_alloc &) {
		error = ENOMEM;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	if (all != nullptr) {
		std::sort(recovered_all.begin(), recovered_all.end(),
		    [](const auto &a, const auto &b) {
			if (a.record.vmid != b.record.vmid)
				return (a.record.vmid < b.record.vmid);
			if (a.record.epoch != b.record.epoch)
				return (a.record.epoch < b.record.epoch);
			return (a.record.delivery_id < b.record.delivery_id);
		    });
		for (size_t i = 1; i < recovered_all.size(); i++) {
			const auto &before = recovered_all[i - 1].record;
			const auto &after = recovered_all[i].record;
			if (before.vmid == after.vmid &&
			    before.epoch == after.epoch &&
			    before.delivery_id == after.delivery_id) {
				errno = EPROTO;
				return (false);
			}
		}
		all->swap(recovered_all);
	}
	records.swap(recovered);
	if (total != nullptr)
		*total = count;
	return (true);
}

static int
cleanup_status_at(int directory, const durable_cleanup &record)
{
	char pending_name[50], accepted_name[50], applied_name[50];
	if (!cleanup_name(record, 'p', pending_name) ||
	    !cleanup_name(record, 'a', accepted_name) ||
	    !cleanup_name(record, 'g', applied_name))
		return (-1);
	int pending = kill_record_status_at(directory, pending_name);
	if (pending != 0 && errno != ENOENT)
		return (-1);
	int accepted = kill_record_status_at(directory, accepted_name);
	if (accepted != 0 && errno != ENOENT)
		return (-1);
	int applied = kill_record_status_at(directory, applied_name);
	if (applied != 0 && errno != ENOENT)
		return (-1);
	if ((pending == 0) + (accepted == 0) + (applied == 0) > 1) {
		errno = EPROTO;
		return (-1);
	}
	return (pending == 0 ? 'p' : accepted == 0 ? 'a' :
	    applied == 0 ? 'g' : 0);
}

bool
dir::list_kills(std::vector<durable_kill> &records)
{
	std::lock_guard lk(this->publishmtx);
	return (list_kills_at(this->dirfd, records));
}

bool
dir::rekey_guest_kills(uint16_t old_vmid, uint64_t old_epoch,
    uint16_t new_vmid, uint64_t new_epoch)
{
	if (old_vmid == 0 || old_vmid >= HYPERTRACE_MAX_VMS ||
	    old_epoch == 0 || new_vmid == 0 ||
	    new_vmid >= HYPERTRACE_MAX_VMS || new_epoch == 0 ||
	    (old_vmid == new_vmid && old_epoch == new_epoch)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	std::vector<durable_kill> records;
	if (!list_kills_at(this->dirfd, records))
		return (false);
	uint16_t fenced_vmid = 0;
	uint64_t fenced_epoch = 0;
	int fenced = guest_rekey_marker_at(this->dirfd, old_vmid,
	    old_epoch, &fenced_vmid, &fenced_epoch);
	if (fenced < 0)
		return (false);
	if (fenced != 0 && (fenced_vmid != new_vmid ||
	    fenced_epoch != new_epoch)) {
		errno = EPROTO;
		return (false);
	}
	/* Reject a foreign incarnation before changing any file. Destination
	 * records prove an earlier partial run only with its durable fence. */
	for (const durable_kill &record : records) {
		if (record.vmid == new_vmid && record.epoch == new_epoch &&
		    fenced == 0) {
			errno = ESTALE;
			return (false);
		}
		if ((record.vmid != old_vmid || record.epoch != old_epoch) &&
		    (record.vmid != new_vmid || record.epoch != new_epoch)) {
			errno = ESTALE;
			return (false);
		}
	}
	if (!guest_rekey_marker_preflight_at(this->dirfd, old_vmid,
	    old_epoch, new_vmid, new_epoch) ||
	    !guest_rekey_marker_ensure(this->dirfd, old_vmid, old_epoch,
	    new_vmid, new_epoch))
		return (false);
	/* An applied marker from either incarnation does not prove that a
	 * restored guest has applied this KILL. Clear all such markers before
	 * moving any source record, including destination-only retry records. */
	for (const durable_kill &record : records) {
		char ack_name[73];
		if (!kill_applied_name(record, ack_name))
			return (false);
		int applied = kill_record_status_at(this->dirfd, ack_name);
		if (applied < 0 && errno != ENOENT)
			return (false);
		if (applied == 0 &&
		    (unlinkat(this->dirfd, ack_name, 0) != 0 ||
		    fsync(this->dirfd) != 0))
			return (false);
	}
	for (const durable_kill &source : records) {
		if (source.vmid != old_vmid || source.epoch != old_epoch)
			continue;
		durable_kill destination = source;
		destination.vmid = new_vmid;
		destination.epoch = new_epoch;
		char source_name[70], destination_name[70];
		if (!durable_kill_name(source, source_name) ||
		    !durable_kill_name(destination, destination_name))
			return (false);
		int present = kill_record_status_at(this->dirfd,
		    destination_name);
		if (present < 0 && errno != ENOENT)
			return (false);
		if (present == 0) {
			/* A previous interrupted run, or host replay, may already
			 * have installed this exact destination record. */
			if (unlinkat(this->dirfd, source_name, 0) != 0)
				return (false);
		} else if (renameat(this->dirfd, source_name,
		    this->dirfd, destination_name) != 0)
			return (false);
		if (fsync(this->dirfd) != 0)
			return (false);
	}
	return (true);
}

/* A fixed-width, checksummed record; the checksum detects torn files, not
 * hostile writers with access to the daemon's private directory. */
static constexpr size_t handoff_legacy_record_size = 120;
static constexpr size_t handoff_record_size = 152;

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
static bool
handoff_valid(const durable_handoff &record, handoff_phase phase)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	bool destination = record.destination_vmid != 0 &&
	    record.destination_vmid < HYPERTRACE_MAX_VMS &&
	    record.destination_epoch != 0 &&
	    (record.destination_vmid != record.source_vmid ||
	    record.destination_epoch != record.source_epoch);
	if (record.token == zero16 || record.source_session == zero16 ||
	    record.source_vmid == 0 || record.source_vmid >= HYPERTRACE_MAX_VMS ||
	    record.source_epoch == 0)
		return (false);
	switch (phase) {
	case handoff_phase::prepared:
		return (record.checkpoint_digest == zero32 &&
		    record.destination_vmid == 0 && record.destination_epoch == 0);
	case handoff_phase::committed:
		return (record.checkpoint_digest != zero32 &&
		    record.destination_vmid == 0 && record.destination_epoch == 0);
	case handoff_phase::reserved:
	case handoff_phase::mutating:
		return (record.checkpoint_digest != zero32 && destination);
	case handoff_phase::claimed:
		return (record.checkpoint_digest != zero32 && destination);
	}
	return (false);
}

static bool
handoff_name(const std::array<uint8_t, 16> &token, handoff_phase phase,
    char name[44])
{
	static const char hex[] = "0123456789abcdef";
	if (token == std::array<uint8_t, 16>{}) {
		errno = EINVAL;
		return (false);
	}
	memcpy(name, ".handoff.", 9);
	for (size_t i = 0; i < token.size(); i++) {
		name[9 + i * 2] = hex[token[i] >> 4];
		name[10 + i * 2] = hex[token[i] & 15];
	}
	name[41] = '.';
	name[42] = (char)phase;
	name[43] = '\0';
	return (true);
}

static std::array<uint8_t, handoff_record_size>
handoff_bytes(const durable_handoff &record)
{
	std::array<uint8_t, handoff_record_size> data{};
	memcpy(data.data(), "HTH2", 4);
	memcpy(data.data() + 4, record.token.data(), 16);
	memcpy(data.data() + 20, record.source_session.data(), 16);
	data[36] = (uint8_t)record.source_vmid;
	data[37] = (uint8_t)(record.source_vmid >> 8);
	for (unsigned i = 0; i < 8; i++) {
		data[38 + i] = (uint8_t)(record.source_epoch >> (8 * i));
		data[80 + i] = (uint8_t)(record.destination_epoch >> (8 * i));
	}
	memcpy(data.data() + 46, record.checkpoint_digest.data(), 32);
	data[78] = (uint8_t)record.destination_vmid;
	data[79] = (uint8_t)(record.destination_vmid >> 8);
	memcpy(data.data() + 88, record.transfer_digest.data(),
	    record.transfer_digest.size());
	(void)SHA256(data.data(), 120, data.data() + 120);
	return (data);
}

static std::array<uint8_t, handoff_legacy_record_size>
handoff_legacy_bytes(const durable_handoff &record)
{
	const auto current = handoff_bytes(record);
	std::array<uint8_t, handoff_legacy_record_size> data{};
	memcpy(data.data(), current.data(), 88);
	memcpy(data.data(), "HTH1", 4);
	(void)SHA256(data.data(), 88, data.data() + 88);
	return (data);
}

static int
handoff_read_at(int directory, const std::array<uint8_t, 16> &token,
    handoff_phase phase, durable_handoff &record)
{
	char name[44];
	if (!handoff_name(token, phase, name))
		return (-1);
	/* O_NONBLOCK prevents a corrupted FIFO from hanging restart before
	 * fstat() can reject its type. Phase files are private single links. */
	int fd = openat(directory, name,
	    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	std::array<uint8_t, handoff_record_size> data{};
	int error = 0;
	if (fstat(fd, &sb) != 0)
		error = errno;
	else if (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    (sb.st_size != (off_t)data.size() &&
	    sb.st_size != (off_t)handoff_legacy_record_size))
		error = EPROTO;
	const size_t wire_length = error == 0 ? (size_t)sb.st_size : 0;
	for (size_t offset = 0; error == 0 && offset < wire_length;) {
		ssize_t n = read(fd, data.data() + offset, wire_length - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	const size_t hash_length = error == 0 ?
	    wire_length - SHA256_DIGEST_LENGTH : 0;
	if (error == 0 &&
	    ((wire_length == handoff_legacy_record_size &&
	    memcmp(data.data(), "HTH1", 4) != 0) ||
	    (wire_length == handoff_record_size &&
	    memcmp(data.data(), "HTH2", 4) != 0) ||
	    SHA256(data.data(), hash_length, digest) == nullptr ||
	    memcmp(digest, data.data() + hash_length,
	    sizeof(digest)) != 0 ||
	    memcmp(data.data() + 4, token.data(), token.size()) != 0))
		error = EPROTO;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	durable_handoff decoded{};
	decoded.token = token;
	memcpy(decoded.source_session.data(), data.data() + 20, 16);
	decoded.source_vmid = (uint16_t)data[36] | (uint16_t)data[37] << 8;
	decoded.destination_vmid = (uint16_t)data[78] |
	    (uint16_t)data[79] << 8;
	for (unsigned i = 0; i < 8; i++) {
		decoded.source_epoch |= (uint64_t)data[38 + i] << (8 * i);
		decoded.destination_epoch |= (uint64_t)data[80 + i] << (8 * i);
	}
	memcpy(decoded.checkpoint_digest.data(), data.data() + 46, 32);
	if (wire_length == handoff_record_size)
		memcpy(decoded.transfer_digest.data(), data.data() + 88,
		    decoded.transfer_digest.size());
	if (!handoff_valid(decoded, phase)) {
		errno = EPROTO;
		return (-1);
	}
	record = decoded;
	return (1);
}

static bool
handoff_same_source(const durable_handoff &a, const durable_handoff &b)
{
	return (a.token == b.token && a.source_session == b.source_session &&
	    a.source_vmid == b.source_vmid && a.source_epoch == b.source_epoch &&
	    a.transfer_digest == b.transfer_digest);
}

static bool
handoff_same_destination(const durable_handoff &a, const durable_handoff &b)
{
	return (handoff_same_source(a, b) &&
	    a.checkpoint_digest == b.checkpoint_digest &&
	    a.destination_vmid == b.destination_vmid &&
	    a.destination_epoch == b.destination_epoch);
}

/* A commit journal retains the old HTH2 after the claimed phase file has
 * been replaced. Decode only a canonical, checksummed claimed record. */
static bool
handoff_claimed_from_bytes(const uint8_t *data, durable_handoff &record)
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (memcmp(data, "HTH2", 4) != 0 ||
	    SHA256(data, 120, digest) == nullptr ||
	    CRYPTO_memcmp(digest, data + 120, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	durable_handoff decoded{};
	memcpy(decoded.token.data(), data + 4, 16);
	memcpy(decoded.source_session.data(), data + 20, 16);
	decoded.source_vmid = dtraced_wire_get_u16(data + 36);
	decoded.source_epoch = dtraced_wire_get_u64(data + 38);
	memcpy(decoded.checkpoint_digest.data(), data + 46, 32);
	decoded.destination_vmid = dtraced_wire_get_u16(data + 78);
	decoded.destination_epoch = dtraced_wire_get_u64(data + 80);
	memcpy(decoded.transfer_digest.data(), data + 88, 32);
	if (!handoff_valid(decoded, handoff_phase::claimed) ||
	    memcmp(handoff_bytes(decoded).data(), data,
	    handoff_record_size) != 0) {
		errno = EPROTO;
		return (false);
	}
	record = decoded;
	return (true);
}

static int handoff_rebind_commit_recover_at(int,
    const std::array<uint8_t, 16> &);
static int handoff_rebind_done_claimed_at(int,
    const std::array<uint8_t, 16> &);
static int handoff_mutating_reset_read_at(int,
    const std::array<uint8_t, 16> &, durable_handoff &);

static int source_release_read_at(int, const durable_handoff &);
static int imported_release_cut_status_at(int,
    const durable_handoff &);

static int
handoff_state_at(int directory, const std::array<uint8_t, 16> &token,
    durable_handoff &record)
{
	durable_handoff reset{};
	int resetting = handoff_mutating_reset_read_at(directory, token, reset);
	if (resetting != 0) {
		if (resetting == 1)
			errno = EBUSY;
		return (-1);
	}
	if (handoff_rebind_commit_recover_at(directory, token) < 0)
		return (-1);
	if (handoff_rebind_done_claimed_at(directory, token) < 0)
		return (-1);
	durable_handoff prepared{}, committed{}, reserved{}, mutating{}, claimed{};
	int p = handoff_read_at(directory, token, handoff_phase::prepared, prepared);
	if (p < 0)
		return (-1);
	int c = handoff_read_at(directory, token, handoff_phase::committed, committed);
	if (c < 0)
		return (-1);
	int v = handoff_read_at(directory, token, handoff_phase::reserved, reserved);
	if (v < 0)
		return (-1);
	int m = handoff_read_at(directory, token, handoff_phase::mutating, mutating);
	if (m < 0)
		return (-1);
	int r = handoff_read_at(directory, token, handoff_phase::claimed, claimed);
	if (r < 0)
		return (-1);
	const durable_handoff *records[] = {
	    &prepared, &committed, &reserved, &mutating, &claimed
	};
	const int present[] = { p, c, v, m, r };
	int first = -1, last = -1, count = 0;
	for (size_t i = 0; i < 5; i++) {
		if (!present[i])
			continue;
		if (first < 0)
			first = (int)i;
		last = (int)i;
		count++;
	}
	/* A transition fsyncs its successor before removing its predecessor.
	 * Only that adjacent pair can survive a crash; a skipped phase or three
	 * phase files cannot result from a legal transition. */
	if (count > 2 || (count == 2 && last != first + 1)) {
		errno = EPROTO;
		return (-1);
	}
	for (size_t i = 0; i < 5; i++) {
		if (!present[i])
			continue;
		for (size_t j = i + 1; j < 5; j++) {
			if (!present[j])
				continue;
			if (!handoff_same_source(*records[i], *records[j]) ||
			    (i >= 1 && records[i]->checkpoint_digest !=
			    records[j]->checkpoint_digest) ||
			    (i >= 2 && (records[i]->destination_vmid !=
			    records[j]->destination_vmid ||
			    records[i]->destination_epoch !=
			    records[j]->destination_epoch))) {
				errno = EPROTO;
				return (-1);
			}
		}
	}
	if (r || m || v) {
		durable_handoff source = r ? claimed : m ? mutating : reserved;
		source.destination_vmid = 0;
		source.destination_epoch = 0;
		int released = source_release_read_at(directory, source);
		if (released == 0)
			released = imported_release_cut_status_at(directory, source);
		if (released != 1) {
			if (released == 0)
				errno = EPROTO;
			return (-1);
		}
	}
	if (r) {
		record = claimed;
		return ((int)handoff_phase::claimed);
	}
	if (m) {
		record = mutating;
		return ((int)handoff_phase::mutating);
	}
	if (v) {
		record = reserved;
		return ((int)handoff_phase::reserved);
	}
	if (c) {
		record = committed;
		return ((int)handoff_phase::committed);
	}
	if (p) {
		record = prepared;
		return ((int)handoff_phase::prepared);
	}
	return (0);
}
/* HT-C END */

static bool
fresh_stop_valid(const durable_session_stop &stop)
{
	return (stop.vmid != 0 && stop.vmid < HYPERTRACE_MAX_VMS &&
	    stop.epoch != 0 && stop.token != std::array<uint8_t, 16>{} &&
	    stop.source_session != std::array<uint8_t, 16>{});
}

static void
fresh_stop_name(uint16_t vmid, uint64_t epoch, char name[64])
{
	snprintf(name, 64, ".fresh-stop.%04x.%016jx", vmid, (uintmax_t)epoch);
}

static std::array<uint8_t, 80>
fresh_stop_bytes(const durable_session_stop &stop)
{
	std::array<uint8_t, 80> wire{};
	memcpy(wire.data(), "FSI1", 4);
	dtraced_wire_put_u16(wire.data() + 4, stop.vmid);
	dtraced_wire_put_u64(wire.data() + 8, stop.epoch);
	memcpy(wire.data() + 16, stop.token.data(), 16);
	memcpy(wire.data() + 32, stop.source_session.data(), 16);
	SHA256(wire.data(), 48, wire.data() + 48);
	return (wire);
}

/* This permanent admission fence is independent of continuity tickets.
 * Caller holds the journal's process lock. Never repair malformed evidence. */
static int
fresh_stop_read_at(int directory, uint16_t vmid, uint64_t epoch,
    durable_session_stop &stop)
{
	char name[64];
	fresh_stop_name(vmid, epoch, name);
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	std::array<uint8_t, 80> wire{};
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)wire.size()))
		error = EPROTO;
	for (size_t offset = 0; error == 0 && offset < wire.size();) {
		ssize_t n = pread(fd, wire.data() + offset, wire.size() - offset, offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	durable_session_stop decoded{};
	decoded.vmid = dtraced_wire_get_u16(wire.data() + 4);
	decoded.epoch = dtraced_wire_get_u64(wire.data() + 8);
	memcpy(decoded.token.data(), wire.data() + 16, 16);
	memcpy(decoded.source_session.data(), wire.data() + 32, 16);
	if (error == 0 && (!fresh_stop_valid(decoded) ||
	    decoded.vmid != vmid || decoded.epoch != epoch ||
	    fresh_stop_bytes(decoded) != wire))
		error = EPROTO;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	stop = decoded;
	return (1);
}

/* A source incarnation may own only one ticket, including after commit or
 * claim.  The caller holds the cross-process handoff lock. */
static int
handoff_source_state_at(int directory,
    uint16_t vmid, uint64_t epoch, durable_handoff &record)
{
	durable_session_stop stopped{};
	int closed = fresh_stop_read_at(directory, vmid, epoch, stopped);
	if (closed != 0) {
		if (closed > 0)
			errno = ECANCELED;
		return (-1);
	}
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (-1);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (-1);
	}
	int error = 0, found = 0;
	std::array<uint8_t, 16> found_token{};
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		const char *name = entry->d_name;
		if (strncmp(name, ".handoff.", 9) != 0 ||
		    strcmp(name, ".handoff.lock") == 0)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		if (strlen(name) != 43 || name[41] != '.' ||
		    (name[42] != (char)handoff_phase::prepared &&
		    name[42] != (char)handoff_phase::committed &&
		    name[42] != (char)handoff_phase::reserved &&
		    name[42] != (char)handoff_phase::mutating &&
		    name[42] != (char)handoff_phase::claimed)) {
			error = EPROTO;
			break;
		}
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(name + 9 + i * 2, 2, octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		if (token == found_token)
			continue; /* Adjacent crash-state phase for this ticket. */
		durable_handoff current{};
		int phase = handoff_state_at(directory, token, current);
		if (phase < 0) {
			error = errno;
			break;
		}
		if (phase == 0)
			continue;
		if (current.source_vmid != vmid || current.source_epoch != epoch)
			continue;
		if (found != 0) {
			error = EBUSY;
			break;
		}
		found = phase;
		found_token = token;
		record = current;
		/* HT-C END */
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (found);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* The phase files are keyed by ticket, but a destination incarnation must
 * never be leased to two tickets.  The process lock serializes this scan
 * with every reservation and claim in the daemon directory. */
static bool
handoff_destination_available_at(int directory, const durable_handoff &ticket)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		const char *name = entry->d_name;
		if (strncmp(name, ".handoff.", 9) != 0 ||
		    strcmp(name, ".handoff.lock") == 0)
			continue;
		if (strlen(name) != 43 || name[41] != '.' ||
		    (name[42] != (char)handoff_phase::prepared &&
		    name[42] != (char)handoff_phase::committed &&
		    name[42] != (char)handoff_phase::reserved &&
		    name[42] != (char)handoff_phase::mutating &&
		    name[42] != (char)handoff_phase::claimed)) {
			error = EPROTO;
			break;
		}
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(name + 9 + i * 2, 2, octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		if (token == ticket.token)
			continue;
		durable_handoff other{};
		int phase = handoff_state_at(directory, token, other);
		if (phase < 0) {
			error = errno;
			break;
		}
		if ((phase == (int)handoff_phase::reserved ||
		    phase == (int)handoff_phase::mutating ||
		    phase == (int)handoff_phase::claimed) &&
		    other.destination_vmid == ticket.destination_vmid &&
		    other.destination_epoch == ticket.destination_epoch) {
			error = EBUSY;
			break;
		}
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}
/* HT-C END */

static bool
handoff_publish_at(int directory, const char *name, const uint8_t *data,
    size_t length)
{
	char temporary[46];
	/* The final name is authority. Never expose it until the complete
	 * checksummed inode has been fsynced. A crash before link leaves only a
	 * disposable temporary name; after link an exact retry reads the phase. */
	static const char hex[] = "0123456789abcdef";
	uint8_t nonce[16];
	arc4random_buf(nonce, sizeof(nonce));
	memcpy(temporary, ".handoff-tmp.", 13);
	for (size_t i = 0; i < sizeof(nonce); i++) {
		temporary[13 + i * 2] = hex[nonce[i] >> 4];
		temporary[14 + i * 2] = hex[nonce[i] & 15];
	}
	temporary[45] = '\0';
	int fd = openat(directory, temporary,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (false);
	size_t offset = 0;
	int error = 0;
	while (offset < length) {
		ssize_t n = write(fd, data + offset, length - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && linkat(directory, temporary,
	    directory, name, 0) != 0)
		error = errno;
	if (unlink_published_temporary_at(directory, temporary) != 0 &&
	    error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* Only callers holding the handoff process lock may replace an intent.
 * The old complete inode remains authoritative until the new one is synced
 * and atomically renamed into place. A lost directory fsync is retried by
 * reading the exact replacement. */
static bool
handoff_replace_at(int directory, const char *name, const uint8_t *data,
    size_t length)
{
	char temporary[46];
	static const char hex[] = "0123456789abcdef";
	uint8_t nonce[16];
	arc4random_buf(nonce, sizeof(nonce));
	memcpy(temporary, ".handoff-tmp.", 13);
	for (size_t i = 0; i < sizeof(nonce); i++) {
		temporary[13 + i * 2] = hex[nonce[i] >> 4];
		temporary[14 + i * 2] = hex[nonce[i] & 15];
	}
	temporary[45] = '\0';
	int fd = openat(directory, temporary,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (false);
	size_t offset = 0;
	int error = 0;
	while (offset < length) {
		ssize_t n = write(fd, data + offset, length - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && renameat(directory, temporary,
	    directory, name) != 0)
		error = errno;
	if (error != 0 && unlinkat(directory, temporary, 0) != 0 &&
	    errno != ENOENT)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/* HSL1 does not replace HTH2: it records a later source-side fact for the
 * exact committed ticket after the VMM lifetime and its ECBs have drained. */
static constexpr size_t source_release_wire_size = 188;

static void
source_release_name(const std::array<uint8_t, 16> &token, char name[43])
{
	char handoff[44];
	(void)handoff_name(token, handoff_phase::committed, handoff);
	memcpy(name, ".released.", 10);
	memcpy(name + 10, handoff + 9, 32);
	name[42] = '\0';
}

static void
source_attestation_name(const std::array<uint8_t, 16> &token,
    char name[43])
{
	char handoff[44];
	(void)handoff_name(token, handoff_phase::committed, handoff);
	memcpy(name, ".attested.", 10);
	memcpy(name + 10, handoff + 9, 32);
	name[42] = '\0';
}

static void
imported_attestation_name(const std::array<uint8_t, 16> &token,
    char name[43])
{
	char handoff[44];
	(void)handoff_name(token, handoff_phase::committed, handoff);
	memcpy(name, ".imported.", 10);
	memcpy(name + 10, handoff + 9, 32);
	name[42] = '\0';
}

static std::array<uint8_t, source_release_wire_size>
source_release_bytes(const durable_handoff &ticket)
{
	std::array<uint8_t, source_release_wire_size> wire{};
	memcpy(wire.data(), "HSL1", 4);
	const auto committed = handoff_bytes(ticket);
	memcpy(wire.data() + 4, committed.data(), committed.size());
	(void)SHA256(wire.data(), 156, wire.data() + 156);
	return (wire);
}

static int
source_release_read_at(int directory, const durable_handoff &ticket)
{
	char name[43];
	source_release_name(ticket.token, name);
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	const auto expected = source_release_bytes(ticket);
	std::array<uint8_t, source_release_wire_size> actual{};
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)actual.size()))
		error = EPROTO;
	for (size_t offset = 0; error == 0 && offset < actual.size();) {
		ssize_t n = pread(fd, actual.data() + offset,
		    actual.size() - offset, (off_t)offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && actual != expected)
		error = EPROTO;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

static int
attestation_read_named_at(int directory, const char *name,
    std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> &wire)
{
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)wire.size()))
		error = EPROTO;
	for (size_t offset = 0; error == 0 && offset < wire.size();) {
		ssize_t n = pread(fd, wire.data() + offset,
		    wire.size() - offset, (off_t)offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

static int
source_attestation_read_at(int directory, const durable_handoff &ticket,
    const uint8_t source_public[32], const uint8_t destination_public[32],
    std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> &attestation)
{
	char name[43];
	source_attestation_name(ticket.token, name);
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> wire{};
	int present = attestation_read_named_at(directory, name, wire);
	if (present != 1)
		return (present);
	const auto witness = source_release_bytes(ticket);
	if (!dtraced_release_attestation_verify(
	    source_public, destination_public, witness.data(), wire.data()))
		return (-1);
	attestation = wire;
	return (1);
}

static void source_gate_name(const std::array<uint8_t, 16> &, char[39]);
static int source_gate_read_at(int, const char *, durable_handoff &,
    std::array<uint8_t, 16> &);

bool
dir::record_source_release(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::committed)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase != (int)handoff_phase::committed ||
	    handoff_bytes(current) != handoff_bytes(ticket)) {
		if (phase >= 0)
			errno = phase == 0 ? ENOENT : EPROTO;
		return (false);
	}
	int present = source_release_read_at(this->dirfd, current);
	if (present < 0)
		return (false);
	if (present == 0) {
		char name[43];
		source_release_name(ticket.token, name);
		const auto wire = source_release_bytes(current);
		if (!handoff_publish_at(this->dirfd, name, wire.data(),
		    wire.size()))
			return (false);
	}
	/* HSL1 is durable and the VMM attestation has proved this epoch dead.
	 * Retire the now-obsolete HGI1 intent, including after a lost release
	 * acknowledgment. Historical committed tickets may have no HGI1. */
	char gate_name[39];
	source_gate_name(ticket.token, gate_name);
	durable_handoff intent{};
	std::array<uint8_t, 16> previous{};
	int gate_present = source_gate_read_at(this->dirfd, gate_name,
	    intent, previous);
	if (gate_present < 0)
		return (false);
	if (gate_present == 1) {
		if (intent.source_session != current.source_session ||
		    intent.source_vmid != current.source_vmid ||
		    intent.source_epoch != current.source_epoch) {
			errno = EPROTO;
			return (false);
		}
		if (unlinkat(this->dirfd, gate_name, 0) != 0)
			return (false);
	}
	return (fsync(this->dirfd) == 0);
}

int
dir::source_release_status(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::committed)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (-1);
	if (phase == 0 || phase == (int)handoff_phase::prepared) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	/* Later handoff phases add a destination without changing the source
	 * release witness. Reconstruct its committed HTH2 image exactly. */
	current.destination_vmid = 0;
	current.destination_epoch = 0;
	if (handoff_bytes(current) != handoff_bytes(ticket)) {
		errno = EPROTO;
		return (-1);
	}
	return (source_release_read_at(this->dirfd, current));
}

bool
dir::attest_source_release(const durable_handoff &ticket,
    EVP_PKEY *source_private, const uint8_t destination_public[32],
    std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> &attestation)
{
	attestation.fill(0);
	if (!handoff_valid(ticket, handoff_phase::committed) ||
	    source_private == nullptr || destination_public == nullptr) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if (phase == 0 || phase == (int)handoff_phase::prepared) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	current.destination_vmid = 0;
	current.destination_epoch = 0;
	if (handoff_bytes(current) != handoff_bytes(ticket)) {
		errno = EPROTO;
		return (false);
	}
	int released = source_release_read_at(this->dirfd, current);
	if (released != 1) {
		if (released == 0)
			errno = EBUSY;
		return (false);
	}
	std::array<uint8_t, 32> source_public{};
	size_t public_length = source_public.size();
	if (EVP_PKEY_base_id(source_private) != EVP_PKEY_ED25519 ||
	    EVP_PKEY_get_raw_public_key(source_private, source_public.data(),
	    &public_length) != 1 || public_length != source_public.size()) {
		errno = EINVAL;
		return (false);
	}
	int present = source_attestation_read_at(this->dirfd, current,
	    source_public.data(), destination_public, attestation);
	if (present < 0)
		return (false);
	if (present == 1)
		return (true);
	const auto witness = source_release_bytes(current);
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> signed_wire{};
	if (!dtraced_release_attestation_sign(source_private,
	    destination_public, witness.data(), signed_wire.data()))
		return (false);
	char name[43];
	source_attestation_name(ticket.token, name);
	if (!handoff_publish_at(this->dirfd, name, signed_wire.data(),
	    signed_wire.size()))
		return (false);
	attestation = signed_wire;
	return (true);
}

bool
dir::read_source_release_attestation(const durable_handoff &ticket,
    const uint8_t source_public[32], const uint8_t destination_public[32],
    std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> &attestation)
{
	attestation.fill(0);
	if (!handoff_valid(ticket, handoff_phase::committed) ||
	    source_public == nullptr || destination_public == nullptr) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if (phase == 0 || phase == (int)handoff_phase::prepared) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	current.destination_vmid = 0;
	current.destination_epoch = 0;
	if (handoff_bytes(current) != handoff_bytes(ticket)) {
		errno = EPROTO;
		return (false);
	}
	int released = source_release_read_at(this->dirfd, current);
	if (released != 1) {
		if (released == 0)
			errno = EBUSY;
		return (false);
	}
	int present = source_attestation_read_at(this->dirfd, current,
	    source_public, destination_public, attestation);
	if (present == 0)
		errno = ENOENT;
	return (present == 1);
}

bool
dir::verify_source_release_attestation(const durable_handoff &ticket,
    const uint8_t source_public[32], const uint8_t destination_public[32],
    const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE])
{
	if (!handoff_valid(ticket, handoff_phase::committed) ||
	    source_public == nullptr || destination_public == nullptr ||
	    wire == nullptr) {
		errno = EINVAL;
		return (false);
	}
	const auto expected = source_release_bytes(ticket);
	return (dtraced_release_attestation_verify(source_public,
	    destination_public, expected.data(), wire) != 0);
}

bool
dir::decode_source_release_attestation(
    const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE],
    const uint8_t source_public[32], const uint8_t destination_public[32],
    const uint8_t expected_token[16],
    const uint8_t expected_checkpoint_digest[32], durable_handoff &ticket)
{
	if (wire == nullptr || source_public == nullptr ||
	    destination_public == nullptr || expected_token == nullptr ||
	    expected_checkpoint_digest == nullptr) {
		errno = EINVAL;
		return (false);
	}
	/* HSA1 carries HSL1 at offset 72 and its canonical HTH2 at 76.
	 * Neither checksum grants authority; verify the signature below. */
	const uint8_t *hsl = wire + 72;
	const uint8_t *hth = hsl + 4;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	if (!dtraced_release_hsl_valid(hsl) ||
	    memcmp(hth, "HTH2", 4) != 0 ||
	    SHA256(hth, 120, hash) == nullptr ||
	    CRYPTO_memcmp(hash, hth + 120, sizeof(hash)) != 0 ||
	    CRYPTO_memcmp(hth + 4, expected_token, 16) != 0 ||
	    CRYPTO_memcmp(hth + 46, expected_checkpoint_digest, 32) != 0) {
		errno = EPROTO;
		return (false);
	}
	durable_handoff decoded{};
	memcpy(decoded.token.data(), hth + 4, 16);
	memcpy(decoded.source_session.data(), hth + 20, 16);
	decoded.source_vmid = (uint16_t)hth[36] | (uint16_t)hth[37] << 8;
	for (unsigned i = 0; i < 8; i++) {
		decoded.source_epoch |= (uint64_t)hth[38 + i] << (8 * i);
		decoded.destination_epoch |= (uint64_t)hth[80 + i] << (8 * i);
	}
	memcpy(decoded.checkpoint_digest.data(), hth + 46, 32);
	decoded.destination_vmid = (uint16_t)hth[78] |
	    (uint16_t)hth[79] << 8;
	memcpy(decoded.transfer_digest.data(), hth + 88, 32);
	const auto canonical = handoff_bytes(decoded);
	if (!handoff_valid(decoded, handoff_phase::committed) ||
	    CRYPTO_memcmp(canonical.data(), hth,
	    handoff_record_size) != 0 ||
	    !verify_source_release_attestation(decoded, source_public,
	    destination_public, wire)) {
		errno = EPROTO;
		return (false);
	}
	ticket = decoded;
	return (true);
}

int
dir::read_imported_source_release(const uint8_t source_public[32],
    const uint8_t destination_public[32], const uint8_t expected_token[16],
    const uint8_t expected_checkpoint_digest[32], durable_handoff &ticket)
{
	if (source_public == nullptr || destination_public == nullptr ||
	    expected_token == nullptr || expected_checkpoint_digest == nullptr) {
		errno = EINVAL;
		return (-1);
	}
	std::array<uint8_t, 16> token{};
	memcpy(token.data(), expected_token, token.size());
	char name[43];
	if (token == std::array<uint8_t, 16>{}) {
		errno = EINVAL;
		return (-1);
	}
	imported_attestation_name(token, name);
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> wire{};
	int present = attestation_read_named_at(this->dirfd, name, wire);
	if (present != 1)
		return (present);
	return (decode_source_release_attestation(wire.data(),
	    source_public, destination_public, expected_token,
	    expected_checkpoint_digest, ticket) ? 1 : -1);
}

static bool handoff_write_at(int, const durable_handoff &, handoff_phase);

/* Phase-file reading can match a foreign release's exact committed source
 * cut without treating this checksum as a signature. Startup and every
 * reservation must verify HSA1 against the configured pinned keys. */
static int
imported_release_cut_status_at(int directory,
    const durable_handoff &source)
{
	char name[43];
	imported_attestation_name(source.token, name);
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> wire{};
	int present = attestation_read_named_at(directory, name, wire);
	if (present != 1)
		return (present);
	const auto expected = handoff_bytes(source);
	if (!dtraced_release_hsl_valid(wire.data() + 72) ||
	    memcmp(wire.data() + 76, expected.data(), expected.size()) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (1);
}

static int
local_source_release_status_locked(int directory,
    const durable_handoff &ticket)
{
	durable_handoff committed = ticket;
	committed.destination_vmid = 0;
	committed.destination_epoch = 0;
	return (source_release_read_at(directory, committed));
}

/* A signed foreign release is the only substitute for the local HSL1
 * witness. Check the entire committed source cut, not just the checkpoint
 * digest, before it can become ticket authority. Caller holds the ticket
 * process lock. */
static int
imported_source_release_status_locked(int directory, const release_keys &keys,
    const durable_handoff &expected)
{
	if (!keys.configured()) {
		errno = EACCES;
		return (-1);
	}
	char name[43];
	imported_attestation_name(expected.token, name);
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> wire{};
	int present = attestation_read_named_at(directory, name, wire);
	if (present != 1)
		return (present);
	durable_handoff released{};
	if (!dir::decode_source_release_attestation(wire.data(),
	    keys.peer_public().data(), keys.own_public().data(),
	    expected.token.data(), expected.checkpoint_digest.data(), released))
		return (-1);
	durable_handoff source = expected;
	source.destination_vmid = 0;
	source.destination_epoch = 0;
	if (handoff_bytes(source) != handoff_bytes(released)) {
		errno = EPROTO;
		return (-1);
	}
	return (1);
}

/* A private foreign import may be prepared only while the destination
 * still has the exact signed source-release proof. The phase-file reader's
 * embedded HSL1 comparison is deliberately insufficient authority. */
static bool
handoff_release_authority_locked(int directory, state *control,
    const durable_handoff &ticket)
{
	int local = local_source_release_status_locked(directory, ticket);
	if (local == 1)
		return (true);
	if (local < 0)
		return (false);
	if (control == nullptr || !control->is_control_machine()) {
		errno = EBUSY;
		return (false);
	}
	int imported = imported_source_release_status_locked(directory,
	    control->handoff_keys, ticket);
	if (imported == 0)
		errno = EBUSY;
	return (imported == 1);
}

bool
dir::adopt_imported_source_release(const std::array<uint8_t, 16> &token,
    const uint8_t checkpoint_digest[32])
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this || checkpoint_digest == nullptr ||
	    token == std::array<uint8_t, 16>{}) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	char name[43];
	imported_attestation_name(token, name);
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> wire{};
	int present = attestation_read_named_at(this->dirfd, name, wire);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	durable_handoff released{};
	if (!this->state->handoff_keys.configured()) {
		errno = EACCES;
		return (false);
	}
	if (!decode_source_release_attestation(wire.data(),
	    this->state->handoff_keys.peer_public().data(),
	    this->state->handoff_keys.own_public().data(), token.data(),
	    checkpoint_digest, released))
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, token, current);
	if (phase < 0)
		return (false);
	if (phase == (int)handoff_phase::committed) {
		if (handoff_bytes(current) != handoff_bytes(released)) {
			errno = EPROTO;
			return (false);
		}
		return (true);
	}
	if (phase != 0) {
		errno = EBUSY;
		return (false);
	}
	return (handoff_write_at(this->dirfd, released,
	    handoff_phase::committed));
}

bool
dir::stage_imported_source_release(
    const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE],
    const uint8_t source_public[32], const uint8_t destination_public[32],
    const uint8_t expected_token[16],
    const uint8_t expected_checkpoint_digest[32])
{
	durable_handoff ticket{};
	if (!decode_source_release_attestation(wire, source_public,
	    destination_public, expected_token, expected_checkpoint_digest,
	    ticket))
		return (false);
	char name[43];
	imported_attestation_name(ticket.token, name);
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> existing{};
	int present = attestation_read_named_at(this->dirfd, name, existing);
	if (present < 0)
		return (false);
	if (present == 1) {
		durable_handoff previous{};
		if (!decode_source_release_attestation(existing.data(),
		    source_public, destination_public, expected_token,
		    expected_checkpoint_digest, previous))
			return (false);
		if (CRYPTO_memcmp(existing.data(), wire,
		    existing.size()) != 0) {
			errno = EPROTO;
			return (false);
		}
		return (true);
	}
	durable_handoff local{};
	int phase = handoff_state_at(this->dirfd, ticket.token, local);
	if (phase < 0)
		return (false);
	if (phase != 0) {
		errno = EBUSY;
		return (false);
	}
	return (handoff_publish_at(this->dirfd, name, wire,
	    DTRACED_RELEASE_ATTESTED_SIZE));
}
/* HT-C END */

/* HSA1 can arrive before the destination ticket. Once present, every
 * restart must recheck its signature against the pinned host keys and its
 * canonical name. A later local ticket must describe that same source cut. */
static bool
imported_attestations_audit_locked(int directory, const release_keys &keys)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		const char *name = entry->d_name;
		if (strncmp(name, ".imported.", 10) != 0)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		if (strlen(name) != 42 || !keys.configured()) {
			error = !keys.configured() ? EACCES : EPROTO;
			break;
		}
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(name + 10 + i * 2, 2, octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		char canonical[43];
		imported_attestation_name(token, canonical);
		if (strcmp(name, canonical) != 0) {
			error = EPROTO;
			break;
		}
		std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> wire{};
		if (attestation_read_named_at(directory, name, wire) != 1) {
			error = errno != 0 ? errno : EPROTO;
			break;
		}
		const uint8_t *checkpoint_digest = wire.data() + 76 + 46;
		durable_handoff released{};
		if (!dir::decode_source_release_attestation(wire.data(),
		    keys.peer_public().data(), keys.own_public().data(),
		    token.data(), checkpoint_digest, released)) {
			error = errno;
			break;
		}
		durable_handoff current{};
		int phase = handoff_state_at(directory, token, current);
		if (phase < 0) {
			error = errno;
			break;
		}
		if (phase == 0)
			continue;
		if (phase == (int)handoff_phase::prepared) {
			error = EPROTO;
			break;
		}
		current.destination_vmid = 0;
		current.destination_epoch = 0;
		if (handoff_bytes(current) != handoff_bytes(released)) {
			error = EPROTO;
			break;
		}
		/* HT-C END */
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
static bool
handoff_write_at(int directory, const durable_handoff &record,
    handoff_phase phase)
{
	char name[44];
	if (!handoff_valid(record, phase) ||
	    !handoff_name(record.token, phase, name)) {
		errno = EINVAL;
		return (false);
	}
	const auto data = handoff_bytes(record);
	return (handoff_publish_at(directory, name, data.data(), data.size()));
}

static bool
handoff_remove_at(int directory, const std::array<uint8_t, 16> &token,
    handoff_phase phase)
{
	char name[44];
	if (!handoff_name(token, phase, name))
		return (false);
	if (unlinkat(directory, name, 0) != 0 && errno != ENOENT)
		return (false);
	return (fsync(directory) == 0);
}

/* HGI1 is an intent, not a completed handoff. It must reach stable storage
 * before the kernel can hide an epoch; a retry can then identify the exact
 * token after a daemon restart. The last owner token is the kernel CAS input. */
static constexpr size_t source_gate_wire_size = 94;

static void
source_gate_name(const std::array<uint8_t, 16> &token, char name[39])
{
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".gate.", 6);
	for (size_t i = 0; i < token.size(); i++) {
		name[6 + i * 2] = hex[token[i] >> 4];
		name[7 + i * 2] = hex[token[i] & 15];
	}
	name[38] = '\0';
}

static std::array<uint8_t, source_gate_wire_size>
source_gate_bytes(const durable_handoff &ticket,
    const std::array<uint8_t, 16> &previous)
{
	std::array<uint8_t, source_gate_wire_size> wire{};
	memcpy(wire.data(), "HGI1", 4);
	memcpy(wire.data() + 4, ticket.token.data(), 16);
	memcpy(wire.data() + 20, ticket.source_session.data(), 16);
	dtraced_wire_put_u16(wire.data() + 36, ticket.source_vmid);
	dtraced_wire_put_u64(wire.data() + 38, ticket.source_epoch);
	memcpy(wire.data() + 46, previous.data(), previous.size());
	(void)SHA256(wire.data(), 62, wire.data() + 62);
	return (wire);
}

/* Return -1 for an invalid/unreadable record, 0 for absent, 1 for exact. */
static int
source_gate_read_at(int directory, const char *name,
    durable_handoff &ticket, std::array<uint8_t, 16> &previous)
{
	if (strlen(name) != 38 || strncmp(name, ".gate.", 6) != 0) {
		errno = EPROTO;
		return (-1);
	}
	std::array<uint8_t, 16> named_token{};
	for (size_t i = 0; i < named_token.size(); i++) {
		uint64_t octet;
		if (!parse_hex(name + 6 + i * 2, 2, octet)) {
			errno = EPROTO;
			return (-1);
		}
		named_token[i] = (uint8_t)octet;
	}
	char canonical[39];
	source_gate_name(named_token, canonical);
	if (strcmp(name, canonical) != 0) {
		errno = EPROTO;
		return (-1);
	}
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	std::array<uint8_t, source_gate_wire_size> wire{};
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)wire.size()))
		error = EPROTO;
	for (size_t offset = 0; error == 0 && offset < wire.size();) {
		ssize_t n = pread(fd, wire.data() + offset,
		    wire.size() - offset, (off_t)offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	durable_handoff decoded{};
	std::array<uint8_t, 16> decoded_previous{};
	if (error == 0) {
		memcpy(decoded.token.data(), wire.data() + 4, 16);
		memcpy(decoded.source_session.data(), wire.data() + 20, 16);
		decoded.source_vmid = dtraced_wire_get_u16(wire.data() + 36);
		decoded.source_epoch = dtraced_wire_get_u64(wire.data() + 38);
		memcpy(decoded_previous.data(), wire.data() + 46, 16);
		uint8_t digest[SHA256_DIGEST_LENGTH];
		if (memcmp(wire.data(), "HGI1", 4) != 0 ||
		    decoded.token != named_token ||
		    decoded.token == std::array<uint8_t, 16>{} ||
		    decoded.source_session == std::array<uint8_t, 16>{} ||
		    decoded.source_vmid == 0 ||
		    decoded.source_vmid >= HYPERTRACE_MAX_VMS ||
		    decoded.source_epoch == 0 ||
		    SHA256(wire.data(), 62, digest) == nullptr ||
		    CRYPTO_memcmp(digest, wire.data() + 62,
		    sizeof(digest)) != 0)
			error = EPROTO;
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	ticket = decoded;
	previous = decoded_previous;
	return (1);
}
/* HT-C END */

/* Scan under the outbound process lock, including records for other tokens.
 * A second ticket may not claim an epoch while an older intent is unresolved. */
static int
source_gate_for_epoch_at(int directory, uint16_t vmid, uint64_t epoch,
    const std::array<uint8_t, 16> &token, durable_handoff &found,
    std::array<uint8_t, 16> &previous)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (-1);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (-1);
	}
	int error = 0, present = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		if (strncmp(entry->d_name, ".gate.", 6) != 0)
			continue;
		durable_handoff candidate{};
		std::array<uint8_t, 16> candidate_previous{};
		if (source_gate_read_at(directory, entry->d_name,
		    candidate, candidate_previous) != 1) {
			error = errno == ENOENT ? EPROTO : errno;
			break;
		}
		if (candidate.source_vmid != vmid ||
		    candidate.source_epoch != epoch)
			continue;
		if (candidate.token != token || present != 0) {
			error = EBUSY;
			break;
		}
		found = candidate;
		previous = candidate_previous;
		present = 1;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (present);
}

static int
source_gate_query_fd(int fd, uint16_t vmid, uint64_t epoch,
    hypertrace_epoch_gate &gate)
{
	gate = {};
	gate.vmid = vmid;
	gate.epoch = epoch;
	if (ioctl(fd, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &gate) != 0)
		return (-1);
	if (gate.vmid != vmid || gate.epoch != epoch || gate.suspended > 1 ||
	    gate.reserved[0] != 0 || gate.reserved[1] != 0 ||
	    gate.reserved[2] != 0 || gate.reserved2 != 0 ||
	    memcmp(gate.previous_token,
	    std::array<uint8_t, 16>{}.data(), 16) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

bool
dir::begin_fresh_session_stop(const durable_session_stop &stop)
{
	if (!fresh_stop_valid(stop)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_session_stop existing{};
	int present = fresh_stop_read_at(this->dirfd, stop.vmid, stop.epoch, existing);
	if (present < 0)
		return (false);
	if (present == 1 && fresh_stop_bytes(existing) != fresh_stop_bytes(stop)) {
		errno = ESTALE;
		return (false);
	}
	if (present == 0) {
		durable_handoff continuity{};
		int phase = handoff_source_state_at(this->dirfd, stop.vmid,
		    stop.epoch, continuity);
		if (phase != 0) {
			if (phase > 0)
				errno = EBUSY;
			return (false);
		}
	}
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	hypertrace_epoch_gate gate{};
	int error = source_gate_query_fd(fd, stop.vmid, stop.epoch, gate) != 0 ? errno : 0;
	if (error == 0 && (gate.suspended != 1 ||
	    memcmp(gate.token, stop.token.data(), 16) != 0))
		error = EBUSY;
	if (error == 0) {
		char name[64];
		fresh_stop_name(stop.vmid, stop.epoch, name);
		const auto wire = fresh_stop_bytes(stop);
		if (present ? fsync(this->dirfd) != 0 :
		    !handoff_publish_at(this->dirfd, name, wire.data(), wire.size()))
			error = errno;
	}
	/* A failed readback leaves the durable fence in place for recovery. */
	if (error == 0 && source_gate_query_fd(fd, stop.vmid, stop.epoch, gate) != 0)
		error = errno;
	if (error == 0 && (gate.suspended != 1 ||
	    memcmp(gate.token, stop.token.data(), 16) != 0))
		error = EBUSY;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0)
		errno = error;
	return (error == 0);
}

/* Only the attested destination may release its freshly owned gate. Source
 * stop fences are permanent; neither they nor continuity gates are resumable
 * through this operation. The kernel retains the token after resume, making
 * a lost response retry distinguishable from another operation's gate. */
bool
dir::release_fresh_session_gate(const durable_session_stop &destination)
{
	if (!fresh_stop_valid(destination)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff active{}, intent{};
	std::array<uint8_t, 16> previous{};
	int phase = handoff_source_state_at(this->dirfd, destination.vmid,
	    destination.epoch, active);
	if (phase != 0) {
		if (phase > 0) errno = EBUSY;
		return (false);
	}
	int present = source_gate_for_epoch_at(this->dirfd, destination.vmid,
	    destination.epoch, destination.token, intent, previous);
	if (present != 0) {
		if (present > 0) errno = EBUSY;
		return (false);
	}
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	hypertrace_epoch_gate gate{};
	int error = source_gate_query_fd(fd, destination.vmid, destination.epoch, gate) != 0 ? errno : 0;
	if (error == 0 && memcmp(gate.token, destination.token.data(), 16) != 0)
		error = ESTALE;
	if (error == 0 && gate.suspended != 0) {
		hypertrace_epoch_gate resume{};
		resume.vmid = destination.vmid;
		resume.epoch = destination.epoch;
		memcpy(resume.token, destination.token.data(), 16);
		if (ioctl(fd, HYPERTRACE_IOC_EPOCH_RESUME, &resume) != 0)
			error = errno;
	}
	if (error == 0 && source_gate_query_fd(fd, destination.vmid, destination.epoch, gate) != 0)
		error = errno;
	if (error == 0 && (gate.suspended != 0 ||
	    memcmp(gate.token, destination.token.data(), 16) != 0))
		error = ESTALE;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) errno = error;
	return (error == 0);
}

int
dir::fresh_session_stop_for_vm(uint16_t vmid, uint64_t epoch,
    durable_session_stop &stop)
{
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_session_stop found{};
	int present = fresh_stop_read_at(this->dirfd, vmid, epoch, found);
	if (present < 0 || fsync(this->dirfd) != 0)
		return (-1);
	if (present)
		stop = found;
	return (present);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
dir::source_gate_begin(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff active{};
	int phase = handoff_source_state_at(this->dirfd,
	    ticket.source_vmid, ticket.source_epoch, active);
	if (phase < 0)
		return (false);
	if (phase != 0 && (phase != (int)handoff_phase::prepared ||
	    !handoff_same_source(active, ticket))) {
		errno = EBUSY;
		return (false);
	}
	durable_handoff intent{};
	std::array<uint8_t, 16> previous{};
	int present = source_gate_for_epoch_at(this->dirfd,
	    ticket.source_vmid, ticket.source_epoch, ticket.token,
	    intent, previous);
	if (present < 0)
		return (false);
	if (present == 1 && intent.source_session != ticket.source_session) {
		errno = EPROTO;
		return (false);
	}
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	hypertrace_epoch_gate gate{};
	int error = source_gate_query_fd(fd,
	    ticket.source_vmid, ticket.source_epoch, gate) != 0 ? errno : 0;
	if (error == 0 && present == 0) {
		if (phase != 0 || gate.suspended != 0 ||
		    memcmp(gate.token, ticket.token.data(), 16) == 0)
			error = phase != 0 ? EPROTO :
		    gate.suspended != 0 ? EBUSY : EALREADY;
		else {
			memcpy(previous.data(), gate.token, previous.size());
			char name[39];
			source_gate_name(ticket.token, name);
			const auto wire = source_gate_bytes(ticket, previous);
			if (!handoff_publish_at(this->dirfd, name,
			    wire.data(), wire.size()))
				error = errno;
		}
	}
	if (error == 0 && gate.suspended != 0)
		error = memcmp(gate.token, ticket.token.data(), 16) == 0 ?
		    0 : EBUSY;
	else if (error == 0 && memcmp(gate.token, previous.data(), 16) != 0)
		error = ESTALE;
	if (error == 0 && gate.suspended == 0) {
		hypertrace_epoch_gate suspend{};
		suspend.vmid = ticket.source_vmid;
		suspend.epoch = ticket.source_epoch;
		memcpy(suspend.token, ticket.token.data(), 16);
		memcpy(suspend.previous_token, previous.data(), 16);
		if (ioctl(fd, HYPERTRACE_IOC_EPOCH_SUSPEND, &suspend) != 0)
			error = errno;
		else if (source_gate_query_fd(fd, ticket.source_vmid,
		    ticket.source_epoch, gate) != 0)
			error = errno;
		else if (gate.suspended != 1 ||
		    memcmp(gate.token, ticket.token.data(), 16) != 0)
			error = EPROTO;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/* An aborted cut can never be reused: the kernel remembers its token after
 * RESUME. Retire its drain observations as well, including on an exact retry
 * after a crash between removal of HGI1 and the directory sync. Only names
 * in this ticket's canonical HGD1 namespace are owned by this operation. */
static bool
source_drain_abort_cleanup_at(int directory,
    const std::array<uint8_t, 16> &token)
{
	static const char hex[] = "0123456789abcdef";
	char prefix[40];
	memcpy(prefix, ".drain.", 7);
	for (size_t i = 0; i < token.size(); i++) {
		prefix[7 + 2 * i] = hex[token[i] >> 4];
		prefix[8 + 2 * i] = hex[token[i] & 15];
	}
	prefix[39] = '.';
	int scanfd = openat(directory, ".",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	std::vector<std::string> names;
	int error = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		if (strlen(entry->d_name) != 104 ||
		    memcmp(entry->d_name, prefix, sizeof(prefix)) != 0)
			continue;
		bool canonical = true;
		for (size_t i = 40; i < 104; i++) {
			if (strchr(hex, entry->d_name[i]) == nullptr) {
				canonical = false;
				break;
			}
		}
		if (canonical)
			names.emplace_back(entry->d_name);
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	for (const auto &name : names) {
		if (unlinkat(directory, name.c_str(), 0) != 0 &&
		    errno != ENOENT)
			return (false);
	}
	return (true);
}

bool
dir::source_gate_abort(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff active{};
	int phase = handoff_source_state_at(this->dirfd,
	    ticket.source_vmid, ticket.source_epoch, active);
	if (phase < 0)
		return (false);
	if (phase != 0) {
		errno = EBUSY; /* The durable ticket must be aborted first. */
		return (false);
	}
	char name[39];
	source_gate_name(ticket.token, name);
	durable_handoff intent{};
	std::array<uint8_t, 16> previous{};
	int present = source_gate_read_at(this->dirfd, name, intent, previous);
	if (present < 0)
		return (false);
	if (present == 1 && (intent.source_session != ticket.source_session ||
	    intent.source_vmid != ticket.source_vmid ||
	    intent.source_epoch != ticket.source_epoch)) {
		errno = EPROTO;
		return (false);
	}
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	hypertrace_epoch_gate gate{};
	int error = source_gate_query_fd(fd,
	    ticket.source_vmid, ticket.source_epoch, gate) != 0 ? errno : 0;
	if (error == 0 && present == 0 && gate.suspended != 0)
		error = memcmp(gate.token, ticket.token.data(), 16) == 0 ?
		    EPROTO : EBUSY; /* Never resume under another ticket's gate. */
	if (error == 0 && present == 1 && gate.suspended != 0) {
		if (memcmp(gate.token, ticket.token.data(), 16) != 0)
			error = ESTALE;
		else {
			hypertrace_epoch_gate resume{};
			resume.vmid = ticket.source_vmid;
			resume.epoch = ticket.source_epoch;
			memcpy(resume.token, ticket.token.data(), 16);
			if (ioctl(fd, HYPERTRACE_IOC_EPOCH_RESUME,
			    &resume) != 0)
				error = errno;
			else if (source_gate_query_fd(fd, ticket.source_vmid,
			    ticket.source_epoch, gate) != 0)
				error = errno;
		}
	}
	if (error == 0 && present == 1 &&
	    (gate.suspended != 0 ||
	    (memcmp(gate.token, ticket.token.data(), 16) != 0 &&
	    memcmp(gate.token, previous.data(), 16) != 0)))
		error = ESTALE;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && present == 1 &&
	    unlinkat(this->dirfd, name, 0) != 0)
		error = errno;
	if (error == 0 && !source_drain_abort_cleanup_at(this->dirfd,
	    ticket.token))
		error = errno;
	if (error == 0 && fsync(this->dirfd) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

static bool list_deliveries_at(int,
    std::vector<durable_delivery_state> &);

/* Build the complete source member while the outbound ticket lock fixes the
 * journal cut. An empty cut stays the legacy empty HTX1 so it needs no
 * destination import. Any retained outbound state is bound into HJM1. */
int
dir::source_journal_transfer_wire_locked(const durable_handoff &ticket,
    std::vector<uint8_t> &result)
{
	result.clear();
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    this->state->inbounddir == nullptr ||
	    this->state->inbounddir == this ||
	    !handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (-1);
	}
	std::vector<uint8_t> ingress_manifest, archive, manifest, candidate;
	std::vector<std::vector<uint8_t>> ingress_frames, frames;
	int ingress = this->state->inbounddir->
	    host_ingress_transfer_bundle_locked(ticket, *this,
	    ingress_manifest, ingress_frames, true);
	if (ingress < 0)
		return (-1);
	source_journal_cut cut;
	if (!source_journal_cut_locked(ticket, cut))
		return (-1);
	bool journal = !cut.deliveries.empty() || !cut.kills.empty() ||
	    !cut.cleanups.empty();
	if (journal) {
		if (!encode_source_journal_archive(ticket, cut, archive) ||
		    !dtraced_transfer_journal_wrap(ticket.token.data(),
		    ingress_manifest, ingress_frames, archive, manifest, frames))
			return (-1);
	} else {
		manifest.swap(ingress_manifest);
		frames.swap(ingress_frames);
	}
	if (!dtraced_transfer_wire_build(ticket.token.data(), manifest,
	    frames, candidate))
		return (-1);
	result.swap(candidate);
	return ((ingress != 0 ? 1 : 0) | (journal ? 2 : 0));
}

/* A source export and PREPARE must observe the same owned, suspended VMM
 * epoch gate while holding the handoff process and publication locks. */
static bool
source_gate_suspended_locked(int directory, const durable_handoff &ticket)
{
	durable_handoff intent{};
	std::array<uint8_t, 16> previous{};
	int present = source_gate_for_epoch_at(directory,
	    ticket.source_vmid, ticket.source_epoch, ticket.token,
	    intent, previous);
	if (present < 0)
		return (false);
	if (present != 1 || intent.source_session != ticket.source_session) {
		errno = present == 0 ? EBUSY : EPROTO;
		return (false);
	}
	int gatefd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (gatefd < 0)
		return (false);
	hypertrace_epoch_gate gate{};
	int error = source_gate_query_fd(gatefd,
	    ticket.source_vmid, ticket.source_epoch, gate) != 0 ? errno : 0;
	if (error == 0 && (gate.suspended != 1 ||
	    memcmp(gate.token, ticket.token.data(), 16) != 0))
		error = ESTALE;
	if (close(gatefd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

bool
dir::source_journal_transfer_wire_export(const durable_handoff &ticket,
    std::vector<uint8_t> &result, bool require_source_gate)
{
	result.clear();
	if (!handoff_valid(ticket, handoff_phase::prepared) ||
	    this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if (phase != 0 && (phase != (int)handoff_phase::prepared ||
	    !handoff_same_source(current, ticket))) {
		errno = EBUSY;
		return (false);
	}
	if (phase == 0) {
		int source_phase = handoff_source_state_at(this->dirfd,
		    ticket.source_vmid, ticket.source_epoch, current);
		if (source_phase < 0)
			return (false);
		if (source_phase != 0) {
			errno = EBUSY;
			return (false);
		}
	}
	if (require_source_gate &&
	    !source_gate_suspended_locked(this->dirfd, ticket))
		return (false);
	std::vector<uint8_t> candidate;
	if (source_journal_transfer_wire_locked(ticket, candidate) < 0)
		return (false);
	if (phase == (int)handoff_phase::prepared &&
	    CRYPTO_memcmp(candidate.data() + candidate.size() -
	    SHA256_DIGEST_LENGTH, current.transfer_digest.data(),
	    SHA256_DIGEST_LENGTH) != 0) {
		errno = EPROTO;
		return (false);
	}
	result.swap(candidate);
	return (true);
}

bool
dir::prepare_handoff(const durable_handoff &ticket, bool require_source_gate)
{
	if (!handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if (phase != 0) {
		if (phase == (int)handoff_phase::prepared &&
		    handoff_same_source(current, ticket)) {
			/* A lost PREPARE reply is an exact retry only while the
			 * source still owns the suspended gate and the saved transfer
			 * still describes this cut. COMMIT applies the same digest check. */
			if (require_source_gate &&
			    !source_gate_suspended_locked(this->dirfd, ticket))
				return (false);
			if (this->state != nullptr &&
			    this->state->is_control_machine()) {
				std::vector<uint8_t> bundle;
				if (source_journal_transfer_wire_locked(current,
				    bundle) < 0)
					return (false);
				if (bundle.size() < SHA256_DIGEST_LENGTH ||
				    CRYPTO_memcmp(bundle.data() + bundle.size() -
				    SHA256_DIGEST_LENGTH,
				    current.transfer_digest.data(),
				    SHA256_DIGEST_LENGTH) != 0) {
					errno = EPROTO;
					return (false);
				}
			}
			return (fsync(this->dirfd) == 0);
		}
		errno = phase == (int)handoff_phase::prepared ? EPROTO : EALREADY;
		return (false);
	}
	durable_handoff active{};
	int source_phase = handoff_source_state_at(this->dirfd,
	    ticket.source_vmid, ticket.source_epoch, active);
	if (source_phase < 0)
		return (false);
	if (source_phase != 0) {
		errno = EBUSY;
		return (false);
	}
	/* A source may publish only while its journaled HGI1 owner still holds
	 * the live kernel epoch gate. Keep this check under the same process and
	 * publish locks as the HTH2 write, so an ABORT cannot resume between
	 * validation and publication. Authenticated callers require this by
	 * default; journal-only fixtures opt out for historical records. */
	if (require_source_gate &&
	    !source_gate_suspended_locked(this->dirfd, ticket))
		return (false);
	/* A pending host-to-guest receipt can still have a sender blocked before
	 * bhyve's queue ACK.  Do not publish a checkpoint cut around that send. */
	std::vector<durable_delivery_state> deliveries;
	if (!list_deliveries_at(this->dirfd, deliveries))
		return (false);
	for (const durable_delivery_state &entry : deliveries) {
		if (entry.record.scope != 0 ||
		    entry.record.vmid != ticket.source_vmid ||
		    entry.record.epoch != ticket.source_epoch)
			continue;
		if (entry.phase == delivery_phase::pending) {
			errno = EBUSY;
			return (false);
		}
		/* A real checkpoint cannot transfer an accepted host delivery if
		 * its source session is outside the ticket or its original ELF is
		 * gone. Audit under the handoff process lock before HTH2 is
		 * published; the portable journal export must repeat this check
		 * when it captures the actual bytes. */
		if (require_source_gate &&
		    (entry.phase == delivery_phase::accepted ||
		    entry.phase == delivery_phase::installed)) {
			if (entry.record.session_id != ticket.source_session ||
			    (entry.record.journal_version != 4 &&
		    entry.record.journal_version != 5)) {
				errno = EOPNOTSUPP;
				return (false);
			}
			int revoked = source_revoked_at(this->dirfd,
			    entry.record.source_id.data(), ticket.source_vmid,
			    ticket.source_epoch);
			if (revoked < 0)
				return (false);
			if (revoked == 0) {
				int verified = verify_host_delivery_payload(entry.record);
				if (verified != 1) {
					if (verified == 0)
						errno = EBUSY;
					return (false);
				}
			}
		}
	}
	/* A cleanup accepted by the control tool but not yet queued by bhyve
	 * must survive a daemon crash and cannot be omitted from the cut. */
	std::vector<durable_cleanup> cleanups;
	if (!list_pending_cleanups_at(this->dirfd, cleanups))
		return (false);
	for (const durable_cleanup &cleanup : cleanups) {
		if (cleanup.vmid == ticket.source_vmid &&
		    cleanup.epoch == ticket.source_epoch) {
			errno = EBUSY;
			return (false);
		}
	}
	/* Rebuild the exact HTX1 source member under the same outbound locks
	 * used for ticket publication. An accepted cohort still needs a
	 * destination execution lease before PREPARE may publish the ticket. */
	if (this->state != nullptr && this->state->is_control_machine()) {
		if (this->state->inbounddir == nullptr) {
			errno = EINVAL;
			return (false);
		}
		std::vector<uint8_t> bundle;
		int transfer_needed = source_journal_transfer_wire_locked(ticket,
		    bundle);
		if (transfer_needed < 0)
			return (false);
		if (memcmp(ticket.transfer_digest.data(),
		    bundle.data() + bundle.size() - SHA256_DIGEST_LENGTH,
		    SHA256_DIGEST_LENGTH) != 0) {
			errno = EPROTO;
			return (false);
		}
		if ((transfer_needed & 1) != 0) {
			std::vector<uint8_t> manifest;
			std::vector<std::vector<uint8_t>> frames;
			if (this->state->inbounddir->
			    host_ingress_transfer_bundle_locked(ticket, *this,
			    manifest, frames, true) < 0)
				return (false);
			if (require_source_gate &&
			    !source_drain_receipts_complete_at(this->dirfd,
			    ticket, manifest))
				return (false);
			/* HCR1 proves execution and HGD1 proves drained output, but
			 * neither transfers the enabled program or derived delivery.
			 * Keep PREPARE closed
			 * until the accepted ELF and consumer state have a transfer lease. */
			errno = EOPNOTSUPP;
			return (false);
		}
		if ((transfer_needed & 2) != 0) {
			/* A journal-only HTX1 is now matched exactly, but a source
			 * must not release until nonempty restore is recoverable. */
			errno = EOPNOTSUPP;
			return (false);
		}
	}
	std::vector<durable_kill> kills;
	if (!list_kills_at(this->dirfd, kills))
		return (false);
	for (const durable_kill &kill : kills) {
		if (kill.vmid != ticket.source_vmid ||
		    kill.epoch != ticket.source_epoch)
			continue;
		char ack_name[73];
		if (!kill_applied_name(kill, ack_name))
			return (false);
		if (kill_record_status_at(this->dirfd, ack_name) != 0) {
			if (errno == ENOENT)
				errno = EBUSY;
			return (false);
		}
	}
	if (require_source_gate) {
		source_journal_cut journal;
		std::vector<uint8_t> archive;
		if (!source_journal_cut_locked(ticket, journal) ||
		    !encode_source_journal_archive(ticket, journal, archive))
			return (false);
	}
	return (handoff_write_at(this->dirfd, ticket, handoff_phase::prepared));
}

bool
dir::abort_handoff(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if (phase == 0)
		return (true);
	if (phase != (int)handoff_phase::prepared) {
		errno = EBUSY;
		return (false);
	}
	if (!handoff_same_source(current, ticket)) {
		errno = EPROTO;
		return (false);
	}
	return (handoff_remove_at(this->dirfd, ticket.token,
	    handoff_phase::prepared));
}

bool
dir::commit_handoff(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::committed)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if (phase == (int)handoff_phase::committed) {
		if (!handoff_same_source(current, ticket) ||
		    current.checkpoint_digest != ticket.checkpoint_digest) {
			errno = EPROTO;
			return (false);
		}
		return (handoff_remove_at(this->dirfd, ticket.token,
		    handoff_phase::prepared));
	}
	if (phase == 0 || phase == (int)handoff_phase::reserved ||
	    phase == (int)handoff_phase::mutating ||
	    phase == (int)handoff_phase::claimed ||
	    !handoff_same_source(current, ticket)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	/* The saved HTX1 was checked at PREPARE, but a source journal record
	 * can still change before COMMIT. Do not publish a checkpoint ticket
	 * whose signed transfer member no longer matches that final cut. */
	if (this->state != nullptr && this->state->is_control_machine()) {
		std::vector<uint8_t> bundle;
		if (source_journal_transfer_wire_locked(current, bundle) < 0)
			return (false);
		if (bundle.size() < SHA256_DIGEST_LENGTH ||
		    CRYPTO_memcmp(bundle.data() + bundle.size() -
		    SHA256_DIGEST_LENGTH, current.transfer_digest.data(),
		    SHA256_DIGEST_LENGTH) != 0) {
			errno = EPROTO;
			return (false);
		}
	}
	if (!handoff_write_at(this->dirfd, ticket, handoff_phase::committed))
		return (false);
	return (handoff_remove_at(this->dirfd, ticket.token,
	    handoff_phase::prepared));
}

bool
dir::reserve_handoff(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::reserved)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if ((phase == (int)handoff_phase::committed ||
	    phase == (int)handoff_phase::reserved) &&
	    handoff_same_source(current, ticket) &&
	    current.checkpoint_digest == ticket.checkpoint_digest &&
	    !handoff_release_authority_locked(this->dirfd,
	    this->state, current))
		return (false);
	if (phase == (int)handoff_phase::reserved) {
		if (!handoff_same_destination(current, ticket)) {
			errno = EBUSY;
			return (false);
		}
		return (handoff_remove_at(this->dirfd, ticket.token,
		    handoff_phase::committed));
	}
	if (phase != (int)handoff_phase::committed ||
	    !handoff_same_source(current, ticket) ||
	    current.checkpoint_digest != ticket.checkpoint_digest) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (!handoff_destination_available_at(this->dirfd, ticket))
		return (false);
	if (!handoff_write_at(this->dirfd, ticket, handoff_phase::reserved))
		return (false);
	return (handoff_remove_at(this->dirfd, ticket.token,
	    handoff_phase::committed));
}

static bool source_journal_stage_remove_locked(int,
    const durable_handoff &);
static int source_journal_stage_status_locked(int,
    const durable_handoff &);
static bool source_journal_pending_rollback_locked(int,
    const durable_handoff &);
static int source_journal_ready_raw_status_locked(int,
    const durable_handoff &);
static int source_journal_claimed_plan_locked(int, state *,
    const durable_handoff &, source_journal_cut &,
    source_journal_destination_plan &,
    std::array<uint8_t, 16> *destination_session = nullptr,
    bool allow_rebind_pending = false,
    std::array<uint8_t, SHA256_DIGEST_LENGTH> *stage_digest_out = nullptr);
static int source_journal_rebind_plan_locked(int, state *,
    const durable_handoff &, uint16_t, uint64_t,
    const std::array<uint8_t, 16> &, uint32_t, uint32_t,
    source_journal_cut &, source_journal_destination_plan &,
    source_journal_destination_plan &,
    std::array<uint8_t, 16> *, bool allow_pending = false,
    std::array<uint8_t, SHA256_DIGEST_LENGTH> *stage_digest_out = nullptr);
static int delivery_record_status_at(int, const durable_delivery &);

bool
dir::cancel_handoff_reservation(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::reserved)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if (phase == (int)handoff_phase::committed &&
	    handoff_same_source(current, ticket) &&
	    current.checkpoint_digest == ticket.checkpoint_digest)
		return (fsync(this->dirfd) == 0);
	if (phase != (int)handoff_phase::reserved ||
	    !handoff_same_destination(current, ticket)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	durable_handoff committed = ticket;
	committed.destination_vmid = 0;
	committed.destination_epoch = 0;
	durable_handoff existing{};
	int present = handoff_read_at(this->dirfd, ticket.token,
	    handoff_phase::committed, existing);
	if (present < 0)
		return (false);
	if (present && (!handoff_same_source(existing, committed) ||
	    existing.checkpoint_digest != committed.checkpoint_digest)) {
		errno = EPROTO;
		return (false);
	}
	if (this->state != nullptr && this->state->is_control_machine()) {
		if (this->state->inbounddir == nullptr ||
		    this->state->inbounddir == this ||
		    !this->state->inbounddir->
		    rollback_host_ingress_pending_locked(ticket))
			return (false);
	}
	if (!source_journal_pending_rollback_locked(this->dirfd, ticket))
		return (false);
	if (!source_journal_stage_remove_locked(this->dirfd, ticket))
		return (false);
	if (!present && !handoff_write_at(this->dirfd, committed,
	    handoff_phase::committed))
		return (false);
	return (handoff_remove_at(this->dirfd, ticket.token,
	    handoff_phase::reserved));
}

/* A local empty handoff uses its HSL1. A foreign journal-only handoff uses
 * the signed HSA1 plus complete HJB1/HJR1 and every mapped pending HTD5.
 * Recheck on exact phase retries so a lost stage cannot look committed. */
static bool
handoff_journal_phase_ready_locked(int directory, state *control,
    const durable_handoff &ticket, int phase)
{
	int staged = source_journal_stage_status_locked(directory, ticket);
	if (staged < 0)
		return (false);
	if (staged == 1) {
		source_journal_cut cut;
		source_journal_destination_plan plan;
		int prepared = source_journal_claimed_plan_locked(directory,
		    control, ticket, cut, plan);
		if (prepared != 1) {
			if (prepared == 0)
				errno = EPROTO;
			return (false);
		}
		if (plan.has_ingress) {
			errno = EOPNOTSUPP;
			return (false);
		}
		if (phase != (int)handoff_phase::claimed) {
			for (const auto &item : plan.deliveries) {
				int delivery = delivery_record_status_at(directory,
				    item.state.record);
				if (delivery < 0)
					return (false);
				if (delivery != (int)delivery_phase::pending) {
					errno = EPROTO;
					return (false);
				}
			}
		}
		return (true);
	}
	int ready = source_journal_ready_raw_status_locked(directory, ticket);
	if (ready != 0) {
		if (ready == 1)
			errno = EPROTO;
		return (false);
	}
	int local_release = local_source_release_status_locked(directory, ticket);
	if (local_release != 1) {
		if (local_release == 0)
			errno = EOPNOTSUPP;
		return (false);
	}
	return (true);
}

/* Published while the ticket is still mutating. Legacy claimed tickets have
 * no witness, so absence of their execution marker cannot prove that they
 * never ran. The witness contains the exact future claimed record. */
static bool
handoff_capable_name(const durable_handoff &ticket, char name[50])
{
	char claimed[44];
	if (!handoff_valid(ticket, handoff_phase::claimed) ||
	    !handoff_name(ticket.token, handoff_phase::claimed, claimed)) {
		errno = EINVAL;
		return (false);
	}
	memcpy(name, ".handoff-capable.", 17);
	memcpy(name + 17, claimed + 9, 32);
	name[49] = '\0';
	return (true);
}

static int
handoff_fixed_read_at(int directory, const char *name, uint8_t *actual,
    size_t length)
{
	int fd = openat(directory, name,
	    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)length))
		error = EPROTO;
	for (size_t offset = 0; error == 0 && offset < length;) {
		ssize_t n = read(fd, actual + offset, length - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

static int
handoff_exact_marker_at(int directory, const char *name,
    const durable_handoff &ticket)
{
	std::array<uint8_t, handoff_record_size> actual{};
	int present = handoff_fixed_read_at(directory, name, actual.data(),
	    actual.size());
	if (present == 1 && actual != handoff_bytes(ticket)) {
		errno = EPROTO;
		return (-1);
	}
	return (present);
}

static int
handoff_capable_at(int directory, const durable_handoff &ticket)
{
	char name[50];
	if (!handoff_capable_name(ticket, name))
		return (-1);
	return (handoff_exact_marker_at(directory, name, ticket));
}

/* A reset decision must survive a crash while the old mutating phase and
 * the newly published committed phase coexist. Its contents bind the exact
 * old destination lifetime, not merely the ticket token. */
static bool
handoff_mutating_reset_name(const std::array<uint8_t, 16> &token,
    char name[48])
{
	char phase_name[44];
	if (!handoff_name(token, handoff_phase::mutating, phase_name))
		return (false);
	memcpy(name, ".handoff-reset.", 15);
	memcpy(name + 15, phase_name + 9, 32);
	name[47] = '\0';
	return (true);
}

static int
handoff_mutating_reset_read_at(int directory,
    const std::array<uint8_t, 16> &token, durable_handoff &record)
{
	char name[48];
	if (!handoff_mutating_reset_name(token, name))
		return (-1);
	std::array<uint8_t, handoff_record_size> wire{};
	int present = handoff_fixed_read_at(directory, name, wire.data(),
	    wire.size());
	if (present != 1)
		return (present);
	if (!handoff_claimed_from_bytes(wire.data(), record) ||
	    record.token != token) {
		errno = EPROTO;
		return (-1);
	}
	return (1);
}

bool
dir::begin_handoff_mutation(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::mutating)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if ((phase != (int)handoff_phase::reserved &&
	    phase != (int)handoff_phase::mutating) ||
	    !handoff_same_destination(current, ticket)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (!handoff_journal_phase_ready_locked(this->dirfd, this->state,
	    current, phase))
		return (false);
	if (phase == (int)handoff_phase::mutating)
		return (handoff_remove_at(this->dirfd, ticket.token,
		    handoff_phase::reserved));
	if (!handoff_write_at(this->dirfd, ticket, handoff_phase::mutating))
		return (false);
	return (handoff_remove_at(this->dirfd, ticket.token,
	    handoff_phase::reserved));
}

bool
dir::claim_handoff(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::claimed)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase < 0)
		return (false);
	if ((phase != (int)handoff_phase::mutating &&
	    phase != (int)handoff_phase::claimed) ||
	    !handoff_same_destination(current, ticket)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (!handoff_journal_phase_ready_locked(this->dirfd, this->state,
	    current, phase))
		return (false);
	if (phase == (int)handoff_phase::claimed) {
		int witnessed = handoff_capable_at(this->dirfd, ticket);
		if (witnessed != 1) {
			if (witnessed == 0)
				errno = EOPNOTSUPP;
			return (false);
		}
		return (handoff_remove_at(this->dirfd, ticket.token,
		    handoff_phase::mutating));
	}
	char capable_name[50];
	if (!handoff_capable_name(ticket, capable_name))
		return (false);
	const auto capable = handoff_bytes(ticket);
	int witnessed = handoff_capable_at(this->dirfd, ticket);
	if (witnessed < 0 ||
	    (witnessed == 0 && !handoff_publish_at(this->dirfd,
	    capable_name, capable.data(), capable.size())))
		return (false);
	if (!handoff_write_at(this->dirfd, ticket, handoff_phase::claimed))
		return (false);
	return (handoff_remove_at(this->dirfd, ticket.token,
	    handoff_phase::mutating));
}

static int handoff_rebind_present_at(int, const durable_handoff &);

/* A claimed ticket remains available for late saved KILL and delivery
 * receipts. Record guest REKEY_APPLIED separately so those operations keep
 * their claimed-phase semantics. An exact retry after a lost ACK accepts the
 * same fsynced record; a different destination or checkpoint never does. */
bool
dir::mark_handoff_rekey_applied(const durable_handoff &ticket)
{
	char claimed_name[44], name[50];
	std::array<uint8_t, handoff_record_size> expected, actual{};
	const std::array<uint8_t, 32> zero_digest{};
	durable_handoff current{};
	struct stat sb;
	int fd, error, phase;

	if (!handoff_valid(ticket, handoff_phase::claimed) ||
	    !handoff_name(ticket.token, handoff_phase::claimed, claimed_name)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, ticket)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	int rebind = handoff_rebind_present_at(this->dirfd, current);
	if (rebind != 0) {
		if (rebind > 0)
			errno = EBUSY;
		return (false);
	}
	memcpy(name, ".handoff-applied.", 17);
	memcpy(name + 17, claimed_name + 9, 32);
	name[49] = '\0';
	expected = handoff_bytes(ticket);
	fd = openat(this->dirfd, name,
	    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd >= 0) {
		error = 0;
		if (fstat(fd, &sb) != 0)
			error = errno;
		else if (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
		    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
		    (sb.st_size != (off_t)actual.size() &&
		    sb.st_size != (off_t)handoff_legacy_record_size))
			error = EPROTO;
		const size_t length = error == 0 ? (size_t)sb.st_size : 0;
		for (size_t offset = 0; error == 0 && offset < length;) {
			ssize_t n = read(fd, actual.data() + offset,
			    length - offset);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				error = n < 0 ? errno : EPROTO;
			else
				offset += (size_t)n;
		}
		if (close(fd) != 0 && error == 0)
			error = errno;
		if (error == 0 &&
		    ((length == actual.size() && actual != expected) ||
		    (length == handoff_legacy_record_size &&
		    (ticket.transfer_digest != zero_digest ||
		    memcmp(actual.data(), handoff_legacy_bytes(ticket).data(),
		    handoff_legacy_record_size) != 0))))
			error = EPROTO;
		if (error == 0 && fsync(this->dirfd) != 0)
			error = errno;
		if (error != 0)
			errno = error;
		return (error == 0);
	}
	if (errno != ENOENT)
		return (false);
	return (handoff_publish_at(this->dirfd, name, expected.data(),
	    expected.size()));
}

/* Read the guest-applied rekey fact without creating it. The caller holds
 * the outbound handoff process lock, so this cannot race its publisher. */
static int
handoff_rekey_applied_at(int directory, const durable_handoff &ticket)
{
	char claimed_name[44], name[50];
	if (!handoff_valid(ticket, handoff_phase::claimed) ||
	    !handoff_name(ticket.token, handoff_phase::claimed, claimed_name)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(name, ".handoff-applied.", 17);
	memcpy(name + 17, claimed_name + 9, 32);
	name[49] = '\0';
	int fd = openat(directory, name,
	    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	std::array<uint8_t, handoff_record_size> actual{};
	struct stat sb;
	int error = 0;
	if (fstat(fd, &sb) != 0)
		error = errno;
	else if (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    (sb.st_size != (off_t)actual.size() &&
	    sb.st_size != (off_t)handoff_legacy_record_size))
		error = EPROTO;
	const size_t length = error == 0 ? (size_t)sb.st_size : 0;
	for (size_t offset = 0; error == 0 && offset < length;) {
		ssize_t n = read(fd, actual.data() + offset, length - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	const std::array<uint8_t, 32> zero_digest{};
	if (error == 0 &&
	    ((length == actual.size() && actual != handoff_bytes(ticket)) ||
	    (length == handoff_legacy_record_size &&
	    (ticket.transfer_digest != zero_digest ||
	    memcmp(actual.data(), handoff_legacy_bytes(ticket).data(),
	    handoff_legacy_record_size) != 0))))
		error = EPROTO;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

int
dir::handoff_rekey_applied_status(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::claimed)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, ticket)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	return (handoff_rekey_applied_at(this->dirfd, ticket));
}

/* This is a conservative write-ahead execution boundary. A claimed
 * destination records its exact VM incarnation before bhyve releases any
 * vCPU. A future recovery may rebind only when this marker is absent and
 * the old VMM epoch has been retired; an uncertain marker is fail-closed. */
static bool
handoff_execution_start_name(const durable_handoff &ticket, char name[48])
{
	char claimed[44];
	if (!handoff_valid(ticket, handoff_phase::claimed) ||
	    !handoff_name(ticket.token, handoff_phase::claimed, claimed)) {
		errno = EINVAL;
		return (false);
	}
	memcpy(name, ".handoff-start.", 15);
	memcpy(name + 15, claimed + 9, 32);
	name[47] = '\0';
	return (true);
}

static int
handoff_execution_start_at(int directory, const durable_handoff &ticket)
{
	char name[48];
	if (!handoff_execution_start_name(ticket, name))
		return (-1);
	return (handoff_exact_marker_at(directory, name, ticket));
}

bool
dir::mark_handoff_execution_start(const durable_handoff &ticket)
{
	char name[48];
	if (!handoff_execution_start_name(ticket, name))
		return (false);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, ticket)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	int rebind = handoff_rebind_present_at(this->dirfd, current);
	if (rebind != 0) {
		if (rebind > 0)
			errno = EBUSY;
		return (false);
	}
	int capable = handoff_capable_at(this->dirfd, ticket);
	if (capable != 1) {
		if (capable == 0)
			errno = EOPNOTSUPP;
		return (false);
	}
	int present = handoff_execution_start_at(this->dirfd, ticket);
	if (present < 0)
		return (false);
	if (present == 1)
		return (fsync(this->dirfd) == 0);
	const auto expected = handoff_bytes(ticket);
	return (handoff_publish_at(this->dirfd, name, expected.data(),
	    expected.size()));
}

int
dir::handoff_execution_start_status(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::claimed)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, ticket.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, ticket)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	int capable = handoff_capable_at(this->dirfd, ticket);
	if (capable != 1) {
		if (capable == 0)
			errno = EOPNOTSUPP;
		return (-1);
	}
	int present = handoff_execution_start_at(this->dirfd, ticket);
	if (present < 0 || fsync(this->dirfd) != 0)
		return (-1);
	return (present);
}
/* HT-C END */

/* A replacement daemon must reject a corrupt or orphaned execution
 * boundary before it can make any new decision about the same ticket. The
 * caller holds the handoff process lock across the complete scan. */
static bool
handoff_execution_starts_audit_locked(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	for (;;) {
		errno = 0;
		dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		const char *name = entry->d_name;
		bool start = strncmp(name, ".handoff-start.", 15) == 0;
		bool capable = strncmp(name, ".handoff-capable.", 17) == 0;
		if (!start && !capable)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		if (strlen(name) != (start ? 47U : 49U)) {
			error = EPROTO;
			break;
		}
		size_t prefix = start ? 15 : 17;
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(name + prefix + i * 2, 2, octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		durable_handoff ticket{};
		int phase = handoff_state_at(directory, token, ticket);
		if (phase != (int)handoff_phase::claimed &&
		    !(capable && phase == (int)handoff_phase::mutating)) {
			error = phase < 0 && errno != EINVAL ? errno : EPROTO;
			break;
		}
		int present = handoff_capable_at(directory, ticket);
		if (present != 1) {
			error = present < 0 ? errno : EPROTO;
			break;
		}
		if (start) {
			present = handoff_execution_start_at(directory, ticket);
			if (present != 1) {
				error = present < 0 ? errno : EPROTO;
				break;
			}
		}
		/* HT-C END */
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/* HRI1 is an intent only. The old claimed record remains authoritative
 * until imported receipts, KILLs, and host ingress have been remapped and a
 * separate commit is durable. Nothing here grants the proposed VM execution. */
static constexpr size_t handoff_rebind_size = 228;
static constexpr size_t handoff_rebind_plan_header_size = 256;
static constexpr size_t handoff_rebind_plan_delivery_size = 186;
static constexpr size_t handoff_rebind_plan_kill_size = 30;
static constexpr size_t handoff_rebind_plan_cleanup_size = 18;
static constexpr size_t handoff_rebind_commit_size = 8 +
    handoff_rebind_size + SHA256_DIGEST_LENGTH * 2;
static int host_transfer_stage_read_at(int, const char *,
    std::vector<uint8_t> &);
static bool handoff_rebind_name(const std::array<uint8_t, 16> &,
    char [49]);
static bool handoff_rebind_plan_bytes(
    const std::array<uint8_t, handoff_rebind_size> &,
    const source_journal_destination_plan &, std::vector<uint8_t> &);
static bool source_journal_delivery_decode(const uint8_t *, size_t,
    durable_delivery &);
static bool handoff_rebind_pending_reconcile_locked(int, state *,
    const durable_handoff &,
    const std::array<uint8_t, handoff_rebind_size> &,
    const std::vector<uint8_t> &, bool);

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
static bool
handoff_rebind_plan_name(const std::array<uint8_t, 16> &token,
    char name[54])
{
	char intent[49];
	if (!handoff_rebind_name(token, intent))
		return (false);
	memcpy(name, ".handoff-rebind-plan.", 21);
	memcpy(name + 21, intent + 16, 32);
	name[53] = '\0';
	return (true);
}

static bool
handoff_rebind_commit_name(const std::array<uint8_t, 16> &token,
    char name[56])
{
	char intent[49];
	if (!handoff_rebind_name(token, intent))
		return (false);
	memcpy(name, ".handoff-rebind-commit.", 23);
	memcpy(name + 23, intent + 16, 32);
	name[55] = '\0';
	return (true);
}

static bool
handoff_rebind_done_name(const std::array<uint8_t, 16> &token,
    char name[54])
{
	char intent[49];
	if (!handoff_rebind_name(token, intent))
		return (false);
	memcpy(name, ".handoff-rebind-done.", 21);
	memcpy(name + 21, intent + 16, 32);
	name[53] = '\0';
	return (true);
}

static bool
handoff_rebind_name(const std::array<uint8_t, 16> &token, char name[49])
{
	char claimed[44];
	if (!handoff_name(token, handoff_phase::claimed, claimed))
		return (false);
	memcpy(name, ".handoff-rebind.", 16);
	memcpy(name + 16, claimed + 9, 32);
	name[48] = '\0';
	return (true);
}

static std::array<uint8_t, handoff_rebind_size>
handoff_rebind_bytes(const durable_handoff &old, uint16_t new_vmid,
    uint64_t new_epoch, const std::array<uint8_t, 16> &new_session,
    uint32_t new_uid, uint32_t new_pid)
{
	std::array<uint8_t, handoff_rebind_size> wire{};
	memcpy(wire.data(), "HRI1", 4);
	dtraced_wire_put_u32(wire.data() + 4, 1);
	const auto claimed = handoff_bytes(old);
	memcpy(wire.data() + 8, claimed.data(), claimed.size());
	dtraced_wire_put_u16(wire.data() + 160, new_vmid);
	dtraced_wire_put_u64(wire.data() + 162, new_epoch);
	memcpy(wire.data() + 170, new_session.data(), new_session.size());
	dtraced_wire_put_u32(wire.data() + 186, new_uid);
	dtraced_wire_put_u32(wire.data() + 190, new_pid);
	(void)SHA256(wire.data(), 196, wire.data() + 196);
	return (wire);
}

static int
handoff_rebind_read_at(int directory, const durable_handoff &old,
    std::array<uint8_t, handoff_rebind_size> *result)
{
	char name[49];
	if (!handoff_rebind_name(old.token, name))
		return (-1);
	std::array<uint8_t, handoff_rebind_size> wire{};
	int present = handoff_fixed_read_at(directory, name, wire.data(),
	    wire.size());
	if (present != 1)
		return (present);
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint16_t new_vmid = dtraced_wire_get_u16(wire.data() + 160);
	uint64_t new_epoch = dtraced_wire_get_u64(wire.data() + 162);
	if (memcmp(wire.data(), "HRI1", 4) != 0 ||
	    dtraced_wire_get_u32(wire.data() + 4) != 1 ||
	    memcmp(wire.data() + 8, handoff_bytes(old).data(),
	    handoff_record_size) != 0 ||
	    new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 ||
	    (new_vmid == old.destination_vmid &&
	    new_epoch == old.destination_epoch) ||
	    memcmp(wire.data() + 170, std::array<uint8_t, 16>{}.data(),
	    16) == 0 ||
	    memcmp(wire.data() + 170, old.source_session.data(), 16) == 0 ||
	    dtraced_wire_get_u32(wire.data() + 186) == UINT32_MAX ||
	    dtraced_wire_get_u32(wire.data() + 190) <= 1 ||
	    wire[194] != 0 || wire[195] != 0 ||
	    SHA256(wire.data(), 196, digest) == nullptr ||
	    CRYPTO_memcmp(digest, wire.data() + 196,
	    SHA256_DIGEST_LENGTH) != 0) {
		errno = EPROTO;
		return (-1);
	}
	if (result != nullptr)
		*result = wire;
	return (1);
}

static int
handoff_rebind_present_at(int directory, const durable_handoff &old)
{
	return (handoff_rebind_read_at(directory, old, nullptr));
}

/* HRP1 is a write-ahead inventory, not a destination execution lease. Its
 * complete, sorted replacement identities survive a daemon restart. The
 * claimed HTH2 and HRI1 must still agree before a later mutation may use it. */
static int
handoff_rebind_plan_read_at(int directory, const durable_handoff &old,
    const std::array<uint8_t, handoff_rebind_size> &intent,
    std::vector<uint8_t> *result,
    source_journal_destination_plan *inventory = nullptr)
{
	char name[54];
	if (!handoff_rebind_plan_name(old.token, name))
		return (-1);
	std::vector<uint8_t> wire;
	int present = host_transfer_stage_read_at(directory, name, wire);
	if (present != 1)
		return (present);
	if (wire.size() < handoff_rebind_plan_header_size +
	    SHA256_DIGEST_LENGTH) {
		errno = EPROTO;
		return (-1);
	}
	const uint8_t *data = wire.data();
	const size_t tail = wire.size() - SHA256_DIGEST_LENGTH;
	uint32_t deliveries = dtraced_wire_get_u32(data + 236);
	uint32_t kills = dtraced_wire_get_u32(data + 240);
	uint32_t cleanups = dtraced_wire_get_u32(data + 244);
	uint32_t revocations = dtraced_wire_get_u32(data + 249);
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (memcmp(data, "HRP1", 4) != 0 ||
	    dtraced_wire_get_u32(data + 4) != 1 ||
	    memcmp(data + 8, intent.data(), intent.size()) != 0 ||
	    deliveries > max_durable_kills || kills > max_durable_kills ||
	    cleanups > max_durable_kills ||
	    revocations > max_durable_kills || data[248] > 1 ||
	    !std::all_of(data + 253, data + 256,
	    [](uint8_t byte) { return (byte == 0); }) ||
	    tail != handoff_rebind_plan_header_size +
	    (size_t)deliveries * handoff_rebind_plan_delivery_size +
	    (size_t)kills * handoff_rebind_plan_kill_size +
	    (size_t)cleanups * handoff_rebind_plan_cleanup_size +
	    (size_t)revocations * 16 ||
	    SHA256(data, tail, digest) == nullptr ||
	    CRYPTO_memcmp(digest, data + tail, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	size_t offset = handoff_rebind_plan_header_size;
	for (uint32_t i = 0; i < deliveries; i++) {
		const uint8_t *entry = data + offset;
		uint8_t record_digest[SHA256_DIGEST_LENGTH];
		if (memcmp(entry, "HTD5", 4) != 0 ||
		    SHA256(entry, 153, record_digest) == nullptr ||
		    CRYPTO_memcmp(record_digest, entry + 153, 32) != 0 ||
		    memcmp(entry + 4, intent.data() + 170, 16) != 0 ||
		    dtraced_wire_get_u16(entry + 28) !=
		    dtraced_wire_get_u16(intent.data() + 160) ||
		    dtraced_wire_get_u64(entry + 30) !=
		    dtraced_wire_get_u64(intent.data() + 162) ||
		    memcmp(entry + 111, old.token.data(), 16) != 0 ||
		    memcmp(entry + 127, old.source_session.data(), 16) != 0 ||
		    entry[78] != 0 ||
		    dtraced_wire_get_u32(entry + 70) !=
		    dtraced_wire_get_u32(intent.data() + 186) ||
		    dtraced_wire_get_u32(entry + 74) !=
		    dtraced_wire_get_u32(intent.data() + 190) ||
		    (entry[185] != 'p' && entry[185] != 'a' &&
		    entry[185] != 'i' && entry[185] != 'x' &&
		    entry[185] != 't') ||
		    (i != 0 && memcmp(entry - handoff_rebind_plan_delivery_size,
		    entry, handoff_rebind_plan_delivery_size) >= 0)) {
			errno = EPROTO;
			return (-1);
		}
		offset += handoff_rebind_plan_delivery_size;
	}
	for (uint32_t i = 0; i < kills; i++) {
		const uint8_t *entry = data + offset;
		if (dtraced_wire_get_u32(entry) <= 1 ||
		    dtraced_wire_get_u32(entry) > INT_MAX ||
		    dtraced_wire_get_u16(entry + 4) !=
		    dtraced_wire_get_u16(intent.data() + 160) ||
		    dtraced_wire_get_u64(entry + 6) !=
		    dtraced_wire_get_u64(intent.data() + 162) ||
		    (i != 0 && memcmp(entry - handoff_rebind_plan_kill_size,
		    entry, handoff_rebind_plan_kill_size) >= 0)) {
			errno = EPROTO;
			return (-1);
		}
		offset += handoff_rebind_plan_kill_size;
	}
	for (uint32_t i = 0; i < cleanups; i++) {
		const uint8_t *entry = data + offset;
		if (dtraced_wire_get_u16(entry) !=
		    dtraced_wire_get_u16(intent.data() + 160) ||
		    dtraced_wire_get_u64(entry + 2) !=
		    dtraced_wire_get_u64(intent.data() + 162) ||
		    dtraced_wire_get_u64(entry + 10) == 0 ||
		    (i != 0 && memcmp(entry - handoff_rebind_plan_cleanup_size,
		    entry, handoff_rebind_plan_cleanup_size) >= 0)) {
			errno = EPROTO;
			return (-1);
		}
		offset += handoff_rebind_plan_cleanup_size;
	}
	for (uint32_t i = 0; i < revocations; i++) {
		const uint8_t *entry = data + offset;
		if ((i != 0 && memcmp(entry - 16, entry, 16) >= 0) ||
		    memcmp(entry, std::array<uint8_t, 16>{}.data(), 16) == 0) {
			errno = EPROTO;
			return (-1);
		}
		offset += 16;
	}
	const uint8_t *kill_base = data + handoff_rebind_plan_header_size +
	    (size_t)deliveries * handoff_rebind_plan_delivery_size;
	const uint8_t *revoke_base = data + tail - (size_t)revocations * 16;
	for (uint32_t i = 0; i < kills; i++) {
		const uint8_t *source = kill_base +
		    (size_t)i * handoff_rebind_plan_kill_size + 14;
		size_t lo = 0, hi = revocations;
		while (lo < hi) {
			size_t mid = lo + (hi - lo) / 2;
			if (memcmp(revoke_base + mid * 16, source, 16) < 0)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (lo == revocations ||
		    memcmp(revoke_base + lo * 16, source, 16) != 0) {
			errno = EPROTO;
			return (-1);
		}
	}
	/* Decode the complete inventory while the old claim still anchors it.
	 * A later commit recovery must be able to reconstruct these identities
	 * from HRP1 without consulting the publisher's in-memory plan. */
	source_journal_destination_plan decoded;
	decoded.has_ingress = data[248] == 1;
	try {
		offset = handoff_rebind_plan_header_size;
		for (uint32_t i = 0; i < deliveries; i++) {
			source_journal_delivery item{};
			if (!source_journal_delivery_decode(data + offset, 185,
			    item.state.record))
				return (-1);
			item.state.phase = (delivery_phase)data[offset + 185];
			decoded.deliveries.push_back(std::move(item));
			offset += handoff_rebind_plan_delivery_size;
		}
		for (uint32_t i = 0; i < kills; i++) {
			const uint8_t *entry = data + offset;
			durable_kill item{};
			item.pid = (pid_t)dtraced_wire_get_u32(entry);
			item.vmid = dtraced_wire_get_u16(entry + 4);
			item.epoch = dtraced_wire_get_u64(entry + 6);
			memcpy(item.source_id.data(), entry + 14, 16);
			decoded.pending_kills.push_back(item);
			offset += handoff_rebind_plan_kill_size;
		}
		for (uint32_t i = 0; i < cleanups; i++) {
			const uint8_t *entry = data + offset;
			durable_cleanup item{};
			item.vmid = dtraced_wire_get_u16(entry);
			item.epoch = dtraced_wire_get_u64(entry + 2);
			item.delivery_id = dtraced_wire_get_u64(entry + 10);
			decoded.queued_cleanups.push_back(item);
			offset += handoff_rebind_plan_cleanup_size;
		}
		for (uint32_t i = 0; i < revocations; i++) {
			std::array<uint8_t, 16> item{};
			memcpy(item.data(), data + offset, item.size());
			decoded.revoked_sources.push_back(item);
			offset += item.size();
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
	std::vector<uint8_t> canonical;
	if (!handoff_rebind_plan_bytes(intent, decoded, canonical))
		return (-1);
	if (canonical != wire) {
		errno = EPROTO;
		return (-1);
	}
	if (inventory != nullptr)
		*inventory = std::move(decoded);
	if (result != nullptr)
		*result = std::move(wire);
	return (1);
}

static bool
handoff_epoch_retired_fd(int fd, uint16_t vmid, uint64_t epoch)
{
	hypertrace_epoch_query query{};
	query.vmid = vmid;
	query.epoch = epoch;
	if (ioctl(fd, HYPERTRACE_IOC_EPOCH_QUERY, &query) != 0)
		return (false);
	if (query.vmid != vmid || query.epoch != epoch || query.live > 1 ||
	    query.reserved2 != 0 || query.reserved[0] != 0 ||
	    query.reserved[1] != 0 || query.reserved[2] != 0) {
		errno = EPROTO;
		return (false);
	}
	if (query.live != 0) {
		errno = EBUSY;
		return (false);
	}
	return (true);
}

bool
dir::begin_handoff_rebind(const durable_handoff &old,
    uint16_t new_vmid, uint64_t new_epoch,
    const std::array<uint8_t, 16> &new_session, uint32_t new_uid,
    uint32_t new_pid)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(old, handoff_phase::claimed) ||
	    new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 ||
	    (new_vmid == old.destination_vmid &&
	    new_epoch == old.destination_epoch) ||
	    new_session == std::array<uint8_t, 16>{} ||
	    new_session == old.source_session ||
	    new_uid == UINT32_MAX || new_pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, old.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, old)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	int capable = handoff_capable_at(this->dirfd, current);
	int started = capable == 1 ?
	    handoff_execution_start_at(this->dirfd, current) : -1;
	int applied = capable == 1 && started == 0 ?
	    handoff_rekey_applied_at(this->dirfd, current) : -1;
	if (capable != 1 || started != 0 || applied != 0) {
		if (capable == 0)
			errno = EOPNOTSUPP;
		else if (capable == 1 && (started == 1 || applied == 1))
			errno = EBUSY;
		return (false);
	}
	/* Refuse a still-running old incarnation before interpreting its
	 * partially bound journal. Recheck retirement at publication below. */
	int retired_fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (retired_fd < 0)
		return (false);
	int retired_error = handoff_epoch_retired_fd(retired_fd,
	    current.destination_vmid, current.destination_epoch) ? 0 : errno;
	if (close(retired_fd) != 0 && retired_error == 0)
		retired_error = errno;
	if (retired_error != 0) {
		errno = retired_error;
		return (false);
	}
	/* An exact BEGIN retry can arrive after STAGE and a partial or full
	 * pending publication. Validate that plan before the strict new-plan
	 * collision check, which intentionally rejects proposed HTD5 records. */
	const auto retry_intent = handoff_rebind_bytes(current, new_vmid,
	    new_epoch, new_session, new_uid, new_pid);
	std::array<uint8_t, handoff_rebind_size> retry_existing{};
	int retry = handoff_rebind_read_at(this->dirfd, current,
	    &retry_existing);
	if (retry < 0)
		return (false);
	if (retry == 1 && retry_existing == retry_intent) {
		std::vector<uint8_t> retry_plan;
		int staged_retry = handoff_rebind_plan_read_at(this->dirfd,
		    current, retry_existing, &retry_plan);
		if (staged_retry < 0)
			return (false);
		if (staged_retry == 1) {
			int epoch_fd = open("/dev/dtrace/hypertrace",
			    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
			if (epoch_fd < 0)
				return (false);
			int error = handoff_epoch_retired_fd(epoch_fd,
			    current.destination_vmid,
			    current.destination_epoch) ? 0 : errno;
			if (close(epoch_fd) != 0 && error == 0)
				error = errno;
			if (error != 0) {
				errno = error;
				return (false);
			}
			return (handoff_rebind_pending_reconcile_locked(
			    this->dirfd, this->state, current, retry_existing,
			    retry_plan, false));
		}
	}
	if (retry == 1 && retry_existing != retry_intent) {
		/* A new attested owner may supersede an inert staged proposal
		 * after both old and proposed VMM epochs have retired. The helper
		 * proves retirement again at the deletion site and refuses any
		 * proposed receipt that advanced beyond pending. */
		if ((dtraced_wire_get_u16(retry_existing.data() + 160) ==
		    new_vmid && dtraced_wire_get_u64(retry_existing.data() + 162) ==
		    new_epoch) || memcmp(retry_existing.data() + 170,
		    new_session.data(), new_session.size()) == 0) {
			errno = EEXIST;
			return (false);
		}
		std::vector<uint8_t> prior_stage;
		int prior = handoff_rebind_plan_read_at(this->dirfd, current,
		    retry_existing, &prior_stage);
		if (prior < 0)
			return (false);
		if (prior == 1) {
			if (!handoff_rebind_pending_reconcile_locked(
			    this->dirfd, this->state, current, retry_existing,
			    prior_stage, true))
				return (false);
			char prior_name[54];
			if (!handoff_rebind_plan_name(current.token, prior_name))
				return (false);
			if (unlinkat(this->dirfd, prior_name, 0) != 0 ||
			    fsync(this->dirfd) != 0)
				return (false);
		}
	}
	source_journal_cut cut;
	source_journal_destination_plan plan;
	source_journal_destination_plan replacement_plan;
	std::array<uint8_t, 16> old_session{};
	int staged = source_journal_rebind_plan_locked(this->dirfd,
	    this->state, current, new_vmid, new_epoch, new_session,
	    new_uid, new_pid, cut, plan, replacement_plan, &old_session);
	if (staged < 0)
		return (false);
	if (staged == 1 && old_session == new_session) {
		errno = EEXIST;
		return (false);
	}
	if (staged == 0) {
		std::vector<uint8_t> empty_wire;
		if (!dtraced_transfer_wire_build(current.token.data(),
		    {}, {}, empty_wire))
			return (false);
		if (memcmp(current.transfer_digest.data(),
		    empty_wire.data() + empty_wire.size() - 32, 32) != 0) {
			errno = EPROTO;
			return (false);
		}
	}
	const auto expected = handoff_rebind_bytes(current, new_vmid,
	    new_epoch, new_session, new_uid, new_pid);
	std::array<uint8_t, handoff_rebind_size> existing{};
	int present = handoff_rebind_read_at(this->dirfd, current, &existing);
	if (present < 0)
		return (false);
	std::vector<uint8_t> staged_wire;
	int planned = 0;
	if (present == 0) {
		planned = handoff_rebind_plan_read_at(this->dirfd,
		    current, expected, nullptr);
		if (planned != 0) {
			if (planned == 1)
				errno = EPROTO;
			return (false);
		}
	}
	if (present == 1) {
		planned = handoff_rebind_plan_read_at(this->dirfd,
		    current, existing, &staged_wire);
		if (planned < 0)
			return (false);
	}
	if (present == 1 && existing != expected &&
	    (dtraced_wire_get_u16(existing.data() + 160) == new_vmid &&
	    dtraced_wire_get_u64(existing.data() + 162) == new_epoch)) {
		errno = EEXIST;
		return (false);
	}
	if (present == 1 && existing != expected &&
	    memcmp(existing.data() + 170, new_session.data(), 16) == 0) {
		errno = EEXIST;
		return (false);
	}
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	int error = handoff_epoch_retired_fd(fd, current.destination_vmid,
	    current.destination_epoch) ? 0 : errno;
	if (error == 0 && present == 1 && existing != expected &&
	    !handoff_epoch_retired_fd(fd,
	    dtraced_wire_get_u16(existing.data() + 160),
	    dtraced_wire_get_u64(existing.data() + 162)))
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	if (present == 1 && existing == expected)
		return (fsync(this->dirfd) == 0);
	if (planned == 1) {
		std::array<uint8_t, 16> previous_session{};
		memcpy(previous_session.data(), existing.data() + 170, 16);
		source_journal_cut previous_cut;
		source_journal_destination_plan previous_prior;
		source_journal_destination_plan previous_replacement;
		if (source_journal_rebind_plan_locked(this->dirfd,
		    this->state, current,
		    dtraced_wire_get_u16(existing.data() + 160),
		    dtraced_wire_get_u64(existing.data() + 162),
		    previous_session,
		    dtraced_wire_get_u32(existing.data() + 186),
		    dtraced_wire_get_u32(existing.data() + 190),
		    previous_cut, previous_prior, previous_replacement,
		    nullptr) < 0)
			return (false);
		std::vector<uint8_t> rebuilt;
		if (!handoff_rebind_plan_bytes(existing,
		    previous_replacement, rebuilt))
			return (false);
		if (rebuilt != staged_wire) {
			errno = EBUSY;
			return (false);
		}
		char plan_name[54];
		if (!handoff_rebind_plan_name(current.token, plan_name))
			return (false);
		if (unlinkat(this->dirfd, plan_name, 0) != 0 ||
		    fsync(this->dirfd) != 0)
			return (false);
	}
	char name[49];
	if (!handoff_rebind_name(current.token, name))
		return (false);
	if (present == 1)
		return (handoff_replace_at(this->dirfd, name,
		    expected.data(), expected.size()));
	return (handoff_publish_at(this->dirfd, name, expected.data(),
	    expected.size()));
}
/* HT-C END */

static bool
handoff_rebinds_audit_locked(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	for (;;) {
		errno = 0;
		dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		const char *name = entry->d_name;
		if (strncmp(name, ".handoff-rebind.", 16) != 0)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		if (strlen(name) != 48) {
			error = EPROTO;
			break;
		}
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(name + 16 + i * 2, 2, octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		char canonical[49];
		if (!handoff_rebind_name(token, canonical) ||
		    strcmp(name, canonical) != 0) {
			error = EPROTO;
			break;
		}
		durable_handoff old{};
		int phase = handoff_state_at(directory, token, old);
		if (phase != (int)handoff_phase::claimed) {
			error = phase < 0 && errno != EINVAL ? errno : EPROTO;
			break;
		}
		int capable = handoff_capable_at(directory, old);
		if (capable != 1) {
			error = capable < 0 ? errno : EPROTO;
			break;
		}
		int started = handoff_execution_start_at(directory, old);
		if (started != 0) {
			error = started < 0 ? errno : EPROTO;
			break;
		}
		int applied = handoff_rekey_applied_at(directory, old);
		if (applied != 0) {
			error = applied < 0 ? errno : EPROTO;
			break;
		}
		int intent = handoff_rebind_read_at(directory, old, nullptr);
		if (intent != 1) {
			error = intent < 0 ? errno : EPROTO;
			break;
		}
		/* HT-C END */
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
int
dir::handoff_status(const std::array<uint8_t, 16> &token,
    durable_handoff &record)
{
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	int phase = handoff_state_at(this->dirfd, token, record);
	if (phase < 0)
		return (-1);
	/* A read-only status is used to resolve a lost transition ACK.  A
	 * visible record (or removal) after a failed directory fsync is not
	 * enough evidence until this directory has itself been synced. */
	if (fsync(this->dirfd) != 0)
		return (-1);
	return (phase);
}
/* HT-C END */

int
dir::source_handoff_for_vm(uint16_t vmid, uint64_t epoch,
    durable_handoff &record)
{
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	return (handoff_source_state_at(this->dirfd, vmid, epoch, record));
}

int
dir::with_source_handoff_phase(uint16_t vmid, uint64_t epoch,
    const std::function<void(int)> &admit)
{
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    !admit) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff record{};
	int phase = handoff_source_state_at(this->dirfd, vmid, epoch, record);
	if (phase >= 0)
		admit(phase);
	return (phase);
}

bool
dir::record_cleanup_pending(const durable_cleanup &record)
{
	char pending_name[50];
	if (!cleanup_name(record, 'p', pending_name))
		return (false);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff active{};
	int phase = handoff_source_state_at(this->dirfd, record.vmid,
	    record.epoch, active);
	if (phase < 0)
		return (false);
	if (phase != 0) {
		errno = EBUSY;
		return (false);
	}
	int status = cleanup_status_at(this->dirfd, record);
	if (status < 0)
		return (false);
	if (status == 'a' || status == 'g') {
		errno = EALREADY;
		return (false);
	}
	if (status == 'p')
		return (fsync(this->dirfd) == 0);
	std::vector<durable_cleanup> pending;
	size_t total = 0;
	if (!list_pending_cleanups_at(this->dirfd, pending, &total))
		return (false);
	if (total >= max_durable_kills) {
		errno = ENOSPC;
		return (false);
	}
	int fd = openat(this->dirfd, pending_name,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (false);
	/* A refused request is answered with a NAK, so its pending record
	 * must not survive to be replayed by recovery after a restart: undo
	 * the record on every failure after it was created. */
	bool synced = fsync(fd) == 0;
	int error = synced ? 0 : errno;
	if (close(fd) != 0 && synced) {
		synced = false;
		error = errno;
	}
	if (synced && fsync(this->dirfd) != 0) {
		synced = false;
		error = errno;
	}
	if (!synced) {
		(void)unlinkat(this->dirfd, pending_name, 0);
		(void)fsync(this->dirfd);
		errno = error;
		return (false);
	}
	return (true);
}

bool
dir::record_cleanup_queued(const durable_cleanup &record)
{
	char pending_name[50], accepted_name[50], applied_name[50];
	if (!cleanup_name(record, 'p', pending_name) ||
	    !cleanup_name(record, 'a', accepted_name) ||
	    !cleanup_name(record, 'g', applied_name))
		return (false);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	int accepted = kill_record_status_at(this->dirfd, accepted_name);
	if (accepted != 0 && errno != ENOENT)
		return (false);
	int pending = kill_record_status_at(this->dirfd, pending_name);
	if (pending != 0 && errno != ENOENT)
		return (false);
	int applied = kill_record_status_at(this->dirfd, applied_name);
	if (applied != 0 && errno != ENOENT)
		return (false);
	if (applied == 0) {
		errno = accepted == 0 || pending == 0 ? EPROTO : EALREADY;
		return (false);
	}
	if (accepted == 0 && pending != 0)
		return (fsync(this->dirfd) == 0); /* exact retry */
	if (accepted == 0 || pending != 0) {
		errno = EPROTO;
		return (false);
	}
	if (renameat(this->dirfd, pending_name,
	    this->dirfd, accepted_name) != 0)
		return (false);
	return (fsync(this->dirfd) == 0);
}

bool
dir::record_cleanup_applied(const durable_cleanup &record)
{
	char accepted_name[50], applied_name[50];
	if (!cleanup_name(record, 'a', accepted_name) ||
	    !cleanup_name(record, 'g', applied_name))
		return (false);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	int phase = cleanup_status_at(this->dirfd, record);
	if (phase < 0)
		return (false);
	if (phase == 'g')
		return (fsync(this->dirfd) == 0);
	if (phase != 'a') {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (renameat(this->dirfd, accepted_name,
	    this->dirfd, applied_name) != 0)
		return (false);
	return (fsync(this->dirfd) == 0);
}

bool
dir::list_pending_cleanups(std::vector<durable_cleanup> &records)
{
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	return (process_lock.held() &&
	    list_pending_cleanups_at(this->dirfd, records));
}

int
dir::cleanup_status(const durable_cleanup &record)
{
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	return (process_lock.held() ?
	    cleanup_status_at(this->dirfd, record) : -1);
}

/* One fixed record per session/token. Names encode only the phase and key. */
static bool
delivery_record_valid(const durable_delivery &record)
{
	const std::array<uint8_t, 16> zero{};
	const std::array<uint8_t, 32> zero_digest{};
	bool plain = record.handoff_token == zero &&
	    record.source_session == zero && record.payload_vmid == 0 &&
	    record.payload_epoch == 0;
	bool bound = record.payload_digest != zero_digest;
	bool migrated = (record.scope == 0 || record.scope == 3) &&
	    record.journal_version == 5 && bound &&
	    record.handoff_token != zero && record.source_session != zero &&
	    record.source_session != record.session_id &&
	    record.payload_vmid != 0 &&
	    record.payload_vmid < HYPERTRACE_MAX_VMS &&
	    record.payload_epoch != 0;
	return (record.session_id != zero && record.delivery_id != 0 &&
	    record.program_id != zero &&
	    record.source_id != zero &&
	    (((record.scope == 0 || record.scope == 1 || record.scope == 3) &&
	    record.vmid != 0 && record.vmid < HYPERTRACE_MAX_VMS &&
	    record.epoch != 0) ||
	    (record.scope == 2 &&
	    ((record.vmid == 0 && record.epoch == 0) ||
	    (record.vmid != 0 && record.vmid < HYPERTRACE_MAX_VMS &&
	    record.epoch != 0)))) &&
	    ((record.scope == 0 || record.scope == 2 || record.scope == 3) ?
	    (record.peer_uid != UINT32_MAX && record.peer_pid > 1) :
	    (record.peer_uid == 0 && record.peer_pid == 0)) &&
	    ((record.scope == 0 &&
	    ((record.journal_version == 3 &&
	    record.payload_digest == zero_digest && plain) ||
	    (record.journal_version == 4 && bound && plain) || migrated)) ||
	    (record.scope == 1 && plain &&
	    ((record.journal_version == 3 &&
	    record.payload_digest == zero_digest) ||
	    (record.journal_version == 4 && bound))) ||
	    (record.scope == 2 && plain &&
	    ((record.journal_version == 3 &&
	    record.payload_digest == zero_digest) ||
	    (record.journal_version == 4 && bound))) ||
	    (record.scope == 3 &&
	    ((record.journal_version == 4 && bound && plain) || migrated))));
}

static void
delivery_record_name(const durable_delivery &record, delivery_phase phase,
    char name[80])
{
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".delivery.", 10);
	for (size_t i = 0; i < record.session_id.size(); i++) {
		name[10 + i * 2] = hex[record.session_id[i] >> 4];
		name[11 + i * 2] = hex[record.session_id[i] & 15];
	}
	(void)snprintf(name + 42, 80 - 42, ".%016jx.%c",
	    (uintmax_t)record.delivery_id, (char)phase);
}

static size_t
delivery_record_size(const durable_delivery &record)
{
	return (record.journal_version == 5 ? 185 :
	    record.journal_version == 4 ? 143 : 111);
}

static std::array<uint8_t, 185>
delivery_record_bytes(const durable_delivery &record)
{
	std::array<uint8_t, 185> data{};
	memcpy(data.data(), record.journal_version == 5 ? "HTD5" :
	    record.journal_version == 4 ? "HTD4" : "HTD3", 4);
	memcpy(data.data() + 4, record.session_id.data(), 16);
	for (unsigned i = 0; i < 8; i++) {
		data[20 + i] = (uint8_t)(record.delivery_id >> (8 * i));
		data[30 + i] = (uint8_t)(record.epoch >> (8 * i));
	}
	data[28] = (uint8_t)record.vmid;
	data[29] = (uint8_t)(record.vmid >> 8);
	memcpy(data.data() + 38, record.program_id.data(), 16);
	memcpy(data.data() + 54, record.source_id.data(), 16);
	for (unsigned i = 0; i < 4; i++) {
		data[70 + i] = (uint8_t)(record.peer_uid >> (8 * i));
		data[74 + i] = (uint8_t)(record.peer_pid >> (8 * i));
	}
	data[78] = record.scope;
	if (record.journal_version >= 4) {
		memcpy(data.data() + 79, record.payload_digest.data(), 32);
		if (record.journal_version == 5) {
			/* HT-C BEGIN: disabled trace continuity. */
			memcpy(data.data() + 111, record.handoff_token.data(), 16);
			memcpy(data.data() + 127, record.source_session.data(), 16);
			data[143] = (uint8_t)record.payload_vmid;
			data[144] = (uint8_t)(record.payload_vmid >> 8);
			for (unsigned i = 0; i < 8; i++)
				data[145 + i] =
				    (uint8_t)(record.payload_epoch >> (8 * i));
			(void)SHA256(data.data(), 153, data.data() + 153);
			/* HT-C END */
		} else
			(void)SHA256(data.data(), 111, data.data() + 111);
	} else
		(void)SHA256(data.data(), 79, data.data() + 79);
	return (data);
}

static int
delivery_read_at(int directory, const char *name,
	std::array<uint8_t, 185> &actual, size_t &length)
{
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	int error = 0;
	if (fstat(fd, &sb) != 0)
		error = errno;
	else if (!S_ISREG(sb.st_mode) ||
	    (sb.st_size != 111 && sb.st_size != 110 && sb.st_size != 143 &&
	    sb.st_size != 185))
		error = EPROTO;
	else {
		length = (size_t)sb.st_size;
		ssize_t n;
		do {
			n = pread(fd, actual.data(), sb.st_size, 0);
		} while (n < 0 && errno == EINTR);
		if (n != sb.st_size)
			error = n < 0 ? errno : EPROTO;
		else if (sb.st_size == 110) {
			/* HTD2 is a host record with no explicit scope byte. */
			uint8_t digest[SHA256_DIGEST_LENGTH];
			(void)SHA256(actual.data(), 78, digest);
			if (memcmp(actual.data(), "HTD2", 4) != 0 ||
			    memcmp(actual.data() + 78, digest,
			    sizeof(digest)) != 0)
				error = EPROTO;
			else {
				memcpy(actual.data(), "HTD3", 4);
				actual[78] = 0;
				(void)SHA256(actual.data(), 79,
				    actual.data() + 79);
				length = 111;
			}
		}
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

static int
delivery_record_at(int directory, const char *name,
	const std::array<uint8_t, 185> &expected, size_t expected_size)
{
	std::array<uint8_t, 185> actual{};
	size_t size = 0;
	int status = delivery_read_at(directory, name, actual, size);
	if (status == 1 && (size != expected_size ||
	    memcmp(actual.data(), expected.data(), size) != 0)) {
		errno = EPROTO;
		return (-1);
	}
	return (status);
}

static int
delivery_record_count(int directory)
{
	int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	DIR *scan = fdopendir(fd);
	if (scan == nullptr) {
		int error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	int count = 0, error = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		if (strncmp(entry->d_name, ".delivery.", 10) == 0)
			count++;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (count);
}

static int
delivery_record_status_at(int directory, const durable_delivery &record)
{
	const auto data = delivery_record_bytes(record);
	const size_t size = delivery_record_size(record);
	int found = 0;
	for (delivery_phase phase : {delivery_phase::pending,
	    delivery_phase::accepted, delivery_phase::installed,
	    delivery_phase::exited, delivery_phase::terminal}) {
		char name[80];
		delivery_record_name(record, phase, name);
		int status = delivery_record_at(directory, name, data, size);
		if (status < 0)
			return (-1);
		if (status != 0) {
			if (found != 0) {
				errno = EPROTO;
				return (-1);
			}
			found = (char)phase;
		}
	}
	return (found);
}

static int
delivery_phase_order(delivery_phase phase)
{
	switch (phase) {
	case delivery_phase::pending: return (1);
	case delivery_phase::accepted: return (2);
	case delivery_phase::installed: return (3);
	case delivery_phase::exited: return (4);
	case delivery_phase::terminal: return (5);
	}
	return (0);
}

int
dir::delivery_status(const durable_delivery &record)
{
	if (!delivery_record_valid(record)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	return (delivery_record_status_at(this->dirfd, record));
}

static int
delivery_hex(char c)
{
	if (c >= '0' && c <= '9') return (c - '0');
	if (c >= 'a' && c <= 'f') return (c - 'a' + 10);
	return (-1);
}

static bool
delivery_record_parse(int directory, const char *name,
    durable_delivery_state &entry)
{
	if (strlen(name) != 61 || strncmp(name, ".delivery.", 10) != 0 ||
	    name[42] != '.' || name[59] != '.' ||
	    (name[60] != 'p' && name[60] != 'a' &&
	    name[60] != 'i' && name[60] != 'x' && name[60] != 't')) {
		errno = EPROTO;
		return (false);
	}
	durable_delivery record{};
	for (size_t i = 0; i < record.session_id.size(); i++) {
		int high = delivery_hex(name[10 + 2 * i]);
		int low = delivery_hex(name[11 + 2 * i]);
		if (high < 0 || low < 0) {
			errno = EPROTO;
			return (false);
		}
		record.session_id[i] = (uint8_t)((high << 4) | low);
	}
	for (size_t i = 43; i < 59; i++) {
		int digit = delivery_hex(name[i]);
		if (digit < 0) {
			errno = EPROTO;
			return (false);
		}
		record.delivery_id = (record.delivery_id << 4) | (uint64_t)digit;
	}
	std::array<uint8_t, 185> data{};
	size_t size = 0;
	if (delivery_read_at(directory, name, data, size) != 1) {
		if (errno == ENOENT) errno = EPROTO;
		return (false);
	}
	if (!((size == 111 && memcmp(data.data(), "HTD3", 4) == 0) ||
	    (size == 143 && memcmp(data.data(), "HTD4", 4) == 0) ||
	    (size == 185 && memcmp(data.data(), "HTD5", 4) == 0)) ||
	    memcmp(data.data() + 4, record.session_id.data(), 16) != 0) {
		errno = EPROTO;
		return (false);
	}
	uint8_t digest[SHA256_DIGEST_LENGTH];
	const size_t digest_offset = size == 185 ? 153 :
	    size == 143 ? 111 : 79;
	(void)SHA256(data.data(), digest_offset, digest);
	if (memcmp(data.data() + digest_offset, digest,
	    sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	uint64_t token = 0, epoch = 0;
	for (unsigned i = 0; i < 8; i++) {
		token |= (uint64_t)data[20 + i] << (8 * i);
		epoch |= (uint64_t)data[30 + i] << (8 * i);
	}
	if (token != record.delivery_id) {
		errno = EPROTO;
		return (false);
	}
	record.vmid = (uint16_t)data[28] | ((uint16_t)data[29] << 8);
	record.epoch = epoch;
	memcpy(record.program_id.data(), data.data() + 38, 16);
	memcpy(record.source_id.data(), data.data() + 54, 16);
	for (unsigned i = 0; i < 4; i++) {
		record.peer_uid |= (uint32_t)data[70 + i] << (8 * i);
		record.peer_pid |= (uint32_t)data[74 + i] << (8 * i);
	}
	record.scope = data[78];
	record.journal_version = size == 185 ? 5 : size == 143 ? 4 : 3;
	if (size >= 143)
		memcpy(record.payload_digest.data(), data.data() + 79, 32);
	if (size == 185) {
		memcpy(record.handoff_token.data(), data.data() + 111, 16);
		memcpy(record.source_session.data(), data.data() + 127, 16);
		record.payload_vmid = (uint16_t)data[143] |
		    ((uint16_t)data[144] << 8);
		for (unsigned i = 0; i < 8; i++)
			record.payload_epoch |=
			    (uint64_t)data[145 + i] << (8 * i);
	}
	const auto expected = delivery_record_bytes(record);
	if (!delivery_record_valid(record) ||
	    memcmp(expected.data(), data.data(), size) != 0) {
		errno = EPROTO;
		return (false);
	}
	entry.record = record;
	entry.phase = (delivery_phase)name[60];
	return (true);
}

static bool
list_deliveries_at(int directory,
    std::vector<durable_delivery_state> &records)
{
	int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return (false);
	DIR *scan = fdopendir(fd);
	if (scan == nullptr) {
		int error = errno;
		close(fd);
		errno = error;
		return (false);
	}
	std::vector<durable_delivery_state> recovered;
	std::unordered_set<std::string> seen;
	int error = 0;
	try {
		for (;;) {
			errno = 0;
			struct dirent *file = readdir(scan);
			if (file == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(file->d_name, ".delivery.", 10) != 0)
				continue;
			if (recovered.size() >= 16384) {
				error = ENOSPC;
				break;
			}
			durable_delivery_state entry{};
			if (!delivery_record_parse(directory, file->d_name, entry)) {
				error = errno;
				break;
			}
			if (!seen.insert(std::string(file->d_name, 59)).second) {
				error = EPROTO;
				break;
			}
			recovered.push_back(entry);
		}
	} catch (const std::bad_alloc &) {
		error = ENOMEM;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	records.swap(recovered);
	return (true);
}

bool
dir::list_deliveries(std::vector<durable_delivery_state> &records)
{
	std::lock_guard lk(this->publishmtx);
	return (list_deliveries_at(this->dirfd, records));
}

/* HCR1 records the recipient set before a host-ingress batch becomes
 * visible. A processed transition is fsynced only after the consumer's
 * identity-checked ACK. These records do not yet authorize checkpoint save. */
static constexpr size_t consumer_receipt_wire_size = 158;
static constexpr size_t consumer_receipt_limit =
    DTRACED_CONSUMER_RECEIPT_LIMIT;

static bool
consumer_receipt_valid(const durable_consumer_receipt &record)
{
	const std::array<uint8_t, 16> zero{};
	return (record.ingress.scope == 3 &&
	    record.ingress.journal_version == 4 &&
	    delivery_record_valid(record.ingress) &&
	    record.consumer_session != zero &&
	    record.consumer_uid != UINT32_MAX && record.consumer_pid > 1 &&
	    record.consumer_pid <= INT_MAX);
}

static void
consumer_receipt_name(const durable_consumer_receipt &record,
    consumer_receipt_phase phase, char name[96])
{
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".consumer.", 10);
	for (size_t i = 0; i < 16; i++) {
		name[10 + i * 2] = hex[record.ingress.session_id[i] >> 4];
		name[11 + i * 2] = hex[record.ingress.session_id[i] & 15];
		name[60 + i * 2] = hex[record.consumer_session[i] >> 4];
		name[61 + i * 2] = hex[record.consumer_session[i] & 15];
	}
	name[42] = '.';
	(void)snprintf(name + 43, 17, "%016jx",
	    (uintmax_t)record.ingress.delivery_id);
	name[59] = '.';
	name[92] = '.';
	name[93] = (char)phase;
	name[94] = '\0';
}

static std::array<uint8_t, consumer_receipt_wire_size>
consumer_receipt_bytes(const durable_consumer_receipt &record)
{
	std::array<uint8_t, consumer_receipt_wire_size> wire{};
	memcpy(wire.data(), "HCR1", 4);
	memcpy(wire.data() + 4, record.ingress.session_id.data(), 16);
	for (unsigned i = 0; i < 8; i++) {
		wire[20 + i] = (uint8_t)(record.ingress.delivery_id >> (8 * i));
		wire[30 + i] = (uint8_t)(record.ingress.epoch >> (8 * i));
	}
	wire[28] = (uint8_t)record.ingress.vmid;
	wire[29] = (uint8_t)(record.ingress.vmid >> 8);
	memcpy(wire.data() + 38, record.ingress.program_id.data(), 16);
	memcpy(wire.data() + 54, record.ingress.source_id.data(), 16);
	memcpy(wire.data() + 70, record.ingress.payload_digest.data(), 32);
	memcpy(wire.data() + 102, record.consumer_session.data(), 16);
	for (unsigned i = 0; i < 4; i++) {
		wire[118 + i] = (uint8_t)(record.consumer_uid >> (8 * i));
		wire[122 + i] = (uint8_t)(record.consumer_pid >> (8 * i));
	}
	(void)SHA256(wire.data(), 126, wire.data() + 126);
	return (wire);
}

/* HCR2 is a destination-only identity record. Keep its codec separate from
 * HCR1: the latter can only name HTD4 and cannot bind a process incarnation.
 * Encoding a record grants no authority to accept HTD5 or run a consumer. */
static constexpr size_t import_consumer_receipt_wire_size = 329;

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
static bool
import_consumer_receipt_valid(const durable_import_consumer_receipt &record)
{
	const auto &owner = record.owner_wire;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	std::array<uint8_t, 16> session{}, birth{};
	memcpy(session.data(), owner.data() + 4, session.size());
	memcpy(birth.data(), owner.data() + 28, birth.size());
	uint32_t uid = dtraced_wire_get_u32(owner.data() + 20);
	uint32_t pid = dtraced_wire_get_u32(owner.data() + 24);
	return (record.ingress.scope == 3 &&
	    record.ingress.journal_version == 5 &&
	    delivery_record_valid(record.ingress) &&
	    memcmp(owner.data(), "HCO1", 4) == 0 &&
	    session != std::array<uint8_t, 16>{} &&
	    birth != std::array<uint8_t, 16>{} &&
	    uid != UINT32_MAX && pid > 1 && pid <= INT_MAX &&
	    record.program_digest != std::array<uint8_t, 32>{} &&
	    SHA256(owner.data(), 44, digest) != NULL &&
	    memcmp(owner.data() + 44, digest, sizeof(digest)) == 0);
}

bool
dir::encode_import_consumer_receipt(
    const durable_import_consumer_receipt &record,
    std::vector<uint8_t> &encoded)
{
	encoded.clear();
	if (!import_consumer_receipt_valid(record)) {
		errno = EINVAL;
		return (false);
	}
	try {
		std::vector<uint8_t> wire(import_consumer_receipt_wire_size);
		memcpy(wire.data(), "HCR2", 4);
		auto delivery = delivery_record_bytes(record.ingress);
		memcpy(wire.data() + 4, delivery.data(), delivery.size());
		memcpy(wire.data() + 189, record.owner_wire.data(),
		    record.owner_wire.size());
		memcpy(wire.data() + 265, record.program_digest.data(),
		    record.program_digest.size());
		if (SHA256(wire.data(), 297, wire.data() + 297) == NULL)
			return (false);
		encoded.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

bool
dir::decode_import_consumer_receipt(const durable_delivery &ingress,
    const std::vector<uint8_t> &encoded,
    durable_import_consumer_receipt &decoded)
{
	decoded = {};
	if (ingress.scope != 3 || ingress.journal_version != 5 ||
	    !delivery_record_valid(ingress) ||
	    encoded.size() != import_consumer_receipt_wire_size ||
	    memcmp(encoded.data(), "HCR2", 4) != 0) {
		errno = EPROTO;
		return (false);
	}
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (SHA256(encoded.data(), 297, digest) == NULL ||
	    memcmp(encoded.data() + 297, digest, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	const auto expected_delivery = delivery_record_bytes(ingress);
	if (memcmp(encoded.data() + 4, expected_delivery.data(),
	    expected_delivery.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	durable_import_consumer_receipt record{};
	record.ingress = ingress;
	memcpy(record.owner_wire.data(), encoded.data() + 189,
	    record.owner_wire.size());
	memcpy(record.program_digest.data(), encoded.data() + 265,
	    record.program_digest.size());
	if (!import_consumer_receipt_valid(record)) {
		errno = EPROTO;
		return (false);
	}
	decoded = record;
	return (true);
}

bool
dir::encode_import_consumer_cohort(const durable_delivery &ingress,
    const std::vector<durable_import_consumer_receipt> &proposed,
    std::vector<uint8_t> &encoded)
{
	encoded.clear();
	if (ingress.scope != 3 || ingress.journal_version != 5 ||
	    !delivery_record_valid(ingress) || proposed.empty() ||
	    proposed.size() > consumer_receipt_limit) {
		errno = EINVAL;
		return (false);
	}
	try {
		std::vector<durable_import_consumer_receipt> members = proposed;
		std::sort(members.begin(), members.end(),
		    [](const auto &a, const auto &b) {
		    return std::lexicographical_compare(a.owner_wire.begin() + 4,
		    a.owner_wire.begin() + 20, b.owner_wire.begin() + 4,
		    b.owner_wire.begin() + 20);
		    });
		std::vector<uint8_t> wire(8 + members.size() *
		    import_consumer_receipt_wire_size + 32);
		memcpy(wire.data(), "HCB2", 4);
		dtraced_wire_put_u32(wire.data() + 4, (uint32_t)members.size());
		const auto expected_delivery = delivery_record_bytes(ingress);
		for (size_t i = 0; i < members.size(); i++) {
			std::vector<uint8_t> receipt;
			if (!encode_import_consumer_receipt(members[i], receipt) ||
			    memcmp(receipt.data() + 4, expected_delivery.data(),
			    expected_delivery.size()) != 0 ||
			    (i != 0 && memcmp(members[i - 1].owner_wire.data() + 4,
			    members[i].owner_wire.data() + 4, 16) == 0)) {
				errno = EPROTO;
				return (false);
			}
			memcpy(wire.data() + 8 + i *
			    import_consumer_receipt_wire_size, receipt.data(),
			    receipt.size());
		}
		if (SHA256(wire.data(), wire.size() - 32,
		    wire.data() + wire.size() - 32) == NULL)
			return (false);
		encoded.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

bool
dir::decode_import_consumer_cohort(const durable_delivery &ingress,
    const std::vector<uint8_t> &encoded,
    std::vector<durable_import_consumer_receipt> &decoded)
{
	decoded.clear();
	if (ingress.scope != 3 || ingress.journal_version != 5 ||
	    !delivery_record_valid(ingress) || encoded.size() < 8 + 32 ||
	    memcmp(encoded.data(), "HCB2", 4) != 0) {
		errno = EPROTO;
		return (false);
	}
	uint32_t count = dtraced_wire_get_u32(encoded.data() + 4);
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (count == 0 || count > consumer_receipt_limit ||
	    encoded.size() != 8 + (size_t)count *
	    import_consumer_receipt_wire_size + sizeof(digest) ||
	    SHA256(encoded.data(), encoded.size() - sizeof(digest), digest) ==
	    NULL || memcmp(encoded.data() + encoded.size() - sizeof(digest),
	    digest, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::vector<durable_import_consumer_receipt> members;
		members.reserve(count);
		for (uint32_t i = 0; i < count; i++) {
			const uint8_t *entry = encoded.data() + 8 +
			    (size_t)i * import_consumer_receipt_wire_size;
			std::vector<uint8_t> receipt(entry,
			    entry + import_consumer_receipt_wire_size);
			durable_import_consumer_receipt record{};
			if (!decode_import_consumer_receipt(ingress, receipt, record) ||
			    (i != 0 && memcmp(members.back().owner_wire.data() + 4,
			    record.owner_wire.data() + 4, 16) >= 0)) {
				errno = EPROTO;
				return (false);
			}
			members.push_back(record);
		}
		decoded.swap(members);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

static bool
import_consumer_result_valid(const durable_import_consumer_result &record)
{
	bool derived = record.phase == consumer_receipt_phase::derived ||
	    record.phase == consumer_receipt_phase::executed_derived;
	bool no_derived = record.phase == consumer_receipt_phase::no_derived ||
	    record.phase == consumer_receipt_phase::executed_no_derived;
	return (record.token != std::array<uint8_t, 16>{} &&
	    record.slots_digest != std::array<uint8_t, 32>{} &&
	    record.receipt_digest != std::array<uint8_t, 32>{} &&
	    (derived || no_derived) &&
	    (derived ==
	    (record.derived_claim_digest != std::array<uint8_t, 32>{})));
}

bool
dir::encode_import_consumer_result(
    const durable_import_consumer_result &record,
    std::vector<uint8_t> &encoded)
{
	encoded.clear();
	if (!import_consumer_result_valid(record)) {
		errno = EINVAL;
		return (false);
	}
	try {
		std::vector<uint8_t> wire(156, 0);
		memcpy(wire.data(), "HRO1", 4);
		memcpy(wire.data() + 4, record.token.data(), 16);
		memcpy(wire.data() + 20, record.slots_digest.data(), 32);
		memcpy(wire.data() + 52, record.receipt_digest.data(), 32);
		wire[84] = (uint8_t)record.phase;
		memcpy(wire.data() + 85,
		    record.derived_claim_digest.data(), 32);
		if (SHA256(wire.data(), 124, wire.data() + 124) == NULL)
			return (false);
		encoded.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

bool
dir::decode_import_consumer_result(const std::vector<uint8_t> &encoded,
    durable_import_consumer_result &decoded)
{
	decoded = {};
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (encoded.size() != 156 ||
	    memcmp(encoded.data(), "HRO1", 4) != 0 ||
	    std::any_of(encoded.begin() + 117, encoded.begin() + 124,
	    [](uint8_t value) { return (value != 0); }) ||
	    SHA256(encoded.data(), 124, digest) == NULL ||
	    memcmp(encoded.data() + 124, digest, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	durable_import_consumer_result record{};
	memcpy(record.token.data(), encoded.data() + 4, 16);
	memcpy(record.slots_digest.data(), encoded.data() + 20, 32);
	memcpy(record.receipt_digest.data(), encoded.data() + 52, 32);
	record.phase = (consumer_receipt_phase)encoded[84];
	memcpy(record.derived_claim_digest.data(), encoded.data() + 85, 32);
	if (!import_consumer_result_valid(record)) {
		errno = EPROTO;
		return (false);
	}
	decoded = record;
	return (true);
}

bool
dir::plan_import_consumer_cohorts(
    const host_ingress_destination_plan &plan,
    const std::vector<std::array<uint8_t, 76>> &owners,
    std::vector<std::vector<uint8_t>> &encoded)
{
	encoded.clear();
	if (plan.deliveries.empty() ||
	    plan.deliveries.size() != plan.source_entries.size() ||
	    plan.source_programs.empty() || owners.empty() ||
	    owners.size() > consumer_receipt_limit) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::map<std::array<uint8_t, 16>, std::array<uint8_t, 76>>
		    by_session;
		for (const auto &owner : owners) {
			std::array<uint8_t, 16> session{};
			memcpy(session.data(), owner.data() + 4, session.size());
			if (session == std::array<uint8_t, 16>{} ||
			    !by_session.emplace(session, owner).second) {
				errno = EPROTO;
				return (false);
			}
		}
		std::map<std::array<uint8_t, 16>, bool> used;
		std::vector<std::vector<uint8_t>> cohorts;
		cohorts.reserve(plan.deliveries.size());
		size_t proof_index = 0;
		for (size_t i = 0; i < plan.deliveries.size(); i++) {
			std::vector<durable_import_consumer_receipt> members;
			members.reserve(plan.source_entries[i].recipients.size());
			for (const auto &source :
			    plan.source_entries[i].recipients) {
				if (proof_index == plan.source_programs.size()) {
					errno = EPROTO;
					return (false);
				}
				const auto &proof =
				    plan.source_programs[proof_index++];
				if (consumer_receipt_bytes(proof.recipient) !=
				    consumer_receipt_bytes(source.record) ||
				    proof.program_digest ==
				    std::array<uint8_t, 32>{}) {
					errno = EPROTO;
					return (false);
				}
				auto owner = by_session.find(
				    proof.recipient.consumer_session);
				if (owner == by_session.end() ||
				    dtraced_wire_get_u32(owner->second.data() + 20) !=
				    proof.recipient.consumer_uid) {
					errno = EPROTO;
					return (false);
				}
				used.emplace(owner->first, true);
				durable_import_consumer_receipt member{};
				member.ingress = plan.deliveries[i];
				member.owner_wire = owner->second;
				member.program_digest = proof.program_digest;
				members.push_back(member);
			}
			std::vector<uint8_t> cohort;
			if (!encode_import_consumer_cohort(plan.deliveries[i],
			    members, cohort))
				return (false);
			cohorts.push_back(std::move(cohort));
		}
		if (proof_index != plan.source_programs.size() ||
		    used.size() != by_session.size()) {
			errno = EPROTO;
			return (false);
		}
		encoded.swap(cohorts);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}
/* HT-C END */

/* HCB1 fixes the complete recipient set before any HCR1 or socket job can
 * become visible. A crash between HCR1 writes can then reconstruct the set. */
static void
consumer_cohort_name(const durable_delivery &ingress, char name[58])
{
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".cohort.", 8);
	for (size_t i = 0; i < 16; i++) {
		name[8 + i * 2] = hex[ingress.session_id[i] >> 4];
		name[9 + i * 2] = hex[ingress.session_id[i] & 15];
	}
	name[40] = '.';
	(void)snprintf(name + 41, 17, "%016jx",
	    (uintmax_t)ingress.delivery_id);
}

static int
consumer_cohort_read_at(int directory, const durable_delivery &ingress,
    std::vector<durable_consumer_receipt> &records)
{
	char name[58];
	consumer_cohort_name(ingress, name);
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_size < 8 + 32 ||
	    sb.st_size > (off_t)(8 + consumer_receipt_limit *
	    consumer_receipt_wire_size + 32)))
		error = EPROTO;
	std::vector<uint8_t> wire;
	try {
		if (error == 0)
			wire.resize((size_t)sb.st_size);
	} catch (const std::bad_alloc &) {
		error = ENOMEM;
	}
	size_t offset = 0;
	while (error == 0 && offset < wire.size()) {
		ssize_t n = pread(fd, wire.data() + offset,
		    wire.size() - offset, (off_t)offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EPROTO;
			break;
		}
		offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	uint32_t count = dtraced_wire_get_u32(wire.data() + 4);
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (memcmp(wire.data(), "HCB1", 4) != 0 || count == 0 ||
	    count > consumer_receipt_limit ||
	    wire.size() != 8 + (size_t)count * consumer_receipt_wire_size +
	    sizeof(digest) ||
	    SHA256(wire.data(), wire.size() - sizeof(digest), digest) == NULL ||
	    memcmp(digest, wire.data() + wire.size() - sizeof(digest),
	    sizeof(digest)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	std::vector<durable_consumer_receipt> parsed;
	try {
		parsed.reserve(count);
		for (uint32_t i = 0; i < count; i++) {
			const uint8_t *entry = wire.data() + 8 +
			    (size_t)i * consumer_receipt_wire_size;
			durable_consumer_receipt record{};
			record.ingress = ingress;
			memcpy(record.consumer_session.data(), entry + 102, 16);
			record.consumer_uid = dtraced_wire_get_u32(entry + 118);
			record.consumer_pid = dtraced_wire_get_u32(entry + 122);
			if (!consumer_receipt_valid(record) ||
			    (i != 0 && parsed.back().consumer_session >=
			    record.consumer_session) ||
			    memcmp(consumer_receipt_bytes(record).data(), entry,
			    consumer_receipt_wire_size) != 0) {
				errno = EPROTO;
				return (-1);
			}
			parsed.push_back(record);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
	records.swap(parsed);
	return (1);
}

static int consumer_receipt_count_at(int);
static int consumer_receipt_status_at(int,
    const durable_consumer_receipt &);

/* HCB1 reserves future HCR1 slots. Count those missing receipts together
 * with materialized HCR1 files while the inbound journal lock is held, so
 * another ingress cannot consume capacity promised by an earlier cohort. */
static bool
consumer_receipt_reserved_at(int directory, size_t &reserved)
{
	int existing = consumer_receipt_count_at(directory);
	if (existing < 0)
		return (false);
	if ((size_t)existing > consumer_receipt_limit) {
		errno = ENOSPC;
		return (false);
	}
	reserved = (size_t)existing;
	std::vector<durable_delivery_state> deliveries;
	if (!list_deliveries_at(directory, deliveries))
		return (false);
	std::unordered_map<std::string, const durable_delivery *> accepted;
	try {
		for (const auto &entry : deliveries) {
			if (entry.record.scope != 3 ||
			    entry.phase != delivery_phase::accepted)
				continue;
			char name[58];
			consumer_cohort_name(entry.record, name);
			if (!accepted.emplace(name, &entry.record).second) {
				errno = EPROTO;
				return (false);
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	try {
		for (;;) {
			errno = 0;
			struct dirent *file = readdir(scan);
			if (file == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(file->d_name, ".cohort.", 8) != 0 ||
			    strncmp(file->d_name, ".cohort.tmp.", 12) == 0)
				continue;
			auto found = accepted.find(file->d_name);
			if (found == accepted.end()) {
				error = EPROTO;
				break;
			}
			std::vector<durable_consumer_receipt> members;
			int cohort_status = consumer_cohort_read_at(directory,
			    *found->second, members);
			if (cohort_status != 1) {
				error = cohort_status == 0 ? EPROTO : errno;
				break;
			}
			for (const auto &member : members) {
				int status = consumer_receipt_status_at(directory,
				    member);
				if (status < 0) {
					error = errno;
					break;
				}
				if (status == 0 && ++reserved >
				    consumer_receipt_limit) {
					error = ENOSPC;
					break;
				}
			}
			if (error != 0)
				break;
		}
	} catch (const std::bad_alloc &) {
		error = ENOMEM;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

int
dir::consumer_cohort(const durable_delivery &ingress,
    const std::vector<durable_consumer_receipt> &proposed,
    std::vector<durable_consumer_receipt> &fixed)
{
	if (ingress.scope != 3 || ingress.journal_version != 4 ||
	    !delivery_record_valid(ingress)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	int present = consumer_cohort_read_at(this->dirfd, ingress, fixed);
	if (present != 0 || proposed.empty())
		return (present);
	if (proposed.size() > consumer_receipt_limit) {
		errno = EPROTO;
		return (-1);
	}
	int ingress_phase = delivery_record_status_at(this->dirfd, ingress);
	if (ingress_phase < 0)
		return (-1);
	if (ingress_phase != (int)delivery_phase::accepted) {
		errno = EPROTO;
		return (-1);
	}
	size_t reserved = 0;
	if (!consumer_receipt_reserved_at(this->dirfd, reserved))
		return (-1);
	if (proposed.size() > consumer_receipt_limit - reserved) {
		errno = ENOSPC;
		return (-1);
	}
	std::vector<durable_consumer_receipt> selected;
	std::vector<uint8_t> wire;
	try {
		selected = proposed;
		std::sort(selected.begin(), selected.end(),
		    [](const auto &a, const auto &b) {
		    return a.consumer_session < b.consumer_session;
		    });
		wire.resize(8 + selected.size() * consumer_receipt_wire_size + 32);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
	memcpy(wire.data(), "HCB1", 4);
	dtraced_wire_put_u32(wire.data() + 4, (uint32_t)selected.size());
	auto ingress_wire = consumer_receipt_bytes(
	    durable_consumer_receipt{ingress});
	for (size_t i = 0; i < selected.size(); i++) {
		const auto &record = selected[i];
		if (!consumer_receipt_valid(record) ||
		    (i != 0 && selected[i - 1].consumer_session ==
		    record.consumer_session)) {
			errno = EPROTO;
			return (-1);
		}
		auto expected = consumer_receipt_bytes(record);
		if (memcmp(expected.data() + 4, ingress_wire.data() + 4,
		    98) != 0) {
			errno = EPROTO;
			return (-1);
		}
		memcpy(wire.data() + 8 + i * consumer_receipt_wire_size,
		    expected.data(), expected.size());
	}
	(void)SHA256(wire.data(), wire.size() - 32, wire.data() +
	    wire.size() - 32);
	char name[58], temporary[45];
	consumer_cohort_name(ingress, name);
	uint8_t nonce[16];
	arc4random_buf(nonce, sizeof(nonce));
	static const char hex[] = "0123456789abcdef";
	memcpy(temporary, ".cohort.tmp.", 12);
	for (size_t i = 0; i < sizeof(nonce); i++) {
		temporary[12 + i * 2] = hex[nonce[i] >> 4];
		temporary[13 + i * 2] = hex[nonce[i] & 15];
	}
	temporary[44] = '\0';
	int fd = openat(this->dirfd, temporary,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (-1);
	size_t offset = 0;
	int error = 0;
	while (offset < wire.size()) {
		ssize_t n = write(fd, wire.data() + offset, wire.size() - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && linkat(this->dirfd, temporary, this->dirfd,
	    name, 0) != 0)
		error = errno;
	if (error == 0 && fsync(this->dirfd) != 0)
		error = errno;
	if (unlink_published_temporary_at(this->dirfd, temporary) != 0 &&
	    error == 0)
		error = errno;
	if (error == 0 && fsync(this->dirfd) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	fixed.swap(selected);
	return (1);
}

bool
dir::recover_consumer_cohorts(
    const std::vector<durable_delivery_state> &ingresses)
{
	std::unordered_map<std::string, const durable_delivery *> accepted;
	std::vector<const durable_delivery *> present;
	try {
		for (const auto &entry : ingresses) {
			if (entry.record.scope != 3 ||
			    entry.phase != delivery_phase::accepted)
				continue;
			char name[58];
			consumer_cohort_name(entry.record, name);
			if (!accepted.emplace(name, &entry.record).second) {
				errno = EPROTO;
				return (false);
			}
		}
		int scanfd = openat(this->dirfd, ".",
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (scanfd < 0)
			return (false);
		DIR *scan = fdopendir(scanfd);
		if (scan == nullptr) {
			int error = errno;
			close(scanfd);
			errno = error;
			return (false);
		}
		int error = 0;
		for (;;) {
			errno = 0;
			struct dirent *file = readdir(scan);
			if (file == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(file->d_name, ".cohort.", 8) != 0 ||
			    strncmp(file->d_name, ".cohort.tmp.", 12) == 0)
				continue;
			auto found = accepted.find(file->d_name);
			if (found == accepted.end()) {
				error = EPROTO;
				break;
			}
			present.push_back(found->second);
		}
		if (closedir(scan) != 0 && error == 0)
			error = errno;
		if (error != 0) {
			errno = error;
			return (false);
		}
		for (const auto *ingress : present) {
			std::vector<durable_consumer_receipt> fixed;
			if (consumer_cohort(*ingress, {}, fixed) != 1)
				return (false);
			for (const auto &record : fixed)
				if (record_consumer_receipt(record,
				    consumer_receipt_phase::pending) < 0)
					return (false);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	return (true);
}

static int
consumer_receipt_read_at(int directory, const char *name,
    std::array<uint8_t, consumer_receipt_wire_size> &wire)
{
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	int error = 0;
	if (fstat(fd, &sb) != 0)
		error = errno;
	else if (!S_ISREG(sb.st_mode) ||
	    sb.st_size != (off_t)wire.size())
		error = EPROTO;
	else {
		ssize_t n;
		do {
			n = pread(fd, wire.data(), wire.size(), 0);
		} while (n < 0 && errno == EINTR);
		if (n != (ssize_t)wire.size())
			error = n < 0 ? errno : EPROTO;
		else {
			uint8_t digest[SHA256_DIGEST_LENGTH];
			(void)SHA256(wire.data(), 126, digest);
			if (memcmp(wire.data(), "HCR1", 4) != 0 ||
			    memcmp(wire.data() + 126, digest,
			    sizeof(digest)) != 0)
				error = EPROTO;
		}
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

static int
consumer_receipt_status_at(int directory,
    const durable_consumer_receipt &record)
{
	const auto expected = consumer_receipt_bytes(record);
	int found = 0;
	for (consumer_receipt_phase phase : {consumer_receipt_phase::pending,
	    consumer_receipt_phase::processed,
	    consumer_receipt_phase::no_derived,
	    consumer_receipt_phase::derived,
	    consumer_receipt_phase::executed_no_derived,
	    consumer_receipt_phase::executed_derived}) {
		char name[96];
		consumer_receipt_name(record, phase, name);
		std::array<uint8_t, consumer_receipt_wire_size> actual{};
		int status = consumer_receipt_read_at(directory, name, actual);
		if (status < 0)
			return (-1);
		if (status != 0) {
			if (found != 0 || actual != expected) {
				errno = EPROTO;
				return (-1);
			}
			found = (char)phase;
		}
	}
	return (found);
}

static int
consumer_receipt_count_at(int directory)
{
	int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	DIR *scan = fdopendir(fd);
	if (scan == nullptr) {
		int error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	int count = 0, error = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		if (strncmp(entry->d_name, ".consumer.", 10) == 0)
			count++;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (count);
}

int
dir::record_consumer_receipt(const durable_consumer_receipt &record,
    consumer_receipt_phase phase)
{
	if (!consumer_receipt_valid(record) ||
	    (phase != consumer_receipt_phase::pending &&
	    phase != consumer_receipt_phase::no_derived &&
	    phase != consumer_receipt_phase::derived &&
	    phase != consumer_receipt_phase::executed_no_derived &&
	    phase != consumer_receipt_phase::executed_derived)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	int ingress_phase = delivery_record_status_at(this->dirfd,
	    record.ingress);
	if (ingress_phase < 0)
		return (-1);
	if (ingress_phase != (int)delivery_phase::accepted) {
		errno = ingress_phase == 0 ? ENOENT : EPROTO;
		return (-1);
	}
	std::vector<durable_consumer_receipt> cohort;
	int cohort_present = consumer_cohort_read_at(this->dirfd,
	    record.ingress, cohort);
	if (cohort_present < 0)
		return (-1);
	if (cohort_present != 0) {
		const auto expected = consumer_receipt_bytes(record);
		bool member = false;
		for (const auto &candidate : cohort)
			if (consumer_receipt_bytes(candidate) == expected) {
				member = true;
				break;
			}
		if (!member) {
			errno = EPROTO;
			return (-1);
		}
	}
	int current = consumer_receipt_status_at(this->dirfd, record);
	if (current < 0)
		return (-1);
	if (current == (int)phase ||
	    (current == (int)consumer_receipt_phase::executed_no_derived &&
	    phase == consumer_receipt_phase::no_derived) ||
	    (current == (int)consumer_receipt_phase::executed_derived &&
	    phase == consumer_receipt_phase::derived) ||
	    (current != 0 && current !=
	    (int)consumer_receipt_phase::pending &&
	    phase == consumer_receipt_phase::pending)) {
		if (fsync(this->dirfd) != 0)
			return (-1);
		return (current);
	}
	consumer_receipt_phase from = consumer_receipt_phase::pending;
	if (current == (int)consumer_receipt_phase::no_derived &&
	    phase == consumer_receipt_phase::executed_no_derived)
		from = consumer_receipt_phase::no_derived;
	else if (current == (int)consumer_receipt_phase::derived &&
	    phase == consumer_receipt_phase::executed_derived)
		from = consumer_receipt_phase::derived;
	else if (current == (int)consumer_receipt_phase::pending &&
	    phase != consumer_receipt_phase::no_derived &&
	    phase != consumer_receipt_phase::derived) {
		errno = EPROTO;
		return (-1);
	} else if (current != 0 &&
	    current != (int)consumer_receipt_phase::pending) {
		errno = EPROTO;
		return (-1);
	}
	char pending[96], completed[96];
	consumer_receipt_name(record, from, pending);
	consumer_receipt_name(record, phase, completed);
	if (current != 0) {
		if (renameat(this->dirfd, pending, this->dirfd, completed) != 0 ||
		    fsync(this->dirfd) != 0)
			return (-1);
		return ((int)phase);
	}
	if (phase != consumer_receipt_phase::pending) {
		errno = ENOENT;
		return (-1);
	}
	if (cohort_present == 0) {
		size_t reserved = 0;
		if (!consumer_receipt_reserved_at(this->dirfd, reserved))
			return (-1);
		if (reserved >= consumer_receipt_limit) {
			errno = ENOSPC;
			return (-1);
		}
	}
	int count = consumer_receipt_count_at(this->dirfd);
	if (count < 0)
		return (-1);
	if ((size_t)count >= consumer_receipt_limit) {
		errno = ENOSPC;
		return (-1);
	}
	char temporary[47];
	uint8_t nonce[16];
	arc4random_buf(nonce, sizeof(nonce));
	static const char hex[] = "0123456789abcdef";
	memcpy(temporary, ".consumer.tmp.", 14);
	for (size_t i = 0; i < sizeof(nonce); i++) {
		temporary[14 + i * 2] = hex[nonce[i] >> 4];
		temporary[15 + i * 2] = hex[nonce[i] & 15];
	}
	temporary[46] = '\0';
	int fd = openat(this->dirfd, temporary,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (-1);
	const auto wire = consumer_receipt_bytes(record);
	size_t offset = 0;
	int error = 0;
	while (offset < wire.size()) {
		ssize_t n = write(fd, wire.data() + offset,
		    wire.size() - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && linkat(this->dirfd, temporary, this->dirfd,
	    pending, 0) != 0)
		error = errno;
	if (error == 0 && fsync(this->dirfd) != 0)
		error = errno;
	if (unlink_published_temporary_at(this->dirfd, temporary) != 0 &&
	    error == 0)
		error = errno;
	if (error == 0 && fsync(this->dirfd) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return ((int)consumer_receipt_phase::pending);
}

bool
dir::list_consumer_receipts(
    std::vector<durable_consumer_receipt_state> &records)
{
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	std::vector<durable_delivery_state> ingress;
	if (!list_deliveries_at(this->dirfd, ingress))
		return (false);
	/* A recovery scan can contain the full journal limit of both ingress
	 * deliveries and recipients. Index the complete authenticated ingress
	 * identity once rather than searching every delivery for each HCR1 file. */
	std::unordered_multimap<std::string, const durable_delivery *> sources;
	try {
		for (const auto &candidate : ingress) {
			if (candidate.record.scope != 3 ||
			    candidate.phase != delivery_phase::accepted)
				continue;
			durable_consumer_receipt probe{};
			probe.ingress = candidate.record;
			const auto wire = consumer_receipt_bytes(probe);
			sources.emplace(std::string((const char *)wire.data() + 4,
			    98), &candidate.record);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	int fd = openat(this->dirfd, ".",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return (false);
	DIR *scan = fdopendir(fd);
	if (scan == nullptr) {
		int error = errno;
		close(fd);
		errno = error;
		return (false);
	}
	std::vector<durable_consumer_receipt_state> recovered;
	std::unordered_set<std::string> seen;
	int error = 0;
	try {
		for (;;) {
			errno = 0;
			struct dirent *file = readdir(scan);
			if (file == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(file->d_name, ".consumer.", 10) != 0)
				continue;
			if (recovered.size() >= consumer_receipt_limit ||
			    strlen(file->d_name) != 94 ||
			    (file->d_name[93] != 'p' && file->d_name[93] != 'c' &&
			    file->d_name[93] != 'n' && file->d_name[93] != 'd' &&
			    file->d_name[93] != 'N' && file->d_name[93] != 'D')) {
				error = EPROTO;
				break;
			}
			std::array<uint8_t, consumer_receipt_wire_size> wire{};
			if (consumer_receipt_read_at(this->dirfd, file->d_name,
			    wire) != 1) {
				error = errno == ENOENT ? EPROTO : errno;
				break;
			}
			durable_consumer_receipt_state entry{};
			const auto range = sources.equal_range(std::string(
			    (const char *)wire.data() + 4, 98));
			auto next = range.first;
			if (next == range.second || ++next != range.second) {
				error = EPROTO;
				break;
			}
			entry.record.ingress = *range.first->second;
			memcpy(entry.record.consumer_session.data(),
			    wire.data() + 102, 16);
			for (unsigned i = 0; i < 4; i++) {
				entry.record.consumer_uid |=
				    (uint32_t)wire[118 + i] << (8 * i);
				entry.record.consumer_pid |=
				    (uint32_t)wire[122 + i] << (8 * i);
			}
			entry.phase = (consumer_receipt_phase)file->d_name[93];
			char canonical[96];
			consumer_receipt_name(entry.record, entry.phase, canonical);
			if (!consumer_receipt_valid(entry.record) ||
			    strcmp(canonical, file->d_name) != 0 ||
			    consumer_receipt_bytes(entry.record) != wire ||
			    !seen.insert(std::string(file->d_name, 93)).second) {
				error = EPROTO;
				break;
			}
			recovered.push_back(entry);
		}
	} catch (const std::bad_alloc &) {
		error = ENOMEM;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	records.swap(recovered);
	return (true);
}

int
dir::consumer_receipt_exact(const std::array<uint8_t, 16> &ingress_session,
    uint64_t delivery_id, const std::array<uint8_t, 16> &consumer_session,
    uint32_t consumer_uid, uint32_t consumer_pid,
    durable_consumer_receipt_state &found)
{
	const std::array<uint8_t, 16> zero{};
	found = {};
	if (ingress_session == zero || consumer_session == zero ||
	    delivery_id == 0 || consumer_uid == UINT32_MAX ||
	    consumer_pid <= 1) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_delivery key{};
	key.session_id = ingress_session;
	key.delivery_id = delivery_id;
	char name[80];
	delivery_record_name(key, delivery_phase::accepted, name);
	std::array<uint8_t, 185> wire{};
	size_t length = 0;
	int present = delivery_read_at(this->dirfd, name, wire, length);
	if (present <= 0)
		return (present);
	durable_delivery_state ingress{};
	if (!delivery_record_parse(this->dirfd, name, ingress))
		return (-1);
	int ingress_phase = delivery_record_status_at(this->dirfd,
	    ingress.record);
	if (ingress_phase < 0)
		return (-1);
	if (ingress.phase != delivery_phase::accepted ||
	    ingress.record.scope != 3 ||
	    ingress_phase != (int)delivery_phase::accepted) {
		errno = EPROTO;
		return (-1);
	}
	/* HTD5 receipts live in the fixed HCR2 cohort, not HCR1. Return the
	 * exact accepted ingress so the caller can resolve its ticket/HLA1. */
	if (ingress.record.journal_version == 5) {
		/* HT-C BEGIN: disabled trace continuity. */
		if (fsync(this->dirfd) != 0)
			return (-1);
		found.record.ingress = ingress.record;
		found.record.consumer_session = consumer_session;
		found.record.consumer_uid = consumer_uid;
		found.record.consumer_pid = consumer_pid;
		found.phase = consumer_receipt_phase::pending;
		return (2);
		/* HT-C END */
	}
	durable_consumer_receipt record{};
	record.ingress = ingress.record;
	record.consumer_session = consumer_session;
	record.consumer_uid = consumer_uid;
	record.consumer_pid = consumer_pid;
	if (!consumer_receipt_valid(record)) {
		errno = EPROTO;
		return (-1);
	}
	int phase = consumer_receipt_status_at(this->dirfd, record);
	if (phase <= 0)
		return (phase);
	if (fsync(this->dirfd) != 0)
		return (-1);
	found.record = record;
	found.phase = (consumer_receipt_phase)phase;
	return (1);
}

/* HDU2 claims one immutable derived result for a recipient and target VM
 * lifetime. A claim is durable before its identified ELF spool is visible. */
static constexpr size_t derived_claim_wire_size = 192;
static constexpr size_t derived_claim_limit = 65536;

static dtraced_derived_parent_t
derived_claim_parent(const durable_derived_claim &claim)
{
	dtraced_derived_parent_t parent{};
	memcpy(parent.consumer_session, claim.consumer_session.data(), 16);
	parent.delivery_id = claim.ingress_delivery_id;
	parent.vmid = claim.ingress_vmid;
	parent.epoch = claim.ingress_epoch;
	memcpy(parent.program_id, claim.ingress_program_id.data(), 16);
	memcpy(parent.source_id, claim.ingress_source_id.data(), 16);
	return (parent);
}

static bool
derived_claim_valid(const durable_derived_claim &claim)
{
	dtraced_derived_parent_t parent = derived_claim_parent(claim);
	uint8_t expected[16];
	return (dtraced_derived_parent_valid(&parent) &&
	    claim.target_vmid != 0 && claim.target_vmid < HYPERTRACE_MAX_VMS &&
	    claim.target_epoch != 0 &&
	    dtraced_derived_program_id_from_digest(&parent,
	    claim.payload_digest.data(), expected) == 0 &&
	    memcmp(expected, claim.derived_program_id.data(), 16) == 0);
}

static std::array<uint8_t, derived_claim_wire_size>
derived_claim_bytes(const durable_derived_claim &claim)
{
	std::array<uint8_t, derived_claim_wire_size> wire{};
	memcpy(wire.data(), "HDU2", 4);
	memcpy(wire.data() + 4, claim.consumer_session.data(), 16);
	dtraced_wire_put_u64(wire.data() + 20, claim.ingress_delivery_id);
	dtraced_wire_put_u16(wire.data() + 28, claim.ingress_vmid);
	dtraced_wire_put_u64(wire.data() + 30, claim.ingress_epoch);
	memcpy(wire.data() + 38, claim.ingress_program_id.data(), 16);
	memcpy(wire.data() + 54, claim.ingress_source_id.data(), 16);
	dtraced_wire_put_u16(wire.data() + 70, claim.target_vmid);
	dtraced_wire_put_u64(wire.data() + 72, claim.target_epoch);
	memcpy(wire.data() + 80, claim.derived_program_id.data(), 16);
	memcpy(wire.data() + 96, claim.payload_digest.data(), 32);
	memcpy(wire.data() + 128, claim.bare_elf_digest.data(), 32);
	(void)SHA256(wire.data(), 160, wire.data() + 160);
	return (wire);
}

static void
derived_claim_name(const std::array<uint8_t, derived_claim_wire_size> &wire,
    char name[42])
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	static const char hex[] = "0123456789abcdef";
	(void)SHA256(wire.data(), 80, digest);
	memcpy(name, ".derived.", 9);
	for (unsigned i = 0; i < 16; i++) {
		name[9 + i * 2] = hex[digest[i] >> 4];
		name[10 + i * 2] = hex[digest[i] & 15];
	}
	name[41] = '\0';
}

static int
derived_claim_read_at(int directory, const char *name,
    std::array<uint8_t, derived_claim_wire_size> &wire)
{
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	int error = 0;
	if (fstat(fd, &sb) != 0)
		error = errno;
	else if (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_size != (off_t)wire.size())
		error = EPROTO;
	else {
		ssize_t n;
		do {
			n = pread(fd, wire.data(), wire.size(), 0);
		} while (n < 0 && errno == EINTR);
		if (n != (ssize_t)wire.size())
			error = n < 0 ? errno : EPROTO;
		else {
			uint8_t digest[SHA256_DIGEST_LENGTH];
			(void)SHA256(wire.data(), 160, digest);
			if (memcmp(wire.data(), "HDU2", 4) != 0 ||
			    memcmp(wire.data() + 160, digest, sizeof(digest)) != 0)
				error = EPROTO;
		}
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

static int
derived_claim_count_at(int directory,
    const std::array<uint8_t, derived_claim_wire_size> &proposed)
{
	int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	DIR *scan = fdopendir(fd);
	if (scan == nullptr) {
		int error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	int count = 0, error = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		if (strncmp(entry->d_name, ".derived.", 9) != 0)
			continue;
		std::array<uint8_t, derived_claim_wire_size> existing{};
		if (derived_claim_read_at(directory, entry->d_name,
		    existing) != 1) {
			error = errno == ENOENT ? EPROTO : errno;
			break;
		}
		char canonical[42];
		derived_claim_name(existing, canonical);
		if (strcmp(canonical, entry->d_name) != 0 ||
		    (memcmp(existing.data(), proposed.data(), 70) == 0 &&
		    existing != proposed)) {
			error = EPROTO;
			break;
		}
		count++;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (count);
}

static bool
derived_claim_record_at(int directory, const durable_derived_claim &claim)
{
	if (!derived_claim_valid(claim)) {
		errno = EINVAL;
		return (false);
	}
	const auto wire = derived_claim_bytes(claim);
	char name[42], temporary[38];
	derived_claim_name(wire, name);
	int count = derived_claim_count_at(directory, wire);
	if (count < 0)
		return (false);
	std::array<uint8_t, derived_claim_wire_size> current{};
	int status = derived_claim_read_at(directory, name, current);
	if (status < 0)
		return (false);
	if (status != 0) {
		if (current != wire) {
			errno = EPROTO;
			return (false);
		}
		return (fsync(directory) == 0);
	}
	if ((size_t)count >= derived_claim_limit) {
		errno = ENOSPC;
		return (false);
	}
	int fd = -1;
	static const char hex[] = "0123456789abcdef";
	for (unsigned attempt = 0; attempt < 8; attempt++) {
		uint8_t nonce[16];
		arc4random_buf(nonce, sizeof(nonce));
		memcpy(temporary, ".elf.", 5);
		for (unsigned i = 0; i < 16; i++) {
			temporary[5 + i * 2] = hex[nonce[i] >> 4];
			temporary[6 + i * 2] = hex[nonce[i] & 15];
		}
		temporary[37] = '\0';
		fd = openat(directory, temporary,
		    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (fd >= 0)
			break;
		if (errno != EEXIST)
			return (false);
	}
	if (fd < 0)
		return (false);
	size_t offset = 0;
	int error = 0;
	while (offset < wire.size()) {
		ssize_t n = write(fd, wire.data() + offset, wire.size() - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && linkat(directory, temporary,
	    directory, name, 0) != 0) {
		error = errno;
		if (error == EEXIST) {
			status = derived_claim_read_at(directory, name, current);
			error = status == 1 && current == wire ? 0 :
			    status < 0 ? errno : EPROTO;
		}
	}
	if (unlink_published_temporary_at(directory, temporary) != 0 &&
	    error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

static bool
list_derived_claims_at(int directory,
    std::vector<durable_derived_claim> &records)
{
	int fd = openat(directory, ".",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return (false);
	DIR *scan = fdopendir(fd);
	if (scan == nullptr) {
		int error = errno;
		close(fd);
		errno = error;
		return (false);
	}
	std::vector<durable_derived_claim> recovered;
	int error = 0;
	try {
		for (;;) {
			errno = 0;
			struct dirent *entry = readdir(scan);
			if (entry == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(entry->d_name, ".derived.", 9) != 0)
				continue;
			if (recovered.size() >= derived_claim_limit ||
			    strlen(entry->d_name) != 41) {
				error = EPROTO;
				break;
			}
			std::array<uint8_t, derived_claim_wire_size> wire{};
			if (derived_claim_read_at(directory, entry->d_name,
			    wire) != 1) {
				error = errno == ENOENT ? EPROTO : errno;
				break;
			}
			durable_derived_claim claim{};
			memcpy(claim.consumer_session.data(), wire.data() + 4, 16);
			claim.ingress_delivery_id =
			    dtraced_wire_get_u64(wire.data() + 20);
			claim.ingress_vmid =
			    dtraced_wire_get_u16(wire.data() + 28);
			claim.ingress_epoch =
			    dtraced_wire_get_u64(wire.data() + 30);
			memcpy(claim.ingress_program_id.data(),
			    wire.data() + 38, 16);
			memcpy(claim.ingress_source_id.data(),
			    wire.data() + 54, 16);
			claim.target_vmid =
			    dtraced_wire_get_u16(wire.data() + 70);
			claim.target_epoch =
			    dtraced_wire_get_u64(wire.data() + 72);
			memcpy(claim.derived_program_id.data(),
			    wire.data() + 80, 16);
			memcpy(claim.payload_digest.data(), wire.data() + 96, 32);
			memcpy(claim.bare_elf_digest.data(), wire.data() + 128, 32);
			char canonical[42];
			derived_claim_name(wire, canonical);
			if (!derived_claim_valid(claim) ||
			    derived_claim_bytes(claim) != wire ||
			    strcmp(canonical, entry->d_name) != 0) {
				error = EPROTO;
				break;
			}
			recovered.push_back(claim);
		}
	} catch (const std::bad_alloc &) {
		error = ENOMEM;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	records.swap(recovered);
	return (true);
}

bool
dir::list_derived_claims(std::vector<durable_derived_claim> &records)
{
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	return (process_lock.held() &&
	    list_derived_claims_at(this->dirfd, records));
}

static std::array<uint8_t, 66>
derived_parent_key(const dtraced_derived_parent_t &parent)
{
	std::array<uint8_t, 66> key{};
	memcpy(key.data(), parent.consumer_session, 16);
	dtraced_wire_put_u64(key.data() + 16, parent.delivery_id);
	dtraced_wire_put_u16(key.data() + 24, parent.vmid);
	dtraced_wire_put_u64(key.data() + 26, parent.epoch);
	memcpy(key.data() + 34, parent.program_id, 16);
	memcpy(key.data() + 50, parent.source_id, 16);
	return (key);
}

static std::array<uint8_t, 18>
derived_ingress_key(const durable_delivery &ingress)
{
	std::array<uint8_t, 18> key{};
	dtraced_wire_put_u64(key.data(), ingress.delivery_id);
	dtraced_wire_put_u16(key.data() + 8, ingress.vmid);
	dtraced_wire_put_u64(key.data() + 10, ingress.epoch);
	return (key);
}

static bool
derived_outbound_was_delivered(delivery_phase phase)
{
	/* Scope-0 terminal is the durable guest uninstall observation.  It
	 * retains the same payload identity after the spool is retired. */
	return (phase == delivery_phase::accepted ||
	    phase == delivery_phase::installed ||
	    phase == delivery_phase::terminal);
}

bool
dir::audit_derived_claims(dir &outbound,
    const std::vector<durable_derived_claim> &claims,
    const std::vector<durable_consumer_receipt_state> &receipts,
    const std::vector<durable_delivery_state> &deliveries,
    bool reconcile_pending,
    const std::vector<durable_delivery_state> *locked_outbound)
{
	if (this == &outbound) {
		errno = EINVAL;
		return (false);
	}
	try {
		std::map<std::array<uint8_t, 66>,
		    const durable_consumer_receipt_state *> parents;
		std::map<std::array<uint8_t, 66>, unsigned> claim_counts;
		std::map<std::array<uint8_t, 18>,
		    const durable_delivery_state *> ingresses;
		std::multimap<std::array<uint8_t, 16>,
		    const durable_delivery_state *> outbounds;
		std::vector<durable_delivery_state> read_outbound;
		std::vector<durable_consumer_receipt> proven_pending;
		if (locked_outbound == nullptr &&
		    !outbound.list_deliveries(read_outbound))
			return (false);
		const auto &outbound_deliveries = locked_outbound != nullptr ?
		    *locked_outbound : read_outbound;
		for (const auto &entry : receipts) {
			const auto &record = entry.record;
			dtraced_derived_parent_t parent{};
			memcpy(parent.consumer_session,
			    record.consumer_session.data(), 16);
			parent.delivery_id = record.ingress.delivery_id;
			parent.vmid = record.ingress.vmid;
			parent.epoch = record.ingress.epoch;
			memcpy(parent.program_id,
			    record.ingress.program_id.data(), 16);
			memcpy(parent.source_id,
			    record.ingress.source_id.data(), 16);
			if (!parents.emplace(derived_parent_key(parent),
			    &entry).second) {
				errno = EPROTO;
				return (false);
			}
		}
		for (const auto &entry : deliveries) {
			if (entry.record.scope != 3)
				continue;
			if (!ingresses.emplace(derived_ingress_key(entry.record),
			    &entry).second) {
				errno = EPROTO;
				return (false);
			}
		}
		for (const auto &entry : outbound_deliveries) {
			if (entry.record.scope != 0)
				continue;
			outbounds.emplace(entry.record.program_id, &entry);
		}
		for (const auto &claim : claims) {
			if (!derived_claim_valid(claim)) {
				errno = EPROTO;
				return (false);
			}
			const auto parent = derived_claim_parent(claim);
			auto recipient = parents.find(derived_parent_key(parent));
			durable_delivery ingress{};
			ingress.delivery_id = claim.ingress_delivery_id;
			ingress.vmid = claim.ingress_vmid;
			ingress.epoch = claim.ingress_epoch;
			auto accepted = ingresses.find(derived_ingress_key(ingress));
			if (recipient == parents.end() ||
			    accepted == ingresses.end() ||
			    accepted->second->phase != delivery_phase::accepted ||
			    consumer_receipt_no_derived(
			    recipient->second->phase) ||
			    delivery_record_bytes(recipient->second->record.ingress) !=
			    delivery_record_bytes(accepted->second->record)) {
				errno = EPROTO;
				return (false);
			}
			if (++claim_counts[derived_parent_key(parent)] != 1) {
				errno = EPROTO;
				return (false);
			}
			uint8_t digest[SHA256_DIGEST_LENGTH];
			uint8_t bare_digest[SHA256_DIGEST_LENGTH];
			bool spool_present = outbound.hash_identified_data(
			    claim.derived_program_id.data(),
			    claim.ingress_source_id.data(), digest, false, true,
			    bare_digest);
			if (!spool_present && errno != ENOENT)
				return (false);
			if (spool_present &&
			    (memcmp(digest, claim.payload_digest.data(),
			    sizeof(digest)) != 0 ||
			    memcmp(bare_digest, claim.bare_elf_digest.data(),
			    sizeof(bare_digest)) != 0)) {
				errno = EPROTO;
				return (false);
			}
			auto matching = outbounds.equal_range(
			    claim.derived_program_id);
			bool delivered = false;
			for (auto it = matching.first; it != matching.second;
			    ++it) {
				const auto &entry = *it->second;
				const auto &record = entry.record;
				uint16_t payload_vmid = record.journal_version == 5 ?
				    record.payload_vmid : record.vmid;
				uint64_t payload_epoch = record.journal_version == 5 ?
				    record.payload_epoch : record.epoch;
				if (record.source_id != claim.ingress_source_id ||
				    (record.journal_version != 4 &&
				    record.journal_version != 5) ||
				    (!spool_present &&
				    !derived_outbound_was_delivered(entry.phase)) ||
				    payload_vmid != claim.target_vmid ||
				    payload_epoch != claim.target_epoch ||
				    record.payload_digest != claim.bare_elf_digest) {
					errno = EPROTO;
					return (false);
				}
				if (derived_outbound_was_delivered(entry.phase))
					delivered = true;
			}
			/* A spool accepted before the consumer ACK is durable proves
			 * the derived outcome. A later accepted/terminal delivery keeps
			 * that proof after the spool is retired. */
			if (consumer_receipt_derived(
			    recipient->second->phase) &&
			    !spool_present && !delivered) {
				errno = EPROTO;
				return (false);
			}
			if (recipient->second->phase ==
			    consumer_receipt_phase::pending &&
			    (spool_present || delivered))
				proven_pending.push_back(recipient->second->record);
		}
		for (const auto &entry : parents) {
			if (consumer_receipt_derived(entry.second->phase) &&
			    claim_counts[entry.first] != 1) {
				errno = EPROTO;
				return (false);
			}
		}
		/* Validate the entire snapshot before changing any HCR1 phase.
		 * A spool link may have survived a crash before its directory fsync;
		 * make that proof durable before the inbound receipt names it.
		 * Each fsynced transition is idempotent after a startup failure. */
		if (reconcile_pending && !proven_pending.empty() &&
		    fsync(outbound.dirfd) != 0)
			return (false);
		if (reconcile_pending)
			for (const auto &record : proven_pending)
				if (record_consumer_receipt(record,
				    consumer_receipt_phase::derived) !=
				    (int)consumer_receipt_phase::derived)
					return (false);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	return (true);
}

int
dir::resolve_derived_outbound(dir &outbound, const uint8_t program[16],
    const uint8_t source[16], durable_consumer_receipt_state &found)
{
	found = {};
	if (this == &outbound || program == nullptr || source == nullptr) {
		errno = EINVAL;
		return (-1);
	}
	uint8_t payload_digest[SHA256_DIGEST_LENGTH]{};
	uint8_t bare_elf_digest[SHA256_DIGEST_LENGTH]{};
	bool spool_present = outbound.hash_identified_data(program, source,
	    payload_digest, false, true, bare_elf_digest);
	if (!spool_present && errno != ENOENT)
		return (-1);
	std::vector<durable_derived_claim> claims;
	if (!outbound.list_derived_claims(claims))
		return (-1);
	const durable_derived_claim *claimed = nullptr;
	for (const auto &entry : claims) {
		if (memcmp(entry.derived_program_id.data(), program, 16) != 0 ||
		    memcmp(entry.ingress_source_id.data(), source, 16) != 0)
			continue;
		if (claimed != nullptr || (spool_present &&
		    (memcmp(entry.payload_digest.data(), payload_digest,
		    sizeof(payload_digest)) != 0 ||
		    memcmp(entry.bare_elf_digest.data(), bare_elf_digest,
		    sizeof(bare_elf_digest)) != 0))) {
			errno = EPROTO;
			return (-1);
		}
		claimed = &entry;
	}
	if (claimed == nullptr) {
		if (!spool_present)
			return (0);
		errno = EPROTO;
		return (-1);
	}
	/* A retained spool does not excuse an inconsistent outbound receipt.
	 * After guest acceptance or uninstall the spool may be retired; the
	 * HDU2 claim and durable receipt preserve lineage through handoff. */
	std::vector<durable_delivery_state> deliveries;
	if (!outbound.list_deliveries(deliveries))
		return (-1);
	bool accepted = false;
	for (const auto &entry : deliveries) {
		const auto &record = entry.record;
		if (record.scope != 0 ||
		    memcmp(record.program_id.data(), program, 16) != 0)
			continue;
		uint16_t payload_vmid = record.journal_version == 5 ?
		    record.payload_vmid : record.vmid;
		uint64_t payload_epoch = record.journal_version == 5 ?
		    record.payload_epoch : record.epoch;
		if (memcmp(record.source_id.data(), source, 16) != 0 ||
		    (record.journal_version != 4 &&
		    record.journal_version != 5) ||
		    (!spool_present &&
		    !derived_outbound_was_delivered(entry.phase)) ||
		    payload_vmid != claimed->target_vmid ||
		    payload_epoch != claimed->target_epoch ||
		    record.payload_digest != claimed->bare_elf_digest) {
			errno = EPROTO;
			return (-1);
		}
		if (derived_outbound_was_delivered(entry.phase))
			accepted = true;
	}
	const bool result_proven = spool_present || accepted;
	if (!spool_present) {
		/* The HDU2 digest identifies a claim, but without a spool or
		 * completed outbound receipt it cannot certify publication. */
		memcpy(payload_digest, claimed->payload_digest.data(),
		    sizeof(payload_digest));
	}
	std::vector<durable_consumer_receipt_state> receipts;
	if (!this->list_consumer_receipts(receipts))
		return (-1);
	int matches = 0;
	for (const auto &receipt : receipts) {
		const auto &ingress = receipt.record.ingress;
		if (memcmp(ingress.source_id.data(), source, 16) != 0)
			continue;
		if (receipt.record.consumer_session !=
		    claimed->consumer_session ||
		    ingress.delivery_id != claimed->ingress_delivery_id ||
		    ingress.vmid != claimed->ingress_vmid ||
		    ingress.epoch != claimed->ingress_epoch ||
		    ingress.program_id != claimed->ingress_program_id)
			continue;
		if (consumer_receipt_no_derived(receipt.phase)) {
			errno = EPROTO;
			return (-1);
		}
		dtraced_derived_parent_t parent{};
		memcpy(parent.consumer_session,
		    receipt.record.consumer_session.data(), 16);
		parent.delivery_id = ingress.delivery_id;
		parent.vmid = ingress.vmid;
		parent.epoch = ingress.epoch;
		memcpy(parent.program_id, ingress.program_id.data(), 16);
		memcpy(parent.source_id, ingress.source_id.data(), 16);
		uint8_t expected[16];
		if (dtraced_derived_program_id_from_digest(&parent,
		    payload_digest, expected) != 0)
			return (-1);
		if (memcmp(expected, program, 16) != 0)
			continue;
		if (matches != 0) {
			errno = EPROTO;
			return (-1);
		}
		found = receipt;
		matches = 1;
	}
	if (matches == 0) {
		errno = EPROTO; /* A retained spool without a parent is an orphan. */
		return (-1);
	}
	if (!result_proven) {
		bool falsely_complete =
		    consumer_receipt_derived(found.phase);
		found = {};
		if (falsely_complete) {
			errno = EPROTO;
			return (-1);
		}
		return (0); /* Claim fsynced before spool publication. */
	}
	return (1);
}

static bool
guest_rekey_arguments_valid(uint16_t old_vmid, uint64_t old_epoch,
    uint16_t new_vmid, uint64_t new_epoch)
{
	return (old_vmid != 0 && old_vmid < HYPERTRACE_MAX_VMS &&
	    old_epoch != 0 && new_vmid != 0 &&
	    new_vmid < HYPERTRACE_MAX_VMS && new_epoch != 0 &&
	    (old_vmid != new_vmid || old_epoch != new_epoch));
}

/* Caller holds this directory's in-process and cross-process journal locks. */
static bool
guest_rekey_marker_preflight_at(int directory, uint16_t old_vmid,
    uint64_t old_epoch, uint16_t new_vmid, uint64_t new_epoch)
{
	uint16_t recorded_vmid = 0;
	uint64_t recorded_epoch = 0;
	int present = guest_rekey_marker_at(directory, old_vmid, old_epoch,
	    &recorded_vmid, &recorded_epoch);
	if (present < 0)
		return (false);
	if (present != 0 && (recorded_vmid != new_vmid ||
	    recorded_epoch != new_epoch)) {
		errno = EPROTO;
		return (false);
	}
	/* A destination already fenced for a later rekey cannot accept this
	 * journal, even if the old-to-new marker is an exact retry. */
	int retired = guest_rekey_marker_at(directory, new_vmid, new_epoch);
	if (retired < 0)
		return (false);
	if (retired != 0) {
		errno = ESTALE;
		return (false);
	}
	return (true);
}

/* Caller holds this directory's in-process and cross-process journal locks. */
static bool
guest_rekey_preflight_at(int directory, uint8_t scope, uint16_t old_vmid,
    uint64_t old_epoch, uint16_t new_vmid, uint64_t new_epoch)
{
	if ((scope != 1 && scope != 2) ||
	    !guest_rekey_arguments_valid(old_vmid, old_epoch,
	    new_vmid, new_epoch)) {
		errno = EINVAL;
		return (false);
	}
	std::vector<durable_delivery_state> deliveries;
	std::vector<durable_kill> kills;
	uint16_t fenced_vmid = 0;
	uint64_t fenced_epoch = 0;
	int fenced = guest_rekey_marker_at(directory, old_vmid, old_epoch,
	    &fenced_vmid, &fenced_epoch);
	if (fenced < 0)
		return (false);
	if (fenced != 0 && (fenced_vmid != new_vmid ||
	    fenced_epoch != new_epoch)) {
		errno = EPROTO;
		return (false);
	}
	if (!list_deliveries_at(directory, deliveries) ||
	    !list_kills_at(directory, kills))
		return (false);
	std::sort(deliveries.begin(), deliveries.end(),
	    [](const durable_delivery_state &a,
	    const durable_delivery_state &b) {
		if (a.record.session_id != b.record.session_id)
			return (a.record.session_id < b.record.session_id);
		return (a.record.delivery_id < b.record.delivery_id);
	    });
	for (size_t i = 0; i < deliveries.size(); i++) {
		const auto &entry = deliveries[i];
		if (i != 0 && entry.record.session_id ==
		    deliveries[i - 1].record.session_id &&
		    entry.record.delivery_id ==
		    deliveries[i - 1].record.delivery_id) {
			errno = EPROTO;
			return (false);
		}
		if (entry.record.scope != scope ||
		    (scope == 2 && (entry.record.journal_version != 4 ||
		    (entry.phase != delivery_phase::pending &&
		    entry.phase != delivery_phase::accepted)))) {
			errno = EOPNOTSUPP;
			return (false);
		}
		if (scope == 2 && entry.record.vmid == 0)
			continue; /* Still requires its original host receipt. */
		if (entry.record.vmid == new_vmid &&
		    entry.record.epoch == new_epoch && fenced == 0) {
			errno = ESTALE;
			return (false);
		}
		if ((entry.record.vmid != old_vmid ||
		    entry.record.epoch != old_epoch) &&
		    (entry.record.vmid != new_vmid ||
		    entry.record.epoch != new_epoch)) {
			errno = ESTALE;
			return (false);
		}
	}
	if (scope == 2 && !kills.empty()) {
		errno = EPROTO;
		return (false);
	}
	for (const auto &kill : kills) {
		if (kill.vmid == new_vmid && kill.epoch == new_epoch &&
		    fenced == 0) {
			errno = ESTALE;
			return (false);
		}
		if ((kill.vmid != old_vmid || kill.epoch != old_epoch) &&
		    (kill.vmid != new_vmid || kill.epoch != new_epoch)) {
			errno = ESTALE;
			return (false);
		}
	}
	return (true);
}

bool
dir::fence_guest_rekey(uint8_t scope, uint16_t old_vmid,
    uint64_t old_epoch, uint16_t new_vmid, uint64_t new_epoch)
{
	if ((scope != 1 && scope != 2) ||
	    !guest_rekey_arguments_valid(old_vmid, old_epoch,
	    new_vmid, new_epoch)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held() ||
	    !guest_rekey_preflight_at(this->dirfd, scope, old_vmid,
	    old_epoch, new_vmid, new_epoch) ||
	    !guest_rekey_marker_preflight_at(this->dirfd, old_vmid,
	    old_epoch, new_vmid, new_epoch))
		return (false);
	return (guest_rekey_marker_ensure(this->dirfd, old_vmid, old_epoch,
	    new_vmid, new_epoch));
}

bool
dir::fence_guest_rekey_pair(dir &outbound, uint16_t old_vmid,
    uint64_t old_epoch, uint16_t new_vmid, uint64_t new_epoch)
{
	struct stat inbound_stat, outbound_stat;
	if (this == &outbound ||
	    !guest_rekey_arguments_valid(old_vmid, old_epoch,
	    new_vmid, new_epoch)) {
		errno = EINVAL;
		return (false);
	}
	if (fstat(this->dirfd, &inbound_stat) != 0 ||
	    fstat(outbound.dirfd, &outbound_stat) != 0)
		return (false);
	if (inbound_stat.st_dev == outbound_stat.st_dev &&
	    inbound_stat.st_ino == outbound_stat.st_ino) {
		errno = EINVAL;
		return (false);
	}
	std::scoped_lock lk(this->publishmtx, outbound.publishmtx);
	/* File descriptor numbers vary between processes. Order by the stable
	 * directory identity so opposing pairs cannot deadlock. */
	bool inbound_first = inbound_stat.st_dev < outbound_stat.st_dev ||
	    (inbound_stat.st_dev == outbound_stat.st_dev &&
	    inbound_stat.st_ino < outbound_stat.st_ino);
	handoff_process_lock first(inbound_first ? this->dirfd : outbound.dirfd);
	if (!first.held())
		return (false);
	handoff_process_lock second(inbound_first ? outbound.dirfd : this->dirfd);
	if (!second.held() ||
	    !guest_rekey_preflight_at(this->dirfd, 1, old_vmid, old_epoch,
	    new_vmid, new_epoch) ||
	    !guest_rekey_preflight_at(outbound.dirfd, 2, old_vmid, old_epoch,
	    new_vmid, new_epoch) ||
	    !guest_rekey_marker_preflight_at(this->dirfd, old_vmid,
	    old_epoch, new_vmid, new_epoch) ||
	    !guest_rekey_marker_preflight_at(outbound.dirfd, old_vmid,
	    old_epoch, new_vmid, new_epoch))
		return (false);
	/* A failed second fsync leaves an exact, retryable partial fence. */
	return (guest_rekey_marker_ensure(this->dirfd, old_vmid, old_epoch,
	    new_vmid, new_epoch) &&
	    guest_rekey_marker_ensure(outbound.dirfd, old_vmid, old_epoch,
	    new_vmid, new_epoch));
}

/* Caller holds the directory's journal locks. A marker proves the cut, but
 * only a fully rewritten journal can precede the driver's rekey commit. */
static bool
guest_rekey_journal_complete_at(int directory, uint8_t scope,
    uint16_t old_vmid, uint64_t old_epoch, uint16_t new_vmid,
    uint64_t new_epoch)
{
	uint16_t fenced_vmid = 0;
	uint64_t fenced_epoch = 0;
	int marker = guest_rekey_marker_at(directory, old_vmid, old_epoch,
	    &fenced_vmid, &fenced_epoch);
	if (marker < 0)
		return (false);
	if (marker == 0) {
		errno = EBUSY;
		return (false);
	}
	if (fenced_vmid != new_vmid || fenced_epoch != new_epoch) {
		errno = EPROTO;
		return (false);
	}
	if (!guest_rekey_marker_preflight_at(directory, old_vmid,
	    old_epoch, new_vmid, new_epoch))
		return (false);
	if (!guest_rekey_preflight_at(directory, scope, old_vmid, old_epoch,
	    new_vmid, new_epoch))
		return (false);
	std::vector<durable_delivery_state> deliveries;
	std::vector<durable_kill> kills;
	if (!list_deliveries_at(directory, deliveries) ||
	    !list_kills_at(directory, kills))
		return (false);
	for (const auto &entry : deliveries)
		if (entry.record.vmid != new_vmid ||
		    entry.record.epoch != new_epoch) {
			errno = EBUSY;
			return (false);
		}
	for (const auto &kill : kills)
		if (kill.vmid != new_vmid || kill.epoch != new_epoch) {
			errno = EBUSY;
			return (false);
		}
	/* No applied KILL marker can survive restore, including an orphan left
	 * by a damaged journal. A restored guest must acknowledge KILLs anew. */
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	for (;;) {
		errno = 0;
		struct dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		if (strncmp(entry->d_name, ".killack.", 9) == 0) {
			error = EBUSY;
			break;
		}
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

bool
dir::guest_rekey_pair_complete(dir &outbound, uint16_t old_vmid,
    uint64_t old_epoch, uint16_t new_vmid, uint64_t new_epoch)
{
	struct stat inbound_stat, outbound_stat;
	if (this == &outbound ||
	    !guest_rekey_arguments_valid(old_vmid, old_epoch,
	    new_vmid, new_epoch)) {
		errno = EINVAL;
		return (false);
	}
	if (fstat(this->dirfd, &inbound_stat) != 0 ||
	    fstat(outbound.dirfd, &outbound_stat) != 0)
		return (false);
	if (inbound_stat.st_dev == outbound_stat.st_dev &&
	    inbound_stat.st_ino == outbound_stat.st_ino) {
		errno = EINVAL;
		return (false);
	}
	std::scoped_lock lk(this->publishmtx, outbound.publishmtx);
	bool inbound_first = inbound_stat.st_dev < outbound_stat.st_dev ||
	    (inbound_stat.st_dev == outbound_stat.st_dev &&
	    inbound_stat.st_ino < outbound_stat.st_ino);
	handoff_process_lock first(inbound_first ? this->dirfd : outbound.dirfd);
	if (!first.held())
		return (false);
	handoff_process_lock second(inbound_first ? outbound.dirfd : this->dirfd);
	return (second.held() &&
	    guest_rekey_journal_complete_at(this->dirfd, 1, old_vmid,
	    old_epoch, new_vmid, new_epoch) &&
	    guest_rekey_journal_complete_at(outbound.dirfd, 2, old_vmid,
	    old_epoch, new_vmid, new_epoch));
}

bool
dir::rekey_guest_journals_with_receipts(dir &outbound,
    uint16_t old_vmid, uint64_t old_epoch, uint16_t new_vmid,
    uint64_t new_epoch,
    const std::function<bool(const durable_delivery_state &)> &inbound_receipt,
    const std::function<bool(const durable_delivery_state &)> &outbound_receipt,
    const std::function<bool(const durable_kill &)> &kill_receipt)
{
	if (!inbound_receipt || !outbound_receipt || !kill_receipt) {
		errno = EINVAL;
		return (false);
	}
	/* This function runs only after the restore coordinator has paused the
	 * guest and verified its handoff. The durable pair fence prevents any
	 * source-incarnation writer from racing the following per-record steps. */
	if (!fence_guest_rekey_pair(outbound, old_vmid, old_epoch,
	    new_vmid, new_epoch))
		return (false);
	try {
		std::vector<durable_delivery_state> inbound_records;
		std::vector<durable_delivery_state> outbound_records;
		std::vector<durable_kill> kills;
		/* Verify every old-incarnation receipt before renaming any journal
		 * record. A failed later receipt must not leave an earlier journal
		 * partially remapped. The durable pair fence excludes new writers. */
		for (auto *journal : {this, &outbound}) {
			auto &records = journal == this ? inbound_records :
			    outbound_records;
			if (!journal->list_deliveries(records))
				return (false);
			uint8_t scope = journal == this ? 1 : 2;
			const auto &receipt = journal == this ?
			    inbound_receipt : outbound_receipt;
			for (const auto &record : records) {
				if (record.record.scope != scope ||
				    (scope == 2 && record.record.journal_version != 4)) {
					errno = EPROTO;
					return (false);
				}
				bool source = record.record.vmid == old_vmid &&
				    record.record.epoch == old_epoch;
				bool destination = record.record.vmid == new_vmid &&
				    record.record.epoch == new_epoch;
				if (!source && !destination) {
					errno = ESTALE;
					return (false);
				}
				/* A retry must recheck the original host receipt even if
				 * an earlier run durably renamed this record. */
				durable_delivery_state original = record;
				original.record.vmid = old_vmid;
				original.record.epoch = old_epoch;
				errno = 0;
				if (!receipt(original)) {
					if (errno == 0)
						errno = EACCES;
					return (false);
				}
			}
		}
		if (!list_kills(kills))
			return (false);
		for (const auto &kill : kills) {
			bool source = kill.vmid == old_vmid &&
			    kill.epoch == old_epoch;
			bool destination = kill.vmid == new_vmid &&
			    kill.epoch == new_epoch;
			if (!source && !destination) {
				errno = ESTALE;
				return (false);
			}
			durable_kill original = kill;
			original.vmid = old_vmid;
			original.epoch = old_epoch;
			errno = 0;
			if (!kill_receipt(original)) {
				if (errno == 0)
					errno = EACCES;
				return (false);
			}
		}
		for (const auto &record : inbound_records) {
			if (record.record.vmid == old_vmid &&
			    record.record.epoch == old_epoch &&
			    !rekey_guest_delivery(record, new_vmid, new_epoch))
				return (false);
		}
		for (const auto &record : outbound_records) {
			if (record.record.vmid == old_vmid &&
			    record.record.epoch == old_epoch &&
			    !outbound.rekey_guest_delivery(record, new_vmid,
			    new_epoch))
				return (false);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	if (!rekey_guest_kills(old_vmid, old_epoch, new_vmid, new_epoch))
		return (false);
	return (guest_rekey_pair_complete(outbound, old_vmid, old_epoch,
	    new_vmid, new_epoch));
}

bool
dir::rekey_guest_delivery(const durable_delivery_state &source,
    uint16_t new_vmid, uint64_t new_epoch)
{
	if ((source.record.scope != 1 && source.record.scope != 2) ||
	    !delivery_record_valid(source.record) || source.record.vmid == 0 ||
	    (source.record.scope == 2 && source.record.journal_version != 4) ||
	    new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 ||
	    (source.record.vmid == new_vmid &&
	    source.record.epoch == new_epoch) ||
	    (source.phase != delivery_phase::pending &&
	    source.phase != delivery_phase::accepted &&
	    source.phase != delivery_phase::installed &&
	    source.phase != delivery_phase::exited &&
	    source.phase != delivery_phase::terminal) ||
	    (source.record.scope == 2 &&
	    source.phase != delivery_phase::pending &&
	    source.phase != delivery_phase::accepted)) {
		errno = EINVAL;
		return (false);
	}
	durable_delivery destination = source.record;
	destination.vmid = new_vmid;
	destination.epoch = new_epoch;
	if (!delivery_record_valid(destination)) {
		errno = EINVAL;
		return (false);
	}
	char name[80], temporary[88];
	delivery_record_name(source.record, source.phase, name);
	if (snprintf(temporary, sizeof(temporary), ".rekey%s", name) >=
	    (int)sizeof(temporary)) {
		errno = EOVERFLOW;
		return (false);
	}
	const auto source_bytes = delivery_record_bytes(source.record);
	const auto destination_bytes = delivery_record_bytes(destination);
	const size_t length = delivery_record_size(source.record);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	/* A key must have exactly one phase. Do not silently rekey one copy of
	 * a damaged journal and leave another copy under the old identity. */
	for (delivery_phase phase : {delivery_phase::pending,
	    delivery_phase::accepted, delivery_phase::installed,
	    delivery_phase::exited, delivery_phase::terminal}) {
		if (phase == source.phase)
			continue;
		char other_name[80];
		delivery_record_name(source.record, phase, other_name);
		std::array<uint8_t, 185> other{};
		size_t other_length = 0;
		int other_status = delivery_read_at(this->dirfd, other_name,
		    other, other_length);
		if (other_status < 0)
			return (false);
		if (other_status != 0) {
			errno = EPROTO;
			return (false);
		}
	}
	std::array<uint8_t, 185> current{};
	size_t current_length = 0;
	int found = delivery_read_at(this->dirfd, name, current,
	    current_length);
	if (found <= 0) {
		if (found == 0)
			errno = ENOENT;
		return (false);
	}
	if (current_length != length) {
		errno = EPROTO;
		return (false);
	}
	if (memcmp(current.data(), source_bytes.data(), length) != 0 &&
	    memcmp(current.data(), destination_bytes.data(), length) != 0) {
		errno = EPROTO;
		return (false);
	}
	/* Destination bytes are a retry only if the old incarnation was already
	 * fenced to this exact destination before the earlier rename. */
	if (memcmp(current.data(), destination_bytes.data(), length) == 0) {
		uint16_t fenced_vmid = 0;
		uint64_t fenced_epoch = 0;
		int fenced = guest_rekey_marker_at(this->dirfd,
		    source.record.vmid, source.record.epoch, &fenced_vmid,
		    &fenced_epoch);
		if (fenced < 0)
			return (false);
		if (fenced == 0) {
			errno = ESTALE;
			return (false);
		}
	}
	if (!guest_rekey_marker_preflight_at(this->dirfd,
	    source.record.vmid, source.record.epoch, new_vmid, new_epoch) ||
	    !guest_rekey_marker_ensure(this->dirfd, source.record.vmid,
	    source.record.epoch, new_vmid, new_epoch))
		return (false);
	if (memcmp(current.data(), destination_bytes.data(), length) == 0) {
		/* The rename may have completed before a crash or failed fsync. */
		if (unlinkat(this->dirfd, temporary, 0) != 0 && errno != ENOENT)
			return (false);
		return (fsync(this->dirfd) == 0);
	}
	if (memcmp(current.data(), source_bytes.data(), length) != 0) {
		errno = EPROTO;
		return (false);
	}
	/* A crash may leave a partial temporary file. It is never authority:
	 * discard it and derive a fresh image from the exact source record. */
	if (unlinkat(this->dirfd, temporary, 0) == 0) {
		if (fsync(this->dirfd) != 0)
			return (false);
	} else if (errno != ENOENT)
		return (false);
	int fd = openat(this->dirfd, temporary,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (false);
	size_t offset = 0;
	int error = 0;
	while (offset < length) {
		ssize_t written = write(fd, destination_bytes.data() + offset,
		    length - offset);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0) {
			error = written < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)written;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	if (renameat(this->dirfd, temporary, this->dirfd, name) != 0)
		return (false);
	return (fsync(this->dirfd) == 0);
}

int
dir::resolve_host_delivery(const durable_delivery &key,
    durable_delivery_state &found)
{
	if (key.scope != 0 || !delivery_record_valid(key)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	int matches = 0;
	durable_delivery_state candidate{};
	for (delivery_phase phase : {delivery_phase::pending,
	    delivery_phase::accepted, delivery_phase::installed,
	    delivery_phase::exited, delivery_phase::terminal}) {
		char name[80];
		delivery_record_name(key, phase, name);
		std::array<uint8_t, 185> bytes{};
		size_t length = 0;
		int present = delivery_read_at(this->dirfd, name, bytes, length);
		if (present < 0)
			return (-1);
		if (present == 0)
			continue;
		if (++matches != 1 ||
		    !delivery_record_parse(this->dirfd, name, candidate) ||
		    candidate.record.scope != 0 ||
		    candidate.phase == delivery_phase::exited ||
		    candidate.record.session_id != key.session_id ||
		    candidate.record.delivery_id != key.delivery_id ||
		    candidate.record.vmid != key.vmid ||
		    candidate.record.epoch != key.epoch ||
		    candidate.record.program_id != key.program_id ||
		    candidate.record.source_id != key.source_id ||
		    candidate.record.peer_uid != key.peer_uid ||
		    candidate.record.peer_pid != key.peer_pid) {
			errno = EPROTO;
			return (-1);
		}
	}
	if (fsync(this->dirfd) != 0)
		return (-1);
	if (matches != 0)
		found = candidate;
	return (matches);
}

struct source_journal_stage_binding {
	std::array<uint8_t, 16> session{};
	uint32_t uid = 0;
	uint32_t pid = 0;
	bool present = false;
};
static int source_journal_stage_load_locked(int,
    const durable_handoff &, source_journal_cut &,
    host_ingress_transfer_bundle &,
    source_journal_stage_binding * = nullptr,
    std::array<uint8_t, SHA256_DIGEST_LENGTH> * = nullptr);
static bool source_journal_destination_plan_locked(int,
    const durable_handoff &, const source_journal_cut &,
    const host_ingress_transfer_bundle &,
    const source_journal_stage_binding &, bool,
    source_journal_destination_plan &);
static bool source_journal_pending_reconcile_locked(int,
    const durable_handoff &, const source_journal_destination_plan &,
    bool, size_t &,
    const source_journal_destination_plan *prior = nullptr);
static int source_journal_ready_status_locked(int,
    const durable_handoff &,
    const std::array<uint8_t, SHA256_DIGEST_LENGTH> &, uint32_t);
static int source_journal_claimed_plan_locked(int, state *,
    const durable_handoff &, source_journal_cut &,
    source_journal_destination_plan &,
    std::array<uint8_t, 16> *, bool,
    std::array<uint8_t, SHA256_DIGEST_LENGTH> *);

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
int
dir::handoff_delivery_status(const durable_handoff &claim, uint8_t scope,
    uint64_t delivery_id, const std::array<uint8_t, 16> &program_id,
    const std::array<uint8_t, 16> &source_id,
    durable_delivery_state &found, bool &revoked, bool &payload_available,
    dir *ingress)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	dir *ledger = scope == 3 ? ingress : this;
	if (claim.token == zero16 || claim.checkpoint_digest == zero32 ||
	    claim.destination_vmid == 0 ||
	    claim.destination_vmid >= HYPERTRACE_MAX_VMS ||
	    claim.destination_epoch == 0 || (scope != 0 && scope != 3) ||
	    delivery_id == 0 || ledger == nullptr ||
	    (scope == 3 && ledger == this) ||
	    program_id == zero16 || source_id == zero16) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	/* The ticket and KILL log belong to outbound; guest uploads belong to
	 * inbound. Keep both locks while checking the exact source receipt. */
	std::unique_lock<std::mutex> ingress_lock(ledger->publishmtx,
	    std::defer_lock);
	if (ledger != this)
		ingress_lock.lock();
	auto sync_journals = [&]() {
		return (fsync(ledger->dirfd) == 0 &&
		    (ledger == this || fsync(this->dirfd) == 0));
	};
	durable_handoff active{};
	int phase = handoff_state_at(this->dirfd, claim.token, active);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::reserved &&
	    phase != (int)handoff_phase::mutating &&
	    phase != (int)handoff_phase::claimed) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	if (active.checkpoint_digest != claim.checkpoint_digest) {
		errno = EPROTO;
		return (-1);
	}
	if (active.destination_vmid != claim.destination_vmid ||
	    active.destination_epoch != claim.destination_epoch) {
		errno = EPERM;
		return (-1);
	}
	if (scope == 0) {
		if (!handoff_release_authority_locked(this->dirfd,
		    this->state, active))
			return (-1);
		source_journal_cut cut;
		int staged;
		if (phase == (int)handoff_phase::reserved) {
			host_ingress_transfer_bundle staged_ingress;
			staged = source_journal_stage_load_locked(this->dirfd,
			    active, cut, staged_ingress);
		} else {
			source_journal_destination_plan plan;
			staged = source_journal_claimed_plan_locked(this->dirfd,
			    this->state, active, cut, plan);
		}
		if (staged < 0)
			return (-1);
		if (staged == 1) {
			int matches = 0;
			const source_journal_delivery *candidate = nullptr;
			for (const auto &item : cut.deliveries) {
				const durable_delivery &record = item.state.record;
				if (record.session_id != active.source_session ||
				    record.vmid != active.source_vmid ||
				    record.epoch != active.source_epoch ||
				    record.delivery_id != delivery_id ||
				    record.program_id != program_id ||
				    record.source_id != source_id)
					continue;
				if (++matches != 1) {
					errno = EPROTO;
					return (-1);
				}
				candidate = &item;
			}
			if (matches != 0) {
				found = candidate->state;
				revoked = candidate->revoked;
				payload_available = !candidate->revoked &&
				    !candidate->payload.empty();
			}
			return (sync_journals() ? matches : -1);
		}
	}
	std::vector<durable_delivery_state> records;
	if (!list_deliveries_at(ledger->dirfd, records))
		return (-1);
	int matches = 0;
	durable_delivery_state candidate{};
	for (const durable_delivery_state &entry : records) {
		const durable_delivery &record = entry.record;
		if (record.scope != scope ||
		    (scope == 0 && record.session_id != active.source_session) ||
		    record.vmid != active.source_vmid ||
		    record.epoch != active.source_epoch ||
		    record.delivery_id != delivery_id ||
		    record.program_id != program_id ||
		    record.source_id != source_id)
			continue;
		if (++matches != 1) {
			errno = EPROTO;
			return (-1);
		}
		candidate = entry;
	}
	if (matches == 0)
		return (sync_journals() ? 0 : -1);
	int revoked_status = source_revoked_at(this->dirfd,
	    source_id.data(), active.source_vmid, active.source_epoch);
	if (revoked_status < 0)
		return (-1);
	if (scope == 3 && revoked_status == 0) {
		revoked_status = source_revoked_at(ledger->dirfd,
		    source_id.data(), active.source_vmid, active.source_epoch);
		if (revoked_status < 0)
			return (-1);
	}
	payload_available = false;
	if (revoked_status == 0 && scope == 3 &&
	    candidate.phase == delivery_phase::accepted &&
	    candidate.record.journal_version == 4) {
		/* The host ingress journal is fsynced after publishing the spool.
		 * The watcher may already have consumed that spool by checkpoint
		 * time; the durable acceptance record is the exact receipt. */
		payload_available = true;
	} else if (revoked_status == 0 && scope == 0 &&
	    (candidate.phase == delivery_phase::accepted ||
	    candidate.phase == delivery_phase::installed) &&
	    candidate.record.journal_version >= 4) {
		int verified = this->verify_host_delivery_payload(candidate.record);
		if (verified < 0)
			return (-1);
		payload_available = verified != 0;
	}
	found = candidate;
	revoked = revoked_status != 0;
	return (sync_journals() ? 1 : -1);
}

int
dir::handoff_kill_status(const durable_handoff &claim, pid_t pid,
    const std::array<uint8_t, 16> &source_id, bool &revoked)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	if (claim.token == zero16 || claim.checkpoint_digest == zero32 ||
	    claim.destination_vmid == 0 ||
	    claim.destination_vmid >= HYPERTRACE_MAX_VMS ||
	    claim.destination_epoch == 0 || pid <= 1 ||
	    source_id == zero16) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff active{};
	int phase = handoff_state_at(this->dirfd, claim.token, active);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::reserved &&
	    phase != (int)handoff_phase::mutating &&
	    phase != (int)handoff_phase::claimed) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	if (active.checkpoint_digest != claim.checkpoint_digest) {
		errno = EPROTO;
		return (-1);
	}
	if (active.destination_vmid != claim.destination_vmid ||
	    active.destination_epoch != claim.destination_epoch) {
		errno = EPERM;
		return (-1);
	}
	if (!handoff_release_authority_locked(this->dirfd,
	    this->state, active))
		return (-1);
	{
		source_journal_cut cut;
		int staged;
		if (phase == (int)handoff_phase::reserved) {
			host_ingress_transfer_bundle staged_ingress;
			staged = source_journal_stage_load_locked(this->dirfd,
			    active, cut, staged_ingress);
		} else {
			source_journal_destination_plan plan;
			staged = source_journal_claimed_plan_locked(this->dirfd,
			    this->state, active, cut, plan);
		}
		if (staged < 0)
			return (-1);
		if (staged == 1) {
			int matches = 0;
			for (const auto &item : cut.kills) {
				if (item.record.pid == pid &&
				    item.record.source_id == source_id)
					matches++;
			}
			if (matches > 1) {
				errno = EPROTO;
				return (-1);
			}
			revoked = matches != 0;
			for (const auto &item : cut.deliveries)
				if (item.state.record.source_id == source_id &&
				    item.revoked)
					revoked = true;
			if (fsync(this->dirfd) != 0)
				return (-1);
			return (matches != 0 ? 'a' : 0);
		}
	}
	durable_kill record{pid, active.source_vmid, active.source_epoch,
	    source_id};
	char kill_name[70], ack_name[73];
	if (!durable_kill_name(record, kill_name) ||
	    !kill_applied_name(record, ack_name))
		return (-1);
	if (kill_record_status_at(this->dirfd, kill_name) != 0) {
		if (errno != ENOENT)
			return (-1);
		/* An orphan applied marker is corrupt journal state, not absence. */
		if (kill_record_status_at(this->dirfd, ack_name) == 0) {
			errno = EPROTO;
			return (-1);
		}
		if (errno != ENOENT)
			return (-1);
		int status = source_revoked_at(this->dirfd, source_id.data(),
		    active.source_vmid, active.source_epoch);
		if (status < 0)
			return (-1);
		revoked = status != 0;
		return (fsync(this->dirfd) == 0 ? 0 : -1);
	}
	revoked = true;
	int applied = kill_record_status_at(this->dirfd, ack_name);
	if (applied < 0 && errno != ENOENT)
		return (-1);
	if (fsync(this->dirfd) != 0)
		return (-1);
	return (applied == 0 ? 'a' : 'p');
}

int
dir::handoff_cleanup_status(const durable_handoff &claim,
    uint64_t delivery_id)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	if (claim.token == zero16 || claim.checkpoint_digest == zero32 ||
	    claim.destination_vmid == 0 ||
	    claim.destination_vmid >= HYPERTRACE_MAX_VMS ||
	    claim.destination_epoch == 0 || delivery_id == 0) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff active{};
	int phase = handoff_state_at(this->dirfd, claim.token, active);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::reserved &&
	    phase != (int)handoff_phase::mutating &&
	    phase != (int)handoff_phase::claimed) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	if (active.checkpoint_digest != claim.checkpoint_digest) {
		errno = EPROTO;
		return (-1);
	}
	if (active.destination_vmid != claim.destination_vmid ||
	    active.destination_epoch != claim.destination_epoch) {
		errno = EPERM;
		return (-1);
	}
	if (!handoff_release_authority_locked(this->dirfd,
	    this->state, active))
		return (-1);
	{
		source_journal_cut cut;
		int staged;
		if (phase == (int)handoff_phase::reserved) {
			host_ingress_transfer_bundle staged_ingress;
			staged = source_journal_stage_load_locked(this->dirfd,
			    active, cut, staged_ingress);
		} else {
			source_journal_destination_plan plan;
			staged = source_journal_claimed_plan_locked(this->dirfd,
			    this->state, active, cut, plan);
		}
		if (staged < 0)
			return (-1);
		if (staged == 1) {
			int matches = 0, result = 0;
			for (const auto &item : cut.cleanups) {
				if (item.record.delivery_id != delivery_id)
					continue;
				if (++matches != 1) {
					errno = EPROTO;
					return (-1);
				}
				result = item.phase;
			}
			return (fsync(this->dirfd) == 0 ? result : -1);
		}
	}
	durable_cleanup record{};
	record.vmid = active.source_vmid;
	record.epoch = active.source_epoch;
	record.delivery_id = delivery_id;
	int status = cleanup_status_at(this->dirfd, record);
	if (status < 0)
		return (-1);
	if (status == 'p') {
		errno = EPROTO; /* PREPARE cannot cross a pending cleanup. */
		return (-1);
	}
	return (fsync(this->dirfd) == 0 ? status : -1);
}

int
dir::bind_handoff_kill(const durable_handoff &claim, pid_t pid,
    const std::array<uint8_t, 16> &source_id)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	if (claim.token == zero16 || claim.checkpoint_digest == zero32 ||
	    claim.destination_vmid == 0 ||
	    claim.destination_vmid >= HYPERTRACE_MAX_VMS ||
	    claim.destination_epoch == 0 || pid <= 1 ||
	    source_id == zero16) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff active{};
	int phase = handoff_state_at(this->dirfd, claim.token, active);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::claimed) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	if (active.checkpoint_digest != claim.checkpoint_digest) {
		errno = EPROTO;
		return (-1);
	}
	if (active.destination_vmid != claim.destination_vmid ||
	    active.destination_epoch != claim.destination_epoch) {
		errno = EPERM;
		return (-1);
	}
	source_journal_cut cut;
	source_journal_destination_plan plan;
	int staged = source_journal_claimed_plan_locked(this->dirfd,
	    this->state, active, cut, plan);
	if (staged < 0)
		return (-1);
	if (staged == 1) {
		int matches = 0;
		for (const auto &kill : cut.kills)
			if (kill.record.pid == pid &&
			    kill.record.source_id == source_id)
				matches++;
		if (matches != 1) {
			errno = matches == 0 ? ENOENT : EPROTO;
			return (-1);
		}
		durable_kill destination{pid, active.destination_vmid,
		    active.destination_epoch, source_id};
		if (!record_kill_at(this->dirfd, destination))
			return (-1);
		char ack_name[73];
		if (!kill_applied_name(destination, ack_name))
			return (-1);
		int applied = kill_record_status_at(this->dirfd, ack_name);
		if (applied < 0 && errno != ENOENT)
			return (-1);
		if (fsync(this->dirfd) != 0)
			return (-1);
		return (applied == 0 ? 'a' : 'p');
	}
	durable_kill source{pid, active.source_vmid, active.source_epoch,
	    source_id};
	char source_name[70];
	if (!durable_kill_name(source, source_name))
		return (-1);
	if (kill_record_status_at(this->dirfd, source_name) != 0)
		return (-1);
	durable_kill destination{pid, active.destination_vmid,
	    active.destination_epoch, source_id};
	if (!record_kill_at(this->dirfd, destination))
		return (-1);
	char ack_name[73];
	if (!kill_applied_name(destination, ack_name))
		return (-1);
	int applied = kill_record_status_at(this->dirfd, ack_name);
	if (applied < 0 && errno != ENOENT)
		return (-1);
	if (fsync(this->dirfd) != 0)
		return (-1);
	return (applied == 0 ? 'a' : 'p');
}

bool
dir::bind_handoff_kills_all(const durable_handoff &claim)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	if (claim.token == zero16 || claim.checkpoint_digest == zero32 ||
	    claim.destination_vmid == 0 ||
	    claim.destination_vmid >= HYPERTRACE_MAX_VMS ||
	    claim.destination_epoch == 0) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff active{};
	int phase = handoff_state_at(this->dirfd, claim.token, active);
	if (phase < 0)
		return (false);
	if (phase != (int)handoff_phase::claimed) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (active.checkpoint_digest != claim.checkpoint_digest) {
		errno = EPROTO;
		return (false);
	}
	if (active.destination_vmid != claim.destination_vmid ||
	    active.destination_epoch != claim.destination_epoch) {
		errno = EPERM;
		return (false);
	}
	/* A foreign source has no local source-VM KILL files. HJB1 and its
	 * completed HJR1 import are the authority for the claimed cut. KILLs
	 * are written before this binder reports success to the restore barrier;
	 * an interrupted prefix is safe to replay on an exact retry. */
	source_journal_cut cut;
	source_journal_destination_plan plan;
	int staged = source_journal_claimed_plan_locked(this->dirfd,
	    this->state, active, cut, plan);
	if (staged < 0)
		return (false);
	if (staged == 1) {
		for (const auto &kill : plan.pending_kills)
			if (!record_kill_at(this->dirfd, kill, false))
				return (false);
		return (fsync(this->dirfd) == 0);
	}
	std::vector<durable_kill> kills;
	if (!list_kills_at(this->dirfd, kills))
		return (false);
	for (const durable_kill &source : kills) {
		if (source.vmid != active.source_vmid ||
		    source.epoch != active.source_epoch)
			continue;
		durable_kill destination = source;
		destination.vmid = active.destination_vmid;
		destination.epoch = active.destination_epoch;
		if (!record_kill_at(this->dirfd, destination, false))
			return (false);
	}
	return (fsync(this->dirfd) == 0);
}
/* HT-C END */

int
dir::host_ingress_phase(const uint8_t program[16], const uint8_t source[16],
    durable_delivery_state *matched)
{
	std::vector<durable_delivery_state> records;
	if (matched != nullptr)
		*matched = {};
	if (!this->list_deliveries(records))
		return (-1);
	int phase = 0;
	for (const auto &entry : records) {
		if (entry.record.scope != 3 ||
		    memcmp(entry.record.program_id.data(), program, 16) != 0 ||
		    memcmp(entry.record.source_id.data(), source, 16) != 0)
			continue;
		if (phase != 0 ||
		    (entry.phase != delivery_phase::pending &&
		    entry.phase != delivery_phase::accepted)) {
			errno = EPROTO;
			return (-1);
		}
		phase = (int)entry.phase;
		if (matched != nullptr)
			*matched = entry;
	}
	return (phase);
}

int
dir::lookup_host_ingress(const durable_delivery &key,
    durable_delivery_state &found)
{
	if (key.scope != 3 || key.delivery_id == 0 ||
	    key.vmid == 0 || key.epoch == 0) {
		errno = EINVAL;
		return (-1);
	}
	std::vector<durable_delivery_state> records;
	if (!this->list_deliveries(records))
		return (-1);
	int matches = 0;
	for (const auto &entry : records) {
		if (entry.record.scope != 3 ||
		    entry.record.vmid != key.vmid ||
		    entry.record.epoch != key.epoch ||
		    entry.record.delivery_id != key.delivery_id)
			continue;
		/* The attested VM incarnation may reconnect with a new session.
		 * The token and program lineage must still identify one record. */
		if (matches != 0 || entry.record.program_id != key.program_id ||
		    entry.record.source_id != key.source_id ||
		    (entry.record.session_id == key.session_id &&
		    (entry.record.peer_uid != key.peer_uid ||
		    entry.record.peer_pid != key.peer_pid))) {
			errno = EPROTO;
			return (-1);
		}
		found = entry;
		matches = 1;
	}
	return (matches);
}

static bool
delivery_transition_at(int directory, const durable_delivery &record,
    delivery_phase phase, bool require_new)
{
	int current = delivery_record_status_at(directory, record);
	if (current < 0)
		return (false);
	if (require_new && current != 0) {
		errno = EEXIST;
		return (false);
	}
	if (record.scope == 0 && record.journal_version == 4 &&
	    phase == delivery_phase::pending && require_new) {
		/* The ordinary host forwarder must not turn a staged imported
		 * program into an unrelated HTD4 send. The imported HTD5 owns its
		 * program identity for this destination VM lifetime, even before
		 * a foreign execution lease makes it runnable. */
		std::vector<durable_delivery_state> recovered;
		if (!list_deliveries_at(directory, recovered))
			return (false);
		for (const auto &entry : recovered)
			if (entry.record.scope == 0 &&
			    entry.record.journal_version == 5 &&
			    entry.record.vmid == record.vmid &&
			    entry.record.epoch == record.epoch &&
			    entry.record.program_id == record.program_id) {
				/* HT-C BEGIN: disabled trace continuity. */
				errno = EBUSY;
				return (false);
				/* HT-C END */
			}
	}
	if (record.scope == 2 && phase == delivery_phase::pending &&
	    require_new) {
		/* A recreated spool must not mint a second token while an
		 * earlier send of the same program is still unresolved. */
		std::vector<durable_delivery_state> recovered;
		if (!list_deliveries_at(directory, recovered))
			return (false);
		for (const auto &entry : recovered)
			if (entry.record.scope == 2 &&
			    entry.record.program_id == record.program_id &&
			    entry.record.source_id == record.source_id) {
				errno = EBUSY;
				return (false);
			}
	}
	if (current == (char)delivery_phase::terminal &&
	    phase != delivery_phase::terminal) {
		errno = ECANCELED;
		return (false);
	}
	if (current != 0 &&
	    delivery_phase_order((delivery_phase)current) >=
	    delivery_phase_order(phase))
		return (fsync(directory) == 0);
	char next[80];
	delivery_record_name(record, phase, next);
	if (current != 0) {
		char previous[80];
		delivery_record_name(record, (delivery_phase)current, previous);
		if (renameat(directory, previous, directory, next) != 0)
			return (false);
		return (fsync(directory) == 0);
	}
	if (phase != delivery_phase::pending) {
		errno = ENOENT;
		return (false);
	}
	int count = delivery_record_count(directory);
	if (count < 0)
		return (false);
	if (count >= 16384) {
		errno = ENOSPC;
		return (false);
	}
	int fd = openat(directory, next,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (false);
	const auto data = delivery_record_bytes(record);
	const size_t size = delivery_record_size(record);
	size_t offset = 0;
	int error = 0;
	while (offset < size) {
		ssize_t n = write(fd, data.data() + offset, size - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		(void)unlinkat(directory, next, 0);
		errno = error;
		return (false);
	}
	return (fsync(directory) == 0);
}

bool
dir::record_delivery(const durable_delivery &record, delivery_phase phase,
    bool require_new)
{
	/* An imported host ingress is inert until the destination owns an
	 * execution lease. Only its ticket-bound import transaction may create
	 * the pending record; an ordinary upload retry cannot accept it. */
	if (record.scope == 3 && record.journal_version == 5) {
		/* HT-C BEGIN: disabled trace continuity. */
		errno = EBUSY;
		return (false);
		/* HT-C END */
	}
	if (!delivery_record_valid(record) ||
	    ((record.scope == 2 || record.scope == 3) &&
	    record.journal_version != 4) ||
	    (record.scope == 0 && phase == delivery_phase::exited) ||
	    (record.scope == 2 && phase != delivery_phase::pending &&
	    phase != delivery_phase::accepted) ||
	    (record.scope == 3 && phase != delivery_phase::pending &&
	    phase != delivery_phase::accepted) ||
	    (phase != delivery_phase::pending &&
	    phase != delivery_phase::accepted &&
	    phase != delivery_phase::installed &&
	    phase != delivery_phase::exited &&
	    phase != delivery_phase::terminal)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	const bool fence_host = record.scope == 0;
	/* A guest journal rekey holds the same cross-process lock. Every
	 * guest delivery transition must serialize with its rewrite. Host
	 * transitions must serialize with KILL publication as well. */
	const bool fence_guest = record.scope == 1 || record.scope == 2;
	handoff_process_lock process_lock(this->dirfd, fence_host || fence_guest);
	if ((fence_host || fence_guest) && !process_lock.held())
		return (false);
	if (fence_host && record.journal_version == 5) {
		/* HT-C BEGIN: disabled trace continuity. */
		/* A foreign HTD5 is imported only by the HJB1 transaction. The
		 * ordinary receipt API must not promote its pending identity before
		 * a destination execution lease exists. Terminal retirement is
		 * safe, but still needs the exact signed source cut. */
		durable_handoff parent{};
		int parent_phase = handoff_state_at(this->dirfd,
		    record.handoff_token, parent);
		if (parent_phase <= 0 ||
		    parent.destination_vmid != record.vmid ||
		    parent.destination_epoch != record.epoch ||
		    parent.source_session != record.source_session) {
			if (parent_phase >= 0)
				errno = EPROTO;
			return (false);
		}
		if (!handoff_release_authority_locked(this->dirfd,
		    this->state, parent))
			return (false);
		int staged = source_journal_stage_status_locked(this->dirfd,
		    parent);
		if (staged < 0)
			return (false);
		if (staged == 0) {
			int orphan = source_journal_ready_raw_status_locked(
			    this->dirfd, parent);
			if (orphan != 0) {
				if (orphan == 1)
					errno = EPROTO;
				return (false);
			}
		} else if (phase != delivery_phase::terminal ||
		    parent_phase != (int)handoff_phase::claimed) {
			errno = EOPNOTSUPP;
			return (false);
		}
		/* HT-C END */
	}
	if (fence_host && phase != delivery_phase::terminal) {
		int revoked = source_revoked_at(this->dirfd,
		    record.source_id.data(), record.vmid, record.epoch);
		if (revoked < 0)
			return (false);
		if (revoked != 0) {
			errno = ECANCELED;
			return (false);
		}
	}
	if (fence_guest && record.vmid != 0) {
		int retired = guest_rekey_marker_at(this->dirfd, record.vmid,
		    record.epoch);
		if (retired < 0)
			return (false);
		if (retired != 0) {
			errno = ESTALE;
			return (false);
		}
	}
	if (fence_host) {
		/* No receipt may cross the saved source cut, including an
		 * installation or exit observed after PREPARE. Exact retries of a
		 * phase already on disk remain idempotent. */
		durable_handoff active{};
		int handoff = handoff_source_state_at(this->dirfd,
		    record.vmid, record.epoch, active);
		if (handoff < 0)
			return (false);
		if (handoff != 0) {
			/* HT-C BEGIN: disabled trace continuity. */
			int current = delivery_record_status_at(this->dirfd,
			    record);
			if (current < 0)
				return (false);
			bool claimed_destination =
			    handoff == (int)handoff_phase::claimed &&
			    record.journal_version == 5 &&
			    record.handoff_token == active.token;
			/* A prior destination's child may exit after that VM has
			 * migrated again. Its terminal receipt only retires the old
			 * binding; the new destination has its own durable record. */
			bool prior_bound_exit = record.journal_version == 5 &&
			    phase == delivery_phase::terminal &&
			    current == (int)delivery_phase::installed &&
			    record.handoff_token != active.token;
			if (!claimed_destination && !prior_bound_exit &&
			    (current != (int)phase || require_new)) {
				errno = EBUSY;
				return (false);
			}
			/* HT-C END */
		}
	}
	return (delivery_transition_at(this->dirfd, record, phase,
	    require_new));
}

static int bound_handoff_status_at(int, state *,
    const durable_delivery &, bool &, bool = false);

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
dir::bind_handoff_delivery(const durable_handoff &claim,
    uint64_t delivery_id, const std::array<uint8_t, 16> &program_id,
    const std::array<uint8_t, 16> &source_id,
    const uint8_t expected_payload_digest[32],
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    durable_delivery_state &bound)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	if (claim.token == zero16 || claim.checkpoint_digest == zero32 ||
	    expected_payload_digest == nullptr ||
	    memcmp(expected_payload_digest, zero32.data(), 32) == 0 ||
	    claim.destination_vmid == 0 ||
	    claim.destination_vmid >= HYPERTRACE_MAX_VMS ||
	    claim.destination_epoch == 0 || delivery_id == 0 ||
	    program_id == zero16 || source_id == zero16 ||
	    destination_session == zero16 || destination_uid == UINT32_MAX ||
	    destination_pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff active{};
	int handoff = handoff_state_at(this->dirfd, claim.token, active);
	if (handoff < 0)
		return (false);
	if (handoff != (int)handoff_phase::mutating &&
	    handoff != (int)handoff_phase::claimed) {
		errno = handoff == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (active.checkpoint_digest != claim.checkpoint_digest) {
		errno = EPROTO;
		return (false);
	}
	if (active.destination_vmid != claim.destination_vmid ||
	    active.destination_epoch != claim.destination_epoch) {
		errno = EPERM;
		return (false);
	}
	std::vector<durable_delivery_state> records;
	if (!list_deliveries_at(this->dirfd, records))
		return (false);
	durable_delivery_state source{}, existing{};
	int sources = 0, destinations = 0;
	for (const durable_delivery_state &entry : records) {
		const durable_delivery &record = entry.record;
		if (record.scope != 0 || record.delivery_id != delivery_id)
			continue;
		if (record.session_id == active.source_session &&
		    record.vmid == active.source_vmid &&
		    record.epoch == active.source_epoch &&
		    record.program_id == program_id &&
		    record.source_id == source_id) {
			if (++sources != 1) {
				errno = EPROTO;
				return (false);
			}
			source = entry;
		}
		if (record.vmid == active.destination_vmid &&
		    record.epoch == active.destination_epoch) {
			if (++destinations != 1) {
				errno = EPROTO;
				return (false);
			}
			existing = entry;
		}
	}
	source_journal_cut foreign_cut;
	source_journal_destination_plan foreign_plan;
	int staged = source_journal_claimed_plan_locked(this->dirfd,
	    this->state, active, foreign_cut, foreign_plan);
	if (staged < 0)
		return (false);
	if (staged == 1) {
		if (handoff != (int)handoff_phase::claimed) {
			errno = EBUSY;
			return (false);
		}
		if (sources != 0) {
			errno = EPROTO;
			return (false);
		}
		const source_journal_delivery *mapped = nullptr;
		for (const auto &item : foreign_plan.deliveries) {
			const auto &record = item.state.record;
			if (record.delivery_id != delivery_id ||
			    record.program_id != program_id ||
			    record.source_id != source_id)
				continue;
			if (mapped != nullptr) {
				errno = EPROTO;
				return (false);
			}
			mapped = &item;
		}
		if (mapped == nullptr) {
			errno = ENOENT;
			return (false);
		}
		if (mapped->state.record.session_id != destination_session ||
		    mapped->state.record.peer_uid != destination_uid ||
		    mapped->state.record.peer_pid != destination_pid) {
			errno = EPERM;
			return (false);
		}
		if (destinations != 1 ||
		    delivery_record_bytes(existing.record) !=
		    delivery_record_bytes(mapped->state.record)) {
			errno = destinations == 0 ? EPROTO : EEXIST;
			return (false);
		}
		if (memcmp(expected_payload_digest,
		    mapped->state.record.payload_digest.data(), 32) != 0 ||
		    mapped->revoked ||
		    (mapped->state.phase != delivery_phase::accepted &&
		    mapped->state.phase != delivery_phase::installed)) {
			errno = mapped->revoked ? ECANCELED : EPROTO;
			return (false);
		}
		if (!validate_host_delivery_payload(existing.record,
		    mapped->payload))
			return (false);
		if (existing.phase != delivery_phase::pending &&
		    existing.phase != delivery_phase::accepted &&
		    existing.phase != delivery_phase::installed) {
			errno = EBUSY;
			return (false);
		}
		int source_revoked = source_revoked_at(this->dirfd,
		    source_id.data(), active.source_vmid,
		    active.source_epoch);
		int destination_revoked = source_revoked < 0 ? -1 :
		    source_revoked_at(this->dirfd, source_id.data(),
		    active.destination_vmid, active.destination_epoch);
		if (source_revoked < 0 || destination_revoked < 0)
			return (false);
		if (source_revoked != 0 || destination_revoked != 0) {
			errno = ECANCELED;
			return (false);
		}
		/* Validate the complete lineage before the durable pending-to-
		 * accepted rename. An invalid ancestor must leave the imported
		 * receipt pending so a repaired import can be retried. */
		bool revoked = false;
		int lineage = bound_handoff_status_at(this->dirfd,
		    this->state, existing.record, revoked, true);
		if (lineage != 1 || revoked) {
			if (lineage == 0)
				errno = EBUSY;
			if (revoked)
				errno = ECANCELED;
			return (false);
		}
		if (existing.phase == delivery_phase::pending) {
			if (!delivery_transition_at(this->dirfd, existing.record,
			    delivery_phase::accepted, false))
				return (false);
			existing.phase = delivery_phase::accepted;
		}
		lineage = bound_handoff_status_at(this->dirfd,
		    this->state, existing.record, revoked);
		if (lineage != 1 || revoked) {
			if (lineage == 0)
				errno = EBUSY;
			if (revoked)
				errno = ECANCELED;
			return (false);
		}
		bound = existing;
		return (fsync(this->dirfd) == 0);
	}
	if (sources != 1 ||
	    (source.phase != delivery_phase::accepted &&
	    source.phase != delivery_phase::installed) ||
	    (source.record.journal_version != 4 &&
	    source.record.journal_version != 5)) {
		errno = sources == 0 ? ENOENT : EOPNOTSUPP;
		return (false);
	}
	if (source.record.journal_version == 5) {
		bool ancestor_revoked = false;
		int ready = bound_handoff_status_at(this->dirfd,
		    this->state, source.record, ancestor_revoked);
		if (ready != 1 || ancestor_revoked) {
			if (ready == 0) errno = EBUSY;
			if (ancestor_revoked) errno = ECANCELED;
			return (false);
		}
	}
	if (memcmp(expected_payload_digest,
	    source.record.payload_digest.data(), 32) != 0) {
		errno = EPROTO;
		return (false);
	}
	int source_revoked = source_revoked_at(this->dirfd,
	    source_id.data(), active.source_vmid, active.source_epoch);
	int destination_revoked = source_revoked < 0 ? -1 :
	    source_revoked_at(this->dirfd, source_id.data(),
	    active.destination_vmid, active.destination_epoch);
	if (source_revoked < 0 || destination_revoked < 0)
		return (false);
	if (source_revoked != 0 || destination_revoked != 0) {
		errno = ECANCELED;
		return (false);
	}
	if (this->verify_host_delivery_payload(source.record) != 1) {
		if (errno == ENOENT)
			errno = EPROTO;
		return (false);
	}
	durable_delivery destination = source.record;
	destination.session_id = destination_session;
	destination.vmid = active.destination_vmid;
	destination.epoch = active.destination_epoch;
	destination.peer_uid = destination_uid;
	destination.peer_pid = destination_pid;
	destination.journal_version = 5;
	destination.handoff_token = active.token;
	destination.source_session = source.record.session_id;
	destination.payload_vmid = source.record.journal_version == 5 ?
	    source.record.payload_vmid : source.record.vmid;
	destination.payload_epoch = source.record.journal_version == 5 ?
	    source.record.payload_epoch : source.record.epoch;
	if (!delivery_record_valid(destination)) {
		errno = EINVAL;
		return (false);
	}
	if (destinations != 0) {
		const durable_delivery &prior = existing.record;
		if (prior.session_id != destination.session_id ||
		    prior.program_id != destination.program_id ||
		    prior.source_id != destination.source_id ||
		    prior.peer_uid != destination.peer_uid ||
		    prior.peer_pid != destination.peer_pid ||
		    prior.journal_version != 5 ||
		    prior.payload_digest != destination.payload_digest ||
		    prior.handoff_token != destination.handoff_token ||
		    prior.source_session != destination.source_session ||
		    prior.payload_vmid != destination.payload_vmid ||
		    prior.payload_epoch != destination.payload_epoch) {
			errno = EEXIST;
			return (false);
		}
	}
	if (handoff == (int)handoff_phase::claimed) {
		if (destinations == 0 ||
		    (existing.phase != delivery_phase::accepted &&
		    existing.phase != delivery_phase::installed)) {
			errno = EBUSY;
			return (false);
		}
		bound = existing;
		return (fsync(this->dirfd) == 0);
	}
	if (destinations == 0 &&
	    !delivery_transition_at(this->dirfd, destination,
	    delivery_phase::pending, false))
		return (false);
	if (!delivery_transition_at(this->dirfd, destination,
	    source.phase, false))
		return (false);
	int phase = delivery_record_status_at(this->dirfd, destination);
	if (phase < 0)
		return (false);
	bound.record = destination;
	bound.phase = (delivery_phase)phase;
	return (fsync(this->dirfd) == 0);
}

static int
bound_handoff_status_at(int directory, state *control,
    const durable_delivery &record, bool &revoked,
    bool assume_first_pending_accepted)
{
	if (record.scope != 0 || record.journal_version != 5 ||
	    !delivery_record_valid(record)) {
		errno = EINVAL;
		return (-1);
	}
	durable_delivery current = record;
	bool any_revoked = false;
	for (unsigned depth = 0; depth < 16384; depth++) {
		durable_handoff ticket{};
		int phase = handoff_state_at(directory,
		    current.handoff_token, ticket);
		if (phase < 0)
			return (-1);
		if (phase == 0 || ticket.source_session !=
		    current.source_session ||
		    ticket.destination_vmid != current.vmid ||
		    ticket.destination_epoch != current.epoch) {
			errno = EPROTO;
			return (-1);
		}
		if (phase != (int)handoff_phase::claimed) {
			if (depth != 0) {
				errno = EPROTO;
				return (-1);
			}
			revoked = false;
			return (fsync(directory) == 0 ? 0 : -1);
		}
		int destination_phase = delivery_record_status_at(directory,
		    current);
		if (destination_phase <= 0) {
			if (destination_phase == 0) errno = EPROTO;
			return (-1);
		}
		if (destination_phase == (int)delivery_phase::pending &&
		    !(depth == 0 && assume_first_pending_accepted)) {
			revoked = false;
			return (fsync(directory) == 0 ? 0 : -1);
		}
		durable_delivery source_key{};
		source_key.session_id = ticket.source_session;
		source_key.delivery_id = current.delivery_id;
		durable_delivery_state source{};
		int sources = 0;
		bool foreign_source = false, foreign_revoked = false;
		for (delivery_phase entry_phase : {delivery_phase::pending,
		    delivery_phase::accepted, delivery_phase::installed,
		    delivery_phase::exited, delivery_phase::terminal}) {
			char name[80];
			delivery_record_name(source_key, entry_phase, name);
			std::array<uint8_t, 185> bytes{};
			size_t length = 0;
			int present = delivery_read_at(directory, name,
			    bytes, length);
			if (present < 0)
				return (-1);
			if (present == 0)
				continue;
			if (++sources != 1 ||
			    !delivery_record_parse(directory, name, source)) {
				errno = EPROTO;
				return (-1);
			}
		}
		if (sources == 0) {
			source_journal_cut cut;
			source_journal_destination_plan plan;
			int staged = source_journal_claimed_plan_locked(directory,
			    control, ticket, cut, plan);
			if (staged < 0)
				return (-1);
			if (staged == 1) {
				for (const auto &item : cut.deliveries) {
					const auto &record = item.state.record;
					if (record.session_id != ticket.source_session ||
					    record.vmid != ticket.source_vmid ||
					    record.epoch != ticket.source_epoch ||
					    record.delivery_id != current.delivery_id ||
					    record.program_id != current.program_id ||
					    record.source_id != current.source_id)
						continue;
					if (++sources != 1) {
						errno = EPROTO;
						return (-1);
					}
					source = item.state;
					foreign_revoked = item.revoked;
				}
				foreign_source = sources == 1;
			}
		}
		if (sources != 1 || source.record.scope != 0 ||
		    source.record.session_id != ticket.source_session ||
		    source.record.vmid != ticket.source_vmid ||
		    source.record.epoch != ticket.source_epoch ||
		    source.record.program_id != current.program_id ||
		    source.record.source_id != current.source_id ||
		    source.record.payload_digest != current.payload_digest ||
		    (source.record.journal_version != 4 &&
		    source.record.journal_version != 5) ||
		    (source.phase != delivery_phase::accepted &&
		    source.phase != delivery_phase::installed) ||
		    (source.record.journal_version == 5 &&
		    (source.record.payload_vmid != current.payload_vmid ||
		    source.record.payload_epoch != current.payload_epoch)) ||
		    (source.record.journal_version == 4 &&
		    (source.record.vmid != current.payload_vmid ||
		    source.record.epoch != current.payload_epoch))) {
			errno = EPROTO;
			return (-1);
		}
		int from = foreign_source ? (foreign_revoked ? 1 : 0) :
		    source_revoked_at(directory, current.source_id.data(),
		    ticket.source_vmid, ticket.source_epoch);
		int to = from < 0 ? -1 : source_revoked_at(directory,
		    current.source_id.data(), ticket.destination_vmid,
		    ticket.destination_epoch);
		if (from < 0 || to < 0)
			return (-1);
		any_revoked |= from != 0 || to != 0;
		if (source.record.journal_version == 4 || foreign_source)
			break;
		if (source.record.handoff_token == current.handoff_token) {
			errno = EPROTO;
			return (-1);
		}
		current = source.record;
		if (depth == 16383) {
			errno = ELOOP;
			return (-1);
		}
	}
	if (fsync(directory) != 0)
		return (-1);
	revoked = any_revoked;
	return (1);
}

int
dir::bound_handoff_status(const durable_delivery &record, bool &revoked)
{
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	return (bound_handoff_status_at(this->dirfd, this->state,
	    record, revoked));
}
/* HT-C END */

bool
dir::retire_terminal_delivery(const durable_delivery &record)
{
	if (!delivery_record_valid(record) || record.scope != 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	int retired = guest_rekey_marker_at(this->dirfd, record.vmid,
	    record.epoch);
	if (retired < 0)
		return (false);
	if (retired != 0) {
		errno = ESTALE;
		return (false);
	}
	int current = delivery_record_status_at(this->dirfd, record);
	if (current < 0)
		return (false);
	if (current == 0)
		return (true);
	if (current != (int)delivery_phase::terminal) {
		errno = EBUSY;
		return (false);
	}
	char name[80];
	delivery_record_name(record, delivery_phase::terminal, name);
	if (unlinkat(this->dirfd, name, 0) != 0)
		return (false);
	return (fsync(this->dirfd) == 0);
}

bool
dir::retire_accepted_outbound(const durable_delivery &record)
{
	if (!delivery_record_valid(record) || record.scope != 2) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	int retired = record.vmid == 0 ? 0 :
	    guest_rekey_marker_at(this->dirfd, record.vmid, record.epoch);
	if (retired < 0)
		return (false);
	if (retired != 0) {
		errno = ESTALE;
		return (false);
	}
	int current = delivery_record_status_at(this->dirfd, record);
	if (current < 0)
		return (false);
	if (current == 0)
		return (true);
	if (current != (int)delivery_phase::accepted) {
		errno = EBUSY;
		return (false);
	}
	char name[80];
	delivery_record_name(record, delivery_phase::accepted, name);
	if (unlinkat(this->dirfd, name, 0) != 0)
		return (false);
	return (fsync(this->dirfd) == 0);
}

bool
dir::write_identified_data(const unsigned char *data, size_t nbytes,
    const uint8_t identity[16], bool *created, const uint8_t *source_id,
    bool reject_revoked)
{
	std::lock_guard lk(this->publishmtx);
	if (source_id != nullptr) {
		int revoked = source_revoked_at(this->dirfd, source_id);
		if (revoked < 0)
			return (false);
		if (revoked > 0) {
			if (reject_revoked) {
				errno = ECANCELED;
				return (false);
			}
			if (created != nullptr)
				*created = false;
			return (true);
		}
	}
	return (publish_spool(this->dirfd, data, nbytes, -1, identity,
	    created, source_id));
}

bool
dir::copy_data(int directory, const char *name)
{
	struct stat sb;
	__cleanup(closefd_generic) int fd = -1;

	if (name == nullptr || name[0] == '\0' || strchr(name, '/') != nullptr ||
	    strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
		errno = EINVAL;
		return (false);
	}
	fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &sb) != 0)
		return (false);
	if (!S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    (uintmax_t)sb.st_size > max_request_bytes - DTRACED_MSGHDRSIZE) {
		errno = EINVAL;
		return (false);
	}
	/* Keep a source-bound spool's revocable lineage. The copy gets a new
	 * program ID (the publication nonce), as any outbound publication does;
	 * host forwarders accept only "elf.<program>.<source>" spools. */
	std::array<uint8_t, 16> program{}, source{};
	bool sourced = spool_identity_from_path(name, program, source);
	return (publish_spool(this->dirfd, nullptr, (size_t)sb.st_size, fd,
	    nullptr, nullptr, sourced ? source.data() : nullptr));
}

bool
dir::process(void)
{
	bool r = true;
	struct dirent *file;

	for (;;) {
		errno = 0;
		file = readdir(this->dirp);
		if (file == NULL) {
			if (errno != 0)
				r = false;
			break;
		}
		try {
			r = this->processfn(*this, file);
		} catch (const std::bad_alloc &) {
			errno = ENOMEM;
			r = false;
		}
		if (!r)
			break;
	}

	rewinddir(this->dirp);
	return (r);
}

bool
dir::listen(void)
{
	int rval;
	__cleanup(closefd_generic) int kq = -1;
	struct kevent ev = {}, ev_data = {}, receipt = {};
	dtraced::state *s;
	struct timespec ts;

	s = this->state;
	if (s->shutdown.load()) {
		s->report_directory_start(ECANCELED);
		return (false);
	}

	if ((kq = kqueue()) == -1) {
		int error = errno;
		ERR("failed to create a kqueue %m");
		s->report_directory_start(error);
		broadcast_shutdown(*s);
		return (false);
	}

	EV_SET(&ev, this->dirfd, EVFILT_VNODE,
	    EV_ADD | EV_CLEAR | EV_ENABLE | EV_RECEIPT,
	    NOTE_WRITE, 0, (void *)this);
	/* Arm the watch before scanning the gap since populate_existing(). */
	int registered = kevent(kq, &ev, 1, &receipt, 1, nullptr);
	if (registered != 1 || (receipt.flags & EV_ERROR) == 0 ||
	    receipt.data != 0) {
		int error = registered == 1 && receipt.data != 0 ?
		    (int)receipt.data : errno == 0 ? EIO : errno;
		errno = error;
		ERR("failed to watch %s: %m", this->dirpath.c_str());
		s->report_directory_start(error);
		broadcast_shutdown(*s);
		return (false);
	}
	if (s->shutdown.load()) {
		s->report_directory_start(ECANCELED);
		return (false);
	}
	if (!this->process()) {
		int error = errno == 0 ? EIO : errno;
		ERR("failed to scan %s: %m", this->dirpath.c_str());
		s->report_directory_start(error);
		broadcast_shutdown(*s);
		return (false);
	}
	s->report_directory_start(0);

	ts.tv_sec = DTRACED_EVENTSLEEPTIME;
	ts.tv_nsec = 0;
	for (;;) {
		/* The replay rescan flag must be checked on timeout too. */
		do {
			rval = kevent(kq, nullptr, 0, &ev_data, 1, &ts);
		} while (rval < 0 && errno == EINTR && !s->shutdown.load());

		if (s->shutdown.load())
			break;

		if (rval < 0) {
			ERR("dtraced::event failed on %s: %m",
			    this->dirpath.c_str());
			broadcast_shutdown(*s);
			return (false);
		}

		if (rval > 0 && (ev_data.flags & EV_ERROR) != 0) {
			errno = ev_data.data != 0 ? (int)ev_data.data : EIO;
			ERR("dtraced::event got EV_ERROR on %s: %m",
			    this->dirpath.c_str());
			broadcast_shutdown(*s);
			return (false);
		}

		if (rval > 0 || this->rescan_requested.exchange(false)) {
			if (!this->process()) {
				ERR("failed to process new files in %s",
				    this->dirpath.c_str());
				broadcast_shutdown(*s);
				return (false);
			}
		}
	}

	return (true);
}

bool
dir::memorized(const std::string &p)
{
	std::lock_guard lock(this->existingmtx);
	return (this->existing_files.find(p) != this->existing_files.end());
}

bool
dir::rmpath(const std::string &p)
{
	std::lock_guard lock(this->existingmtx);
	return (this->existing_files.erase(p) > 0);
}

bool
dir::request_reprocess(const uint8_t program[16], const uint8_t source[16],
    const uint8_t expected[32], bool envelope)
{
	char name[70];
	identified_spool_name(program, source, name);
	uint8_t actual[32];
	if (!this->hash_identified_data(program, source, actual, envelope))
		return (false);
	if (memcmp(actual, expected, sizeof(actual)) != 0) {
		errno = EPROTO;
		return (false);
	}
	{
		std::lock_guard lock(this->existingmtx);
		this->existing_files.erase(name);
		this->rescan_requested.store(true);
	}
	return (true);
}

void
dir::request_scan(void)
{
	this->rescan_requested.store(true);
}

bool
dir::hash_identified_data(const uint8_t program[16],
    const uint8_t source[16], uint8_t digest[32], bool envelope, bool target,
    uint8_t bare_elf_digest[32])
{
	if ((envelope && target) || (bare_elf_digest != nullptr &&
	    (!target || bare_elf_digest == digest)) || digest == nullptr) {
		errno = EINVAL;
		return (false);
	}
	char name[70];
	identified_spool_name(program, source, name);
	int fd = openat(this->dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (false);
	struct stat before, after;
	const size_t prefix_size = target ?
	    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4 : 4;
	bool ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
	    before.st_size >= (off_t)prefix_size &&
	    (uintmax_t)before.st_size <=
	    max_request_bytes - DTRACED_MSGHDRSIZE;
	EVP_MD_CTX *ctx = ok ? EVP_MD_CTX_new() : nullptr;
	EVP_MD_CTX *bare_ctx = ok && bare_elf_digest != nullptr ?
	    EVP_MD_CTX_new() : nullptr;
	if (ctx == nullptr || (bare_elf_digest != nullptr && bare_ctx == nullptr))
		ok = false;
	if (ok)
		ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
	if (ok && bare_ctx != nullptr)
		ok = EVP_DigestInit_ex(bare_ctx, EVP_sha256(), nullptr) == 1;
	unsigned char block[65536];
	unsigned char prefix[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4]{};
	size_t prefix_copied = 0;
	size_t total = 0;
	while (ok) {
		ssize_t n = read(fd, block, sizeof(block));
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			ok = false;
			break;
		}
		if (n == 0)
			break;
		if ((size_t)n > (size_t)before.st_size - total) {
			ok = false;
			break;
		}
		if (prefix_copied < prefix_size) {
			size_t copied = std::min(prefix_size - prefix_copied,
			    (size_t)n);
			memcpy(prefix + prefix_copied, block, copied);
			prefix_copied += copied;
		}
		if (EVP_DigestUpdate(ctx, block, (size_t)n) != 1) {
			ok = false;
			break;
		}
		if (bare_ctx != nullptr) {
			size_t skip = total < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE ?
			    std::min(HYPERTRACE_VM_ENVELOPE_WIRE_SIZE - total,
			    (size_t)n) : 0;
			if ((size_t)n > skip && EVP_DigestUpdate(bare_ctx,
			    block + skip, (size_t)n - skip) != 1) {
				ok = false;
				break;
			}
		}
		total += (size_t)n;
	}
	if (ok && prefix_copied == prefix_size) {
		if (target) {
			hypertrace_vm_envelope decoded{};
			hypertrace_envelope_decode(&decoded, prefix);
			ok = decoded.magic == HYPERTRACE_TARGET_MAGIC &&
			    decoded.version == HYPERTRACE_ENVELOPE_VERSION &&
			    decoded.name_length == 0 &&
			    memcmp(prefix + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
			    "\177ELF", 4) == 0;
		} else if (envelope)
			ok = (uint32_t)hypertrace_envelope_get_le(prefix, 4) ==
			    HYPERTRACE_ENVELOPE_MAGIC;
		else
			ok = memcmp(prefix, "\177ELF", 4) == 0;
	} else
		ok = false;
	unsigned length = 0;
	if (ok)
		ok = total == (size_t)before.st_size &&
		    fstat(fd, &after) == 0 && after.st_dev == before.st_dev &&
		    after.st_ino == before.st_ino && after.st_size == before.st_size &&
		    after.st_mtim.tv_sec == before.st_mtim.tv_sec &&
		    after.st_mtim.tv_nsec == before.st_mtim.tv_nsec &&
		    EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32;
	if (ok && bare_ctx != nullptr)
		ok = EVP_DigestFinal_ex(bare_ctx, bare_elf_digest,
		    &length) == 1 && length == 32;
	EVP_MD_CTX_free(bare_ctx);
	EVP_MD_CTX_free(ctx);
	if (close(fd) != 0)
		ok = false;
	if (!ok) {
		/* Only the failed open above can prove that the file is absent. */
		errno = EPROTO;
		memset(digest, 0, 32);
		if (bare_elf_digest != nullptr)
			memset(bare_elf_digest, 0, 32);
	}
	return (ok);
}

int
dir::verify_host_delivery_payload(const durable_delivery &record,
    std::vector<uint8_t> *verified_copy)
{
	if (verified_copy != nullptr)
		verified_copy->clear();
	if (record.scope != 0 ||
	    (record.journal_version != 4 && record.journal_version != 5) ||
	    !delivery_record_valid(record)) {
		errno = EINVAL;
		return (-1);
	}
	char name[70];
	identified_spool_name(record.program_id.data(),
	    record.source_id.data(), name);
	int fd = openat(this->dirfd, name,
	    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat before{}, after{}, named{};
	bool ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
	    before.st_size >= 4 && (uintmax_t)before.st_size <=
	    max_request_bytes - DTRACED_MSGHDRSIZE;
	/* Portable journal bytes must come from one private source inode. */
	if (ok && verified_copy != nullptr)
		ok = before.st_nlink == 1 && before.st_uid == geteuid() &&
		    (before.st_mode & 077) == 0;
	auto read_exact = [&](void *out, size_t size, off_t offset) {
		size_t done = 0;
		while (done < size) {
			ssize_t n = pread(fd, (uint8_t *)out + done, size - done,
			    offset + (off_t)done);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				return (false);
			done += (size_t)n;
		}
		return (true);
	};
	uint8_t prefix[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4]{};
	size_t elf_offset = 0;
	if (ok)
		ok = read_exact(prefix, 4, 0);
	if (ok && memcmp(prefix, "\177ELF", 4) != 0) {
		hypertrace_vm_envelope envelope{};
		ok = before.st_size >= (off_t)sizeof(prefix) &&
		    read_exact(prefix, sizeof(prefix), 0);
		if (ok) {
			hypertrace_envelope_decode(&envelope, prefix);
			uint16_t expected_vmid = record.journal_version == 5 ?
			    record.payload_vmid : record.vmid;
			uint64_t expected_epoch = record.journal_version == 5 ?
			    record.payload_epoch : record.epoch;
			ok = envelope.magic == HYPERTRACE_TARGET_MAGIC &&
			    envelope.version == HYPERTRACE_ENVELOPE_VERSION &&
			    envelope.vmid == expected_vmid &&
			    envelope.epoch == expected_epoch &&
			    envelope.name_length == 0 &&
			    memcmp(prefix + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
			    "\177ELF", 4) == 0;
			elf_offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
		}
	}
	std::vector<uint8_t> captured;
	if (ok && verified_copy != nullptr) {
		try {
			captured.resize((size_t)before.st_size);
		} catch (const std::bad_alloc &) {
			(void)close(fd);
			errno = ENOMEM;
			return (-1);
		}
		ok = read_exact(captured.data(), elf_offset + 4, 0) &&
		    memcmp(captured.data(), prefix, elf_offset + 4) == 0;
	}
	EVP_MD_CTX *ctx = ok ? EVP_MD_CTX_new() : nullptr;
	if (ctx == nullptr)
		ok = false;
	if (ok)
		ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
	uint8_t block[65536], digest[32]{};
	for (off_t pos = (off_t)elf_offset; ok && pos < before.st_size;) {
		size_t chunk = std::min(sizeof(block),
		    (size_t)(before.st_size - pos));
		uint8_t *destination = verified_copy != nullptr ?
		    captured.data() + (size_t)pos : block;
		if (!read_exact(destination, chunk, pos) ||
		    EVP_DigestUpdate(ctx, destination, chunk) != 1) {
			ok = false;
			break;
		}
		pos += (off_t)chunk;
	}
	unsigned length = 0;
	if (ok)
		ok = EVP_DigestFinal_ex(ctx, digest, &length) == 1 &&
		    length == sizeof(digest) &&
		    memcmp(digest, record.payload_digest.data(), sizeof(digest)) == 0 &&
		    fsync(fd) == 0 && fstat(fd, &after) == 0 &&
		    fstatat(this->dirfd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
		    before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
		    before.st_size == after.st_size &&
		    before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
		    before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
		    before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
		    before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
		    named.st_dev == before.st_dev && named.st_ino == before.st_ino;
	EVP_MD_CTX_free(ctx);
	if (close(fd) != 0)
		ok = false;
	if (!ok) {
		errno = EPROTO;
		return (-1);
	}
	if (verified_copy != nullptr)
		verified_copy->swap(captured);
	return (1);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* Destination staging must validate the copied bytes against HTD4/HTD5,
 * rather than treating a signed transfer digest as proof of ELF identity. */
bool
dir::validate_host_delivery_payload(const durable_delivery &record,
    const std::vector<uint8_t> &bytes)
{
	if (record.scope != 0 ||
	    (record.journal_version != 4 && record.journal_version != 5) ||
	    !delivery_record_valid(record) || bytes.size() < 4 ||
	    bytes.size() > max_request_bytes - DTRACED_MSGHDRSIZE) {
		errno = EPROTO;
		return (false);
	}
	size_t elf_offset = 0;
	if (memcmp(bytes.data(), "\177ELF", 4) != 0) {
		if (bytes.size() < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4) {
			errno = EPROTO;
			return (false);
		}
		hypertrace_vm_envelope envelope{};
		hypertrace_envelope_decode(&envelope, bytes.data());
		const uint16_t vmid = record.journal_version == 5 ?
		    record.payload_vmid : record.vmid;
		const uint64_t epoch = record.journal_version == 5 ?
		    record.payload_epoch : record.epoch;
		if (envelope.magic != HYPERTRACE_TARGET_MAGIC ||
		    envelope.version != HYPERTRACE_ENVELOPE_VERSION ||
		    envelope.vmid != vmid || envelope.epoch != epoch ||
		    envelope.name_length != 0) {
			errno = EPROTO;
			return (false);
		}
		elf_offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
	}
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (memcmp(bytes.data() + elf_offset, "\177ELF", 4) != 0 ||
	    SHA256(bytes.data() + elf_offset, bytes.size() - elf_offset,
	    digest) == nullptr ||
	    memcmp(digest, record.payload_digest.data(), sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	return (true);
}

/* Collect the transfer-relevant outbound journal while PREPARE owns both
 * source locks. Nothing escapes on failure. The future HTX1 archive encoder
 * must bind this canonical set, including copied payloads, to the ticket. */
bool
dir::source_journal_cut_locked(const durable_handoff &ticket,
    source_journal_cut &result)
{
	result = {};
	if (!handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (false);
	}
	std::vector<durable_delivery_state> deliveries;
	std::vector<durable_kill> kills;
	std::vector<durable_cleanup> pending;
	std::vector<source_journal_cleanup> cleanups;
	if (!list_deliveries_at(this->dirfd, deliveries) ||
	    !list_kills_at(this->dirfd, kills) ||
	    !list_pending_cleanups_at(this->dirfd, pending, nullptr,
	    &cleanups))
		return (false);
	/* Leave room for the HTX1 wrapper and a signed source-journal header.
	 * Every retained entry is charged before it can become export data. */
	const size_t limit = DTRACED_TRANSFER_MAX_SIZE - 4096;
	size_t used = 128;
	source_journal_cut candidate;
	try {
		for (const auto &entry : deliveries) {
			const durable_delivery &record = entry.record;
			if (record.scope != 0 ||
			    record.vmid != ticket.source_vmid ||
			    record.epoch != ticket.source_epoch)
				continue;
			if (entry.phase == delivery_phase::pending) {
				errno = EBUSY;
				return (false);
			}
			if (entry.phase != delivery_phase::accepted &&
			    entry.phase != delivery_phase::installed)
				continue;
			if (record.session_id != ticket.source_session ||
			    (record.journal_version != 4 &&
			    record.journal_version != 5)) {
				errno = EOPNOTSUPP;
				return (false);
			}
			int revoked = source_revoked_at(this->dirfd,
			    record.source_id.data(), ticket.source_vmid,
			    ticket.source_epoch);
			if (revoked < 0)
				return (false);
			if (record.journal_version == 5) {
				bool ancestor_revoked = false;
				int bound = bound_handoff_status_at(this->dirfd,
				    this->state, record, ancestor_revoked);
				if (bound != 1) {
					if (bound == 0)
						errno = EBUSY;
					return (false);
				}
				revoked |= ancestor_revoked;
			}
			source_journal_delivery copied{};
			copied.state = entry;
			copied.revoked = revoked != 0;
			if (!copied.revoked) {
				int verified = verify_host_delivery_payload(record,
				    &copied.payload);
				if (verified != 1) {
					if (verified == 0)
						errno = EBUSY;
					return (false);
				}
				if (!validate_host_delivery_payload(record,
				    copied.payload))
					return (false);
			}
			const size_t charge = 256 + copied.payload.size();
			if (used > limit || charge > limit - used) {
				errno = E2BIG;
				return (false);
			}
			used += charge;
			candidate.deliveries.push_back(std::move(copied));
		}
		std::sort(candidate.deliveries.begin(),
		    candidate.deliveries.end(), [](const auto &a, const auto &b) {
			const auto &left = a.state.record;
			const auto &right = b.state.record;
			if (left.session_id != right.session_id)
				return (left.session_id < right.session_id);
			return (left.delivery_id < right.delivery_id);
		    });
		for (const durable_kill &kill : kills) {
			if (kill.vmid != ticket.source_vmid ||
			    kill.epoch != ticket.source_epoch)
				continue;
			char ack_name[73];
			if (!kill_applied_name(kill, ack_name))
				return (false);
			int applied = kill_record_status_at(this->dirfd,
			    ack_name);
			if (applied != 0) {
				if (errno == ENOENT)
					errno = EBUSY;
				return (false);
			}
			if (used > limit || 64 > limit - used) {
				errno = E2BIG;
				return (false);
			}
			used += 64;
			candidate.kills.push_back({kill, true});
		}
		std::sort(candidate.kills.begin(), candidate.kills.end(),
		    [](const auto &a, const auto &b) {
			if (a.record.pid != b.record.pid)
				return (a.record.pid < b.record.pid);
			return (a.record.source_id < b.record.source_id);
		    });
		for (const auto &cleanup : cleanups) {
			if (cleanup.record.vmid != ticket.source_vmid ||
			    cleanup.record.epoch != ticket.source_epoch)
				continue;
			if (cleanup.phase == 'p') {
				errno = EBUSY;
				return (false);
			}
			if (used > limit || 32 > limit - used) {
				errno = E2BIG;
				return (false);
			}
			used += 32;
			candidate.cleanups.push_back(cleanup);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	if (fsync(this->dirfd) != 0)
		return (false);
	result = std::move(candidate);
	return (true);
}

/* HJX1 is the canonical outbound half of a future HTX1 source member.
 * Its hash detects torn copies; only an HTX1 digest in signed HSA1 can
 * authenticate it to a foreign destination. Do not import it on its own. */
static constexpr size_t source_journal_header_size = 64;
static constexpr size_t source_journal_tail_size = SHA256_DIGEST_LENGTH;
static constexpr size_t source_journal_max_size =
    DTRACED_TRANSFER_MAX_SIZE - 4096;

static bool
source_journal_delivery_decode(const uint8_t *wire, size_t length,
    durable_delivery &result)
{
	if (wire == nullptr ||
	    !((length == 143 && memcmp(wire, "HTD4", 4) == 0) ||
	    (length == 185 && memcmp(wire, "HTD5", 4) == 0))) {
		errno = EPROTO;
		return (false);
	}
	durable_delivery record{};
	record.journal_version = length == 185 ? 5 : 4;
	memcpy(record.session_id.data(), wire + 4, 16);
	record.delivery_id = dtraced_wire_get_u64(wire + 20);
	record.vmid = dtraced_wire_get_u16(wire + 28);
	record.epoch = dtraced_wire_get_u64(wire + 30);
	memcpy(record.program_id.data(), wire + 38, 16);
	memcpy(record.source_id.data(), wire + 54, 16);
	record.peer_uid = dtraced_wire_get_u32(wire + 70);
	record.peer_pid = dtraced_wire_get_u32(wire + 74);
	record.scope = wire[78];
	memcpy(record.payload_digest.data(), wire + 79, 32);
	if (length == 185) {
		memcpy(record.handoff_token.data(), wire + 111, 16);
		memcpy(record.source_session.data(), wire + 127, 16);
		record.payload_vmid = dtraced_wire_get_u16(wire + 143);
		record.payload_epoch = dtraced_wire_get_u64(wire + 145);
	}
	if (!delivery_record_valid(record) ||
	    memcmp(delivery_record_bytes(record).data(), wire, length) != 0) {
		errno = EPROTO;
		return (false);
	}
	result = record;
	return (true);
}

static bool
source_journal_delivery_after(const durable_delivery &current,
    const durable_delivery &previous)
{
	return (current.session_id > previous.session_id ||
	    (current.session_id == previous.session_id &&
	    current.delivery_id > previous.delivery_id));
}

static bool
source_journal_kill_after(const durable_kill &current,
    const durable_kill &previous)
{
	return (current.pid > previous.pid ||
	    (current.pid == previous.pid &&
	    current.source_id > previous.source_id));
}

bool
dir::encode_source_journal_archive(const durable_handoff &ticket,
    const source_journal_cut &cut, std::vector<uint8_t> &result)
{
	result.clear();
	if (!handoff_valid(ticket, handoff_phase::prepared) ||
	    cut.deliveries.size() > max_durable_kills ||
	    cut.kills.size() > max_durable_kills ||
	    cut.cleanups.size() > max_durable_kills) {
		errno = EINVAL;
		return (false);
	}
	size_t length = source_journal_header_size + source_journal_tail_size;
	for (size_t i = 0; i < cut.deliveries.size(); i++) {
		const auto &item = cut.deliveries[i];
		const auto &record = item.state.record;
		if (record.scope != 0 ||
		    (record.journal_version != 4 && record.journal_version != 5) ||
		    !delivery_record_valid(record) ||
		    record.session_id != ticket.source_session ||
		    record.vmid != ticket.source_vmid ||
		    record.epoch != ticket.source_epoch ||
		    (item.state.phase != delivery_phase::accepted &&
		    item.state.phase != delivery_phase::installed) ||
		    (i != 0 && !source_journal_delivery_after(record,
		    cut.deliveries[i - 1].state.record)) ||
		    (item.revoked ? !item.payload.empty() :
		    !validate_host_delivery_payload(record, item.payload))) {
			errno = EPROTO;
			return (false);
		}
		size_t charge = 12 + delivery_record_size(record) +
		    item.payload.size();
		if (length > source_journal_max_size ||
		    charge > source_journal_max_size - length) {
			errno = E2BIG;
			return (false);
		}
		length += charge;
	}
	for (size_t i = 0; i < cut.kills.size(); i++) {
		const auto &item = cut.kills[i];
		if (!item.applied || item.record.pid <= 1 ||
		    item.record.pid > INT32_MAX ||
		    item.record.source_id == std::array<uint8_t, 16>{} ||
		    item.record.vmid != ticket.source_vmid ||
		    item.record.epoch != ticket.source_epoch ||
		    (i != 0 && !source_journal_kill_after(item.record,
		    cut.kills[i - 1].record))) {
			errno = EPROTO;
			return (false);
		}
		if (length > source_journal_max_size - 24) {
			errno = E2BIG;
			return (false);
		}
		length += 24;
	}
	for (size_t i = 0; i < cut.cleanups.size(); i++) {
		const auto &item = cut.cleanups[i];
		if (item.record.vmid != ticket.source_vmid ||
		    item.record.epoch != ticket.source_epoch ||
		    item.record.delivery_id == 0 ||
		    (item.phase != 'a' && item.phase != 'g') ||
		    (i != 0 && item.record.delivery_id <=
		    cut.cleanups[i - 1].record.delivery_id)) {
			errno = EPROTO;
			return (false);
		}
		if (length > source_journal_max_size - 16) {
			errno = E2BIG;
			return (false);
		}
		length += 16;
	}
	try {
		std::vector<uint8_t> wire(length, 0);
		memcpy(wire.data(), "HJX1", 4);
		dtraced_wire_put_u32(wire.data() + 4, 1);
		memcpy(wire.data() + 8, ticket.token.data(), 16);
		memcpy(wire.data() + 24, ticket.source_session.data(), 16);
		dtraced_wire_put_u16(wire.data() + 40, ticket.source_vmid);
		dtraced_wire_put_u64(wire.data() + 48, ticket.source_epoch);
		dtraced_wire_put_u16(wire.data() + 56,
		    (uint16_t)cut.deliveries.size());
		dtraced_wire_put_u16(wire.data() + 58,
		    (uint16_t)cut.kills.size());
		dtraced_wire_put_u16(wire.data() + 60,
		    (uint16_t)cut.cleanups.size());
		size_t offset = source_journal_header_size;
		for (const auto &item : cut.deliveries) {
			const auto &record = item.state.record;
			size_t record_size = delivery_record_size(record);
			const auto bytes = delivery_record_bytes(record);
			wire[offset] = 1;
			wire[offset + 1] = (uint8_t)item.state.phase;
			wire[offset + 2] = item.revoked ? 1 : 0;
			dtraced_wire_put_u16(wire.data() + offset + 4,
			    (uint16_t)record_size);
			dtraced_wire_put_u32(wire.data() + offset + 8,
			    (uint32_t)item.payload.size());
			offset += 12;
			memcpy(wire.data() + offset, bytes.data(), record_size);
			offset += record_size;
			if (!item.payload.empty()) {
				memcpy(wire.data() + offset, item.payload.data(),
				    item.payload.size());
				offset += item.payload.size();
			}
		}
		for (const auto &item : cut.kills) {
			wire[offset] = 2;
			wire[offset + 1] = 1;
			dtraced_wire_put_u32(wire.data() + offset + 4,
			    (uint32_t)item.record.pid);
			memcpy(wire.data() + offset + 8,
			    item.record.source_id.data(), 16);
			offset += 24;
		}
		for (const auto &item : cut.cleanups) {
			wire[offset] = 3;
			wire[offset + 1] = (uint8_t)item.phase;
			dtraced_wire_put_u64(wire.data() + offset + 8,
			    item.record.delivery_id);
			offset += 16;
		}
		if (offset != length - source_journal_tail_size ||
		    SHA256(wire.data(), offset, wire.data() + offset) == nullptr) {
			errno = EIO;
			return (false);
		}
		result.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

bool
dir::decode_source_journal_archive(const durable_handoff &ticket,
    const uint8_t *wire, size_t length, source_journal_cut &result)
{
	result = {};
	const uint8_t zero6[6] = {};
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (!handoff_valid(ticket, handoff_phase::prepared) || wire == nullptr ||
	    length < source_journal_header_size + source_journal_tail_size ||
	    length > source_journal_max_size ||
	    memcmp(wire, "HJX1", 4) != 0 ||
	    dtraced_wire_get_u32(wire + 4) != 1 ||
	    memcmp(wire + 8, ticket.token.data(), 16) != 0 ||
	    memcmp(wire + 24, ticket.source_session.data(), 16) != 0 ||
	    dtraced_wire_get_u16(wire + 40) != ticket.source_vmid ||
	    memcmp(wire + 42, zero6, sizeof(zero6)) != 0 ||
	    dtraced_wire_get_u64(wire + 48) != ticket.source_epoch ||
	    wire[62] != 0 || wire[63] != 0 ||
	    dtraced_wire_get_u16(wire + 56) > max_durable_kills ||
	    dtraced_wire_get_u16(wire + 58) > max_durable_kills ||
	    dtraced_wire_get_u16(wire + 60) > max_durable_kills ||
	    SHA256(wire, length - source_journal_tail_size, digest) == nullptr ||
	    CRYPTO_memcmp(digest, wire + length - source_journal_tail_size,
	    sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	const size_t tail = length - source_journal_tail_size;
	size_t offset = source_journal_header_size;
	source_journal_cut parsed;
	try {
		const uint16_t delivery_count = dtraced_wire_get_u16(wire + 56);
		const uint16_t kill_count = dtraced_wire_get_u16(wire + 58);
		const uint16_t cleanup_count = dtraced_wire_get_u16(wire + 60);
		parsed.deliveries.reserve(delivery_count);
		parsed.kills.reserve(kill_count);
		parsed.cleanups.reserve(cleanup_count);
		for (uint16_t i = 0; i < delivery_count; i++) {
			if (tail - offset < 12 || wire[offset] != 1 ||
			    (wire[offset + 1] != 'a' && wire[offset + 1] != 'i') ||
			    wire[offset + 2] > 1 || wire[offset + 3] != 0 ||
			    wire[offset + 6] != 0 || wire[offset + 7] != 0) {
				errno = EPROTO;
				return (false);
			}
			const size_t record_size = dtraced_wire_get_u16(
			    wire + offset + 4);
			const size_t payload_size = dtraced_wire_get_u32(
			    wire + offset + 8);
			const delivery_phase phase =
			    (delivery_phase)wire[offset + 1];
			const bool revoked = wire[offset + 2] != 0;
			offset += 12;
			if ((record_size != 143 && record_size != 185) ||
			    record_size > tail - offset ||
			    payload_size > tail - offset - record_size ||
			    (revoked ? payload_size != 0 : payload_size == 0)) {
				errno = EPROTO;
				return (false);
			}
			source_journal_delivery item{};
			if (!source_journal_delivery_decode(wire + offset,
			    record_size, item.state.record))
				return (false);
			item.state.phase = phase;
			item.revoked = revoked;
			const auto &record = item.state.record;
			if (record.scope != 0 ||
			    record.session_id != ticket.source_session ||
			    record.vmid != ticket.source_vmid ||
			    record.epoch != ticket.source_epoch ||
			    (i != 0 && !source_journal_delivery_after(record,
			    parsed.deliveries.back().state.record))) {
				errno = EPROTO;
				return (false);
			}
			offset += record_size;
			if (!revoked) {
				item.payload.assign(wire + offset,
				    wire + offset + payload_size);
				if (!validate_host_delivery_payload(record,
				    item.payload))
					return (false);
			}
			offset += payload_size;
			parsed.deliveries.push_back(std::move(item));
		}
		for (uint16_t i = 0; i < kill_count; i++) {
			if (tail - offset < 24 || wire[offset] != 2 ||
			    wire[offset + 1] != 1 || wire[offset + 2] != 0 ||
			    wire[offset + 3] != 0) {
				errno = EPROTO;
				return (false);
			}
			uint32_t pid = dtraced_wire_get_u32(wire + offset + 4);
			source_journal_kill item{};
			item.record.pid = (pid_t)pid;
			item.record.vmid = ticket.source_vmid;
			item.record.epoch = ticket.source_epoch;
			memcpy(item.record.source_id.data(), wire + offset + 8, 16);
			item.applied = true;
			if (pid <= 1 || pid > INT32_MAX ||
			    item.record.source_id == std::array<uint8_t, 16>{} ||
			    (i != 0 && !source_journal_kill_after(item.record,
			    parsed.kills.back().record))) {
				errno = EPROTO;
				return (false);
			}
			offset += 24;
			parsed.kills.push_back(item);
		}
		for (uint16_t i = 0; i < cleanup_count; i++) {
			if (tail - offset < 16 || wire[offset] != 3 ||
			    (wire[offset + 1] != 'a' &&
			    wire[offset + 1] != 'g') ||
			    memcmp(wire + offset + 2, zero6,
			    sizeof(zero6)) != 0) {
				errno = EPROTO;
				return (false);
			}
			source_journal_cleanup item{};
			item.record.vmid = ticket.source_vmid;
			item.record.epoch = ticket.source_epoch;
			item.record.delivery_id = dtraced_wire_get_u64(
			    wire + offset + 8);
			item.phase = (char)wire[offset + 1];
			if (item.record.delivery_id == 0 ||
			    (i != 0 && item.record.delivery_id <=
			    parsed.cleanups.back().record.delivery_id)) {
				errno = EPROTO;
				return (false);
			}
			offset += 16;
			parsed.cleanups.push_back(item);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	if (offset != tail) {
		errno = EPROTO;
		return (false);
	}
	result = std::move(parsed);
	return (true);
}

/* A reserved ticket binds the complete source transfer digest. Decode both
 * HJM1 children before exposing either result to a destination transaction.
 * This is deliberately read-only: it grants no journal or execution lease. */
bool
dir::decode_source_journal_transfer_wire(const durable_handoff &reserved,
    const std::vector<uint8_t> &wire, source_journal_cut &journal,
    host_ingress_transfer_bundle &ingress)
{
	journal = {};
	ingress = {};
	if (!handoff_valid(reserved, handoff_phase::reserved) ||
	    wire.size() < DTRACED_TRANSFER_HEADER_SIZE +
	    DTRACED_TRANSFER_DIGEST_SIZE ||
	    CRYPTO_memcmp(wire.data() + wire.size() -
	    DTRACED_TRANSFER_DIGEST_SIZE, reserved.transfer_digest.data(),
	    reserved.transfer_digest.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	std::vector<uint8_t> manifest, ingress_manifest, archive;
	std::vector<std::vector<uint8_t>> frames, ingress_frames;
	if (!dtraced_transfer_wire_unpack(wire.data(), wire.size(),
	    reserved.token.data(), manifest, frames) ||
	    !dtraced_transfer_journal_split(reserved.token.data(), manifest,
	    frames, ingress_manifest, ingress_frames, archive))
		return (false);
	if (archive.empty()) {
		errno = EPROTO;
		return (false);
	}
	durable_handoff source = reserved;
	source.checkpoint_digest.fill(0);
	source.destination_vmid = 0;
	source.destination_epoch = 0;
	source_journal_cut parsed_journal;
	host_ingress_transfer_bundle parsed_ingress;
	if (!decode_source_journal_archive(source, archive.data(),
	    archive.size(), parsed_journal) ||
	    (!ingress_manifest.empty() &&
	    !decode_host_ingress_transfer_bundle(source, ingress_manifest,
	    ingress_frames, parsed_ingress)))
		return (false);
	journal = std::move(parsed_journal);
	ingress = std::move(parsed_ingress);
	return (true);
}

/* The HCR1 execution receipt is useful for transfer only while its accepted
 * ingress ELF is still available and has the exact bare-ELF digest recorded
 * at upload. The VM envelope is checked against the journal lifetime before
 * the ELF bytes are hashed; no host address or untrusted length is followed. */
int
dir::verify_host_ingress_payload(const durable_delivery &record,
    std::vector<uint8_t> *verified_copy)
{
	if (verified_copy != nullptr)
		verified_copy->clear();
	if (record.scope != 3 ||
	    (record.journal_version != 4 && record.journal_version != 5) ||
	    !delivery_record_valid(record)) {
		errno = EINVAL;
		return (-1);
	}
	char name[70];
	identified_spool_name(record.program_id.data(),
	    record.source_id.data(), name);
	int fd = openat(this->dirfd, name,
	    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat before{}, after{}, named{};
	bool ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
	    before.st_nlink == 1 && before.st_uid == geteuid() &&
	    (before.st_mode & 077) == 0 &&
	    before.st_size >= (off_t)(HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 1 + 4) &&
	    (uintmax_t)before.st_size <=
	    max_request_bytes - DTRACED_MSGHDRSIZE;
	auto read_exact = [&](void *out, size_t size, off_t offset) {
		size_t done = 0;
		while (done < size) {
			ssize_t n = pread(fd, (uint8_t *)out + done, size - done,
			    offset + (off_t)done);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				return (false);
			done += (size_t)n;
		}
		return (true);
	};
	uint8_t prefix[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE]{};
	hypertrace_vm_envelope envelope{};
	size_t elf_offset = 0;
	if (ok)
		ok = read_exact(prefix, sizeof(prefix), 0);
	if (ok) {
		hypertrace_envelope_decode(&envelope, prefix);
		ok = envelope.magic == HYPERTRACE_ENVELOPE_MAGIC &&
		    envelope.version == HYPERTRACE_ENVELOPE_VERSION &&
		    envelope.vmid == record.vmid &&
		    envelope.epoch == record.epoch &&
		    envelope.name_length != 0 &&
		    envelope.name_length < DTRACED_FDIDENTLEN &&
		    envelope.name_length <= (uintmax_t)before.st_size -
		    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE - 4;
		if (ok)
			elf_offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
			    (size_t)envelope.name_length;
	}
	uint8_t elf_magic[4]{};
	if (ok)
		ok = read_exact(elf_magic, sizeof(elf_magic),
		    (off_t)elf_offset) &&
		    memcmp(elf_magic, "\177ELF", sizeof(elf_magic)) == 0;
	std::vector<uint8_t> captured;
	if (ok && verified_copy != nullptr) {
		try {
			captured.resize((size_t)before.st_size);
		} catch (const std::bad_alloc &) {
			(void)close(fd);
			errno = ENOMEM;
			return (-1);
		}
		ok = read_exact(captured.data(), elf_offset, 0) &&
		    memcmp(captured.data(), prefix, sizeof(prefix)) == 0;
	}
	EVP_MD_CTX *ctx = ok ? EVP_MD_CTX_new() : nullptr;
	if (ctx == nullptr)
		ok = false;
	if (ok)
		ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
	uint8_t block[65536], digest[32]{};
	for (off_t pos = (off_t)elf_offset; ok && pos < before.st_size;) {
		size_t chunk = std::min(sizeof(block),
		    (size_t)(before.st_size - pos));
		uint8_t *destination = verified_copy != nullptr ?
		    captured.data() + (size_t)pos : block;
		if (!read_exact(destination, chunk, pos) ||
		    EVP_DigestUpdate(ctx, destination, chunk) != 1) {
			ok = false;
			break;
		}
		pos += (off_t)chunk;
	}
	unsigned length = 0;
	if (ok)
		ok = EVP_DigestFinal_ex(ctx, digest, &length) == 1 &&
		    length == sizeof(digest) &&
		    memcmp(digest, record.payload_digest.data(),
		    sizeof(digest)) == 0 &&
		    fsync(fd) == 0 && fstat(fd, &after) == 0 &&
		    fstatat(this->dirfd, name, &named,
		    AT_SYMLINK_NOFOLLOW) == 0 &&
		    before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
		    before.st_size == after.st_size &&
		    before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
		    before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
		    before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
		    before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
		    named.st_dev == before.st_dev && named.st_ino == before.st_ino;
	EVP_MD_CTX_free(ctx);
	if (close(fd) != 0)
		ok = false;
	if (!ok) {
		errno = EPROTO;
		return (-1);
	}
	if (verified_copy != nullptr)
		verified_copy->swap(captured);
	return (1);
}
/* HT-C END */

/* Enumerate durable recipients after source admission is permanently closed.
 * Never infer retirement from a missing live socket or from a processing ACK.
 * Hold the outbound cut before taking inbound locks, as ordinary ingress does.
 * The caller releases these locks before sending any collector-stop RPC. */
int
dir::fresh_session_consumers(dir &outbound, const durable_session_stop &stop,
    std::vector<host_ingress_program_evidence> &result)
{
	struct stat inbound_stat, outbound_stat;
	if (&outbound == this || !fresh_stop_valid(stop)) {
		errno = EINVAL;
		return (-1);
	}
	if (fstat(this->dirfd, &inbound_stat) != 0 ||
	    fstat(outbound.dirfd, &outbound_stat) != 0)
		return (-1);
	if (inbound_stat.st_dev == outbound_stat.st_dev &&
	    inbound_stat.st_ino == outbound_stat.st_ino) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard source(outbound.publishmtx);
	handoff_process_lock process_lock(outbound.dirfd);
	if (!process_lock.held())
		return (-1);
	durable_session_stop bound{};
	int present = fresh_stop_read_at(outbound.dirfd, stop.vmid, stop.epoch, bound);
	if (present != 1 || fresh_stop_bytes(bound) != fresh_stop_bytes(stop)) {
		if (present >= 0)
			errno = present == 0 ? EBUSY : ESTALE;
		return (-1);
	}
	if (fsync(outbound.dirfd) != 0)
		return (-1);
	std::vector<durable_delivery_state> ingress;
	if (!list_deliveries(ingress))
		return (-1);
	for (const auto &entry : ingress) {
		const auto &record = entry.record;
		if (record.scope == 3 && record.vmid == stop.vmid &&
		    record.epoch == stop.epoch && record.journal_version != 4) {
			/* Preserved experimental continuity recipients use HCR2.
			 * Do not silently omit them from a fresh-session stop. */
			errno = ENOTSUP;
			return (-1);
		}
	}
	std::vector<durable_consumer_receipt_state> receipts;
	if (!list_consumer_receipts(receipts))
		return (-1);
	try {
		/* HCB1 precedes its HCR1 members. A failed publication or interrupted
		 * recovery must not turn an incomplete census into a completed stop.
		 * Keep the source cut while comparing canonical receipt identities;
		 * never repair or omit missing evidence as part of the stop query. */
		std::unordered_set<std::string> observed;
		for (const auto &entry : receipts) {
			if (entry.record.ingress.vmid != stop.vmid ||
			    entry.record.ingress.epoch != stop.epoch)
				continue;
			const auto wire = consumer_receipt_bytes(entry.record);
			observed.emplace((const char *)wire.data(), wire.size());
		}
		for (const auto &entry : ingress) {
			if (entry.record.scope != 3 || entry.record.vmid != stop.vmid ||
			    entry.record.epoch != stop.epoch)
				continue;
			std::vector<durable_consumer_receipt> fixed;
			if (consumer_cohort(entry.record, {}, fixed) < 0)
				return (-1);
			for (const auto &member : fixed) {
				const auto wire = consumer_receipt_bytes(member);
				if (observed.find(std::string((const char *)wire.data(),
				    wire.size())) == observed.end()) {
					errno = EBUSY;
					return (-1);
				}
			}
		}
		std::vector<host_ingress_program_evidence> candidate;
		std::vector<std::array<uint8_t, 24>> lifetimes;
		std::unordered_map<std::string, size_t> owners;
		for (const auto &entry : receipts) {
			if (entry.record.ingress.vmid != stop.vmid ||
			    entry.record.ingress.epoch != stop.epoch)
				continue;
			host_ingress_program_evidence proof{};
			proof.recipient = entry.record;
			int pinned = consumer_program_status(entry.record,
			    proof.owner_wire, proof.program_digest);
			if (pinned != 1) {
				if (pinned == 0)
					errno = EBUSY;
				return (-1);
			}
			std::array<uint8_t, 24> lifetime{};
			if (consumer_handle_status(entry.record, lifetime) < 0)
				return (-1);
			std::string key((const char *)proof.owner_wire.data(),
			    proof.owner_wire.size());
			auto [position, inserted] = owners.emplace(key, candidate.size());
			if (inserted) {
				candidate.push_back(proof);
				lifetimes.push_back(lifetime);
			} else if (candidate[position->second].program_digest !=
			    proof.program_digest || lifetimes[position->second] != lifetime) {
				/* One owner-level stop cannot cover inconsistent registered
				 * handle lifetimes (including legacy/modern mixtures). */
				errno = EPROTO;
				return (-1);
			}
		}
		if (fsync(this->dirfd) != 0)
			return (-1);
		result.swap(candidate);
		return (result.empty() ? 0 : 1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

static int fresh_stop_completed_at(int, const durable_session_stop &);

int
dir::fresh_consumer_stop_receipt(dir &outbound, const durable_session_stop &stop,
    const host_ingress_program_evidence &proof, bool publish)
{
	struct stat inbound_stat, outbound_stat;
	if (&outbound == this || !fresh_stop_valid(stop) ||
	    proof.recipient.ingress.scope != 3 ||
	    proof.recipient.ingress.journal_version != 4 ||
	    proof.recipient.ingress.vmid != stop.vmid ||
	    proof.recipient.ingress.epoch != stop.epoch) {
		errno = EINVAL;
		return (-1);
	}
	if (fstat(this->dirfd, &inbound_stat) != 0 ||
	    fstat(outbound.dirfd, &outbound_stat) != 0)
		return (-1);
	if (inbound_stat.st_dev == outbound_stat.st_dev &&
	    inbound_stat.st_ino == outbound_stat.st_ino) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard journal(outbound.publishmtx);
	handoff_process_lock process_lock(outbound.dirfd);
	if (!process_lock.held())
		return (-1);
	/* The coordinator audits the complete census once per step. Verify this
	 * exact immutable recipient directly instead of rescanning all recipients
	 * for every already-completed owner. */
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	int pinned = consumer_program_status(proof.recipient, owner, program);
	if (pinned != 1) {
		if (pinned == 0)
			errno = ESTALE;
		return (-1);
	}
	if (owner != proof.owner_wire || program != proof.program_digest) {
		errno = ESTALE;
		return (-1);
	}
	/* A completed stop supersedes per-owner ACKs. Do not recreate them
	 * after retirement; still validate the immutable recipient above. */
	int completed = fresh_stop_completed_at(outbound.dirfd, stop);
	if (completed != 0)
		return (completed);
	std::array<uint8_t, 224> wire{};
	const auto fence = fresh_stop_bytes(stop);
	memcpy(wire.data(), "FSA1", 4);
	memcpy(wire.data() + 4, fence.data(), fence.size());
	memcpy(wire.data() + 84, proof.owner_wire.data(), 76);
	memcpy(wire.data() + 160, proof.program_digest.data(), 32);
	SHA256(wire.data(), 192, wire.data() + 192);
	char name[80];
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".fresh-ack.", 11);
	for (size_t i = 0; i < 32; i++) {
		name[11 + 2 * i] = hex[wire[192 + i] >> 4];
		name[12 + 2 * i] = hex[wire[192 + i] & 15];
	}
	name[75] = '\0';
	durable_session_stop bound{};
	int present = fresh_stop_read_at(outbound.dirfd, stop.vmid, stop.epoch, bound);
	if (present != 1 || fresh_stop_bytes(bound) != fence) {
		if (present >= 0)
			errno = ESTALE;
		return (-1);
	}
	int fd = openat(outbound.dirfd, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd >= 0) {
		std::array<uint8_t, 224> saved{};
		struct stat sb;
		int error = fstat(fd, &sb) != 0 ? errno : 0;
		if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
		    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
		    sb.st_size != (off_t)saved.size()))
			error = EPROTO;
		for (size_t offset = 0; error == 0 && offset < saved.size();) {
			ssize_t n = pread(fd, saved.data() + offset,
			    saved.size() - offset, offset);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				error = n < 0 ? errno : EPROTO;
			else
				offset += (size_t)n;
		}
		if (close(fd) != 0 && error == 0)
			error = errno;
		if (error == 0 && saved != wire)
			error = EPROTO;
		if (error == 0 && fsync(outbound.dirfd) != 0)
			error = errno;
		if (error != 0)
			errno = error;
		return (error == 0 ? 1 : -1);
	}
	if (errno != ENOENT)
		return (-1);
	if (!publish)
		return (0);
	fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	hypertrace_epoch_gate gate{};
	int error = source_gate_query_fd(fd, stop.vmid, stop.epoch, gate) != 0 ? errno : 0;
	if (error == 0 && (gate.suspended != 1 ||
	    memcmp(gate.token, stop.token.data(), 16) != 0))
		error = EBUSY;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && !handoff_publish_at(outbound.dirfd, name,
	    wire.data(), wire.size()))
		error = errno;
	if (error != 0)
		errno = error;
	return (error == 0 ? 1 : -1);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* HTM1 is a canonical, bounded description of accepted ingress at a source
 * cut. It carries exact HTD4 and HCR1 identities and terminal outcomes, not
 * ELF contents or live DTrace enablement. The caller holds the outbound
 * handoff lock; source uploads take that lock before accepting an HTD4. */
int
dir::host_ingress_transfer_manifest(const durable_handoff &ticket,
    std::vector<uint8_t> &result)
{
	result.clear();
	if (!handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (-1);
	}
	std::vector<durable_delivery_state> ingress;
	if (!list_deliveries(ingress))
		return (-1);
	std::vector<durable_delivery> selected;
	try {
		for (const auto &entry : ingress) {
			if (entry.record.scope != 3 ||
			    entry.record.vmid != ticket.source_vmid ||
			    entry.record.epoch != ticket.source_epoch)
				continue;
			if (entry.phase == delivery_phase::pending) {
				errno = EBUSY;
				return (-1);
			}
			if (entry.phase != delivery_phase::accepted) {
				errno = EPROTO;
				return (-1);
			}
			selected.push_back(entry.record);
		}
		std::sort(selected.begin(), selected.end(),
		    [](const auto &a, const auto &b) {
			return (a.session_id < b.session_id ||
			    (a.session_id == b.session_id &&
			    a.delivery_id < b.delivery_id));
		    });
		if (selected.empty())
			return (0);
		if (selected.size() > consumer_receipt_limit) {
			errno = E2BIG;
			return (-1);
		}
		for (size_t i = 1; i < selected.size(); i++)
			if (selected[i - 1].session_id == selected[i].session_id &&
			    selected[i - 1].delivery_id == selected[i].delivery_id) {
				errno = EPROTO;
				return (-1);
			}
		std::vector<uint8_t> wire(50, 0);
		memcpy(wire.data(), "HTM1", 4);
		memcpy(wire.data() + 4, ticket.token.data(), 16);
		memcpy(wire.data() + 20, ticket.source_session.data(), 16);
		dtraced_wire_put_u16(wire.data() + 36, ticket.source_vmid);
		dtraced_wire_put_u64(wire.data() + 38, ticket.source_epoch);
		dtraced_wire_put_u32(wire.data() + 46, (uint32_t)selected.size());
		auto append = [&](const uint8_t *bytes, size_t length) {
			if (length > max_request_bytes - 32 - wire.size()) {
				errno = E2BIG;
				return (false);
			}
			wire.insert(wire.end(), bytes, bytes + length);
			return (true);
		};
		for (const auto &delivery : selected) {
			std::vector<durable_consumer_receipt> cohort;
			int present = consumer_cohort(delivery, {}, cohort);
			if (present < 0)
				return (-1);
			if (present == 0) {
				errno = EBUSY;
				return (-1);
			}
			const auto delivery_wire = delivery_record_bytes(delivery);
			if (!append(delivery_wire.data(), 143))
				return (-1);
			uint8_t count[4];
			dtraced_wire_put_u32(count, (uint32_t)cohort.size());
			if (!append(count, sizeof(count)))
				return (-1);
			for (const auto &member : cohort) {
				durable_consumer_receipt_state receipt{};
				int found = consumer_receipt_exact(
				    delivery.session_id, delivery.delivery_id,
				    member.consumer_session, member.consumer_uid,
				    member.consumer_pid, receipt);
				if (found < 0)
					return (-1);
				if (found != 1 ||
				    (receipt.phase !=
				    consumer_receipt_phase::executed_no_derived &&
				    receipt.phase !=
				    consumer_receipt_phase::executed_derived)) {
					errno = EBUSY;
					return (-1);
				}
				const auto member_wire =
				    consumer_receipt_bytes(receipt.record);
				uint8_t phase = (uint8_t)receipt.phase;
				if (!append(member_wire.data(), member_wire.size()) ||
				    !append(&phase, 1))
					return (-1);
			}
			int verified = verify_host_ingress_payload(delivery);
			if (verified < 0)
				return (-1);
			if (verified == 0) {
				errno = EBUSY;
				return (-1);
			}
		}
		uint8_t digest[32];
		(void)SHA256(wire.data(), wire.size(), digest);
		if (!append(digest, sizeof(digest)))
			return (-1);
		if (!validate_host_ingress_transfer_manifest(ticket, wire))
			return (-1);
		result.swap(wire);
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

bool
dir::host_ingress_transfer_audit_locked(dir &outbound)
{
	std::vector<durable_derived_claim> claims;
	std::vector<durable_consumer_receipt_state> receipts;
	std::vector<durable_delivery_state> ingress, outbound_deliveries;
	return (list_derived_claims_at(outbound.dirfd, claims) &&
	    this->list_consumer_receipts(receipts) &&
	    this->list_deliveries(ingress) &&
	    list_deliveries_at(outbound.dirfd, outbound_deliveries) &&
	    this->audit_derived_claims(outbound, claims, receipts, ingress,
	    false, &outbound_deliveries));
}

int
dir::host_ingress_transfer_snapshot(const durable_handoff &ticket,
    std::vector<uint8_t> &result)
{
	result.clear();
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    this->state->outbounddir == this) {
		errno = EINVAL;
		return (-1);
	}
	dir &outbound = *this->state->outbounddir;
	std::lock_guard source(outbound.publishmtx);
	handoff_process_lock process_lock(outbound.dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(outbound.dirfd, ticket.token, current);
	if (phase < 0)
		return (-1);
	if (phase != 0 && (phase != (int)handoff_phase::prepared ||
	    !handoff_same_source(current, ticket))) {
		errno = EBUSY;
		return (-1);
	}
	if (phase == 0) {
		int source_phase = handoff_source_state_at(outbound.dirfd,
		    ticket.source_vmid, ticket.source_epoch, current);
		if (source_phase < 0)
			return (-1);
		if (source_phase != 0) {
			errno = EBUSY;
			return (-1);
		}
	}
	int present = this->host_ingress_transfer_manifest(ticket, result);
	if (present <= 0)
		return (present);
	if (!this->host_ingress_transfer_audit_locked(outbound)) {
		result.clear();
		return (-1);
	}
	return (1);
}

bool
dir::validate_host_ingress_transfer_manifest(const durable_handoff &ticket,
    const std::vector<uint8_t> &wire,
    std::vector<host_ingress_transfer_entry> *decoded)
{
	if (decoded != nullptr)
		decoded->clear();
	const size_t tail = wire.size() >= 32 ? wire.size() - 32 : 0;
	uint8_t digest[32];
	if (!handoff_valid(ticket, handoff_phase::prepared) ||
	    wire.size() < 50 + 143 + 4 + 158 + 1 + 32 ||
	    wire.size() > max_request_bytes ||
	    memcmp(wire.data(), "HTM1", 4) != 0 ||
	    memcmp(wire.data() + 4, ticket.token.data(), 16) != 0 ||
	    memcmp(wire.data() + 20, ticket.source_session.data(), 16) != 0 ||
	    dtraced_wire_get_u16(wire.data() + 36) != ticket.source_vmid ||
	    dtraced_wire_get_u64(wire.data() + 38) != ticket.source_epoch ||
	    SHA256(wire.data(), tail, digest) == nullptr ||
	    memcmp(digest, wire.data() + tail, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	uint32_t count = dtraced_wire_get_u32(wire.data() + 46);
	if (count == 0 || count > consumer_receipt_limit) {
		errno = EPROTO;
		return (false);
	}
	size_t offset = 50;
	std::array<uint8_t, 16> prior_session{};
	uint64_t prior_id = 0;
	std::vector<host_ingress_transfer_entry> parsed;
	for (uint32_t i = 0; i < count; i++) {
		if (tail - offset < 147) {
			errno = EPROTO;
			return (false);
		}
		const uint8_t *d = wire.data() + offset;
		durable_delivery delivery{};
		memcpy(delivery.session_id.data(), d + 4, 16);
		delivery.delivery_id = dtraced_wire_get_u64(d + 20);
		delivery.vmid = dtraced_wire_get_u16(d + 28);
		delivery.epoch = dtraced_wire_get_u64(d + 30);
		memcpy(delivery.program_id.data(), d + 38, 16);
		memcpy(delivery.source_id.data(), d + 54, 16);
		delivery.peer_uid = dtraced_wire_get_u32(d + 70);
		delivery.peer_pid = dtraced_wire_get_u32(d + 74);
		delivery.scope = d[78];
		delivery.journal_version = 4;
		memcpy(delivery.payload_digest.data(), d + 79, 32);
		const auto expected_delivery = delivery_record_bytes(delivery);
		if (memcmp(d, expected_delivery.data(), 143) != 0 ||
		    !delivery_record_valid(delivery) ||
		    delivery.vmid != ticket.source_vmid ||
		    delivery.epoch != ticket.source_epoch ||
		    (i != 0 && !(prior_session < delivery.session_id ||
		    (prior_session == delivery.session_id &&
		    prior_id < delivery.delivery_id)))) {
			errno = EPROTO;
			return (false);
		}
		prior_session = delivery.session_id;
		prior_id = delivery.delivery_id;
		offset += 143;
		uint32_t recipients = dtraced_wire_get_u32(wire.data() + offset);
		offset += 4;
		if (recipients == 0 || recipients > consumer_receipt_limit ||
		    recipients > (tail - offset) / 159) {
			errno = EPROTO;
			return (false);
		}
		host_ingress_transfer_entry parsed_entry{};
		if (decoded != nullptr)
			parsed_entry.ingress = delivery;
		std::array<uint8_t, 16> prior_member{};
		for (uint32_t j = 0; j < recipients; j++) {
			const uint8_t *r = wire.data() + offset;
			durable_consumer_receipt member{};
			member.ingress = delivery;
			memcpy(member.consumer_session.data(), r + 102, 16);
			member.consumer_uid = dtraced_wire_get_u32(r + 118);
			member.consumer_pid = dtraced_wire_get_u32(r + 122);
			const auto expected = consumer_receipt_bytes(member);
			if (!consumer_receipt_valid(member) ||
			    memcmp(r, expected.data(), expected.size()) != 0 ||
			    (j != 0 && !(prior_member < member.consumer_session)) ||
			    (r[158] != 'N' && r[158] != 'D')) {
				errno = EPROTO;
				return (false);
			}
			if (decoded != nullptr) {
				try {
					parsed_entry.recipients.push_back(
					    {member, (consumer_receipt_phase)r[158]});
				} catch (const std::bad_alloc &) {
					errno = ENOMEM;
					return (false);
				}
			}
			prior_member = member.consumer_session;
			offset += 159;
		}
		if (decoded != nullptr) {
			try {
				parsed.push_back(std::move(parsed_entry));
			} catch (const std::bad_alloc &) {
				errno = ENOMEM;
				return (false);
			}
		}
	}
	if (offset != tail) {
		errno = EPROTO;
		return (false);
	}
	if (decoded != nullptr)
		decoded->swap(parsed);
	return (true);
}

/* Validate a copied ingress frame before staging it at a destination. The
 * source VM name is untrusted transport metadata; destination admission must
 * replace it with the live VMM-attested name. */
bool
dir::validate_host_ingress_transfer_payload(const durable_delivery &record,
    const std::vector<uint8_t> &bytes)
{
	if (record.scope != 3 ||
	    (record.journal_version != 4 && record.journal_version != 5) ||
	    !delivery_record_valid(record) ||
	    bytes.size() < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 1 + 4 ||
	    bytes.size() > max_request_bytes - DTRACED_MSGHDRSIZE) {
		errno = EPROTO;
		return (false);
	}
	hypertrace_vm_envelope envelope{};
	hypertrace_envelope_decode(&envelope, bytes.data());
	if (envelope.magic != HYPERTRACE_ENVELOPE_MAGIC ||
	    envelope.version != HYPERTRACE_ENVELOPE_VERSION ||
	    envelope.vmid != record.vmid || envelope.epoch != record.epoch ||
	    envelope.name_length == 0 ||
	    envelope.name_length >= DTRACED_FDIDENTLEN ||
	    envelope.name_length > bytes.size() -
	    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE - 4) {
		errno = EPROTO;
		return (false);
	}
	size_t elf_offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
	    (size_t)envelope.name_length;
	uint8_t digest[32];
	if (memcmp(bytes.data() + elf_offset, "\177ELF", 4) != 0 ||
	    SHA256(bytes.data() + elf_offset, bytes.size() - elf_offset,
	    digest) == nullptr ||
	    memcmp(digest, record.payload_digest.data(), sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	return (true);
}

/* HTP1 is one ticket-bound accepted ingress frame. HTM1 fixes the ordered
 * recipient set; each matching HTP1 carries the original VM envelope and
 * ELF bytes. Its digest detects torn copies, not an unauthenticated peer. */
static constexpr size_t host_transfer_frame_header_size = 167;
static constexpr size_t host_transfer_frame_tail_size = 32;

static bool
host_transfer_frame_identity_valid(const durable_handoff &ticket,
    const durable_delivery &record)
{
	return (handoff_valid(ticket, handoff_phase::prepared) &&
	    record.scope == 3 &&
	    record.journal_version == 4 && delivery_record_valid(record) &&
	    record.vmid == ticket.source_vmid &&
	    record.epoch == ticket.source_epoch);
}

bool
dir::encode_host_ingress_transfer_frame(const durable_handoff &ticket,
    const durable_delivery &record, const std::vector<uint8_t> &bytes,
    std::vector<uint8_t> &frame)
{
	frame.clear();
	if (!host_transfer_frame_identity_valid(ticket, record) ||
	    !validate_host_ingress_transfer_payload(record, bytes)) {
		errno = EINVAL;
		return (false);
	}
	try {
		std::vector<uint8_t> wire(host_transfer_frame_header_size +
		    bytes.size() + host_transfer_frame_tail_size, 0);
		memcpy(wire.data(), "HTP1", 4);
		memcpy(wire.data() + 4, ticket.token.data(), ticket.token.size());
		const auto delivery = delivery_record_bytes(record);
		memcpy(wire.data() + 20, delivery.data(), 143);
		dtraced_wire_put_u32(wire.data() + 163, (uint32_t)bytes.size());
		memcpy(wire.data() + host_transfer_frame_header_size,
		    bytes.data(), bytes.size());
		(void)SHA256(wire.data(), wire.size() - host_transfer_frame_tail_size,
		    wire.data() + wire.size() - host_transfer_frame_tail_size);
		frame.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

bool
dir::decode_host_ingress_transfer_frame(const durable_handoff &ticket,
    const durable_delivery &record, const std::vector<uint8_t> &frame,
    std::vector<uint8_t> *payload)
{
	if (payload != nullptr)
		payload->clear();
	if (!host_transfer_frame_identity_valid(ticket, record) ||
	    frame.size() < host_transfer_frame_header_size +
	    host_transfer_frame_tail_size ||
	    frame.size() > max_request_bytes - DTRACED_MSGHDRSIZE +
	    host_transfer_frame_header_size + host_transfer_frame_tail_size ||
	    memcmp(frame.data(), "HTP1", 4) != 0 ||
	    memcmp(frame.data() + 4, ticket.token.data(), ticket.token.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	const auto delivery = delivery_record_bytes(record);
	const size_t length = dtraced_wire_get_u32(frame.data() + 163);
	if (memcmp(frame.data() + 20, delivery.data(), 143) != 0 ||
	    length > max_request_bytes - DTRACED_MSGHDRSIZE ||
	    frame.size() != host_transfer_frame_header_size + length +
	    host_transfer_frame_tail_size) {
		errno = EPROTO;
		return (false);
	}
	uint8_t digest[32];
	if (SHA256(frame.data(), frame.size() - host_transfer_frame_tail_size,
	    digest) == nullptr ||
	    memcmp(digest, frame.data() + frame.size() -
	    host_transfer_frame_tail_size, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::vector<uint8_t> captured(
		    frame.begin() + host_transfer_frame_header_size,
		    frame.end() - host_transfer_frame_tail_size);
		if (!validate_host_ingress_transfer_payload(record, captured))
			return (false);
		if (payload != nullptr)
			payload->swap(captured);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* Decode the complete ordered source set before exposing any imported ELF.
 * An individual valid HTP1 cannot prove that its HTM1 siblings arrived. */
bool
dir::decode_host_ingress_transfer_bundle(const durable_handoff &ticket,
    const std::vector<uint8_t> &manifest,
    const std::vector<std::vector<uint8_t>> &frames,
    host_ingress_transfer_bundle &bundle)
{
	bundle.entries.clear();
	bundle.source_programs.clear();
	bundle.payloads.clear();
	host_ingress_transfer_bundle parsed;
	std::vector<uint8_t> nested;
	const std::vector<uint8_t> *source_manifest = &manifest;
	if (manifest.size() >= 4 &&
	    memcmp(manifest.data(), "HTM2", 4) == 0) {
		if (!validate_host_ingress_program_manifest(ticket, manifest,
		    &nested, &parsed.source_programs))
			return (false);
		source_manifest = &nested;
	}
	if (!validate_host_ingress_transfer_manifest(ticket, *source_manifest,
	    &parsed.entries))
		return (false);
	if (frames.size() != parsed.entries.size()) {
		errno = EPROTO;
		return (false);
	}
	try {
		parsed.payloads.reserve(frames.size());
		for (size_t i = 0; i < frames.size(); i++) {
			std::vector<uint8_t> payload;
			if (!decode_host_ingress_transfer_frame(ticket,
			    parsed.entries[i].ingress, frames[i], &payload))
				return (false);
			parsed.payloads.push_back(std::move(payload));
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	bundle.entries.swap(parsed.entries);
	bundle.source_programs.swap(parsed.source_programs);
	bundle.payloads.swap(parsed.payloads);
	return (true);
}

bool
dir::decode_host_ingress_transfer_wire(const durable_handoff &ticket,
    const std::vector<uint8_t> &wire, host_ingress_transfer_bundle &bundle)
{
	bundle = {};
	if (!handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (false);
	}
	std::vector<uint8_t> manifest;
	std::vector<std::vector<uint8_t>> frames;
	if (!dtraced_transfer_wire_unpack(wire.data(), wire.size(),
	    ticket.token.data(), manifest, frames))
		return (false);
	if (manifest.empty())
		return (true);
	return (decode_host_ingress_transfer_bundle(ticket, manifest, frames,
	    bundle));
}

bool
dir::plan_host_ingress_destination(const durable_handoff &reserved,
    const std::vector<uint8_t> &manifest,
    const std::vector<std::vector<uint8_t>> &frames,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    host_ingress_destination_plan &plan)
{
	plan.source_entries.clear();
	plan.source_programs.clear();
	plan.deliveries.clear();
	plan.payloads.clear();
	if (!handoff_valid(reserved, handoff_phase::reserved) ||
	    destination_session == std::array<uint8_t, 16>{} ||
	    destination_session == reserved.source_session ||
	    destination_uid == UINT32_MAX || destination_pid <= 1 ||
	    destination_name.empty() ||
	    destination_name.size() >= DTRACED_FDIDENTLEN ||
	    destination_name.find('\0') != std::string::npos) {
		errno = EINVAL;
		return (false);
	}
	/* The exported HTM1 or HTM2 plus HTP1 set describes the source cut. The
	 * reserved ticket adds destination authority without changing that set. */
	durable_handoff source = reserved;
	source.checkpoint_digest.fill(0);
	source.destination_vmid = 0;
	source.destination_epoch = 0;
	host_ingress_transfer_bundle decoded;
	if (!decode_host_ingress_transfer_bundle(source, manifest, frames,
	    decoded))
		return (false);
	host_ingress_destination_plan candidate;
	try {
		candidate.deliveries.reserve(decoded.entries.size());
		candidate.payloads.reserve(decoded.entries.size());
		for (size_t i = 0; i < decoded.entries.size(); i++) {
			const auto &old_bytes = decoded.payloads[i];
			hypertrace_vm_envelope old_envelope{};
			hypertrace_envelope_decode(&old_envelope,
			    old_bytes.data());
			const size_t elf_offset =
			    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
			    (size_t)old_envelope.name_length;
			const size_t elf_length = old_bytes.size() - elf_offset;
			const size_t new_size = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
			    destination_name.size() + elf_length;
			if (new_size > max_request_bytes - DTRACED_MSGHDRSIZE) {
				errno = E2BIG;
				return (false);
			}
			durable_delivery delivery = decoded.entries[i].ingress;
			delivery.session_id = destination_session;
			delivery.vmid = reserved.destination_vmid;
			delivery.epoch = reserved.destination_epoch;
			delivery.peer_uid = destination_uid;
			delivery.peer_pid = destination_pid;
			delivery.journal_version = 5;
			delivery.handoff_token = reserved.token;
			delivery.source_session = decoded.entries[i].ingress.session_id;
			delivery.payload_vmid = decoded.entries[i].ingress.vmid;
			delivery.payload_epoch = decoded.entries[i].ingress.epoch;
			if (!delivery_record_valid(delivery)) {
				errno = EPROTO;
				return (false);
			}
			std::vector<uint8_t> bytes(new_size);
			hypertrace_vm_envelope envelope = old_envelope;
			envelope.vmid = delivery.vmid;
			envelope.epoch = delivery.epoch;
			envelope.name_length = destination_name.size();
			hypertrace_envelope_encode(bytes.data(), &envelope);
			memcpy(bytes.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
			    destination_name.data(), destination_name.size());
			memcpy(bytes.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
			    destination_name.size(), old_bytes.data() + elf_offset,
			    elf_length);
			if (!validate_host_ingress_transfer_payload(delivery,
			    bytes))
				return (false);
			candidate.deliveries.push_back(delivery);
			candidate.payloads.push_back(std::move(bytes));
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	candidate.source_entries.swap(decoded.entries);
	candidate.source_programs.swap(decoded.source_programs);
	plan.source_entries.swap(candidate.source_entries);
	plan.source_programs.swap(candidate.source_programs);
	plan.deliveries.swap(candidate.deliveries);
	plan.payloads.swap(candidate.payloads);
	return (true);
}

/* HTB1 is an inert, private transfer sidecar. It records the exact source
 * frames and destination attestation used for a plan, but never authorizes
 * a journal entry or a consumer to execute. */
static constexpr size_t host_transfer_stage_header_size = 96;
static constexpr size_t host_transfer_stage_max_size = max_request_bytes;

static bool
host_transfer_stage_name(const std::array<uint8_t, 16> &token, char name[39])
{
	static const char hex[] = "0123456789abcdef";
	if (token == std::array<uint8_t, 16>{}) {
		errno = EINVAL;
		return (false);
	}
	memcpy(name, ".htb1.", 6);
	for (size_t i = 0; i < token.size(); i++) {
		name[6 + i * 2] = hex[token[i] >> 4];
		name[7 + i * 2] = hex[token[i] & 15];
	}
	name[38] = '\0';
	return (true);
}

static bool
source_journal_stage_name(const std::array<uint8_t, 16> &token,
    char name[39])
{
	if (!host_transfer_stage_name(token, name))
		return (false);
	memcpy(name, ".hjb1.", 6);
	return (true);
}

static bool
source_journal_ready_name(const std::array<uint8_t, 16> &token,
    char name[39])
{
	if (!host_transfer_stage_name(token, name))
		return (false);
	memcpy(name, ".hjr1.", 6);
	return (true);
}

static bool
host_transfer_owner_name(const std::array<uint8_t, 16> &token, char name[39])
{
	if (!host_transfer_stage_name(token, name))
		return (false);
	memcpy(name, ".htl1.", 6);
	return (true);
}

static bool
host_transfer_cohort_name(const std::array<uint8_t, 16> &token,
    char name[39])
{
	if (!host_transfer_stage_name(token, name))
		return (false);
	memcpy(name, ".hck1.", 6);
	return (true);
}

static bool
host_transfer_result_name(const std::array<uint8_t, 16> &token,
    char name[39])
{
	if (!host_transfer_stage_name(token, name))
		return (false);
	memcpy(name, ".hrs1.", 6);
	return (true);
}

static bool
host_transfer_promotion_name(const std::array<uint8_t, 16> &token,
    char name[39])
{
	if (!host_transfer_stage_name(token, name))
		return (false);
	memcpy(name, ".hpa1.", 6);
	return (true);
}

static bool
host_transfer_commit_name(const std::array<uint8_t, 16> &token,
    char name[39])
{
	if (!host_transfer_stage_name(token, name))
		return (false);
	memcpy(name, ".hlc1.", 6);
	return (true);
}

static bool
host_transfer_activation_name(const std::array<uint8_t, 16> &token,
    char name[39])
{
	if (!host_transfer_stage_name(token, name))
		return (false);
	memcpy(name, ".hla1.", 6);
	return (true);
}

static bool
host_transfer_outcome_name(const durable_import_consumer_result &record,
    char name[106])
{
	if (!host_transfer_stage_name(record.token, name) ||
	    record.receipt_digest == std::array<uint8_t, 32>{} ||
	    (record.phase != consumer_receipt_phase::no_derived &&
	    record.phase != consumer_receipt_phase::derived &&
	    record.phase != consumer_receipt_phase::executed_no_derived &&
	    record.phase != consumer_receipt_phase::executed_derived)) {
		errno = EINVAL;
		return (false);
	}
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".hro1.", 6);
	name[38] = '.';
	for (size_t i = 0; i < record.receipt_digest.size(); i++) {
		name[39 + i * 2] = hex[record.receipt_digest[i] >> 4];
		name[40 + i * 2] = hex[record.receipt_digest[i] & 15];
	}
	name[103] = '.';
	name[104] = (char)record.phase;
	name[105] = '\0';
	return (true);
}

/* HCK1 is one inert, ticket-bound bundle of the planned HCB2 cohorts. HTL1
 * names the owner set; neither sidecar changes an HTD5 phase or queues a job. */
static bool
host_transfer_cohort_wire(const std::array<uint8_t, 16> &token,
    const uint8_t stage_digest[32], const uint8_t owner_digest[32],
    const std::vector<std::vector<uint8_t>> &cohorts,
    std::vector<uint8_t> &result)
{
	result.clear();
	if (cohorts.empty() || cohorts.size() > consumer_receipt_limit) {
		errno = EPROTO;
		return (false);
	}
	size_t length = 88 + SHA256_DIGEST_LENGTH;
	for (const auto &cohort : cohorts) {
		if (cohort.empty() || cohort.size() > UINT32_MAX ||
		    length > host_transfer_stage_max_size - 4 ||
		    cohort.size() > host_transfer_stage_max_size - length - 4) {
			errno = E2BIG;
			return (false);
		}
		length += 4 + cohort.size();
	}
	try {
		std::vector<uint8_t> wire(length, 0);
		memcpy(wire.data(), "HCK1", 4);
		memcpy(wire.data() + 4, token.data(), 16);
		memcpy(wire.data() + 20, stage_digest, 32);
		memcpy(wire.data() + 52, owner_digest, 32);
		dtraced_wire_put_u32(wire.data() + 84,
		    (uint32_t)cohorts.size());
		size_t offset = 88;
		for (const auto &cohort : cohorts) {
			dtraced_wire_put_u32(wire.data() + offset,
			    (uint32_t)cohort.size());
			offset += 4;
			memcpy(wire.data() + offset, cohort.data(), cohort.size());
			offset += cohort.size();
		}
		if (SHA256(wire.data(), offset, wire.data() + offset) == NULL)
			return (false);
		result.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* HRS1 durably reserves one pending result slot per HCR2 in HCK1 order.
 * Its immutable slots are not outcomes or permission to dispatch a job. */
static bool
host_transfer_result_wire(const std::array<uint8_t, 16> &token,
    const uint8_t cohort_digest[32],
    const host_ingress_destination_plan &plan,
    const std::vector<std::vector<uint8_t>> &cohorts,
    std::vector<uint8_t> &result)
{
	result.clear();
	if (cohorts.empty() || cohorts.size() != plan.deliveries.size()) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::vector<std::array<uint8_t, 32>> ids;
		for (size_t i = 0; i < cohorts.size(); i++) {
			std::vector<durable_import_consumer_receipt> members;
			if (!dir::decode_import_consumer_cohort(
			    plan.deliveries[i], cohorts[i], members))
				return (false);
			if (members.size() > consumer_receipt_limit - ids.size()) {
				errno = E2BIG;
				return (false);
			}
			for (const auto &member : members) {
				std::vector<uint8_t> receipt;
				if (!dir::encode_import_consumer_receipt(member,
				    receipt))
					return (false);
				std::array<uint8_t, 32> digest{};
				if (SHA256(receipt.data(), receipt.size(),
				    digest.data()) == NULL)
					return (false);
				ids.push_back(digest);
			}
		}
		if (ids.empty()) {
			errno = EPROTO;
			return (false);
		}
		std::vector<uint8_t> wire(64 + ids.size() * 33 + 32, 0);
		memcpy(wire.data(), "HRS1", 4);
		memcpy(wire.data() + 4, token.data(), 16);
		memcpy(wire.data() + 20, cohort_digest, 32);
		dtraced_wire_put_u32(wire.data() + 52, (uint32_t)ids.size());
		size_t offset = 64;
		for (const auto &id : ids) {
			memcpy(wire.data() + offset, id.data(), id.size());
			offset += id.size();
			wire[offset++] = 'p';
		}
		if (SHA256(wire.data(), offset, wire.data() + offset) == NULL)
			return (false);
		result.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* HPA1 fixes the ordered HTD5 identities before any phase can change.
 * Publication alone is inert; a later transaction must verify a live owner
 * and create the execution lease before it may accept these deliveries. */
static bool
host_transfer_promotion_wire(const std::array<uint8_t, 16> &token,
    const uint8_t result_digest[32],
    const host_ingress_destination_plan &plan, std::vector<uint8_t> &result)
{
	result.clear();
	if (plan.deliveries.empty() ||
	    plan.deliveries.size() > consumer_receipt_limit ||
	    plan.deliveries.size() > (host_transfer_stage_max_size - 96) / 32) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::vector<uint8_t> wire(64 + plan.deliveries.size() * 32 + 32,
		    0);
		memcpy(wire.data(), "HPA1", 4);
		memcpy(wire.data() + 4, token.data(), 16);
		memcpy(wire.data() + 20, result_digest, 32);
		dtraced_wire_put_u32(wire.data() + 52,
		    (uint32_t)plan.deliveries.size());
		for (size_t i = 0; i < plan.deliveries.size(); i++) {
			const auto &record = plan.deliveries[i];
			if (record.scope != 3 || record.journal_version != 5 ||
			    record.handoff_token != token) {
				errno = EPROTO;
				return (false);
			}
			const auto bytes = delivery_record_bytes(record);
			if (SHA256(bytes.data(), delivery_record_size(record),
			    wire.data() + 64 + i * 32) == NULL)
				return (false);
		}
		if (SHA256(wire.data(), wire.size() - 32,
		    wire.data() + wire.size() - 32) == NULL)
			return (false);
		result.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* HLC1 is published only after every fixed HTD5 reached accepted. It is a
 * crash-recovery commit marker, not yet permission for the watcher to run. */
static std::array<uint8_t, 128>
host_transfer_commit_wire(const durable_handoff &ticket,
    const uint8_t promotion_digest[32], const uint8_t owner_digest[32])
{
	std::array<uint8_t, 128> wire{};
	memcpy(wire.data(), "HLC1", 4);
	memcpy(wire.data() + 4, ticket.token.data(), 16);
	memcpy(wire.data() + 20, promotion_digest, 32);
	memcpy(wire.data() + 52, owner_digest, 32);
	dtraced_wire_put_u16(wire.data() + 84, ticket.destination_vmid);
	dtraced_wire_put_u64(wire.data() + 86, ticket.destination_epoch);
	(void)SHA256(wire.data(), 96, wire.data() + 96);
	return (wire);
}

/* HLA1 records that a committed import passed the guest-applied rekey gate.
 * It is not a recipient outcome: HRS1/HRO1 still decide replay. */
static std::array<uint8_t, 128>
host_transfer_activation_wire(const durable_handoff &ticket,
    const uint8_t commit_digest[32], const uint8_t slots_digest[32])
{
	std::array<uint8_t, 128> wire{};
	memcpy(wire.data(), "HLA1", 4);
	memcpy(wire.data() + 4, ticket.token.data(), 16);
	memcpy(wire.data() + 20, commit_digest, 32);
	memcpy(wire.data() + 52, slots_digest, 32);
	dtraced_wire_put_u16(wire.data() + 84, ticket.destination_vmid);
	dtraced_wire_put_u64(wire.data() + 86, ticket.destination_epoch);
	(void)SHA256(wire.data(), 96, wire.data() + 96);
	return (wire);
}

static bool
host_transfer_stage_encode(const durable_handoff &reserved,
    const std::vector<uint8_t> &manifest,
    const std::vector<std::vector<uint8_t>> &frames,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name, std::vector<uint8_t> &wire,
    host_ingress_destination_plan &plan)
{
	wire.clear();
	if (!dir::plan_host_ingress_destination(reserved, manifest, frames,
	    destination_session, destination_uid, destination_pid,
	    destination_name, plan))
		return (false);
	size_t length = host_transfer_stage_header_size +
	    destination_name.size() + manifest.size() + SHA256_DIGEST_LENGTH;
	if (length > host_transfer_stage_max_size ||
	    frames.size() > UINT32_MAX || manifest.size() > UINT32_MAX) {
		plan = {};
		errno = E2BIG;
		return (false);
	}
	for (const auto &frame : frames) {
		if (frame.size() > UINT32_MAX ||
		    length > host_transfer_stage_max_size - 4 ||
		    frame.size() > host_transfer_stage_max_size - length - 4) {
			plan = {};
			errno = E2BIG;
			return (false);
		}
		length += 4 + frame.size();
	}
	try {
		wire.resize(length, 0);
		memcpy(wire.data(), "HTB1", 4);
		memcpy(wire.data() + 4, reserved.token.data(), 16);
		memcpy(wire.data() + 20,
		    reserved.checkpoint_digest.data(), 32);
		dtraced_wire_put_u16(wire.data() + 52,
		    reserved.destination_vmid);
		dtraced_wire_put_u64(wire.data() + 54,
		    reserved.destination_epoch);
		memcpy(wire.data() + 62, destination_session.data(), 16);
		dtraced_wire_put_u32(wire.data() + 78, destination_uid);
		dtraced_wire_put_u32(wire.data() + 82, destination_pid);
		dtraced_wire_put_u16(wire.data() + 86,
		    (uint16_t)destination_name.size());
		dtraced_wire_put_u32(wire.data() + 88,
		    (uint32_t)frames.size());
		dtraced_wire_put_u32(wire.data() + 92,
		    (uint32_t)manifest.size());
		size_t offset = host_transfer_stage_header_size;
		memcpy(wire.data() + offset, destination_name.data(),
		    destination_name.size());
		offset += destination_name.size();
		memcpy(wire.data() + offset, manifest.data(), manifest.size());
		offset += manifest.size();
		for (const auto &frame : frames) {
			dtraced_wire_put_u32(wire.data() + offset,
			    (uint32_t)frame.size());
			offset += 4;
			memcpy(wire.data() + offset, frame.data(), frame.size());
			offset += frame.size();
		}
		(void)SHA256(wire.data(), offset, wire.data() + offset);
		return (true);
	} catch (const std::bad_alloc &) {
		plan = {};
		wire.clear();
		errno = ENOMEM;
		return (false);
	}
}

static int
host_transfer_stage_read_at(int directory, const char *name,
    std::vector<uint8_t> &wire)
{
	wire.clear();
	int fd = openat(directory, name,
	    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	int error = 0;
	if (fstat(fd, &sb) != 0)
		error = errno;
	else if (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size < (off_t)(host_transfer_stage_header_size +
	    SHA256_DIGEST_LENGTH) ||
	    (uintmax_t)sb.st_size > host_transfer_stage_max_size)
		error = EPROTO;
	if (error == 0) {
		try {
			wire.resize((size_t)sb.st_size);
		} catch (const std::bad_alloc &) {
			error = ENOMEM;
		}
	}
	for (size_t offset = 0; error == 0 && offset < wire.size();) {
		ssize_t n = read(fd, wire.data() + offset, wire.size() - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		wire.clear();
		errno = error;
		return (-1);
	}
	return (1);
}

static int
source_journal_ready_raw_status_locked(int directory,
    const durable_handoff &ticket)
{
	char name[39];
	if (!source_journal_ready_name(ticket.token, name))
		return (-1);
	std::vector<uint8_t> wire;
	return (host_transfer_stage_read_at(directory, name, wire));
}

/* HJB1 stores the exact authenticated HTX1 source member, without granting
 * any destination journal or execution state. The current reserved ticket
 * supplies authority; this checksum only detects torn private files. */
static constexpr size_t source_journal_stage_v1_header_size = 80;
static constexpr size_t source_journal_stage_header_size = 104;

static bool
source_journal_stage_encode(const durable_handoff &ticket,
    const std::vector<uint8_t> &transfer,
    const source_journal_stage_binding &binding,
    std::vector<uint8_t> &stage)
{
	stage.clear();
	if (!handoff_valid(ticket, handoff_phase::reserved) ||
	    !binding.present ||
	    binding.session == std::array<uint8_t, 16>{} ||
	    binding.session == ticket.source_session ||
	    binding.uid == UINT32_MAX || binding.pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	if (transfer.size() > host_transfer_stage_max_size -
	    source_journal_stage_header_size - SHA256_DIGEST_LENGTH ||
	    transfer.size() > UINT32_MAX) {
		errno = E2BIG;
		return (false);
	}
	try {
		std::vector<uint8_t> candidate(source_journal_stage_header_size +
		    transfer.size() + SHA256_DIGEST_LENGTH, 0);
		memcpy(candidate.data(), "HJB1", 4);
		dtraced_wire_put_u32(candidate.data() + 4, 2);
		memcpy(candidate.data() + 8, ticket.token.data(), 16);
		memcpy(candidate.data() + 24,
		    ticket.checkpoint_digest.data(), 32);
		dtraced_wire_put_u16(candidate.data() + 56,
		    ticket.destination_vmid);
		dtraced_wire_put_u64(candidate.data() + 64,
		    ticket.destination_epoch);
		dtraced_wire_put_u32(candidate.data() + 72,
		    (uint32_t)transfer.size());
		memcpy(candidate.data() + 80, binding.session.data(), 16);
		dtraced_wire_put_u32(candidate.data() + 96, binding.uid);
		dtraced_wire_put_u32(candidate.data() + 100, binding.pid);
		memcpy(candidate.data() + source_journal_stage_header_size,
		    transfer.data(), transfer.size());
		const size_t tail = candidate.size() - SHA256_DIGEST_LENGTH;
		if (SHA256(candidate.data(), tail, candidate.data() + tail) ==
		    nullptr) {
			errno = EIO;
			return (false);
		}
		stage.swap(candidate);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

static bool
source_journal_stage_decode(const durable_handoff &ticket,
    const std::vector<uint8_t> &stage, std::vector<uint8_t> &transfer,
    source_journal_stage_binding &binding)
{
	transfer.clear();
	binding = {};
	const uint8_t zero6[6] = {};
	const uint8_t zero4[4] = {};
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint32_t version = stage.size() >= 8 ?
	    dtraced_wire_get_u32(stage.data() + 4) : 0;
	size_t header_size = version == 1 ?
	    source_journal_stage_v1_header_size :
	    version == 2 ? source_journal_stage_header_size : 0;
	if (!handoff_valid(ticket, handoff_phase::reserved) ||
	    header_size == 0 || stage.size() < header_size +
	    DTRACED_TRANSFER_HEADER_SIZE + 2 * SHA256_DIGEST_LENGTH ||
	    stage.size() > host_transfer_stage_max_size ||
	    memcmp(stage.data(), "HJB1", 4) != 0 ||
	    memcmp(stage.data() + 8, ticket.token.data(), 16) != 0 ||
	    memcmp(stage.data() + 24,
	    ticket.checkpoint_digest.data(), 32) != 0 ||
	    dtraced_wire_get_u16(stage.data() + 56) !=
	    ticket.destination_vmid ||
	    memcmp(stage.data() + 58, zero6, sizeof(zero6)) != 0 ||
	    dtraced_wire_get_u64(stage.data() + 64) !=
	    ticket.destination_epoch ||
	    memcmp(stage.data() + 76, zero4, sizeof(zero4)) != 0 ||
	    dtraced_wire_get_u32(stage.data() + 72) != stage.size() -
	    header_size - SHA256_DIGEST_LENGTH ||
	    SHA256(stage.data(), stage.size() - SHA256_DIGEST_LENGTH,
	    digest) == nullptr ||
	    CRYPTO_memcmp(digest, stage.data() + stage.size() -
	    SHA256_DIGEST_LENGTH, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	source_journal_stage_binding parsed;
	if (version == 2) {
		memcpy(parsed.session.data(), stage.data() + 80, 16);
		parsed.uid = dtraced_wire_get_u32(stage.data() + 96);
		parsed.pid = dtraced_wire_get_u32(stage.data() + 100);
		if (parsed.session == std::array<uint8_t, 16>{} ||
		    parsed.session == ticket.source_session ||
		    parsed.uid == UINT32_MAX || parsed.pid <= 1) {
			errno = EPROTO;
			return (false);
		}
		parsed.present = true;
	}
	try {
		std::vector<uint8_t> candidate(
		    stage.begin() + header_size,
		    stage.end() - SHA256_DIGEST_LENGTH);
		if (!dtraced_transfer_wire_valid(candidate.data(),
		    candidate.size(), ticket.token.data()) ||
		    CRYPTO_memcmp(candidate.data() + candidate.size() -
		    SHA256_DIGEST_LENGTH, ticket.transfer_digest.data(),
		    SHA256_DIGEST_LENGTH) != 0) {
			errno = EPROTO;
			return (false);
		}
		transfer.swap(candidate);
		binding = parsed;
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* Called with the outbound publication and process locks held. */
static int
source_journal_stage_status_locked(int directory,
    const durable_handoff &ticket)
{
	char name[39];
	if (!source_journal_stage_name(ticket.token, name))
		return (-1);
	std::vector<uint8_t> stage, transfer;
	int present = host_transfer_stage_read_at(directory, name, stage);
	if (present != 1)
		return (present);
	source_journal_stage_binding binding;
	return (source_journal_stage_decode(ticket, stage, transfer,
	    binding) ? 1 : -1);
}

/* A reserved HJB1 is the authoritative foreign source cut for read-only
 * status queries. Keep the entire decode under the ticket process lock; no
 * source record is copied into the ordinary local journal here. */
static int
source_journal_stage_load_locked(int directory,
    const durable_handoff &ticket, source_journal_cut &journal,
    host_ingress_transfer_bundle &ingress,
    source_journal_stage_binding *binding,
    std::array<uint8_t, SHA256_DIGEST_LENGTH> *stage_digest)
{
	journal = {};
	ingress = {};
	if (binding != nullptr)
		*binding = {};
	if (stage_digest != nullptr)
		*stage_digest = {};
	char name[39];
	if (!source_journal_stage_name(ticket.token, name))
		return (-1);
	std::vector<uint8_t> stage, transfer;
	int present = host_transfer_stage_read_at(directory, name, stage);
	if (present != 1)
		return (present);
	source_journal_stage_binding parsed;
	if (!source_journal_stage_decode(ticket, stage, transfer, parsed) ||
	    !dir::decode_source_journal_transfer_wire(ticket, transfer,
	    journal, ingress))
		return (-1);
	if (binding != nullptr)
		*binding = parsed;
	if (stage_digest != nullptr)
		memcpy(stage_digest->data(), stage.data() + stage.size() -
		    SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
	return (1);
}

/* HJR1 is the fsynced boundary after every pending receipt exists. It binds
 * the exact HJB1 bytes; neither the marker nor its checksum grants execution. */
static std::array<uint8_t, 128>
source_journal_ready_bytes(const durable_handoff &ticket,
    const std::array<uint8_t, SHA256_DIGEST_LENGTH> &stage_digest,
    uint32_t delivery_count)
{
	std::array<uint8_t, 128> wire{};
	memcpy(wire.data(), "HJR1", 4);
	dtraced_wire_put_u32(wire.data() + 4, 1);
	memcpy(wire.data() + 8, ticket.token.data(), 16);
	memcpy(wire.data() + 24, ticket.checkpoint_digest.data(), 32);
	memcpy(wire.data() + 56, stage_digest.data(), 32);
	dtraced_wire_put_u32(wire.data() + 88, delivery_count);
	(void)SHA256(wire.data(), 96, wire.data() + 96);
	return (wire);
}

static int
source_journal_ready_status_locked(int directory,
    const durable_handoff &ticket,
    const std::array<uint8_t, SHA256_DIGEST_LENGTH> &stage_digest,
    uint32_t delivery_count)
{
	char name[39];
	if (!source_journal_ready_name(ticket.token, name))
		return (-1);
	std::vector<uint8_t> actual;
	int present = host_transfer_stage_read_at(directory, name, actual);
	if (present != 1)
		return (present);
	const auto expected = source_journal_ready_bytes(ticket,
	    stage_digest, delivery_count);
	if (actual.size() != expected.size() ||
	    memcmp(actual.data(), expected.data(), expected.size()) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (1);
}

static bool
source_journal_ready_publish_locked(int directory,
    const durable_handoff &ticket,
    const std::array<uint8_t, SHA256_DIGEST_LENGTH> &stage_digest,
    uint32_t delivery_count)
{
	int present = source_journal_ready_status_locked(directory,
	    ticket, stage_digest, delivery_count);
	if (present < 0)
		return (false);
	if (present == 1)
		return (fsync(directory) == 0);
	char name[39];
	if (!source_journal_ready_name(ticket.token, name))
		return (false);
	const auto wire = source_journal_ready_bytes(ticket, stage_digest,
	    delivery_count);
	if (handoff_publish_at(directory, name, wire.data(), wire.size()))
		return (true);
	if (errno != EEXIST)
		return (false);
	return (source_journal_ready_status_locked(directory,
	    ticket, stage_digest, delivery_count) == 1 &&
	    fsync(directory) == 0);
}

static bool
source_journal_stage_remove_locked(int directory,
    const durable_handoff &ticket)
{
	char name[39];
	if (!source_journal_stage_name(ticket.token, name))
		return (false);
	std::vector<uint8_t> stage, transfer;
	int present = host_transfer_stage_read_at(directory, name, stage);
	if (present < 0)
		return (false);
	if (present == 0)
		return (true);
	source_journal_stage_binding binding;
	if (!source_journal_stage_decode(ticket, stage, transfer, binding) ||
	    unlinkat(directory, name, 0) != 0)
		return (false);
	return (fsync(directory) == 0);
}

bool
dir::stage_source_journal_destination_wire(const durable_handoff &reserved,
    const std::vector<uint8_t> &transfer,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (false);
	}
	source_journal_cut journal;
	host_ingress_transfer_bundle ingress;
	if (!decode_source_journal_transfer_wire(reserved, transfer,
	    journal, ingress))
		return (false);
	std::vector<uint8_t> stage;
	source_journal_stage_binding binding{destination_session,
	    destination_uid, destination_pid, true};
	if (!source_journal_stage_encode(reserved, transfer, binding, stage))
		return (false);
	char name[39];
	if (!source_journal_stage_name(reserved.token, name))
		return (false);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, reserved.token, current);
	if (phase < 0)
		return (false);
	if (phase != (int)handoff_phase::reserved ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (!handoff_release_authority_locked(this->dirfd,
	    this->state, current))
		return (false);
	std::vector<uint8_t> existing;
	int present = host_transfer_stage_read_at(this->dirfd, name, existing);
	if (present < 0)
		return (false);
	if (present == 1 && existing != stage) {
		errno = EEXIST;
		return (false);
	}
	if (present == 1)
		return (fsync(this->dirfd) == 0);
	if (handoff_publish_at(this->dirfd, name, stage.data(), stage.size()))
		return (true);
	if (errno != EEXIST)
		return (false);
	present = host_transfer_stage_read_at(this->dirfd, name, existing);
	if (present != 1)
		return (false);
	if (existing != stage) {
		errno = EEXIST;
		return (false);
	}
	return (fsync(this->dirfd) == 0);
}

int
dir::load_source_journal_destination_stage(const durable_handoff &reserved,
    source_journal_cut &journal, host_ingress_transfer_bundle &ingress)
{
	journal = {};
	ingress = {};
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, reserved.token, current);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::reserved ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	if (!handoff_release_authority_locked(this->dirfd,
	    this->state, current))
		return (-1);
	return (source_journal_stage_load_locked(this->dirfd, reserved,
	    journal, ingress));
}

/* Mapping is shared by the read-only plan, pending import, and CANCEL.
 * All callers hold the outbound ticket lock while examining local revocations. */
static bool
source_journal_destination_plan_locked(int directory,
    const durable_handoff &current, const source_journal_cut &cut,
    const host_ingress_transfer_bundle &ingress,
    const source_journal_stage_binding &binding,
    bool check_revocations, source_journal_destination_plan &result)
{
	source_journal_destination_plan candidate;
	candidate.has_ingress = !ingress.entries.empty();
	try {
		for (const auto &item : cut.kills) {
			durable_kill mapped = item.record;
			mapped.vmid = current.destination_vmid;
			mapped.epoch = current.destination_epoch;
			candidate.pending_kills.push_back(mapped);
			candidate.revoked_sources.push_back(mapped.source_id);
		}
		for (const auto &item : cut.deliveries)
			if (item.revoked)
				candidate.revoked_sources.push_back(
				    item.state.record.source_id);
		std::sort(candidate.revoked_sources.begin(),
		    candidate.revoked_sources.end());
		candidate.revoked_sources.erase(std::unique(
		    candidate.revoked_sources.begin(),
		    candidate.revoked_sources.end()),
		    candidate.revoked_sources.end());
		for (const auto &item : cut.deliveries) {
			if (item.revoked)
				continue;
			source_journal_delivery mapped_item = item;
			durable_delivery &mapped = mapped_item.state.record;
			if (std::binary_search(candidate.revoked_sources.begin(),
			    candidate.revoked_sources.end(), mapped.source_id)) {
				errno = EPROTO;
				return (false);
			}
			if (check_revocations) {
				int revoked = source_revoked_at(directory,
				    mapped.source_id.data(), current.destination_vmid,
				    current.destination_epoch);
				if (revoked < 0)
					return (false);
				if (revoked != 0) {
					errno = ECANCELED;
					return (false);
				}
			}
			mapped.payload_vmid = mapped.journal_version == 5 ?
			    mapped.payload_vmid : mapped.vmid;
			mapped.payload_epoch = mapped.journal_version == 5 ?
			    mapped.payload_epoch : mapped.epoch;
			mapped.source_session = mapped.session_id;
			mapped.session_id = binding.session;
			mapped.vmid = current.destination_vmid;
			mapped.epoch = current.destination_epoch;
			mapped.peer_uid = binding.uid;
			mapped.peer_pid = binding.pid;
			mapped.journal_version = 5;
			mapped.handoff_token = current.token;
			if (!delivery_record_valid(mapped)) {
				errno = EPROTO;
				return (false);
			}
			candidate.deliveries.push_back(std::move(mapped_item));
		}
		for (const auto &item : cut.cleanups) {
			if (item.phase != 'a')
				continue;
			durable_cleanup mapped = item.record;
			mapped.vmid = current.destination_vmid;
			mapped.epoch = current.destination_epoch;
			candidate.queued_cleanups.push_back(mapped);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	result = std::move(candidate);
	return (true);
}

/* Produce destination identities without publishing a spool, delivery,
 * revocation, KILL, or cleanup. The HJB1 remains the only durable authority
 * until an import transaction can commit every mapped record together. */
int
dir::plan_source_journal_destination(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    source_journal_destination_plan &result)
{
	result = {};
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(reserved, handoff_phase::reserved) ||
	    destination_session == std::array<uint8_t, 16>{} ||
	    destination_session == reserved.source_session ||
	    destination_uid == UINT32_MAX || destination_pid <= 1) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, reserved.token, current);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::reserved ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	if (!handoff_release_authority_locked(this->dirfd,
	    this->state, current))
		return (-1);
	source_journal_cut cut;
	host_ingress_transfer_bundle ingress;
	source_journal_stage_binding binding;
	int staged = source_journal_stage_load_locked(this->dirfd,
	    current, cut, ingress, &binding);
	if (staged != 1)
		return (staged);
	if (!binding.present) {
		errno = EOPNOTSUPP; /* Version 1 lacks a recoverable owner. */
		return (-1);
	}
	if (binding.session != destination_session ||
	    binding.uid != destination_uid ||
	    binding.pid != destination_pid) {
		errno = EPERM;
		return (-1);
	}
	if (!source_journal_destination_plan_locked(this->dirfd, current,
	    cut, ingress, binding, true, result))
		return (-1);
	if (fsync(this->dirfd) != 0)
		return (-1);
	return (1);
}

/* One reconciliation rule serves read-only recovery and the importer.
 * Check all ticket records as well as collisions with each planned program
 * and delivery identity before the importer makes its first durable write. */
static bool
source_journal_pending_reconcile_locked(int directory,
    const durable_handoff &ticket,
    const source_journal_destination_plan &plan, bool allow_advanced,
    size_t &missing, const source_journal_destination_plan *prior)
{
	missing = 0;
	std::vector<durable_delivery_state> existing;
	if (!list_deliveries_at(directory, existing))
		return (false);
	using delivery_key = std::pair<std::array<uint8_t, 16>, uint64_t>;
	std::map<delivery_key, const durable_delivery *> by_key;
	std::map<std::array<uint8_t, 16>, const durable_delivery *> by_program;
	std::map<std::array<uint8_t, 16>, const durable_delivery *> prior_program;
	std::map<delivery_key, bool> found;
	try {
		if (prior != nullptr) {
			for (const auto &item : prior->deliveries) {
				const auto &record = item.state.record;
				if (record.handoff_token != ticket.token ||
				    !prior_program.emplace(record.program_id,
				    &record).second) {
					errno = EPROTO;
					return (false);
				}
			}
		}
		for (const auto &item : plan.deliveries) {
			const auto &record = item.state.record;
			auto key = std::make_pair(record.session_id,
			    record.delivery_id);
			if (!by_key.emplace(key, &record).second ||
			    !by_program.emplace(record.program_id, &record).second) {
				errno = EPROTO;
				return (false);
			}
		}
		for (const auto &entry : existing) {
			const auto &record = entry.record;
			auto previous = prior_program.find(record.program_id);
			if (previous != prior_program.end()) {
				const auto &old = *previous->second;
				if (record.handoff_token == ticket.token &&
				    record.vmid == old.vmid &&
				    record.epoch == old.epoch &&
				    record.session_id == old.session_id) {
					if (delivery_record_bytes(record) !=
					    delivery_record_bytes(old)) {
						errno = EPROTO;
						return (false);
					}
					continue;
				}
				/* A local empty HTX1 still has its original HTD4/HTD5
				 * source receipt beside the old bound HTD5. */
				if (record.scope == 0 &&
				    (record.journal_version == 4 ||
				    record.journal_version == 5) &&
				    record.session_id == ticket.source_session &&
				    record.vmid == ticket.source_vmid &&
				    record.epoch == ticket.source_epoch &&
				    record.delivery_id == old.delivery_id &&
				    record.source_id == old.source_id &&
				    record.payload_digest == old.payload_digest)
					continue;
			}
			auto key = std::make_pair(record.session_id,
			    record.delivery_id);
			auto identity = by_key.find(key);
			auto program = by_program.find(record.program_id);
			if (identity == by_key.end() &&
			    program == by_program.end()) {
				if (record.handoff_token == ticket.token) {
					errno = EPROTO;
					return (false);
				}
				continue;
			}
			if (identity == by_key.end() ||
			    program == by_program.end() ||
			    identity->second != program->second ||
			    delivery_record_bytes(record) !=
			    delivery_record_bytes(*identity->second)) {
				errno = EEXIST;
				return (false);
			}
			if (entry.phase != delivery_phase::pending &&
			    !(allow_advanced &&
			    (entry.phase == delivery_phase::accepted ||
			    entry.phase == delivery_phase::installed ||
			    entry.phase == delivery_phase::terminal))) {
				errno = EBUSY;
				return (false);
			}
			if (!found.emplace(key, true).second) {
				errno = EPROTO;
				return (false);
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	missing = by_key.size() - found.size();
	return (true);
}

/* Reserved, mutating, and claimed foreign tickets may use the source cut
 * only after HJR1 and every exact delivery receipt are durable. */
static int
source_journal_claimed_plan_locked(int directory, state *control,
    const durable_handoff &ticket, source_journal_cut &cut,
    source_journal_destination_plan &plan,
    std::array<uint8_t, 16> *destination_session,
    bool allow_rebind_pending,
    std::array<uint8_t, SHA256_DIGEST_LENGTH> *stage_digest_out)
{
	cut = {};
	plan = {};
	if (destination_session != nullptr)
		*destination_session = {};
	if (stage_digest_out != nullptr)
		*stage_digest_out = {};
	if (!handoff_release_authority_locked(directory, control, ticket))
		return (-1);
	host_ingress_transfer_bundle ingress;
	source_journal_stage_binding binding;
	std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
	int staged = source_journal_stage_load_locked(directory, ticket,
	    cut, ingress, &binding, &stage_digest);
	if (staged == 0) {
		int ready = source_journal_ready_raw_status_locked(directory, ticket);
		if (ready != 0) {
			if (ready == 1)
				errno = EPROTO;
			return (-1);
		}
		return (0);
	}
	if (staged < 0)
		return (staged);
	if (stage_digest_out != nullptr)
		*stage_digest_out = stage_digest;
	if (!binding.present) {
		errno = EPROTO;
		return (-1);
	}
	if (!source_journal_destination_plan_locked(directory, ticket,
	    cut, ingress, binding, false, plan))
		return (-1);
	if (plan.deliveries.size() > UINT32_MAX) {
		errno = E2BIG;
		return (-1);
	}
	int ready = source_journal_ready_status_locked(directory, ticket,
	    stage_digest, (uint32_t)plan.deliveries.size());
	if (ready != 1) {
		if (ready == 0)
			errno = EBUSY;
		return (-1);
	}
	if (allow_rebind_pending) {
		/* A proposed pending HTD5 has the same ticket token as the old
		 * claim. Verify old receipts directly here; the rebind caller will
		 * reconcile both old and proposed identities together. */
		for (const auto &item : plan.deliveries) {
			int phase = delivery_record_status_at(directory,
			    item.state.record);
			if (phase < 0)
				return (-1);
			if (phase != (int)delivery_phase::pending &&
			    phase != (int)delivery_phase::accepted &&
			    phase != (int)delivery_phase::installed &&
			    phase != (int)delivery_phase::terminal) {
				errno = phase == 0 ? EPROTO : EBUSY;
				return (-1);
			}
		}
	} else {
		size_t missing;
		if (!source_journal_pending_reconcile_locked(directory, ticket,
		    plan, true, missing))
			return (-1);
		if (missing != 0) {
			errno = EPROTO;
			return (-1);
		}
	}
	if (destination_session != nullptr)
		*destination_session = binding.session;
	return (1);
}

/* KILLs have no handoff token in their filename. Match every old-destination
 * KILL to the fixed source cut (or local source VM), and refuse an applied
 * ACK: it would prove guest work occurred despite the missing start marker. */
static bool
source_journal_rebind_kills_locked(int directory,
    const durable_handoff &old, uint16_t new_vmid, uint64_t new_epoch,
    bool staged,
    source_journal_destination_plan &prior,
    source_journal_destination_plan &replacement)
{
	std::vector<durable_kill> records;
	if (!list_kills_at(directory, records))
		return (false);
	using kill_key = std::pair<pid_t, std::array<uint8_t, 16>>;
	std::map<kill_key, bool> expected;
	try {
		if (!staged) {
			for (const auto &record : records) {
				if (record.vmid != old.source_vmid ||
				    record.epoch != old.source_epoch)
					continue;
				durable_kill previous = record;
				previous.vmid = old.destination_vmid;
				previous.epoch = old.destination_epoch;
				durable_kill proposed = record;
				proposed.vmid = new_vmid;
				proposed.epoch = new_epoch;
				prior.pending_kills.push_back(previous);
				replacement.pending_kills.push_back(proposed);
				replacement.revoked_sources.push_back(
				    record.source_id);
			}
			std::sort(replacement.revoked_sources.begin(),
			    replacement.revoked_sources.end());
			replacement.revoked_sources.erase(std::unique(
			    replacement.revoked_sources.begin(),
			    replacement.revoked_sources.end()),
			    replacement.revoked_sources.end());
		}
		for (const auto &record : prior.pending_kills) {
			if (record.vmid != old.destination_vmid ||
			    record.epoch != old.destination_epoch ||
			    !expected.emplace(kill_key{record.pid,
			    record.source_id}, true).second) {
				errno = EPROTO;
				return (false);
			}
			/* The fixed source cut names a KILL, but only the bound
			 * destination record proves that the old claim was fenced.
			 * Do not remap a revocation that was never durably bound or
			 * has since disappeared from the old incarnation. */
			char name[70];
			if (!durable_kill_name(record, name))
				return (false);
			if (kill_record_status_at(directory, name) != 0) {
				if (errno == ENOENT)
					errno = EPROTO;
				return (false);
			}
			char ack_name[73];
			if (!kill_applied_name(record, ack_name))
				return (false);
			int applied = kill_record_status_at(directory, ack_name);
			if (applied == 0) {
				errno = EBUSY;
				return (false);
			}
			if (errno != ENOENT)
				return (false);
		}
		for (const auto &record : records) {
			if (record.vmid == old.destination_vmid &&
			    record.epoch == old.destination_epoch &&
			    expected.find(kill_key{record.pid,
			    record.source_id}) == expected.end()) {
				errno = EPROTO;
				return (false);
			}
		}
		if (replacement.pending_kills.size() != expected.size()) {
			errno = EPROTO;
			return (false);
		}
		for (const auto &record : replacement.pending_kills) {
			if (expected.find(kill_key{record.pid,
			    record.source_id}) == expected.end()) {
				errno = EPROTO;
				return (false);
			}
			char name[70];
			if (!durable_kill_name(record, name))
				return (false);
			int present = kill_record_status_at(directory, name);
			if (present == 0) {
				errno = EEXIST;
				return (false);
			}
			if (errno != ENOENT)
				return (false);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	return (true);
}

/* A queued CLEANUP still needs guest application. The old guest's applied
 * phase forbids recovery under a missing execution-start marker, while a
 * proposed incarnation may not reuse an existing cleanup identity. */
static bool
source_journal_rebind_cleanups_locked(int directory,
    const durable_handoff &old, uint16_t new_vmid, uint64_t new_epoch,
    bool staged, source_journal_destination_plan &prior,
    source_journal_destination_plan &replacement)
{
	std::vector<durable_cleanup> pending;
	std::vector<source_journal_cleanup> all;
	if (!list_pending_cleanups_at(directory, pending, nullptr, &all))
		return (false);
	std::map<uint64_t, bool> expected;
	try {
		if (!staged) {
			for (const auto &entry : all) {
				const auto &record = entry.record;
				if (record.vmid != old.source_vmid ||
				    record.epoch != old.source_epoch)
					continue;
				if (entry.phase == 'p') {
					errno = EBUSY;
					return (false);
				}
				if (entry.phase != 'a')
					continue;
				durable_cleanup previous = record;
				previous.vmid = old.destination_vmid;
				previous.epoch = old.destination_epoch;
				durable_cleanup proposed = record;
				proposed.vmid = new_vmid;
				proposed.epoch = new_epoch;
				prior.queued_cleanups.push_back(previous);
				replacement.queued_cleanups.push_back(proposed);
			}
		}
		for (const auto &record : prior.queued_cleanups) {
			if (record.vmid != old.destination_vmid ||
			    record.epoch != old.destination_epoch ||
			    !expected.emplace(record.delivery_id, true).second) {
				errno = EPROTO;
				return (false);
			}
			int phase = cleanup_status_at(directory, record);
			if (phase < 0)
				return (false);
			/* The old claim must still own the queued cleanup.  A
			 * missing receipt is not an empty queue: committing its
			 * replacement would manufacture cleanup authority. */
			if (phase != 'a') {
				errno = phase == 0 ? EPROTO : EBUSY;
				return (false);
			}
		}
		for (const auto &entry : all) {
			const auto &record = entry.record;
			if (record.vmid != old.destination_vmid ||
			    record.epoch != old.destination_epoch)
				continue;
			if (entry.phase == 'g' || entry.phase == 'p') {
				errno = EBUSY;
				return (false);
			}
			if (expected.find(record.delivery_id) == expected.end()) {
				errno = EPROTO;
				return (false);
			}
		}
		if (replacement.queued_cleanups.size() != expected.size()) {
			errno = EPROTO;
			return (false);
		}
		for (const auto &record : replacement.queued_cleanups) {
			if (expected.find(record.delivery_id) == expected.end()) {
				errno = EPROTO;
				return (false);
			}
			int phase = cleanup_status_at(directory, record);
			if (phase < 0)
				return (false);
			if (phase != 0) {
				errno = EEXIST;
				return (false);
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	return (true);
}

/* Before publishing an inert rebind intent, derive the replacement's
 * outbound identities from the same HJB1 cut. Existing HTD5 records for the
 * old claim are expected; any other collision with the replacement plan is
 * not. This does not publish records or give the replacement a lease. */
static int
source_journal_rebind_plan_locked(int directory, state *control,
    const durable_handoff &old, uint16_t new_vmid, uint64_t new_epoch,
    const std::array<uint8_t, 16> &new_session, uint32_t new_uid,
    uint32_t new_pid, source_journal_cut &cut,
    source_journal_destination_plan &prior,
    source_journal_destination_plan &replacement,
    std::array<uint8_t, 16> *old_session, bool allow_pending,
    std::array<uint8_t, SHA256_DIGEST_LENGTH> *stage_digest_out)
{
	replacement = {};
	int staged = source_journal_claimed_plan_locked(directory, control,
	    old, cut, prior, old_session, allow_pending, stage_digest_out);
	if (staged < 0)
		return (staged);
	if (staged == 0) {
		/* A local empty transfer has no HJB1, yet CLAIM may already
		 * have bound host deliveries into HTD5. Include those exact old
		 * identities in the replacement collision check. */
		std::vector<durable_delivery_state> existing;
		if (!list_deliveries_at(directory, existing))
			return (-1);
		try {
			for (const auto &entry : existing) {
				const auto &record = entry.record;
				if (record.handoff_token != old.token)
					continue;
				if (allow_pending && record.scope == 0 &&
				    record.journal_version == 5 &&
				    record.vmid == new_vmid &&
				    record.epoch == new_epoch &&
				    record.session_id == new_session &&
				    record.source_session == old.source_session)
					continue;
				if (record.scope != 0 ||
				    record.journal_version != 5 ||
				    record.vmid != old.destination_vmid ||
				    record.epoch != old.destination_epoch ||
				    record.source_session != old.source_session) {
					errno = EPROTO;
					return (-1);
				}
				if (record.session_id == new_session) {
					errno = EEXIST;
					return (-1);
				}
				int revoked = source_revoked_at(directory,
				    record.source_id.data(), new_vmid, new_epoch);
				if (revoked < 0)
					return (-1);
				if (revoked != 0) {
					errno = ECANCELED;
					return (-1);
				}
				prior.deliveries.push_back({entry, false, {}});
				source_journal_delivery mapped{entry, false, {}};
				mapped.state.record.session_id = new_session;
				mapped.state.record.vmid = new_vmid;
				mapped.state.record.epoch = new_epoch;
				mapped.state.record.peer_uid = new_uid;
				mapped.state.record.peer_pid = new_pid;
				if (!delivery_record_valid(mapped.state.record)) {
					errno = EPROTO;
					return (-1);
				}
				replacement.deliveries.push_back(
				    std::move(mapped));
			}
		} catch (const std::bad_alloc &) {
			errno = ENOMEM;
			return (-1);
		}
		size_t missing;
		if (!source_journal_pending_reconcile_locked(directory, old,
		    replacement, false, missing, &prior))
			return (-1);
		if (!allow_pending &&
		    missing != replacement.deliveries.size()) {
			errno = EEXIST;
			return (-1);
		}
		if (!source_journal_rebind_kills_locked(directory, old,
		    new_vmid, new_epoch, false, prior, replacement))
			return (-1);
		if (!source_journal_rebind_cleanups_locked(directory, old,
		    new_vmid, new_epoch, false, prior, replacement))
			return (-1);
		return (0);
	}
	source_journal_cut reloaded;
	host_ingress_transfer_bundle ingress;
	source_journal_stage_binding old_binding;
	int loaded = source_journal_stage_load_locked(directory, old,
	    reloaded, ingress, &old_binding);
	if (loaded != 1) {
		if (loaded == 0)
			errno = EPROTO;
		return (-1);
	}
	if (!old_binding.present ||
	    (old_session != nullptr && old_binding.session != *old_session)) {
		errno = EPROTO;
		return (-1);
	}
	durable_handoff proposed = old;
	proposed.destination_vmid = new_vmid;
	proposed.destination_epoch = new_epoch;
	source_journal_stage_binding binding;
	binding.session = new_session;
	binding.uid = new_uid;
	binding.pid = new_pid;
	binding.present = true;
	if (!source_journal_destination_plan_locked(directory, proposed,
	    reloaded, ingress, binding, true, replacement))
		return (-1);
	if (replacement.has_ingress != prior.has_ingress ||
	    replacement.deliveries.size() != prior.deliveries.size() ||
	    replacement.pending_kills.size() != prior.pending_kills.size() ||
	    replacement.queued_cleanups.size() != prior.queued_cleanups.size()) {
		errno = EPROTO;
		return (-1);
	}
	size_t missing;
	if (!source_journal_pending_reconcile_locked(directory, proposed,
	    replacement, false, missing, &prior))
		return (-1);
	if (!allow_pending &&
	    missing != replacement.deliveries.size()) {
		errno = EEXIST;
		return (-1);
	}
	if (!source_journal_rebind_kills_locked(directory, old,
	    new_vmid, new_epoch, true, prior, replacement))
		return (-1);
	if (!source_journal_rebind_cleanups_locked(directory, old,
	    new_vmid, new_epoch, true, prior, replacement))
		return (-1);
	return (1);
}

/* The proposed journal is still inert, so check its name budget before
 * publishing an HRP1 that a later commit would have to replay. The process
 * handoff lock keeps other daemon writers out of this census. Recheck at the
 * pending boundary because unrelated journals may have grown since STAGE;
 * a future commit must make one final check before its durable decision. */
static bool
source_journal_rebind_capacity_locked(int directory,
    const source_journal_destination_plan &replacement)
{
	int kills = kill_record_count_at(directory);
	if (kills < 0)
		return (false);
	std::vector<durable_cleanup> pending;
	size_t cleanups = 0;
	if (!list_pending_cleanups_at(directory, pending, &cleanups))
		return (false);
	if ((size_t)kills > max_durable_kills ||
	    replacement.pending_kills.size() > max_durable_kills -
	    (size_t)kills || cleanups > max_durable_kills ||
	    replacement.queued_cleanups.size() > max_durable_kills -
	    cleanups) {
		errno = ENOSPC;
		return (false);
	}
	return (true);
}

static bool
handoff_rebind_plan_bytes(
    const std::array<uint8_t, handoff_rebind_size> &intent,
    const source_journal_destination_plan &plan,
    std::vector<uint8_t> &result)
{
	result.clear();
	if (plan.deliveries.size() > max_durable_kills ||
	    plan.pending_kills.size() > max_durable_kills ||
	    plan.queued_cleanups.size() > max_durable_kills ||
	    plan.revoked_sources.size() > max_durable_kills) {
		errno = E2BIG;
		return (false);
	}
	const size_t length = handoff_rebind_plan_header_size +
	    plan.deliveries.size() * handoff_rebind_plan_delivery_size +
	    plan.pending_kills.size() * handoff_rebind_plan_kill_size +
	    plan.queued_cleanups.size() * handoff_rebind_plan_cleanup_size +
	    plan.revoked_sources.size() * 16 +
	    SHA256_DIGEST_LENGTH;
	if (length > DTRACED_TRANSFER_MAX_SIZE) {
		errno = E2BIG;
		return (false);
	}
	try {
		std::vector<std::array<uint8_t,
		    handoff_rebind_plan_delivery_size>> deliveries;
		std::vector<std::array<uint8_t,
		    handoff_rebind_plan_kill_size>> kills;
		std::vector<std::array<uint8_t,
		    handoff_rebind_plan_cleanup_size>> cleanups;
		std::vector<std::array<uint8_t, 16>> revocations =
		    plan.revoked_sources;
		for (const auto &item : plan.deliveries) {
			std::array<uint8_t,
			    handoff_rebind_plan_delivery_size> entry{};
			const auto bytes = delivery_record_bytes(item.state.record);
			memcpy(entry.data(), bytes.data(), bytes.size());
			entry[185] = (uint8_t)item.state.phase;
			deliveries.push_back(entry);
		}
		for (const auto &item : plan.pending_kills) {
			std::array<uint8_t,
			    handoff_rebind_plan_kill_size> entry{};
			dtraced_wire_put_u32(entry.data(), (uint32_t)item.pid);
			dtraced_wire_put_u16(entry.data() + 4, item.vmid);
			dtraced_wire_put_u64(entry.data() + 6, item.epoch);
			memcpy(entry.data() + 14, item.source_id.data(), 16);
			kills.push_back(entry);
		}
		for (const auto &item : plan.queued_cleanups) {
			std::array<uint8_t,
			    handoff_rebind_plan_cleanup_size> entry{};
			dtraced_wire_put_u16(entry.data(), item.vmid);
			dtraced_wire_put_u64(entry.data() + 2, item.epoch);
			dtraced_wire_put_u64(entry.data() + 10,
			    item.delivery_id);
			cleanups.push_back(entry);
		}
		std::sort(deliveries.begin(), deliveries.end());
		std::sort(kills.begin(), kills.end());
		std::sort(cleanups.begin(), cleanups.end());
		std::sort(revocations.begin(), revocations.end());
		if (std::adjacent_find(deliveries.begin(), deliveries.end(),
		    [](const auto &a, const auto &b) {
			/* HTD5 session and delivery ID are the journal key.
			 * A changed record or phase cannot reuse that key. */
			return (memcmp(a.data() + 4, b.data() + 4, 24) == 0);
		    }) != deliveries.end() ||
		    std::adjacent_find(kills.begin(), kills.end()) != kills.end() ||
		    std::adjacent_find(cleanups.begin(), cleanups.end()) !=
		    cleanups.end() ||
		    std::adjacent_find(revocations.begin(), revocations.end()) !=
		    revocations.end()) {
			errno = EPROTO;
			return (false);
		}
		std::vector<uint8_t> wire(length, 0);
		memcpy(wire.data(), "HRP1", 4);
		dtraced_wire_put_u32(wire.data() + 4, 1);
		memcpy(wire.data() + 8, intent.data(), intent.size());
		dtraced_wire_put_u32(wire.data() + 236,
		    (uint32_t)deliveries.size());
		dtraced_wire_put_u32(wire.data() + 240,
		    (uint32_t)kills.size());
		dtraced_wire_put_u32(wire.data() + 244,
		    (uint32_t)cleanups.size());
		wire[248] = plan.has_ingress ? 1 : 0;
		dtraced_wire_put_u32(wire.data() + 249,
		    (uint32_t)revocations.size());
		size_t offset = handoff_rebind_plan_header_size;
		for (const auto &entry : deliveries) {
			memcpy(wire.data() + offset, entry.data(), entry.size());
			offset += entry.size();
		}
		for (const auto &entry : kills) {
			memcpy(wire.data() + offset, entry.data(), entry.size());
			offset += entry.size();
		}
		for (const auto &entry : cleanups) {
			memcpy(wire.data() + offset, entry.data(), entry.size());
			offset += entry.size();
		}
		for (const auto &entry : revocations) {
			memcpy(wire.data() + offset, entry.data(), entry.size());
			offset += entry.size();
		}
		if (SHA256(wire.data(), offset, wire.data() + offset) ==
		    nullptr) {
			errno = EIO;
			return (false);
		}
		result.swap(wire);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* HRC1 is a commit decision, not an execution lease. It binds the exact
 * intent and the empty HRP1 inventory. Once durable, recovery must finish
 * the old-to-new HTH2/capability replacement before ordinary startup audits
 * inspect either file. The caller holds the cross-process handoff lock. */
static std::array<uint8_t, handoff_rebind_commit_size>
handoff_rebind_commit_bytes(
    const std::array<uint8_t, handoff_rebind_size> &intent,
    const std::vector<uint8_t> &plan)
{
	std::array<uint8_t, handoff_rebind_commit_size> wire{};
	memcpy(wire.data(), "HRC1", 4);
	dtraced_wire_put_u32(wire.data() + 4, 1);
	memcpy(wire.data() + 8, intent.data(), intent.size());
	memcpy(wire.data() + 8 + intent.size(),
	    plan.data() + plan.size() - SHA256_DIGEST_LENGTH,
	    SHA256_DIGEST_LENGTH);
	(void)SHA256(wire.data(), wire.size() - SHA256_DIGEST_LENGTH,
	    wire.data() + wire.size() - SHA256_DIGEST_LENGTH);
	return (wire);
}

static bool
handoff_rebind_commit_validate(
    const std::array<uint8_t, handoff_rebind_commit_size> &wire,
    const std::array<uint8_t, 16> &token, durable_handoff &old,
    durable_handoff &proposed,
    std::array<uint8_t, handoff_rebind_size> &intent,
    std::vector<uint8_t> &expected_plan)
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (memcmp(wire.data(), "HRC1", 4) != 0 ||
	    dtraced_wire_get_u32(wire.data() + 4) != 1 ||
	    SHA256(wire.data(), wire.size() - sizeof(digest), digest) ==
	    nullptr || CRYPTO_memcmp(digest,
	    wire.data() + wire.size() - sizeof(digest), sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	memcpy(intent.data(), wire.data() + 8, intent.size());
	if (!handoff_claimed_from_bytes(intent.data() + 8, old) ||
	    old.token != token) {
		errno = EPROTO;
		return (false);
	}
	const uint16_t vmid = dtraced_wire_get_u16(intent.data() + 160);
	const uint64_t epoch = dtraced_wire_get_u64(intent.data() + 162);
	std::array<uint8_t, 16> session{};
	memcpy(session.data(), intent.data() + 170, session.size());
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    (vmid == old.destination_vmid &&
	    epoch == old.destination_epoch) ||
	    session == std::array<uint8_t, 16>{} ||
	    session == old.source_session ||
	    dtraced_wire_get_u32(intent.data() + 186) == UINT32_MAX ||
	    dtraced_wire_get_u32(intent.data() + 190) <= 1 ||
	    intent != handoff_rebind_bytes(old, vmid, epoch, session,
	    dtraced_wire_get_u32(intent.data() + 186),
	    dtraced_wire_get_u32(intent.data() + 190))) {
		errno = EPROTO;
		return (false);
	}
	source_journal_destination_plan empty;
	if (!handoff_rebind_plan_bytes(intent, empty, expected_plan))
		return (false);
	if (CRYPTO_memcmp(expected_plan.data() + expected_plan.size() -
	    SHA256_DIGEST_LENGTH, wire.data() + 8 + intent.size(),
	    SHA256_DIGEST_LENGTH) != 0) {
		errno = EPROTO;
		return (false);
	}
	proposed = old;
	proposed.destination_vmid = vmid;
	proposed.destination_epoch = epoch;
	return (true);
}

static int
handoff_rebind_done_read_at(int directory,
    const std::array<uint8_t, 16> &token,
    std::array<uint8_t, handoff_rebind_commit_size> *result,
    durable_handoff *old_result, durable_handoff *new_result)
{
	char name[54];
	if (!handoff_rebind_done_name(token, name))
		return (-1);
	std::array<uint8_t, handoff_rebind_commit_size> wire{};
	int present = handoff_fixed_read_at(directory, name, wire.data(),
	    wire.size());
	if (present != 1)
		return (present);
	durable_handoff old{}, proposed{};
	std::array<uint8_t, handoff_rebind_size> intent{};
	std::vector<uint8_t> plan;
	if (!handoff_rebind_commit_validate(wire, token, old, proposed,
	    intent, plan))
		return (-1);
	if (result != nullptr)
		*result = wire;
	if (old_result != nullptr)
		*old_result = old;
	if (new_result != nullptr)
		*new_result = proposed;
	return (1);
}

static int
handoff_rebind_done_claimed_at(int directory,
    const std::array<uint8_t, 16> &token)
{
	durable_handoff proposed{}, claimed{};
	int present = handoff_rebind_done_read_at(directory, token,
	    nullptr, nullptr, &proposed);
	if (present != 1)
		return (present);
	if (handoff_read_at(directory, token, handoff_phase::claimed,
	    claimed) != 1 || !handoff_same_destination(claimed, proposed) ||
	    handoff_capable_at(directory, proposed) != 1) {
		errno = EPROTO;
		return (-1);
	}
	return (1);
}

static int
handoff_rebind_commit_recover_at(int directory,
    const std::array<uint8_t, 16> &token)
{
	char commit_name[56], intent_name[49], plan_name[54],
	    claimed_name[44], capable_name[50];
	if (!handoff_rebind_commit_name(token, commit_name) ||
	    !handoff_rebind_name(token, intent_name) ||
	    !handoff_rebind_plan_name(token, plan_name) ||
	    !handoff_name(token, handoff_phase::claimed, claimed_name))
		return (-1);
	std::array<uint8_t, handoff_rebind_commit_size> wire{};
	int present = handoff_fixed_read_at(directory, commit_name,
	    wire.data(), wire.size());
	if (present != 1)
		return (present);
	std::array<uint8_t, handoff_rebind_size> intent{};
	durable_handoff old{}, proposed{};
	std::vector<uint8_t> expected_plan;
	if (!handoff_rebind_commit_validate(wire, token, old, proposed,
	    intent, expected_plan))
		return (-1);
	if (!handoff_capable_name(proposed, capable_name))
		return (-1);
	durable_handoff claimed{};
	int claim = handoff_read_at(directory, token,
	    handoff_phase::claimed, claimed);
	if (claim != 1) {
		if (claim == 0)
			errno = EPROTO;
		return (-1);
	}
	if (!handoff_same_destination(claimed, old) &&
	    !handoff_same_destination(claimed, proposed)) {
		errno = EPROTO;
		return (-1);
	}
	std::array<uint8_t, handoff_record_size> capable{};
	int has_capable = handoff_fixed_read_at(directory, capable_name,
	    capable.data(), capable.size());
	if (has_capable != 1) {
		if (has_capable == 0)
			errno = EPROTO;
		return (-1);
	}
	if (capable != handoff_bytes(old) &&
	    capable != handoff_bytes(proposed)) {
		errno = EPROTO;
		return (-1);
	}
	if (handoff_execution_start_at(directory, old) != 0 ||
	    handoff_rekey_applied_at(directory, old) != 0) {
		errno = EPROTO;
		return (-1);
	}
	std::array<uint8_t, handoff_rebind_size> on_disk_intent{};
	int has_intent = handoff_fixed_read_at(directory, intent_name,
	    on_disk_intent.data(), on_disk_intent.size());
	if (has_intent < 0)
		return (-1);
	if (has_intent == 1 && on_disk_intent != intent) {
		errno = EPROTO;
		return (-1);
	}
	std::vector<uint8_t> on_disk_plan;
	int has_plan = handoff_rebind_plan_read_at(directory, old, intent,
	    &on_disk_plan);
	if (has_plan < 0)
		return (-1);
	if ((has_plan == 1 && on_disk_plan != expected_plan) ||
	    (handoff_same_destination(claimed, old) &&
	    (has_intent != 1 || has_plan != 1))) {
		errno = EPROTO;
		return (-1);
	}
	const auto new_bytes = handoff_bytes(proposed);
	if (capable != new_bytes &&
	    !handoff_replace_at(directory, capable_name, new_bytes.data(),
	    new_bytes.size()))
		return (-1);
	if (!handoff_same_destination(claimed, proposed) &&
	    !handoff_replace_at(directory, claimed_name, new_bytes.data(),
	    new_bytes.size()))
		return (-1);
	if (has_plan == 1 &&
	    (unlinkat(directory, plan_name, 0) != 0 || fsync(directory) != 0))
		return (-1);
	if (has_intent == 1 &&
	    (unlinkat(directory, intent_name, 0) != 0 || fsync(directory) != 0))
		return (-1);
	char done_name[54];
	if (!handoff_rebind_done_name(token, done_name))
		return (-1);
	std::array<uint8_t, handoff_rebind_commit_size> previous_wire{};
	durable_handoff previous_proposed{};
	int done = handoff_rebind_done_read_at(directory, token,
	    &previous_wire, nullptr, &previous_proposed);
	if (done < 0)
		return (-1);
	if (done == 1 && previous_wire != wire &&
	    !handoff_same_destination(previous_proposed, old)) {
		errno = EPROTO;
		return (-1);
	}
	if (done == 0) {
		if (!handoff_publish_at(directory, done_name, wire.data(),
		    wire.size()))
			return (-1);
	} else if (previous_wire != wire) {
		if (!handoff_replace_at(directory, done_name, wire.data(),
		    wire.size()))
			return (-1);
	} else if (fsync(directory) != 0)
		return (-1);
	if (unlinkat(directory, commit_name, 0) != 0 || fsync(directory) != 0)
		return (-1);
	return (1);
}
/* HT-C END */

static bool
handoff_rebind_commits_recover_locked(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	std::vector<std::array<uint8_t, 16>> tokens, done_tokens;
	int error = 0;
	for (;;) {
		errno = 0;
		dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		bool commit = strncmp(entry->d_name,
		    ".handoff-rebind-commit.", 23) == 0;
		bool done = strncmp(entry->d_name,
		    ".handoff-rebind-done.", 21) == 0;
		if (!commit && !done)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		size_t prefix = commit ? 23 : 21;
		if (strlen(entry->d_name) != prefix + 32) {
			error = EPROTO;
			break;
		}
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(entry->d_name + prefix + 2 * i, 2,
			    octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		char canonical[56];
		if (!(commit ? handoff_rebind_commit_name(token, canonical) :
		    handoff_rebind_done_name(token, canonical)) ||
		    strcmp(entry->d_name, canonical) != 0) {
			error = EPROTO;
			break;
		}
		(commit ? tokens : done_tokens).push_back(token);
		/* HT-C END */
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error == 0)
		for (const auto &token : tokens)
			/* HT-C BEGIN: disabled trace continuity. */
			if (handoff_rebind_commit_recover_at(directory, token) != 1) {
				error = errno;
			break;
			}
			/* HT-C END */
	if (error == 0)
		for (const auto &token : done_tokens)
			/* HT-C BEGIN: disabled trace continuity. */
			if (handoff_rebind_done_claimed_at(directory, token) != 1) {
				error = errno == 0 ? EPROTO : errno;
			break;
			}
			/* HT-C END */
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
dir::stage_handoff_rebind(const durable_handoff &old,
    uint16_t new_vmid, uint64_t new_epoch,
    const std::array<uint8_t, 16> &new_session, uint32_t new_uid,
    uint32_t new_pid)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(old, handoff_phase::claimed) ||
	    new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 || new_session == std::array<uint8_t, 16>{} ||
	    new_uid == UINT32_MAX || new_pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, old.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, old)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	int capable = handoff_capable_at(this->dirfd, current);
	int started = capable == 1 ?
	    handoff_execution_start_at(this->dirfd, current) : -1;
	int applied = capable == 1 && started == 0 ?
	    handoff_rekey_applied_at(this->dirfd, current) : -1;
	if (capable != 1 || started != 0 || applied != 0) {
		if (capable == 0)
			errno = EOPNOTSUPP;
		else if (capable == 1 && (started == 1 || applied == 1))
			errno = EBUSY;
		return (false);
	}
	const auto expected = handoff_rebind_bytes(current, new_vmid,
	    new_epoch, new_session, new_uid, new_pid);
	std::array<uint8_t, handoff_rebind_size> intent{};
	int present = handoff_rebind_read_at(this->dirfd, current, &intent);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	if (intent != expected) {
		errno = EPERM;
		return (false);
	}
	std::vector<uint8_t> existing;
	present = handoff_rebind_plan_read_at(this->dirfd, current,
	    intent, &existing);
	if (present < 0)
		return (false);
	source_journal_cut cut;
	source_journal_destination_plan prior, replacement;
	int staged = source_journal_rebind_plan_locked(this->dirfd,
	    this->state, current, new_vmid, new_epoch, new_session,
	    new_uid, new_pid, cut, prior, replacement, nullptr,
	    present == 1);
	if (staged < 0 || !source_journal_rebind_capacity_locked(this->dirfd,
	    replacement))
		return (false);
	std::vector<uint8_t> wire;
	if (!handoff_rebind_plan_bytes(intent, replacement, wire))
		return (false);
	if (present == 1) {
		if (existing != wire) {
			errno = EBUSY;
			return (false);
		}
		return (fsync(this->dirfd) == 0);
	}
	char name[54];
	if (!handoff_rebind_plan_name(current.token, name))
		return (false);
	return (handoff_publish_at(this->dirfd, name,
	    wire.data(), wire.size()));
}

/* HRP1 is durable before the first write. Pending HTD5 receipts are inert;
 * a crash after any subset is repaired by an exact retry. KILL, cleanup,
 * ingress, and execution authority remain with the old claimed record. */
bool
dir::publish_handoff_rebind_pending(const durable_handoff &old,
    uint16_t new_vmid, uint64_t new_epoch,
    const std::array<uint8_t, 16> &new_session, uint32_t new_uid,
    uint32_t new_pid)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(old, handoff_phase::claimed) ||
	    new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 || new_session == std::array<uint8_t, 16>{} ||
	    new_uid == UINT32_MAX || new_pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, old.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, old)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	int capable = handoff_capable_at(this->dirfd, current);
	int started = capable == 1 ?
	    handoff_execution_start_at(this->dirfd, current) : -1;
	int applied = capable == 1 && started == 0 ?
	    handoff_rekey_applied_at(this->dirfd, current) : -1;
	if (capable != 1 || started != 0 || applied != 0) {
		if (capable == 0)
			errno = EOPNOTSUPP;
		else if (capable == 1 && (started == 1 || applied == 1))
			errno = EBUSY;
		return (false);
	}
	const auto expected = handoff_rebind_bytes(current, new_vmid,
	    new_epoch, new_session, new_uid, new_pid);
	std::array<uint8_t, handoff_rebind_size> intent{};
	int present = handoff_rebind_read_at(this->dirfd, current, &intent);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	if (intent != expected) {
		errno = EPERM;
		return (false);
	}
	std::vector<uint8_t> staged_wire;
	present = handoff_rebind_plan_read_at(this->dirfd, current,
	    intent, &staged_wire);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	source_journal_cut cut;
	source_journal_destination_plan prior, replacement;
	if (source_journal_rebind_plan_locked(this->dirfd,
	    this->state, current, new_vmid, new_epoch, new_session,
	    new_uid, new_pid, cut, prior, replacement, nullptr, true) < 0)
		return (false);
	if (!source_journal_rebind_capacity_locked(this->dirfd, replacement))
		return (false);
	std::vector<uint8_t> rebuilt;
	if (!handoff_rebind_plan_bytes(intent, replacement, rebuilt))
		return (false);
	if (rebuilt != staged_wire) {
		errno = EBUSY;
		return (false);
	}
	int count = delivery_record_count(this->dirfd);
	if (count < 0)
		return (false);
	size_t missing;
	if (!source_journal_pending_reconcile_locked(this->dirfd,
	    current, replacement, false, missing, &prior))
		return (false);
	if ((size_t)count > 16384 || missing > 16384 - (size_t)count) {
		errno = ENOSPC;
		return (false);
	}
	for (const auto &item : replacement.deliveries)
		if (!delivery_transition_at(this->dirfd,
		    item.state.record, delivery_phase::pending, false))
			return (false);
	return (fsync(this->dirfd) == 0);
}

bool
dir::commit_handoff_rebind_empty(const durable_handoff &old,
    uint16_t new_vmid, uint64_t new_epoch,
    const std::array<uint8_t, 16> &new_session, uint32_t new_uid,
    uint32_t new_pid, bool publish)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(old, handoff_phase::claimed) ||
	    new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 || new_session == std::array<uint8_t, 16>{} ||
	    new_uid == UINT32_MAX || new_pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, old.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, old)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	int capable = handoff_capable_at(this->dirfd, current);
	int started = capable == 1 ?
	    handoff_execution_start_at(this->dirfd, current) : -1;
	int applied = capable == 1 && started == 0 ?
	    handoff_rekey_applied_at(this->dirfd, current) : -1;
	if (capable != 1 || started != 0 || applied != 0) {
		if (capable == 0)
			errno = EOPNOTSUPP;
		else if (capable == 1 && (started == 1 || applied == 1))
			errno = EBUSY;
		return (false);
	}
	const auto expected = handoff_rebind_bytes(current, new_vmid,
	    new_epoch, new_session, new_uid, new_pid);
	std::array<uint8_t, handoff_rebind_size> intent{};
	int has_intent = handoff_rebind_read_at(this->dirfd, current,
	    &intent);
	if (has_intent != 1) {
		if (has_intent == 0)
			errno = ENOENT;
		return (false);
	}
	if (intent != expected) {
		errno = EPERM;
		return (false);
	}
	std::vector<uint8_t> staged_wire;
	int has_plan = handoff_rebind_plan_read_at(this->dirfd,
	    current, intent, &staged_wire);
	if (has_plan != 1) {
		if (has_plan == 0)
			errno = ENOENT;
		return (false);
	}
	source_journal_cut cut;
	source_journal_destination_plan prior, replacement;
	int staged = source_journal_rebind_plan_locked(this->dirfd,
	    this->state, current, new_vmid, new_epoch, new_session,
	    new_uid, new_pid, cut, prior, replacement, nullptr);
	if (staged < 0)
		return (false);
	/* The nonempty case needs an atomic journal-and-owner transaction; do
	 * not let an empty-looking replacement conceal source-side records. */
	if (staged != 0 || !cut.deliveries.empty() || !cut.kills.empty() ||
	    !cut.cleanups.empty() || prior.has_ingress ||
	    !prior.deliveries.empty() || !prior.pending_kills.empty() ||
	    !prior.queued_cleanups.empty() || !prior.revoked_sources.empty() ||
	    replacement.has_ingress || !replacement.deliveries.empty() ||
	    !replacement.pending_kills.empty() ||
	    !replacement.queued_cleanups.empty() ||
	    !replacement.revoked_sources.empty()) {
		errno = EOPNOTSUPP;
		return (false);
	}
	std::vector<uint8_t> rebuilt;
	if (!handoff_rebind_plan_bytes(intent, replacement, rebuilt))
		return (false);
	if (staged_wire != rebuilt) {
		errno = EPROTO;
		return (false);
	}
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	int error = handoff_epoch_retired_fd(fd,
	    current.destination_vmid, current.destination_epoch) ? 0 : errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	if (!publish)
		return (fsync(this->dirfd) == 0);
	char name[56];
	if (!handoff_rebind_commit_name(current.token, name))
		return (false);
	const auto commit = handoff_rebind_commit_bytes(intent, staged_wire);
	if (!handoff_publish_at(this->dirfd, name, commit.data(),
	    commit.size()))
		return (false);
	return (handoff_rebind_commit_recover_at(this->dirfd,
	    current.token) == 1);
}

bool
dir::handoff_rebind_empty_plan_ready(const durable_handoff &old,
    uint16_t new_vmid, uint64_t new_epoch,
    const std::array<uint8_t, 16> &new_session, uint32_t new_uid,
    uint32_t new_pid)
{
	return (commit_handoff_rebind_empty(old, new_vmid, new_epoch,
	    new_session, new_uid, new_pid, false));
}

/* Recover HRC2's immutable source and destination inventory without using
 * the current journal phase as authority. This must also work after the
 * claimed HTH2 changes or a pending HTD5 has been promoted. HRC2 is not an
 * execution lease. The caller holds the outbound publication/process locks. */
static bool
handoff_rebind_decision_v2_snapshot_locked(int directory,
    const std::array<uint8_t, 16> &token,
    const uint8_t wire[DTRACED_REBIND_DECISION_V2_SIZE],
    durable_handoff &old_result, durable_handoff &proposed_result,
    source_journal_destination_plan &replacement_result,
    bool &foreign_result,
    std::array<uint8_t, SHA256_DIGEST_LENGTH> &stage_digest_result)
{
	dtraced_rebind_decision_v2 decision{};
	durable_handoff old{};
	if (dtraced_rebind_decision_v2_decode(&decision, wire,
	    token.data()) != 0 ||
	    !handoff_claimed_from_bytes(decision.intent.data() + 8, old) ||
	    old.token != token) {
		errno = EPROTO;
		return (false);
	}
	const uint16_t vmid = dtraced_wire_get_u16(decision.intent.data() + 160);
	const uint64_t epoch = dtraced_wire_get_u64(decision.intent.data() + 162);
	std::array<uint8_t, 16> session{};
	memcpy(session.data(), decision.intent.data() + 170, session.size());
	const uint32_t uid = dtraced_wire_get_u32(decision.intent.data() + 186);
	const uint32_t pid = dtraced_wire_get_u32(decision.intent.data() + 190);
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    (vmid == old.destination_vmid && epoch == old.destination_epoch) ||
	    session == std::array<uint8_t, 16>{} ||
	    session == old.source_session || uid == UINT32_MAX || pid <= 1 ||
	    decision.intent != handoff_rebind_bytes(old, vmid, epoch,
	    session, uid, pid)) {
		errno = EPROTO;
		return (false);
	}
	std::vector<uint8_t> plan_wire;
	source_journal_destination_plan inventory;
	int present = handoff_rebind_plan_read_at(directory, old,
	    decision.intent, &plan_wire, &inventory);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	if (CRYPTO_memcmp(plan_wire.data() + plan_wire.size() -
	    SHA256_DIGEST_LENGTH, decision.plan_digest.data(),
	    SHA256_DIGEST_LENGTH) != 0) {
		errno = EPROTO;
		return (false);
	}
	source_journal_cut cut;
	host_ingress_transfer_bundle ingress;
	source_journal_stage_binding binding;
	std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
	int staged = source_journal_stage_load_locked(directory, old, cut,
	    ingress, &binding, &stage_digest);
	if (staged < 0)
		return (false);
	if ((staged == 1) != decision.foreign ||
	    stage_digest != decision.stage_digest ||
	    (staged == 1 && !binding.present) ||
	    (staged == 0 && !inventory.has_ingress &&
	    inventory.deliveries.empty() && inventory.pending_kills.empty() &&
	    inventory.queued_cleanups.empty() &&
	    inventory.revoked_sources.empty())) {
		errno = EPROTO;
		return (false);
	}
	if (staged == 1) {
		if (inventory.deliveries.size() > UINT32_MAX) {
			errno = E2BIG;
			return (false);
		}
		int ready = source_journal_ready_status_locked(directory, old,
		    stage_digest, (uint32_t)inventory.deliveries.size());
		if (ready != 1) {
			if (ready == 0)
				errno = EPROTO;
			return (false);
		}
	}
	durable_handoff proposed = old;
	proposed.destination_vmid = vmid;
	proposed.destination_epoch = epoch;
	/* A replay may see either side of the owner replacement, but neither
	 * the claimed HTH2 nor its capability witness may name a third owner.
	 * Read the files directly: handoff_state_at() can invoke commit recovery. */
	durable_handoff claimed{};
	if (handoff_read_at(directory, token, handoff_phase::claimed,
	    claimed) != 1 ||
	    (!handoff_same_destination(claimed, old) &&
	    !handoff_same_destination(claimed, proposed))) {
		errno = EPROTO;
		return (false);
	}
	char capable_name[50];
	std::array<uint8_t, handoff_record_size> capable{};
	if (!handoff_capable_name(old, capable_name) ||
	    handoff_fixed_read_at(directory, capable_name, capable.data(),
	    capable.size()) != 1 ||
	    (capable != handoff_bytes(old) &&
	    capable != handoff_bytes(proposed))) {
		errno = EPROTO;
		return (false);
	}
	old_result = old;
	proposed_result = proposed;
	replacement_result = std::move(inventory);
	foreign_result = decision.foreign;
	stage_digest_result = stage_digest;
	return (true);
}

/* Before HRC2 can be published, mutable source journals must still build
 * exactly the immutable HRP1 inventory, and every proposed HTD5 must be
 * pending. A future replay uses snapshot_locked above, not this precommit
 * census, after the first journal phase changes. */
static bool
handoff_rebind_decision_v2_recover_locked(int directory, state *control,
    const std::array<uint8_t, 16> &token,
    const uint8_t wire[DTRACED_REBIND_DECISION_V2_SIZE],
    durable_handoff &old_result, durable_handoff &proposed_result,
    source_journal_destination_plan &replacement_result)
{
	durable_handoff old{}, proposed{};
	source_journal_destination_plan inventory;
	bool foreign;
	std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
	if (!handoff_rebind_decision_v2_snapshot_locked(directory, token,
	    wire, old, proposed, inventory, foreign, stage_digest))
		return (false);
	dtraced_rebind_decision_v2 decision{};
	if (dtraced_rebind_decision_v2_decode(&decision, wire,
	    token.data()) != 0)
		return (false);
	std::array<uint8_t, 16> session{};
	memcpy(session.data(), decision.intent.data() + 170, session.size());
	source_journal_cut cut;
	source_journal_destination_plan prior, replacement;
	std::array<uint8_t, SHA256_DIGEST_LENGTH> current_stage_digest{};
	int staged = source_journal_rebind_plan_locked(directory, control,
	    old, proposed.destination_vmid, proposed.destination_epoch,
	    session, dtraced_wire_get_u32(decision.intent.data() + 186),
	    dtraced_wire_get_u32(decision.intent.data() + 190),
	    cut, prior, replacement, nullptr, true, &current_stage_digest);
	if (staged < 0)
		return (false);
	std::vector<uint8_t> expected, rebuilt;
	if ((staged == 1) != foreign ||
	    current_stage_digest != stage_digest ||
	    !handoff_rebind_plan_bytes(decision.intent, inventory, expected) ||
	    !handoff_rebind_plan_bytes(decision.intent, replacement, rebuilt))
		return (false);
	if (rebuilt != expected) {
		errno = EPROTO;
		return (false);
	}
	size_t missing;
	if (!source_journal_pending_reconcile_locked(directory, old,
	    replacement, false, missing, &prior))
		return (false);
	if (missing != 0) {
		errno = EBUSY;
		return (false);
	}
	old_result = old;
	proposed_result = proposed;
	replacement_result = std::move(replacement);
	return (true);
}

/* This is a read-only boundary after PENDING, not the HRC2 decision. It
 * proves the entire proposed receipt census against HRP1 while the old
 * claim still owns every executable record. A later decision must repeat
 * the capacity and retirement checks under this same process lock. */
bool
dir::handoff_rebind_nonempty_preflight(const durable_handoff &old,
    uint16_t new_vmid, uint64_t new_epoch,
    const std::array<uint8_t, 16> &new_session, uint32_t new_uid,
    uint32_t new_pid)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(old, handoff_phase::claimed) ||
	    new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 || new_session == std::array<uint8_t, 16>{} ||
	    new_uid == UINT32_MAX || new_pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, old.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, old)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	int capable = handoff_capable_at(this->dirfd, current);
	int started = capable == 1 ?
	    handoff_execution_start_at(this->dirfd, current) : -1;
	int applied = capable == 1 && started == 0 ?
	    handoff_rekey_applied_at(this->dirfd, current) : -1;
	if (capable != 1 || started != 0 || applied != 0) {
		if (capable == 0)
			errno = EOPNOTSUPP;
		else if (capable == 1 && (started == 1 || applied == 1))
			errno = EBUSY;
		return (false);
	}
	const auto expected = handoff_rebind_bytes(current, new_vmid,
	    new_epoch, new_session, new_uid, new_pid);
	std::array<uint8_t, handoff_rebind_size> intent{};
	int present = handoff_rebind_read_at(this->dirfd, current, &intent);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	if (intent != expected) {
		errno = EPERM;
		return (false);
	}
	std::vector<uint8_t> staged_wire;
	present = handoff_rebind_plan_read_at(this->dirfd, current,
	    intent, &staged_wire);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	source_journal_cut cut;
	source_journal_destination_plan prior, replacement;
	std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
	int staged = source_journal_rebind_plan_locked(this->dirfd,
	    this->state, current, new_vmid, new_epoch, new_session,
	    new_uid, new_pid, cut, prior, replacement, nullptr, true,
	    &stage_digest);
	if (staged < 0)
		return (false);
	if (staged == 0 && cut.deliveries.empty() && cut.kills.empty() &&
	    cut.cleanups.empty() && !prior.has_ingress &&
	    prior.deliveries.empty() && prior.pending_kills.empty() &&
	    prior.queued_cleanups.empty() && prior.revoked_sources.empty() &&
	    !replacement.has_ingress && replacement.deliveries.empty() &&
	    replacement.pending_kills.empty() &&
	    replacement.queued_cleanups.empty() &&
	    replacement.revoked_sources.empty()) {
		errno = EOPNOTSUPP;
		return (false);
	}
	std::vector<uint8_t> rebuilt;
	if (!handoff_rebind_plan_bytes(intent, replacement, rebuilt))
		return (false);
	if (staged_wire != rebuilt) {
		errno = EPROTO;
		return (false);
	}
	/* Form the exact HRC2 decision candidate from the same HJB1 read used
	 * to reconstruct HRP1. This remains memory-only until journal replay
	 * and owner replacement have a recoverable transaction. */
	dtraced_rebind_decision_v2 decision{};
	decision.intent = intent;
	memcpy(decision.plan_digest.data(), staged_wire.data() +
	    staged_wire.size() - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
	decision.stage_digest = stage_digest;
	decision.foreign = staged == 1;
	std::array<uint8_t, DTRACED_REBIND_DECISION_V2_SIZE> candidate{};
	if (dtraced_rebind_decision_v2_encode(candidate.data(), decision) != 0)
		return (false);
	durable_handoff recovered_old{}, proposed{};
	source_journal_destination_plan recovered_replacement;
	if (!handoff_rebind_decision_v2_recover_locked(this->dirfd,
	    this->state, current.token, candidate.data(), recovered_old,
	    proposed, recovered_replacement))
		return (false);
	if (!handoff_same_destination(recovered_old, current) ||
	    proposed.destination_vmid != new_vmid ||
	    proposed.destination_epoch != new_epoch) {
		errno = EPROTO;
		return (false);
	}
	if (!source_journal_rebind_capacity_locked(this->dirfd,
	    recovered_replacement))
		return (false);
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	int error = handoff_epoch_retired_fd(fd,
	    current.destination_vmid, current.destination_epoch) ? 0 : errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (fsync(this->dirfd) == 0);
}

bool
dir::handoff_rebind_empty_done(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &session, uint32_t uid, uint32_t pid)
{
	if (!handoff_valid(claimed, handoff_phase::claimed) ||
	    session == std::array<uint8_t, 16>{} ||
	    uid == UINT32_MAX || pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, claimed.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, claimed)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	std::array<uint8_t, handoff_rebind_commit_size> wire{};
	durable_handoff proposed{};
	int done = handoff_rebind_done_read_at(this->dirfd, claimed.token,
	    &wire, nullptr, &proposed);
	if (done != 1) {
		if (done == 0)
			errno = ENOENT;
		return (false);
	}
	const uint8_t *intent = wire.data() + 8;
	if (!handoff_same_destination(proposed, current) ||
	    memcmp(intent + 170, session.data(), session.size()) != 0 ||
	    dtraced_wire_get_u32(intent + 186) != uid ||
	    dtraced_wire_get_u32(intent + 190) != pid) {
		errno = EPERM;
		return (false);
	}
	return (fsync(this->dirfd) == 0);
}

/* Caller holds the process and local locks. Before any removal, this helper
 * independently proves that both old and proposed VMM epochs are retired.
 * Keep HRI1/HRP1 durable until every proposed receipt is absent. */
static bool
handoff_rebind_pending_reconcile_locked(int directory, state *control,
    const durable_handoff &current,
    const std::array<uint8_t, handoff_rebind_size> &intent,
    const std::vector<uint8_t> &staged_wire, bool remove_pending)
{
	std::array<uint8_t, 16> session{};
	memcpy(session.data(), intent.data() + 170, 16);
	source_journal_cut cut;
	source_journal_destination_plan prior, replacement;
	if (source_journal_rebind_plan_locked(directory,
	    control, current,
	    dtraced_wire_get_u16(intent.data() + 160),
	    dtraced_wire_get_u64(intent.data() + 162), session,
	    dtraced_wire_get_u32(intent.data() + 186),
	    dtraced_wire_get_u32(intent.data() + 190),
	    cut, prior, replacement, nullptr, true) < 0)
		return (false);
	std::vector<uint8_t> rebuilt;
	if (!handoff_rebind_plan_bytes(intent, replacement, rebuilt))
		return (false);
	if (rebuilt != staged_wire) {
		errno = EPROTO;
		return (false);
	}
	for (const auto &item : replacement.deliveries) {
		int status = delivery_record_status_at(directory,
		    item.state.record);
		if (status < 0)
			return (false);
		if (status != 0 && status != (int)delivery_phase::pending) {
			errno = EBUSY;
			return (false);
		}
	}
	if (!remove_pending)
		return (fsync(directory) == 0);
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	int error = handoff_epoch_retired_fd(fd,
	    current.destination_vmid, current.destination_epoch) ? 0 : errno;
	if (error == 0 && !handoff_epoch_retired_fd(fd,
	    dtraced_wire_get_u16(intent.data() + 160),
	    dtraced_wire_get_u64(intent.data() + 162)))
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	for (const auto &item : replacement.deliveries) {
		char name[80];
		delivery_record_name(item.state.record,
		    delivery_phase::pending, name);
		if (unlinkat(directory, name, 0) != 0 && errno != ENOENT)
			return (false);
	}
	return (fsync(directory) == 0);
}

/* Cancel only the inert proposed receipts. Every record is checked before
 * the first unlink, so a guest-visible phase can never be discarded. HRP1
 * and HRI1 remain until a separate BEGIN chooses the next incarnation. */
bool
dir::cancel_handoff_rebind_pending(const durable_handoff &old)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(old, handoff_phase::claimed)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, old.token, current);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(current, old)) {
		errno = phase < 0 ? errno : phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	std::array<uint8_t, handoff_rebind_size> intent{};
	int present = handoff_rebind_read_at(this->dirfd, current, &intent);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	std::vector<uint8_t> staged_wire;
	present = handoff_rebind_plan_read_at(this->dirfd, current,
	    intent, &staged_wire);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (false);
	int error = handoff_epoch_retired_fd(fd,
	    current.destination_vmid, current.destination_epoch) ? 0 : errno;
	if (error == 0 && !handoff_epoch_retired_fd(fd,
	    dtraced_wire_get_u16(intent.data() + 160),
	    dtraced_wire_get_u64(intent.data() + 162)))
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (handoff_rebind_pending_reconcile_locked(this->dirfd,
	    this->state, current, intent, staged_wire, true));
}
/* HT-C END */

static bool
handoff_rebind_plans_audit_locked(int directory, state *control)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	for (;;) {
		errno = 0;
		dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		const char *name = entry->d_name;
		if (strncmp(name, ".handoff-rebind-plan.", 21) != 0)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		if (strlen(name) != 53) {
			error = EPROTO;
			break;
		}
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(name + 21 + 2 * i, 2, octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		char canonical[54];
		if (!handoff_rebind_plan_name(token, canonical) ||
		    strcmp(name, canonical) != 0) {
			error = EPROTO;
			break;
		}
		durable_handoff old{};
		int phase = handoff_state_at(directory, token, old);
		if (phase != (int)handoff_phase::claimed) {
			error = phase < 0 && errno != EINVAL ? errno : EPROTO;
			break;
		}
		std::array<uint8_t, handoff_rebind_size> intent{};
		std::vector<uint8_t> staged_wire;
		if (handoff_rebind_read_at(directory, old, &intent) != 1 ||
		    handoff_rebind_plan_read_at(directory, old, intent,
		    &staged_wire) != 1) {
			error = errno == ENOENT ? EPROTO : errno;
			break;
		}
		if (control != nullptr) {
			std::array<uint8_t, 16> session{};
			memcpy(session.data(), intent.data() + 170, 16);
			source_journal_cut cut;
			source_journal_destination_plan prior, replacement;
			if (source_journal_rebind_plan_locked(directory, control,
			    old, dtraced_wire_get_u16(intent.data() + 160),
			    dtraced_wire_get_u64(intent.data() + 162), session,
			    dtraced_wire_get_u32(intent.data() + 186),
			    dtraced_wire_get_u32(intent.data() + 190),
			    cut, prior, replacement, nullptr, true) < 0) {
				error = errno;
				break;
			}
			std::vector<uint8_t> rebuilt;
			if (!handoff_rebind_plan_bytes(intent, replacement,
			    rebuilt)) {
				error = errno;
				break;
			}
			if (rebuilt != staged_wire) {
				error = EPROTO;
				break;
			}
		}
		/* HT-C END */
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
int
dir::claimed_source_journal_status(const durable_handoff &claim,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    bool require_replays)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(claim, handoff_phase::claimed) ||
	    destination_session == std::array<uint8_t, 16>{} ||
	    destination_uid == UINT32_MAX || destination_pid <= 1) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff active{};
	int phase = handoff_state_at(this->dirfd, claim.token, active);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::claimed ||
	    !handoff_same_destination(active, claim)) {
		errno = phase == 0 ? ENOENT :
		    phase == (int)handoff_phase::claimed ? EPROTO : EBUSY;
		return (-1);
	}
	source_journal_cut cut;
	source_journal_destination_plan plan;
	int staged = source_journal_claimed_plan_locked(this->dirfd,
	    this->state, active, cut, plan);
	if (staged != 1)
		return (staged);
	if (plan.has_ingress) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	host_ingress_transfer_bundle ingress;
	source_journal_stage_binding binding;
	int loaded = source_journal_stage_load_locked(this->dirfd, active,
	    cut, ingress, &binding);
	if (loaded != 1 || !binding.present) {
		if (loaded == 0 || !binding.present)
			errno = EPROTO;
		return (-1);
	}
	if (binding.session != destination_session ||
	    binding.uid != destination_uid ||
	    binding.pid != destination_pid) {
		errno = EPERM;
		return (-1);
	}
	if (require_replays) {
		bool pending = false;
		for (const auto &item : plan.deliveries) {
			int status = delivery_record_status_at(this->dirfd,
			    item.state.record);
			if (status < 0)
				return (-1);
			if (status == (int)delivery_phase::pending)
				pending = true;
			else if (status != (int)delivery_phase::accepted &&
			    status != (int)delivery_phase::installed &&
			    status != (int)delivery_phase::terminal) {
				errno = EPROTO;
				return (-1);
			}
		}
		if (fsync(this->dirfd) != 0)
			return (-1);
		return (pending ? 1 : 2);
	}
	return (fsync(this->dirfd) == 0 ? 1 : -1);
}

/* Every imported send and ACK must agree with one claimed HJB1 member.
 * The caller owns the outbound publish and handoff process locks. */
static bool
claimed_source_journal_delivery_locked(int directory, state *control,
    const durable_delivery &record, source_journal_destination_plan &plan,
    const source_journal_delivery *&found)
{
	found = nullptr;
	durable_handoff ticket{};
	int phase = handoff_state_at(directory, record.handoff_token, ticket);
	if (phase < 0)
		return (false);
	if (phase != (int)handoff_phase::claimed) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (record.vmid != ticket.destination_vmid ||
	    record.epoch != ticket.destination_epoch ||
	    record.source_session != ticket.source_session) {
		errno = EPROTO;
		return (false);
	}
	source_journal_cut cut;
	int staged = source_journal_claimed_plan_locked(directory,
	    control, ticket, cut, plan);
	if (staged != 1) {
		if (staged == 0)
			errno = ENOENT;
		return (false);
	}
	for (const auto &item : plan.deliveries) {
		if (item.state.record.program_id != record.program_id)
			continue;
		if (found != nullptr ||
		    delivery_record_bytes(item.state.record) !=
		    delivery_record_bytes(record)) {
			errno = EPROTO;
			return (false);
		}
		found = &item;
	}
	if (found == nullptr) {
		errno = ENOENT;
		return (false);
	}
	return (true);
}

/* A host replay must use the transferred HTD5 identity and verified HJB1
 * bytes. Keep the payload private until the ticket has crossed the source
 * release and destination claim barriers. The caller receives bare ELF so
 * an old source-VM target envelope cannot route it away from the new VM. */
int
dir::claimed_source_journal_replay_payload(const durable_delivery &record,
    std::vector<uint8_t> &result)
{
	result.clear();
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this || record.scope != 0 ||
	    record.journal_version != 5 || !delivery_record_valid(record)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	source_journal_destination_plan plan;
	const source_journal_delivery *found = nullptr;
	if (!claimed_source_journal_delivery_locked(this->dirfd,
	    this->state, record, plan, found))
		return (-1);
	int status = delivery_record_status_at(this->dirfd, record);
	if (status < 0)
		return (-1);
	if (status != (int)delivery_phase::pending) {
		errno = EBUSY;
		return (-1);
	}
	if (!validate_host_delivery_payload(record, found->payload))
		return (-1);
	try {
		std::vector<uint8_t> bare = found->payload;
		if (memcmp(bare.data(), "\177ELF", 4) != 0)
			bare.erase(bare.begin(), bare.begin() +
			    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE);
		result.swap(bare);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
	return (1);
}

/* A guest queue ACK advances only the exact imported receipt. Recheck the
 * claimed source cut and destination revocation under the handoff lock; the
 * generic HTD5 transition remains unavailable to an ordinary forwarder. */
bool
dir::accept_claimed_source_journal_replay(const durable_delivery &record)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this || record.scope != 0 ||
	    record.journal_version != 5 || !delivery_record_valid(record)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	source_journal_destination_plan plan;
	const source_journal_delivery *found = nullptr;
	if (!claimed_source_journal_delivery_locked(this->dirfd,
	    this->state, record, plan, found) ||
	    !validate_host_delivery_payload(record, found->payload))
		return (false);
	int current = delivery_record_status_at(this->dirfd, record);
	if (current < 0)
		return (false);
	if (current != (int)delivery_phase::pending &&
	    current != (int)delivery_phase::accepted) {
		errno = current == 0 ? ENOENT : EBUSY;
		return (false);
	}
	int revoked = source_revoked_at(this->dirfd,
	    record.source_id.data(), record.vmid, record.epoch);
	if (revoked < 0)
		return (false);
	if (revoked != 0) {
		errno = ECANCELED;
		return (false);
	}
	return (delivery_transition_at(this->dirfd, record,
	    delivery_phase::accepted, false));
}

/* The first destination write is an inert receipt. A retry may find some
 * receipts already durable; it must agree with every byte before continuing.
 * The ELF payload remains private in HJB1 until a later activation step. */
bool
dir::import_source_journal_pending(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(reserved, handoff_phase::reserved) ||
	    destination_session == std::array<uint8_t, 16>{} ||
	    destination_session == reserved.source_session ||
	    destination_uid == UINT32_MAX || destination_pid <= 1) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, reserved.token, current);
	if (phase < 0)
		return (false);
	if (phase != (int)handoff_phase::reserved ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (!handoff_release_authority_locked(this->dirfd,
	    this->state, current))
		return (false);
	source_journal_cut cut;
	host_ingress_transfer_bundle ingress;
	source_journal_stage_binding binding;
	std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
	int staged = source_journal_stage_load_locked(this->dirfd,
	    current, cut, ingress, &binding, &stage_digest);
	if (staged != 1) {
		if (staged == 0)
			errno = ENOENT;
		return (false);
	}
	if (!binding.present) {
		errno = EOPNOTSUPP;
		return (false);
	}
	if (binding.session != destination_session ||
	    binding.uid != destination_uid ||
	    binding.pid != destination_pid) {
		errno = EPERM;
		return (false);
	}
	source_journal_destination_plan plan;
	if (!source_journal_destination_plan_locked(this->dirfd, current,
	    cut, ingress, binding, true, plan))
		return (false);
	if (plan.deliveries.size() > UINT32_MAX) {
		errno = E2BIG;
		return (false);
	}
	int count = delivery_record_count(this->dirfd);
	if (count < 0)
		return (false);
	size_t needed;
	if (!source_journal_pending_reconcile_locked(this->dirfd,
	    current, plan, false, needed))
		return (false);
	int ready = source_journal_ready_status_locked(this->dirfd, current,
	    stage_digest, (uint32_t)plan.deliveries.size());
	if (ready < 0)
		return (false);
	if (ready == 1 && needed != 0) {
		errno = EPROTO;
		return (false);
	}
	if ((size_t)count > 16384 || needed > 16384 - (size_t)count) {
		errno = ENOSPC;
		return (false);
	}
	for (const auto &item : plan.deliveries)
		if (!delivery_transition_at(this->dirfd, item.state.record,
		    delivery_phase::pending, false))
			return (false);
	return (source_journal_ready_publish_locked(this->dirfd,
	    current, stage_digest, (uint32_t)plan.deliveries.size()));
}

int
dir::source_journal_pending_status(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    source_journal_destination_plan &result)
{
	result = {};
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    !handoff_valid(reserved, handoff_phase::reserved) ||
	    destination_session == std::array<uint8_t, 16>{} ||
	    destination_session == reserved.source_session ||
	    destination_uid == UINT32_MAX || destination_pid <= 1) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(this->dirfd, reserved.token, current);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::reserved ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	if (!handoff_release_authority_locked(this->dirfd,
	    this->state, current))
		return (-1);
	source_journal_cut cut;
	host_ingress_transfer_bundle ingress;
	source_journal_stage_binding binding;
	std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
	int staged = source_journal_stage_load_locked(this->dirfd,
	    current, cut, ingress, &binding, &stage_digest);
	if (staged != 1) {
		if (staged == 0) {
			char name[39];
			if (!source_journal_ready_name(current.token, name))
				return (-1);
			std::vector<uint8_t> orphan;
			int present = host_transfer_stage_read_at(this->dirfd,
			    name, orphan);
			if (present != 0) {
				if (present == 1)
					errno = EPROTO;
				return (-1);
			}
		}
		return (staged);
	}
	if (!binding.present) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	if (binding.session != destination_session ||
	    binding.uid != destination_uid ||
	    binding.pid != destination_pid) {
		errno = EPERM;
		return (-1);
	}
	source_journal_destination_plan plan;
	if (!source_journal_destination_plan_locked(this->dirfd, current,
	    cut, ingress, binding, true, plan))
		return (-1);
	if (plan.deliveries.size() > UINT32_MAX) {
		errno = E2BIG;
		return (-1);
	}
	size_t missing;
	if (!source_journal_pending_reconcile_locked(this->dirfd,
	    current, plan, false, missing) || fsync(this->dirfd) != 0)
		return (-1);
	int ready = source_journal_ready_status_locked(this->dirfd,
	    current, stage_digest, (uint32_t)plan.deliveries.size());
	if (ready < 0)
		return (-1);
	if (ready == 1 && missing != 0) {
		errno = EPROTO;
		return (-1);
	}
	result = std::move(plan);
	return (ready == 1 ? 2 : 1);
}

/* CANCEL is retryable after a partial import or crash. Check every receipt
 * before removing any, and leave the HJB1 stage until deletion reaches disk. */
static bool
source_journal_pending_rollback_locked(int directory,
    const durable_handoff &current)
{
	source_journal_cut cut;
	host_ingress_transfer_bundle ingress;
	source_journal_stage_binding binding;
	std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
	int staged = source_journal_stage_load_locked(directory, current,
	    cut, ingress, &binding, &stage_digest);
	if (staged < 0)
		return (false);
	source_journal_destination_plan plan;
	if (staged == 1 && binding.present &&
	    !source_journal_destination_plan_locked(directory, current, cut,
	    ingress, binding, false, plan))
		return (false);
	char ready_name[39];
	if (!source_journal_ready_name(current.token, ready_name))
		return (false);
	int ready;
	if (staged == 1 && binding.present) {
		if (plan.deliveries.size() > UINT32_MAX) {
			errno = E2BIG;
			return (false);
		}
		ready = source_journal_ready_status_locked(directory, current,
		    stage_digest, (uint32_t)plan.deliveries.size());
	} else {
		std::vector<uint8_t> orphan;
		ready = host_transfer_stage_read_at(directory, ready_name, orphan);
		if (ready == 1) {
			errno = EPROTO;
			return (false);
		}
	}
	if (ready < 0)
		return (false);
	std::vector<durable_delivery_state> existing;
	if (!list_deliveries_at(directory, existing))
		return (false);
	std::map<std::pair<std::array<uint8_t, 16>, uint64_t>,
	    durable_delivery> expected;
	try {
		for (const auto &item : plan.deliveries) {
			const auto &record = item.state.record;
			if (!expected.emplace(std::make_pair(record.session_id,
			    record.delivery_id), record).second) {
				errno = EPROTO;
				return (false);
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	size_t matched = 0;
	for (const auto &entry : existing) {
		auto key = std::make_pair(entry.record.session_id,
		    entry.record.delivery_id);
		auto found = expected.find(key);
		if (entry.record.handoff_token != current.token &&
		    found == expected.end())
			continue;
		if (staged != 1 || !binding.present ||
		    found == expected.end() ||
		    delivery_record_bytes(entry.record) !=
		    delivery_record_bytes(found->second)) {
			errno = EPROTO;
			return (false);
		}
		if (entry.phase != delivery_phase::pending) {
			errno = EBUSY;
			return (false);
		}
		matched++;
	}
	if (ready == 1 && matched != plan.deliveries.size()) {
		errno = EPROTO;
		return (false);
	}
	if (ready == 1 &&
	    (unlinkat(directory, ready_name, 0) != 0 ||
	    fsync(directory) != 0))
		return (false);
	for (const auto &item : plan.deliveries) {
		char name[80];
		delivery_record_name(item.state.record,
		    delivery_phase::pending, name);
		if (unlinkat(directory, name, 0) != 0 && errno != ENOENT)
			return (false);
	}
	return (fsync(directory) == 0);
}

/* HRP1 is audited before the HJB1/HJR1 scans. A staged rebind deliberately
 * has two HTD5 receipts for one ticket, so the ordinary single-owner census
 * is no longer applicable. Require each old receipt here; the HRP1 audit
 * checks the exact old/proposed census and inventory. */
static bool
source_journal_audit_receipts_locked(int directory,
    const durable_handoff &ticket, int phase,
    const source_journal_destination_plan &plan, size_t &missing)
{
	missing = 0;
	if (phase == (int)handoff_phase::claimed) {
		std::array<uint8_t, handoff_rebind_size> intent{};
		int present = handoff_rebind_read_at(directory, ticket, &intent);
		if (present < 0)
			return (false);
		if (present == 1) {
			int staged = handoff_rebind_plan_read_at(directory, ticket,
			    intent, nullptr);
			if (staged < 0)
				return (false);
			if (staged == 1) {
				for (const auto &item : plan.deliveries) {
					int status = delivery_record_status_at(directory,
					    item.state.record);
					if (status < 0)
						return (false);
					if (status != (int)delivery_phase::pending &&
					    status != (int)delivery_phase::accepted &&
					    status != (int)delivery_phase::installed &&
					    status != (int)delivery_phase::terminal) {
						errno = EPROTO;
						return (false);
					}
				}
				return (true);
			}
		}
	}
	return (source_journal_pending_reconcile_locked(directory, ticket,
	    plan, phase != (int)handoff_phase::reserved, missing));
}
/* HT-C END */

/* Startup must not silently accept an orphan or corrupt private source
 * journal. The outbound handoff lock is held across this entire scan so a
 * publisher cannot change its ticket or stage while recovery validates it. */
static bool
source_journal_stages_audit_locked(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	for (;;) {
		errno = 0;
		dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		const char *name = entry->d_name;
		if (strncmp(name, ".hjb1.", 6) != 0)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		if (strlen(name) != 38) {
			error = EPROTO;
			break;
		}
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(name + 6 + i * 2, 2, octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		char canonical[39];
		if (!source_journal_stage_name(token, canonical) ||
		    strcmp(name, canonical) != 0) {
			error = EPROTO;
			break;
		}
		durable_handoff reserved{};
		int phase = handoff_state_at(directory, token, reserved);
		if (phase != (int)handoff_phase::reserved &&
		    phase != (int)handoff_phase::mutating &&
		    phase != (int)handoff_phase::claimed) {
			error = phase < 0 ? errno : EPROTO;
			break;
		}
		std::vector<uint8_t> stage, transfer;
		source_journal_stage_binding binding;
		if (host_transfer_stage_read_at(directory, name, stage) != 1 ||
		    !source_journal_stage_decode(reserved, stage, transfer,
		    binding)) {
			error = errno != 0 ? errno : EPROTO;
			break;
		}
		source_journal_cut journal;
		host_ingress_transfer_bundle ingress;
		if (!dir::decode_source_journal_transfer_wire(reserved, transfer,
		    journal, ingress)) {
			error = errno != 0 ? errno : EPROTO;
			break;
		}
		if (phase != (int)handoff_phase::reserved) {
			if (!binding.present) {
				error = EPROTO;
				break;
			}
			source_journal_destination_plan plan;
			if (!source_journal_destination_plan_locked(directory,
			    reserved, journal, ingress, binding, false, plan)) {
				error = errno;
				break;
			}
			if (plan.deliveries.size() > UINT32_MAX) {
				error = E2BIG;
				break;
			}
			std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
			memcpy(digest.data(), stage.data() + stage.size() -
			    digest.size(), digest.size());
			int ready = source_journal_ready_status_locked(directory,
			    reserved, digest, (uint32_t)plan.deliveries.size());
			if (ready != 1) {
				error = ready < 0 ? errno : EPROTO;
				break;
			}
			size_t missing;
			if (!source_journal_audit_receipts_locked(directory,
			    reserved, phase, plan, missing)) {
				error = errno;
				break;
			}
			if (missing != 0) {
				error = EPROTO;
				break;
			}
		}
		/* HT-C END */
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	/* A reserved-ticket HTD5 must be one of the exact pending receipts
	 * reconstructed from HJB1. Partial imports are valid after a crash; a
	 * receipt with no stage, changed bytes, or an advanced phase is not. */
	std::vector<durable_delivery_state> records;
	if (!list_deliveries_at(directory, records))
		return (false);
	using delivery_key = std::pair<std::array<uint8_t, 16>, uint64_t>;
	std::map<std::array<uint8_t, 16>,
	    std::map<delivery_key, durable_delivery>> staged_records;
	try {
		for (const auto &entry : records) {
			const durable_delivery &record = entry.record;
			if (record.scope != 0 || record.journal_version != 5)
				continue;
			/* HT-C BEGIN: disabled trace continuity. */
			durable_handoff reserved{};
			int phase = handoff_state_at(directory,
			    record.handoff_token, reserved);
			if (phase < 0)
				return (false);
			if (phase == 0 ||
			    phase == (int)handoff_phase::committed) {
				errno = EPROTO;
				return (false);
			}
			if (phase != (int)handoff_phase::reserved)
				continue;
			if (entry.phase != delivery_phase::pending) {
				errno = EPROTO;
				return (false);
			}
			auto found = staged_records.find(record.handoff_token);
			if (found == staged_records.end()) {
				source_journal_cut journal;
				host_ingress_transfer_bundle ingress;
				source_journal_stage_binding binding;
				int staged = source_journal_stage_load_locked(
				    directory, reserved, journal, ingress, &binding);
				if (staged != 1 || !binding.present) {
					if (staged == 0 ||
					    (staged == 1 && !binding.present))
						errno = EPROTO;
					return (false);
				}
				source_journal_destination_plan plan;
				if (!source_journal_destination_plan_locked(directory,
				    reserved, journal, ingress, binding, false, plan))
					return (false);
				std::map<delivery_key, durable_delivery> expected;
				for (const auto &item : plan.deliveries) {
					const auto &candidate = item.state.record;
					if (!expected.emplace(std::make_pair(
					    candidate.session_id,
					    candidate.delivery_id), candidate).second) {
						errno = EPROTO;
						return (false);
					}
				}
				found = staged_records.emplace(
				    record.handoff_token, std::move(expected)).first;
			}
			auto expected = found->second.find(std::make_pair(
			    record.session_id, record.delivery_id));
			if (expected == found->second.end() ||
			    delivery_record_bytes(record) !=
			    delivery_record_bytes(expected->second)) {
				errno = EPROTO;
				return (false);
			}
			/* HT-C END */
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	return (true);
}

/* HJR1 may exist even for a cut with no deliveries. Audit every marker,
 * including those that have no HTD5 receipt to lead the stage scan to it. */
static bool
source_journal_ready_audit_locked(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	int error = 0;
	for (;;) {
		errno = 0;
		dirent *entry = readdir(scan);
		if (entry == nullptr) {
			error = errno;
			break;
		}
		const char *name = entry->d_name;
		if (strncmp(name, ".hjr1.", 6) != 0)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		if (strlen(name) != 38) {
			error = EPROTO;
			break;
		}
		std::array<uint8_t, 16> token{};
		for (size_t i = 0; i < token.size(); i++) {
			uint64_t octet;
			if (!parse_hex(name + 6 + i * 2, 2, octet)) {
				error = EPROTO;
				break;
			}
			token[i] = (uint8_t)octet;
		}
		if (error != 0)
			break;
		char canonical[39];
		if (!source_journal_ready_name(token, canonical) ||
		    strcmp(name, canonical) != 0) {
			error = EPROTO;
			break;
		}
		durable_handoff reserved{};
		int phase = handoff_state_at(directory, token, reserved);
		if (phase != (int)handoff_phase::reserved &&
		    phase != (int)handoff_phase::mutating &&
		    phase != (int)handoff_phase::claimed) {
			error = phase < 0 ? errno : EPROTO;
			break;
		}
		source_journal_cut cut;
		host_ingress_transfer_bundle ingress;
		source_journal_stage_binding binding;
		std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
		if (source_journal_stage_load_locked(directory, reserved,
		    cut, ingress, &binding, &stage_digest) != 1 ||
		    !binding.present) {
			error = EPROTO;
			break;
		}
		source_journal_destination_plan plan;
		if (!source_journal_destination_plan_locked(directory, reserved,
		    cut, ingress, binding, false, plan)) {
			error = errno;
			break;
		}
		if (plan.deliveries.size() > UINT32_MAX) {
			error = E2BIG;
			break;
		}
		size_t missing;
		if (!source_journal_audit_receipts_locked(directory,
		    reserved, phase, plan, missing)) {
			error = errno;
			break;
		}
		int ready = source_journal_ready_status_locked(directory,
		    reserved, stage_digest, (uint32_t)plan.deliveries.size());
		if (ready != 1 || missing != 0) {
			error = ready < 0 ? errno : EPROTO;
			break;
		}
		/* HT-C END */
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* Read only the destination identity used to revalidate an HTB1 through the
 * full claimed-ticket transaction. Caller holds the inbound process lock. */
static int
host_transfer_stage_identity_at(int directory,
    const std::array<uint8_t, 16> &token,
    std::array<uint8_t, 16> &session, uint32_t &uid, uint32_t &pid,
    std::string &name)
{
	session = {};
	uid = pid = 0;
	name.clear();
	char stage_name[39];
	if (!host_transfer_stage_name(token, stage_name))
		return (-1);
	std::vector<uint8_t> stage;
	int present = host_transfer_stage_read_at(directory, stage_name, stage);
	if (present == 0) {
		char activation_name[39];
		std::vector<uint8_t> activation;
		if (!host_transfer_activation_name(token, activation_name))
			return (-1);
		int active = host_transfer_stage_read_at(directory,
		    activation_name, activation);
		if (active < 0)
			return (-1);
		if (active != 0) {
			errno = EPROTO;
			return (-1);
		}
	}
	if (present <= 0)
		return (present);
	const size_t tail = stage.size() - SHA256_DIGEST_LENGTH;
	const size_t name_length = dtraced_wire_get_u16(stage.data() + 86);
	if (name_length == 0 || name_length >= DTRACED_FDIDENTLEN ||
	    name_length > tail - host_transfer_stage_header_size) {
		errno = EPROTO;
		return (-1);
	}
	try {
		memcpy(session.data(), stage.data() + 62, session.size());
		uid = dtraced_wire_get_u32(stage.data() + 78);
		pid = dtraced_wire_get_u32(stage.data() + 82);
		name.assign((const char *)stage.data() +
		    host_transfer_stage_header_size, name_length);
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

/* HRO1 phases are immutable files. Keep the processed record when publishing
 * its executed successor, so a crash cannot erase the ACK that justified it.
 * The caller holds both ticket and inbound journal process locks. */
static int
host_transfer_outcome_read_at(int directory,
    const durable_import_consumer_result &identity,
    durable_import_consumer_result &observed)
{
	observed = {};
	durable_import_consumer_result processed{}, executed{};
	bool have_processed = false, have_executed = false;
	for (consumer_receipt_phase phase : {
	    consumer_receipt_phase::no_derived,
	    consumer_receipt_phase::derived,
	    consumer_receipt_phase::executed_no_derived,
	    consumer_receipt_phase::executed_derived}) {
		durable_import_consumer_result probe = identity;
		probe.phase = phase;
		char name[106];
		if (!host_transfer_outcome_name(probe, name))
			return (-1);
		std::vector<uint8_t> wire;
		int present = host_transfer_stage_read_at(directory, name, wire);
		if (present < 0)
			return (-1);
		if (present == 0)
			continue;
		durable_import_consumer_result decoded{};
		if (!dir::decode_import_consumer_result(wire, decoded) ||
		    decoded.token != identity.token ||
		    decoded.slots_digest != identity.slots_digest ||
		    decoded.receipt_digest != identity.receipt_digest ||
		    decoded.phase != phase) {
			errno = EPROTO;
			return (-1);
		}
		if (phase == consumer_receipt_phase::executed_no_derived ||
		    phase == consumer_receipt_phase::executed_derived) {
			if (have_executed) {
				errno = EPROTO;
				return (-1);
			}
			executed = decoded;
			have_executed = true;
		} else {
			if (have_processed) {
				errno = EPROTO;
				return (-1);
			}
			processed = decoded;
			have_processed = true;
		}
	}
	if (have_executed && (!have_processed ||
	    consumer_receipt_derived(processed.phase) !=
	    consumer_receipt_derived(executed.phase) ||
	    processed.derived_claim_digest != executed.derived_claim_digest)) {
		errno = EPROTO;
		return (-1);
	}
	if (!have_processed)
		return (0);
	observed = have_executed ? executed : processed;
	return ((int)observed.phase);
}

static int
host_transfer_outcome_publish_at(int directory,
    const durable_import_consumer_result &record)
{
	std::vector<uint8_t> wire;
	if (!dir::encode_import_consumer_result(record, wire))
		return (-1);
	durable_import_consumer_result observed{};
	int current = host_transfer_outcome_read_at(directory, record, observed);
	if (current < 0)
		return (-1);
	const bool terminal = record.phase ==
	    consumer_receipt_phase::executed_no_derived ||
	    record.phase == consumer_receipt_phase::executed_derived;
	if (current != 0) {
		if (consumer_receipt_derived(observed.phase) !=
		    consumer_receipt_derived(record.phase) ||
		    observed.derived_claim_digest != record.derived_claim_digest) {
			errno = EPROTO;
			return (-1);
		}
		if (current == (int)record.phase ||
		    (!terminal && (observed.phase ==
		    consumer_receipt_phase::executed_no_derived ||
		    observed.phase == consumer_receipt_phase::executed_derived))) {
			if (fsync(directory) != 0)
				return (-1);
			return (current);
		}
		if (!terminal) {
			errno = EPROTO;
			return (-1);
		}
	} else if (terminal) {
		errno = EBUSY;
		return (-1);
	}
	char name[106];
	if (!host_transfer_outcome_name(record, name) ||
	    !handoff_publish_at(directory, name, wire.data(), wire.size()))
		return (-1);
	return ((int)record.phase);
}

static bool
host_transfer_outcome_audit_at(int directory,
    const std::array<uint8_t, 16> &token,
    const std::vector<durable_committed_import_result_state> &results)
{
	char prefix[40];
	if (!host_transfer_stage_name(token, prefix))
		return (false);
	memcpy(prefix, ".hro1.", 6);
	prefix[38] = '.';
	prefix[39] = '\0';
	try {
		std::unordered_set<std::string> allowed;
		allowed.reserve(results.size() * 4);
		for (const auto &entry : results)
			for (consumer_receipt_phase phase : {
			    consumer_receipt_phase::no_derived,
			    consumer_receipt_phase::derived,
			    consumer_receipt_phase::executed_no_derived,
			    consumer_receipt_phase::executed_derived}) {
				durable_import_consumer_result probe = entry.outcome;
				probe.phase = phase;
				char name[106];
				if (!host_transfer_outcome_name(probe, name))
					return (false);
				allowed.emplace(name);
			}
		int fd = openat(directory, ".",
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (fd < 0)
			return (false);
		DIR *scan = fdopendir(fd);
		if (scan == nullptr) {
			int error = errno;
			close(fd);
			errno = error;
			return (false);
		}
		int error = 0;
		size_t seen = 0;
		for (;;) {
			errno = 0;
			struct dirent *entry = readdir(scan);
			if (entry == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(entry->d_name, prefix, 38) != 0)
				continue;
			if (strlen(entry->d_name) != 105 ||
			    allowed.count(entry->d_name) == 0 ||
			    ++seen > results.size() * 2) {
				error = EPROTO;
				break;
			}
		}
		if (closedir(scan) != 0 && error == 0)
			error = errno;
		if (error != 0) {
			errno = error;
			return (false);
		}
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* Validate every current outcome before an activated write. HRS1 already
 * passed its canonical cohort check, so its slot table is authoritative. */
static bool
host_transfer_outcome_audit_slots_at(int directory,
    const std::array<uint8_t, 16> &token,
    const std::vector<uint8_t> &result_wire)
{
	try {
		uint32_t count = dtraced_wire_get_u32(result_wire.data() + 52);
		std::vector<durable_committed_import_result_state> slots;
		slots.reserve(count);
		for (uint32_t i = 0; i < count; i++) {
			durable_committed_import_result_state slot{};
			slot.outcome.token = token;
			memcpy(slot.outcome.slots_digest.data(),
			    result_wire.data() + result_wire.size() - 32, 32);
			memcpy(slot.outcome.receipt_digest.data(),
			    result_wire.data() + 64 + (size_t)i * 33, 32);
			durable_import_consumer_result observed{};
			int phase = host_transfer_outcome_read_at(directory,
			    slot.outcome, observed);
			if (phase < 0)
				return (false);
			if (phase != 0)
				slot.outcome = observed;
			slots.push_back(std::move(slot));
		}
		return (host_transfer_outcome_audit_at(directory, token, slots));
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

static bool
host_transfer_stage_decode(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name, const std::vector<uint8_t> &wire,
    host_ingress_destination_plan &plan)
{
	plan = {};
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (wire.size() < host_transfer_stage_header_size +
	    SHA256_DIGEST_LENGTH ||
	    wire.size() > host_transfer_stage_max_size ||
	    memcmp(wire.data(), "HTB1", 4) != 0 ||
	    memcmp(wire.data() + 4, reserved.token.data(), 16) != 0 ||
	    memcmp(wire.data() + 20,
	    reserved.checkpoint_digest.data(), 32) != 0 ||
	    dtraced_wire_get_u16(wire.data() + 52) !=
	    reserved.destination_vmid ||
	    dtraced_wire_get_u64(wire.data() + 54) !=
	    reserved.destination_epoch ||
	    memcmp(wire.data() + 62, destination_session.data(), 16) != 0 ||
	    dtraced_wire_get_u32(wire.data() + 78) != destination_uid ||
	    dtraced_wire_get_u32(wire.data() + 82) != destination_pid ||
	    dtraced_wire_get_u16(wire.data() + 86) !=
	    destination_name.size() ||
	    SHA256(wire.data(), wire.size() - SHA256_DIGEST_LENGTH,
	    digest) == nullptr ||
	    memcmp(digest, wire.data() + wire.size() -
	    SHA256_DIGEST_LENGTH, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	size_t offset = host_transfer_stage_header_size;
	const size_t tail = wire.size() - SHA256_DIGEST_LENGTH;
	if (destination_name.size() > tail - offset ||
	    memcmp(wire.data() + offset, destination_name.data(),
	    destination_name.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	offset += destination_name.size();
	const uint32_t count = dtraced_wire_get_u32(wire.data() + 88);
	const uint32_t manifest_length = dtraced_wire_get_u32(wire.data() + 92);
	if (count == 0 || count > consumer_receipt_limit ||
	    manifest_length > tail - offset ||
	    count > (tail - offset - manifest_length) / 4) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::vector<uint8_t> manifest(wire.begin() + offset,
		    wire.begin() + offset + manifest_length);
		offset += manifest_length;
		std::vector<std::vector<uint8_t>> frames;
		frames.reserve(count);
		for (uint32_t i = 0; i < count; i++) {
			if (tail - offset < 4) {
				errno = EPROTO;
				return (false);
			}
			uint32_t length = dtraced_wire_get_u32(
			    wire.data() + offset);
			offset += 4;
			if (length > tail - offset) {
				errno = EPROTO;
				return (false);
			}
			frames.emplace_back(wire.begin() + offset,
			    wire.begin() + offset + length);
			offset += length;
		}
		if (offset != tail) {
			errno = EPROTO;
			return (false);
		}
		return (dir::plan_host_ingress_destination(reserved, manifest,
		    frames, destination_session, destination_uid, destination_pid,
		    destination_name, plan));
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

bool
dir::stage_host_ingress_destination(const durable_handoff &reserved,
    const std::vector<uint8_t> &manifest,
    const std::vector<std::vector<uint8_t>> &frames,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    host_ingress_destination_plan &plan)
{
	plan = {};
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this) {
		errno = EINVAL;
		return (false);
	}
	std::vector<uint8_t> wire;
	host_ingress_destination_plan candidate;
	if (!host_transfer_stage_encode(reserved, manifest, frames,
	    destination_session, destination_uid, destination_pid,
	    destination_name, wire, candidate))
		return (false);
	char name[39];
	if (!host_transfer_stage_name(reserved.token, name))
		return (false);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	std::vector<uint8_t> existing;
	int present = host_transfer_stage_read_at(this->dirfd, name, existing);
	if (present < 0)
		return (false);
	if (present == 0 && !handoff_publish_at(this->dirfd, name,
	    wire.data(), wire.size())) {
		if (errno != EEXIST)
			return (false);
		present = host_transfer_stage_read_at(this->dirfd, name, existing);
		if (present != 1)
			return (false);
	}
	if (present == 1 && existing != wire) {
		errno = EEXIST;
		return (false);
	}
	/* A retry may observe a link published just before a crash but before
	 * the publisher's directory fsync. Make that exact inode durable now. */
	if (present == 1 && fsync(this->dirfd) != 0)
		return (false);
	plan.source_entries.swap(candidate.source_entries);
	plan.source_programs.swap(candidate.source_programs);
	plan.deliveries.swap(candidate.deliveries);
	plan.payloads.swap(candidate.payloads);
	return (true);
}

int
dir::stage_host_ingress_destination_wire(const durable_handoff &reserved,
    const std::vector<uint8_t> &wire,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    host_ingress_destination_plan &plan)
{
	plan = {};
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (-1);
	}
	std::vector<uint8_t> manifest;
	std::vector<std::vector<uint8_t>> frames;
	if (!dtraced_transfer_wire_unpack(wire.data(), wire.size(),
	    reserved.token.data(), manifest, frames))
		return (-1);
	if (manifest.empty())
		return (0);
	return (this->stage_host_ingress_destination(reserved, manifest,
	    frames, destination_session, destination_uid, destination_pid,
	    destination_name, plan) ? 1 : -1);
}

int
dir::stage_host_ingress_destination_wire_reserved(
    const durable_handoff &reserved, const std::vector<uint8_t> &wire,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    host_ingress_destination_plan &plan)
{
	plan = {};
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    this->state->outbounddir == this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (-1);
	}
	dir &outbound = *this->state->outbounddir;
	int has_ingress, has_journal;
	if (!dtraced_transfer_wire_inspect(wire.data(), wire.size(),
	    reserved.token.data(), &has_ingress, &has_journal))
		return (-1);
	if (has_journal != 0) {
		/* Stage the complete source cut under the outbound ticket lock.
		 * Its private HJB1 is not a destination journal import. */
		return (outbound.stage_source_journal_destination_wire(
		    reserved, wire, destination_session, destination_uid,
		    destination_pid) ? 2 : -1);
	}
	handoff_process_lock destination_lock(outbound.dirfd);
	if (!destination_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(outbound.dirfd, reserved.token, current);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::reserved ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	if (wire.size() < DTRACED_TRANSFER_HEADER_SIZE +
	    DTRACED_TRANSFER_DIGEST_SIZE ||
	    memcmp(wire.data() + wire.size() - DTRACED_TRANSFER_DIGEST_SIZE,
	    current.transfer_digest.data(),
	    current.transfer_digest.size()) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (this->stage_host_ingress_destination_wire(reserved, wire,
	    destination_session, destination_uid, destination_pid,
	    destination_name, plan));
}

int
dir::load_host_ingress_destination_stage(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    host_ingress_destination_plan &plan)
{
	plan = {};
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (-1);
	}
	char name[39];
	if (!host_transfer_stage_name(reserved.token, name))
		return (-1);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	std::vector<uint8_t> wire;
	int present = host_transfer_stage_read_at(this->dirfd, name, wire);
	if (present != 1)
		return (present);
	return (host_transfer_stage_decode(reserved, destination_session,
	    destination_uid, destination_pid, destination_name, wire, plan) ?
	    1 : -1);
}

/* Publish only pending HTD4 records after the complete HTB1 sidecar is
 * durable. The watcher ignores pending records, including after restart.
 * A crash between one record and its spool is completed by an exact retry;
 * promotion to accepted requires a separate consumer recovery transaction. */
bool
dir::import_host_ingress_pending(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    this->state->outbounddir == this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (false);
	}
	dir &outbound = *this->state->outbounddir;
	handoff_process_lock destination_lock(outbound.dirfd);
	if (!destination_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(outbound.dirfd, reserved.token, current);
	if (phase < 0)
		return (false);
	if ((phase != (int)handoff_phase::reserved &&
	    phase != (int)handoff_phase::mutating) ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	char name[39];
	if (!host_transfer_stage_name(reserved.token, name))
		return (false);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	std::vector<uint8_t> wire;
	int present = host_transfer_stage_read_at(this->dirfd, name, wire);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	host_ingress_destination_plan plan;
	if (!host_transfer_stage_decode(reserved, destination_session,
	    destination_uid, destination_pid, destination_name, wire, plan))
		return (false);
	std::vector<durable_delivery_state> existing;
	if (!list_deliveries_at(this->dirfd, existing))
		return (false);
	int count = delivery_record_count(this->dirfd);
	if (count < 0)
		return (false);
	std::map<std::array<uint8_t, 16>, bool> program_ids;
	try {
		for (const auto &record : plan.deliveries)
			if (!program_ids.emplace(record.program_id, true).second) {
				errno = EPROTO;
				return (false);
			}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	size_t needed = 0;
	for (const auto &record : plan.deliveries) {
		bool found = false;
		const auto expected = delivery_record_bytes(record);
		for (const auto &entry : existing) {
			bool same_program = entry.record.program_id ==
			    record.program_id;
			bool same_token = entry.record.session_id ==
			    record.session_id &&
			    entry.record.delivery_id == record.delivery_id;
			if (!same_program && !same_token)
				continue;
			if (delivery_record_bytes(entry.record) != expected) {
				errno = EEXIST;
				return (false);
			}
			if (entry.phase != delivery_phase::pending) {
				errno = EBUSY;
				return (false);
			}
			found = true;
		}
		if (!found)
			needed++;
	}
	if ((size_t)count > 16384 || needed > 16384 - (size_t)count) {
		errno = ENOSPC;
		return (false);
	}
	for (size_t i = 0; i < plan.deliveries.size(); i++) {
		const auto &record = plan.deliveries[i];
		if (!delivery_transition_at(this->dirfd, record,
		    delivery_phase::pending, false) ||
		    !publish_spool(this->dirfd, plan.payloads[i].data(),
		    plan.payloads[i].size(), -1, record.program_id.data(),
		    nullptr, record.source_id.data()))
			return (false);
	}
	return (true);
}

/* CANCEL holds the outbound process lock while this removes the inert
 * destination import. The stage remains present until every pending record
 * and spool deletion has reached disk, so a crash can retry the same cleanup
 * before the reservation is released. An accepted record is never rolled
 * back by this path. */
bool
dir::rollback_host_ingress_pending_locked(const durable_handoff &reserved)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (false);
	}
	char stage_name[39];
	if (!host_transfer_stage_name(reserved.token, stage_name))
		return (false);
	char owner_name[39];
	if (!host_transfer_owner_name(reserved.token, owner_name))
		return (false);
	char cohort_name[39];
	if (!host_transfer_cohort_name(reserved.token, cohort_name))
		return (false);
	char result_name[39];
	if (!host_transfer_result_name(reserved.token, result_name))
		return (false);
	char promotion_name[39];
	if (!host_transfer_promotion_name(reserved.token, promotion_name))
		return (false);
	char commit_name[39];
	if (!host_transfer_commit_name(reserved.token, commit_name))
		return (false);
	char activation_name[39];
	if (!host_transfer_activation_name(reserved.token, activation_name))
		return (false);
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	std::vector<uint8_t> commit;
	int committed = host_transfer_stage_read_at(this->dirfd,
	    commit_name, commit);
	if (committed < 0)
		return (false);
	std::vector<uint8_t> activation;
	int activated = host_transfer_stage_read_at(this->dirfd,
	    activation_name, activation);
	if (activated < 0)
		return (false);
	if (activated != 0 && committed == 0) {
		errno = EPROTO;
		return (false);
	}
	if (committed != 0 || activated != 0) {
		errno = EBUSY;
		return (false);
	}
	std::vector<uint8_t> stage;
	int present = host_transfer_stage_read_at(this->dirfd,
	    stage_name, stage);
	if (present < 0)
		return (false);
	std::vector<durable_delivery_state> existing;
	if (!list_deliveries_at(this->dirfd, existing))
		return (false);
	if (present == 0) {
		for (const auto &entry : existing)
			if (entry.record.handoff_token == reserved.token) {
				errno = EPROTO;
				return (false);
			}
		if ((unlinkat(this->dirfd, promotion_name, 0) != 0 &&
		    errno != ENOENT) ||
		    (unlinkat(this->dirfd, result_name, 0) != 0 &&
		    errno != ENOENT) ||
		    (unlinkat(this->dirfd, cohort_name, 0) != 0 &&
		    errno != ENOENT) ||
		    (unlinkat(this->dirfd, owner_name, 0) != 0 &&
		    errno != ENOENT))
			return (false);
		return (fsync(this->dirfd) == 0);
	}
	const size_t tail = stage.size() - SHA256_DIGEST_LENGTH;
	const size_t name_length = dtraced_wire_get_u16(stage.data() + 86);
	if (name_length == 0 || name_length >= DTRACED_FDIDENTLEN ||
	    name_length > tail - host_transfer_stage_header_size) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::array<uint8_t, 16> session{};
		memcpy(session.data(), stage.data() + 62, session.size());
		const uint32_t uid = dtraced_wire_get_u32(stage.data() + 78);
		const uint32_t pid = dtraced_wire_get_u32(stage.data() + 82);
		std::string name((const char *)stage.data() +
		    host_transfer_stage_header_size, name_length);
		host_ingress_destination_plan plan;
		if (!host_transfer_stage_decode(reserved, session, uid, pid,
		    name, stage, plan))
			return (false);
		for (const auto &entry : existing) {
			if (entry.record.handoff_token != reserved.token)
				continue;
			bool exact = false;
			for (const auto &record : plan.deliveries)
				if (delivery_record_bytes(entry.record) ==
				    delivery_record_bytes(record)) {
					exact = true;
					break;
				}
			if (!exact || entry.phase != delivery_phase::pending) {
				errno = EBUSY;
				return (false);
			}
		}
		std::vector<bool> matched(plan.deliveries.size(), false);
		for (size_t i = 0; i < plan.deliveries.size(); i++) {
			const auto &record = plan.deliveries[i];
			for (const auto &entry : existing) {
				bool collision = entry.record.program_id ==
				    record.program_id ||
				    (entry.record.session_id == record.session_id &&
				    entry.record.delivery_id == record.delivery_id);
				if (!collision)
					continue;
				if (delivery_record_bytes(entry.record) !=
				    delivery_record_bytes(record) ||
				    entry.phase != delivery_phase::pending) {
					errno = EBUSY;
					return (false);
				}
				matched[i] = true;
			}
		}
		for (size_t i = 0; i < plan.deliveries.size(); i++) {
			if (!matched[i])
				continue;
			const auto &record = plan.deliveries[i];
			char spool[70], delivery[80];
			identified_spool_name(record.program_id.data(),
			    record.source_id.data(), spool);
			delivery_record_name(record, delivery_phase::pending,
			    delivery);
			if (unlinkat(this->dirfd, spool, 0) != 0 &&
			    errno != ENOENT)
				return (false);
			if (unlinkat(this->dirfd, delivery, 0) != 0)
				return (false);
		}
		if (fsync(this->dirfd) != 0 ||
		    (unlinkat(this->dirfd, promotion_name, 0) != 0 &&
		    errno != ENOENT) ||
		    fsync(this->dirfd) != 0 ||
		    (unlinkat(this->dirfd, result_name, 0) != 0 &&
		    errno != ENOENT) ||
		    fsync(this->dirfd) != 0 ||
		    (unlinkat(this->dirfd, cohort_name, 0) != 0 &&
		    errno != ENOENT) ||
		    fsync(this->dirfd) != 0 ||
		    (unlinkat(this->dirfd, owner_name, 0) != 0 &&
		    errno != ENOENT) ||
		    fsync(this->dirfd) != 0 ||
		    unlinkat(this->dirfd, stage_name, 0) != 0 ||
		    fsync(this->dirfd) != 0)
			return (false);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* The reset marker is durable before any pending journal is removed. A crash
 * can therefore resume cleanup even after committed and mutating coexist,
 * which the ordinary forward-only phase reader deliberately rejects. The
 * caller holds the outbound process lock (and the publish mutex at runtime). */
static bool
handoff_mutating_reset_recover_one_locked(int directory, state *control,
    const durable_handoff &old)
{
	if (control == nullptr || !control->is_control_machine() ||
	    control->inbounddir == nullptr ||
	    control->outbounddir == nullptr ||
	    control->inbounddir == control->outbounddir) {
		errno = EINVAL;
		return (false);
	}
	durable_handoff marker{}, prepared{}, committed{}, reserved{},
	    mutating{}, claimed{};
	int present = handoff_mutating_reset_read_at(directory, old.token,
	    marker);
	if (present != 1 || handoff_bytes(marker) != handoff_bytes(old)) {
		errno = present == 0 ? ENOENT : EPROTO;
		return (false);
	}
	int p = handoff_read_at(directory, old.token,
	    handoff_phase::prepared, prepared);
	int c = handoff_read_at(directory, old.token,
	    handoff_phase::committed, committed);
	int v = handoff_read_at(directory, old.token,
	    handoff_phase::reserved, reserved);
	int m = handoff_read_at(directory, old.token,
	    handoff_phase::mutating, mutating);
	int r = handoff_read_at(directory, old.token,
	    handoff_phase::claimed, claimed);
	if (p < 0 || c < 0 || v < 0 || m < 0 || r < 0)
		return (false);
	durable_handoff source = old;
	source.destination_vmid = 0;
	source.destination_epoch = 0;
	if (p != 0 || r != 0 || (c == 1 && v == 1) ||
	    (m == 0 && (c != 1 || v != 0)) ||
	    (m == 1 && !handoff_same_destination(mutating, old)) ||
	    (v == 1 && !handoff_same_destination(reserved, old)) ||
	    (c == 1 && (!handoff_same_source(committed, source) ||
	    committed.checkpoint_digest != source.checkpoint_digest))) {
		errno = EPROTO;
		return (false);
	}
	int released = source_release_read_at(directory, source);
	if (released == 0)
		released = imported_release_cut_status_at(directory, source);
	if (released != 1) {
		if (released == 0)
			errno = EPROTO;
		return (false);
	}
	int capable = handoff_capable_at(directory, old);
	int started = handoff_execution_start_at(directory, old);
	int applied = handoff_rekey_applied_at(directory, old);
	if (capable < 0 || started < 0 || applied < 0)
		return (false);
	if (capable != 0 || started != 0 || applied != 0) {
		errno = EBUSY;
		return (false);
	}
	int epoch_fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (epoch_fd < 0)
		return (false);
	int error = handoff_epoch_retired_fd(epoch_fd, old.destination_vmid,
	    old.destination_epoch) ? 0 : errno;
	if (close(epoch_fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	if (v == 1 && !handoff_remove_at(directory, old.token,
	    handoff_phase::reserved))
		return (false);
	if (m == 1) {
		if (!control->inbounddir->
		    rollback_host_ingress_pending_locked(old) ||
		    !source_journal_pending_rollback_locked(directory, old) ||
		    !source_journal_stage_remove_locked(directory, old))
			return (false);
		if (c == 0 && !handoff_write_at(directory, source,
		    handoff_phase::committed))
			return (false);
		if (!handoff_remove_at(directory, old.token,
		    handoff_phase::mutating))
			return (false);
	}
	char name[48];
	if (!handoff_mutating_reset_name(old.token, name) ||
	    unlinkat(directory, name, 0) != 0)
		return (false);
	return (fsync(directory) == 0);
}

bool
dir::reset_handoff_mutation(const std::array<uint8_t, 16> &token,
    const std::array<uint8_t, 32> &digest, uint16_t recovery_vmid,
    uint64_t recovery_epoch)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    token == std::array<uint8_t, 16>{} ||
	    digest == std::array<uint8_t, 32>{} || recovery_vmid == 0 ||
	    recovery_vmid >= HYPERTRACE_MAX_VMS || recovery_epoch == 0) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	durable_handoff old{};
	int marker = handoff_mutating_reset_read_at(this->dirfd, token, old);
	if (marker < 0)
		return (false);
	if (marker == 0) {
		int phase = handoff_state_at(this->dirfd, token, old);
		if (phase < 0)
			return (false);
		if (phase == (int)handoff_phase::committed &&
		    old.checkpoint_digest == digest)
			return (fsync(this->dirfd) == 0);
		if (phase != (int)handoff_phase::mutating) {
			errno = phase == 0 ? ENOENT : EBUSY;
			return (false);
		}
	}
	if (old.checkpoint_digest != digest ||
	    (old.destination_vmid == recovery_vmid &&
	    old.destination_epoch == recovery_epoch)) {
		errno = EPERM;
		return (false);
	}
	if (marker == 0) {
		int capable = handoff_capable_at(this->dirfd, old);
		int started = handoff_execution_start_at(this->dirfd, old);
		int applied = handoff_rekey_applied_at(this->dirfd, old);
		if (capable < 0 || started < 0 || applied < 0)
			return (false);
		if (capable != 0 || started != 0 || applied != 0) {
			errno = EBUSY;
			return (false);
		}
		int epoch_fd = open("/dev/dtrace/hypertrace",
		    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
		if (epoch_fd < 0)
			return (false);
		int error = handoff_epoch_retired_fd(epoch_fd,
		    old.destination_vmid, old.destination_epoch) ? 0 : errno;
		if (close(epoch_fd) != 0 && error == 0)
			error = errno;
		if (error != 0) {
			errno = error;
			return (false);
		}
		char name[48];
		if (!handoff_mutating_reset_name(token, name))
			return (false);
		const auto wire = handoff_bytes(old);
		if (!handoff_publish_at(this->dirfd, name, wire.data(),
		    wire.size()))
			return (false);
	}
	return (handoff_mutating_reset_recover_one_locked(this->dirfd,
	    this->state, old));
}
/* HT-C END */

static bool
handoff_mutating_resets_recover_locked(int directory, state *control)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0)
		return (false);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno;
		close(scanfd);
		errno = error;
		return (false);
	}
	std::vector<std::array<uint8_t, 16>> tokens;
	int error = 0;
	try {
		for (;;) {
			errno = 0;
			dirent *entry = readdir(scan);
			if (entry == nullptr) {
				error = errno;
				break;
			}
			const char *name = entry->d_name;
			if (strncmp(name, ".handoff-reset.", 15) != 0)
				continue;
			/* HT-C BEGIN: disabled trace continuity. */
			if (strlen(name) != 47) {
				error = EPROTO;
				break;
			}
			std::array<uint8_t, 16> token{};
			for (size_t i = 0; i < token.size(); i++) {
				uint64_t octet;
				if (!parse_hex(name + 15 + i * 2, 2,
				    octet)) {
					error = EPROTO;
					break;
				}
				token[i] = (uint8_t)octet;
			}
			if (error != 0)
				break;
			char canonical[48];
			if (!handoff_mutating_reset_name(token, canonical) ||
			    strcmp(name, canonical) != 0) {
				error = EPROTO;
				break;
			}
			tokens.push_back(token);
			/* HT-C END */
		}
	} catch (const std::bad_alloc &) {
		error = ENOMEM;
	}
	if (closedir(scan) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	for (const auto &token : tokens) {
		/* HT-C BEGIN: disabled trace continuity. */
		durable_handoff old{};
		if (handoff_mutating_reset_read_at(directory, token, old) != 1 ||
		    !handoff_mutating_reset_recover_one_locked(directory,
		    control, old))
			return (false);
		/* HT-C END */
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
int
dir::host_ingress_transfer_frame(const durable_handoff &ticket,
    const std::vector<uint8_t> &manifest, size_t index,
    std::vector<uint8_t> &frame)
{
	frame.clear();
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    this->state->outbounddir == this) {
		errno = EINVAL;
		return (-1);
	}
	std::vector<host_ingress_transfer_entry> entries;
	if (!validate_host_ingress_transfer_manifest(ticket, manifest,
	    &entries))
		return (-1);
	if (index >= entries.size()) {
		errno = EINVAL;
		return (-1);
	}
	/* Every accepted upload and execution receipt takes this source lock.
	 * Recompute the manifest under it before copying the exact spool bytes;
	 * an export assembled across requests is provisional until PREPARE binds
	 * the same manifest to the checkpoint member. */
	dir &outbound = *this->state->outbounddir;
	std::lock_guard source(outbound.publishmtx);
	handoff_process_lock process_lock(outbound.dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff ticket_state{};
	int phase = handoff_state_at(outbound.dirfd, ticket.token,
	    ticket_state);
	if (phase < 0)
		return (-1);
	if (phase != 0 && (phase != (int)handoff_phase::prepared ||
	    !handoff_same_source(ticket_state, ticket))) {
		errno = EBUSY;
		return (-1);
	}
	if (phase == 0) {
		int source_phase = handoff_source_state_at(outbound.dirfd,
		    ticket.source_vmid, ticket.source_epoch, ticket_state);
		if (source_phase < 0)
			return (-1);
		if (source_phase != 0) {
			errno = EBUSY;
			return (-1);
		}
	}
	std::vector<uint8_t> current;
	int present = this->host_ingress_transfer_manifest(ticket, current);
	if (present < 0)
		return (-1);
	if (present == 0 || current != manifest) {
		errno = ESTALE;
		return (-1);
	}
	if (!this->host_ingress_transfer_audit_locked(outbound))
		return (-1);
	std::vector<uint8_t> bytes;
	int verified = this->verify_host_ingress_payload(
	    entries[index].ingress, &bytes);
	if (verified != 1) {
		if (verified == 0)
			errno = EBUSY;
		return (-1);
	}
	return (encode_host_ingress_transfer_frame(ticket,
	    entries[index].ingress, bytes, frame) ? 1 : -1);
}

static void consumer_owner_name(const std::array<uint8_t, 16> &, uint32_t,
    char [49]);
static int consumer_owner_read_at(int, const char *,
    std::array<uint8_t, 76> &);

int
dir::host_ingress_transfer_bundle_export(const durable_handoff &ticket,
    std::vector<uint8_t> &manifest,
    std::vector<std::vector<uint8_t>> &frames, bool with_programs)
{
	manifest.clear();
	frames.clear();
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    this->state->outbounddir == this ||
	    !handoff_valid(ticket, handoff_phase::prepared)) {
		errno = EINVAL;
		return (-1);
	}
	dir &outbound = *this->state->outbounddir;
	std::lock_guard source(outbound.publishmtx);
	handoff_process_lock process_lock(outbound.dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(outbound.dirfd, ticket.token, current);
	if (phase < 0)
		return (-1);
	if (phase != 0 && (phase != (int)handoff_phase::prepared ||
	    !handoff_same_source(current, ticket))) {
		errno = EBUSY;
		return (-1);
	}
	if (phase == 0) {
		int source_phase = handoff_source_state_at(outbound.dirfd,
		    ticket.source_vmid, ticket.source_epoch, current);
		if (source_phase < 0)
			return (-1);
		if (source_phase != 0) {
			errno = EBUSY;
			return (-1);
		}
	}
	return (this->host_ingress_transfer_bundle_locked(ticket, outbound,
	    manifest, frames, with_programs));
}

int
dir::host_ingress_transfer_bundle_locked(const durable_handoff &ticket,
    dir &outbound, std::vector<uint8_t> &manifest,
    std::vector<std::vector<uint8_t>> &frames, bool with_programs)
{
	manifest.clear();
	frames.clear();
	std::vector<uint8_t> candidate_manifest;
	int present = this->host_ingress_transfer_manifest(ticket,
	    candidate_manifest);
	if (present <= 0)
		return (present);
	if (!this->host_ingress_transfer_audit_locked(outbound))
		return (-1);
	std::vector<host_ingress_transfer_entry> entries;
	if (!validate_host_ingress_transfer_manifest(ticket,
	    candidate_manifest, &entries))
		return (-1);
	/* Legacy HTM1 has only a session/PID/UID receipt and still needs a
	 * current HCO1. HCP1 freezes the actual process birth and program
	 * before the socket job; a terminal receipt keeps that proof valid
	 * after the consumer exits or its HCO1 rotates. */
	if (!with_programs) {
		for (const auto &entry : entries) {
			for (const auto &recipient : entry.recipients) {
				const auto &member = recipient.record;
				char owner_name[49];
				consumer_owner_name(member.consumer_session,
				    member.consumer_pid, owner_name);
				std::array<uint8_t, 76> owner{};
				int found = consumer_owner_read_at(this->dirfd,
				    owner_name, owner);
				if (found != 1) {
					if (found == 0)
						errno = EBUSY;
					return (-1);
				}
				if (dtraced_wire_get_u32(owner.data() + 20) !=
				    member.consumer_uid) {
					errno = EPROTO;
					return (-1);
				}
			}
		}
	}
	if (with_programs) {
		std::vector<uint8_t> program_manifest;
		if (host_ingress_program_manifest_locked(ticket,
		    candidate_manifest, program_manifest) != 1)
			return (-1);
		candidate_manifest.swap(program_manifest);
	}
	/* Reserve for the largest legal destination name so the bundle can be
	 * staged as one HTB1 sidecar without discovering a late size failure. */
	size_t length = host_transfer_stage_header_size +
	    DTRACED_FDIDENTLEN - 1 + SHA256_DIGEST_LENGTH;
	if (candidate_manifest.size() > host_transfer_stage_max_size - length) {
		errno = E2BIG;
		return (-1);
	}
	length += candidate_manifest.size();
	try {
		std::vector<std::vector<uint8_t>> candidate_frames;
		candidate_frames.reserve(entries.size());
		for (const auto &entry : entries) {
			std::vector<uint8_t> bytes, frame;
			int verified = this->verify_host_ingress_payload(
			    entry.ingress, &bytes);
			if (verified != 1) {
				if (verified == 0)
					errno = EBUSY;
				return (-1);
			}
			if (length > host_transfer_stage_max_size - 4 ||
			    bytes.size() > host_transfer_stage_max_size - length - 4) {
				errno = E2BIG;
				return (-1);
			}
			if (!encode_host_ingress_transfer_frame(ticket,
			    entry.ingress, bytes, frame))
				return (-1);
			if (length > host_transfer_stage_max_size - 4 ||
			    frame.size() > host_transfer_stage_max_size - length - 4) {
				errno = E2BIG;
				return (-1);
			}
			length += 4 + frame.size();
			candidate_frames.push_back(std::move(frame));
		}
		manifest.swap(candidate_manifest);
		frames.swap(candidate_frames);
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}
/* HT-C END */

int
dir::verify_pending_outbound(const durable_delivery &record)
{
	if (record.scope != 2 || record.journal_version != 4 ||
	    !delivery_record_valid(record)) {
		errno = EINVAL;
		return (-1);
	}
	uint8_t digest[32];
	if (!this->hash_identified_data(record.program_id.data(),
	    record.source_id.data(), digest))
		return (errno == ENOENT ? 0 : -1);
	if (memcmp(digest, record.payload_digest.data(), sizeof(digest)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (1);
}

int
dir::queue_recovered_outbound(const durable_delivery &record,
    uint16_t vmid, uint64_t epoch)
{
	if (this->state == nullptr || this->state->is_control_machine() ||
	    record.scope != 2 || record.journal_version != 4 ||
	    !delivery_record_valid(record) || vmid == 0 ||
	    vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    (record.vmid != 0 &&
	    (record.vmid != vmid || record.epoch != epoch))) {
		errno = EINVAL;
		return (-1);
	}
	char expected_ident[sizeof(((client_fd *)nullptr)->ident)];
	if (snprintf(expected_ident, sizeof(expected_ident),
	    "dtraced-dttransport-%d", getpid()) >=
	    (int)sizeof(expected_ident)) {
		errno = EOVERFLOW;
		return (-1);
	}
	std::lock_guard clients(this->state->sockfdsmtx);
	client_fd *forwarder = nullptr;
	for (client_fd *candidate : this->state->sockfds) {
		if (candidate->retired.load() ||
		    candidate->kind != DTRACED_KIND_FORWARDER ||
		    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
		    candidate->peer_pid != getpid() ||
		    candidate->peer_uid != geteuid() ||
		    strcmp(candidate->ident, expected_ident) != 0)
			continue;
		if (forwarder != nullptr) {
			errno = EPROTO;
			return (-1);
		}
		forwarder = candidate;
	}
	if (forwarder == nullptr)
		return (0);
	try {
		std::unique_ptr<job> queued =
		    std::make_unique<job>(NOTIFY_ELFWRITE, forwarder);
		auto &ne = queued->notify_elfwrite_get();
		char name[70];
		identified_spool_name(record.program_id.data(),
		    record.source_id.data(), name);
		ne.path = strdup(name);
		if (ne.path == nullptr)
			return (-1);
		ne.pathlen = strlen(name);
		ne.dir = this;
		ne.nosha = true;
		ne.replay = new durable_delivery(record);
		ne.replay_vmid = vmid;
		ne.replay_epoch = epoch;
		std::list<job *> staged;
		staged.push_back(queued.get());
		{
			std::lock_guard jobs(this->state->joblistmtx);
			/* A failed event arm must leave no queued replay for an
			 * exact retry to duplicate. The write dispatcher cannot inspect
			 * the list until this lock is released. */
			if (!forwarder->re_enable_write())
				return (-1);
			this->state->joblist.splice(this->state->joblist.end(),
			    staged);
		}
		(void)queued.release();
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

bool
dir::withdraw_pending_delivery(const durable_delivery &record)
{
	if (!delivery_record_valid(record) || record.journal_version != 4 ||
	    (record.scope != 0 && record.scope != 2)) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard lk(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (false);
	int current = delivery_record_status_at(this->dirfd, record);
	if (current < 0)
		return (false);
	if (current == 0)
		return (true);
	if (current != (int)delivery_phase::pending) {
		errno = EBUSY;
		return (false);
	}
	char spool[70];
	identified_spool_name(record.program_id.data(), record.source_id.data(),
	    spool);
	struct stat sb;
	if (fstatat(this->dirfd, spool, &sb, AT_SYMLINK_NOFOLLOW) == 0) {
		errno = EEXIST;
		return (false);
	}
	if (errno != ENOENT)
		return (false);
	char name[80];
	delivery_record_name(record, delivery_phase::pending, name);
	if (unlinkat(this->dirfd, name, 0) != 0 && errno != ENOENT)
		return (false);
	return (fsync(this->dirfd) == 0);
}

int
dir::queue_pending_host_outbound(client_fd *forwarder)
{
	if (forwarder == nullptr) {
		errno = EINVAL;
		return (-1);
	}
	/* Records name an attested VM lifetime and bhyve process; any other
	 * channel (or a directory outside a daemon state) has nothing to
	 * resend. */
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    forwarder->kind != DTRACED_KIND_FORWARDER ||
	    !forwarder->is_subscribed(DTD_SUB_ELFWRITE) ||
	    forwarder->vmid == 0 || forwarder->vm_epoch == 0 ||
	    forwarder->peer_pid <= 1)
		return (0);
	std::vector<durable_delivery_state> records;
	if (!this->list_deliveries(records))
		return (-1);
	try {
		std::list<job *> staged;
		std::vector<std::unique_ptr<job>> owned;
		for (const auto &entry : records) {
			const durable_delivery &record = entry.record;
			/* Only this bhyve process's channel for this VM lifetime:
			 * a fresh session (new epoch) never receives old work. */
			if (record.scope != 0 || record.journal_version != 4 ||
			    entry.phase != delivery_phase::pending ||
			    record.session_id != forwarder->session_id ||
			    record.peer_uid != (uint32_t)forwarder->peer_uid ||
			    record.peer_pid != (uint32_t)forwarder->peer_pid ||
			    record.vmid != forwarder->vmid ||
			    record.epoch != forwarder->vm_epoch)
				continue;
			int revoked = this->source_revoked_for_vm(
			    record.source_id.data(), record.vmid, record.epoch);
			if (revoked < 0)
				return (-1);
			if (revoked != 0)
				continue;
			int present = this->verify_host_delivery_payload(record);
			if (present < 0 && errno != EPROTO)
				return (-1);
			if (present == 0) {
				/* Its publication was refused and the spool removed:
				 * nothing was or can be sent. */
				if (!this->withdraw_pending_delivery(record))
					return (-1);
				continue;
			}
			if (present != 1) {
				/* A missing or replaced spool cannot be resent; a
				 * send would only fail and drop the channel again. */
				if (present < 0)
					ERR("pending delivery %016jx no longer matches "
					    "its spool", (uintmax_t)record.delivery_id);
				continue;
			}
			auto queued = std::make_unique<job>(NOTIFY_ELFWRITE,
			    forwarder);
			auto &ne = queued->notify_elfwrite_get();
			char name[70];
			identified_spool_name(record.program_id.data(),
			    record.source_id.data(), name);
			ne.path = strdup(name);
			if (ne.path == nullptr)
				return (-1);
			ne.pathlen = strlen(name);
			ne.dir = this;
			ne.nosha = this->state->nosha;
			ne.recorded = new durable_delivery(record);
			owned.push_back(std::move(queued));
			staged.push_back(owned.back().get());
		}
		if (owned.empty())
			return (0);
		{
			std::lock_guard jobs(this->state->joblistmtx);
			if (!forwarder->re_enable_write())
				return (-1);
			this->state->joblist.splice(this->state->joblist.end(),
			    staged);
		}
		for (auto &queued : owned)
			(void)queued.release();
		return ((int)owned.size());
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

void
dir::forget_unrecorded_host_spools(
    const std::vector<durable_delivery_state> &records)
{
	std::unordered_set<std::string> named;
	for (const auto &entry : records) {
		if (entry.record.scope != 0)
			continue;
		char name[70];
		identified_spool_name(entry.record.program_id.data(),
		    entry.record.source_id.data(), name);
		named.insert(name);
	}
	std::lock_guard lock(this->existingmtx);
	for (auto it = this->existing_files.begin();
	    it != this->existing_files.end();) {
		std::array<uint8_t, 16> program{}, source{};
		if (spool_identity_from_path(*it, program, source) &&
		    named.count(*it) == 0)
			it = this->existing_files.erase(it);
		else
			++it;
	}
}

bool
dir::forget_unassigned_ingress(
    const std::vector<durable_delivery_state> &ingresses)
{
	std::vector<durable_consumer_receipt_state> receipts;
	if (!this->list_consumer_receipts(receipts))
		return (false);
	for (const auto &entry : ingresses) {
		const durable_delivery &ingress = entry.record;
		if (ingress.scope != 3 || ingress.journal_version != 4 ||
		    entry.phase != delivery_phase::accepted)
			continue;
		std::vector<durable_consumer_receipt> fixed;
		int cohort = this->consumer_cohort(ingress, {}, fixed);
		if (cohort < 0)
			return (false);
		if (cohort != 0)
			continue;
		bool assigned = std::any_of(receipts.begin(), receipts.end(),
		    [&](const durable_consumer_receipt_state &receipt) {
			const auto &prior = receipt.record.ingress;
			return (prior.scope == 3 &&
			    prior.delivery_id == ingress.delivery_id &&
			    prior.vmid == ingress.vmid &&
			    prior.epoch == ingress.epoch &&
			    prior.program_id == ingress.program_id &&
			    prior.source_id == ingress.source_id);
		    });
		if (assigned)
			continue;
		char name[70];
		identified_spool_name(ingress.program_id.data(),
		    ingress.source_id.data(), name);
		(void)this->rmpath(name);
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* Queue only an exact imported host receipt for its live VMM forwarder.
 * The job re-reads HJB1 at send time; no ELF spool becomes watcher-visible. */
int
dir::queue_claimed_source_journal_replay(const durable_delivery &record)
{
	std::vector<uint8_t> payload;
	if (claimed_source_journal_replay_payload(record, payload) != 1)
		return (-1);
	std::lock_guard clients(this->state->sockfdsmtx);
	client_fd *forwarder = nullptr;
	for (client_fd *candidate : this->state->sockfds) {
		if (candidate->retired.load() ||
		    candidate->kind != DTRACED_KIND_FORWARDER ||
		    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
		    candidate->session_id != record.session_id ||
		    candidate->peer_uid != record.peer_uid ||
		    candidate->peer_pid <= 1 ||
		    (uint32_t)candidate->peer_pid != record.peer_pid ||
		    candidate->vmid != record.vmid ||
		    candidate->vm_epoch != record.epoch ||
		    !candidate->current_vm_attestation())
			continue;
		if (forwarder != nullptr) {
			errno = EPROTO;
			return (-1);
		}
		forwarder = candidate;
	}
	if (forwarder == nullptr)
		return (0);
	try {
		std::unique_ptr<job> queued =
		    std::make_unique<job>(NOTIFY_ELFWRITE, forwarder);
		auto &ne = queued->notify_elfwrite_get();
		char name[70];
		identified_spool_name(record.program_id.data(),
		    record.source_id.data(), name);
		ne.path = strdup(name);
		if (ne.path == nullptr)
			return (-1);
		ne.pathlen = strlen(name);
		ne.dir = this;
		ne.nosha = this->state->nosha;
		ne.replay = new durable_delivery(record);
		std::list<job *> staged;
		staged.push_back(queued.get());
		{
			std::lock_guard jobs(this->state->joblistmtx);
			/* Admission can retry while an exact replay is queued. Keep
			 * one job per destination receipt on this connection. */
			for (job *pending : this->state->joblist) {
				if (pending->connsockfd != forwarder ||
				    pending->kind != NOTIFY_ELFWRITE)
					continue;
				const durable_delivery *prior =
				    pending->notify_elfwrite_get().replay;
				if (prior == nullptr || prior->journal_version != 5 ||
				    prior->session_id != record.session_id ||
				    prior->delivery_id != record.delivery_id)
					continue;
				if (delivery_record_bytes(*prior) !=
				    delivery_record_bytes(record)) {
					errno = EPROTO;
					return (-1);
				}
				return (1);
			}
			if (!forwarder->re_enable_write())
				return (-1);
			this->state->joblist.splice(this->state->joblist.end(),
			    staged);
		}
		(void)queued.release();
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}
/* HT-C END */

/* HCO1 is created and fsynced before this consumer can receive new work.
 * A PID reused after a process crash cannot satisfy its earlier HCR1 replay
 * with a new process-local nonce, even if it owns the same HCS1 session. */
static void
consumer_owner_name(const std::array<uint8_t, 16> &session, uint32_t pid,
    char name[49])
{
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".owner.", 7);
	for (size_t i = 0; i < session.size(); i++) {
		name[7 + i * 2] = hex[session[i] >> 4];
		name[8 + i * 2] = hex[session[i] & 15];
	}
	name[39] = '.';
	for (unsigned i = 0; i < 8; i++)
		name[40 + i] = hex[(pid >> (28 - 4 * i)) & 15];
	name[48] = '\0';
}

static std::array<uint8_t, 76>
consumer_owner_bytes(const client_fd &consumer)
{
	std::array<uint8_t, 76> wire{};
	memcpy(wire.data(), "HCO1", 4);
	memcpy(wire.data() + 4, consumer.session_id.data(), 16);
	dtraced_wire_put_u32(wire.data() + 20, (uint32_t)consumer.peer_uid);
	dtraced_wire_put_u32(wire.data() + 24, (uint32_t)consumer.peer_pid);
	memcpy(wire.data() + 28, consumer.consumer_birth.data(), 16);
	(void)SHA256(wire.data(), 44, wire.data() + 44);
	return (wire);
}

/* -1 malformed/error, 0 absent, 1 canonical. Startup audits every HCO1,
 * including an owner whose consumer is not currently connected. */
static int
consumer_owner_read_at(int directory, const char *name,
    std::array<uint8_t, 76> &wire)
{
	if (strlen(name) != 48) {
		errno = EPROTO;
		return (-1);
	}
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != 76))
		error = EPROTO;
	if (error == 0) {
		ssize_t n;
		do {
			n = pread(fd, wire.data(), wire.size(), 0);
		} while (n < 0 && errno == EINTR);
		if (n != (ssize_t)wire.size())
			error = n < 0 ? errno : EPROTO;
		else {
			uint8_t digest[SHA256_DIGEST_LENGTH];
			std::array<uint8_t, 16> session{}, birth{};
			memcpy(session.data(), wire.data() + 4, 16);
			memcpy(birth.data(), wire.data() + 28, 16);
			uint32_t uid = dtraced_wire_get_u32(wire.data() + 20);
			uint32_t pid = dtraced_wire_get_u32(wire.data() + 24);
			char canonical[49];
			consumer_owner_name(session, pid, canonical);
			if (memcmp(wire.data(), "HCO1", 4) != 0 ||
			    session == std::array<uint8_t, 16>{} ||
			    birth == std::array<uint8_t, 16>{} ||
			    uid == UINT32_MAX || pid <= 1 || pid > INT_MAX ||
			    strcmp(name, canonical) != 0 ||
			    SHA256(wire.data(), 44, digest) == NULL ||
			    memcmp(wire.data() + 44, digest,
			    sizeof(digest)) != 0)
				error = EPROTO;
		}
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

/* HCP1 preserves the source program evidence across consumer exit and HCO1
 * rotation. A pending HCR1 may acquire it before its first socket job; a
 * terminal legacy receipt is never backfilled from a replacement process. */
static void
consumer_program_name(const durable_consumer_receipt &record, char name[92])
{
	char receipt[96];
	consumer_receipt_name(record, consumer_receipt_phase::pending, receipt);
	memcpy(name, ".program.", 9);
	memcpy(name + 9, receipt + 10, 82);
	name[91] = '\0';
}

static constexpr size_t consumer_program_wire_size = 302;

static std::array<uint8_t, consumer_program_wire_size>
consumer_program_bytes(const durable_consumer_receipt &record,
    const std::array<uint8_t, 76> &owner,
    const std::array<uint8_t, 32> &program_digest)
{
	std::array<uint8_t, consumer_program_wire_size> wire{};
	memcpy(wire.data(), "HCP1", 4);
	auto receipt = consumer_receipt_bytes(record);
	memcpy(wire.data() + 4, receipt.data(), receipt.size());
	memcpy(wire.data() + 162, owner.data(), owner.size());
	memcpy(wire.data() + 238, program_digest.data(),
	    program_digest.size());
	(void)SHA256(wire.data(), 270, wire.data() + 270);
	return (wire);
}

static bool
consumer_program_decode_wire(const uint8_t *wire,
    const durable_consumer_receipt &record,
    std::array<uint8_t, 76> &owner,
    std::array<uint8_t, 32> &program_digest)
{
	owner = {};
	program_digest = {};
	uint8_t outer[SHA256_DIGEST_LENGTH], owner_digest[32];
	const auto receipt = consumer_receipt_bytes(record);
	std::array<uint8_t, 16> birth{};
	memcpy(birth.data(), wire + 190, birth.size());
	if (memcmp(wire, "HCP1", 4) != 0 ||
	    memcmp(wire + 4, receipt.data(), receipt.size()) != 0 ||
	    memcmp(wire + 162, "HCO1", 4) != 0 ||
	    memcmp(wire + 166, record.consumer_session.data(), 16) != 0 ||
	    dtraced_wire_get_u32(wire + 182) != record.consumer_uid ||
	    dtraced_wire_get_u32(wire + 186) != record.consumer_pid ||
	    birth == std::array<uint8_t, 16>{} ||
	    SHA256(wire + 162, 44, owner_digest) == NULL ||
	    memcmp(wire + 206, owner_digest, 32) != 0 ||
	    std::all_of(wire + 238, wire + 270,
	    [](uint8_t value) { return (value == 0); }) ||
	    SHA256(wire, 270, outer) == NULL ||
	    memcmp(wire + 270, outer, sizeof(outer)) != 0) {
		errno = EPROTO;
		return (false);
	}
	memcpy(owner.data(), wire + 162, owner.size());
	memcpy(program_digest.data(), wire + 238, program_digest.size());
	return (true);
}

static int
consumer_program_read_at(int directory,
    const durable_consumer_receipt &record,
    std::array<uint8_t, 76> &owner,
    std::array<uint8_t, 32> &program_digest)
{
	owner = {};
	program_digest = {};
	if (!consumer_receipt_valid(record)) {
		errno = EINVAL;
		return (-1);
	}
	char name[92];
	consumer_program_name(record, name);
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	std::array<uint8_t, consumer_program_wire_size> wire{};
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)wire.size()))
		error = EPROTO;
	for (size_t offset = 0; error == 0 && offset < wire.size();) {
		ssize_t n = pread(fd, wire.data() + offset,
		    wire.size() - offset, (off_t)offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && !consumer_program_decode_wire(wire.data(),
	    record, owner, program_digest))
		error = errno;
	if (error != 0) {
		owner = {};
		program_digest = {};
		errno = error;
		return (-1);
	}
	return (1);
}

/* HHL1 is published before HCP1, under the same process lock. A crash may
 * leave HHL1 without HCP1; the exact retry can finish publication. Existing
 * HCP1 without HHL1 is legacy evidence and must never acquire a new handle. */
static int
consumer_handle_at(int directory, const durable_consumer_receipt &record,
    const std::array<uint8_t, 76> &owner,
    const std::array<uint8_t, 32> &program,
    std::array<uint8_t, 24> &lifetime, bool publish)
{
	const auto binding = consumer_program_bytes(record, owner, program);
	std::array<uint8_t, 362> wire{};
	memcpy(wire.data(), "HHL1", 4);
	memcpy(wire.data() + 4, binding.data(), binding.size());
	memcpy(wire.data() + 306, lifetime.data(), lifetime.size());
	SHA256(wire.data(), 330, wire.data() + 330);
	char program_name[92], name[100];
	consumer_program_name(record, program_name);
	snprintf(name, sizeof(name), ".handle.%s", program_name + 9);
	int fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT)
			return (-1);
		if (!publish)
			return (0);
		return (handoff_publish_at(directory, name, wire.data(), wire.size()) ? 1 : -1);
	}
	struct stat st;
	std::array<uint8_t, 362> saved{};
	int error = fstat(fd, &st) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
	    st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
	    st.st_size != (off_t)saved.size()))
		error = EPROTO;
	for (size_t used = 0; error == 0 && used < saved.size();) {
		ssize_t n = read(fd, saved.data() + used, saved.size() - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			used += (size_t)n;
	}
	std::array<uint8_t, 24> decoded{};
	if (error == 0) {
		memcpy(decoded.data(), saved.data() + 306, decoded.size());
		std::array<uint8_t, 32> hash{};
		SHA256(saved.data(), 330, hash.data());
		if (memcmp(saved.data(), wire.data(), 306) != 0 ||
		    memcmp(saved.data() + 330, hash.data(), hash.size()) != 0 ||
		    (decoded != std::array<uint8_t, 24>{} &&
		    ((dtraced_wire_get_u64(decoded.data()) |
		    dtraced_wire_get_u64(decoded.data() + 8)) == 0 ||
		    dtraced_wire_get_u64(decoded.data() + 16) == 0)))
			error = EPROTO;
		else if (publish && decoded != lifetime)
			error = EEXIST;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	lifetime = decoded;
	return (1);
}

/* Private immutable records end with a SHA256 checksum. Both new publication
 * and exact retry must sync before the caller can use the durable evidence. */
template<size_t N>
static int
consumer_private_record_at(int directory, const char *name,
    const std::array<uint8_t, N> &wire, bool publish)
{
	int fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT)
			return (-1);
		if (!publish)
			return (0);
		return (handoff_publish_at(directory, name, wire.data(), wire.size()) ? 1 : -1);
	}
	std::array<uint8_t, N> saved{};
	struct stat st;
	int error = fstat(fd, &st) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
	    st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
	    st.st_size != (off_t)saved.size()))
		error = EPROTO;
	for (size_t used = 0; error == 0 && used < saved.size();) {
		ssize_t n = read(fd, saved.data() + used, saved.size() - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			used += (size_t)n;
	}
	if (error == 0) {
		std::array<uint8_t, 32> hash{};
		SHA256(saved.data(), N - 32, hash.data());
		if (memcmp(saved.data() + N - 32, hash.data(), hash.size()) != 0)
			error = EPROTO;
		else if (saved != wire)
			error = ESTALE;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

/* Read the durable completion independently of retired per-recipient journals.
 * FSI1 remains mandatory: completion must never remove the admission denial.
 * This is collector-stop evidence only, not permission to retire or resume a VM. */
static int
fresh_stop_completed_at(int directory, const durable_session_stop &stop)
{
	if (!fresh_stop_valid(stop)) {
		errno = EINVAL;
		return (-1);
	}
	char name[64];
	snprintf(name, sizeof(name), ".fresh-done.%04x.%016jx",
	    stop.vmid, (uintmax_t)stop.epoch);
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	std::array<uint8_t, 160> wire{};
	struct stat st;
	int error = fstat(fd, &st) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
	    st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
	    st.st_size != (off_t)wire.size()))
		error = EPROTO;
	for (size_t used = 0; error == 0 && used < wire.size();) {
		ssize_t n = pread(fd, wire.data() + used, wire.size() - used, used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			used += (size_t)n;
	}
	const auto fence = fresh_stop_bytes(stop);
	std::array<uint8_t, 32> digest{}, empty{};
	SHA256(wire.data(), 128, digest.data());
	SHA256(nullptr, 0, empty.data());
	uint64_t count = dtraced_wire_get_u64(wire.data() + 88);
	if (error == 0 && (memcmp(wire.data(), "FSD1", 4) != 0 ||
	    dtraced_wire_get_u32(wire.data() + 4) != 0 ||
	    count > consumer_receipt_limit ||
	    memcmp(wire.data() + 128, digest.data(), digest.size()) != 0 ||
	    (count == 0 && memcmp(wire.data() + 96, empty.data(), empty.size()) != 0)))
		error = EPROTO;
	if (error == 0 && memcmp(wire.data() + 8, fence.data(), fence.size()) != 0)
		error = ESTALE;
	durable_session_stop bound{};
	if (error == 0) {
		int present = fresh_stop_read_at(directory, stop.vmid, stop.epoch, bound);
		if (present != 1)
			error = present < 0 ? errno : EPROTO;
		else if (fresh_stop_bytes(bound) != fence)
			error = ESTALE;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0)
		errno = error;
	return (error == 0 ? 1 : -1);
}

int
dir::fresh_session_stop_completed(const durable_session_stop &stop)
{
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	return (fresh_stop_completed_at(this->dirfd, stop));
}

/* Caller holds both publication and cross-process locks throughout. */
static int
fresh_session_ack_retirement_at(int directory, const durable_session_stop *stop,
    std::vector<std::string> &result, bool retire)
try {
	if (stop != nullptr) {
		int complete = fresh_stop_completed_at(directory, *stop);
		if (complete != 1) {
			if (complete == 0) errno = EBUSY;
			return (-1);
		}
	}
	const auto fence = stop != nullptr ? fresh_stop_bytes(*stop) :
	    std::array<uint8_t, 80>{};
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scanfd < 0) return (-1);
	DIR *scan = fdopendir(scanfd);
	if (scan == nullptr) {
		int error = errno; close(scanfd); errno = error; return (-1);
	}
	std::vector<std::string> names;
	int error = 0;
	try {
		for (;;) {
			errno = 0;
			dirent *entry = readdir(scan);
			if (entry == nullptr) { error = errno; break; }
			if (strncmp(entry->d_name, ".fresh-ack.", 11) != 0) continue;
			if (strlen(entry->d_name) != 75) { error = EPROTO; break; }
			int fd = openat(directory, entry->d_name,
			    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
			if (fd < 0) { error = errno; break; }
			std::array<uint8_t, 224> wire{};
			struct stat st;
			if (fstat(fd, &st) != 0) error = errno;
			else if (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
			    st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
			    st.st_size != (off_t)wire.size()) error = EPROTO;
			for (size_t used = 0; error == 0 && used < wire.size();) {
				ssize_t n = pread(fd, wire.data() + used, wire.size() - used, used);
				if (n < 0 && errno == EINTR) continue;
				if (n <= 0) error = n < 0 ? errno : EPROTO;
				else used += (size_t)n;
			}
			if (close(fd) != 0 && error == 0) error = errno;
			if (error != 0) break;
			std::array<uint8_t, 32> hash{};
			SHA256(wire.data(), 192, hash.data());
			if (memcmp(wire.data(), "FSA1", 4) != 0 ||
			    memcmp(wire.data() + 192, hash.data(), hash.size()) != 0) {
				error = EPROTO; break;
			}
			static const char hex[] = "0123456789abcdef";
			for (size_t i = 0; i < hash.size(); ++i)
				if (entry->d_name[11 + 2*i] != hex[hash[i] >> 4] ||
				    entry->d_name[12 + 2*i] != hex[hash[i] & 15]) {
					error = EPROTO; break;
				}
			if (error != 0) break;
			if (stop != nullptr) {
				if (memcmp(wire.data() + 4, fence.data(), fence.size()) != 0) continue;
				if (names.size() >= consumer_receipt_limit) { error = EPROTO; break; }
			} else {
				/* Startup has no live VM identity. Decode the immutable
				 * fence from each ACK and require exact durable completion. */
				durable_session_stop candidate{};
				candidate.vmid = dtraced_wire_get_u16(wire.data() + 8);
				candidate.epoch = dtraced_wire_get_u64(wire.data() + 12);
				memcpy(candidate.token.data(), wire.data() + 20, 16);
				memcpy(candidate.source_session.data(), wire.data() + 36, 16);
				const auto canonical = fresh_stop_bytes(candidate);
				if (!fresh_stop_valid(candidate) ||
				    memcmp(wire.data() + 4, canonical.data(), canonical.size()) != 0) {
					error = EPROTO; break;
				}
				int complete = fresh_stop_completed_at(directory, candidate);
				/* Another token for this lifetime is not deletion authority. */
				if (complete < 0 && errno == ESTALE) continue;
				if (complete < 0) { error = errno; break; }
				if (complete == 0 || names.size() >= consumer_receipt_limit) continue;
			}
			names.emplace_back(entry->d_name);
		}
	} catch (const std::bad_alloc &) { error = ENOMEM; }
	if (closedir(scan) != 0 && error == 0) error = errno;
	if (error != 0) { errno = error; return (-1); }
	std::sort(names.begin(), names.end());
	if (retire) {
		/* Scan and validate the whole candidate set before the first unlink.
		 * The same process/publication locks exclude late ACK publishers. */
		int removal_error = 0;
		for (const auto &name : names) {
			if (unlinkat(directory, name.c_str(), 0) != 0) {
				removal_error = errno;
				break;
			}
		}
		/* Also sync empty retries and partial removal after failure. */
		if (fsync(directory) != 0 && removal_error == 0)
			removal_error = errno;
		if (removal_error != 0) { errno = removal_error; return (-1); }
	}
	result.swap(names);
	return (1);
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (-1);
}

int
dir::plan_fresh_session_ack_retirement(const durable_session_stop &stop,
    std::vector<std::string> &result)
{
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held()) return (-1);
	return (fresh_session_ack_retirement_at(this->dirfd, &stop, result, false));
}

int
dir::retire_fresh_session_acks(const durable_session_stop &stop)
{
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held()) return (-1);
	std::vector<std::string> retired;
	return (fresh_session_ack_retirement_at(this->dirfd, &stop, retired, true));
}

/* Retry abandoned cleanup after daemon restart, even if the source no longer
 * exists. Only FSA1 is removed; all admission/completion and owner evidence stays. */
int
dir::retire_completed_fresh_session_acks()
{
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held()) return (-1);
	for (;;) {
		std::vector<std::string> retired;
		if (fresh_session_ack_retirement_at(this->dirfd, nullptr, retired, true) != 1)
			return (-1);
		if (retired.empty()) return (1);
	}
}

/* FSD1 summarizes a fully proven collector stop. Keep all dependencies until
 * a separate retirement transaction can replace their recovery obligations.
 * In particular this record is neither source-VM retirement nor RELEASE. */
int
dir::complete_fresh_session_stop(dir &outbound, const durable_session_stop &stop)
try {
	std::vector<host_ingress_program_evidence> recipients;
	if (fresh_session_consumers(outbound, stop, recipients) < 0)
		return (-1);
	std::vector<std::array<uint8_t, 132>> identities;
	identities.reserve(recipients.size());
	for (const auto &proof : recipients) {
		int stopped = fresh_consumer_stop_receipt(outbound, stop, proof, false);
		if (stopped != 1) {
			if (stopped == 0)
				errno = EAGAIN;
			return (-1);
		}
		std::array<uint8_t, 24> lifetime{};
		if (consumer_handle_status(proof.recipient, lifetime) < 0)
			return (-1);
		std::array<uint8_t, 132> identity{};
		memcpy(identity.data(), proof.owner_wire.data(), 76);
		memcpy(identity.data() + 76, proof.program_digest.data(), 32);
		memcpy(identity.data() + 108, lifetime.data(), 24);
		identities.push_back(identity);
	}
	std::sort(identities.begin(), identities.end());
	std::array<uint8_t, 160> wire{};
	memcpy(wire.data(), "FSD1", 4);
	const auto fence = fresh_stop_bytes(stop);
	memcpy(wire.data() + 8, fence.data(), fence.size());
	dtraced_wire_put_u64(wire.data() + 88, identities.size());
	SHA256(reinterpret_cast<const unsigned char *>(identities.data()),
	    identities.size() * sizeof(identities[0]), wire.data() + 96);
	SHA256(wire.data(), 128, wire.data() + 128);
	/* The permanent source cut excludes new admitted cohort members while
	 * individual proof readers drop their locks. Revalidate its exact identity
	 * under the publication lock before making the summary durable. */
	std::lock_guard journal(outbound.publishmtx);
	handoff_process_lock process_lock(outbound.dirfd);
	if (!process_lock.held())
		return (-1);
	durable_session_stop bound{};
	int present = fresh_stop_read_at(outbound.dirfd, stop.vmid, stop.epoch, bound);
	if (present != 1 || fresh_stop_bytes(bound) != fence) {
		if (present >= 0)
			errno = ESTALE;
		return (-1);
	}
	int fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	hypertrace_epoch_gate gate{};
	int error = source_gate_query_fd(fd, stop.vmid, stop.epoch, gate) != 0 ? errno : 0;
	if (error == 0 && (gate.suspended != 1 ||
	    memcmp(gate.token, stop.token.data(), 16) != 0))
		error = EBUSY;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	char name[64];
	snprintf(name, sizeof(name), ".fresh-done.%04x.%016jx",
	    stop.vmid, (uintmax_t)stop.epoch);
	return (consumer_private_record_at(outbound.dirfd, name, wire, true));
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (-1);
}

static int
consumer_process_binding_at(int directory, const durable_consumer_receipt &record,
    const std::array<uint8_t, 76> &owner,
    const std::array<uint8_t, 32> &program,
    const std::array<uint8_t, 24> &lifetime, bool publish, bool exited = false)
{
	std::array<uint8_t, 16> boot{};
	size_t size = boot.size();
	if (sysctlbyname("kern.boot_id", boot.data(), &size, nullptr, 0) != 0)
		return (-1);
	if (size != boot.size() || boot == std::array<uint8_t, 16>{}) {
		errno = EPROTO;
		return (-1);
	}
	const auto binding = consumer_program_bytes(record, owner, program);
	std::array<uint8_t, 378> wire{};
	memcpy(wire.data(), exited ? "HPX1" : "HPB1", 4);
	memcpy(wire.data() + 4, binding.data(), binding.size());
	memcpy(wire.data() + 306, lifetime.data(), lifetime.size());
	memcpy(wire.data() + 330, boot.data(), boot.size());
	SHA256(wire.data(), 346, wire.data() + 346);
	char program_name[92], name[100];
	consumer_program_name(record, program_name);
	snprintf(name, sizeof(name), "%s%s",
	    exited ? ".process-exit." : ".process.", program_name + 9);
	return (consumer_private_record_at(directory, name, wire, publish));
}

/*
 * Retirement by reboot. HPB1 is published only for a registration whose
 * kernel birth identity was verified, and binds that exact collector,
 * program and kernel handle lifetime to the kern.boot_id of the boot that
 * observed it. kern.boot_id is generated once per kernel instance and no
 * process, descendant or DTrace handle survives into another instance, so a
 * checksummed HPB1 that matches every identity byte but names a different,
 * nonzero boot proves all three retirement facts at once. This is not a PID
 * inference: the current occupant of the numeric PID is never consulted.
 * A same-boot record proves nothing here (0); damaged evidence fails.
 */
static int
consumer_prior_boot_at(int directory, const durable_consumer_receipt &record,
    const std::array<uint8_t, 76> &owner,
    const std::array<uint8_t, 32> &program,
    const std::array<uint8_t, 24> &lifetime)
{
	std::array<uint8_t, 16> boot{};
	size_t size = boot.size();
	if (sysctlbyname("kern.boot_id", boot.data(), &size, nullptr, 0) != 0)
		return (-1);
	if (size != boot.size() || boot == std::array<uint8_t, 16>{}) {
		errno = EPROTO;
		return (-1);
	}
	const auto binding = consumer_program_bytes(record, owner, program);
	std::array<uint8_t, 378> expected{};
	memcpy(expected.data(), "HPB1", 4);
	memcpy(expected.data() + 4, binding.data(), binding.size());
	memcpy(expected.data() + 306, lifetime.data(), lifetime.size());
	char program_name[92], name[100];
	consumer_program_name(record, program_name);
	snprintf(name, sizeof(name), ".process.%s", program_name + 9);
	int fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	std::array<uint8_t, 378> saved{};
	struct stat st;
	int error = fstat(fd, &st) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
	    st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
	    st.st_size != (off_t)saved.size()))
		error = EPROTO;
	for (size_t used = 0; error == 0 && used < saved.size();) {
		ssize_t n = read(fd, saved.data() + used, saved.size() - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			used += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0) {
		std::array<uint8_t, 32> hash{};
		SHA256(saved.data(), 346, hash.data());
		if (memcmp(saved.data() + 346, hash.data(), hash.size()) != 0 ||
		    std::all_of(saved.begin() + 330, saved.begin() + 346,
		    [](uint8_t value) { return (value == 0); }))
			error = EPROTO;
		else if (memcmp(saved.data(), expected.data(), 330) != 0)
			error = ESTALE;
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (memcmp(saved.data() + 330, boot.data(), boot.size()) == 0 ? 0 : 1);
}

/* HPE1 is shared by all receipts of the exact collector identity. It proves
 * process exit only, allowing descriptor retirement without losing evidence
 * for another delivery during a daemon crash between receipt checkpoints. */
static int
consumer_shared_exit_at(int directory,
    const std::array<uint8_t, 76> &owner,
    const std::array<uint8_t, 32> &program,
    const std::array<uint8_t, 24> &lifetime, bool publish)
{
	std::array<uint8_t, 184> wire{};
	memcpy(wire.data(), "HPE1", 4);
	memcpy(wire.data() + 4, owner.data(), owner.size());
	memcpy(wire.data() + 80, program.data(), program.size());
	memcpy(wire.data() + 112, lifetime.data(), lifetime.size());
	size_t size = 16;
	if (sysctlbyname("kern.boot_id", wire.data() + 136, &size, nullptr, 0) != 0)
		return (-1);
	if (size != 16 || std::all_of(wire.begin() + 136, wire.begin() + 152,
	    [](uint8_t value) { return (value == 0); })) {
		errno = EPROTO;
		return (-1);
	}
	SHA256(wire.data(), 152, wire.data() + 152);
	char name[96];
	strlcpy(name, ".process-retired.", sizeof(name));
	size_t offset = strlen(name);
	for (unsigned i = 0; i < 32; i++)
		snprintf(name + offset + 2 * i, sizeof(name) - offset - 2 * i,
		    "%02x", wire[152 + i]);
	return (consumer_private_record_at(directory, name, wire, publish));
}

/* HRE1 proves an owned empty reaper at exit. Reserved bytes 152..159 remain
 * zero; the checksum covers them. Bind to the same exact collector and boot
 * as HPE1, but never reinterpret a process-exit receipt as descendant evidence. */
static int
consumer_reaper_empty_at(int directory,
    const std::array<uint8_t, 76> &owner,
    const std::array<uint8_t, 32> &program,
    const std::array<uint8_t, 24> &lifetime, bool publish)
{
	std::array<uint8_t, 192> wire{};
	memcpy(wire.data(), "HRE1", 4);
	memcpy(wire.data() + 4, owner.data(), owner.size());
	memcpy(wire.data() + 80, program.data(), program.size());
	memcpy(wire.data() + 112, lifetime.data(), lifetime.size());
	size_t size = 16;
	if (sysctlbyname("kern.boot_id", wire.data() + 136, &size, nullptr, 0) != 0)
		return (-1);
	if (size != 16 || std::all_of(wire.begin() + 136, wire.begin() + 152,
	    [](uint8_t value) { return (value == 0); })) {
		errno = EPROTO;
		return (-1);
	}
	SHA256(wire.data(), 160, wire.data() + 160);
	char name[96];
	strlcpy(name, ".reaper-empty.", sizeof(name));
	size_t offset = strlen(name);
	for (unsigned i = 0; i < 32; i++)
		snprintf(name + offset + 2 * i, sizeof(name) - offset - 2 * i,
		    "%02x", wire[160 + i]);
	return (consumer_private_record_at(directory, name, wire, publish));
}

/* The registry key was authenticated before registration admission. Unlike
 * the receipt path, this also covers collectors with no admitted deliveries. */
int
dir::checkpoint_collector_exit(const std::array<uint8_t, 96> &key,
    collector_owner_registry &owners)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	if (!owners.retained(key))
		return (0); // Another checkpoint already released it.
	int exited = owners.exited(key);
	if (exited != 1)
		return (exited);
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> lifetime{};
	memcpy(owner.data(), "HCO1", 4);
	memcpy(owner.data() + 4, key.data(), 16);
	memcpy(owner.data() + 20, key.data() + 32, 8);
	memcpy(owner.data() + 28, key.data() + 16, 16);
	SHA256(owner.data(), 44, owner.data() + 44);
	memcpy(program.data(), key.data() + 40, program.size());
	memcpy(lifetime.data(), key.data() + 72, lifetime.size());
	int empty = consumer_reaper_empty_at(this->dirfd, owner, program,
	    lifetime, false);
	if (empty < 0)
		return (-1);
	if (empty == 0) {
		empty = owners.reaper_empty(key);
		if (empty < 0 || (empty == 1 && consumer_reaper_empty_at(
		    this->dirfd, owner, program, lifetime, true) != 1))
			return (-1);
	}
	if (consumer_shared_exit_at(this->dirfd, owner, program, lifetime, true) != 1)
		return (-1);
	return (owners.release_after_durable_exit(key) == 0 ? 1 : -1);
}

int
dir::record_consumer_program(const durable_consumer_receipt &record,
    const client_fd &consumer)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    !consumer_receipt_valid(record) ||
	    !consumer.consumer_birth_valid ||
	    !consumer.consumer_program_valid ||
	    consumer.consumer_program_digest == std::array<uint8_t, 32>{} ||
	    consumer.session_id != record.consumer_session ||
	    consumer.peer_uid != (uid_t)record.consumer_uid ||
	    consumer.peer_pid != (pid_t)record.consumer_pid) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	int phase = consumer_receipt_status_at(this->dirfd, record);
	if (phase <= 0) {
		if (phase == 0)
			errno = EPROTO;
		return (-1);
	}
	char owner_name[49];
	consumer_owner_name(consumer.session_id,
	    (uint32_t)consumer.peer_pid, owner_name);
	std::array<uint8_t, 76> durable_owner{};
	int present = consumer_owner_read_at(this->dirfd, owner_name,
	    durable_owner);
	if (present != 1) {
		if (present == 0)
			errno = EBUSY;
		return (-1);
	}
	if (durable_owner != consumer_owner_bytes(consumer)) {
		errno = EPROTO;
		return (-1);
	}
	/* A reconciler can persist HPE1 and release the pin before this
	 * pending delivery publishes HCP1. Its exact durable registration
	 * evidence still authorizes HPB1; missing evidence never does. */
	auto process_verified = [&](const std::array<uint8_t, 24> &lifetime) {
		if (this->state->collector_owners.retained(collector_owner_identity(
		    consumer.session_id, consumer.consumer_birth,
		    (uint32_t)consumer.peer_uid, (uint32_t)consumer.peer_pid,
		    consumer.consumer_program_digest, lifetime)))
			return (1);
		return (consumer_shared_exit_at(this->dirfd, durable_owner,
		    consumer.consumer_program_digest, lifetime, false));
	};
	std::array<uint8_t, 76> existing_owner{};
	std::array<uint8_t, 32> existing_program{};
	present = consumer_program_read_at(this->dirfd, record,
	    existing_owner, existing_program);
	if (present < 0)
		return (-1);
	if (present == 1) {
		if (existing_owner != durable_owner ||
		    existing_program != consumer.consumer_program_digest) {
			errno = EEXIST;
			return (-1);
		}
		auto lifetime = consumer.consumer_handle_lifetime;
		int pinned = consumer_handle_at(this->dirfd, record, durable_owner,
		    consumer.consumer_program_digest, lifetime, false);
		if (pinned < 0)
			return (-1);
		if ((pinned == 0 && lifetime != std::array<uint8_t, 24>{}) ||
		    (pinned == 1 && lifetime != consumer.consumer_handle_lifetime)) {
			errno = ESTALE;
			return (-1);
		}
		if (lifetime != std::array<uint8_t, 24>{}) {
			int verified = process_verified(lifetime);
			if (verified < 0 || (verified == 1 &&
			    consumer_process_binding_at(this->dirfd, record, durable_owner,
			    consumer.consumer_program_digest, lifetime, true) != 1))
				return (-1);
		}
		return (fsync(this->dirfd) == 0 ? 1 : -1);
	}
	if (phase != (int)consumer_receipt_phase::pending) {
		errno = EBUSY;
		return (-1);
	}
	auto lifetime = consumer.consumer_handle_lifetime;
	if (lifetime != std::array<uint8_t, 24>{} &&
	    ((dtraced_wire_get_u64(lifetime.data()) |
	    dtraced_wire_get_u64(lifetime.data() + 8)) == 0 ||
	    dtraced_wire_get_u64(lifetime.data() + 16) == 0)) {
		errno = EINVAL;
		return (-1);
	}
	if (consumer_handle_at(this->dirfd, record, durable_owner,
	    consumer.consumer_program_digest, lifetime, true) != 1)
		return (-1);
	if (lifetime != std::array<uint8_t, 24>{}) {
		int verified = process_verified(lifetime);
		if (verified < 0 || (verified == 1 &&
		    consumer_process_binding_at(this->dirfd, record, durable_owner,
		    consumer.consumer_program_digest, lifetime, true) != 1))
			return (-1);
	}
	const auto wire = consumer_program_bytes(record, durable_owner,
	    consumer.consumer_program_digest);
	char name[92];
	consumer_program_name(record, name);
	return (handoff_publish_at(this->dirfd, name, wire.data(),
	    wire.size()) ? 1 : -1);
}

int
dir::consumer_handle_status(const durable_consumer_receipt &record,
    std::array<uint8_t, 24> &lifetime)
{
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> candidate{};
	int present = consumer_program_read_at(this->dirfd, record, owner, program);
	if (present != 1)
		return (present);
	present = consumer_handle_at(this->dirfd, record, owner, program,
	    candidate, false);
	if (present != 1)
		return (present);
	if (candidate == std::array<uint8_t, 24>{})
		return (0);
	lifetime = candidate;
	return (1);
}

int
dir::recover_consumer_process(const durable_consumer_receipt &record,
    collector_owner_registry &owners)
{
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> lifetime{};
	{
		std::lock_guard journal(this->publishmtx);
		handoff_process_lock process_lock(this->dirfd);
		if (!process_lock.held())
			return (-1);
		int present = consumer_program_read_at(this->dirfd, record, owner, program);
		if (present == 1)
			present = consumer_handle_at(this->dirfd, record, owner, program,
			    lifetime, false);
		if (present == 1 && lifetime != std::array<uint8_t, 24>{})
			present = consumer_process_binding_at(this->dirfd, record, owner,
			    program, lifetime, false);
		else if (present == 1)
			present = 0;
		if (present != 1) {
			if (present == 0)
				errno = EAGAIN;
			return (-1);
		}
	}
	std::array<uint8_t, 16> birth{};
	memcpy(birth.data(), owner.data() + 28, birth.size());
	auto key = collector_owner_identity(record.consumer_session, birth,
	    record.consumer_uid, record.consumer_pid, program, lifetime);
	if (owners.retained(key))
		return (1);
	pd_birth_identity expected{};
	expected.pid = (pid_t)record.consumer_pid;
	expected.start_sec = dtraced_wire_get_u64(birth.data());
	expected.start_usec = dtraced_wire_get_u64(birth.data() + 8);
	int fd = -1;
	if (collector_process_pin(expected.pid, expected, &fd) != 0)
		return (-1);
	int result = owners.retain(key, fd);
	int error = result != 0 ? errno : 0;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

/* Persist explicit process exit before losing the retained descriptor. This
 * is not FSA1: descendant output and kernel handle retirement remain separate.
 * HPE1 is shared by exact identities; old HPX1 is promoted on exact retry. */
int
dir::checkpoint_consumer_process_exit(const durable_consumer_receipt &record,
    collector_owner_registry &owners)
{
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> lifetime{};
	int present = consumer_program_read_at(this->dirfd, record, owner, program);
	if (present == 1)
		present = consumer_handle_at(this->dirfd, record, owner, program,
		    lifetime, false);
	if (present == 1 && lifetime != std::array<uint8_t, 24>{})
		present = consumer_process_binding_at(this->dirfd, record, owner,
		    program, lifetime, false);
	else if (present == 1)
		present = 0;
	if (present != 1) {
		if (present == 0)
			errno = EAGAIN;
		return (-1);
	}
	std::array<uint8_t, 16> birth{};
	memcpy(birth.data(), owner.data() + 28, birth.size());
	auto key = collector_owner_identity(record.consumer_session, birth,
	    record.consumer_uid, record.consumer_pid, program, lifetime);
	present = consumer_shared_exit_at(this->dirfd, owner, program, lifetime, false);
	if (present < 0)
		return (-1);
	/* Preserve descendant evidence before releasing the only pinned query.
	 * Errors retain the descriptor. A nonempty/non-reaper snapshot proves only
	 * process exit; absence of HRE1 must never become a descendant proof. */
	auto preserve_reaper = [&]() {
		int saved = consumer_reaper_empty_at(this->dirfd, owner, program,
		    lifetime, false);
		if (saved != 0)
			return (saved);
		if (!owners.retained(key))
			return (0); // Old exit proof cannot synthesize a lost snapshot.
		int empty = owners.reaper_empty(key);
		if (empty != 1)
			return (empty);
		return (consumer_reaper_empty_at(this->dirfd, owner, program,
		    lifetime, true));
	};
	if (present == 0) {
		/* Promote an exact old per-receipt checkpoint when available. */
		int exited = consumer_process_binding_at(this->dirfd, record, owner,
		    program, lifetime, false, true);
		if (exited < 0)
			return (-1);
		/* HRE1 includes an explicit exit snapshot. Recover a crash between
		 * its durable publication and HPE1 without needing a lost pin. */
		if (exited == 0)
			exited = consumer_reaper_empty_at(this->dirfd, owner, program,
			    lifetime, false);
		if (exited == 0)
			exited = owners.exited(key);
		if (exited != 1)
			return (exited);
		if (preserve_reaper() < 0)
			return (-1);
		if (consumer_shared_exit_at(this->dirfd, owner, program, lifetime,
		    true) != 1)
			return (-1);
	}
	if (present == 1 && preserve_reaper() < 0)
		return (-1);
	/* HPE1 is durable for all exact receipts before retiring this receipt's
	 * redundant HPX1. Validate the legacy binding before unlinking; never
	 * discard the shared evidence or the HCP1/HHL1/HPB1 dependencies here.
	 * Sync even an absent legacy name to finish a lost unlink-sync retry. */
	int legacy = consumer_process_binding_at(this->dirfd, record, owner,
	    program, lifetime, false, true);
	if (legacy < 0)
		return (-1);
	if (legacy == 1) {
		char program_name[92], name[100];
		consumer_program_name(record, program_name);
		snprintf(name, sizeof(name), ".process-exit.%s", program_name + 9);
		if (unlinkat(this->dirfd, name, 0) != 0)
			return (-1);
	}
	if (fsync(this->dirfd) != 0)
		return (-1);
	/* Every exact receipt can now recover from HPE1 without this descriptor. */
	return (owners.release_after_durable_exit(key) == 0 ? 1 : -1);
}

/* HRE1 is descendant evidence, not an FSA1 stop receipt. */
int
dir::consumer_reaper_exit_status(const durable_consumer_receipt &record)
{
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> lifetime{};
	int present = consumer_program_read_at(this->dirfd, record, owner, program);
	if (present == 1)
		present = consumer_handle_at(this->dirfd, record, owner, program,
		    lifetime, false);
	if (present == 1 && lifetime != std::array<uint8_t, 24>{})
		present = consumer_process_binding_at(this->dirfd, record, owner,
		    program, lifetime, false);
	else if (present == 1)
		present = 0;
	if (present != 1)
		return (present);
	return (consumer_reaper_empty_at(this->dirfd, owner, program, lifetime, false));
}

/* Only a descriptor retained at verified registration can satisfy this query.
 * Historical HCO1 nonces and missing descriptors never establish process death.
 * This is process evidence only, not a durable collector-stop receipt. */
int
dir::consumer_process_exited(const durable_consumer_receipt &record,
    collector_owner_registry &owners)
{
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> lifetime{};
	{
		std::lock_guard journal(this->publishmtx);
		handoff_process_lock process_lock(this->dirfd);
		if (!process_lock.held())
			return (-1);
		int present = consumer_program_read_at(this->dirfd, record,
		    owner, program);
		if (present == 1)
			present = consumer_handle_at(this->dirfd, record, owner,
			    program, lifetime, false);
		if (present != 1 || lifetime == std::array<uint8_t, 24>{}) {
			if (present >= 0)
				errno = EAGAIN;
			return (-1);
		}
	}
	std::array<uint8_t, 16> birth{};
	memcpy(birth.data(), owner.data() + 28, birth.size());
	return (owners.exited(collector_owner_identity(record.consumer_session,
	    birth, record.consumer_uid, record.consumer_pid, program, lifetime)));
}

int
dir::consumer_prior_boot_retired(const durable_consumer_receipt &record)
{
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> lifetime{};
	int present = consumer_program_read_at(this->dirfd, record, owner, program);
	if (present == 1)
		present = consumer_handle_at(this->dirfd, record, owner, program,
		    lifetime, false);
	if (present != 1 || lifetime == std::array<uint8_t, 24>{})
		return (present < 0 ? -1 : 0);
	return (consumer_prior_boot_at(this->dirfd, record, owner, program, lifetime));
}

int
dir::consumer_kernel_handle_retired(const durable_consumer_receipt &record)
{
	std::array<uint8_t, 24> lifetime{};
	int present = consumer_handle_status(record, lifetime);
	if (present != 1) {
		if (present == 0)
			errno = EAGAIN;
		return (-1);
	}
	return (collector_handle_retired(lifetime));
}

int
dir::consumer_program_status(const durable_consumer_receipt &record,
    std::array<uint8_t, 76> &owner,
    std::array<uint8_t, 32> &program_digest)
{
	owner = {};
	program_digest = {};
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	int phase = consumer_receipt_status_at(this->dirfd, record);
	if (phase <= 0) {
		if (phase == 0)
			errno = ENOENT;
		return (-1);
	}
	return (consumer_program_read_at(this->dirfd, record, owner,
	    program_digest));
}

/* HCE1 is the durable observation of an execution report. The report's
 * socket identity is checked by the caller before publication. Binding the
 * frozen HCP1 digest prevents a later process incarnation from inheriting
 * an unfinished report after daemon restart. */
static constexpr size_t consumer_execution_wire_size = 227;

static void
consumer_execution_name(const durable_consumer_receipt &record,
    char name[94])
{
	char receipt[96];
	consumer_receipt_name(record, consumer_receipt_phase::pending, receipt);
	memcpy(name, ".execution.", 11);
	memcpy(name + 11, receipt + 10, 82);
	name[93] = '\0';
}

static std::array<uint8_t, consumer_execution_wire_size>
consumer_execution_bytes(const durable_consumer_receipt &record,
    consumer_receipt_phase target, const std::array<uint8_t, 32> &proof)
{
	std::array<uint8_t, consumer_execution_wire_size> wire{};
	memcpy(wire.data(), "HCE1", 4);
	const auto receipt = consumer_receipt_bytes(record);
	memcpy(wire.data() + 4, receipt.data(), receipt.size());
	wire[162] = (uint8_t)target;
	memcpy(wire.data() + 163, proof.data(), proof.size());
	(void)SHA256(wire.data(), 195, wire.data() + 195);
	return (wire);
}

static int
consumer_execution_read_at(int directory,
    const durable_consumer_receipt &record,
    const std::array<uint8_t, 32> &proof,
    consumer_receipt_phase &target)
{
	char name[94];
	consumer_execution_name(record, name);
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	std::array<uint8_t, consumer_execution_wire_size> wire{};
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)wire.size()))
		error = EPROTO;
	for (size_t offset = 0; error == 0 && offset < wire.size();) {
		ssize_t n = pread(fd, wire.data() + offset,
		    wire.size() - offset, (off_t)offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0) {
		uint8_t digest[32];
		(void)SHA256(wire.data(), 195, digest);
		target = (consumer_receipt_phase)wire[162];
		if (memcmp(wire.data(), "HCE1", 4) != 0 ||
		    memcmp(wire.data() + 4,
		    consumer_receipt_bytes(record).data(), 158) != 0 ||
		    memcmp(wire.data() + 163, proof.data(), proof.size()) != 0 ||
		    memcmp(wire.data() + 195, digest, sizeof(digest)) != 0 ||
		    (target != consumer_receipt_phase::executed_no_derived &&
		    target != consumer_receipt_phase::executed_derived))
			error = EPROTO;
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

int
dir::record_consumer_execution(const durable_consumer_receipt &record,
    consumer_receipt_phase target, bool publish)
{
	if (!consumer_receipt_valid(record) ||
	    (target != consumer_receipt_phase::executed_no_derived &&
	    target != consumer_receipt_phase::executed_derived)) {
		errno = EINVAL;
		return (-1);
	}
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	int phase = consumer_receipt_status_at(this->dirfd, record);
	if (phase <= 0) {
		if (phase == 0)
			errno = ENOENT;
		return (-1);
	}
	int ingress = delivery_record_status_at(this->dirfd, record.ingress);
	if (ingress != (int)delivery_phase::accepted) {
		if (ingress == 0)
			errno = ENOENT;
		else if (ingress > 0)
			errno = EPROTO;
		return (-1);
	}
	if ((phase == (int)consumer_receipt_phase::no_derived ||
	    phase == (int)consumer_receipt_phase::executed_no_derived) &&
	    target != consumer_receipt_phase::executed_no_derived) {
		errno = EPROTO;
		return (-1);
	}
	if ((phase == (int)consumer_receipt_phase::derived ||
	    phase == (int)consumer_receipt_phase::executed_derived) &&
	    target != consumer_receipt_phase::executed_derived) {
		errno = EPROTO;
		return (-1);
	}
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	int frozen_present = consumer_program_read_at(this->dirfd,
	    record, owner, program);
	if (frozen_present != 1) {
		if (frozen_present == 0)
			errno = EPROTO;
		return (-1);
	}
	const auto frozen = consumer_program_bytes(record, owner, program);
	std::array<uint8_t, 32> proof{};
	memcpy(proof.data(), frozen.data() + 270, proof.size());
	consumer_receipt_phase existing{};
	int present = consumer_execution_read_at(this->dirfd, record,
	    proof, existing);
	if (present < 0)
		return (-1);
	if (present == 1 && existing != target) {
		errno = EPROTO;
		return (-1);
	}
	if (present == 0) {
		if (!publish) {
			errno = ENOENT;
			return (-1);
		}
		char name[94];
		consumer_execution_name(record, name);
		const auto wire = consumer_execution_bytes(record, target, proof);
		if (!handoff_publish_at(this->dirfd, name, wire.data(),
		    wire.size()))
			return (-1);
	}
	if (phase == (int)target)
		return (fsync(this->dirfd) == 0 ? phase : -1);
	char from[96], to[96];
	consumer_receipt_name(record, (consumer_receipt_phase)phase, from);
	consumer_receipt_name(record, target, to);
	if (renameat(this->dirfd, from, this->dirfd, to) != 0 ||
	    fsync(this->dirfd) != 0)
		return (-1);
	return ((int)target);
}

bool
dir::recover_consumer_executions(
    const std::vector<durable_consumer_receipt_state> &receipts)
{
	std::unordered_map<std::string, const durable_consumer_receipt *> by_name;
	try {
		for (const auto &entry : receipts) {
			char name[94];
			consumer_execution_name(entry.record, name);
			if (!by_name.emplace(name, &entry.record).second) {
				errno = EPROTO;
				return (false);
			}
		}
		int fd = openat(this->dirfd, ".",
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (fd < 0)
			return (false);
		DIR *scan = fdopendir(fd);
		if (scan == nullptr) {
			int error = errno;
			close(fd);
			errno = error;
			return (false);
		}
		std::vector<const durable_consumer_receipt *> pending;
		int error = 0;
		for (;;) {
			errno = 0;
			struct dirent *file = readdir(scan);
			if (file == nullptr) {
				error = errno;
				break;
			}
			if (strncmp(file->d_name, ".execution.", 11) != 0)
				continue;
			auto found = by_name.find(file->d_name);
			if (found == by_name.end()) {
				error = EPROTO;
				break;
			}
			pending.push_back(found->second);
		}
		if (closedir(scan) != 0 && error == 0)
			error = errno;
		if (error != 0) {
			errno = error;
			return (false);
		}
		for (const auto *record : pending) {
			std::array<uint8_t, 76> owner{};
			std::array<uint8_t, 32> program{};
			if (consumer_program_status(*record, owner, program) != 1)
				return (false);
			const auto frozen = consumer_program_bytes(*record,
			    owner, program);
			std::array<uint8_t, 32> proof{};
			memcpy(proof.data(), frozen.data() + 270, proof.size());
			consumer_receipt_phase target{};
			if (consumer_execution_read_at(this->dirfd, *record,
			    proof, target) != 1 ||
			    record_consumer_execution(*record, target, false) !=
			    (int)target)
				return (false);
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	return (true);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* HTM2 is a provisional overlay on exact HTM1. It carries one HCP1 proof
 * per HTM1 recipient in canonical order. A later checkpoint must bind the
 * entire overlay in HTX1 before source PREPARE may admit accepted ingress. */
bool
dir::validate_host_ingress_program_manifest(const durable_handoff &ticket,
    const std::vector<uint8_t> &wire,
    std::vector<uint8_t> *source_manifest,
    std::vector<host_ingress_program_evidence> *evidence)
{
	if (source_manifest != nullptr)
		source_manifest->clear();
	if (evidence != nullptr)
		evidence->clear();
	const size_t minimum = 12 + 50 + 143 + 4 + 159 + 32 +
	    consumer_program_wire_size + 32;
	if (wire.size() < minimum || wire.size() > max_request_bytes ||
	    memcmp(wire.data(), "HTM2", 4) != 0) {
		errno = EPROTO;
		return (false);
	}
	const size_t tail = wire.size() - SHA256_DIGEST_LENGTH;
	const uint32_t nested_length = dtraced_wire_get_u32(wire.data() + 4);
	const uint32_t count = dtraced_wire_get_u32(wire.data() + 8);
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (count == 0 || count > consumer_receipt_limit ||
	    nested_length > tail - 12 ||
	    tail != 12 + (size_t)nested_length +
	    (size_t)count * consumer_program_wire_size ||
	    SHA256(wire.data(), tail, digest) == NULL ||
	    memcmp(wire.data() + tail, digest, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::vector<uint8_t> nested(wire.begin() + 12,
		    wire.begin() + 12 + nested_length);
		std::vector<host_ingress_transfer_entry> entries;
		if (!validate_host_ingress_transfer_manifest(ticket, nested,
		    &entries))
			return (false);
		size_t recipients = 0;
		for (const auto &entry : entries)
			recipients += entry.recipients.size();
		if (recipients != count) {
			errno = EPROTO;
			return (false);
		}
		std::vector<host_ingress_program_evidence> checked;
		checked.reserve(count);
		size_t offset = 12 + nested_length;
		for (const auto &entry : entries)
			for (const auto &recipient : entry.recipients) {
				host_ingress_program_evidence member{};
				member.recipient = recipient.record;
				if (!consumer_program_decode_wire(wire.data() + offset,
				    member.recipient, member.owner_wire,
				    member.program_digest))
					return (false);
				checked.push_back(member);
				offset += consumer_program_wire_size;
			}
		if (source_manifest != nullptr)
			source_manifest->swap(nested);
		if (evidence != nullptr)
			evidence->swap(checked);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

int
dir::host_ingress_program_manifest_locked(const durable_handoff &ticket,
    const std::vector<uint8_t> &source_manifest,
    std::vector<uint8_t> &result)
{
	result.clear();
	std::vector<host_ingress_transfer_entry> entries;
	if (!validate_host_ingress_transfer_manifest(ticket, source_manifest,
	    &entries))
		return (-1);
	size_t count = 0;
	for (const auto &entry : entries)
		count += entry.recipients.size();
	if (count == 0 || count > consumer_receipt_limit ||
	    source_manifest.size() > max_request_bytes - 12 - 32 ||
	    count * consumer_program_wire_size >
	    max_request_bytes - 12 - 32 - source_manifest.size()) {
		errno = E2BIG;
		return (-1);
	}
	try {
		std::vector<uint8_t> candidate(12 + source_manifest.size() +
		    count * consumer_program_wire_size + 32, 0);
		memcpy(candidate.data(), "HTM2", 4);
		dtraced_wire_put_u32(candidate.data() + 4,
		    (uint32_t)source_manifest.size());
		dtraced_wire_put_u32(candidate.data() + 8,
		    (uint32_t)count);
		memcpy(candidate.data() + 12, source_manifest.data(),
		    source_manifest.size());
		size_t offset = 12 + source_manifest.size();
		for (const auto &entry : entries)
			for (const auto &recipient : entry.recipients) {
				std::array<uint8_t, 76> owner{};
				std::array<uint8_t, 32> digest{};
				int status = consumer_program_status(
				    recipient.record, owner, digest);
				if (status != 1) {
					if (status == 0)
						errno = EBUSY;
					return (-1);
				}
				auto proof = consumer_program_bytes(
				    recipient.record, owner, digest);
				memcpy(candidate.data() + offset, proof.data(),
				    proof.size());
				offset += proof.size();
			}
		if (SHA256(candidate.data(), offset,
		    candidate.data() + offset) == NULL)
			return (-1);
		if (!validate_host_ingress_program_manifest(ticket,
		    candidate))
			return (-1);
		result.swap(candidate);
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

int
dir::host_ingress_program_manifest(const durable_handoff &ticket,
    const std::vector<uint8_t> &source_manifest,
    std::vector<uint8_t> &result)
{
	result.clear();
	std::vector<uint8_t> current;
	int present = host_ingress_transfer_snapshot(ticket, current);
	if (present <= 0) {
		if (present == 0 && !source_manifest.empty()) {
			errno = ESTALE;
			return (-1);
		}
		return (present);
	}
	if (current != source_manifest) {
		errno = ESTALE;
		return (-1);
	}
	std::vector<uint8_t> candidate;
	if (host_ingress_program_manifest_locked(ticket, current,
	    candidate) != 1)
		return (-1);
	std::vector<uint8_t> still_current;
	present = host_ingress_transfer_snapshot(ticket, still_current);
	if (present != 1) {
		if (present == 0)
			errno = ESTALE;
		return (-1);
	}
	if (still_current != current) {
		errno = ESTALE;
		return (-1);
	}
	result.swap(candidate);
	return (1);
}

/* A successful consumer drain is an observation about one frozen HCP1
 * recipient and one exact HTX1 cut. It is not an execution-state lease. */
static constexpr size_t source_drain_wire_size =
    4 + 16 + 16 + 2 + 8 + 32 + consumer_program_wire_size + 32;

static void
source_drain_name(const durable_handoff &ticket,
    const durable_consumer_receipt &recipient, char name[105])
{
	static const char hex[] = "0123456789abcdef";
	const auto receipt = consumer_receipt_bytes(recipient);
	uint8_t digest[SHA256_DIGEST_LENGTH];
	(void)SHA256(receipt.data(), receipt.size(), digest);
	memcpy(name, ".drain.", 7);
	for (size_t i = 0; i < ticket.token.size(); i++) {
		name[7 + 2 * i] = hex[ticket.token[i] >> 4];
		name[8 + 2 * i] = hex[ticket.token[i] & 15];
	}
	name[39] = '.';
	for (size_t i = 0; i < sizeof(digest); i++) {
		name[40 + 2 * i] = hex[digest[i] >> 4];
		name[41 + 2 * i] = hex[digest[i] & 15];
	}
	name[104] = '\0';
}

static std::array<uint8_t, source_drain_wire_size>
source_drain_bytes(const durable_handoff &ticket,
    const host_ingress_program_evidence &proof)
{
	std::array<uint8_t, source_drain_wire_size> wire{};
	memcpy(wire.data(), "HGD1", 4);
	memcpy(wire.data() + 4, ticket.token.data(), 16);
	memcpy(wire.data() + 20, ticket.source_session.data(), 16);
	dtraced_wire_put_u16(wire.data() + 36, ticket.source_vmid);
	dtraced_wire_put_u64(wire.data() + 38, ticket.source_epoch);
	memcpy(wire.data() + 46, ticket.transfer_digest.data(), 32);
	const auto program = consumer_program_bytes(proof.recipient,
	    proof.owner_wire, proof.program_digest);
	memcpy(wire.data() + 78, program.data(), program.size());
	(void)SHA256(wire.data(), wire.size() - SHA256_DIGEST_LENGTH,
	    wire.data() + wire.size() - SHA256_DIGEST_LENGTH);
	return (wire);
}

/* Read only a canonical, private, single-link inode. A torn or changed
 * receipt cannot be replaced on retry, even if the consumer ACK was lost. */
static int
source_drain_read_at(int directory, const char *name,
    const std::array<uint8_t, source_drain_wire_size> &expected)
{
	int fd = openat(directory, name,
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : -1);
	std::array<uint8_t, source_drain_wire_size> wire{};
	struct stat sb;
	int error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)wire.size()))
		error = EPROTO;
	for (size_t offset = 0; error == 0 && offset < wire.size();) {
		ssize_t n = pread(fd, wire.data() + offset,
		    wire.size() - offset, (off_t)offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && wire != expected)
		error = EPROTO;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (1);
}

/* PREPARE holds the outbound publication and process locks. Require the
 * complete HTM2 recipient set to have exact HGD1 receipts before an
 * execution lease may ever open the accepted-ingress path. */
static bool
source_drain_receipts_complete_at(int directory,
    const durable_handoff &ticket, const std::vector<uint8_t> &manifest)
{
	std::vector<host_ingress_program_evidence> recipients;
	if (!dir::validate_host_ingress_program_manifest(ticket,
	    manifest, nullptr, &recipients))
		return (false);
	if (recipients.empty()) {
		errno = EPROTO;
		return (false);
	}
	for (const auto &proof : recipients) {
		char name[105];
		source_drain_name(ticket, proof.recipient, name);
		const auto wire = source_drain_bytes(ticket, proof);
		int present = source_drain_read_at(directory, name, wire);
		if (present != 1) {
			if (present == 0)
				errno = EBUSY;
			return (false);
		}
	}
	return (true);
}

int
dir::source_consumer_drain_receipt(const durable_handoff &ticket,
    const host_ingress_program_evidence &proof, bool publish)
{
	if (!handoff_valid(ticket, handoff_phase::prepared) ||
	    ticket.transfer_digest == std::array<uint8_t, 32>{} ||
	    !consumer_receipt_valid(proof.recipient) ||
	    this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    this->state->inbounddir == nullptr ||
	    this->state->inbounddir == this) {
		errno = EINVAL;
		return (-1);
	}
	const auto program = consumer_program_bytes(proof.recipient,
	    proof.owner_wire, proof.program_digest);
	std::array<uint8_t, 76> checked_owner{};
	std::array<uint8_t, 32> checked_program{};
	if (!consumer_program_decode_wire(program.data(), proof.recipient,
	    checked_owner, checked_program))
		return (-1);
	std::lock_guard source(this->publishmtx);
	handoff_process_lock process_lock(this->dirfd);
	if (!process_lock.held())
		return (-1);
	durable_handoff active{}, intent{};
	std::array<uint8_t, 16> previous{};
	int phase = handoff_source_state_at(this->dirfd,
	    ticket.source_vmid, ticket.source_epoch, active);
	if (phase != 0) {
		if (phase > 0)
			errno = EBUSY;
		return (-1);
	}
	int gate_present = source_gate_for_epoch_at(this->dirfd,
	    ticket.source_vmid, ticket.source_epoch, ticket.token,
	    intent, previous);
	if (gate_present != 1 ||
	    intent.source_session != ticket.source_session) {
		if (gate_present == 0)
			errno = EBUSY;
		else if (gate_present == 1)
			errno = EPROTO;
		return (-1);
	}
	int gatefd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (gatefd < 0)
		return (-1);
	hypertrace_epoch_gate gate{};
	int error = source_gate_query_fd(gatefd,
	    ticket.source_vmid, ticket.source_epoch, gate) != 0 ? errno : 0;
	if (error == 0 && (gate.suspended != 1 ||
	    memcmp(gate.token, ticket.token.data(), 16) != 0))
		error = ESTALE;
	if (close(gatefd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	std::vector<uint8_t> manifest, bundle;
	std::vector<std::vector<uint8_t>> frames;
	int present = this->state->inbounddir->
	    host_ingress_transfer_bundle_locked(ticket, *this,
	    manifest, frames, true);
	if (present != 1) {
		if (present == 0)
			errno = ESTALE;
		return (-1);
	}
	if (!dtraced_transfer_wire_build(ticket.token.data(),
	    manifest, frames, bundle))
		return (-1);
	if (memcmp(ticket.transfer_digest.data(),
	    bundle.data() + bundle.size() - SHA256_DIGEST_LENGTH,
	    SHA256_DIGEST_LENGTH) != 0) {
		errno = ESTALE;
		return (-1);
	}
	std::vector<host_ingress_program_evidence> recipients;
	if (!validate_host_ingress_program_manifest(ticket,
	    manifest, nullptr, &recipients))
		return (-1);
	bool matched = false;
	for (const auto &member : recipients) {
		if (consumer_receipt_bytes(member.recipient) ==
	    consumer_receipt_bytes(proof.recipient) &&
	    member.owner_wire == proof.owner_wire &&
	    member.program_digest == proof.program_digest) {
			matched = true;
			break;
		}
	}
	if (!matched) {
		errno = ESTALE;
		return (-1);
	}
	char name[105];
	source_drain_name(ticket, proof.recipient, name);
	const auto wire = source_drain_bytes(ticket, proof);
	int recorded = source_drain_read_at(this->dirfd, name, wire);
	if (recorded != 0 || !publish)
		return (recorded);
	if (!handoff_publish_at(this->dirfd, name,
	    wire.data(), wire.size()))
		return (-1);
	return (1);
}

int
dir::drain_source_consumer_step(const durable_handoff &ticket)
{
	if (!handoff_valid(ticket, handoff_phase::prepared) ||
	    ticket.transfer_digest == std::array<uint8_t, 32>{} ||
	    this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->outbounddir != this ||
	    this->state->inbounddir == nullptr) {
		errno = EINVAL;
		return (-1);
	}
	std::vector<uint8_t> manifest, bundle;
	std::vector<std::vector<uint8_t>> frames;
	int present = this->state->inbounddir->
	    host_ingress_transfer_bundle_export(ticket,
	    manifest, frames, true);
	if (present < 0 ||
	    !dtraced_transfer_wire_build(ticket.token.data(),
	    manifest, frames, bundle))
		return (-1);
	if (memcmp(ticket.transfer_digest.data(),
	    bundle.data() + bundle.size() - SHA256_DIGEST_LENGTH,
	    SHA256_DIGEST_LENGTH) != 0) {
		errno = ESTALE;
		return (-1);
	}
	if (present == 0)
		return (0);
	std::vector<host_ingress_program_evidence> recipients;
	if (!validate_host_ingress_program_manifest(ticket,
	    manifest, nullptr, &recipients))
		return (-1);
	for (const auto &proof : recipients) {
		char name[105];
		source_drain_name(ticket, proof.recipient, name);
		const auto wire = source_drain_bytes(ticket, proof);
		int recorded = source_drain_read_at(this->dirfd,
		    name, wire);
		if (recorded < 0)
			return (-1);
		if (recorded == 1)
			continue;
		client_fd *consumer = nullptr;
		{
			std::lock_guard clients(this->state->sockfdsmtx);
			for (client_fd *candidate : this->state->sockfds) {
				if (candidate->retired.load() ||
				    candidate->kind != DTRACED_KIND_CONSUMER ||
				    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
				    candidate->consumer_replay_pending ||
				    !candidate->consumer_birth_valid ||
				    !candidate->consumer_program_valid ||
				    candidate->session_id !=
				    proof.recipient.consumer_session ||
				    candidate->peer_uid !=
				    proof.recipient.consumer_uid ||
				    candidate->peer_pid !=
				    (pid_t)proof.recipient.consumer_pid ||
				    memcmp(candidate->consumer_birth.data(),
				    proof.owner_wire.data() + 28, 16) != 0 ||
				    candidate->consumer_program_digest !=
				    proof.program_digest)
					continue;
				candidate->acquire();
				consumer = candidate;
				break;
			}
		}
		if (consumer == nullptr) {
			errno = EAGAIN;
			return (-1);
		}
		dtraced_consumer_drain_t challenge{};
		memcpy(challenge.token, ticket.token.data(), 16);
		memcpy(challenge.source_session,
		    ticket.source_session.data(), 16);
		memcpy(challenge.consumer_session,
		    proof.recipient.consumer_session.data(), 16);
		memcpy(challenge.program_digest,
		    proof.program_digest.data(), 32);
		challenge.vmid = ticket.source_vmid;
		challenge.epoch = ticket.source_epoch;
		bool drained = consumer->request_consumer_drain(challenge);
		int drain_error = drained ? 0 : errno;
		consumer->release();
		if (!drained) {
			errno = drain_error;
			return (-1);
		}
		if (source_consumer_drain_receipt(ticket, proof, true) != 1)
			return (-1);
		return (1);
	}
	/* The last ACK may have been published before a concurrent source
	 * mutation. Revalidate the exact cut and gate before saying complete. */
	return (source_consumer_drain_receipt(ticket,
	    recipients.back(), false) == 1 ? 0 : -1);
}
/* HT-C END */

/* -1 malformed/error, 0 absent, 1 exact. Caller serializes with the inbound
 * journal's process lock. A mismatched incarnation never repairs in place. */
static int
consumer_owner_status_at(int directory, const client_fd &consumer)
{
	char name[49];
	consumer_owner_name(consumer.session_id,
	    (uint32_t)consumer.peer_pid, name);
	std::array<uint8_t, 76> wire{};
	int status = consumer_owner_read_at(directory, name, wire);
	if (status == 1 && wire != consumer_owner_bytes(consumer)) {
		errno = EPROTO;
		return (-1);
	}
	return (status);
}

/* Prefer immutable per-receipt identity to the rotatable HCO1 owner. An
 * unfrozen pending receipt may use its exact existing HCO1, but absence of
 * both records never identifies a replacement as the original process. */
static int
consumer_replay_same_owner_at(int directory,
    const durable_consumer_receipt &record, const client_fd &consumer)
{
	if (record.consumer_pid != (uint32_t)consumer.peer_pid)
		return (0);
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	int present = consumer_program_read_at(directory, record, owner, program);
	if (present < 0)
		return (-1);
	if (present == 0) {
		char name[49];
		consumer_owner_name(record.consumer_session, record.consumer_pid, name);
		present = consumer_owner_read_at(directory, name, owner);
		if (present < 0)
			return (-1);
	}
	return (present == 1 && owner == consumer_owner_bytes(consumer) ? 1 : 0);
}

/* Caller holds the inbound process lock. Recheck every cohort member's
 * immutable retirement dependencies, including members added after a receipt
 * snapshot. Never use the current occupant of an old numeric PID as evidence. */
static int
consumer_retired_at(int directory, const durable_consumer_receipt &record)
{
	std::array<uint8_t, 76> owner{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> lifetime{};
	int proven = consumer_program_read_at(directory, record, owner, program);
	if (proven != 1)
		return (proven);
	proven = consumer_handle_at(directory, record, owner, program, lifetime, false);
	if (proven != 1 || lifetime == std::array<uint8_t, 24>{})
		return (proven < 0 ? -1 : 0);
	/* An earlier kernel boot retired the collector, its descendants and its
	 * handle together; same-boot members still need all three facts. */
	proven = consumer_prior_boot_at(directory, record, owner, program, lifetime);
	if (proven != 0)
		return (proven);
	proven = consumer_process_binding_at(directory, record, owner, program,
	    lifetime, false);
	if (proven != 1)
		return (proven);
	proven = consumer_shared_exit_at(directory, owner, program, lifetime, false);
	if (proven != 1)
		return (proven);
	proven = consumer_reaper_empty_at(directory, owner, program, lifetime, false);
	if (proven != 1)
		return (proven);
	return (collector_handle_retired(lifetime));
}

/* Called with the inbound process lock. HCB1 is authoritative even when a
 * crash left one of its HCR1 members unwritten: never rotate an owner past
 * such a member or past a parsed-only outcome. */
static bool
consumer_owner_cohorts_settled_at(int directory,
    const client_fd &consumer)
{
	std::vector<durable_delivery_state> ingresses;
	if (!list_deliveries_at(directory, ingresses))
		return (false);
	for (const auto &entry : ingresses) {
		if (entry.record.scope != 3 ||
		    entry.phase != delivery_phase::accepted)
			continue;
		std::vector<durable_consumer_receipt> members;
		int present = consumer_cohort_read_at(directory,
		    entry.record, members);
		if (present < 0)
			return (false);
		for (const auto &member : members) {
			if (member.consumer_session != consumer.session_id)
				continue;
			if (member.consumer_uid != (uint32_t)consumer.peer_uid) {
				errno = EPERM;
				return (false);
			}
			int phase = consumer_receipt_status_at(directory, member);
			if (phase < 0)
				return (false);
			if (phase != (int)consumer_receipt_phase::executed_no_derived &&
			    phase != (int)consumer_receipt_phase::executed_derived) {
				errno = EBUSY;
				return (false);
			}
			int same = consumer_replay_same_owner_at(directory, member, consumer);
			if (same < 0)
				return (false);
			if (same == 0) {
				int retired = consumer_retired_at(directory, member);
				if (retired != 1) {
					if (retired == 0)
						errno = EBUSY;
					return (false);
				}
			}
		}
	}
	return (true);
}

static bool
consumer_owner_publish_at(int directory, const client_fd &consumer,
    const std::array<uint8_t, 76> *prior)
{
	char name[49], temporary[44];
	consumer_owner_name(consumer.session_id,
	    (uint32_t)consumer.peer_pid, name);
	if (prior == nullptr) {
		int status = consumer_owner_status_at(directory, consumer);
		if (status != 0)
			return (status == 1 && fsync(directory) == 0);
	} else {
		std::array<uint8_t, 76> current{};
		int status = consumer_owner_read_at(directory, name, current);
		if (status != 1) {
			if (status == 0)
				errno = EBUSY;
			return (false);
		}
		if (current != *prior) {
			errno = EBUSY;
			return (false);
		}
	}
	uint8_t nonce[16];
	arc4random_buf(nonce, sizeof(nonce));
	static const char hex[] = "0123456789abcdef";
	memcpy(temporary, ".owner.tmp.", 11);
	for (size_t i = 0; i < sizeof(nonce); i++) {
		temporary[11 + i * 2] = hex[nonce[i] >> 4];
		temporary[12 + i * 2] = hex[nonce[i] & 15];
	}
	temporary[43] = '\0';
	int fd = openat(directory, temporary,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (false);
	const auto wire = consumer_owner_bytes(consumer);
	size_t offset = 0;
	int error = 0;
	while (offset < wire.size()) {
		ssize_t n = write(fd, wire.data() + offset, wire.size() - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n < 0 ? errno : EIO;
			break;
		}
		offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0) {
		if (prior != nullptr) {
			if (renameat(directory, temporary, directory, name) != 0)
				error = errno;
		} else if (linkat(directory, temporary, directory, name, 0) != 0)
			error = errno;
	}
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (unlink_published_temporary_at(directory, temporary) != 0 &&
	    error == 0)
		error = errno;
	if (error == 0 && fsync(directory) != 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (false);
	}
	return (true);
}

static bool
consumer_owner_bind_at(int directory, const client_fd &consumer)
{
	return (consumer_owner_publish_at(directory, consumer, nullptr));
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* HTL1 reserves the exact destination consumer owners that could receive a
 * staged transfer. It is deliberately inert: HCR1/HCB1 still describe HTD4,
 * so neither this record nor HCO1 may promote an imported HTD5. Holding the
 * outbound ticket lock, then sockfdsmtx, then inbound journal locks matches
 * the identified watcher and prevents a consumer from retiring mid-cut. */
bool
dir::reserve_host_ingress_consumer_owners(
    const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    this->state->outbounddir == this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (false);
	}
	dir &outbound = *this->state->outbounddir;
	handoff_process_lock destination_lock(outbound.dirfd);
	if (!destination_lock.held())
		return (false);
	durable_handoff current{};
	int phase = handoff_state_at(outbound.dirfd, reserved.token, current);
	if (phase < 0)
		return (false);
	if ((phase != (int)handoff_phase::reserved &&
	    phase != (int)handoff_phase::mutating) ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	char stage_name[39];
	if (!host_transfer_stage_name(reserved.token, stage_name))
		return (false);
	std::lock_guard clients(this->state->sockfdsmtx);
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock inbound_lock(this->dirfd);
	if (!inbound_lock.held())
		return (false);
	std::vector<uint8_t> stage;
	int present = host_transfer_stage_read_at(this->dirfd, stage_name,
	    stage);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	host_ingress_destination_plan plan;
	if (!host_transfer_stage_decode(reserved, destination_session,
	    destination_uid, destination_pid, destination_name, stage, plan))
		return (false);
	std::map<std::array<uint8_t, 16>, uint32_t> required;
	std::map<std::array<uint8_t, 16>, std::array<uint8_t, 32>>
	    required_programs;
	try {
		for (size_t i = 0; i < plan.deliveries.size(); i++) {
			int status = delivery_record_status_at(this->dirfd,
			    plan.deliveries[i]);
			if (status < 0)
				return (false);
			if (status != (int)delivery_phase::pending) {
				errno = EBUSY;
				return (false);
			}
			for (const auto &recipient :
			    plan.source_entries[i].recipients) {
				const auto &owner = recipient.record;
				auto inserted = required.emplace(
				    owner.consumer_session, owner.consumer_uid);
				if (!inserted.second &&
				    inserted.first->second != owner.consumer_uid) {
					errno = EPROTO;
					return (false);
				}
			}
		}
		if (required.empty() || required.size() > consumer_receipt_limit) {
			errno = EPROTO;
			return (false);
		}
		for (const auto &proof : plan.source_programs) {
			auto owner = required.find(proof.recipient.consumer_session);
			if (owner == required.end() ||
			    owner->second != proof.recipient.consumer_uid) {
				errno = EPROTO;
				return (false);
			}
			auto added = required_programs.emplace(
			    proof.recipient.consumer_session,
			    proof.program_digest);
			if (!added.second &&
			    added.first->second != proof.program_digest) {
				errno = EPROTO;
				return (false);
			}
		}
		if (!required_programs.empty() &&
		    required_programs.size() != required.size()) {
			errno = EPROTO;
			return (false);
		}
		std::vector<uint8_t> wire(96 + required.size() * 76 + 32, 0);
		memcpy(wire.data(), "HTL1", 4);
		memcpy(wire.data() + 4, reserved.token.data(), 16);
		memcpy(wire.data() + 20, stage.data() + stage.size() - 32, 32);
		dtraced_wire_put_u16(wire.data() + 52,
		    reserved.destination_vmid);
		dtraced_wire_put_u64(wire.data() + 54,
		    reserved.destination_epoch);
		dtraced_wire_put_u32(wire.data() + 62,
		    (uint32_t)required.size());
		size_t offset = 96;
		std::vector<std::array<uint8_t, 76>> selected_owners;
		selected_owners.reserve(required.size());
		for (const auto &[session, uid] : required) {
			client_fd *matched = nullptr;
			for (client_fd *candidate : this->state->sockfds) {
				if (!candidate->retired.load() &&
				    candidate->kind == DTRACED_KIND_CONSUMER &&
				    candidate->is_subscribed(DTD_SUB_ELFWRITE) &&
				    candidate->session_id == session &&
				    candidate->peer_uid != (uid_t)uid) {
					errno = EPERM;
					return (false);
				}
				if (!candidate->retired.load() &&
				    candidate->kind == DTRACED_KIND_CONSUMER &&
				    candidate->is_subscribed(DTD_SUB_ELFWRITE) &&
				    candidate->session_id == session &&
				    candidate->consumer_replay_pending) {
					errno = EBUSY;
					return (false);
				}
				if (candidate->retired.load() ||
				    candidate->consumer_replay_pending ||
				    candidate->kind != DTRACED_KIND_CONSUMER ||
				    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
				    !candidate->consumer_birth_valid ||
				    !candidate->consumer_program_valid ||
				    candidate->session_id != session ||
				    candidate->peer_uid != (uid_t)uid)
					continue;
				if (matched != nullptr) {
					errno = EPROTO;
					return (false);
				}
				matched = candidate;
			}
			if (matched == nullptr) {
				errno = EBUSY;
				return (false);
			}
			auto program = required_programs.find(session);
			if (!required_programs.empty() &&
			    (program == required_programs.end() ||
			    matched->consumer_program_digest != program->second)) {
				errno = EPROTO;
				return (false);
			}
			char owner_name[49];
			consumer_owner_name(session,
			    (uint32_t)matched->peer_pid, owner_name);
			std::array<uint8_t, 76> durable_owner{};
			int owner_present = consumer_owner_read_at(this->dirfd,
			    owner_name, durable_owner);
			if (owner_present != 1) {
				if (owner_present == 0)
					errno = EBUSY;
				return (false);
			}
			if (durable_owner != consumer_owner_bytes(*matched)) {
				errno = EPROTO;
				return (false);
			}
			memcpy(wire.data() + offset, durable_owner.data(),
			    durable_owner.size());
			offset += durable_owner.size();
			selected_owners.push_back(durable_owner);
		}
		std::vector<std::vector<uint8_t>> planned;
		if (!plan.source_programs.empty() &&
		    !plan_import_consumer_cohorts(plan,
		    selected_owners, planned))
			return (false);
		if (SHA256(wire.data(), wire.size() - 32,
		    wire.data() + wire.size() - 32) == nullptr)
			return (false);
		std::vector<uint8_t> cohort_wire;
		if (!planned.empty() && !host_transfer_cohort_wire(
		    reserved.token, stage.data() + stage.size() - 32,
		    wire.data() + wire.size() - 32, planned, cohort_wire))
			return (false);
		std::vector<uint8_t> result_wire;
		if (!cohort_wire.empty() && !host_transfer_result_wire(
		    reserved.token, cohort_wire.data() + cohort_wire.size() - 32,
		    plan, planned, result_wire))
			return (false);
		std::vector<uint8_t> promotion_wire;
		if (!result_wire.empty() && !host_transfer_promotion_wire(
		    reserved.token, result_wire.data() + result_wire.size() - 32,
		    plan, promotion_wire))
			return (false);
		char name[39];
		if (!host_transfer_owner_name(reserved.token, name))
			return (false);
		std::vector<uint8_t> existing;
		present = host_transfer_stage_read_at(this->dirfd, name,
		    existing);
		if (present < 0)
			return (false);
		if (present == 1) {
			if (existing != wire) {
				errno = EEXIST;
				return (false);
			}
			if (fsync(this->dirfd) != 0)
				return (false);
		} else if (!handoff_publish_at(this->dirfd, name,
		    wire.data(), wire.size())) {
			return (false);
		}
		if (cohort_wire.empty())
			return (true);
		char cohort_name[39];
		if (!host_transfer_cohort_name(reserved.token, cohort_name))
			return (false);
		existing.clear();
		present = host_transfer_stage_read_at(this->dirfd,
		    cohort_name, existing);
		if (present < 0)
			return (false);
		if (present == 1) {
			if (existing != cohort_wire) {
				errno = EEXIST;
				return (false);
			}
			if (fsync(this->dirfd) != 0)
				return (false);
		} else if (!handoff_publish_at(this->dirfd, cohort_name,
		    cohort_wire.data(), cohort_wire.size())) {
			return (false);
		}
		char result_name[39];
		if (!host_transfer_result_name(reserved.token, result_name))
			return (false);
		existing.clear();
		present = host_transfer_stage_read_at(this->dirfd,
		    result_name, existing);
		if (present < 0)
			return (false);
		if (present == 1) {
			if (existing != result_wire) {
				errno = EEXIST;
				return (false);
			}
			if (fsync(this->dirfd) != 0)
				return (false);
		} else if (!handoff_publish_at(this->dirfd, result_name,
		    result_wire.data(), result_wire.size())) {
			return (false);
		}
		char promotion_name[39];
		if (!host_transfer_promotion_name(reserved.token,
		    promotion_name))
			return (false);
		existing.clear();
		present = host_transfer_stage_read_at(this->dirfd,
		    promotion_name, existing);
		if (present < 0)
			return (false);
		if (present == 1) {
			if (existing != promotion_wire) {
				errno = EEXIST;
				return (false);
			}
			return (fsync(this->dirfd) == 0);
		}
		return (handoff_publish_at(this->dirfd, promotion_name,
		    promotion_wire.data(), promotion_wire.size()));
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

/* Recover HTL1 only against the exact staged transfer and current durable
 * HCO1 owners. The caller still needs live consumer and program-image proof
 * before it can ever promote HTD5 or publish a job. */
int
dir::load_host_ingress_consumer_owners(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<std::array<uint8_t, 76>> &owners)
{
	owners.clear();
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    this->state->outbounddir == this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (-1);
	}
	dir &outbound = *this->state->outbounddir;
	handoff_process_lock destination_lock(outbound.dirfd);
	if (!destination_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(outbound.dirfd, reserved.token, current);
	if (phase < 0)
		return (-1);
	if ((phase != (int)handoff_phase::reserved &&
	    phase != (int)handoff_phase::mutating &&
	    phase != (int)handoff_phase::claimed) ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	char stage_name[39], owner_name[39];
	if (!host_transfer_stage_name(reserved.token, stage_name) ||
	    !host_transfer_owner_name(reserved.token, owner_name))
		return (-1);
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock inbound_lock(this->dirfd);
	if (!inbound_lock.held())
		return (-1);
	std::vector<uint8_t> stage, wire;
	int present = host_transfer_stage_read_at(this->dirfd,
	    stage_name, stage);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (-1);
	}
	host_ingress_destination_plan plan;
	if (!host_transfer_stage_decode(reserved, destination_session,
	    destination_uid, destination_pid, destination_name, stage, plan))
		return (-1);
	std::vector<durable_delivery_state> existing;
	if (!list_deliveries_at(this->dirfd, existing))
		return (-1);
	for (const auto &entry : existing) {
		if (entry.record.handoff_token != reserved.token)
			continue;
		bool exact = false;
		for (const auto &delivery : plan.deliveries)
			if (delivery_record_bytes(entry.record) ==
			    delivery_record_bytes(delivery)) {
				exact = true;
				break;
			}
		if (!exact) {
			errno = EPROTO;
			return (-1);
		}
	}
	for (const auto &delivery : plan.deliveries) {
		int status = delivery_record_status_at(this->dirfd, delivery);
		if (status < 0)
			return (-1);
		if (status != (int)delivery_phase::pending) {
			errno = EBUSY;
			return (-1);
		}
	}
	present = host_transfer_stage_read_at(this->dirfd, owner_name, wire);
	if (present != 1)
		return (present);
	uint32_t count = wire.size() >= 66 ?
	    dtraced_wire_get_u32(wire.data() + 62) : 0;
	uint8_t digest[32];
	if (count == 0 || count > consumer_receipt_limit ||
	    wire.size() != 96 + (size_t)count * 76 + 32 ||
	    memcmp(wire.data(), "HTL1", 4) != 0 ||
	    memcmp(wire.data() + 4, reserved.token.data(), 16) != 0 ||
	    memcmp(wire.data() + 20, stage.data() + stage.size() - 32, 32) != 0 ||
	    dtraced_wire_get_u16(wire.data() + 52) !=
	    reserved.destination_vmid ||
	    dtraced_wire_get_u64(wire.data() + 54) !=
	    reserved.destination_epoch ||
	    std::any_of(wire.begin() + 66, wire.begin() + 96,
	    [](uint8_t value) { return (value != 0); }) ||
	    SHA256(wire.data(), wire.size() - 32, digest) == nullptr ||
	    memcmp(digest, wire.data() + wire.size() - 32, 32) != 0) {
		errno = EPROTO;
		return (-1);
	}
	try {
		std::map<std::array<uint8_t, 16>, uint32_t> required;
		for (const auto &entry : plan.source_entries)
			for (const auto &recipient : entry.recipients) {
				const auto &record = recipient.record;
				auto inserted = required.emplace(
				    record.consumer_session, record.consumer_uid);
				if (!inserted.second &&
				    inserted.first->second != record.consumer_uid) {
					errno = EPROTO;
					return (-1);
				}
			}
		if (required.size() != count) {
			errno = EPROTO;
			return (-1);
		}
		std::vector<std::array<uint8_t, 76>> decoded;
		decoded.reserve(count);
		size_t offset = 96;
		for (const auto &[session, uid] : required) {
			std::array<uint8_t, 76> owner{};
			memcpy(owner.data(), wire.data() + offset, owner.size());
			if (memcmp(owner.data() + 4, session.data(), 16) != 0 ||
			    dtraced_wire_get_u32(owner.data() + 20) != uid) {
				errno = EPROTO;
				return (-1);
			}
			char name[49];
			consumer_owner_name(session,
			    dtraced_wire_get_u32(owner.data() + 24), name);
			std::array<uint8_t, 76> current_owner{};
			int status = consumer_owner_read_at(this->dirfd,
			    name, current_owner);
			if (status != 1) {
				if (status == 0)
					errno = EBUSY;
				return (-1);
			}
			if (current_owner != owner) {
				errno = EPROTO;
				return (-1);
			}
			decoded.push_back(owner);
			offset += owner.size();
		}
		owners.swap(decoded);
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

int
dir::load_import_consumer_cohorts(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<std::vector<uint8_t>> &cohorts)
{
	cohorts.clear();
	std::vector<std::array<uint8_t, 76>> owners;
	int present = load_host_ingress_consumer_owners(reserved,
	    destination_session, destination_uid, destination_pid,
	    destination_name, owners);
	if (present <= 0)
		return (present);
	host_ingress_destination_plan plan;
	present = load_host_ingress_destination_stage(reserved,
	    destination_session, destination_uid, destination_pid,
	    destination_name, plan);
	if (present != 1) {
		if (present == 0)
			errno = EPROTO;
		return (-1);
	}
	std::vector<std::vector<uint8_t>> planned;
	if (!plan_import_consumer_cohorts(plan, owners, planned))
		return (-1);
	char stage_name[39], owner_name[39], cohort_name[39];
	if (!host_transfer_stage_name(reserved.token, stage_name) ||
	    !host_transfer_owner_name(reserved.token, owner_name) ||
	    !host_transfer_cohort_name(reserved.token, cohort_name))
		return (-1);
	std::vector<uint8_t> stage, owner_wire, cohort_wire;
	if (host_transfer_stage_read_at(this->dirfd, stage_name,
	    stage) != 1 ||
	    host_transfer_stage_read_at(this->dirfd, owner_name,
	    owner_wire) != 1) {
		errno = EPROTO;
		return (-1);
	}
	std::vector<uint8_t> expected;
	if (!host_transfer_cohort_wire(reserved.token,
	    stage.data() + stage.size() - 32,
	    owner_wire.data() + owner_wire.size() - 32,
	    planned, expected))
		return (-1);
	present = host_transfer_stage_read_at(this->dirfd,
	    cohort_name, cohort_wire);
	if (present <= 0)
		return (present);
	if (cohort_wire != expected) {
		errno = EPROTO;
		return (-1);
	}
	cohorts.swap(planned);
	return (1);
}

int
dir::load_import_pending_results(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<std::array<uint8_t, 32>> &slot_ids)
{
	slot_ids.clear();
	std::vector<std::vector<uint8_t>> cohorts;
	int present = load_import_consumer_cohorts(reserved,
	    destination_session, destination_uid, destination_pid,
	    destination_name, cohorts);
	if (present <= 0)
		return (present);
	host_ingress_destination_plan plan;
	present = load_host_ingress_destination_stage(reserved,
	    destination_session, destination_uid, destination_pid,
	    destination_name, plan);
	if (present != 1) {
		if (present == 0)
			errno = EPROTO;
		return (-1);
	}
	char cohort_name[39], result_name[39];
	if (!host_transfer_cohort_name(reserved.token, cohort_name) ||
	    !host_transfer_result_name(reserved.token, result_name))
		return (-1);
	std::vector<uint8_t> cohort_wire, result_wire;
	if (host_transfer_stage_read_at(this->dirfd,
	    cohort_name, cohort_wire) != 1) {
		errno = EPROTO;
		return (-1);
	}
	std::vector<uint8_t> expected;
	if (!host_transfer_result_wire(reserved.token,
	    cohort_wire.data() + cohort_wire.size() - 32,
	    plan, cohorts, expected))
		return (-1);
	present = host_transfer_stage_read_at(this->dirfd,
	    result_name, result_wire);
	if (present <= 0)
		return (present);
	if (result_wire != expected) {
		errno = EPROTO;
		return (-1);
	}
	try {
		std::vector<std::array<uint8_t, 32>> parsed;
		uint32_t count = dtraced_wire_get_u32(expected.data() + 52);
		parsed.reserve(count);
		size_t offset = 64;
		for (uint32_t i = 0; i < count; i++) {
			std::array<uint8_t, 32> id{};
			memcpy(id.data(), expected.data() + offset, id.size());
			offset += 33;
			parsed.push_back(id);
		}
		slot_ids.swap(parsed);
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

int
dir::import_promotion_transaction(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<std::array<uint8_t, 32>> &delivery_ids,
    bool allow_accepted, bool promote, bool require_commit,
    std::vector<durable_committed_import_entry> *committed_entries,
    const durable_import_consumer_result *publish_result,
    consumer_receipt_phase *published_phase,
    const std::array<uint8_t, 32> *query_receipt_digest,
    durable_import_consumer_result *query_result,
    std::vector<durable_committed_import_result_state> *all_results,
    bool activate, bool read_activation, bool require_activation_result)
{
	delivery_ids.clear();
	if (committed_entries != nullptr)
		committed_entries->clear();
	if (all_results != nullptr)
		all_results->clear();
	if (published_phase != nullptr)
		*published_phase = consumer_receipt_phase::pending;
	if (query_result != nullptr)
		*query_result = {};
	if ((committed_entries != nullptr && !require_commit) ||
	    (require_activation_result &&
	    (!require_commit || publish_result == nullptr || promote ||
	    activate || read_activation || all_results != nullptr ||
	    query_receipt_digest != nullptr)) ||
	    ((activate || read_activation) &&
	    (!require_commit || promote || publish_result != nullptr ||
	    query_receipt_digest != nullptr || all_results == nullptr)) ||
	    (activate && read_activation) ||
	    (all_results != nullptr && (!require_commit || promote ||
	    publish_result != nullptr || query_receipt_digest != nullptr)) ||
	    (publish_result != nullptr &&
	    (!require_commit || promote || published_phase == nullptr)) ||
	    (query_receipt_digest != nullptr &&
	    (!require_commit || promote || published_phase == nullptr ||
	    query_result == nullptr || publish_result != nullptr)) ||
	    (query_receipt_digest == nullptr && query_result != nullptr) ||
	    (publish_result == nullptr && query_receipt_digest == nullptr &&
	    published_phase != nullptr)) {
		errno = EINVAL;
		return (-1);
	}
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr ||
	    this->state->outbounddir == this ||
	    !handoff_valid(reserved, handoff_phase::reserved)) {
		errno = EINVAL;
		return (-1);
	}
	dir &outbound = *this->state->outbounddir;
	handoff_process_lock destination_lock(outbound.dirfd);
	if (!destination_lock.held())
		return (-1);
	durable_handoff current{};
	int phase = handoff_state_at(outbound.dirfd, reserved.token, current);
	if (phase < 0)
		return (-1);
	if ((phase != (int)handoff_phase::reserved &&
	    phase != (int)handoff_phase::mutating &&
	    phase != (int)handoff_phase::claimed) ||
	    ((promote || require_commit) &&
	    phase != (int)handoff_phase::claimed) ||
	    !handoff_same_destination(current, reserved)) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (-1);
	}
	char stage_name[39], owner_name[39], cohort_name[39];
	char result_name[39], promotion_name[39], commit_name[39];
	char activation_name[39];
	if (!host_transfer_stage_name(reserved.token, stage_name) ||
	    !host_transfer_owner_name(reserved.token, owner_name) ||
	    !host_transfer_cohort_name(reserved.token, cohort_name) ||
	    !host_transfer_result_name(reserved.token, result_name) ||
	    !host_transfer_promotion_name(reserved.token, promotion_name) ||
	    ((promote || require_commit) && !host_transfer_commit_name(reserved.token,
	    commit_name)) ||
	    ((activate || read_activation || require_activation_result) &&
	    !host_transfer_activation_name(
	    reserved.token, activation_name)))
		return (-1);
	std::unique_lock clients(this->state->sockfdsmtx, std::defer_lock);
	if (promote)
		clients.lock();
	std::lock_guard journal(this->publishmtx);
	handoff_process_lock inbound_lock(this->dirfd);
	if (!inbound_lock.held())
		return (-1);
	std::vector<uint8_t> promotion_wire;
	int present = host_transfer_stage_read_at(this->dirfd,
	    promotion_name, promotion_wire);
	if (present == 0 && require_commit) {
		if (activate || read_activation || require_activation_result) {
			std::vector<uint8_t> stray_activation;
			int activated = host_transfer_stage_read_at(this->dirfd,
			    activation_name, stray_activation);
			if (activated < 0)
				return (-1);
			if (activated != 0) {
				errno = EPROTO;
				return (-1);
			}
		}
		std::vector<uint8_t> stray_commit;
		int committed = host_transfer_stage_read_at(this->dirfd,
		    commit_name, stray_commit);
		if (committed < 0)
			return (-1);
		if (committed != 0) {
			errno = EPROTO;
			return (-1);
		}
		if (all_results != nullptr &&
		    !host_transfer_outcome_audit_at(this->dirfd,
		    reserved.token, {}))
			return (-1);
	}
	if (present <= 0)
		return (present);
	std::vector<uint8_t> stage, owner_wire, cohort_wire, result_wire;
	if (host_transfer_stage_read_at(this->dirfd, stage_name, stage) != 1 ||
	    host_transfer_stage_read_at(this->dirfd, owner_name,
	    owner_wire) != 1 ||
	    host_transfer_stage_read_at(this->dirfd, cohort_name,
	    cohort_wire) != 1 ||
	    host_transfer_stage_read_at(this->dirfd, result_name,
	    result_wire) != 1) {
		errno = EPROTO;
		return (-1);
	}
	host_ingress_destination_plan plan;
	if (!host_transfer_stage_decode(reserved, destination_session,
	    destination_uid, destination_pid, destination_name, stage, plan))
		return (-1);
	std::vector<durable_delivery_state> existing;
	if (!list_deliveries_at(this->dirfd, existing))
		return (-1);
	for (const auto &entry : existing) {
		if (entry.record.handoff_token != reserved.token)
			continue;
		bool exact = false;
		for (const auto &delivery : plan.deliveries)
			if (delivery_record_bytes(entry.record) ==
			    delivery_record_bytes(delivery)) {
				exact = true;
				break;
			}
		if (!exact) {
			errno = EPROTO;
			return (-1);
		}
	}
	bool all_accepted = true;
	for (const auto &delivery : plan.deliveries) {
		int status = delivery_record_status_at(this->dirfd, delivery);
		if (status < 0)
			return (-1);
		if (status != (int)delivery_phase::accepted)
			all_accepted = false;
		if (status != (int)delivery_phase::pending &&
		    !(allow_accepted && status == (int)delivery_phase::accepted)) {
			errno = EBUSY;
			return (-1);
		}
	}
	if (require_commit && !all_accepted) {
		errno = EBUSY;
		return (-1);
	}
	uint32_t count = owner_wire.size() >= 66 ?
	    dtraced_wire_get_u32(owner_wire.data() + 62) : 0;
	uint8_t digest[32];
	if (count == 0 || count > consumer_receipt_limit ||
	    owner_wire.size() != 96 + (size_t)count * 76 + 32 ||
	    memcmp(owner_wire.data(), "HTL1", 4) != 0 ||
	    memcmp(owner_wire.data() + 4, reserved.token.data(), 16) != 0 ||
	    memcmp(owner_wire.data() + 20,
	    stage.data() + stage.size() - 32, 32) != 0 ||
	    dtraced_wire_get_u16(owner_wire.data() + 52) !=
	    reserved.destination_vmid ||
	    dtraced_wire_get_u64(owner_wire.data() + 54) !=
	    reserved.destination_epoch ||
	    std::any_of(owner_wire.begin() + 66, owner_wire.begin() + 96,
	    [](uint8_t value) { return (value != 0); }) ||
	    SHA256(owner_wire.data(), owner_wire.size() - 32, digest) == nullptr ||
	    memcmp(digest, owner_wire.data() + owner_wire.size() - 32, 32) != 0) {
		errno = EPROTO;
		return (-1);
	}
	try {
		std::map<std::array<uint8_t, 16>, uint32_t> required;
		for (const auto &entry : plan.source_entries)
			for (const auto &recipient : entry.recipients) {
				const auto &record = recipient.record;
				auto inserted = required.emplace(
				    record.consumer_session, record.consumer_uid);
				if (!inserted.second &&
				    inserted.first->second != record.consumer_uid) {
					errno = EPROTO;
					return (-1);
				}
			}
		if (required.size() != count) {
			errno = EPROTO;
			return (-1);
		}
		std::vector<std::array<uint8_t, 76>> owners;
		owners.reserve(count);
		size_t offset = 96;
		for (const auto &[session, uid] : required) {
			std::array<uint8_t, 76> owner{};
			memcpy(owner.data(), owner_wire.data() + offset,
			    owner.size());
			if (memcmp(owner.data() + 4, session.data(), 16) != 0 ||
			    dtraced_wire_get_u32(owner.data() + 20) != uid) {
				errno = EPROTO;
				return (-1);
			}
			char name[49];
			consumer_owner_name(session,
			    dtraced_wire_get_u32(owner.data() + 24), name);
			std::array<uint8_t, 76> current_owner{};
			int owner_status = consumer_owner_read_at(this->dirfd,
			    name, current_owner);
			if (owner_status != 1 || current_owner != owner) {
				if (owner_status == 0)
					errno = EBUSY;
				else if (owner_status == 1)
					errno = EPROTO;
				return (-1);
			}
			owners.push_back(owner);
			offset += owner.size();
		}
		std::vector<std::vector<uint8_t>> cohorts;
		if (!plan_import_consumer_cohorts(plan, owners, cohorts))
			return (-1);
		std::vector<uint8_t> expected;
		if (!host_transfer_cohort_wire(reserved.token,
		    stage.data() + stage.size() - 32,
		    owner_wire.data() + owner_wire.size() - 32,
		    cohorts, expected))
			return (-1);
		if (cohort_wire != expected) {
			errno = EPROTO;
			return (-1);
		}
		if (!host_transfer_result_wire(reserved.token,
		    cohort_wire.data() + cohort_wire.size() - 32,
		    plan, cohorts, expected))
			return (-1);
		if (result_wire != expected) {
			errno = EPROTO;
			return (-1);
		}
		if (!host_transfer_promotion_wire(reserved.token,
		    result_wire.data() + result_wire.size() - 32,
		    plan, expected))
			return (-1);
		if (promotion_wire != expected) {
			errno = EPROTO;
			return (-1);
		}
		std::vector<uint8_t> verified_commit;
		if (require_commit) {
			const auto commit = host_transfer_commit_wire(reserved,
			    promotion_wire.data() + promotion_wire.size() - 32,
			    owner_wire.data() + owner_wire.size() - 32);
			std::vector<uint8_t> existing_commit;
			int committed = host_transfer_stage_read_at(this->dirfd,
			    commit_name, existing_commit);
			if (committed == 0 &&
			    (activate || read_activation || require_activation_result)) {
				std::vector<uint8_t> stray_activation;
				int activated = host_transfer_stage_read_at(this->dirfd,
				    activation_name, stray_activation);
				if (activated < 0)
					return (-1);
				if (activated != 0) {
					errno = EPROTO;
					return (-1);
				}
			}
			if (committed == 0 && all_results != nullptr &&
			    !host_transfer_outcome_audit_at(this->dirfd,
			    reserved.token, {}))
				return (-1);
			if (committed <= 0)
				return (committed);
			if (existing_commit.size() != commit.size() ||
			    !std::equal(commit.begin(), commit.end(),
			    existing_commit.begin())) {
				errno = EPROTO;
				return (-1);
			}
			verified_commit.swap(existing_commit);
		}
		if (require_activation_result) {
			if (!host_transfer_outcome_audit_slots_at(this->dirfd,
			    reserved.token, result_wire))
				return (-1);
			const auto marker = host_transfer_activation_wire(reserved,
			    verified_commit.data() + verified_commit.size() - 32,
			    result_wire.data() + result_wire.size() - 32);
			std::vector<uint8_t> existing;
			int activated = host_transfer_stage_read_at(this->dirfd,
			    activation_name, existing);
			if (activated < 0)
				return (-1);
			if (activated == 0) {
				errno = EBUSY;
				return (-1);
			}
			if (existing.size() != marker.size() ||
			    !std::equal(marker.begin(), marker.end(),
			    existing.begin())) {
				errno = EPROTO;
				return (-1);
			}
			int applied = handoff_rekey_applied_at(outbound.dirfd,
			    reserved);
			if (applied < 0)
				return (-1);
			if (applied == 0) {
				errno = EPROTO;
				return (-1);
			}
		}
		if (publish_result != nullptr ||
		    query_receipt_digest != nullptr) {
			const auto &receipt_digest = publish_result != nullptr ?
			    publish_result->receipt_digest : *query_receipt_digest;
			if (receipt_digest == std::array<uint8_t, 32>{} ||
			    (publish_result != nullptr &&
			    (!import_consumer_result_valid(*publish_result) ||
			    publish_result->token != reserved.token ||
			    memcmp(publish_result->slots_digest.data(),
			    result_wire.data() + result_wire.size() - 32,
			    publish_result->slots_digest.size()) != 0))) {
				errno = EPROTO;
				return (-1);
			}
			uint32_t matches = 0;
			uint32_t count = dtraced_wire_get_u32(
			    result_wire.data() + 52);
			for (uint32_t i = 0; i < count; i++)
				if (memcmp(result_wire.data() + 64 + i * 33,
				    receipt_digest.data(),
				    receipt_digest.size()) == 0)
					matches++;
			if (matches != 1) {
				errno = EPROTO;
				return (-1);
			}
			int phase;
			if (publish_result != nullptr) {
				phase = host_transfer_outcome_publish_at(
				    this->dirfd, *publish_result);
			} else {
				durable_import_consumer_result identity{};
				identity.token = reserved.token;
				identity.receipt_digest = receipt_digest;
				memcpy(identity.slots_digest.data(),
				    result_wire.data() + result_wire.size() - 32,
				    identity.slots_digest.size());
				phase = host_transfer_outcome_read_at(this->dirfd,
				    identity, *query_result);
			}
			if (phase < 0)
				return (-1);
			*published_phase = (consumer_receipt_phase)phase;
			return (1);
		}
		if (promote) {
			const auto commit = host_transfer_commit_wire(reserved,
			    promotion_wire.data() + promotion_wire.size() - 32,
			    owner_wire.data() + owner_wire.size() - 32);
			std::vector<uint8_t> existing_commit;
			int committed = host_transfer_stage_read_at(this->dirfd,
			    commit_name, existing_commit);
			if (committed < 0)
				return (-1);
			if (committed == 1) {
				if (!all_accepted || existing_commit.size() !=
				    commit.size() || !std::equal(commit.begin(),
				    commit.end(), existing_commit.begin())) {
					errno = EPROTO;
					return (-1);
				}
				if (fsync(this->dirfd) != 0)
					return (-1);
			} else {
				std::map<std::array<uint8_t, 16>,
				    std::array<uint8_t, 32>> programs;
				for (const auto &proof : plan.source_programs) {
					auto inserted = programs.emplace(
					    proof.recipient.consumer_session,
					    proof.program_digest);
					if (!inserted.second &&
					    inserted.first->second != proof.program_digest) {
						errno = EPROTO;
						return (-1);
					}
				}
				if (programs.size() != owners.size()) {
					errno = EPROTO;
					return (-1);
				}
				for (const auto &owner : owners) {
					std::array<uint8_t, 16> session{};
					memcpy(session.data(), owner.data() + 4, 16);
					auto program = programs.find(session);
					if (program == programs.end()) {
						errno = EPROTO;
						return (-1);
					}
					client_fd *matched = nullptr;
					for (client_fd *candidate :
					    this->state->sockfds) {
						if (candidate->retired.load() ||
						    candidate->kind != DTRACED_KIND_CONSUMER ||
						    !candidate->is_subscribed(
						    DTD_SUB_ELFWRITE) ||
						    candidate->session_id != session)
							continue;
						if (candidate->peer_uid !=
						    (uid_t)dtraced_wire_get_u32(
						    owner.data() + 20)) {
							errno = EPERM;
							return (-1);
						}
						if (candidate->consumer_replay_pending ||
						    !candidate->consumer_birth_valid ||
						    !candidate->consumer_program_valid) {
							errno = EBUSY;
							return (-1);
						}
						if (matched != nullptr) {
							errno = EPROTO;
							return (-1);
						}
						matched = candidate;
					}
					if (matched == nullptr ||
					    consumer_owner_bytes(*matched) != owner) {
						errno = EBUSY;
						return (-1);
					}
					if (matched->consumer_program_digest !=
					    program->second) {
						errno = EPROTO;
						return (-1);
					}
				}
				for (const auto &delivery : plan.deliveries)
					if (!delivery_transition_at(this->dirfd,
					    delivery, delivery_phase::accepted, false))
						return (-1);
				if (!handoff_publish_at(this->dirfd, commit_name,
				    commit.data(), commit.size()))
					return (-1);
			}
		}
		std::vector<durable_committed_import_result_state> recovered;
		if (all_results != nullptr) {
			uint32_t count = dtraced_wire_get_u32(
			    result_wire.data() + 52);
			recovered.reserve(count);
			size_t slot = 0;
			for (size_t i = 0; i < cohorts.size(); i++) {
				std::vector<durable_import_consumer_receipt> members;
				if (!decode_import_consumer_cohort(plan.deliveries[i],
				    cohorts[i], members))
					return (-1);
				for (const auto &member : members) {
					std::vector<uint8_t> hcr2;
					if (!encode_import_consumer_receipt(member,
					    hcr2))
						return (-1);
					durable_committed_import_result_state state{};
					state.recipient = member;
					state.outcome.token = reserved.token;
					memcpy(state.outcome.slots_digest.data(),
					    result_wire.data() + result_wire.size() - 32,
					    state.outcome.slots_digest.size());
					if (SHA256(hcr2.data(), hcr2.size(),
					    state.outcome.receipt_digest.data()) == nullptr ||
					    slot >= count ||
					    memcmp(result_wire.data() + 64 + slot * 33,
					    state.outcome.receipt_digest.data(), 32) != 0) {
						errno = EPROTO;
						return (-1);
					}
					durable_import_consumer_result observed{};
					int phase = host_transfer_outcome_read_at(this->dirfd,
					    state.outcome, observed);
					if (phase < 0)
						return (-1);
					if (phase != 0)
						state.outcome = observed;
					recovered.push_back(std::move(state));
					slot++;
				}
			}
			if (slot != count) {
				errno = EPROTO;
				return (-1);
			}
			if (!host_transfer_outcome_audit_at(this->dirfd,
			    reserved.token, recovered))
				return (-1);
		}
		if (activate || read_activation) {
			const auto marker = host_transfer_activation_wire(reserved,
			    verified_commit.data() + verified_commit.size() - 32,
			    result_wire.data() + result_wire.size() - 32);
			std::vector<uint8_t> existing;
			int present = host_transfer_stage_read_at(this->dirfd,
			    activation_name, existing);
			if (present < 0)
				return (-1);
			if (present == 1 && (existing.size() != marker.size() ||
			    !std::equal(marker.begin(), marker.end(),
			    existing.begin()))) {
				errno = EPROTO;
				return (-1);
			}
			int applied = handoff_rekey_applied_at(outbound.dirfd,
			    reserved);
			if (applied < 0)
				return (-1);
			if (present == 1 && applied == 0) {
				errno = EPROTO;
				return (-1);
			}
			if (present == 0 && read_activation)
				return (0);
			if (applied == 0) {
				errno = EBUSY;
				return (-1);
			}
			if (present == 0) {
				if (!handoff_publish_at(this->dirfd,
				    activation_name, marker.data(), marker.size()))
					return (-1);
			} else if (activate && fsync(this->dirfd) != 0)
				return (-1);
			if (activate)
				return (1);
		}
		std::vector<std::array<uint8_t, 32>> parsed;
		parsed.reserve(plan.deliveries.size());
		for (size_t i = 0; i < plan.deliveries.size(); i++) {
			std::array<uint8_t, 32> id{};
			memcpy(id.data(), expected.data() + 64 + i * 32,
			    id.size());
			parsed.push_back(id);
		}
		std::vector<durable_committed_import_entry> typed;
		if (committed_entries != nullptr) {
			typed.reserve(plan.deliveries.size());
			for (size_t i = 0; i < plan.deliveries.size(); i++) {
				durable_committed_import_entry entry{};
				entry.ingress = plan.deliveries[i];
				if (!decode_import_consumer_cohort(entry.ingress,
				    cohorts[i], entry.recipients))
					return (-1);
				typed.push_back(std::move(entry));
			}
		}
		delivery_ids.swap(parsed);
		if (committed_entries != nullptr)
			committed_entries->swap(typed);
		if (all_results != nullptr)
			all_results->swap(recovered);
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

int
dir::load_import_promotion_intent(const durable_handoff &reserved,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<std::array<uint8_t, 32>> &delivery_ids,
    bool allow_accepted)
{
	return (import_promotion_transaction(reserved, destination_session,
	    destination_uid, destination_pid, destination_name, delivery_ids,
	    allow_accepted, false));
}

bool
dir::promote_import_host_ingress(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	int present = import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, true);
	if (present == 1)
		return (true);
	if (present == 0)
		errno = ENOENT;
	return (false);
}

int
dir::load_committed_import_host_ingress(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<std::array<uint8_t, 32>> &delivery_ids)
{
	return (import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true));
}

int
dir::load_committed_import_recipients(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<durable_committed_import_entry> &entries)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	return (import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true, &entries));
}

int
dir::record_import_consumer_result(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    const durable_import_consumer_result &result)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	consumer_receipt_phase published = consumer_receipt_phase::pending;
	int present = import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true, nullptr,
	    &result, &published);
	if (present == 0)
		errno = ENOENT;
	return (present == 1 ? (int)published : -1);
}

int
dir::record_activated_import_consumer_result(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    const durable_import_consumer_result &result)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	consumer_receipt_phase published = consumer_receipt_phase::pending;
	int present = import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true, nullptr,
	    &result, &published, nullptr, nullptr, nullptr, false, false, true);
	if (present == 0)
		errno = ENOENT;
	return (present == 1 ? (int)published : -1);
}

int
dir::load_import_consumer_result(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    const std::array<uint8_t, 32> &receipt_digest,
    durable_import_consumer_result &observed)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	consumer_receipt_phase phase = consumer_receipt_phase::pending;
	int present = import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true, nullptr,
	    nullptr, &phase, &receipt_digest, &observed);
	if (present == 0)
		errno = ENOENT;
	return (present == 1 ? (phase == consumer_receipt_phase::pending ?
	    0 : (int)phase) : -1);
}

int
dir::load_committed_import_results(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<durable_committed_import_result_state> &results)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	return (import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true, nullptr,
	    nullptr, nullptr, nullptr, nullptr, &results));
}

bool
dir::activate_import_host_ingress(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	std::vector<durable_committed_import_result_state> results;
	int present = import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true, nullptr,
	    nullptr, nullptr, nullptr, nullptr, &results, true, false);
	if (present == 0)
		errno = ENOENT;
	return (present == 1);
}

int
dir::load_import_activation(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	std::vector<durable_committed_import_result_state> results;
	return (import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true, nullptr,
	    nullptr, nullptr, nullptr, nullptr, &results, false, true));
}

int
dir::load_activated_import_view(const durable_handoff &claimed,
    const std::array<uint8_t, 16> &destination_session,
    uint32_t destination_uid, uint32_t destination_pid,
    const std::string &destination_name,
    std::vector<durable_committed_import_entry> &entries,
    std::vector<durable_committed_import_result_state> &results)
{
	std::vector<std::array<uint8_t, 32>> delivery_ids;
	return (import_promotion_transaction(claimed,
	    destination_session, destination_uid, destination_pid,
	    destination_name, delivery_ids, true, false, true, &entries,
	    nullptr, nullptr, nullptr, nullptr, &results, false, true));
}

int
dir::load_activated_import_recipient(
    const std::array<uint8_t, 16> &token,
    const std::array<uint8_t, 16> &ingress_session, uint64_t delivery_id,
    const std::array<uint8_t, 16> &consumer_session,
    uint32_t consumer_uid, uint32_t consumer_pid,
    durable_committed_import_result_state &result)
{
	result = {};
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this ||
	    this->state->outbounddir == nullptr || token == std::array<uint8_t, 16>{} ||
	    ingress_session == std::array<uint8_t, 16>{} || delivery_id == 0 ||
	    consumer_session == std::array<uint8_t, 16>{} ||
	    consumer_uid == UINT32_MAX || consumer_pid <= 1) {
		errno = EINVAL;
		return (-1);
	}
	durable_handoff claimed{};
	int phase = this->state->outbounddir->handoff_status(token, claimed);
	if (phase < 0)
		return (-1);
	if (phase != (int)handoff_phase::claimed)
		return (0);
	std::array<uint8_t, 16> destination_session{};
	uint32_t uid = 0, pid = 0;
	std::string name;
	{
		std::lock_guard journal(this->publishmtx);
		handoff_process_lock process_lock(this->dirfd);
		if (!process_lock.held())
			return (-1);
		int present = host_transfer_stage_identity_at(this->dirfd,
		    token, destination_session, uid, pid, name);
		if (present <= 0)
			return (present);
	}
	try {
		std::vector<durable_committed_import_entry> entries;
		std::vector<durable_committed_import_result_state> outcomes;
		int present = load_activated_import_view(claimed,
		    destination_session, uid, pid, name, entries, outcomes);
		if (present <= 0)
			return (present);
		const durable_committed_import_result_state *matched = nullptr;
		for (const auto &entry : outcomes) {
			const auto &receipt = entry.recipient;
			if (receipt.ingress.handoff_token != token ||
			    receipt.ingress.session_id != ingress_session ||
			    receipt.ingress.delivery_id != delivery_id ||
			    memcmp(receipt.owner_wire.data() + 4,
			    consumer_session.data(), consumer_session.size()) != 0 ||
			    dtraced_wire_get_u32(receipt.owner_wire.data() + 20) !=
			    consumer_uid ||
			    dtraced_wire_get_u32(receipt.owner_wire.data() + 24) !=
			    consumer_pid)
				continue;
			if (matched != nullptr) {
				errno = EPROTO;
				return (-1);
			}
			matched = &entry;
		}
		if (matched == nullptr)
			return (0);
		result = *matched;
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

int
dir::list_activated_import_recipients(client_fd *consumer,
    std::vector<durable_committed_import_result_state> &results)
{
	results.clear();
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this || consumer == nullptr ||
	    consumer->retired.load() ||
	    consumer->kind != DTRACED_KIND_CONSUMER ||
	    !consumer->is_subscribed(DTD_SUB_ELFWRITE) ||
	    consumer->peer_uid == (uid_t)-1 || consumer->peer_pid <= 1 ||
	    !consumer->consumer_birth_valid ||
	    !consumer->consumer_program_valid) {
		errno = EINVAL;
		return (-1);
	}
	std::vector<durable_delivery_state> deliveries;
	if (!list_deliveries(deliveries))
		return (-1);
	try {
		std::vector<durable_committed_import_result_state> recovered;
		const auto owner = consumer_owner_bytes(*consumer);
		for (const auto &entry : deliveries) {
			const auto &ingress = entry.record;
			if (ingress.scope != 3 || ingress.journal_version != 5)
				continue;
			durable_committed_import_result_state result{};
			int found = load_activated_import_recipient(
			    ingress.handoff_token, ingress.session_id,
			    ingress.delivery_id, consumer->session_id,
			    (uint32_t)consumer->peer_uid,
			    (uint32_t)consumer->peer_pid, result);
			if (found < 0)
				return (-1);
			if (found == 0)
				continue;
			const auto &bound = result.recipient.ingress;
			if (delivery_record_bytes(bound) !=
			    delivery_record_bytes(ingress) ||
			    result.recipient.owner_wire != owner ||
			    result.recipient.program_digest !=
			    consumer->consumer_program_digest) {
				errno = EPROTO;
				return (-1);
			}
			recovered.push_back(std::move(result));
		}
		results.swap(recovered);
		return (results.empty() ? 0 : 1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

int
dir::queue_activated_import_consumer(client_fd *consumer,
    const std::array<uint8_t, 16> *only_token)
{
	if (consumer == nullptr || consumer->consumer_replay_pending) {
		errno = EBUSY;
		return (-1);
	}
	std::lock_guard import_jobs(consumer->consumer_import_jobs_mtx);
	std::vector<durable_committed_import_result_state> results;
	int present = list_activated_import_recipients(consumer, results);
	if (present == 0) {
		consumer->consumer_import_queued_receipts.clear();
		return (0);
	}
	if (present < 0)
		return (present);
	try {
		/* Rebuild only pending keys. A long-lived receiver must not retain
		 * historical HRO1 identities after they become terminal. */
		std::set<std::array<uint8_t, 48>> queued_receipts;
		std::list<job *> staged;
		std::vector<std::unique_ptr<job>> owned;
		for (const auto &entry : results) {
			if (entry.outcome.phase != consumer_receipt_phase::pending)
				continue;
			std::array<uint8_t, 48> receipt_key{};
			memcpy(receipt_key.data(),
			    entry.recipient.ingress.handoff_token.data(), 16);
			memcpy(receipt_key.data() + 16,
			    entry.outcome.receipt_digest.data(), 32);
			bool already_queued = consumer->
			    consumer_import_queued_receipts.count(receipt_key) != 0;
			if (already_queued) {
				queued_receipts.insert(receipt_key);
				continue;
			}
			if ((only_token != nullptr &&
			    entry.recipient.ingress.handoff_token != *only_token) ||
			    !queued_receipts.insert(receipt_key).second)
				continue;
			char spool[70];
			identified_spool_name(
			    entry.recipient.ingress.program_id.data(),
			    entry.recipient.ingress.source_id.data(), spool);
			auto pending = std::make_unique<job>(NOTIFY_ELFWRITE,
			    consumer);
			auto &notification = pending->notify_elfwrite_get();
			notification.path = strdup(spool);
			if (notification.path == nullptr)
				return (-1);
			notification.pathlen = strlen(spool);
			notification.dir = this;
			notification.nosha = true;
			owned.push_back(std::move(pending));
			staged.push_back(owned.back().get());
		}
		if (owned.empty()) {
			consumer->consumer_import_queued_receipts.swap(
			    queued_receipts);
			return (0);
		}
		if (consumer->retired.load()) {
			errno = EAGAIN;
			return (-1);
		}
		{
			std::lock_guard jobs(this->state->joblistmtx);
			/* A failed kevent must leave no jobs for an exact HPI1 retry
			 * to queue again. The event consumer also takes joblistmtx, so
			 * it cannot inspect the list until the splice completes. */
			if (!consumer->re_enable_write())
				return (-1);
			this->state->joblist.splice(this->state->joblist.end(),
			    staged);
		}
		for (auto &pending : owned)
			(void)pending.release();
		consumer->consumer_import_queued_receipts.swap(queued_receipts);
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

int
dir::resolve_import_derived_outbound(dir &outbound,
    const durable_committed_import_result_state &parent,
    const durable_derived_claim &claim, std::array<uint8_t, 32> &claim_digest)
{
	claim_digest = {};
	if (this->state == nullptr || this->state->inbounddir != this ||
	    this->state->outbounddir != &outbound || this == &outbound ||
	    !derived_claim_valid(claim)) {
		errno = EINVAL;
		return (-1);
	}
	const auto &ingress = parent.recipient.ingress;
	std::array<uint8_t, 16> consumer_session{};
	memcpy(consumer_session.data(), parent.recipient.owner_wire.data() + 4,
	    consumer_session.size());
	const uint32_t uid = dtraced_wire_get_u32(
	    parent.recipient.owner_wire.data() + 20);
	const uint32_t pid = dtraced_wire_get_u32(
	    parent.recipient.owner_wire.data() + 24);
	if (ingress.scope != 3 || ingress.journal_version != 5 ||
	    claim.consumer_session != consumer_session ||
	    claim.ingress_delivery_id != ingress.delivery_id ||
	    claim.ingress_vmid != ingress.vmid ||
	    claim.ingress_epoch != ingress.epoch ||
	    claim.ingress_program_id != ingress.program_id ||
	    claim.ingress_source_id != ingress.source_id) {
		errno = EPROTO;
		return (-1);
	}
	durable_committed_import_result_state current{};
	int found = load_activated_import_recipient(ingress.handoff_token,
	    ingress.session_id, ingress.delivery_id, consumer_session, uid, pid,
	    current);
	if (found != 1) {
		if (found == 0)
			errno = EBUSY;
		return (-1);
	}
	if (delivery_record_bytes(current.recipient.ingress) !=
	    delivery_record_bytes(ingress) ||
	    current.recipient.owner_wire != parent.recipient.owner_wire ||
	    current.recipient.program_digest !=
	    parent.recipient.program_digest ||
	    current.outcome.receipt_digest != parent.outcome.receipt_digest ||
	    current.outcome.slots_digest != parent.outcome.slots_digest ||
	    consumer_receipt_no_derived(current.outcome.phase)) {
		errno = EPROTO;
		return (-1);
	}
	uint8_t payload_digest[SHA256_DIGEST_LENGTH]{};
	uint8_t bare_digest[SHA256_DIGEST_LENGTH]{};
	bool spool = outbound.hash_identified_data(
	    claim.derived_program_id.data(), claim.ingress_source_id.data(),
	    payload_digest, false, true, bare_digest);
	if (!spool && errno != ENOENT)
		return (-1);
	if (spool &&
	    (memcmp(payload_digest, claim.payload_digest.data(),
	    sizeof(payload_digest)) != 0 ||
	    memcmp(bare_digest, claim.bare_elf_digest.data(),
	    sizeof(bare_digest)) != 0)) {
		errno = EPROTO;
		return (-1);
	}
	std::vector<durable_derived_claim> claims;
	if (!outbound.list_derived_claims(claims))
		return (-1);
	const durable_derived_claim *matched = nullptr;
	const auto expected = derived_claim_bytes(claim);
	for (const auto &entry : claims) {
		if (entry.consumer_session != consumer_session ||
		    entry.ingress_delivery_id != ingress.delivery_id ||
		    entry.ingress_vmid != ingress.vmid ||
		    entry.ingress_epoch != ingress.epoch ||
		    entry.ingress_program_id != ingress.program_id ||
		    entry.ingress_source_id != ingress.source_id)
			continue;
		if (matched != nullptr || derived_claim_bytes(entry) != expected) {
			errno = EPROTO;
			return (-1);
		}
		matched = &entry;
	}
	if (matched == nullptr) {
		if (spool)
			errno = EPROTO;
		else
			errno = EAGAIN;
		return (spool ? -1 : 0);
	}
	std::vector<durable_delivery_state> deliveries;
	if (!outbound.list_deliveries(deliveries))
		return (-1);
	bool delivered = false;
	for (const auto &entry : deliveries) {
		const auto &record = entry.record;
		if (record.scope != 0 ||
		    record.program_id != claim.derived_program_id)
			continue;
		uint16_t payload_vmid = record.journal_version == 5 ?
		    record.payload_vmid : record.vmid;
		uint64_t payload_epoch = record.journal_version == 5 ?
		    record.payload_epoch : record.epoch;
		if (record.source_id != claim.ingress_source_id ||
		    (record.journal_version != 4 &&
		    record.journal_version != 5) ||
		    payload_vmid != claim.target_vmid ||
		    payload_epoch != claim.target_epoch ||
		    record.payload_digest != claim.bare_elf_digest ||
		    (!spool && !derived_outbound_was_delivered(entry.phase))) {
			errno = EPROTO;
			return (-1);
		}
		if (derived_outbound_was_delivered(entry.phase))
			delivered = true;
	}
	if (!spool && !delivered) {
		errno = EAGAIN;
		return (0);
	}
	memcpy(claim_digest.data(), expected.data() + 160,
	    claim_digest.size());
	return (1);
}

int
dir::record_activated_import_processing(
    const durable_committed_import_result_state &parent,
    consumer_receipt_phase target,
    const std::array<uint8_t, 32> &claim_digest)
{
	const std::array<uint8_t, 32> empty_digest{};
	if ((target != consumer_receipt_phase::no_derived &&
	    target != consumer_receipt_phase::derived) ||
	    (target == consumer_receipt_phase::no_derived &&
	    claim_digest != empty_digest) ||
	    (target == consumer_receipt_phase::derived &&
	    claim_digest == empty_digest)) {
		errno = EINVAL;
		return (-1);
	}
	const auto &ingress = parent.recipient.ingress;
	std::array<uint8_t, 16> consumer_session{};
	memcpy(consumer_session.data(), parent.recipient.owner_wire.data() + 4,
	    consumer_session.size());
	const uint32_t uid = dtraced_wire_get_u32(
	    parent.recipient.owner_wire.data() + 20);
	const uint32_t pid = dtraced_wire_get_u32(
	    parent.recipient.owner_wire.data() + 24);
	durable_committed_import_result_state current{};
	int present = load_activated_import_recipient(ingress.handoff_token,
	    ingress.session_id, ingress.delivery_id, consumer_session, uid, pid,
	    current);
	if (present != 1) {
		if (present == 0)
			errno = EBUSY;
		return (-1);
	}
	if (delivery_record_bytes(current.recipient.ingress) !=
	    delivery_record_bytes(ingress) ||
	    current.recipient.owner_wire != parent.recipient.owner_wire ||
	    current.recipient.program_digest !=
	    parent.recipient.program_digest ||
	    current.outcome.receipt_digest != parent.outcome.receipt_digest ||
	    current.outcome.slots_digest != parent.outcome.slots_digest) {
		errno = EPROTO;
		return (-1);
	}
	durable_handoff claimed{};
	int phase = this->state->outbounddir->handoff_status(
	    ingress.handoff_token, claimed);
	if (phase != (int)handoff_phase::claimed) {
		errno = phase < 0 ? errno : EBUSY;
		return (-1);
	}
	std::array<uint8_t, 16> destination_session{};
	uint32_t destination_uid = 0, destination_pid = 0;
	std::string name;
	{
		std::lock_guard journal(this->publishmtx);
		handoff_process_lock process_lock(this->dirfd);
		if (!process_lock.held())
			return (-1);
		present = host_transfer_stage_identity_at(this->dirfd,
		    ingress.handoff_token, destination_session,
		    destination_uid, destination_pid, name);
		if (present != 1) {
			if (present == 0)
				errno = ENOENT;
			return (-1);
		}
	}
	durable_import_consumer_result outcome = current.outcome;
	outcome.phase = target;
	outcome.derived_claim_digest = claim_digest;
	return (record_activated_import_consumer_result(claimed,
	    destination_session, destination_uid, destination_pid,
	    name, outcome));
}

int
dir::record_activated_import_execution(
    const std::array<uint8_t, 16> &token,
    const std::array<uint8_t, 16> &ingress_session, uint64_t delivery_id,
    const std::array<uint8_t, 16> &consumer_session,
    uint32_t consumer_uid, uint32_t consumer_pid,
    consumer_receipt_phase target)
{
	if (target != consumer_receipt_phase::executed_no_derived &&
	    target != consumer_receipt_phase::executed_derived) {
		errno = EINVAL;
		return (-1);
	}
	durable_committed_import_result_state current{};
	int present = load_activated_import_recipient(token, ingress_session,
	    delivery_id, consumer_session, consumer_uid, consumer_pid, current);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (-1);
	}
	if (current.outcome.phase == consumer_receipt_phase::pending) {
		errno = EAGAIN;
		return (-1);
	}
	if ((target == consumer_receipt_phase::executed_derived &&
	    !consumer_receipt_derived(current.outcome.phase)) ||
	    (target == consumer_receipt_phase::executed_no_derived &&
	    !consumer_receipt_no_derived(current.outcome.phase))) {
		errno = EPROTO;
		return (-1);
	}
	durable_handoff claimed{};
	int phase = this->state->outbounddir->handoff_status(token, claimed);
	if (phase != (int)handoff_phase::claimed) {
		errno = phase < 0 ? errno : EBUSY;
		return (-1);
	}
	std::array<uint8_t, 16> destination_session{};
	uint32_t uid = 0, pid = 0;
	std::string name;
	{
		std::lock_guard journal(this->publishmtx);
		handoff_process_lock process_lock(this->dirfd);
		if (!process_lock.held())
			return (-1);
		present = host_transfer_stage_identity_at(this->dirfd, token,
		    destination_session, uid, pid, name);
		if (present != 1) {
			if (present == 0)
				errno = ENOENT;
			return (-1);
		}
	}
	durable_import_consumer_result result = current.outcome;
	result.phase = target;
	return (record_activated_import_consumer_result(claimed,
	    destination_session, uid, pid, name, result));
}
/* HT-C END */

/* A replacement incarnation needs settled execution and explicit retirement evidence.
 * PID absence is never proof; parsed-only and pending work keep their owner. */
static int
consumer_replay_owner(const durable_consumer_receipt_state &entry,
    uint32_t uid, pid_t pid, bool same_incarnation, bool retired)
{
	if (entry.record.consumer_uid != uid) {
		errno = EPERM;
		return (-1);
	}
	if (entry.record.consumer_pid == (uint32_t)pid && same_incarnation)
		return (1);
	if (entry.phase != consumer_receipt_phase::executed_no_derived &&
	    entry.phase != consumer_receipt_phase::executed_derived) {
		errno = EBUSY;
		return (-1);
	}
	if (!retired) {
		errno = EBUSY;
		return (-1);
	}
	return (0);
}

static int
consumer_replay_retirement(dir &directory,
    const durable_consumer_receipt &record, collector_owner_registry &owners)
{
	/* A previous kernel boot proves all three facts; never a PID test. */
	int proven = directory.consumer_prior_boot_retired(record);
	if (proven != 0)
		return (proven);
	proven = directory.checkpoint_consumer_process_exit(record, owners);
	if (proven != 1)
		return (proven);
	proven = directory.consumer_reaper_exit_status(record);
	if (proven != 1)
		return (proven);
	return (directory.consumer_kernel_handle_retired(record));
}

int
dir::queue_recovered_consumer(client_fd *consumer)
{
	if (this->state == nullptr || !this->state->is_control_machine() ||
	    this->state->inbounddir != this || consumer == nullptr ||
	    consumer->retired.load() ||
	    consumer->kind != DTRACED_KIND_CONSUMER ||
	    !consumer->is_subscribed(DTD_SUB_ELFWRITE) ||
	    consumer->peer_uid == (uid_t)-1 || consumer->peer_pid <= 1 ||
	    !consumer->consumer_birth_valid) {
		errno = EINVAL;
		return (-1);
	}
	std::vector<durable_consumer_receipt_state> receipts;
	if (!this->list_consumer_receipts(receipts))
		return (-1);
	/* Registration must precede even the first delivery. A hello alone is
	 * neither a program binding nor HPI2 kernel-birth verification. Admission
	 * and registration serialize recovery through the existing scan gate. */
	bool registered;
	int process_fd;
	{
		std::lock_guard clients(this->state->sockfdsmtx);
		registered = consumer->consumer_program_valid;
		process_fd = consumer->consumer_process_fd;
	}
	if (!registered) {
		consumer->consumer_replay_registration_pending.store(true);
		return (0);
	}
	for (const auto &entry : receipts) {
		if (entry.record.consumer_session != consumer->session_id)
			continue;
		std::array<uint8_t, 24> lifetime{};
		int modern = consumer_handle_status(entry.record, lifetime);
		if (modern < 0)
			return (-1);
		if (modern == 0)
			continue;
		if (process_fd < 0) {
			errno = EOPNOTSUPP;
			return (-1);
		}
	}
	int owner_status;
	std::array<uint8_t, 76> prior_owner{};
	{
		std::lock_guard lk(this->publishmtx);
		handoff_process_lock process_lock(this->dirfd);
		if (!process_lock.held())
			return (-1);
		char name[49];
		consumer_owner_name(consumer->session_id,
		    (uint32_t)consumer->peer_pid, name);
		owner_status = consumer_owner_read_at(this->dirfd,
		    name, prior_owner);
		if (owner_status == 1 &&
		    prior_owner != consumer_owner_bytes(*consumer)) {
			if (dtraced_wire_get_u32(prior_owner.data() + 20) !=
			    (uint32_t)consumer->peer_uid) {
				errno = EPERM;
				return (-1);
			}
			owner_status = 2; /* Same PID, new incarnation. */
		}
	}
	if (owner_status < 0)
		return (-1);
	try {
		std::list<job *> staged;
		std::vector<std::unique_ptr<job>> owned;
		for (const auto &entry : receipts) {
			if (entry.record.consumer_session != consumer->session_id)
				continue;
			if (entry.record.consumer_uid != (uint32_t)consumer->peer_uid) {
				errno = EPERM;
				return (-1);
			}
			if (entry.record.consumer_pid ==
			    (uint32_t)consumer->peer_pid && owner_status != 1 &&
			    entry.phase != consumer_receipt_phase::executed_no_derived &&
			    entry.phase != consumer_receipt_phase::executed_derived) {
				errno = owner_status == 0 ? EPROTO : EBUSY;
				return (-1);
			}
			int same;
			{
				std::lock_guard journal(this->publishmtx);
				handoff_process_lock process_lock(this->dirfd);
				if (!process_lock.held())
					return (-1);
				same = consumer_replay_same_owner_at(this->dirfd,
				    entry.record, *consumer);
			}
			if (same < 0)
				return (-1);
			bool retired = false;
			if (same == 0 &&
			    (entry.phase == consumer_receipt_phase::executed_no_derived ||
			    entry.phase == consumer_receipt_phase::executed_derived)) {
				int proven = consumer_replay_retirement(*this, entry.record,
				    this->state->collector_owners);
				if (proven < 0)
					return (-1);
				retired = proven == 1;
			}
			if (consumer_replay_owner(entry,
			    (uint32_t)consumer->peer_uid,
			    consumer->peer_pid, same == 1, retired) < 0)
				return (-1);

			if (consumer_receipt_complete(entry.phase))
				continue;
			if (entry.phase != consumer_receipt_phase::pending) {
				errno = EPROTO;
				return (-1);
			}
			/* A permanent stop survives daemon restart. Keep its receipts
			 * for collector shutdown, but do not recreate delivery jobs.
			 * The send path still serializes with a stop racing this scan. */
			if (this->state->outbounddir != nullptr) {
				durable_session_stop stopped{};
				int closed = this->state->outbounddir->fresh_session_stop_for_vm(
				    entry.record.ingress.vmid, entry.record.ingress.epoch,
				    stopped);
				if (closed < 0)
					return (-1);
				if (closed != 0)
					continue;
			}
			char name[70];
			identified_spool_name(entry.record.ingress.program_id.data(),
			    entry.record.ingress.source_id.data(), name);
			/* Newly accepted files are still owned by the live watcher.
			 * Startup-memorized files need explicit receipt replay. */
			if (!this->memorized(name))
				continue;
			auto pending =
			    std::make_unique<job>(NOTIFY_ELFWRITE, consumer);
			auto &ne = pending->notify_elfwrite_get();
			ne.path = strdup(name);
			if (ne.path == nullptr)
				return (-1);
			ne.pathlen = strlen(name);
			ne.dir = this;
			ne.nosha = true;
			pending->handoff_vmid = entry.record.ingress.vmid;
			pending->handoff_epoch = entry.record.ingress.epoch;
			owned.push_back(std::move(pending));
			staged.push_back(owned.back().get());
		}
		{
			std::lock_guard lk(this->publishmtx);
			handoff_process_lock process_lock(this->dirfd);
			if (!process_lock.held())
				return (-1);
			/* A crash can leave HCB1 committed before its HCR1 members or
			 * HCO1 owner. The absent-owner case must inspect the cohort too;
			 * the earlier receipt snapshot alone cannot fence that gap. */
			if (owner_status == 0 &&
			    !consumer_owner_cohorts_settled_at(this->dirfd,
			    *consumer))
				return (-1);
			if (owner_status == 2) {
				if (!consumer_owner_cohorts_settled_at(this->dirfd,
				    *consumer) ||
				    !consumer_owner_publish_at(this->dirfd,
				    *consumer, &prior_owner))
					return (-1);
			} else if (!consumer_owner_bind_at(this->dirfd,
			    *consumer))
				return (-1);
		}
		if (owned.empty()) {
			consumer->consumer_replay_registration_pending.store(false);
			return (0);
		}
		{
			std::lock_guard jobs(this->state->joblistmtx);
			/* A failed event arm must not publish jobs that an exact
			 * recovery retry would enqueue again. The write dispatcher
			 * takes this lock before inspecting the list. */
			if (!consumer->re_enable_write())
				return (-1);
			this->state->joblist.splice(this->state->joblist.end(),
			    staged);
			/* Open the send gate before dispatch can take a resumed job. */
			consumer->consumer_replay_registration_pending.store(false);
		}
		for (auto &pending : owned)
			(void)pending.release();
		return (1);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (-1);
	}
}

bool
dir::memorize_file(struct dirent *f)
{
	if (f == NULL) {
		ERR("dirent is NULL");
		return (false);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (true);

	if (f->d_name[0] == '.')
		return (true);

	std::lock_guard lock(this->existingmtx);
	this->existing_files.insert(std::string(f->d_name));
	return (true);
}

dir::dir(const char *path, foreach_fn_t fn)
    : dirpath(path)
    , processfn(fn)
{
	bool retry;

	if (!this->dirpath.empty() && this->dirpath.back() != '/')
		this->dirpath += '/';
	retry = true;
againmkdir:
	this->dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (this->dirfd == -1) {
		if (retry && errno == ENOENT) {
			if (mkdir(path, 0700) != 0) {
				int error = errno;
				ERR("failed to mkdir %s: %m", path);
				throw std::system_error(error, std::generic_category(),
				    "mkdir");
			} else {
				retry = false;
				goto againmkdir;
			}
		}

		int error = errno;
		ERR("failed to open %s: %m", path);
		throw std::system_error(error, std::generic_category(), "open");
	}

	this->dirp = fdopendir(this->dirfd);
	if (this->dirp == NULL) {
		int error = errno;
		ERR("fdopendir(%d) failed for %s: %m", this->dirfd,
		    this->dirpath.c_str());
		(void)close(this->dirfd);
		throw std::system_error(error, std::generic_category(),
		    "fdopendir");
	}
}

dir::dir(const std::string &path, foreach_fn_t fn, DIR *stream)
    : dirpath(path), dirp(stream), processfn(fn), dirfd(::dirfd(stream))
{
}

std::unique_ptr<dir>
dir::fresh_empty_session(uint16_t vmid, uint64_t epoch)
{
	return (session_directory(vmid, epoch, true));
}

std::unique_ptr<dir>
dir::existing_session(uint16_t vmid, uint64_t epoch)
{
	return (session_directory(vmid, epoch, false));
}

std::unique_ptr<dir>
dir::session_directory(uint16_t vmid, uint64_t epoch, bool empty)
{
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EINVAL;
		return (nullptr);
	}
	struct stat st;
	if (fstat(this->dirfd, &st) != 0)
		return (nullptr);
	if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
	    (st.st_mode & 0077) != 0) {
		errno = EPERM;
		return (nullptr);
	}
	char name[40];
	snprintf(name, sizeof(name), ".session.%04x.%016jx", vmid,
	    (uintmax_t)epoch);
	if (empty && mkdirat(this->dirfd, name, 0700) != 0 && errno != EEXIST)
		return (nullptr);
	int fd = openat(this->dirfd, name,
	    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (nullptr);
	int error = 0;
	if (fstat(fd, &st) != 0)
		error = errno;
	else if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
	    (st.st_mode & 0077) != 0)
		error = EPERM;
	if (error != 0) {
		close(fd);
		errno = error;
		return (nullptr);
	}
	DIR *stream = fdopendir(fd);
	if (stream == nullptr) {
		error = errno;
		close(fd);
		errno = error;
		return (nullptr);
	}
	errno = 0;
	while (empty) {
		struct dirent *entry = readdir(stream);
		if (entry == nullptr)
			break;
		if (strcmp(entry->d_name, ".") != 0 &&
		    strcmp(entry->d_name, "..") != 0) {
			error = EEXIST;
			break;
		}
	}
	if (error == 0)
		error = errno;
	if (empty && error == 0 && (fsync(fd) != 0 || fsync(this->dirfd) != 0))
		error = errno;
	if (error != 0) {
		closedir(stream);
		errno = error;
		return (nullptr);
	}
	rewinddir(stream);
	try {
		auto result = std::unique_ptr<dir>(new dir(
		    this->dirpath + name + "/", this->processfn, stream));
		result->state = this->state;
		return (result);
	} catch (...) {
		closedir(stream);
		throw;
	}
}

dir::~dir()
{
	/* fdopendir transfers descriptor ownership to the directory stream. */
	(void)closedir(this->dirp);
}

bool
dir::file_exists(const char *f)
{

	return (faccessat(this->dirfd, f, F_OK, 0) == 0);
}

static bool handoff_mutating_resets_recover_locked(int, state *);

bool
dir::populate_existing(void)
{
	struct dirent *file;
	bool ok = true;
	bool handoff_temporary = false;
	bool handoff_boundary_marker = false;
	bool handoff_rebind_intent = false;
	bool handoff_rebind_plan = false;
	bool handoff_rebind_commit = false;
	bool handoff_rebind_done = false;
	bool handoff_mutating_reset = false;
	std::vector<std::string> stale;
	auto is_temporary = [](const char *name) {
		if (strncmp(name, ".owner.tmp.", 11) == 0) {
			if (strlen(name) != 43)
				return (false);
			for (size_t i = 11; i < 43; i++)
				if (!((name[i] >= '0' && name[i] <= '9') ||
				    (name[i] >= 'a' && name[i] <= 'f')))
					return (false);
			return (true);
		}
		if (strncmp(name, ".consumer.tmp.", 14) == 0) {
			if (strlen(name) != 46)
				return (false);
			for (size_t i = 14; i < 46; i++)
				if (!((name[i] >= '0' && name[i] <= '9') ||
				    (name[i] >= 'a' && name[i] <= 'f')))
					return (false);
			return (true);
		}
		if (strncmp(name, ".cohort.tmp.", 12) == 0) {
			if (strlen(name) != 44)
				return (false);
			for (size_t i = 12; i < 44; i++)
				if (!((name[i] >= '0' && name[i] <= '9') ||
				    (name[i] >= 'a' && name[i] <= 'f')))
					return (false);
			return (true);
		}
		if (strncmp(name, ".handoff-tmp.", 13) == 0) {
			if (strlen(name) != 45)
				return (false);
			for (size_t i = 13; i < 45; i++)
				if (!((name[i] >= '0' && name[i] <= '9') ||
				    (name[i] >= 'a' && name[i] <= 'f')))
					return (false);
			return (true);
		}
		if (strncmp(name, ".elf.", 5) != 0 || strlen(name) != 37)
			return (false);
		for (size_t i = 5; i < 37; i++)
			if (!((name[i] >= '0' && name[i] <= '9') ||
			    (name[i] >= 'a' && name[i] <= 'f')))
				return (false);
		return (true);
	};

	rewinddir(this->dirp);
	for (;;) {
		errno = 0;
		file = readdir(this->dirp);
		if (file == NULL) {
			if (errno != 0)
				ok = false;
			break;
		}
		if (is_temporary(file->d_name)) {
			stale.emplace_back(file->d_name);
			if (strncmp(file->d_name, ".handoff-tmp.", 13) == 0)
				handoff_temporary = true;
		} else {
			if (strncmp(file->d_name, ".handoff-start.", 15) == 0 ||
			    strncmp(file->d_name, ".handoff-capable.", 17) == 0)
				/* HT-C BEGIN: disabled trace continuity. */
				handoff_boundary_marker = true;
				/* HT-C END */
			if (strncmp(file->d_name, ".handoff-rebind.", 16) == 0)
				/* HT-C BEGIN: disabled trace continuity. */
				handoff_rebind_intent = true;
				/* HT-C END */
			if (strncmp(file->d_name,
			    ".handoff-rebind-plan.", 21) == 0)
				/* HT-C BEGIN: disabled trace continuity. */
				handoff_rebind_plan = true;
				/* HT-C END */
			if (strncmp(file->d_name,
			    ".handoff-rebind-commit.", 23) == 0)
				/* HT-C BEGIN: disabled trace continuity. */
				handoff_rebind_commit = true;
				/* HT-C END */
			if (strncmp(file->d_name,
			    ".handoff-rebind-done.", 21) == 0)
				/* HT-C BEGIN: disabled trace continuity. */
				handoff_rebind_done = true;
				/* HT-C END */
			if (strncmp(file->d_name, ".handoff-reset.", 15) == 0)
				/* HT-C BEGIN: disabled trace continuity. */
				handoff_mutating_reset = true;
				/* HT-C END */
			if (strncmp(file->d_name, ".owner.", 7) == 0) {
				std::array<uint8_t, 76> wire{};
				if (consumer_owner_read_at(this->dirfd,
				    file->d_name, wire) != 1) {
					ok = false;
					break;
				}
			}
			std::lock_guard lock(this->existingmtx);
			this->existing_files.insert(std::string(file->d_name));
		}
	}

	rewinddir(this->dirp);
	if (!ok)
		return (false);
	/* A replacement daemon can overlap an in-flight handoff publisher.
	 * The control outbound directory also audits every durable HJB1 under
	 * that lock, even if none was visible during the initial scan. */
	bool audit_journal = this->state != nullptr &&
	    this->state->is_control_machine() &&
	    this->state->outbounddir == this;
	handoff_process_lock process_lock(this->dirfd,
	    handoff_temporary || handoff_boundary_marker ||
	    handoff_rebind_intent || handoff_rebind_plan ||
	    handoff_rebind_commit || handoff_rebind_done ||
	    handoff_mutating_reset || audit_journal);
	if ((handoff_temporary || handoff_boundary_marker ||
	    handoff_rebind_intent || handoff_rebind_plan ||
	    handoff_rebind_commit || handoff_rebind_done ||
	    handoff_mutating_reset || audit_journal) &&
	    !process_lock.held())
		return (false);
	for (const std::string &name : stale)
		if (unlinkat(this->dirfd, name.c_str(), 0) != 0 &&
		    errno != ENOENT)
			return (false);
	if (!stale.empty() && fsync(this->dirfd) != 0)
		return (false);
	if (audit_journal &&
	    !handoff_mutating_resets_recover_locked(this->dirfd, this->state))
		/* HT-C BEGIN: disabled trace continuity. */
		return (false);
		/* HT-C END */
	if ((handoff_rebind_commit || handoff_rebind_done ||
	    audit_journal) &&
	    !handoff_rebind_commits_recover_locked(this->dirfd))
		/* HT-C BEGIN: disabled trace continuity. */
		return (false);
		/* HT-C END */
	if ((handoff_boundary_marker || audit_journal) &&
	    !handoff_execution_starts_audit_locked(this->dirfd))
		/* HT-C BEGIN: disabled trace continuity. */
		return (false);
		/* HT-C END */
	if ((handoff_rebind_intent || audit_journal) &&
	    !handoff_rebinds_audit_locked(this->dirfd))
		/* HT-C BEGIN: disabled trace continuity. */
		return (false);
		/* HT-C END */
	if ((handoff_rebind_plan || audit_journal) &&
	    !handoff_rebind_plans_audit_locked(this->dirfd,
	    audit_journal ? this->state : nullptr))
		/* HT-C BEGIN: disabled trace continuity. */
		return (false);
		/* HT-C END */
	if (audit_journal &&
	    (!source_journal_stages_audit_locked(this->dirfd) ||
	    !source_journal_ready_audit_locked(this->dirfd) ||
	    !imported_attestations_audit_locked(this->dirfd,
	    this->state->handoff_keys)))
		/* HT-C BEGIN: disabled trace continuity. */
		return (false);
		/* HT-C END */
	return (ok);
}

/* The VM target and bare-ELF digest of a host outbound spool, exactly as
 * job::send_elf() derives them from the bytes it sends: an optional VM
 * target envelope, then an ELF. 1 valid, -1 not a sendable spool. */
static int
host_outbound_spool(dir &directory, const char *name, uint16_t &target_vmid,
    uint64_t &target_epoch, std::array<uint8_t, 32> &digest)
{
	target_vmid = 0;
	target_epoch = 0;
	int fd = openat(directory.dirfd, name,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return (-1);
	struct stat sb;
	std::vector<uint8_t> bytes;
	bool ok = fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) &&
	    sb.st_size >= 4 && (uint64_t)sb.st_size <= max_request_bytes -
	    SHA256_DIGEST_LENGTH;
	if (ok) {
		try {
			bytes.resize((size_t)sb.st_size);
		} catch (const std::bad_alloc &) {
			ok = false;
		}
	}
	for (size_t offset = 0; ok && offset < bytes.size();) {
		ssize_t n = read(fd, bytes.data() + offset, bytes.size() - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			ok = false;
		else
			offset += (size_t)n;
	}
	int error = errno;
	(void)close(fd);
	if (!ok) {
		errno = error;
		return (-1);
	}
	size_t offset = 0;
	if (memcmp(bytes.data(), "\177ELF", 4) != 0) {
		hypertrace_vm_envelope target;
		if (bytes.size() < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4) {
			errno = EPROTO;
			return (-1);
		}
		hypertrace_envelope_decode(&target, bytes.data());
		if (target.magic != HYPERTRACE_TARGET_MAGIC ||
		    target.version != HYPERTRACE_ENVELOPE_VERSION ||
		    target.vmid == 0 || target.vmid >= HYPERTRACE_MAX_VMS ||
		    target.epoch == 0 || target.name_length != 0 ||
		    memcmp(bytes.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
		    "\177ELF", 4) != 0) {
			errno = EPROTO;
			return (-1);
		}
		offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
		target_vmid = target.vmid;
		target_epoch = target.epoch;
	}
	if (SHA256(bytes.data() + offset, bytes.size() - offset,
	    digest.data()) == NULL) {
		errno = EIO;
		return (-1);
	}
	return (1);
}

/* Record the pending HTD4 delivery of a host outbound spool to one attested
 * forwarder before the spool is memorized, so neither a failed first send
 * nor a restart can lose it: admission recovery resends a pending record
 * with its recorded delivery ID (the guest treats an exact token retry as
 * the same delivery). 1 recorded, 0 not a recipient (other VM target or a
 * revoked source), 2 not recordable here (send_elf() decides, as before),
 * -1 error. */
static int
record_host_outbound_intent(dir &directory, client_fd &client,
    const std::array<uint8_t, 16> &program,
    const std::array<uint8_t, 16> &source, uint16_t target_vmid,
    uint64_t target_epoch, const std::array<uint8_t, 32> &digest,
    std::unique_ptr<durable_delivery> &recorded)
{
	if (client.vmid == 0 || client.vm_epoch == 0 || client.peer_pid <= 1 ||
	    client.peer_uid == (uid_t)-1 || !client.current_vm_attestation())
		return (2);
	if (target_vmid != 0 &&
	    (client.vmid != target_vmid || client.vm_epoch != target_epoch))
		return (0);
	durable_delivery record{};
	record.session_id = client.session_id;
	record.vmid = client.vmid;
	record.epoch = client.vm_epoch;
	record.program_id = program;
	record.source_id = source;
	record.peer_uid = (uint32_t)client.peer_uid;
	record.peer_pid = (uint32_t)client.peer_pid;
	record.journal_version = 4;
	record.payload_digest = digest;
	for (unsigned attempt = 0; attempt < 8; attempt++) {
		do {
			arc4random_buf(&record.delivery_id,
			    sizeof(record.delivery_id));
		} while (record.delivery_id == 0);
		if (directory.record_delivery(record, delivery_phase::pending,
		    true)) {
			recorded = std::make_unique<durable_delivery>(record);
			return (1);
		}
		if (errno == ECANCELED)
			return (0);
		if (errno == EBUSY)
			return (2); /* a source handoff defers in send_elf() */
		if (errno != EEXIST)
			return (-1);
	}
	errno = EEXIST;
	return (-1);
}

/* Guest: record the pending scope-2 HTD4 token for the transport
 * forwarder before the spool is memorized; startup recovery settles or
 * replays it through the host ingest status (dtraced_dttransport.cc).
 * 1 recorded, 2 not recordable here (send_elf() records, as before), -1
 * error. */
static int
record_guest_outbound_intent(dir &directory, client_fd &client,
    const std::array<uint8_t, 16> &program,
    const std::array<uint8_t, 16> &source, uint16_t vmid, uint64_t epoch,
    const std::array<uint8_t, 32> &digest,
    std::unique_ptr<durable_delivery> &recorded)
{
	durable_delivery record{};
	record.session_id = client.session_id;
	record.vmid = vmid;
	record.epoch = epoch;
	record.program_id = program;
	record.source_id = source;
	record.peer_uid = (uint32_t)client.peer_uid;
	record.peer_pid = (uint32_t)client.peer_pid;
	record.scope = 2;
	record.journal_version = 4;
	record.payload_digest = digest;
	for (unsigned attempt = 0; attempt < 8; attempt++) {
		do {
			arc4random_buf(&record.delivery_id,
			    sizeof(record.delivery_id));
		} while (record.delivery_id == 0);
		if (directory.record_delivery(record, delivery_phase::pending,
		    true)) {
			recorded = std::make_unique<durable_delivery>(record);
			return (1);
		}
		if (errno == ESTALE || errno == EINVAL)
			return (2); /* rekeyed lifetime or unusable peer identity */
		if (errno != EEXIST) {
			/* A failed write may still have published the token;
			 * otherwise send_elf() records one at send time, as it
			 * did before queue-time recording. */
			int saved = errno;
			int phase = directory.delivery_status(record);
			if (phase == (int)delivery_phase::pending) {
				recorded = std::make_unique<durable_delivery>(record);
				return (1);
			}
			if (phase == 0)
				return (2);
			errno = phase < 0 ? errno : saved;
			return (-1);
		}
	}
	errno = EEXIST;
	return (-1);
}

static bool
queue_elfwrite_batch(state &s, dir &directory, struct dirent *file, int kind,
    int nosha, const durable_delivery *ingress = nullptr)
{
	try {
		std::unique_ptr<dir::source_transaction> source_live;
		std::vector<durable_consumer_receipt> cohort;
		int cohort_present = 0;
		if (ingress != nullptr) {
			if (s.outbounddir == nullptr) {
				errno = EINVAL;
				return (false);
			}
			/* Pending HCR1 records and job publication belong to the same
			 * source cut as consumer processing. Acquire before sockfdsmtx,
			 * matching the KILL publisher's lock order. */
			source_live = s.outbounddir->lock_live_source(
			    ingress->source_id.data(), ingress->vmid,
			    ingress->epoch);
			if (!source_live) {
				if (errno == EBUSY)
					return (true); /* ABORT requests another scan. */
				if (errno == ECANCELED)
					return (directory.memorize_file(file));
				return (false);
			}
			cohort_present = directory.consumer_cohort(*ingress, {}, cohort);
			if (cohort_present < 0)
				return (false);
			if (cohort_present == 0) {
				/* Legacy HCR1 records have no reconstructible cohort. Do
				 * not assign their upload to a new session after a crash. */
				std::vector<durable_consumer_receipt_state> receipts;
				if (!directory.list_consumer_receipts(receipts))
					return (false);
				for (const auto &entry : receipts) {
					const auto &prior = entry.record.ingress;
					if (prior.scope == 3 &&
					    prior.delivery_id == ingress->delivery_id &&
					    prior.vmid == ingress->vmid &&
					    prior.epoch == ingress->epoch &&
					    prior.program_id == ingress->program_id &&
					    prior.source_id == ingress->source_id)
						return (directory.memorize_file(file));
				}
			}
		}
		std::list<job *> staged;
		std::vector<std::unique_ptr<job>> owned;
		/* Outbound spools: durable intent per recipient before the spool
		 * is memorized (see record_host_outbound_intent). The guest's one
		 * recipient is its transport forwarder in the current VM lifetime;
		 * the identity query runs before sockfdsmtx is held. */
		std::array<uint8_t, 16> host_program{}, host_source{};
		std::array<uint8_t, 32> host_digest{};
		uint16_t host_target_vmid = 0;
		uint64_t host_target_epoch = 0;
		const bool spool_intent = ingress == nullptr &&
		    kind == DTRACED_KIND_FORWARDER && &directory == s.outbounddir &&
		    spool_identity_from_path(file->d_name, host_program,
		    host_source) &&
		    host_outbound_spool(directory, file->d_name, host_target_vmid,
		    host_target_epoch, host_digest) == 1;
		const bool host_intent = spool_intent && s.is_control_machine();
		uint16_t guest_vmid = 0;
		uint64_t guest_epoch = 0;
		bool guest_recipient = false;
		if (spool_intent && !s.is_control_machine()) {
			std::lock_guard clients(s.sockfdsmtx);
			for (client_fd *client : s.sockfds)
				guest_recipient |= !client->retired.load() &&
				    client->kind == kind &&
				    client->is_subscribed(DTD_SUB_ELFWRITE);
		}
		const bool guest_intent = guest_recipient &&
		    host_target_vmid == 0 && s.dtt_fd >= 0 &&
		    s.query_vm_identity(guest_vmid, guest_epoch) &&
		    guest_vmid != 0 && guest_epoch != 0;
		std::lock_guard clients_lock(s.sockfdsmtx);
		owned.reserve(s.sockfds.size());
		if (ingress != nullptr && cohort_present == 0) {
			std::vector<durable_consumer_receipt> proposed;
			for (client_fd *client : s.sockfds) {
				if (client->retired.load() ||
				    client->consumer_replay_pending ||
				    client->consumer_replay_registration_pending.load() ||
				    (kind == DTRACED_KIND_CONSUMER &&
				    !client->consumer_program_valid) ||
				    client->kind != kind ||
				    !client->is_subscribed(DTD_SUB_ELFWRITE))
					continue;
				durable_consumer_receipt receipt{};
				receipt.ingress = *ingress;
				receipt.consumer_session = client->session_id;
				receipt.consumer_uid = (uint32_t)client->peer_uid;
				receipt.consumer_pid = (uint32_t)client->peer_pid;
				proposed.push_back(receipt);
			}
			if (!proposed.empty()) {
				cohort_present = directory.consumer_cohort(*ingress,
				    proposed, cohort);
				if (cohort_present != 1)
					return (false);
			}
		}
		/* Repair every member before publishing even the first job. A
		 * crash between HCR1 fsyncs can be completed from HCB1. */
		for (const auto &receipt : cohort)
			if (directory.record_consumer_receipt(receipt,
			    consumer_receipt_phase::pending) < 0)
				return (false);
		bool had_recipient = false;
		for (client_fd *client : s.sockfds) {
			if (client->retired.load() || client->consumer_replay_pending ||
			    client->consumer_replay_registration_pending.load() ||
			    (kind == DTRACED_KIND_CONSUMER &&
			    !client->consumer_program_valid) ||
			    client->kind != kind ||
			    !client->is_subscribed(DTD_SUB_ELFWRITE))
				continue;
			had_recipient = true;
			std::unique_ptr<durable_delivery> recorded;
			std::unique_ptr<durable_delivery> guest_recorded;
			if (host_intent) {
				int intent = record_host_outbound_intent(directory,
				    *client, host_program, host_source,
				    host_target_vmid, host_target_epoch, host_digest,
				    recorded);
				if (intent < 0)
					return (false);
				if (intent == 0)
					continue;
			} else if (guest_intent &&
			    record_guest_outbound_intent(directory, *client,
			    host_program, host_source, guest_vmid, guest_epoch,
			    host_digest, guest_recorded) < 0)
				return (false);
			if (ingress != nullptr) {
				auto matched = std::find_if(cohort.begin(), cohort.end(),
				    [client](const auto &receipt) {
				    return (receipt.consumer_session == client->session_id &&
				    receipt.consumer_uid == (uint32_t)client->peer_uid &&
				    receipt.consumer_pid == (uint32_t)client->peer_pid);
				    });
				if (matched == cohort.end())
					continue;
				int phase = directory.record_consumer_receipt(*matched,
				    consumer_receipt_phase::pending);
				if (phase < 0)
					return (false);
				if (phase == (int)consumer_receipt_phase::pending &&
				    client->consumer_program_valid &&
				    directory.record_consumer_program(*matched,
				    *client) != 1)
					return (false);
				if (consumer_receipt_complete(
				    (consumer_receipt_phase)phase))
					continue;
			}
			auto pending = std::make_unique<job>(NOTIFY_ELFWRITE,
			    client);
			notify_elfwrite_job &ne = pending->notify_elfwrite_get();
			ne.path = strdup(file->d_name);
			if (ne.path == nullptr)
				return (false);
			ne.pathlen = strlen(file->d_name);
			ne.dir = &directory;
			ne.nosha = nosha;
			ne.recorded = recorded.release();
			if (guest_recorded) {
				/* send_elf() sends a recorded guest token as an exact
				 * replay in this VM lifetime. */
				ne.replay = guest_recorded.release();
				ne.replay_vmid = guest_vmid;
				ne.replay_epoch = guest_epoch;
			}
			if (ingress != nullptr) {
				pending->handoff_vmid = ingress->vmid;
				pending->handoff_epoch = ingress->epoch;
			}
			owned.push_back(std::move(pending));
			staged.push_back(owned.back().get());
		}
		/* A file with no current recipient must remain unmemorized so a
		 * later subscriber can trigger another scan and receive it. The
		 * durable ingress journal still decides whether a guest upload is
		 * authorized; a spool file alone never authorizes replay. */
		if (owned.empty())
			return ((!had_recipient && cohort_present == 0) ||
			    directory.memorize_file(file));
		if (!directory.memorize_file(file))
			return (false);
		{
			std::lock_guard lk(s.joblistmtx);
			s.joblist.splice(s.joblist.end(), staged);
		}
		for (auto &pending : owned)
			(void)pending.release();
		for (client_fd *client : s.sockfds) {
			if (client->kind != kind ||
			    !client->is_subscribed(DTD_SUB_ELFWRITE))
				continue;
			if (!client->re_enable_write())
				ERR("re_enable_write() failed with: %m");
		}
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

bool
process_inbound(dir &dir, struct dirent *f)
{
	dtraced::state *s;
	std::string d_name_s, fullpath;
	bool installed = false;
	guest_delivery delivery{};
	bool delivery_known = false;
	durable_delivery_state accepted_ingress{};
	bool identified_ingress = false;
	pid_t registered_pid = -1;
	std::unique_lock<std::mutex> ingress_revocations;
	s = dir.state;

	if (s == NULL) {
		ERR("state is NULL");
		return (false);
	}

	if (f == NULL) {
		ERR("dirent is NULL");
		return (false);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (true);

	if (f->d_name[0] == '.')
		return (true);

	d_name_s = std::string(f->d_name);
	if (dir.memorized(d_name_s))
		return (true);
	fullpath = dir.full_path();
	fullpath += d_name_s;
	DEBUG("processing %s", fullpath.c_str());
	if (!s->is_control_machine())
		delivery_known = find_guest_delivery(*s, fullpath, delivery);
	std::array<uint8_t, 16> canonical_program{}, canonical_source{};
	if (!s->is_control_machine() && !delivery_known &&
	    spool_identity_from_path(d_name_s, canonical_program,
	    canonical_source)) {
		/* A stored ELF is not restart authorization. */
		return (dir.memorize_file(f));
	}
	if (s->is_control_machine() &&
	    spool_identity_from_path(d_name_s, canonical_program,
	    canonical_source)) {
		/* Identified guest uploads need an accepted journal transaction;
		 * an orphan spool cannot authorize a host DTrace consumer. Keep
		 * the KILL cut through queue publication. */
		ingress_revocations = std::unique_lock(s->revocationmtx);
		durable_delivery_state accepted{};
		int phase = dir.host_ingress_phase(canonical_program.data(),
		    canonical_source.data(), &accepted);
		if (phase < 0)
			return (false);
		if (phase == (int)delivery_phase::pending)
			return (true); /* The host has not committed acceptance. */
		/* A handoff-bound HTD5 is never a local upload. Even if an
		 * interrupted or corrupt transition names it accepted, the watcher
		 * must wait for an explicit destination execution lease. */
		if (phase == (int)delivery_phase::accepted &&
		    accepted.record.journal_version == 5)
			/* HT-C BEGIN: disabled trace continuity. */
			return (true);
			/* HT-C END */
		if (phase == 0 || s->outbounddir == nullptr) {
			if (phase == 0)
				return (dir.memorize_file(f));
			errno = EINVAL;
			return (false);
		}
		int revoked = s->outbounddir->source_revoked_for_vm(
		    accepted.record.source_id.data(), accepted.record.vmid,
		    accepted.record.epoch);
		if (revoked < 0)
			return (false);
		if (revoked > 0)
			return (dir.memorize_file(f));
		accepted_ingress = accepted;
		identified_ingress = true;
	}
	if (delivery_known && delivery.replay_granted) {
		uint8_t current_digest[32];
		if (!dir.hash_identified_data(delivery.program_id.data(),
		    delivery.source_id.data(), current_digest) ||
		    memcmp(current_digest, delivery.replay_digest.data(),
		    sizeof(current_digest)) != 0) {
			errno = EPROTO;
			return (false);
		}
	}

	if (s->is_control_machine()) {
		/*
		 * If we have a host configuration of dtraced
		 * we simply send off the ELF file to dtrace(1).
		 *
		 * We iterate over all our known dtrace(1)s that have
		 * registered with dtraced and send off the file path
		 * to them. They will parse said file path (we assume
		 * they won't be writing over it since this requires root
		 * anyway) and decide if the file is meant for them to
		 * process. There may be more dtrace(1) instances that
		 * want to process the same file in the future.
		 */
		return (queue_elfwrite_batch(*s, dir, f,
		    DTRACED_KIND_CONSUMER, 1,
		    identified_ingress ? &accepted_ingress.record : nullptr));
	} else if (!launch_program(*s, fullpath, false,
	    "/usr/sbin/dtrace", &installed, &registered_pid,
	    delivery_known && delivery.replay_granted)) {
		if (errno == EAGAIN && delivery_known &&
		    delivery.replay_granted)
			return (dir.request_reprocess(delivery.program_id.data(),
			    delivery.source_id.data(),
			    delivery.replay_digest.data()));
		if (errno == ECANCELED) {
			if (delivery_known)
				retire_guest_delivery(*s, delivery);
			return (dir.memorize_file(f));
		}
		ERR("cannot launch guest program: %m");
		return (false);
	}
	if (delivery_known && !installed &&
	    !finish_guest_delivery(*s, delivery)) {
		ERR("cannot report guest delivery without installation: %m");
		return (false);
	}
	if (installed) {
		if (!delivery_known)
			WARN("installed guest ELF has no current delivery context: %s",
			    fullpath.c_str());
		else {
			std::lock_guard events(s->install_event_mtx);
			bool active = false, tracked = false;
			{
				std::lock_guard children(s->pidlistmtx);
				if (registered_pid > 1 &&
				    s->pidlist.count(registered_pid) != 0 &&
				    s->revoked_sources.count(delivery.source_id) == 0) {
					active = true;
					try {
						tracked = s->pid_deliveries.emplace(
						    registered_pid, delivery).second;
						if (!tracked)
							errno = EEXIST;
					} catch (const std::bad_alloc &) {
						errno = ENOMEM;
					}
				}
			}
			if (active && !tracked) {
				ERR("cannot track installed guest tracing child: %m");
				return (false);
			}
			if (!active && !finish_guest_delivery(*s, delivery)) {
				ERR("cannot retire guest delivery after child exit: %m");
				return (false);
			}
			if (tracked &&
			    (!s->inbounddir->record_delivery(
			    guest_delivery_record(delivery), delivery_phase::accepted) ||
			    !send_install_observation(s->dtt_fd, delivery))) {
				std::lock_guard children(s->pidlistmtx);
				s->pid_deliveries.erase(registered_pid);
				ERR("cannot forward guest installation observation: %m");
				return (false);
			}
		}
	}

	return (dir.memorize_file(f));
}


bool
process_base(dir &dir, struct dirent *f)
{
	state *s;
	std::string d_name_s, fullpath;

	{
		std::lock_guard lk(dir.dirmtx);
		s = dir.state;

		if (s == NULL) {
			ERR("state is NULL in base directory monitoring thread");
			return (false);
		}

		if (f == NULL) {
			ERR("dirent is NULL in base directory monitoring thread");
			return (false);
		}

		if (strcmp(f->d_name, SOCKFD_NAME) == 0)
			return (true);

		if (f->d_name[0] == '.')
			return (true);


		/*
		 * Exit early if the file doesn't exist. There is definitely
		 * multiple race conditions here, but it doesn't really matter
		 * as we don't expect this to ever happen if communication
		 * happens through dtraced itself.
		 */
		d_name_s = std::string(f->d_name);
		if (!dir.file_exists(f->d_name)) {
			ERR("%s%s does not exist", dir.full_path().c_str(),
			    f->d_name);
			(void)dir.rmpath(d_name_s);
			return (false);
		}

		if (dir.memorized(d_name_s))
			return (true);

		DEBUG("processing %s", f->d_name);
		fullpath = dir.full_path();
	}

	fullpath += d_name_s;

	/* Guests receive the base program only with its source lineage: a
	 * sourceless outbound spool cannot be delivered or revoked, and a
	 * host forwarder refuses it. The host link still runs. */
	std::array<uint8_t, 16> base_program{}, base_source{};
	if (!spool_identity_from_path(d_name_s, base_program, base_source))
		ERR("base program %s has no source; not published to guests",
		    f->d_name);
	else if (!s->outbounddir->copy_data(dir.dirfd, f->d_name)) {
		ERR("cannot publish base program %s: %m", f->d_name);
		return (false);
	}

	if (!launch_program(*s, fullpath, true)) {
		ERR("cannot launch host program: %m");
		return (false);
	}

	return (dir.memorize_file(f));
}

bool
process_outbound(dir &dir, struct dirent *f)
{
	state *s;
	std::string d_name_s;

	s = dir.state;
	if (s == NULL) {
		ERR("state is NULL");
		return (false);
	}

	if (f == NULL) {
		ERR("dirent is NULL");
		return (false);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (true);

	if (f->d_name[0] == '.')
		return (true);

	{
		/*
		 * Exit early if the file doesn't exist. There is definitely
		 * multiple race conditions here, but it doesn't really matter
		 * as we don't expect this to ever happen if communication
		 * happens through dtraced itself.
		 */
		d_name_s = std::string(f->d_name);
		std::lock_guard lk(dir.dirmtx);
		if (!dir.file_exists(f->d_name)) {
			ERR("%s%s does not exist", dir.full_path().c_str(),
			    f->d_name);
			dir.rmpath(d_name_s);
			return (false);
		}

		if (dir.memorized(d_name_s))
			return (true);
	}

	return (queue_elfwrite_batch(*s, dir, f,
	    DTRACED_KIND_FORWARDER, s->nosha));
}

}
