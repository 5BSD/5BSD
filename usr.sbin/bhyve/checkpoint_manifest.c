/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <sha256.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "checkpoint_manifest.h"

/* Post-destroy HSA1 is deliberately outside the already-published manifest.
 * Its random handoff token names a separate durable member; restore must
 * verify both the manifest identity and a pinned-host signature before use. */
static int
checkpoint_release_name(const uint8_t token[16], char name[38])
{
	static const char hex[] = "0123456789abcdef";
	const uint8_t zero[16] = {};
	if (token == NULL || memcmp(token, zero, sizeof(zero)) == 0)
		return (EINVAL);
	memcpy(name, ".hsa.", 5);
	for (size_t i = 0; i < 16; i++) {
		name[5 + i * 2] = hex[token[i] >> 4];
		name[6 + i * 2] = hex[token[i] & 15];
	}
	name[37] = '\0';
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
checkpoint_release_read_at(int dirfd, const uint8_t token[16],
    uint8_t wire[CHECKPOINT_RELEASE_WIRE_SIZE])
{
	char name[38];
	int error = checkpoint_release_name(token, name);
	if (wire == NULL || error != 0)
		return (EINVAL);
	memset(wire, 0, CHECKPOINT_RELEASE_WIRE_SIZE);
	int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
	    O_CLOEXEC);
	if (fd < 0)
		return (errno != 0 ? errno : EIO);
	struct stat sb;
	error = fstat(fd, &sb) != 0 ? errno : 0;
	if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    sb.st_size != (off_t)CHECKPOINT_RELEASE_WIRE_SIZE))
		error = EPROTO;
	for (size_t offset = 0; error == 0 &&
	    offset < CHECKPOINT_RELEASE_WIRE_SIZE;) {
		ssize_t n = pread(fd, wire + offset,
		    CHECKPOINT_RELEASE_WIRE_SIZE - offset, (off_t)offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EPROTO;
		else
			offset += (size_t)n;
	}
	if (close(fd) != 0 && error == 0)
		error = errno != 0 ? errno : EIO;
	if (error != 0)
		memset(wire, 0, CHECKPOINT_RELEASE_WIRE_SIZE);
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
checkpoint_release_publish_at(int dirfd, const uint8_t token[16],
    const uint8_t wire[CHECKPOINT_RELEASE_WIRE_SIZE])
{
	char name[38], temporary[42];
	static const char hex[] = "0123456789abcdef";
	uint8_t nonce[16];
	int error = checkpoint_release_name(token, name);
	if (wire == NULL || error != 0)
		return (EINVAL);
	if (memcmp(wire, "HSA1", 4) != 0 || wire[4] != 1 ||
	    memcmp(wire + 80, token, 16) != 0)
		return (EPROTO);
	arc4random_buf(nonce, sizeof(nonce));
	memcpy(temporary, ".hsa-tmp.", 9);
	for (size_t i = 0; i < sizeof(nonce); i++) {
		temporary[9 + i * 2] = hex[nonce[i] >> 4];
		temporary[10 + i * 2] = hex[nonce[i] & 15];
	}
	temporary[41] = '\0';
	int fd = openat(dirfd, temporary, O_WRONLY | O_CREAT | O_EXCL |
	    O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return (errno != 0 ? errno : EIO);
	for (size_t offset = 0; error == 0 &&
	    offset < CHECKPOINT_RELEASE_WIRE_SIZE;) {
		ssize_t n = write(fd, wire + offset,
		    CHECKPOINT_RELEASE_WIRE_SIZE - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			error = n < 0 ? errno : EIO;
		else
			offset += (size_t)n;
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno != 0 ? errno : EIO;
	if (close(fd) != 0 && error == 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0 && linkat(dirfd, temporary, dirfd, name, 0) != 0) {
		error = errno != 0 ? errno : EIO;
		if (error == EEXIST) {
			uint8_t existing[CHECKPOINT_RELEASE_WIRE_SIZE];
			int read_error = checkpoint_release_read_at(dirfd, token,
			    existing);
			error = read_error != 0 ? read_error :
			    memcmp(existing, wire, sizeof(existing)) == 0 ? 0 : EPROTO;
		}
	}
	if (unlinkat(dirfd, temporary, 0) != 0 && error == 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0 && fsync(dirfd) != 0)
		error = errno != 0 ? errno : EIO;
	return (error);
}

int
checkpoint_release_remove_at(int dirfd, const uint8_t token[16])
{
	char name[38];
	int error = checkpoint_release_name(token, name);
	if (error != 0)
		return (error);
	if (unlinkat(dirfd, name, 0) != 0)
		return (errno == ENOENT ? 0 : errno != 0 ? errno : EIO);
	return (fsync(dirfd) == 0 ? 0 : errno != 0 ? errno : EIO);
}

#define CHECKPOINT_MANIFEST_CONTENTS_MAX (sizeof(CHECKPOINT_MANIFEST_MAGIC_V4) + \
    CHECKPOINT_ARCH_MAX + CHECKPOINT_MACHINE_MAX + \
    4 * (NAME_MAX + 8) + 4 * (CHECKPOINT_SHA256_HEX_LEN + 16) + 32)

const char *
checkpoint_host_architecture(void)
{

#if defined(__amd64__)
	return ("amd64");
#elif defined(__aarch64__)
	return ("arm64");
#elif defined(__riscv)
	return ("riscv64");
#else
	return ("unknown");
#endif
}

bool
checkpoint_manifest_compatible(const struct checkpoint_manifest *m)
{
	const char *host;

	if (m == NULL ||
	    memchr(m->architecture, '\0', sizeof(m->architecture)) == NULL ||
	    memchr(m->machine, '\0', sizeof(m->machine)) == NULL)
		return (false);
	host = checkpoint_host_architecture();
	return ((m->format_version == 3 || m->format_version == 4 ||
	    m->format_version == 5) &&
	    strcmp(host, "unknown") != 0 &&
	    strcmp(m->architecture, host) == 0 &&
	    strcmp(m->machine, CHECKPOINT_MACHINE_ABI) == 0);
}

static bool
checkpoint_digest_valid(const char *digest)
{

	if (digest == NULL ||
	    strnlen(digest, CHECKPOINT_SHA256_HEX_LEN + 1) !=
	    CHECKPOINT_SHA256_HEX_LEN)
		return (false);
	for (unsigned int i = 0; i < CHECKPOINT_SHA256_HEX_LEN; i++) {
		if (!((digest[i] >= '0' && digest[i] <= '9') ||
		    (digest[i] >= 'a' && digest[i] <= 'f')))
			return (false);
	}
	return (true);
}

bool
checkpoint_member_valid(const char *member)
{
	size_t len;

	if (member == NULL)
		return (false);
	len = strnlen(member, NAME_MAX + 1);
	return (len > 0 && len <= NAME_MAX && strcmp(member, ".") != 0 &&
	    strcmp(member, "..") != 0 && strchr(member, '/') == NULL);
}

static bool
checkpoint_generation_member_valid(const char *base, const char *role,
    const char *member, const char **generation)
{
	const char *cursor;
	size_t base_len, member_len, prefix_len, role_len;

	if (base == NULL || role == NULL || member == NULL)
		return (false);
	/*
	 * These values can originate in a checkpoint pathname or manifest.
	 * Establish all string bounds before doing prefix arithmetic or using a
	 * string routine which assumes a terminator.  In particular, do not let a
	 * malformed fixed-size caller object turn validation into an out-of-bounds
	 * strlen().
	 */
	base_len = strnlen(base, NAME_MAX + 1);
	role_len = strnlen(role, NAME_MAX + 1);
	member_len = strnlen(member, NAME_MAX + 1);
	if (base_len == 0 || base_len > NAME_MAX || role_len == 0 ||
	    role_len > NAME_MAX || member_len > NAME_MAX ||
	    base_len > SIZE_MAX - role_len - 2)
		return (false);
	prefix_len = base_len + 1 + role_len + 1;
	if (prefix_len > member_len ||
	    member_len != prefix_len + CHECKPOINT_GENERATION_HEX_LEN ||
	    strncmp(member, base, base_len) != 0 ||
	    member[base_len] != '.' ||
	    strncmp(member + base_len + 1, role, role_len) != 0 ||
	    member[base_len + 1 + role_len] != '.')
		return (false);
	cursor = member + prefix_len;
	for (unsigned int i = 0; i < CHECKPOINT_GENERATION_HEX_LEN; i++) {
		if (!((cursor[i] >= '0' && cursor[i] <= '9') ||
		    (cursor[i] >= 'a' && cursor[i] <= 'f') ||
		    (cursor[i] >= 'A' && cursor[i] <= 'F')))
			return (false);
	}
	if (generation != NULL)
		*generation = cursor;
	return (true);
}

bool
checkpoint_manifest_valid_for(const char *base,
    const struct checkpoint_manifest *m)
{
	const char *data_generation, *kern_generation, *meta_generation;
	const char *trace_generation;

	if (base == NULL || m == NULL ||
	    (m->format_version != 3 && m->format_version != 4 &&
	    m->format_version != 5) ||
	    memchr(m->data, '\0', sizeof(m->data)) == NULL ||
	    memchr(m->kern, '\0', sizeof(m->kern)) == NULL ||
	    memchr(m->meta, '\0', sizeof(m->meta)) == NULL)
		return (false);
	if (!checkpoint_generation_member_valid(base, "data", m->data,
	    &data_generation) ||
	    !checkpoint_generation_member_valid(base, "kern", m->kern,
	    &kern_generation) ||
	    !checkpoint_generation_member_valid(base, "meta", m->meta,
	    &meta_generation))
		return (false);
	if (strncmp(data_generation, kern_generation,
	    CHECKPOINT_GENERATION_HEX_LEN) != 0 ||
	    strncmp(data_generation, meta_generation,
	    CHECKPOINT_GENERATION_HEX_LEN) != 0)
		return (false);
	if (m->format_version == 3)
		return (m->trace[0] == '\0' && m->trace_sha256[0] == '\0');
	return (memchr(m->trace, '\0', sizeof(m->trace)) != NULL &&
	    checkpoint_generation_member_valid(base, "trace", m->trace,
	    &trace_generation) &&
	    strncmp(data_generation, trace_generation,
	    CHECKPOINT_GENERATION_HEX_LEN) == 0);
}

static int
checkpoint_manifest_serialize(const struct checkpoint_manifest *m,
    char contents[CHECKPOINT_MANIFEST_CONTENTS_MAX], size_t *length)
{
	int written;

	if (m->format_version == 4 || m->format_version == 5)
		written = snprintf(contents, CHECKPOINT_MANIFEST_CONTENTS_MAX,
		    "%s"
		    "architecture=%s\nmachine=%s\n"
		    "data=%s\nkern=%s\nmeta=%s\ntrace=%s\n"
		    "data_sha256=%s\nkern_sha256=%s\n"
		    "meta_sha256=%s\ntrace_sha256=%s\n",
		    m->format_version == 5 ? CHECKPOINT_MANIFEST_MAGIC_V5 :
		    CHECKPOINT_MANIFEST_MAGIC_V4,
		    m->architecture, m->machine, m->data, m->kern, m->meta,
		    m->trace, m->data_sha256, m->kern_sha256,
		    m->meta_sha256, m->trace_sha256);
	else
		written = snprintf(contents, CHECKPOINT_MANIFEST_CONTENTS_MAX,
		    CHECKPOINT_MANIFEST_MAGIC "architecture=%s\nmachine=%s\n"
		    "data=%s\nkern=%s\nmeta=%s\n"
		    "data_sha256=%s\nkern_sha256=%s\nmeta_sha256=%s\n",
		    m->architecture, m->machine, m->data, m->kern, m->meta,
		    m->data_sha256, m->kern_sha256, m->meta_sha256);
	if (written < 0)
		return (EIO);
	if ((size_t)written >= CHECKPOINT_MANIFEST_CONTENTS_MAX)
		return (EOVERFLOW);
	*length = (size_t)written;
	return (0);
}

static uint8_t
checkpoint_hex_nibble(char digit)
{
	if (digit >= '0' && digit <= '9')
		return ((uint8_t)(digit - '0'));
	if (digit >= 'a' && digit <= 'f')
		return ((uint8_t)(digit - 'a' + 10));
	return ((uint8_t)(digit - 'A' + 10));
}

int
checkpoint_manifest_handoff_token(const char *base,
    const struct checkpoint_manifest *m, uint8_t token[16])
{
	const char *generation;
	uint8_t parsed_token[16] = {};

	if (token == NULL ||
	    !checkpoint_manifest_compatible(m) ||
	    !checkpoint_manifest_valid_for(base, m) ||
	    !checkpoint_generation_member_valid(base, "data", m->data,
	    &generation))
		return (EINVAL);
	for (size_t i = 0; i < sizeof(parsed_token); i++)
		parsed_token[i] = (checkpoint_hex_nibble(generation[i * 2]) << 4) |
		    checkpoint_hex_nibble(generation[i * 2 + 1]);
	if (memcmp(parsed_token, (const uint8_t[16]){0}, 16) == 0)
		return (EINVAL);
	memcpy(token, parsed_token, sizeof(parsed_token));
	return (0);
}

int
checkpoint_manifest_handoff_identity(const char *base,
    const struct checkpoint_manifest *m, uint8_t token[16],
    uint8_t digest[32])
{
	char contents[CHECKPOINT_MANIFEST_CONTENTS_MAX];
	uint8_t parsed_token[16], parsed_digest[32];
	SHA256_CTX hash;
	size_t length;
	int error;

	if (token == NULL || digest == NULL || m == NULL ||
	    !checkpoint_digest_valid(m->data_sha256) ||
	    !checkpoint_digest_valid(m->kern_sha256) ||
	    !checkpoint_digest_valid(m->meta_sha256) ||
	    ((m->format_version == 4 || m->format_version == 5) &&
	    !checkpoint_digest_valid(m->trace_sha256)))
		return (EINVAL);
	error = checkpoint_manifest_handoff_token(base, m, parsed_token);
	if (error != 0)
		return (error);
	error = checkpoint_manifest_serialize(m, contents, &length);
	if (error != 0)
		return (error);
	SHA256_Init(&hash);
	SHA256_Update(&hash, contents, length);
	SHA256_Final(parsed_digest, &hash);
	if (memcmp(parsed_digest, (const uint8_t[32]){0}, 32) == 0)
		return (EIO);
	memcpy(token, parsed_token, sizeof(parsed_token));
	memcpy(digest, parsed_digest, sizeof(parsed_digest));
	return (0);
}

static int checkpoint_validate_fd(int fd);

static int
checkpoint_manifest_read_fd(int fd, struct checkpoint_manifest *m,
    bool *is_manifest)
{
	char buffer[sizeof(CHECKPOINT_MANIFEST_MAGIC_V4) +
	    CHECKPOINT_ARCH_MAX + CHECKPOINT_MACHINE_MAX +
	    4 * (NAME_MAX + 8) +
	    4 * (CHECKPOINT_SHA256_HEX_LEN + 16) + 32];
	struct checkpoint_manifest candidate;
	char *cursor, *end, *line;
	size_t used;
	ssize_t nread;
	int error, fields, version;

	*is_manifest = false;
	error = checkpoint_validate_fd(fd);
	if (error != 0)
		return (error);
	used = 0;
	error = 0;
	while (used < sizeof(buffer)) {
		do {
			nread = read(fd, buffer + used, sizeof(buffer) - used);
		} while (nread < 0 && errno == EINTR);
		if (nread < 0) {
			error = errno != 0 ? errno : EIO;
			break;
		}
		if (nread == 0)
			break;
		used += (size_t)nread;
	}
	if (error != 0)
		return (error);
	if (used >= strlen(CHECKPOINT_MANIFEST_MAGIC_V5) &&
	    memcmp(buffer, CHECKPOINT_MANIFEST_MAGIC_V5,
	    strlen(CHECKPOINT_MANIFEST_MAGIC_V5)) == 0) {
		version = 5;
		fields = 10;
		cursor = buffer + strlen(CHECKPOINT_MANIFEST_MAGIC_V5);
	} else if (used >= strlen(CHECKPOINT_MANIFEST_MAGIC_V4) &&
	    memcmp(buffer, CHECKPOINT_MANIFEST_MAGIC_V4,
	    strlen(CHECKPOINT_MANIFEST_MAGIC_V4)) == 0) {
		version = 4;
		fields = 10;
		cursor = buffer + strlen(CHECKPOINT_MANIFEST_MAGIC_V4);
	} else if (used >= strlen(CHECKPOINT_MANIFEST_MAGIC) &&
	    memcmp(buffer, CHECKPOINT_MANIFEST_MAGIC,
	    strlen(CHECKPOINT_MANIFEST_MAGIC)) == 0) {
		version = 3;
		fields = 8;
		cursor = buffer + strlen(CHECKPOINT_MANIFEST_MAGIC);
	} else {
		/* Only the exact current, unreleased manifest format is accepted. */
		return (EINVAL);
	}
	if (used == sizeof(buffer))
		return (EINVAL);

	buffer[used] = '\0';
	memset(&candidate, 0, sizeof(candidate));
	candidate.format_version = version;
	end = buffer + used;
	for (int field = 0; field < fields; field++) {
		const char *prefix;
		char *destination;
		size_t destination_size, prefix_len, value_len;
		int logical_field;

		line = strchr(cursor, '\n');
		if (line == NULL || line > end)
			return (EINVAL);
		*line = '\0';
		logical_field = version == 3 && field >= 5 ? field + 1 : field;
		if (logical_field == 0) {
			prefix = "architecture=";
			destination = candidate.architecture;
			destination_size = sizeof(candidate.architecture);
		} else if (logical_field == 1) {
			prefix = "machine=";
			destination = candidate.machine;
			destination_size = sizeof(candidate.machine);
		} else if (logical_field == 2) {
			prefix = "data=";
			destination = candidate.data;
			destination_size = sizeof(candidate.data);
		} else if (logical_field == 3) {
			prefix = "kern=";
			destination = candidate.kern;
			destination_size = sizeof(candidate.kern);
		} else if (logical_field == 4) {
			prefix = "meta=";
			destination = candidate.meta;
			destination_size = sizeof(candidate.meta);
		} else if (logical_field == 5) {
			prefix = "trace=";
			destination = candidate.trace;
			destination_size = sizeof(candidate.trace);
		} else if (logical_field == 6) {
			prefix = "data_sha256=";
			destination = candidate.data_sha256;
			destination_size = sizeof(candidate.data_sha256);
		} else if (logical_field == 7) {
			prefix = "kern_sha256=";
			destination = candidate.kern_sha256;
			destination_size = sizeof(candidate.kern_sha256);
		} else if (logical_field == 8) {
			prefix = "meta_sha256=";
			destination = candidate.meta_sha256;
			destination_size = sizeof(candidate.meta_sha256);
		} else {
			prefix = "trace_sha256=";
			destination = candidate.trace_sha256;
			destination_size = sizeof(candidate.trace_sha256);
		}
		prefix_len = strlen(prefix);
		if (strncmp(cursor, prefix, prefix_len) != 0)
			return (EINVAL);
		value_len = strlen(cursor + prefix_len);
		if (value_len == 0 || value_len >= destination_size)
			return (EINVAL);
		memcpy(destination, cursor + prefix_len, value_len + 1);
		if (logical_field >= 2 && logical_field <= 5 &&
		    !checkpoint_member_valid(destination))
			return (EINVAL);
		if (logical_field >= 6 &&
		    !checkpoint_digest_valid(destination))
			return (EINVAL);
		cursor = line + 1;
	}
	if (cursor != end)
		return (EINVAL);
	*m = candidate;
	*is_manifest = true;
	return (0);
}

int
checkpoint_manifest_read(const char *filename, struct checkpoint_manifest *m,
    bool *is_manifest)
{
	struct checkpoint_manifest candidate;
	bool candidate_is_manifest;
	int fd, error;

	if (filename == NULL || m == NULL || is_manifest == NULL)
		return (EINVAL);
	/* All failures leave the caller with no accepted manifest result. */
	*is_manifest = false;
	/*
	 * A manifest names members relative to its own directory.  Following a
	 * final-component symlink here would let the manifest contents come from
	 * one directory while restore resolves its members in another.  Generated
	 * checkpoints are regular files, so reject that ambiguous topology.
	 */
	fd = open(filename,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return (errno != 0 ? errno : EIO);
	error = checkpoint_manifest_read_fd(fd, &candidate,
	    &candidate_is_manifest);
	if (close(fd) != 0 && error == 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0) {
		if (candidate_is_manifest)
			*m = candidate;
		*is_manifest = candidate_is_manifest;
	}
	return (error);
}

int
checkpoint_manifest_read_at(int dirfd, const char *filename,
    struct checkpoint_manifest *m, bool *exists, bool *is_manifest)
{
	struct checkpoint_manifest candidate;
	bool candidate_is_manifest;
	int fd, error;

	if (dirfd < 0 || filename == NULL || m == NULL || exists == NULL ||
	    is_manifest == NULL)
		return (EINVAL);
	*exists = false;
	*is_manifest = false;
	fd = openat(dirfd, filename,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return (errno == ENOENT ? 0 : errno != 0 ? errno : EIO);
	*exists = true;
	error = checkpoint_manifest_read_fd(fd, &candidate,
	    &candidate_is_manifest);
	if (close(fd) != 0 && error == 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0) {
		if (candidate_is_manifest)
			*m = candidate;
		*is_manifest = candidate_is_manifest;
	}
	return (error);
}

int
checkpoint_generation_names(const char *base, struct checkpoint_manifest *m,
    char **manifest_tmp)
{
	struct checkpoint_manifest candidate;
	uint32_t random_words[4];
	char generation[CHECKPOINT_GENERATION_HEX_LEN + 1];
	char *temporary;
	int length;

	if (base == NULL || m == NULL || manifest_tmp == NULL)
		return (EINVAL);
	*manifest_tmp = NULL;
	if (!checkpoint_member_valid(base))
		return (EINVAL);
	if (strcmp(checkpoint_host_architecture(), "unknown") == 0)
		return (ENOTSUP);
	memset(&candidate, 0, sizeof(candidate));
	candidate.format_version = 3;
	if (strlcpy(candidate.architecture, checkpoint_host_architecture(),
	    sizeof(candidate.architecture)) >= sizeof(candidate.architecture) ||
	    strlcpy(candidate.machine, CHECKPOINT_MACHINE_ABI,
	    sizeof(candidate.machine)) >= sizeof(candidate.machine))
		return (EOVERFLOW);
	arc4random_buf(random_words, sizeof(random_words));
	length = snprintf(generation, sizeof(generation), "%08x%08x%08x%08x",
	    random_words[0], random_words[1], random_words[2], random_words[3]);
	if (length != CHECKPOINT_GENERATION_HEX_LEN)
		return (EIO);
	length = snprintf(candidate.data, sizeof(candidate.data), "%s.data.%s", base,
	    generation);
	if (length < 0 || (size_t)length >= sizeof(candidate.data))
		goto name_too_long;
	length = snprintf(candidate.kern, sizeof(candidate.kern), "%s.kern.%s", base,
	    generation);
	if (length < 0 || (size_t)length >= sizeof(candidate.kern))
		goto name_too_long;
	length = snprintf(candidate.meta, sizeof(candidate.meta), "%s.meta.%s", base,
	    generation);
	if (length < 0 || (size_t)length >= sizeof(candidate.meta))
		goto name_too_long;
	temporary = NULL;
	if (asprintf(&temporary, "%s.manifest.%s.tmp", base, generation) < 0)
		return (ENOMEM);
	if (strlen(temporary) > NAME_MAX) {
		free(temporary);
		goto name_too_long;
	}
	*m = candidate;
	*manifest_tmp = temporary;
	return (0);

name_too_long:
	return (ENAMETOOLONG);
}

int
checkpoint_generation_names_trace(const char *base,
    struct checkpoint_manifest *m, char **manifest_tmp)
{
	struct checkpoint_manifest candidate;
	const char *generation;
	char *temporary = NULL;
	int error, length;

	if (m == NULL || manifest_tmp == NULL)
		return (EINVAL);
	*manifest_tmp = NULL;
	error = checkpoint_generation_names(base, &candidate, &temporary);
	if (error != 0)
		return (error);
	if (!checkpoint_generation_member_valid(base, "data",
	    candidate.data, &generation)) {
		error = EINVAL;
		goto fail;
	}
	length = snprintf(candidate.trace, sizeof(candidate.trace),
	    "%s.trace.%.*s", base, CHECKPOINT_GENERATION_HEX_LEN,
	    generation);
	if (length < 0 || (size_t)length >= sizeof(candidate.trace)) {
		error = ENAMETOOLONG;
		goto fail;
	}
	candidate.format_version = 4;
	*m = candidate;
	*manifest_tmp = temporary;
	return (0);
fail:
	free(temporary);
	return (error);
}

static int
checkpoint_write_all(int fd, const void *buffer, size_t length)
{
	const uint8_t *cursor;
	ssize_t written;

	cursor = buffer;
	while (length != 0) {
		written = write(fd, cursor, length);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return (errno != 0 ? errno : EIO);
		}
		if (written == 0)
			return (EIO);
		cursor += written;
		length -= (size_t)written;
	}
	return (0);
}

int
checkpoint_generation_names_fresh(const char *base,
    struct checkpoint_manifest *m, char **manifest_tmp)
{
	int error = checkpoint_generation_names_trace(base, m, manifest_tmp);
	if (error == 0)
		m->format_version = 5;
	return (error);
}

static bool
checkpoint_manifest_tmp_valid_for(const char *base, const char *manifest_tmp,
    const struct checkpoint_manifest *m)
{
	const char *generation;
	char expected[NAME_MAX + 1];
	int length;

	if (!checkpoint_member_valid(manifest_tmp) ||
	    !checkpoint_generation_member_valid(base, "data", m->data,
	    &generation))
		return (false);
	length = snprintf(expected, sizeof(expected), "%s.manifest.%.*s.tmp",
	    base, CHECKPOINT_GENERATION_HEX_LEN, generation);
	return (length >= 0 && (size_t)length < sizeof(expected) &&
	    strcmp(expected, manifest_tmp) == 0);
}

static int
checkpoint_validate_fd(int fd)
{
	struct stat sb;

	if (fstat(fd, &sb) != 0)
		return (errno != 0 ? errno : EIO);
	if (!S_ISREG(sb.st_mode))
		return (EINVAL);
	return (0);
}

/*
 * A generation has three different serialization domains: guest memory,
 * kernel/device state, and metadata.  Distinct member names alone are not
 * sufficient to establish that property since an imported or malformed
 * checkpoint directory can make two names hard links to one regular file.
 * Reject that topology before the current manifest's digest checks can
 * consume an alias as two state domains.  No older manifest loader exists.
 */
static int
checkpoint_validate_distinct_fds(int data_fd, int kern_fd, int meta_fd)
{
	struct stat data_sb, kern_sb, meta_sb;
	int error;

	if (fstat(data_fd, &data_sb) != 0)
		return (errno != 0 ? errno : EIO);
	if (fstat(kern_fd, &kern_sb) != 0) {
		error = errno != 0 ? errno : EIO;
		return (error);
	}
	if (fstat(meta_fd, &meta_sb) != 0) {
		error = errno != 0 ? errno : EIO;
		return (error);
	}
	if (!S_ISREG(data_sb.st_mode) || !S_ISREG(kern_sb.st_mode) ||
	    !S_ISREG(meta_sb.st_mode))
		return (EINVAL);
	if ((data_sb.st_dev == kern_sb.st_dev && data_sb.st_ino == kern_sb.st_ino) ||
	    (data_sb.st_dev == meta_sb.st_dev && data_sb.st_ino == meta_sb.st_ino) ||
	    (kern_sb.st_dev == meta_sb.st_dev && kern_sb.st_ino == meta_sb.st_ino))
		return (EINVAL);
	return (0);
}

static bool
checkpoint_ranges_overlap(const void *first, size_t first_size,
    const void *second, size_t second_size)
{
	uintptr_t first_start, second_start;

	first_start = (uintptr_t)first;
	second_start = (uintptr_t)second;
	if (first_size > UINTPTR_MAX - first_start ||
	    second_size > UINTPTR_MAX - second_start)
		return (true);
	return (first_start < second_start + second_size &&
	    second_start < first_start + first_size);
}

static bool
checkpoint_output_fds_valid(const struct checkpoint_manifest *m,
    int *data_fd, int *kern_fd, int *meta_fd)
{

	if (data_fd == NULL || kern_fd == NULL || meta_fd == NULL ||
	    (uintptr_t)data_fd % _Alignof(int) != 0 ||
	    (uintptr_t)kern_fd % _Alignof(int) != 0 ||
	    (uintptr_t)meta_fd % _Alignof(int) != 0 ||
	    checkpoint_ranges_overlap(data_fd, sizeof(*data_fd), kern_fd,
	    sizeof(*kern_fd)) ||
	    checkpoint_ranges_overlap(data_fd, sizeof(*data_fd), meta_fd,
	    sizeof(*meta_fd)) ||
	    checkpoint_ranges_overlap(kern_fd, sizeof(*kern_fd), meta_fd,
	    sizeof(*meta_fd)))
		return (false);
	if (m != NULL &&
	    (checkpoint_ranges_overlap(data_fd, sizeof(*data_fd), m,
	    sizeof(*m)) ||
	    checkpoint_ranges_overlap(kern_fd, sizeof(*kern_fd), m,
	    sizeof(*m)) ||
	    checkpoint_ranges_overlap(meta_fd, sizeof(*meta_fd), m,
	    sizeof(*m))))
		return (false);
	return (true);
}

static int
checkpoint_hash_fd(int fd, char *digest)
{
	int error;
	char *result;

	error = checkpoint_validate_fd(fd);
	result = NULL;
	while (error == 0 && result == NULL) {
		if (lseek(fd, 0, SEEK_SET) < 0) {
			error = errno != 0 ? errno : EIO;
			break;
		}
		errno = 0;
		result = SHA256_Fd(fd, digest);
		if (result == NULL && errno != EINTR)
			error = errno != 0 ? errno : EIO;
	}
	if (error == 0 && lseek(fd, 0, SEEK_SET) < 0)
		error = errno != 0 ? errno : EIO;
	return (error);
}

static int
checkpoint_hash_member_at(int dirfd, const char *member, char *digest)
{
	int error, fd;

	fd = openat(dirfd, member,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return (errno != 0 ? errno : EIO);
	error = checkpoint_hash_fd(fd, digest);
	if (close(fd) != 0 && error == 0)
		error = errno != 0 ? errno : EIO;
	return (error);
}

static int
checkpoint_manifest_hash_at(int dirfd, struct checkpoint_manifest *m)
{
	int error;

	if (dirfd < 0 || m == NULL ||
	    (m->format_version != 3 && m->format_version != 4 &&
	    m->format_version != 5) ||
	    !checkpoint_member_valid(m->data) ||
	    !checkpoint_member_valid(m->kern) ||
	    !checkpoint_member_valid(m->meta) ||
	    ((m->format_version == 4 || m->format_version == 5) && !checkpoint_member_valid(m->trace)))
		return (EINVAL);
	error = checkpoint_hash_member_at(dirfd, m->data, m->data_sha256);
	if (error == 0)
		error = checkpoint_hash_member_at(dirfd, m->kern,
		    m->kern_sha256);
	if (error == 0)
		error = checkpoint_hash_member_at(dirfd, m->meta,
		    m->meta_sha256);
	if (error == 0 && (m->format_version == 4 || m->format_version == 5))
		error = checkpoint_hash_member_at(dirfd, m->trace,
		    m->trace_sha256);
	return (error);
}

int
checkpoint_manifest_open_verified_at(int dirfd,
    const struct checkpoint_manifest *m, int *data_fd, int *kern_fd,
    int *meta_fd)
{
	char actual[CHECKPOINT_SHA256_HEX_LEN + 1];
	int error;

	/* Reject aliasing before initializing outputs or inspecting the manifest. */
	if (!checkpoint_output_fds_valid(m, data_fd, kern_fd, meta_fd))
		return (EINVAL);
	*data_fd = -1;
	*kern_fd = -1;
	*meta_fd = -1;
	if (dirfd < 0 || m == NULL || m->format_version != 3 ||
	    !checkpoint_member_valid(m->data) ||
	    !checkpoint_member_valid(m->kern) ||
	    !checkpoint_member_valid(m->meta) ||
	    (!checkpoint_digest_valid(m->data_sha256) ||
	    !checkpoint_digest_valid(m->kern_sha256) ||
	    !checkpoint_digest_valid(m->meta_sha256)))
		return (EINVAL);
	*data_fd = openat(dirfd, m->data,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (*data_fd < 0)
		return (errno != 0 ? errno : EIO);
	*kern_fd = openat(dirfd, m->kern,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (*kern_fd < 0) {
		error = errno != 0 ? errno : EIO;
		goto fail;
	}
	*meta_fd = openat(dirfd, m->meta,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (*meta_fd < 0) {
		error = errno != 0 ? errno : EIO;
		goto fail;
	}
	error = checkpoint_validate_distinct_fds(*data_fd, *kern_fd, *meta_fd);
	if (error != 0)
		goto fail;
	error = checkpoint_hash_fd(*data_fd, actual);
	if (error == 0 && strcmp(actual, m->data_sha256) != 0)
		error = EILSEQ;
	if (error == 0)
		error = checkpoint_hash_fd(*kern_fd, actual);
	if (error == 0 && strcmp(actual, m->kern_sha256) != 0)
		error = EILSEQ;
	if (error == 0)
		error = checkpoint_hash_fd(*meta_fd, actual);
	if (error == 0 && strcmp(actual, m->meta_sha256) != 0)
		error = EILSEQ;
	if (error != 0)
		goto fail;
	return (0);

fail:
	if (*data_fd >= 0)
		close(*data_fd);
	if (*kern_fd >= 0)
		close(*kern_fd);
	if (*meta_fd >= 0)
		close(*meta_fd);
	*data_fd = -1;
	*kern_fd = -1;
	*meta_fd = -1;
	return (error);
}

int
checkpoint_manifest_open_verified_trace_at(int dirfd,
    const struct checkpoint_manifest *m, int *data_fd, int *kern_fd,
    int *meta_fd, int *trace_fd)
{
	struct checkpoint_manifest legacy;
	struct stat trace_stat, data_stat, kern_stat, meta_stat;
	char actual[CHECKPOINT_SHA256_HEX_LEN + 1];
	int error;

	if (trace_fd == NULL || (uintptr_t)trace_fd % _Alignof(int) != 0 ||
	    !checkpoint_output_fds_valid(m, data_fd, kern_fd, meta_fd) ||
	    checkpoint_ranges_overlap(trace_fd, sizeof(*trace_fd), data_fd,
	    sizeof(*data_fd)) ||
	    checkpoint_ranges_overlap(trace_fd, sizeof(*trace_fd), kern_fd,
	    sizeof(*kern_fd)) ||
	    checkpoint_ranges_overlap(trace_fd, sizeof(*trace_fd), meta_fd,
	    sizeof(*meta_fd)) ||
	    (m != NULL && checkpoint_ranges_overlap(trace_fd,
	    sizeof(*trace_fd), m, sizeof(*m))))
		return (EINVAL);
	*trace_fd = -1;
	*data_fd = *kern_fd = *meta_fd = -1;
	if (m == NULL || (m->format_version != 3 && m->format_version != 4 &&
	    m->format_version != 5))
		return (EINVAL);
	if (m->format_version == 3)
		return (checkpoint_manifest_open_verified_at(dirfd, m,
		    data_fd, kern_fd, meta_fd));
	if (!checkpoint_member_valid(m->trace) ||
	    !checkpoint_digest_valid(m->trace_sha256))
		return (EINVAL);
	legacy = *m;
	legacy.format_version = 3;
	legacy.trace[0] = '\0';
	legacy.trace_sha256[0] = '\0';
	error = checkpoint_manifest_open_verified_at(dirfd, &legacy,
	    data_fd, kern_fd, meta_fd);
	if (error != 0)
		return (error);
	*trace_fd = openat(dirfd, m->trace,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (*trace_fd < 0) {
		error = errno != 0 ? errno : EIO;
		goto fail;
	}
	if (fstat(*trace_fd, &trace_stat) != 0 ||
	    fstat(*data_fd, &data_stat) != 0 ||
	    fstat(*kern_fd, &kern_stat) != 0 ||
	    fstat(*meta_fd, &meta_stat) != 0) {
		error = errno != 0 ? errno : EIO;
		goto fail;
	}
	if (!S_ISREG(trace_stat.st_mode) || trace_stat.st_size <= 0 ||
	    (uintmax_t)trace_stat.st_size > 64U * 1024U * 1024U ||
	    (trace_stat.st_dev == data_stat.st_dev &&
	    trace_stat.st_ino == data_stat.st_ino) ||
	    (trace_stat.st_dev == kern_stat.st_dev &&
	    trace_stat.st_ino == kern_stat.st_ino) ||
	    (trace_stat.st_dev == meta_stat.st_dev &&
	    trace_stat.st_ino == meta_stat.st_ino)) {
		error = EINVAL;
		goto fail;
	}
	error = checkpoint_hash_fd(*trace_fd, actual);
	if (error == 0 && strcmp(actual, m->trace_sha256) != 0)
		error = EILSEQ;
	if (error == 0)
		return (0);
fail:
	if (*trace_fd >= 0)
		(void)close(*trace_fd);
	(void)close(*data_fd);
	(void)close(*kern_fd);
	(void)close(*meta_fd);
	*trace_fd = *data_fd = *kern_fd = *meta_fd = -1;
	return (error);
}

int
checkpoint_publish(int dirfd, const char *checkpoint_file,
    const char *manifest_tmp, struct checkpoint_manifest *m,
    bool *published)
{
	struct checkpoint_manifest candidate;
	char contents[CHECKPOINT_MANIFEST_CONTENTS_MAX];
	size_t length;
	int fd, error;

	if (published == NULL)
		return (EINVAL);
	*published = false;
	if (dirfd < 0 || !checkpoint_member_valid(checkpoint_file) ||
	    m == NULL ||
	    !checkpoint_manifest_compatible(m) ||
	    !checkpoint_manifest_valid_for(checkpoint_file, m) ||
	    !checkpoint_manifest_tmp_valid_for(checkpoint_file, manifest_tmp,
	    m))
		return (EINVAL);
	candidate = *m;
	error = checkpoint_manifest_hash_at(dirfd, &candidate);
	if (error != 0)
		return (error);
	error = checkpoint_manifest_serialize(&candidate, contents, &length);
	if (error != 0)
		return (error);

	fd = openat(dirfd, manifest_tmp,
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (fd < 0)
		return (errno != 0 ? errno : EIO);
	error = checkpoint_write_all(fd, contents, length);
	if (error == 0 && fsync(fd) != 0)
		error = errno != 0 ? errno : EIO;
	if (close(fd) != 0 && error == 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0 && renameat(dirfd, manifest_tmp, dirfd,
	    checkpoint_file) != 0) {
		error = errno != 0 ? errno : EIO;
	} else if (error == 0) {
		*m = candidate;
		*published = true;
	}
	if (error == 0 && fsync(dirfd) != 0)
		error = errno != 0 ? errno : EIO;
	if (error != 0)
		(void)unlinkat(dirfd, manifest_tmp, 0);
	return (error);
}
