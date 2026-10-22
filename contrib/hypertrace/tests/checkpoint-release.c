/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "checkpoint_manifest.c"

int
main(void)
{
	char path[] = "/tmp/hypertrace-checkpoint-release.XXXXXX";
	assert(mkdtemp(path) != NULL);
	int dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(dirfd >= 0);
	/* Fresh sessions have their own manifest identity. All four members
	 * remain digest-verified; the format must survive publication/readback. */
	for (unsigned version = 4; version <= 5; version++) {
		struct checkpoint_manifest m, parsed;
		char *temporary = NULL;
		bool published = false, exists = false, is_manifest = false;
		assert((version == 5 ?
		    checkpoint_generation_names_fresh("image", &m, &temporary) :
		    checkpoint_generation_names_trace("image", &m, &temporary)) == 0);
		assert(m.format_version == version && checkpoint_manifest_compatible(&m));
		const char *members[] = {m.data, m.kern, m.meta, m.trace};
		for (unsigned i = 0; i < 4; i++) {
			int member = openat(dirfd, members[i], O_WRONLY | O_CREAT | O_EXCL, 0600);
			assert(member >= 0 && write(member, "member", 6) == 6 && close(member) == 0);
		}
		assert(checkpoint_publish(dirfd, "image", temporary, &m, &published) == 0 && published);
		assert(checkpoint_manifest_read_at(dirfd, "image", &parsed, &exists, &is_manifest) == 0 && exists && is_manifest);
		assert(parsed.format_version == version && checkpoint_manifest_valid_for("image", &parsed));
		uint8_t token1[16], digest1[32], token2[16], digest2[32];
		assert(checkpoint_manifest_handoff_identity("image", &parsed, token1, digest1) == 0);
		parsed.format_version = version == 5 ? 4 : 5;
		assert(checkpoint_manifest_handoff_identity("image", &parsed, token2, digest2) == 0);
		assert(memcmp(token1, token2, 16) == 0 && memcmp(digest1, digest2, 32) != 0);
		parsed.format_version = version;
		int data, kern, meta, trace;
		assert(checkpoint_manifest_open_verified_trace_at(dirfd, &parsed, &data, &kern, &meta, &trace) == 0);
		assert(close(data) == 0 && close(kern) == 0 && close(meta) == 0 && close(trace) == 0);
		int member = openat(dirfd, m.trace, O_WRONLY);
		assert(member >= 0 && write(member, "X", 1) == 1 && close(member) == 0);
		assert(checkpoint_manifest_open_verified_trace_at(dirfd, &parsed, &data, &kern, &meta, &trace) == EILSEQ);
		assert(data == -1 && kern == -1 && meta == -1 && trace == -1);
		for (unsigned i = 0; i < 4; i++)
			assert(unlinkat(dirfd, members[i], 0) == 0);
		assert(unlinkat(dirfd, "image", 0) == 0);
		free(temporary);
	}
	uint8_t token[16] = { 0xa1 };
	uint8_t wire[CHECKPOINT_RELEASE_WIRE_SIZE] = { 0 };
	uint8_t actual[CHECKPOINT_RELEASE_WIRE_SIZE] = { 0 };
	memcpy(wire, "HSA1", 4);
	wire[4] = 1;
	memcpy(wire + 80, token, sizeof(token));
	assert(checkpoint_release_publish_at(dirfd, token, wire) == 0);
	assert(checkpoint_release_publish_at(dirfd, token, wire) == 0);
	assert(checkpoint_release_read_at(dirfd, token, actual) == 0);
	assert(memcmp(wire, actual, sizeof(wire)) == 0);
	wire[100] = 1;
	assert(checkpoint_release_publish_at(dirfd, token, wire) == EPROTO);
	wire[100] = 0;
	char name[38];
	assert(checkpoint_release_name(token, name) == 0);
	int fd = openat(dirfd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
	assert(fd >= 0);
	assert(ftruncate(fd, 1) == 0 && close(fd) == 0);
	assert(checkpoint_release_read_at(dirfd, token, actual) == EPROTO);
	for (size_t i = 0; i < sizeof(actual); i++)
		assert(actual[i] == 0);
	assert(checkpoint_release_remove_at(dirfd, token) == 0);
	assert(checkpoint_release_read_at(dirfd, token, actual) == ENOENT);
	assert(checkpoint_release_remove_at(dirfd, token) == 0);
	assert(close(dirfd) == 0 && rmdir(path) == 0);
	return (0);
}
