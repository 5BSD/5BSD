/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include <sha256.h>
#include <stdlib.h>
#include <unistd.h>
#include "checkpoint_manifest.h"
#include "hypertrace_session.h"
#define HYPERTRACE_TRANSFER_MIN_BYTES 64U
#define HYPERTRACE_TRANSFER_MAX_BYTES (63U * 1024U * 1024U)
struct restore_state {
	unsigned checkpoint_format_version;
	void *hypertrace_transfer;
	size_t hypertrace_transfer_length;
	bool hypertrace_session_present;
	uint8_t hypertrace_session[HYPERTRACE_SESSION_RECORD_SIZE];
};
static int continuity_calls;
static int hypertrace_transfer_inspect(const void *bytes, size_t length,
    const uint8_t token[16], bool *present)
{
	(void)bytes; (void)length; (void)token; (void)present;
	continuity_calls++;
	errno = EPROTO;
	return (-1);
}
#include "fresh-session-load.inc"
int main(void)
{
	char path[] = "/tmp/fresh-session-load.XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0 && unlink(path) == 0);
	uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE], token[16] = {1};
	char digest[SHA256_DIGEST_STRING_LENGTH];
	struct hypertrace_session_record record = {
	    .vmid = 7, .epoch = 41, .stop_token = 99,
	    .features = HYPERTRACE_SESSION_FEATURES };
	assert(hypertrace_session_record_encode(wire, sizeof(wire), &record) == 0);
	for (int scenario = 0; scenario < 5; scenario++) {
		struct restore_state state = {.checkpoint_format_version = 5};
		size_t size = scenario == 1 ? sizeof(wire) - 1 : sizeof(wire);
		assert(ftruncate(fd, 0) == 0 && pwrite(fd, wire, size, 0) == (ssize_t)size);
		assert(SHA256_Data(wire, size, digest) != NULL);
		if (scenario == 2) digest[0] = digest[0] == 'a' ? 'b' : 'a';
		if (scenario == 3) {
			wire[10] = 1; /* Correct checksum, noncanonical reserved byte. */
			assert(pwrite(fd, wire, size, 0) == (ssize_t)size);
			assert(SHA256_Data(wire, size, digest) != NULL);
		}
		if (scenario == 4) state.checkpoint_format_version = 4;
		int result = load_hypertrace_transfer_fd(fd, token, digest, &state);
		assert((result == 0) == (scenario == 0));
		assert(state.hypertrace_session_present == (scenario == 0));
		assert(state.hypertrace_transfer == NULL && state.hypertrace_transfer_length == 0);
		if (scenario == 0) assert(memcmp(state.hypertrace_session, wire, sizeof(wire)) == 0);
		if (scenario == 2) assert(result == EILSEQ);
		wire[10] = 0;
	}
	assert(continuity_calls == 0 && close(fd) == 0);
	return (0);
}
