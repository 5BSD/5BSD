/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <crypto/cryptodev.h>

#include <cryptocmp.h>

#include "fake_service.h"

static struct cryptocmp_generate
generate_request(void)
{
	struct cryptocmp_generate request;

	memset(&request, 0, sizeof(request));
	request.mac = 1;
	request.mackeylen = 32;
	request.rights = 1;
	return (request);
}

ATF_TC_WITHOUT_HEAD(successful_operation_matrix);
ATF_TC_BODY(successful_operation_matrix, tc)
{
	struct cryptocmp_key_generate key_request;
	struct cryptocmp_generate request;
	struct cryptocmp_named_info info;
	struct cryptocmp_named_list_entry entries[CRYPTOCMP_NAMED_LIST_MAX];
	struct cryptocmp_client *client;
	uint8_t public_key[32];
	uint64_t generation;
	uint32_t count, next_cursor;
	int descriptor;

	fake_service_reset();
	request = generate_request();
	memset(&key_request, 0, sizeof(key_request));
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
	ATF_REQUIRE_EQ(0, cryptocmp_generate(client, &request, &descriptor));
	ATF_REQUIRE(descriptor >= 0);
	close(descriptor);
	ATF_REQUIRE_EQ(0, cryptocmp_generate_key(client, &key_request,
	    public_key, &descriptor));
	ATF_CHECK_EQ(0xa5, public_key[0]);
	close(descriptor);
	ATF_REQUIRE_EQ(0, cryptocmp_named_create(client, "test", &request,
	    &generation));
	ATF_CHECK_EQ(42, generation);
	ATF_REQUIRE_EQ(0, cryptocmp_named_lease(client, "test", 1, 60,
	    &generation, &descriptor));
	ATF_CHECK_EQ(42, generation);
	close(descriptor);
	ATF_REQUIRE_EQ(0,
	    cryptocmp_named_rotate(client, "test", &generation));
	ATF_CHECK_EQ(42, generation);
	ATF_REQUIRE_EQ(0,
	    cryptocmp_named_delete(client, "test", &generation));
	ATF_CHECK_EQ(42, generation);
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE_EQ(0, cryptocmp_named_stat(client, "test", &info));
	ATF_CHECK_EQ(42, info.generation);
	ATF_CHECK_EQ(3, info.rights);
	ATF_CHECK_EQ(11, info.cipher);
	ATF_CHECK_EQ(32, info.keylen);
	memset(entries, 0, sizeof(entries));
	count = 0;
	next_cursor = 99;
	ATF_REQUIRE_EQ(0, cryptocmp_named_list(client, 0, entries,
	    CRYPTOCMP_NAMED_LIST_MAX, &count, &next_cursor));
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(0, next_cursor);
	ATF_CHECK_STREQ("alpha", entries[0].name);
	ATF_CHECK_EQ(10, entries[0].generation);
	ATF_CHECK_EQ(3, entries[0].rights);
	ATF_CHECK_STREQ("beta", entries[1].name);
	ATF_CHECK_EQ(11, entries[1].generation);
	/* Refuse to advance past entries that do not fit. */
	memset(entries, 0, sizeof(entries));
	count = 0;
	next_cursor = 99;
	ATF_CHECK_ERRNO(ENOMEM, cryptocmp_named_list(client, 0, entries, 1,
	    &count, &next_cursor) == -1);
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(0, next_cursor);
	ATF_REQUIRE_EQ(0, cryptocmp_named_list(client, 0, entries,
	    CRYPTOCMP_NAMED_LIST_MAX, &count, &next_cursor));
	ATF_CHECK_EQ(2, count);
	/* Ten real operations plus the open-time HELLO handshake. */
	ATF_CHECK_EQ(11, fake_service_calls());
	ATF_CHECK_EQ(0, fake_service_failed());
	cryptocmp_close(client);
	ATF_CHECK_EQ(1, fake_service_closed());
}

/*
 * cryptocmp_open() performs a version-negotiation HELLO: a well-formed provider
 * reply lets open() succeed, and a HELLO reply that fails the protocol contract
 * (here a mismatched ABI version) makes open() itself fail fast with EPROTO --
 * before any real crypto call -- and fails the session.
 */
ATF_TC_WITHOUT_HEAD(open_negotiates_version);
ATF_TC_BODY(open_negotiates_version, tc)
{
	struct cryptocmp_client *client;

	fake_service_reset();

	/* A clean provider: the HELLO succeeds and open() returns a client. */
	client = NULL;
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
	ATF_REQUIRE(client != NULL);
	ATF_CHECK_EQ(1, fake_service_calls());
	ATF_CHECK_EQ(0, fake_service_failed());
	cryptocmp_close(client);

	/* A version-mismatched HELLO reply fails open() fast with EPROTO. */
	client = NULL;
	fake_service_fault_next(FAKE_SERVICE_FAULT_WRONG_VERSION);
	ATF_CHECK_ERRNO(EPROTO, cryptocmp_open(&client) == -1);
	ATF_CHECK(client == NULL);
	ATF_CHECK_EQ(1, fake_service_failed());
}

ATF_TC_WITHOUT_HEAD(error_and_output_contracts);
ATF_TC_BODY(error_and_output_contracts, tc)
{
	struct cryptocmp_key_generate key_request;
	struct cryptocmp_generate request;
	struct cryptocmp_named_info info;
	struct cryptocmp_named_list_entry entries[CRYPTOCMP_NAMED_LIST_MAX];
	struct cryptocmp_client *client;
	uint8_t public_key[32];
	uint64_t generation;
	uint32_t count, next_cursor;
	int descriptor;

	fake_service_reset();
	request = generate_request();
	memset(&key_request, 0, sizeof(key_request));
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
	fake_service_status_next(EPERM);
	descriptor = 99;
	ATF_CHECK_ERRNO(EPERM,
	    cryptocmp_generate(client, &request, &descriptor) == -1);
	ATF_CHECK_EQ(-1, descriptor);
	fake_service_status_next(ENOENT);
	generation = 99;
	descriptor = 99;
	ATF_CHECK_ERRNO(ENOENT, cryptocmp_named_lease(client, "missing", 1,
	    0, &generation, &descriptor) == -1);
	ATF_CHECK_EQ(0, generation);
	ATF_CHECK_EQ(-1, descriptor);
	fake_service_status_next(EACCES);
	memset(public_key, 0xff, sizeof(public_key));
	descriptor = 99;
	ATF_CHECK_ERRNO(EACCES, cryptocmp_generate_key(client, &key_request,
	    public_key, &descriptor) == -1);
	ATF_CHECK_EQ(-1, descriptor);
	ATF_CHECK_EQ(0, public_key[0]);
	fake_service_fault_next(FAKE_SERVICE_FAULT_CALL);
	ATF_CHECK_ERRNO(ECONNRESET,
	    cryptocmp_generate(client, &request, &descriptor) == -1);
	/* A STAT error status maps through and leaves the out struct zeroed. */
	fake_service_status_next(ENOENT);
	memset(&info, 0xff, sizeof(info));
	ATF_CHECK_ERRNO(ENOENT, cryptocmp_named_stat(client, "missing", &info)
	    == -1);
	ATF_CHECK_EQ(0, info.generation);
	ATF_CHECK_EQ(0, info.rights);
	/* A LIST error status maps through and leaves count/cursor zeroed. */
	fake_service_status_next(EPERM);
	memset(entries, 0xff, sizeof(entries));
	count = 99;
	next_cursor = 99;
	ATF_CHECK_ERRNO(EPERM, cryptocmp_named_list(client, 0, entries,
	    CRYPTOCMP_NAMED_LIST_MAX, &count, &next_cursor) == -1);
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(0, next_cursor);
	cryptocmp_close(client);
}

ATF_TC_WITHOUT_HEAD(malformed_reply_matrix);
ATF_TC_BODY(malformed_reply_matrix, tc)
{
	static const enum fake_service_fault faults[] = {
		FAKE_SERVICE_FAULT_TRUNCATE,
		FAKE_SERVICE_FAULT_WRONG_MAGIC,
		FAKE_SERVICE_FAULT_WRONG_VERSION,
		FAKE_SERVICE_FAULT_WRONG_OPCODE,
		FAKE_SERVICE_FAULT_POSITIVE_STATUS,
		FAKE_SERVICE_FAULT_INVALID_STATUS,
		FAKE_SERVICE_FAULT_MISSING_FD,
	};
	struct cryptocmp_generate request;
	struct cryptocmp_client *client;
	int descriptor;
	size_t i;

	fake_service_reset();
	request = generate_request();
	for (i = 0; i < nitems(faults); i++) {
		unsigned calls;

		ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
		fake_service_fault_next(faults[i]);
		descriptor = 99;
		ATF_CHECK_ERRNO(EPROTO,
		    cryptocmp_generate(client, &request, &descriptor) == -1);
		ATF_CHECK_EQ(-1, descriptor);
		calls = fake_service_calls();
		ATF_CHECK_ERRNO(EPROTO,
		    cryptocmp_generate(client, &request, &descriptor) == -1);
		ATF_CHECK_EQ(calls, fake_service_calls());
		cryptocmp_close(client);
	}
	ATF_CHECK_EQ(nitems(faults), fake_service_failed());
}

ATF_TC_WITHOUT_HEAD(unexpected_descriptor_is_closed);
ATF_TC_BODY(unexpected_descriptor_is_closed, tc)
{
	struct cryptocmp_generate request;
	struct cryptocmp_client *client;
	int descriptor, fd;

	fake_service_reset();
	request = generate_request();
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
	fake_service_status_next(EPERM);
	fake_service_fault_next(FAKE_SERVICE_FAULT_UNEXPECTED_FD);
	ATF_CHECK_ERRNO(EPROTO,
	    cryptocmp_generate(client, &request, &descriptor) == -1);
	ATF_CHECK_EQ(-1, descriptor);
	fd = fake_service_last_fd();
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	cryptocmp_close(client);
}

ATF_TC_WITHOUT_HEAD(named_metadata_reply_validation);
ATF_TC_BODY(named_metadata_reply_validation, tc)
{
	static const enum fake_service_fault stat_faults[] = {
		FAKE_SERVICE_FAULT_STAT_GENERATION,
		FAKE_SERVICE_FAULT_STAT_RIGHTS,
	};
	static const enum fake_service_fault list_faults[] = {
		FAKE_SERVICE_FAULT_LIST_CURSOR,
		FAKE_SERVICE_FAULT_LIST_NAME,
		FAKE_SERVICE_FAULT_LIST_GENERATION,
		FAKE_SERVICE_FAULT_LIST_RIGHTS,
		FAKE_SERVICE_FAULT_LIST_PAD,
	};
	struct cryptocmp_named_list_entry entries[CRYPTOCMP_NAMED_LIST_MAX];
	struct cryptocmp_generate request;
	struct cryptocmp_named_info info;
	struct cryptocmp_client *client;
	uint64_t generation;
	uint32_t count, next_cursor;
	size_t i;

	fake_service_reset();
	request = generate_request();
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
	fake_service_fault_next(FAKE_SERVICE_FAULT_NAMED_GENERATION);
	ATF_CHECK_ERRNO(EPROTO, cryptocmp_named_create(client, "key",
	    &request, &generation) == -1);
	cryptocmp_close(client);
	for (i = 0; i < nitems(stat_faults); i++) {
		ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
		fake_service_fault_next(stat_faults[i]);
		ATF_CHECK_ERRNO(EPROTO, cryptocmp_named_stat(client, "key",
		    &info) == -1);
		cryptocmp_close(client);
	}
	for (i = 0; i < nitems(list_faults); i++) {
		ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
		fake_service_fault_next(list_faults[i]);
		ATF_CHECK_ERRNO(EPROTO, cryptocmp_named_list(client, 1, entries,
		    CRYPTOCMP_NAMED_LIST_MAX, &count, &next_cursor) == -1);
		cryptocmp_close(client);
	}
	ATF_CHECK_EQ(1 + nitems(stat_faults) + nitems(list_faults),
	    fake_service_failed());
}

ATF_TC_WITHOUT_HEAD(fork_rejects_inherited_client);
ATF_TC_BODY(fork_rejects_inherited_client, tc)
{
	struct cryptocmp_generate request;
	struct cryptocmp_client *client;
	int descriptor, status;
	pid_t child;

	fake_service_reset();
	request = generate_request();
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (cryptocmp_generate(client, &request, &descriptor) != -1 ||
		    errno != EINVAL)
			_exit(1);
		cryptocmp_close(client);
		_exit(0);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_REQUIRE_EQ(0, cryptocmp_generate(client, &request, &descriptor));
	close(descriptor);
	cryptocmp_close(client);
}

ATF_TC_WITHOUT_HEAD(digest_and_random_matrix);
ATF_TC_BODY(digest_and_random_matrix, tc)
{
	struct cryptocmp_client *client;
	uint8_t buf[64];
	int descriptor;
	size_t i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));

	/* DIGEST success: unkeyed hash session mints and delivers a fd. */
	descriptor = -1;
	ATF_REQUIRE_EQ(0, cryptocmp_digest(client, CRYPTO_SHA2_256, 0, 0,
	    &descriptor));
	ATF_REQUIRE(descriptor >= 0);
	close(descriptor);
	ATF_REQUIRE_EQ(0, cryptocmp_digest(client, CRYPTO_SHA2_512, 60, 0,
	    &descriptor));
	ATF_REQUIRE(descriptor >= 0);
	close(descriptor);

	/* DIGEST argument validation: no IPC is issued on rejection. */
	descriptor = 99;
	ATF_CHECK_ERRNO(EINVAL,
	    cryptocmp_digest(NULL, CRYPTO_SHA2_256, 0, 0, &descriptor) == -1);
	descriptor = 99;
	ATF_CHECK_ERRNO(EINVAL,
	    cryptocmp_digest(client, CRYPTO_SHA2_256, 0, 0, NULL) == -1);
	descriptor = 99;
	ATF_CHECK_ERRNO(EINVAL,
	    cryptocmp_digest(client, CRYPTO_SHA2_256_HMAC, 0, 0, &descriptor)
	    == -1);
	ATF_CHECK_EQ(-1, descriptor);
	descriptor = 99;
	ATF_CHECK_ERRNO(EINVAL,
	    cryptocmp_digest(client, 0, 0, 0, &descriptor) == -1);
	ATF_CHECK_EQ(-1, descriptor);

	/* DIGEST error status maps through; no fd is retained. */
	descriptor = 99;
	fake_service_status_next(EPERM);
	ATF_CHECK_ERRNO(EPERM,
	    cryptocmp_digest(client, CRYPTO_SHA2_256, 0, 0, &descriptor) == -1);
	ATF_CHECK_EQ(-1, descriptor);

	/* DIGEST malformed replies are terminal and drop any fd. */
	fake_service_fault_next(FAKE_SERVICE_FAULT_MISSING_FD);
	descriptor = 99;
	ATF_CHECK_ERRNO(EPROTO,
	    cryptocmp_digest(client, CRYPTO_SHA2_256, 0, 0, &descriptor) == -1);
	ATF_CHECK_EQ(-1, descriptor);
	cryptocmp_close(client);
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));
	fake_service_fault_next(FAKE_SERVICE_FAULT_UNEXPECTED_FD);
	fake_service_status_next(EPERM);
	descriptor = 99;
	ATF_CHECK_ERRNO(EPROTO,
	    cryptocmp_digest(client, CRYPTO_SHA2_256, 0, 0, &descriptor) == -1);
	ATF_CHECK_EQ(-1, descriptor);
	cryptocmp_close(client);
	ATF_REQUIRE_EQ(0, cryptocmp_open(&client));

	/* RANDOM success: buffer is filled with exactly nbytes of output. */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE_EQ(0, cryptocmp_random(client, buf, sizeof(buf)));
	for (i = 0; i < sizeof(buf); i++)
		ATF_CHECK_EQ(0x5a, buf[i]);
	ATF_REQUIRE_EQ(0, cryptocmp_random(client, buf, 1));

	/* RANDOM argument validation: reject before IPC and leave buf zeroed. */
	ATF_CHECK_ERRNO(EINVAL, cryptocmp_random(NULL, buf, 16) == -1);
	ATF_CHECK_ERRNO(EINVAL, cryptocmp_random(client, NULL, 16) == -1);
	memset(buf, 0xff, sizeof(buf));
	ATF_CHECK_ERRNO(EINVAL, cryptocmp_random(client, buf, 0) == -1);
	ATF_CHECK_EQ(0xff, buf[0]);
	ATF_CHECK_ERRNO(EINVAL,
	    cryptocmp_random(client, buf, CRYPTOCMP_MAX_RANDOM_BYTES + 1) == -1);

	/* RANDOM error status maps through and zeroes the caller buffer. */
	memset(buf, 0xff, sizeof(buf));
	fake_service_status_next(EPERM);
	ATF_CHECK_ERRNO(EPERM, cryptocmp_random(client, buf, sizeof(buf)) == -1);
	ATF_CHECK_EQ(0, buf[0]);

	cryptocmp_close(client);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, successful_operation_matrix);
	ATF_TP_ADD_TC(tp, open_negotiates_version);
	ATF_TP_ADD_TC(tp, digest_and_random_matrix);
	ATF_TP_ADD_TC(tp, error_and_output_contracts);
	ATF_TP_ADD_TC(tp, malformed_reply_matrix);
	ATF_TP_ADD_TC(tp, unexpected_descriptor_is_closed);
	ATF_TP_ADD_TC(tp, named_metadata_reply_validation);
	ATF_TP_ADD_TC(tp, fork_rejects_inherited_client);
	return (atf_no_error());
}
