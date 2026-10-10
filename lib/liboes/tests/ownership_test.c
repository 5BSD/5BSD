/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <liboes.h>
#include <stdlib.h>
static bool fail_allocation;
static void *
test_calloc(size_t count, size_t size)
{
	if (fail_allocation) {
		errno = ENOMEM;
		return (NULL);
	}
	return (calloc(count, size));
}
#define calloc test_calloc
#include "../liboes.c"
#undef calloc

#include <unistd.h>

/* Pipes exercise ownership without requiring OES or privileged device access.
 * Adoption deliberately does not claim to validate the device type. */
ATF_TC_WITHOUT_HEAD(owned_and_borrowed);
ATF_TC_BODY(owned_and_borrowed, tc)
{
	int p[2], copy;
	oes_client_t *client;
	ATF_REQUIRE_EQ(0, pipe(p));
	client = oes_client_create_from_fd(p[0]);
	ATF_REQUIRE(client != NULL);
	oes_client_destroy(client);
	ATF_REQUIRE(fcntl(p[0], F_GETFD) != -1);
	copy = dup(p[0]);
	ATF_REQUIRE(copy >= 0);
	client = oes_client_adopt_fd(p[0]);
	ATF_REQUIRE(client != NULL);
	ATF_CHECK_EQ(p[0], oes_client_fd(client));
	oes_client_destroy(client);
	ATF_CHECK_ERRNO(EBADF, fcntl(p[0], F_GETFD) == -1);
	ATF_CHECK(fcntl(copy, F_GETFD) != -1);
	close(copy);
	close(p[1]);
}
ATF_TC_WITHOUT_HEAD(invalid_descriptor);
ATF_TC_BODY(invalid_descriptor, tc)
{
	int p[2], fd;
	ATF_CHECK_ERRNO(EBADF, oes_client_adopt_fd(-1) == NULL);
	ATF_REQUIRE_EQ(0, pipe(p));
	fd = p[0];
	close(fd);
	ATF_CHECK_ERRNO(EBADF, oes_client_adopt_fd(fd) == NULL);
	ATF_CHECK(fcntl(p[1], F_GETFD) != -1);
	close(p[1]);
}
ATF_TC_WITHOUT_HEAD(allocation_failure_preserves_ownership);
ATF_TC_BODY(allocation_failure_preserves_ownership, tc)
{
	int p[2];
	ATF_REQUIRE_EQ(0, pipe(p));
	fail_allocation = true;
	ATF_CHECK_ERRNO(ENOMEM, oes_client_adopt_fd(p[0]) == NULL);
	ATF_CHECK(fcntl(p[0], F_GETFD) != -1);
	close(p[0]);
	close(p[1]);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, owned_and_borrowed);
	ATF_TP_ADD_TC(tp, invalid_descriptor);
	ATF_TP_ADD_TC(tp, allocation_failure_preserves_ownership);
	return (atf_no_error());
}
