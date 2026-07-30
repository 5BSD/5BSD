/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>
#include <libservice.h>
#include <service_bootstrap.h>

static int
install_bootstrap(const struct service_bootstrap *bootstrap, size_t size)
{
	struct envfd_create_options options =
	    ENVFD_CREATE_OPTIONS_INITIALIZER(size);
	ssize_t written;
	int fd;

	options.eco_flags = ENVFD_WRITE_ONCE;
	fd = envfd_create(SERVICE_BOOTSTRAP_ENVFD_NAME, &options);
	if (fd == -1)
		return (-1);
	written = write(fd, bootstrap, size);
	if (written != (ssize_t)size)
		return (-1);
	if (fd != SERVICE_BOOTSTRAP_FD) {
		if (dup2(fd, SERVICE_BOOTSTRAP_FD) != SERVICE_BOOTSTRAP_FD)
			return (-1);
		close(fd);
	}
	return (0);
}

static void
valid_empty_bootstrap(struct service_bootstrap *bootstrap)
{

	memset(bootstrap, 0, sizeof(*bootstrap));
	bootstrap->magic = SERVICE_BOOTSTRAP_MAGIC;
	bootstrap->version = SERVICE_BOOTSTRAP_VERSION;
	bootstrap->header_size = offsetof(struct service_bootstrap, label);
	bootstrap->total_size = sizeof(*bootstrap);
	bootstrap->channel_fd = 3;
	bootstrap->capprotect_fd = -1;
	strlcpy(bootstrap->label, "org.test.bootstrap",
	    sizeof(bootstrap->label));
}

enum bootstrap_case {
	BOOTSTRAP_ABSENT,
	BOOTSTRAP_TRUNCATED,
	BOOTSTRAP_ZERO,
	BOOTSTRAP_VERSION,
	BOOTSTRAP_RESERVED,
	BOOTSTRAP_FLAGS,
	BOOTSTRAP_COUNT,
	BOOTSTRAP_LABEL,
	BOOTSTRAP_UNUSED,
	BOOTSTRAP_CAPPROTECT,
	BOOTSTRAP_TOKEN_LAYOUT,
	BOOTSTRAP_DUPLICATE_COMPONENT,
	BOOTSTRAP_WRITABLE,
	BOOTSTRAP_BAD_CHANNEL,
	BOOTSTRAP_ENV_VALUE,
	BOOTSTRAP_WRONG_TYPE
};

static int
run_bootstrap_case(enum bootstrap_case test_case, int expected_errno)
{
	struct service_bootstrap bootstrap;
	cap_rights_t rights;
	pid_t pid;
	int fd, status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(SERVICE_BOOTSTRAP_FD);
		unsetenv(SERVICE_BOOTSTRAP_ENV);
		if (test_case != BOOTSTRAP_ABSENT) {
			if (setenv(SERVICE_BOOTSTRAP_ENV,
			    test_case == BOOTSTRAP_ENV_VALUE ? "4" : "5",
			    1) == -1)
				_exit(6);
			memset(&bootstrap, 0, sizeof(bootstrap));
			if (test_case != BOOTSTRAP_TRUNCATED &&
			    test_case != BOOTSTRAP_ZERO)
				valid_empty_bootstrap(&bootstrap);
			if (test_case == BOOTSTRAP_VERSION)
				bootstrap.version++;
			if (test_case == BOOTSTRAP_RESERVED)
				bootstrap.reserved[3] = 1;
			if (test_case == BOOTSTRAP_FLAGS)
				bootstrap.flags = UINT32_C(0x80000000);
			if (test_case == BOOTSTRAP_COUNT)
				bootstrap.ntokens =
				    SERVICE_BOOTSTRAP_TOKEN_MAX + 1;
			if (test_case == BOOTSTRAP_LABEL)
				memset(bootstrap.label, 'x',
				    sizeof(bootstrap.label));
			if (test_case == BOOTSTRAP_UNUSED)
				bootstrap.token_fds[1] = 42;
			if (test_case == BOOTSTRAP_CAPPROTECT)
				bootstrap.capprotect_fd = 4;
			if (test_case == BOOTSTRAP_TOKEN_LAYOUT) {
				bootstrap.ntokens = 1;
				bootstrap.token_fds[0] = 7;
			}
			if (test_case == BOOTSTRAP_DUPLICATE_COMPONENT) {
				bootstrap.ncomponents = 2;
				bootstrap.components[0].fd = 6;
				bootstrap.components[1].fd = 7;
				strlcpy(bootstrap.components[0].name, "storage",
				    sizeof(bootstrap.components[0].name));
				strlcpy(bootstrap.components[1].name, "storage",
				    sizeof(bootstrap.components[1].name));
			}
			if (test_case == BOOTSTRAP_BAD_CHANNEL) {
				fd = open("/dev/null", O_RDONLY);
				if (fd == -1 || dup2(fd, 3) != 3)
					_exit(2);
				if (fd != 3)
					close(fd);
			}
			if (test_case == BOOTSTRAP_WRONG_TYPE) {
				fd = open("/dev/null", O_RDONLY);
				if (fd == -1 ||
				    dup2(fd, SERVICE_BOOTSTRAP_FD) !=
				    SERVICE_BOOTSTRAP_FD)
					_exit(3);
				if (fd != SERVICE_BOOTSTRAP_FD)
					close(fd);
			} else if (install_bootstrap(&bootstrap,
			    test_case == BOOTSTRAP_TRUNCATED ? 1 :
			    sizeof(bootstrap)) == -1)
				_exit(3);
			if (test_case == BOOTSTRAP_BAD_CHANNEL) {
				cap_rights_init(&rights, CAP_READ, CAP_FSTAT,
				    CAP_IOCTL);
				if (cap_rights_limit(SERVICE_BOOTSTRAP_FD,
				    &rights) == -1 ||
				    cap_ioctls_limit(SERVICE_BOOTSTRAP_FD,
				    (const unsigned long[]){ ENVFD_GETINFO },
				    1) == -1)
					_exit(5);
			}
		}
		errno = 0;
		_exit(service_init() == -1 && errno == expected_errno ? 0 : 4);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	return (WIFEXITED(status) ? WEXITSTATUS(status) : 255);
}

ATF_TC(bootstrap_validation);
ATF_TC_HEAD(bootstrap_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "service_init rejects absent, truncated, malformed, and wrongly typed bootstrap descriptors");
}
ATF_TC_BODY(bootstrap_validation, tc)
{
	(void)tc;
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_ABSENT, EBADF));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_TRUNCATED, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_ZERO, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_VERSION, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_RESERVED, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_FLAGS, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_COUNT, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_LABEL, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_UNUSED, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_CAPPROTECT, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_TOKEN_LAYOUT, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_DUPLICATE_COMPONENT,
	    EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_WRITABLE, EINVAL));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_BAD_CHANNEL, EINVAL));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_ENV_VALUE, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_WRONG_TYPE, EINVAL));
}

ATF_TC(api_rejects_invalid_descriptors_and_arguments);
ATF_TC_HEAD(api_rejects_invalid_descriptors_and_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "libservice validates descriptor types, arguments, and payload sizes");
}
ATF_TC_BODY(api_rejects_invalid_descriptors_and_arguments, tc)
{
	int fd;

	(void)tc;
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_ERRNO(ENOTCONN,
	    service_authorize_capabilities() == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_register(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_unregister(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_lookup(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_send(-1, NULL, 1) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_recv(-1, NULL, 1, NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_send_fds(-1, "", 0, NULL, 1) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_recv_fds(-1, NULL, 0, NULL, NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(ENOTCONN, service_component_fd("network") == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_component_recv_bootstrap(-1, NULL, NULL, 0) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_component_send_reply(-1, 1, 0,
	    COMPONENT_SESSION_MEMBER_PROCDESC, -1) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_component_send_reply(-1, 1, EACCES,
	    COMPONENT_SESSION_MEMBER_PROCDESC, fd) == -1);
#if SIZE_MAX > UINT32_MAX
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_send(-1, "", (size_t)UINT32_MAX + 1) == -1);
#endif
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bootstrap_validation);
	ATF_TP_ADD_TC(tp, api_rejects_invalid_descriptors_and_arguments);
	return (atf_no_error());
}
