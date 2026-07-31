#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Contract tests for the kernel-only libcapability boundary.

test_cppflags=
if [ -r /usr/src/lib/libcapability/capability.h ]; then
	test_cppflags="-I/usr/src/lib/libcapability -I/usr/src/sys"
fi

find_libcapability()
{
	local p _m _p

	_m=$(uname -m)
	_p=$(uname -p)
	for p in \
	    /usr/obj/usr/src/${_m}.${_p}/lib/libcapability/libcapability.a \
	    /usr/lib/libcapability.a
	do
		if [ -r "$p" ]; then
			capability_archive=$p
			return
		fi
	done
	atf_skip "libcapability static library not found"
}

build_contract_test()
{
	find_libcapability
	command -v cc >/dev/null 2>&1 || atf_skip "cc not available"
	cat > contract.c <<'CEOF'
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <capability.h>

int
main(void)
{
	struct capability_info information;
	char request = 'q', reply[8];
	int fd, request_fds[CAPABILITY_CALL_MAX_FDS + 1];
	int reply_fds[CAPABILITY_CALL_MAX_FDS + 1];
	size_t reply_length, reply_nfds;

	memset(&information, 0, sizeof(information));
	information.size = 1;
	errno = 0;
	if (capability_get_info(0, &information) != -1 || errno != EINVAL)
		return (1);
	errno = 0;
	if (capability_get_info(-1, &information) != -1 || errno != EINVAL)
		return (2);
	reply_length = sizeof(reply);
	reply_nfds = 0;
	errno = 0;
	if (capability_kernel_call(-1, &request, sizeof(request), NULL, 0,
	    reply, &reply_length, NULL, &reply_nfds) != -1 ||
	    errno != EINVAL || reply_length != 0 || reply_nfds != 0)
		return (3);
	reply_length = 1;
	reply_nfds = 0;
	errno = 0;
	if (capability_kernel_call(0, NULL, 1, NULL, 0, reply,
	    &reply_length, NULL, &reply_nfds) != -1 || errno != EINVAL ||
	    reply_length != 0 || reply_nfds != 0)
		return (4);
	reply_length = 0;
	reply_nfds = 1;
	errno = 0;
	if (capability_kernel_call(0, &request, sizeof(request), NULL, 0,
	    NULL, &reply_length, NULL, &reply_nfds) != -1 ||
	    errno != EINVAL || reply_length != 0 || reply_nfds != 0)
		return (5);
	memset(request_fds, 0, sizeof(request_fds));
	reply_length = sizeof(reply);
	reply_nfds = 2;
	reply_fds[0] = 99;
	reply_fds[1] = 99;
	errno = 0;
	if (capability_kernel_call(0, &request, sizeof(request), request_fds,
	    CAPABILITY_CALL_MAX_FDS + 1, reply, &reply_length, reply_fds,
	    &reply_nfds) != -1 || errno != EINVAL || reply_length != 0 ||
	    reply_nfds != 0 || reply_fds[0] != -1 || reply_fds[1] != -1)
		return (6);
	reply_length = sizeof(reply);
	reply_nfds = CAPABILITY_CALL_MAX_FDS + 1;
	errno = 0;
	if (capability_kernel_call(0, &request, sizeof(request), NULL, 0,
	    reply, &reply_length, reply_fds, &reply_nfds) != -1 ||
	    errno != EINVAL || reply_length != 0 || reply_nfds != 0)
		return (7);
	fd = open("/dev/null", O_RDONLY);
	if (fd == -1)
		return (8);
	memset(&information, 0, sizeof(information));
	errno = 0;
	if (capability_get_info(fd, &information) != -1 || errno != ENOTTY)
		return (9);
	reply_fds[0] = 99;
	reply_fds[1] = 99;
	reply_length = sizeof(reply);
	reply_nfds = 2;
	errno = 0;
	if (capability_kernel_call(fd, &request, sizeof(request), NULL, 0,
	    reply, &reply_length, reply_fds, &reply_nfds) != -1 ||
	    errno != ENOTTY || reply_length != 0 || reply_nfds != 0 ||
	    reply_fds[0] != -1 || reply_fds[1] != -1)
		return (10);
	close(fd);
	return (0);
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall -Wextra -Werror \
	    $test_cppflags -o contract contract.c "$capability_archive"
}

atf_test_case kernel_boundary cleanup
kernel_boundary_head()
{
	atf_set "descr" \
	    "libcapability exposes only validated synchronous kernel capability calls"
}
kernel_boundary_body()
{
	build_contract_test
	atf_check -s exit:0 ./contract
}
kernel_boundary_cleanup()
{
	rm -f contract contract.c
}

atf_init_test_cases()
{
	atf_add_test_case kernel_boundary
}
