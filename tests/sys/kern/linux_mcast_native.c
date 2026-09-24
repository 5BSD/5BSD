/* SPDX-License-Identifier: BSD-2-Clause */
/* Run only in a disposable VM: native filters and Linux descriptor rights. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <machine/reg.h>

#include <net/if.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x)                                                               \
	do {                                                                   \
		if (!(x)) {                                                    \
			fprintf(stderr, "native line %d errno %d\n", __LINE__, \
			    errno);                                            \
			return 1;                                              \
		}                                                              \
	} while (0)
static int
native(int af, unsigned index)
{
	struct __msfilterreq req = { 0 };
	struct sockaddr_storage vec[3] = { 0 };
	struct group_req join = { 0 };
	int fd = socket(af, SOCK_DGRAM, 0),
	    level = af == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
	int option = af == AF_INET ? IP_MSFILTER : IPV6_MSFILTER;
	CHECK(fd >= 0);
	join.gr_interface = index;
	if (af == AF_INET) {
		struct sockaddr_in *g = (void *)&join.gr_group;
		g->sin_family = af;
		g->sin_len = sizeof(*g);
		inet_pton(af, "239.9.0.9", &g->sin_addr);
		for (int i = 0; i < 2; i++) {
			struct sockaddr_in *a = (void *)&vec[i];
			a->sin_family = af;
			a->sin_len = sizeof(*a);
			inet_pton(af, i ? "10.0.2.16" : "10.0.2.15",
			    &a->sin_addr);
		}
	} else {
		struct sockaddr_in6 *g = (void *)&join.gr_group;
		g->sin6_family = af;
		g->sin6_len = sizeof(*g);
		inet_pton(af, "ff05::1234", &g->sin6_addr);
		for (int i = 0; i < 2; i++) {
			struct sockaddr_in6 *a = (void *)&vec[i];
			a->sin6_family = af;
			a->sin6_len = sizeof(*a);
			inet_pton(af, i ? "fd00::2" : "fd00::1", &a->sin6_addr);
		}
	}
	CHECK(
	    setsockopt(fd, level, MCAST_JOIN_GROUP, &join, sizeof(join)) == 0);
	req.msfr_group = join.gr_group;
	req.msfr_ifindex = index;
	req.msfr_fmode = MCAST_INCLUDE;
	req.msfr_nsrcs = 2;
	req.msfr_srcs = vec;
	CHECK(setsockopt(fd, level, option, &req, sizeof(req)) == 0);
	req.msfr_fmode = MCAST_EXCLUDE;
	req.msfr_srcs = (void *)1;
	CHECK(setsockopt(fd, level, option, &req, sizeof(req)) == -1 &&
	    errno == EFAULT);
	req.msfr_srcs = vec;
	req.msfr_nsrcs = 3;
	socklen_t len = sizeof(req);
	CHECK(getsockopt(fd, level, option, &req, &len) == 0 &&
	    req.msfr_fmode == MCAST_INCLUDE && req.msfr_nsrcs == 2);
	/* Native delta callers retain full-state order and duplicate counts. */
	struct group_source_req delta = { 0 };
	delta.gsr_interface = index;
	delta.gsr_group = join.gr_group;
	delta.gsr_source = vec[0];
	vec[1] = vec[0];
	req.msfr_nsrcs = 2;
	CHECK(setsockopt(fd, level, option, &req, sizeof(req)) == 0);
	CHECK(setsockopt(fd, level, MCAST_LEAVE_SOURCE_GROUP, &delta,
	    sizeof(delta)) == 0);
	req.msfr_nsrcs = 3;
	len = sizeof(req);
	CHECK(getsockopt(fd, level, option, &req, &len) == 0 &&
	    req.msfr_nsrcs == 1 && memcmp(&vec[0], &delta.gsr_source,
	    sizeof(vec[0])) == 0);
	CHECK(setsockopt(fd, level, MCAST_LEAVE_SOURCE_GROUP, &delta,
	    sizeof(delta)) == 0);
	CHECK(setsockopt(fd, level, MCAST_JOIN_GROUP, &join, sizeof(join)) == 0);
	req.msfr_fmode = MCAST_EXCLUDE;
	req.msfr_nsrcs = 0;
	CHECK(setsockopt(fd, level, option, &req, sizeof(req)) == 0);
	req.msfr_nsrcs = 3;
	len = sizeof(req);
	CHECK(getsockopt(fd, level, option, &req, &len) == 0 &&
	    req.msfr_nsrcs == 0 && req.msfr_fmode == MCAST_EXCLUDE);
	CHECK(setsockopt(fd, level, MCAST_JOIN_SOURCE_GROUP, &delta,
	    sizeof(delta)) == 0);
	req.msfr_nsrcs = 3; len = sizeof(req);
	CHECK(getsockopt(fd, level, option, &req, &len) == 0 &&
	    req.msfr_fmode == MCAST_INCLUDE && req.msfr_nsrcs == 1);
	CHECK(setsockopt(fd, level, MCAST_BLOCK_SOURCE, &delta,
	    sizeof(delta)) == -1 && errno == EINVAL);
	req.msfr_fmode = MCAST_EXCLUDE; req.msfr_nsrcs = 0;
	CHECK(setsockopt(fd, level, option, &req, sizeof(req)) == 0);
	CHECK(setsockopt(fd, level, MCAST_BLOCK_SOURCE, &delta,
	    sizeof(delta)) == 0);
	CHECK(setsockopt(fd, level, MCAST_UNBLOCK_SOURCE, &delta,
	    sizeof(delta)) == 0);
	CHECK(setsockopt(fd, level, MCAST_JOIN_SOURCE_GROUP, &delta,
	    sizeof(delta)) == -1 && errno == EINVAL);
	CHECK(
	    setsockopt(fd, level, MCAST_LEAVE_GROUP, &join, sizeof(join)) == 0);
	close(fd);
	return 0;
}
static int
caps(const char *path, int mode)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0), execfd = open(path, O_RDONLY),
	    status;
	struct ip_mreq req;
	inet_pton(AF_INET, "239.9.0.9", &req.imr_multiaddr);
	inet_pton(AF_INET, "10.0.2.15", &req.imr_interface);
	CHECK(fd >= 0 && execfd >= 0);
	CHECK(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &req,
		  sizeof(req)) == 0);
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		cap_rights_t rights;
		char m[2] = { '0' + mode, 0 };
		char *argv[] = { (char *)path, "caps", m, NULL },
		     *env[] = { NULL };
		if (mode == 0 || mode == 3)
			cap_rights_init(&rights, CAP_GETSOCKOPT,
			    CAP_SETSOCKOPT);
		else if (mode == 1)
			cap_rights_init(&rights, CAP_GETSOCKOPT);
		else
			cap_rights_init(&rights, CAP_SETSOCKOPT);
		if (cap_rights_limit(fd, &rights) || dup2(fd, 3) < 0 ||
		    ptrace(PT_TRACE_ME, 0, NULL, 0) ||
		    (mode == 3 && cap_enter()))
			_exit(90);
		fexecve(execfd, argv, env);
		_exit(91);
	}
	close(fd);
	close(execfd);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
	CHECK(ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	struct reg regs;
	int result = 1;
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
	    ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) == 0)
		result = (regs.r_rax != 0);
	printf("MCAST_CAPS mode=%d status=%x rc=%d\n", mode, status, result);
	if (WIFSTOPPED(status)) {
		ptrace(PT_KILL, pid, NULL, 0);
		waitpid(pid, &status, 0);
	}
	CHECK(result == 0);
	return 0;
}
int
main(int argc, char **argv)
{
	CHECK(argc == 3);
	unsigned index = if_nametoindex(argv[1]);
	CHECK(index != 0);
	CHECK(native(AF_INET, index) == 0);
	CHECK(native(AF_INET6, index) == 0);
	for (int m = 0; m < 4; m++)
		CHECK(caps(argv[2], m) == 0);
	puts("MCAST_NATIVE_PASS");
	return 0;
}
