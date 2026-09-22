/* SPDX-License-Identifier: BSD-2-Clause */
/* Native-created descriptor rights across exec into a Linux64 probe. */
#ifdef LINUX_PROBE
__asm__(".text\n.globl _start\n_start:\n"
	"sub $32,%rsp\nmovq $0,8(%rsp)\nmovl $8,16(%rsp)\n"
	"mov $55,%eax\nmov $3,%edi\nmov $1,%esi\nmov $57,%edx\n"
	"lea 8(%rsp),%r10\nlea 16(%rsp),%r8\nsyscall\n"
	"mov 8(%rsp),%r12\nint3\nud2\n");
#else
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <machine/reg.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
static int
run(const char *path, int mode)
{
	cap_rights_t rights;
	struct reg regs;
	int fd, sock, st, rc = 1;
	pid_t p, got;
	bool reaped = false;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	fd = open(path, O_RDONLY);
	if (sock < 0 || fd < 0)
		return 1;
	p = fork();
	if (p < 0)
		return 2;
	if (!p) {
		char *av[] = { (char *)path, NULL }, *env[] = { NULL };
		int type;
		socklen_t len = sizeof(type);
		cap_rights_init(&rights, mode == 1 ? CAP_READ : CAP_GETSOCKOPT);
		if (cap_rights_limit(sock, &rights))
			_exit(91);
		int e = getsockopt(sock, SOL_SOCKET, SO_TYPE, &type, &len);
		if (mode == 1 ? (e != -1 || errno != ENOTCAPABLE) :
				(e || type != SOCK_DGRAM))
			_exit(92);
		if (dup2(sock, 3) < 0 || ptrace(PT_TRACE_ME, 0, NULL, 0))
			_exit(93);
		if (mode == 2 && cap_enter())
			_exit(94);
		fexecve(fd, av, env);
		_exit(95);
	}
	close(sock);
	close(fd);
	got = waitpid(p, &st, 0);
	reaped = got == p && (WIFEXITED(st) || WIFSIGNALED(st));
	if (got != p || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP)
		goto out;
	if (ptrace(PT_CONTINUE, p, (caddr_t)1, 0))
		goto out;
	got = waitpid(p, &st, 0);
	reaped = got == p && (WIFEXITED(st) || WIFSIGNALED(st));
	if (got != p || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP ||
	    ptrace(PT_GETREGS, p, (caddr_t)&regs, 0))
		goto out;
	rc = mode == 0 ? ((long)regs.r_rax != 0 || regs.r_r12 == 0) :
			 ((long)regs.r_rax != -1);
	printf("COOKIE_CAPS mode=%d result=%ld rc=%d\n", mode, (long)regs.r_rax,
	    rc);
out:
	if (!reaped) {
		if (ptrace(PT_KILL, p, NULL, 0))
			kill(p, SIGKILL);
		waitpid(p, &st, 0);
	}
	return rc;
}
int
main(int argc, char **argv)
{
	if (argc != 2)
		return 1;
	for (int mode = 0; mode < 3; mode++)
		if (run(argv[1], mode))
			return mode + 1;
	return 0;
}
#endif
