/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dq_legitimacy_test's 32-bit image: a freestanding i386 program built
 * twice at buildworld time (Makefile), as a FreeBSD and a Linux executable,
 *   clang --target=i386-unknown-freebsd -fuse-ld=lld -nostdlib -static ...
 *   clang --target=i386-linux-gnu -fuse-ld=lld -nostdlib -static ...
 * and expects the kernel to refuse (ENOEXEC).  Should a kernel ever run
 * it, it exits with status 0: exit is system call 1 through int $0x80 in
 * both ABIs, with the status on the stack for FreeBSD and in %ebx for
 * Linux.
 */

void	_start(void);

void
_start(void)
{

	__asm__ volatile("xorl %ebx, %ebx\n"
	    "pushl $0\n"
	    "pushl $0\n"
	    "movl $1, %eax\n"
	    "int $0x80");
	for (;;)
		;
}
