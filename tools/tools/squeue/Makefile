# SPDX-License-Identifier: BSD-2-Clause
#
# Standalone squeue conformance binaries.  Two front-ends share one engine, so
# there are two binaries, one per interface:
#
#   squeue_check   - native 5BSD squeue_* front-end; a normal FreeBSD binary.
#   iouring_check  - Linux io_uring front-end; a freestanding Linux/amd64
#                    static binary run under the Linuxulator.
#
# "make" builds the native one via the normal machinery.  iouring_check needs
# a Linux target, so it has its own explicit rule ("make iouring_check"),
# which requires clang + lld.  Neither is installed by default.

PROG=	squeue_check
MAN=
LIBADD=	pthread
WARNS?=	6

# Linux-ABI companion (built only when explicitly requested).
LINUX_CC?=	clang
LINUX_CFLAGS=	--target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
		-fno-stack-protector -fno-builtin -O2 -Wall

iouring_check: iouring_check.c
	${LINUX_CC} ${LINUX_CFLAGS} -o ${.TARGET} ${.ALLSRC}

both: squeue_check iouring_check

CLEANFILES+=	iouring_check

.include <bsd.prog.mk>
